use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use certificate::SelfSignedCertificate;
use http::HttpServer;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::Instrument;
use webtransport::WebTransportServer;

#[tokio::main]
async fn main() -> Result<()> {
    utils::init_logging();
    utils::set_additional_paths().context("Cannot set additional paths")?;

    let certificate =
        SelfSignedCertificate::new().context("Cannot generate self-signed certificate")?;

    info!("Certificate fingerprint: {}", certificate.fingerprint());

    let webtransport_server = WebTransportServer::new(&certificate)?;
    let http_server = HttpServer::new(webtransport_server.local_port()).await?;
    let browser = utils::launch_google_chrome(http_server.local_port(), certificate.fingerprint())?;

    tokio::select! {
        result = http_server.serve() => {
            error!("HTTP server: {:?}", result);
        }
        result = webtransport_server.serve() => {
            error!("WebTransport server: {:?}", result);
        }
        () = browser.wait() => {}
    }

    Ok(())
}

mod certificate {
    use super::*;
    use base64::engine::general_purpose::STANDARD as Base64Engine;
    use base64::Engine;
    use rcgen::CertificateParams;
    use rcgen::DistinguishedName;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use ring::digest::digest;
    use ring::digest::SHA256;
    use time::Duration;
    use time::OffsetDateTime;

    pub struct SelfSignedCertificate {
        certificate: Vec<u8>,
        key: Vec<u8>,
        fingerprint: String,
    }

    impl SelfSignedCertificate {
        pub fn new() -> Result<Self> {
            let keypair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
            let digest = digest(&SHA256, &keypair.public_key_der());
            let fingerprint = Base64Engine.encode(digest);

            let mut dname = DistinguishedName::new();
            dname.push(DnType::CommonName, "localhost");

            let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]);
            cert_params.distinguished_name = dname;
            cert_params.alg = &PKCS_ECDSA_P256_SHA256;
            cert_params.key_pair = Some(keypair);
            cert_params.not_before = OffsetDateTime::now_utc()
                .checked_sub(Duration::days(5))
                .unwrap();
            cert_params.not_after = OffsetDateTime::now_utc()
                .checked_add(Duration::days(5))
                .unwrap();

            let certificate = rcgen::Certificate::from_params(cert_params)?;

            Ok(SelfSignedCertificate {
                certificate: certificate.serialize_der()?,
                key: certificate.serialize_private_key_der(),
                fingerprint,
            })
        }

        pub fn certificate_der(&self) -> &[u8] {
            &self.certificate
        }

        pub fn private_key_der(&self) -> &[u8] {
            &self.key
        }

        pub fn fingerprint(&self) -> &str {
            &self.fingerprint
        }
    }
}

mod webtransport {
    use super::certificate::SelfSignedCertificate;
    use super::*;
    use std::time::Duration;
    use wtransport::endpoint::endpoint_side::Server;
    use wtransport::endpoint::IncomingSession;
    use wtransport::tls::Certificate;
    use wtransport::Endpoint;
    use wtransport::ServerConfig;

    pub struct WebTransportServer {
        endpoint: Endpoint<Server>,
    }

    impl WebTransportServer {
        pub fn new(certificate: &SelfSignedCertificate) -> Result<Self> {
            let certificate = Certificate::new(
                vec![certificate.certificate_der().to_vec()],
                certificate.private_key_der().to_vec(),
            );

            let config = ServerConfig::builder()
                .with_bind_default(0)
                .with_certificate(certificate)
                .keep_alive_interval(Some(Duration::from_secs(3)))
                .build();

            let endpoint = Endpoint::server(config)?;

            Ok(Self { endpoint })
        }

        pub fn local_port(&self) -> u16 {
            self.endpoint.local_addr().unwrap().port()
        }

        pub async fn serve(self) -> Result<()> {
            info!("Server running on port {}", self.local_port());

            for id in 0.. {
                let incoming_session = self.endpoint.accept().await;

                tokio::spawn(
                    Self::handle_incoming_session(incoming_session)
                        .instrument(info_span!("Connection", id)),
                );
            }

            Ok(())
        }

        async fn handle_incoming_session(incoming_session: IncomingSession) {
            async fn handle_incoming_session_impl(incoming_session: IncomingSession) -> Result<()> {
                let mut buffer = vec![0; 65536].into_boxed_slice();

                info!("Waiting for session request...");

                let session_request = incoming_session.await?;

                info!(
                    "New session: Authority: '{}', Path: '{}'",
                    session_request.authority(),
                    session_request.path()
                );

                let connection = session_request.accept().await?;

                info!("Waiting for data from client...");

                loop {
                    tokio::select! {
                        stream = connection.accept_bi() => {
                            let mut stream = stream?;
                            info!("Accepted BI stream");

                            let bytes_read = match stream.1.read(&mut buffer).await? {
                                Some(bytes_read) => bytes_read,
                                None => continue,
                            };

                            let str_data = std::str::from_utf8(&buffer[..bytes_read])?;

                            info!("Received (bi) '{str_data}' from client");

                            stream.0.write_all(b"ACK").await?;
                        }
                        stream = connection.accept_uni() => {
                            let mut stream = stream?;
                            info!("Accepted UNI stream");

                            let bytes_read = match stream.read(&mut buffer).await? {
                                Some(bytes_read) => bytes_read,
                                None => continue,
                            };

                            let str_data = std::str::from_utf8(&buffer[..bytes_read])?;

                            info!("Received (uni) '{str_data}' from client");

                            let mut stream = connection.open_uni().await?.await?;
                            stream.write_all(b"ACK").await?;
                        }
                        dgram = connection.receive_datagram() => {
                            let dgram = dgram?;
                            let str_data = std::str::from_utf8(&dgram)?;

                            info!("Received (dgram) '{str_data}' from client");

                            connection.send_datagram(b"ACK")?;
                        }
                    }
                }
            }

            let result = handle_incoming_session_impl(incoming_session).await;
            info!("Result: {:?}", result);
        }
    }
}

mod http {
    use super::*;
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Html;
    use axum::routing::get;
    use axum::serve;
    use axum::serve::Serve;
    use axum::Router;
    use std::net::Ipv6Addr;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    pub struct HttpServer {
        serve: Serve<Router, Router>,
        local_port: u16,
    }

    impl HttpServer {
        pub async fn new(webtransport_port: u16) -> Result<Self> {
            let router = Self::build_router(webtransport_port);

            let listener = TcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0))
                .await
                .context("Cannot bind TCP listener for HTTP server")?;

            let local_port = listener
                .local_addr()
                .context("Cannot get local port")?
                .port();

            Ok(HttpServer {
                serve: serve(listener, router),
                local_port,
            })
        }

        pub fn local_port(&self) -> u16 {
            self.local_port
        }

        pub async fn serve(self) -> Result<()> {
            info!("Server running on port {}", self.local_port());

            self.serve.await.context("HTTP server error")?;

            Ok(())
        }

        fn build_router(webtransport_port: u16) -> Router {
            let root = move || async move {
                Html(
                    http_data::INDEX_DATA
                        .replace("${WEBTRANSPORT_PORT}", &webtransport_port.to_string()),
                )
            };

            let style =
                move || async move { ([(CONTENT_TYPE, "text/css")], http_data::STYLE_DATA) };

            let client = move || async move {
                (
                    [(CONTENT_TYPE, "application/javascript")],
                    http_data::CLIENT_DATA,
                )
            };

            Router::new()
                .route("/", get(root))
                .route("/style.css", get(style))
                .route("/client.js", get(client))
        }
    }
}

mod utils {
    use super::*;
    use pathsearch::find_executable_in_path;
    use std::path::PathBuf;
    use std::process::Stdio;
    use sysinfo::ProcessExt;
    use sysinfo::ProcessRefreshKind;
    use sysinfo::RefreshKind;
    use sysinfo::System;
    use sysinfo::SystemExt;
    use tokio::process::Child;
    use tokio::process::Command;
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::EnvFilter;

    pub fn init_logging() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        tracing_subscriber::fmt()
            .with_target(true)
            .with_level(true)
            .with_env_filter(env_filter)
            .init();
    }

    pub fn set_additional_paths() -> Result<()> {
        const GOOGLE_CHROME_ADDS_PATHS: &[&str] = if cfg!(windows) {
            &[r"C:\Program Files\Google\Chrome\Application"]
        } else {
            &[]
        };

        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::env::split_paths(&old_path)
                .chain(GOOGLE_CHROME_ADDS_PATHS.iter().map(PathBuf::from)),
        )?;

        std::env::set_var("PATH", new_path);

        Ok(())
    }

    pub struct BrowerHandler(Child);

    impl BrowerHandler {
        pub async fn wait(mut self) {
            let _ = self.0.wait().await;
        }
    }

    pub fn launch_google_chrome(http_port: u16, cert_fingerprint: &str) -> Result<BrowerHandler> {
        info!("Launching google-chrome brower...");

        if is_google_chrome_running() {
            return Err(anyhow!(
                "Google Chrome is already running. Please close it before running this example."
            ));
        }

        let chrome_bin = google_chrome_bin()?;

        let child = Command::new(chrome_bin)
            .arg("--webtransport-developer-mode")
            .arg(format!(
                "--ignore-certificate-errors-spki-list={cert_fingerprint}"
            ))
            .arg(format!("http://localhost:{http_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(BrowerHandler(child))
    }

    fn is_google_chrome_running() -> bool {
        let mut system = System::new();
        system.refresh_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));

        system
            .processes()
            .values()
            .any(|p| p.exe().to_string_lossy().contains("chrome"))
    }

    fn google_chrome_bin() -> Result<PathBuf> {
        const GOOGLE_CHROME_EXES: [&str; 3] = ["google-chrome", "google-chrome-stable", "chrome"];

        GOOGLE_CHROME_EXES
            .iter()
            .find_map(find_executable_in_path)
            .ok_or_else(|| anyhow!("Cannot find Google Chrome executable"))
    }
}

mod http_data {

    pub const INDEX_DATA: &str = r#"
<!doctype html>
<html lang="en">
  <title>WTransport-Example</title>
  <meta charset="utf-8">
  <script src="client.js"></script>
  <link rel="stylesheet" href="style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <body>

    <h1>WTransport Example</h1>

    <div>
      <h2>Establish WebTransport connection</h2>
      <div class="input-line">
        <label for="url">URL:</label>
        <input type="text" name="url" id="url" value="https://localhost:${WEBTRANSPORT_PORT}/">
        <input type="button" id="connect" value="Connect" onclick="connect()">
      </div>
    </div>

    <div>
      <h2>Send data over WebTransport</h2>
      <form name="sending">
        <textarea name="data" id="data"></textarea>
        <div>
          <input type="radio" name="sendtype" value="datagram" id="datagram" checked>
          <label for="datagram">Send a datagram</label>
        </div>
        <div>
          <input type="radio" name="sendtype" value="unidi" id="unidi-stream">
          <label for="unidi-stream">Open a unidirectional stream</label>
        </div>
        <div>
          <input type="radio" name="sendtype" value="bidi" id="bidi-stream">
          <label for="bidi-stream">Open a bidirectional stream</label>
        </div>
        <input type="button" id="send" name="send" value="Send data" disabled onclick="sendData()">
      </form>
    </div>

    <div>
      <h2>Event log</h2>
      <ul id="event-log">
      </ul>
    </div>

  </body>
</html>
"#;

    pub const STYLE_DATA: &str = r#"
body {
  font-family: sans-serif;
}

h1 {
  margin: 0 auto;
  width: fit-content;
}

h2 {
  border-bottom: 1px dotted #333;
  font-size: 120%;
  font-weight: normal;
  padding-bottom: 0.2em;
  padding-top: 0.5em;
}

code {
  background-color: #eee;
}

input[type=text], textarea {
  font-family: monospace;
}

#top {
  display: flex;
  flex-direction: row-reverse;
  flex-wrap: wrap;
  justify-content: center;
}

#explanation {
  border: 1px dotted black;
  font-size: 90%;
  height: fit-content;
  margin-bottom: 1em;
  padding: 1em;
  width: 13em;
}

#tool {
  flex-grow: 1;
  margin: 0 auto;
  max-width: 26em;
  padding: 0 1em;
  width: 26em;
}

.input-line {
  display: flex;
}

.input-line input[type=text] {
  flex-grow: 1;
  margin: 0 0.5em;
}

textarea {
  height: 3em;
  width: 100%;
}

#send {
  margin-top: 0.5em;
  width: 15em;
}

#event-log {
  border: 1px dotted black;
  font-family: monospace;
  height: 12em;
  overflow: scroll;
  padding-bottom: 1em;
  padding-top: 1em;
}

.log-error {
  color: darkred;
}

#explanation ul {
  padding-left: 1em;
}
"#;

    pub const CLIENT_DATA: &str = r#"
// Adds an entry to the event log on the page, optionally applying a specified
// CSS class.

let currentTransport, streamNumber, currentTransportDatagramWriter;

// "Connect" button handler.
async function connect() {
  const url = document.getElementById('url').value;
  try {
    var transport = new WebTransport(url);
    addToEventLog('Initiating connection...');
  } catch (e) {
    addToEventLog('Failed to create connection object. ' + e, 'error');
    return;
  }

  try {
    await transport.ready;
    addToEventLog('Connection ready.');
  } catch (e) {
    addToEventLog('Connection failed. ' + e, 'error');
    return;
  }

  transport.closed
      .then(() => {
        addToEventLog('Connection closed normally.');
      })
      .catch(() => {
        addToEventLog('Connection closed abruptly.', 'error');
      });

  currentTransport = transport;
  streamNumber = 1;
  try {
    currentTransportDatagramWriter = transport.datagrams.writable.getWriter();
    addToEventLog('Datagram writer ready.');
  } catch (e) {
    addToEventLog('Sending datagrams not supported: ' + e, 'error');
    return;
  }
  readDatagrams(transport);
  acceptUnidirectionalStreams(transport);
  document.forms.sending.elements.send.disabled = false;
  document.getElementById('connect').disabled = true;
}

// "Send data" button handler.
async function sendData() {
  let form = document.forms.sending.elements;
  let encoder = new TextEncoder('utf-8');
  let rawData = sending.data.value;
  let data = encoder.encode(rawData);
  let transport = currentTransport;
  try {
    switch (form.sendtype.value) {
      case 'datagram':
        await currentTransportDatagramWriter.write(data);
        addToEventLog('Sent datagram: ' + rawData);
        break;
      case 'unidi': {
        let stream = await transport.createUnidirectionalStream();
        let writer = stream.getWriter();
        await writer.write(data);
        await writer.close();
        addToEventLog('Sent a unidirectional stream with data: ' + rawData);
        break;
      }
      case 'bidi': {
        let stream = await transport.createBidirectionalStream();
        let number = streamNumber++;
        readFromIncomingStream(stream, number);

        let writer = stream.writable.getWriter();
        await writer.write(data);
        await writer.close();
        addToEventLog(
            'Opened bidirectional stream #' + number +
            ' with data: ' + rawData);
        break;
      }
    }
  } catch (e) {
    addToEventLog('Error while sending data: ' + e, 'error');
  }
}

// Reads datagrams from |transport| into the event log until EOF is reached.
async function readDatagrams(transport) {
  try {
    var reader = transport.datagrams.readable.getReader();
    addToEventLog('Datagram reader ready.');
  } catch (e) {
    addToEventLog('Receiving datagrams not supported: ' + e, 'error');
    return;
  }
  let decoder = new TextDecoder('utf-8');
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        addToEventLog('Done reading datagrams!');
        return;
      }
      let data = decoder.decode(value);
      addToEventLog('Datagram received: ' + data);
    }
  } catch (e) {
    addToEventLog('Error while reading datagrams: ' + e, 'error');
  }
}

async function acceptUnidirectionalStreams(transport) {
  let reader = transport.incomingUnidirectionalStreams.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        addToEventLog('Done accepting unidirectional streams!');
        return;
      }
      let stream = value;
      let number = streamNumber++;
      addToEventLog('New incoming unidirectional stream #' + number);
      readFromIncomingStream(stream, number);
    }
  } catch (e) {
    addToEventLog('Error while accepting streams: ' + e, 'error');
  }
}

async function readFromIncomingStream(stream, number) {
  let decoder = new TextDecoderStream('utf-8');
  let reader = stream.pipeThrough(decoder).getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        addToEventLog('Stream #' + number + ' closed');
        return;
      }
      let data = value;
      addToEventLog('Received data on stream #' + number + ': ' + data);
    }
  } catch (e) {
    addToEventLog(
        'Error while reading from stream #' + number + ': ' + e, 'error');
    addToEventLog('    ' + e.message);
  }
}

function addToEventLog(text, severity = 'info') {
  let log = document.getElementById('event-log');
  let mostRecentEntry = log.lastElementChild;
  let entry = document.createElement('li');
  entry.innerText = text;
  entry.className = 'log-' + severity;
  log.appendChild(entry);

  // If the most recent entry in the log was visible, scroll the log to the
  // newly added element.
  if (mostRecentEntry != null &&
      mostRecentEntry.getBoundingClientRect().top <
          log.getBoundingClientRect().bottom) {
    entry.scrollIntoView();
  }
}
"#;
}
