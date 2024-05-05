use anyhow::Context;
use anyhow::Result;
use wtransport::tls::Sha256DigestFmt;
use wtransport::Identity;

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";

#[tokio::main]
async fn main() -> Result<()> {
    println!("Generating self signed certificate for WebTransport");

    let identity =
        Identity::self_signed(["localhost"]).context("cannot create self signed identity")?;

    println!("Storing certificate to file: '{CERT_FILE}'");

    identity
        .certificate_chain()
        .store_pemfile(CERT_FILE)
        .await
        .context("cannot store certificate chain")?;

    println!("Storing private key to file: '{KEY_FILE}'");

    identity
        .private_key()
        .store_secret_pemfile(KEY_FILE)
        .await
        .context("cannot store private key")?;

    println!(
        "Certificate serial: {}",
        identity.certificate_chain().as_slice()[0].serial()
    );

    println!(
        "Certificate hash: {}",
        identity.certificate_chain().as_slice()[0]
            .hash()
            .fmt(Sha256DigestFmt::BytesArray)
    );

    Ok(())
}
