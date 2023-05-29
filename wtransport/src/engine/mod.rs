use crate::datagram::Datagram;
use crate::datagram::DgramError;
use crate::engine::session::SessionLocalRequest;
use crate::engine::session::SessionRemoteRequest;
use crate::engine::stream::BiLocal;
use crate::engine::stream::BiRemote;
use crate::engine::stream::Stream;
use crate::engine::stream::UniLocal;
use crate::engine::stream::UniRemote;
use crate::engine::stream::Wt;
use crate::engine::worker::Worker;
use crate::engine::worker::WorkerError;
use crate::engine::worker::WorkerHandler;
use crate::error::DatagramError;
use crate::error::H3Code;
use crate::error::H3Error;
use quinn::VarInt;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::sync::Mutex;
use wtransport_proto::frame::SessionId;
use wtransport_proto::settings::Settings;
use wtransport_proto::stream::StreamHeader;
use wtransport_proto::stream::StreamKind;

pub(crate) struct Engine {
    quic_connection: quinn::Connection,
    worker_handle: Mutex<WorkerHandler>,
    settings_channel: Mutex<watch::Receiver<Option<Settings>>>,
    bi_streams_channel: Mutex<mpsc::Receiver<Stream<BiRemote, Wt>>>,
    uni_streams_channel: Mutex<mpsc::Receiver<Stream<UniRemote, Wt>>>,
    session_streams_channel: Mutex<mpsc::Receiver<SessionRemoteRequest>>,
}

impl Engine {
    pub fn new(quic_connection: quinn::Connection) -> Self {
        let settings_channel = watch::channel(None);
        let bi_streams_channel = mpsc::channel(1024);
        let uni_streams_channel = mpsc::channel(1024);
        let session_streams_channel = mpsc::channel(1);

        let worker = Worker::new(
            quic_connection.clone(),
            settings_channel.0,
            bi_streams_channel.0,
            uni_streams_channel.0,
            session_streams_channel.0,
        );

        let worker_handle = WorkerHandler::run_worker(worker);

        Self {
            quic_connection,
            worker_handle: Mutex::new(worker_handle),
            settings_channel: Mutex::new(settings_channel.1),
            bi_streams_channel: Mutex::new(bi_streams_channel.1),
            uni_streams_channel: Mutex::new(uni_streams_channel.1),
            session_streams_channel: Mutex::new(session_streams_channel.1),
        }
    }

    pub async fn remote_settings(&self) -> Result<Settings, WorkerError> {
        let mut lock = self.settings_channel.lock().await;
        loop {
            if let Some(settings) = lock.borrow().as_ref() {
                return Ok(settings.clone());
            }

            if lock.changed().await.is_err() {
                return Err(self.worker_result().await);
            }
        }
    }

    pub async fn accept_session(&self) -> Result<SessionRemoteRequest, WorkerError> {
        let mut lock = self.session_streams_channel.lock().await;
        match lock.recv().await {
            Some(session_remote_request) => Ok(session_remote_request),
            None => Err(self.worker_result().await),
        }
    }

    pub async fn connect_session(&self) -> Result<SessionLocalRequest, WorkerError> {
        let stream = match Stream::open_bi(&self.quic_connection).await {
            Some(stream) => stream.upgrade(),
            None => return Err(self.worker_result().await),
        };

        Ok(SessionLocalRequest::new(stream))
    }

    pub async fn accept_bi(&self) -> Result<Stream<BiRemote, Wt>, WorkerError> {
        let mut lock = self.bi_streams_channel.lock().await;
        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => Err(self.worker_result().await),
        }
    }

    pub async fn accept_uni(&self) -> Result<Stream<UniRemote, Wt>, WorkerError> {
        let mut lock = self.uni_streams_channel.lock().await;
        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => Err(self.worker_result().await),
        }
    }

    pub async fn open_bi(&self, session_id: SessionId) -> Result<Stream<BiLocal, Wt>, WorkerError> {
        let stream = match Stream::open_bi(&self.quic_connection).await {
            Some(stream) => stream,
            None => return Err(self.worker_result().await),
        };

        match stream.upgrade().upgrade(session_id).await {
            Ok(stream) => Ok(stream),
            Err(_) => Err(self.worker_result().await),
        }
    }

    pub async fn open_uni(
        &self,
        session_id: SessionId,
    ) -> Result<Stream<UniLocal, Wt>, WorkerError> {
        let stream = match Stream::open_uni(&self.quic_connection).await {
            Some(stream) => stream,
            None => return Err(self.worker_result().await),
        };

        match stream
            .upgrade(StreamHeader::new(
                StreamKind::WebTransport,
                Some(session_id),
            ))
            .await
        {
            Ok(stream) => Ok(stream.upgrade()),
            Err(_) => Err(self.worker_result().await),
        }
    }

    pub async fn receive_datagram(&self, session_id: SessionId) -> Result<Datagram, WorkerError> {
        loop {
            let quic_dgram = match self.quic_connection.read_datagram().await {
                Ok(quic_dgram) => quic_dgram,
                Err(_) => return Err(self.worker_result().await),
            };

            if let Some(dgram) = Datagram::read(quic_dgram, session_id).map_err(|DgramError| {
                WorkerError::LocalClosed(H3Error::new(H3Code::Datagram, "Error reading datagram"))
            })? {
                return Ok(dgram);
            }
        }
    }

    pub async fn send_datagram(
        &self,
        data: &[u8],
        session_id: SessionId,
    ) -> Result<(), DatagramError> {
        let dgram = Datagram::write(data, session_id);

        self.quic_connection
            .send_datagram(dgram.into_quic_bytes())?;
        Ok(())
    }

    async fn worker_result(&self) -> WorkerError {
        let mut lock = self.worker_handle.lock().await;
        lock.result().await
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.quic_connection.close(VarInt::from_u32(0), b"");
        // TODO(bfesta): if not mutex-ed maybe we should abort the worker
    }
}

pub(crate) mod session;
pub(crate) mod stream;
pub(crate) mod worker;
