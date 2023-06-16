use crate::datagram::Datagram;
use crate::driver::request::Request;
use crate::driver::response::Response;
use crate::driver::stream_acceptor::StreamAcceptor;
use crate::driver::streams::biremote::StreamBiRemoteH3;
use crate::driver::streams::biremote::StreamBiRemoteWT;
use crate::driver::streams::qpack::RemoteQPackDecStream;
use crate::driver::streams::qpack::RemoteQPackEncStream;
use crate::driver::streams::session::LocalSessionStream;
use crate::driver::streams::session::RemoteSessionStream;
use crate::driver::streams::settings::LocalSettingsStream;
use crate::driver::streams::settings::RemoteSettingsStream;
use crate::driver::streams::uniremote::StreamUniRemoteH3;
use crate::driver::streams::uniremote::StreamUniRemoteWT;
use crate::driver::streams::ProtoReadError;
use crate::driver::streams::ProtoWriteError;
use crate::driver::streams::Stream;
use crate::driver::utils::varint_w2q;
use crate::driver::utils::WorkerHandler;
use crate::error::SendDatagramError;
use crate::stream::OpeningBiStream;
use crate::stream::OpeningUniStream;
use std::future::pending;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use wtransport_proto::bytes;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::headers::Headers;
use wtransport_proto::ids::SessionId;
use wtransport_proto::stream_header::StreamHeader;
use wtransport_proto::stream_header::StreamKind;

#[derive(Clone, Copy, Debug)]
pub enum DriverError {
    LocallyClosed(ErrorCode),
    NotConnected,
}

pub struct Driver {
    quic_connection: quinn::Connection,
    worker_handler: Mutex<WorkerHandler<DriverError>>,
    ready_uni_streams: Mutex<mpsc::Receiver<StreamUniRemoteWT>>,
    ready_bi_streams: Mutex<mpsc::Receiver<StreamBiRemoteWT>>,
    ready_session_ids: Mutex<mpsc::Receiver<SessionId>>,
}

impl Driver {
    pub async fn init(
        is_server: bool,
        quic_connection: quinn::Connection,
    ) -> Result<Self, DriverError> {
        let stream_acceptor = StreamAcceptor::start(1024, quic_connection.clone());

        let ready_uni_streams = mpsc::channel(1);
        let ready_bi_streams = mpsc::channel(1);
        let ready_session_ids = mpsc::channel(1);

        let worker_handler = WorkerHandler::spawn({
            let quic_connection = quic_connection.clone();

            async move {
                DriverWorker {
                    is_server,
                    quic_connection,
                    stream_acceptor,
                    local_settings_stream: None,
                    remote_settings_stream: None,
                    remote_qpack_enc_stream: None,
                    remote_qpack_dec_stream: None,
                    local_session_stream: None,
                    remote_session_stream: None,
                    ready_uni_streams: ready_uni_streams.0,
                    ready_bi_streams: ready_bi_streams.0,
                    ready_session_ids: ready_session_ids.0,
                }
                .run()
                .await
            }
        });

        Ok(Self {
            quic_connection,
            worker_handler: Mutex::new(worker_handler),
            ready_bi_streams: Mutex::new(ready_bi_streams.1),
            ready_uni_streams: Mutex::new(ready_uni_streams.1),
            ready_session_ids: Mutex::new(ready_session_ids.1),
        })
    }

    pub async fn accept_session_id(&self) -> Result<SessionId, DriverError> {
        let mut lock = self.ready_session_ids.lock().await;
        match lock.recv().await {
            Some(session_id) => Ok(session_id),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn accept_uni(&self) -> Result<StreamUniRemoteWT, DriverError> {
        let mut lock = self.ready_uni_streams.lock().await;
        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn accept_bi(&self) -> Result<StreamBiRemoteWT, DriverError> {
        let mut lock = self.ready_bi_streams.lock().await;
        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn receive_datagram(&self, session_id: SessionId) -> Result<Datagram, DriverError> {
        loop {
            let quic_dgram = match self.quic_connection.read_datagram().await {
                Ok(quic_dgram) => quic_dgram,
                Err(_) => return Err(self.result().await),
            };

            match Datagram::read(session_id, quic_dgram) {
                Ok(Some(datagram)) => return Ok(datagram),
                Ok(None) => continue,
                Err(error_code) => {
                    let mut lock = self.worker_handler.lock().await;

                    let error = lock
                        .abort_with_result(DriverError::LocallyClosed(error_code))
                        .await;

                    if let DriverError::LocallyClosed(error_code) = error {
                        self.quic_connection
                            .close(varint_w2q(error_code.to_code()), b"");
                    }

                    return Err(error);
                }
            }
        }
    }

    pub async fn open_uni(&self, session_id: SessionId) -> Result<OpeningUniStream, DriverError> {
        let quic_stream = Stream::open_uni(&self.quic_connection)
            .await
            .ok_or(DriverError::NotConnected)?;

        Ok(OpeningUniStream::new(session_id, quic_stream))
    }

    pub async fn open_bi(&self, session_id: SessionId) -> Result<OpeningBiStream, DriverError> {
        let quic_stream = Stream::open_bi(&self.quic_connection)
            .await
            .ok_or(DriverError::NotConnected)?;

        Ok(OpeningBiStream::new(session_id, quic_stream))
    }

    pub fn send_datagram(
        &self,
        session_id: SessionId,
        payload: &[u8],
    ) -> Result<(), SendDatagramError> {
        let datagram = Datagram::write(session_id, payload);

        match self
            .quic_connection
            .send_datagram(datagram.into_quic_bytes())
        {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::UnsupportedByPeer) => {
                Err(SendDatagramError::UnsupportedByPeer)
            }
            Err(quinn::SendDatagramError::Disabled) => {
                unreachable!()
            }

            Err(quinn::SendDatagramError::TooLarge) => Err(SendDatagramError::TooLarge),
            Err(quinn::SendDatagramError::ConnectionLost(_)) => {
                Err(SendDatagramError::NotConnected)
            }
        }
    }

    pub async fn result(&self) -> DriverError {
        let mut lock = self.worker_handler.lock().await;
        lock.result().await
    }
}

struct DriverWorker {
    is_server: bool,
    quic_connection: quinn::Connection,
    stream_acceptor: StreamAcceptor,
    local_settings_stream: Option<LocalSettingsStream>,
    remote_settings_stream: Option<RemoteSettingsStream>,
    remote_qpack_enc_stream: Option<RemoteQPackEncStream>,
    remote_qpack_dec_stream: Option<RemoteQPackDecStream>,
    local_session_stream: Option<LocalSessionStream>,
    remote_session_stream: Option<RemoteSessionStream>,
    ready_uni_streams: mpsc::Sender<StreamUniRemoteWT>,
    ready_bi_streams: mpsc::Sender<StreamBiRemoteWT>,
    ready_session_ids: mpsc::Sender<SessionId>,
}

impl DriverWorker {
    async fn run(mut self) -> DriverError {
        let driver_error = self.run_impl().await;

        if let Err(DriverError::LocallyClosed(error_code)) = &driver_error {
            self.quic_connection
                .close(varint_w2q(error_code.to_code()), b"");
        }

        driver_error.unwrap_err()
    }

    async fn run_impl(&mut self) -> Result<(), DriverError> {
        let mut inc_session = mpsc::channel(1);

        self.send_settings().await?;

        if !self.is_server {
            self.send_session().await?;
        }

        loop {
            tokio::select! {
                driver_error = Self::ctrl_streams_error(&mut self.local_settings_stream,
                                                        &mut self.remote_settings_stream,
                                                        &mut self.remote_qpack_enc_stream,
                                                        &mut self.remote_qpack_dec_stream,
                                                        &mut self.local_session_stream,
                                                        &mut self.remote_session_stream) => {
                    return Err(driver_error);
                }
                result = self.stream_acceptor.accept_uni_h3() => {
                    let stream_uni_remote_h3 = result?;
                    self.handle_uni_stream_h3(stream_uni_remote_h3)?;
                }
                result = self.stream_acceptor.accept_bi_h3() => {
                    let (stream_bi_remote_h3, first_frame) = result?;
                    self.handle_bi_stream_h3(stream_bi_remote_h3, first_frame, &inc_session.0)?
                }
                result = Self::accept_uni_wt(&self.stream_acceptor, &self.ready_uni_streams) => {
                    result?;
                }
                result = Self::accept_bi_wt(&self.stream_acceptor, &self.ready_bi_streams) => {
                    result?;
                }
                inc_session = inc_session.1.recv() => {
                    let slot = match self.ready_session_ids.try_reserve() {
                        Ok(slot) => slot,
                        Err(mpsc::error::TrySendError::Closed(_)) => return Err(DriverError::NotConnected),
                        Err(mpsc::error::TrySendError::Full(_)) => unreachable!(),
                    };
                    let remote_session_stream = inc_session.expect("Sender cannot be dropped")?;
                    self.remote_session_stream = Some(remote_session_stream);
                    slot.send(self.remote_session_stream.as_ref().expect("Just set").session_id());

                }
            }
        }
    }

    async fn send_settings(&mut self) -> Result<(), DriverError> {
        debug_assert!(self.local_settings_stream.is_none());

        let h3_stream = match Stream::open_uni(&self.quic_connection)
            .await
            .ok_or(DriverError::NotConnected)?
            .upgrade(StreamHeader::new_control())
            .await
        {
            Ok(h3_stream) => h3_stream,
            Err(ProtoWriteError::NotConnected) => return Err(DriverError::NotConnected),
            Err(ProtoWriteError::Stopped) => {
                return Err(DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream));
            }
        };

        let mut local_settings_stream = LocalSettingsStream::new(h3_stream);

        match local_settings_stream.send_settings().await {
            Ok(()) => {
                self.local_settings_stream = Some(local_settings_stream);
                Ok(())
            }
            Err(ProtoWriteError::NotConnected) => Err(DriverError::NotConnected),
            Err(ProtoWriteError::Stopped) => {
                Err(DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream))
            }
        }
    }

    async fn send_session(&mut self) -> Result<(), DriverError> {
        debug_assert!(self.local_session_stream.is_none());

        let slot = match self.ready_session_ids.try_reserve() {
            Ok(slot) => slot,
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(DriverError::NotConnected),
            Err(mpsc::error::TrySendError::Full(_)) => unreachable!(),
        };

        let mut h3_stream = Stream::open_bi(&self.quic_connection)
            .await
            .ok_or(DriverError::NotConnected)?
            .upgrade();

        let request = Request::new_webtransport();

        match h3_stream
            .write_frame(request.headers().generate_frame(h3_stream.id()))
            .await
        {
            Ok(()) => {}
            Err(ProtoWriteError::Stopped) => {
                return Err(DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream));
            }
            Err(ProtoWriteError::NotConnected) => {
                return Err(DriverError::NotConnected);
            }
        }

        let frame = match h3_stream.read_frame().await {
            Ok(frame) => frame,
            Err(ProtoReadError::H3(error_code)) => {
                return Err(DriverError::LocallyClosed(error_code))
            }
            Err(ProtoReadError::IO(io_error)) => match io_error {
                bytes::IoReadError::ImmediateFin
                | bytes::IoReadError::UnexpectedFin
                | bytes::IoReadError::Reset => {
                    return Err(DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream));
                }
                bytes::IoReadError::NotConnected => {
                    return Err(DriverError::NotConnected);
                }
            },
        };

        let headers = match frame.kind() {
            FrameKind::Headers => {
                Headers::with_frame(&frame, h3_stream.id()).map_err(DriverError::LocallyClosed)?
            }
            _ => {
                return Err(DriverError::LocallyClosed(ErrorCode::FrameUnexpected));
            }
        };

        let response_code = Response::with_headers(headers).status()?;

        if !(200..300).contains(&response_code) {
            return Err(DriverError::LocallyClosed(ErrorCode::RequestRejected));
        }

        self.local_session_stream = Some(LocalSessionStream::new(h3_stream));

        slot.send(
            self.local_session_stream
                .as_ref()
                .expect("Just set")
                .session_id(),
        );

        Ok(())
    }

    async fn ctrl_streams_error(
        local_settings: &mut Option<LocalSettingsStream>,
        remote_settings: &mut Option<RemoteSettingsStream>,
        remote_qpack_enc: &mut Option<RemoteQPackEncStream>,
        remote_qpack_dec: &mut Option<RemoteQPackDecStream>,
        local_session: &mut Option<LocalSessionStream>,
        remote_session: &mut Option<RemoteSessionStream>,
    ) -> DriverError {
        let local_settings_err = async {
            match local_settings {
                Some(s) => s.done().await,
                None => pending().await,
            }
        };

        let remote_settings_err = async {
            match remote_settings {
                Some(s) => s.done().await,
                None => pending().await,
            }
        };

        let remote_qpack_enc_err = async {
            match remote_qpack_enc {
                Some(s) => s.done().await,
                None => pending().await,
            }
        };

        let remote_qpack_dec_err = async {
            match remote_qpack_dec {
                Some(s) => s.done().await,
                None => pending().await,
            }
        };

        let local_session_err = async {
            match local_session {
                Some(s) => s.done().await,
                None => pending().await,
            }
        };

        let remote_session_err = async {
            match remote_session {
                Some(s) => s.done().await,
                None => pending().await,
            }
        };

        tokio::select! {
            error = local_settings_err => error,
            error = remote_settings_err => error,
            error = remote_qpack_enc_err => error,
            error = remote_qpack_dec_err => error,
            error = local_session_err => error,
            error = remote_session_err => error,
        }
    }

    fn handle_uni_stream_h3(&mut self, stream: StreamUniRemoteH3) -> Result<(), DriverError> {
        match stream.kind() {
            StreamKind::Control => {
                if self.remote_session_stream.is_some() {
                    return Err(DriverError::LocallyClosed(ErrorCode::StreamCreation));
                }
                self.remote_settings_stream = Some(RemoteSettingsStream::new(stream));
            }
            StreamKind::QPackEncoder => {
                if self.remote_qpack_enc_stream.is_some() {
                    return Err(DriverError::LocallyClosed(ErrorCode::StreamCreation));
                }
                self.remote_qpack_enc_stream = Some(RemoteQPackEncStream::new(stream));
            }
            StreamKind::QPackDecoder => {
                if self.remote_qpack_dec_stream.is_some() {
                    return Err(DriverError::LocallyClosed(ErrorCode::StreamCreation));
                }
                self.remote_qpack_dec_stream = Some(RemoteQPackDecStream::new(stream));
            }
            StreamKind::WebTransport => unreachable!(),
            StreamKind::Exercise(_) => {}
        }

        Ok(())
    }

    fn handle_bi_stream_h3(
        &mut self,
        stream: StreamBiRemoteH3,
        first_frame: Frame<'static>,
        inc_session: &mpsc::Sender<Result<RemoteSessionStream, DriverError>>,
    ) -> Result<(), DriverError> {
        match first_frame.kind() {
            FrameKind::Data => Ok(()),
            FrameKind::Headers => {
                let headers = match Headers::with_frame(&first_frame, stream.id()) {
                    Ok(headers) => headers,
                    Err(error_code) => return Err(DriverError::LocallyClosed(error_code)),
                };

                self.process_h3_request(stream, headers, inc_session)
            }
            FrameKind::Settings => Err(DriverError::LocallyClosed(ErrorCode::FrameUnexpected)),
            FrameKind::WebTransport => unreachable!(),
            FrameKind::Exercise(_) => Ok(()),
        }
    }

    async fn accept_uni_wt(
        stream_acceptor: &StreamAcceptor,
        ready_uni_streams: &mpsc::Sender<StreamUniRemoteWT>,
    ) -> Result<(), DriverError> {
        let slot = match ready_uni_streams.clone().reserve_owned().await {
            Ok(slot) => slot,
            Err(mpsc::error::SendError(_)) => return Err(DriverError::NotConnected),
        };

        let stream = stream_acceptor.accept_uni_wt().await?;

        slot.send(stream);

        Ok(())
    }

    async fn accept_bi_wt(
        stream_acceptor: &StreamAcceptor,
        ready_bi_streams: &mpsc::Sender<StreamBiRemoteWT>,
    ) -> Result<(), DriverError> {
        let slot = match ready_bi_streams.clone().reserve_owned().await {
            Ok(slot) => slot,
            Err(mpsc::error::SendError(_)) => return Err(DriverError::NotConnected),
        };

        let stream = stream_acceptor.accept_bi_wt().await?;

        slot.send(stream);

        Ok(())
    }

    fn process_h3_request(
        &mut self,
        mut stream: StreamBiRemoteH3,
        headers: Headers,
        inc_session: &mpsc::Sender<Result<RemoteSessionStream, DriverError>>,
    ) -> Result<(), DriverError> {
        if self.is_server {
            if self.remote_session_stream.is_some() {
                stream
                    .stop(ErrorCode::RequestRejected.to_code())
                    .expect("Cannot be already stopped");
                return Ok(());
            }

            let slot = match inc_session.clone().try_reserve_owned() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    stream
                        .stop(ErrorCode::RequestRejected.to_code())
                        .expect("Cannot be already stopped");
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(DriverError::NotConnected);
                }
            };

            tokio::spawn(async move {
                match Request::try_accept_webtransport(stream, headers).await {
                    Ok(Some(session_stream)) => {
                        slot.send(Ok(session_stream));
                    }
                    Ok(None) => {}
                    Err(driver_error) => {
                        slot.send(Err(driver_error));
                    }
                }
            });

            Ok(())
        } else {
            Err(DriverError::LocallyClosed(ErrorCode::StreamCreation))
        }
    }
}

pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod stream_acceptor;
pub(crate) mod streams;
pub(crate) mod utils;
