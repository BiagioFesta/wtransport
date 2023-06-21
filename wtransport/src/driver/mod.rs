use self::result::DriverError;
use self::result::DriverHandler;
use self::result::DriverResultSet;
use self::worker::Worker;
use crate::datagram::Datagram;
use crate::driver::streams::biremote::StreamBiRemoteWT;
use crate::driver::streams::uniremote::StreamUniRemoteWT;
use crate::driver::streams::Stream;
use crate::error::SendDatagramError;
use crate::session::SessionInfo;
use crate::stream::OpeningBiStream;
use crate::stream::OpeningUniStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::ids::SessionId;

pub struct Driver {
    quic_connection: quinn::Connection,
    ready_sessions: Mutex<mpsc::Receiver<SessionInfo>>,
    ready_uni_wt_streams: Mutex<mpsc::Receiver<StreamUniRemoteWT>>,
    ready_bi_wt_streams: Mutex<mpsc::Receiver<StreamBiRemoteWT>>,
    driver_handler: result::DriverHandler,
}

impl Driver {
    pub fn init(is_server: bool, quic_connection: quinn::Connection) -> Self {
        let ready_sessions = mpsc::channel(1);
        let ready_uni_wt_streams = mpsc::channel(4);
        let ready_bi_wt_streams = mpsc::channel(1);
        let driver_handler = DriverHandler::new();

        tokio::spawn(
            Worker::new(
                is_server,
                quic_connection.clone(),
                ready_sessions.0,
                ready_uni_wt_streams.0,
                ready_bi_wt_streams.0,
                driver_handler.setter(),
            )
            .run(),
        );

        Self {
            quic_connection,
            ready_sessions: Mutex::new(ready_sessions.1),
            ready_uni_wt_streams: Mutex::new(ready_uni_wt_streams.1),
            ready_bi_wt_streams: Mutex::new(ready_bi_wt_streams.1),
            driver_handler,
        }
    }

    pub async fn accept_session(&self) -> Result<SessionInfo, DriverError> {
        let mut lock = self.ready_sessions.lock().await;

        match lock.recv().await {
            Some(session_info) => Ok(session_info),
            None => {
                drop(lock);
                Err(self.driver_handler.result().await)
            }
        }
    }

    pub async fn accept_uni(&self) -> Result<StreamUniRemoteWT, DriverError> {
        let mut lock = self.ready_uni_wt_streams.lock().await;

        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => {
                drop(lock);
                Err(self.driver_handler.result().await)
            }
        }
    }

    pub async fn accept_bi(&self) -> Result<StreamBiRemoteWT, DriverError> {
        let mut lock = self.ready_bi_wt_streams.lock().await;

        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => {
                drop(lock);
                Err(self.driver_handler.result().await)
            }
        }
    }

    pub async fn receive_datagram(&self, session_id: SessionId) -> Result<Datagram, DriverError> {
        loop {
            let quic_dgram = match self.quic_connection.read_datagram().await {
                Ok(quic_dgram) => quic_dgram,
                Err(_) => return Err(self.driver_handler.result().await),
            };

            match Datagram::read(session_id, quic_dgram) {
                Ok(Some(datagram)) => return Ok(datagram),
                Ok(None) => continue,
                Err(error_code) => {
                    self.driver_handler
                        .set_proto_error(error_code, &self.quic_connection);
                    return Err(self.driver_handler.result().await);
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
}

mod worker {
    use super::*;
    use crate::driver::request::MalformedRequest;
    use crate::driver::request::Request;
    use crate::driver::response::Response;
    use crate::driver::streams::biremote::StreamBiRemoteH3;
    use crate::driver::streams::qpack::RemoteQPackDecStream;
    use crate::driver::streams::qpack::RemoteQPackEncStream;
    use crate::driver::streams::session::SessionStream;
    use crate::driver::streams::settings::LocalSettingsStream;
    use crate::driver::streams::settings::RemoteSettingsStream;
    use crate::driver::streams::uniremote::StreamUniRemoteH3;
    use crate::driver::streams::ProtoReadError;
    use crate::driver::streams::ProtoWriteError;
    use wtransport_proto::bytes;
    use wtransport_proto::frame::Frame;
    use wtransport_proto::frame::FrameKind;
    use wtransport_proto::headers::Headers;
    use wtransport_proto::settings::Settings;
    use wtransport_proto::stream_header::StreamHeader;
    use wtransport_proto::stream_header::StreamKind;

    pub struct Worker {
        is_server: bool,
        quic_connection: quinn::Connection,
        ready_sessions: mpsc::Sender<SessionInfo>,
        ready_uni_wt_streams: mpsc::Sender<StreamUniRemoteWT>,
        ready_bi_wt_streams: mpsc::Sender<StreamBiRemoteWT>,
        driver_result_set: DriverResultSet,
        local_settings_stream: LocalSettingsStream,
        remote_settings_stream: RemoteSettingsStream,
        remote_qpack_enc_stream: RemoteQPackEncStream,
        remote_qpack_dec_stream: RemoteQPackDecStream,
        session_stream: SessionStream,
    }

    impl Worker {
        pub fn new(
            is_server: bool,
            quic_connection: quinn::Connection,
            ready_sessions: mpsc::Sender<SessionInfo>,
            ready_uni_wt_streams: mpsc::Sender<StreamUniRemoteWT>,
            ready_bi_wt_streams: mpsc::Sender<StreamBiRemoteWT>,
            driver_result_set: DriverResultSet,
        ) -> Self {
            Self {
                is_server,
                quic_connection,
                ready_sessions,
                ready_uni_wt_streams,
                ready_bi_wt_streams,
                driver_result_set,
                local_settings_stream: LocalSettingsStream::empty(),
                remote_settings_stream: RemoteSettingsStream::empty(),
                remote_qpack_enc_stream: RemoteQPackEncStream::empty(),
                remote_qpack_dec_stream: RemoteQPackDecStream::empty(),
                session_stream: SessionStream::empty(),
            }
        }

        pub async fn run(mut self) {
            let error = self
                .run_impl()
                .await
                .expect_err("Worker must return an error");

            match error {
                DriverError::Proto(error_code) => {
                    self.driver_result_set
                        .set_proto_error(error_code, &self.quic_connection);
                }
                DriverError::NotConnected => {
                    self.driver_result_set.set_not_connected();
                }
            }
        }

        async fn run_impl(&mut self) -> Result<(), DriverError> {
            let mut remote_settings_watcher = self.remote_settings_stream.subscribe();
            let mut ready_uni_h3_streams = mpsc::channel(4);
            let mut ready_bi_h3_streams = mpsc::channel(1);
            let mut incoming_sessions = mpsc::channel(1);

            self.open_and_send_settings().await?;

            loop {
                tokio::select! {
                    result = Self::accept_uni(&self.quic_connection,
                                              &ready_uni_h3_streams.0,
                                              &self.ready_uni_wt_streams) => {
                        result?;
                    }

                    result = Self::accept_bi(&self.quic_connection,
                                             &ready_bi_h3_streams.0,
                                             &self.ready_bi_wt_streams) => {
                        result?;
                    }

                    uni_h3_stream = ready_uni_h3_streams.1.recv() => {
                        let uni_h3_stream = uni_h3_stream.expect("Sender cannot be dropped")?;
                        self.handle_uni_h3_stream(uni_h3_stream)?;
                    }

                    bi_h3_stream = ready_bi_h3_streams.1.recv() => {
                        let (bi_h3_stream, first_frame) = bi_h3_stream.expect("Sender cannot be dropped")?;
                        self.handle_bi_h3_stream(bi_h3_stream, first_frame, &incoming_sessions.0)?;
                    }

                    error = Self::run_control_streams(&mut self.local_settings_stream,
                                                      &mut self.remote_settings_stream,
                                                      &mut self.remote_qpack_enc_stream,
                                                      &mut self.remote_qpack_dec_stream,
                                                      &mut self.session_stream) => {
                        return Err(error);
                    }

                    settings = remote_settings_watcher.accept_settings() => {
                        let settings = settings.expect("Channel cannot be dropped");
                        self.handle_remote_settings(settings, &incoming_sessions.0)?;
                    }

                    incoming_session = incoming_sessions.1.recv() => {
                        let incoming_session = incoming_session.expect("Sender cannot be dropped")?;
                        self.handle_incoming_session(incoming_session)?;
                    }

                    () = self.driver_result_set.closed() => {
                        return Err(DriverError::NotConnected);
                    }
                }
            }
        }

        async fn open_and_send_settings(&mut self) -> Result<(), DriverError> {
            assert!(self.local_settings_stream.is_empty());

            let stream = match Stream::open_uni(&self.quic_connection)
                .await
                .ok_or(DriverError::NotConnected)?
                .upgrade(StreamHeader::new_control())
                .await
            {
                Ok(h3_stream) => h3_stream,
                Err(ProtoWriteError::NotConnected) => return Err(DriverError::NotConnected),
                Err(ProtoWriteError::Stopped) => {
                    return Err(DriverError::Proto(ErrorCode::ClosedCriticalStream));
                }
            };

            self.local_settings_stream.set_stream(stream);
            self.local_settings_stream.send_settings().await
        }

        async fn accept_uni(
            quic_connection: &quinn::Connection,
            ready_uni_h3_streams: &mpsc::Sender<Result<StreamUniRemoteH3, DriverError>>,
            ready_uni_wt_streams: &mpsc::Sender<StreamUniRemoteWT>,
        ) -> Result<(), DriverError> {
            let h3_slot = ready_uni_h3_streams
                .clone()
                .reserve_owned()
                .await
                .expect("Receiver cannot be dropped");

            let wt_slot = match ready_uni_wt_streams.clone().reserve_owned().await {
                Ok(wt_slot) => wt_slot,
                Err(mpsc::error::SendError(_)) => return Err(DriverError::NotConnected),
            };

            let stream_quic = Stream::accept_uni(quic_connection)
                .await
                .ok_or(DriverError::NotConnected)?;

            tokio::spawn(async move {
                let stream_h3 = match stream_quic.upgrade().await {
                    Ok(stream_h3) => stream_h3,
                    Err(ProtoReadError::H3(error_code)) => {
                        h3_slot.send(Err(DriverError::Proto(error_code)));
                        return;
                    }
                    Err(ProtoReadError::IO(_)) => {
                        return;
                    }
                };

                if matches!(stream_h3.kind(), StreamKind::WebTransport) {
                    let stream_wt = stream_h3.upgrade();
                    wt_slot.send(stream_wt);
                } else {
                    h3_slot.send(Ok(stream_h3));
                }
            });

            Ok(())
        }

        async fn accept_bi(
            quic_connection: &quinn::Connection,
            ready_bi_h3_streams: &mpsc::Sender<
                Result<(StreamBiRemoteH3, Frame<'static>), DriverError>,
            >,
            ready_bi_wt_streams: &mpsc::Sender<StreamBiRemoteWT>,
        ) -> Result<(), DriverError> {
            let h3_slot = ready_bi_h3_streams
                .clone()
                .reserve_owned()
                .await
                .expect("Receiver cannot be dropped");

            let wt_slot = match ready_bi_wt_streams.clone().reserve_owned().await {
                Ok(wt_slot) => wt_slot,
                Err(mpsc::error::SendError(_)) => return Err(DriverError::NotConnected),
            };

            let stream_quic = Stream::accept_bi(quic_connection)
                .await
                .ok_or(DriverError::NotConnected)?;

            tokio::spawn(async move {
                let mut stream_h3 = stream_quic.upgrade();

                let frame = match stream_h3.read_frame().await {
                    Ok(frame) => frame,
                    Err(ProtoReadError::H3(error_code)) => {
                        h3_slot.send(Err(DriverError::Proto(error_code)));
                        return;
                    }
                    Err(ProtoReadError::IO(_)) => {
                        return;
                    }
                };

                match frame.session_id() {
                    Some(session_id) => {
                        let stream_wt = stream_h3.upgrade(session_id);
                        wt_slot.send(stream_wt);
                    }
                    None => {
                        h3_slot.send(Ok((stream_h3, frame)));
                    }
                }
            });

            Ok(())
        }

        fn handle_uni_h3_stream(&mut self, stream: StreamUniRemoteH3) -> Result<(), DriverError> {
            match stream.kind() {
                StreamKind::Control => {
                    if !self.remote_settings_stream.is_empty() {
                        return Err(DriverError::Proto(ErrorCode::StreamCreation));
                    }

                    self.remote_settings_stream.set_stream(stream);
                }
                StreamKind::QPackEncoder => {
                    if !self.remote_qpack_enc_stream.is_empty() {
                        return Err(DriverError::Proto(ErrorCode::StreamCreation));
                    }

                    self.remote_qpack_enc_stream = RemoteQPackEncStream::with_stream(stream);
                }
                StreamKind::QPackDecoder => {
                    if !self.remote_qpack_dec_stream.is_empty() {
                        return Err(DriverError::Proto(ErrorCode::StreamCreation));
                    }

                    self.remote_qpack_dec_stream = RemoteQPackDecStream::with_stream(stream);
                }
                StreamKind::WebTransport => unreachable!(),
                StreamKind::Exercise(_) => {}
            }

            Ok(())
        }

        fn handle_bi_h3_stream(
            &mut self,
            stream: StreamBiRemoteH3,
            first_frame: Frame<'static>,
            incoming_sessions: &mpsc::Sender<Result<SessionStream, DriverError>>,
        ) -> Result<(), DriverError> {
            match first_frame.kind() {
                FrameKind::Data => {
                    return Err(DriverError::Proto(ErrorCode::FrameUnexpected));
                }
                FrameKind::Headers => {
                    tokio::spawn(Self::handle_h3_request(
                        stream,
                        first_frame,
                        incoming_sessions.clone(),
                    ));
                }
                FrameKind::Settings => {
                    return Err(DriverError::Proto(ErrorCode::FrameUnexpected));
                }
                FrameKind::WebTransport => unreachable!(),
                FrameKind::Exercise(_) => {}
            }

            Ok(())
        }

        fn handle_incoming_session(
            &mut self,
            session_stream: SessionStream,
        ) -> Result<(), DriverError> {
            debug_assert!(!session_stream.is_empty());

            let slot = match self.ready_sessions.try_reserve() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(DriverError::NotConnected),
                Err(mpsc::error::TrySendError::Full(_)) => return Ok(()),
            };

            if self.session_stream.is_empty() {
                self.session_stream = session_stream;
                slot.send(
                    self.session_stream
                        .session_info()
                        .expect("Session is not empty")
                        .clone(),
                );
            }

            Ok(())
        }

        async fn run_control_streams(
            local_settings: &mut LocalSettingsStream,
            remote_settings: &mut RemoteSettingsStream,
            remote_qpack_enc: &mut RemoteQPackEncStream,
            remote_qpack_dec: &mut RemoteQPackDecStream,
            session: &mut SessionStream,
        ) -> DriverError {
            tokio::select! {
                error = local_settings.run() => error,
                error = remote_settings.run() => error,
                error = remote_qpack_enc.run() => error,
                error = remote_qpack_dec.run() => error,
                error = session.run() => error,
            }
        }

        async fn handle_h3_request(
            mut stream: StreamBiRemoteH3,
            first_frame: Frame<'static>,
            incoming_sessions: mpsc::Sender<Result<SessionStream, DriverError>>,
        ) {
            let slot = match incoming_sessions.try_reserve() {
                Ok(slot) => slot,
                Err(_) => {
                    stream
                        .stop(ErrorCode::RequestRejected.to_code())
                        .expect("Stream not already stopped");
                    return;
                }
            };

            let headers = match Headers::with_frame(&first_frame, stream.id()) {
                Ok(headers) => headers,
                Err(error_code) => {
                    slot.send(Err(DriverError::Proto(error_code)));
                    return;
                }
            };

            let request = match Request::with_headers(headers) {
                Ok(request) => request,
                Err(MalformedRequest) => {
                    stream
                        .stop(ErrorCode::Message.to_code())
                        .expect("Stream not already stopped");
                    return;
                }
            };

            if !request.is_webtransport_connect() {
                stream
                    .stop(ErrorCode::RequestRejected.to_code())
                    .expect("Stream not already stopped");
                return;
            }

            let response = Response::new_webtransport(200);

            match stream
                .write_frame(response.headers().generate_frame(stream.id()))
                .await
            {
                Ok(()) => {
                    slot.send(Ok(SessionStream::server(stream)));
                }
                Err(ProtoWriteError::Stopped) => {
                    slot.send(Err(DriverError::Proto(ErrorCode::ClosedCriticalStream)));
                }
                Err(ProtoWriteError::NotConnected) => {
                    slot.send(Err(DriverError::NotConnected));
                }
            }
        }

        fn handle_remote_settings(
            &mut self,
            _settings: Settings,
            incoming_sessions: &mpsc::Sender<Result<SessionStream, DriverError>>,
        ) -> Result<(), DriverError> {
            // TODO(bfesta): validate settings

            if !self.is_server {
                tokio::spawn(Self::send_session_request(
                    self.quic_connection.clone(),
                    incoming_sessions.clone(),
                ));
            }

            Ok(())
        }

        async fn send_session_request(
            quic_connection: quinn::Connection,
            incoming_sessions: mpsc::Sender<Result<SessionStream, DriverError>>,
        ) {
            let slot = match incoming_sessions.try_reserve() {
                Ok(slot) => slot,
                Err(_) => {
                    return;
                }
            };

            let mut stream = match Stream::open_bi(&quic_connection).await {
                Some(quic_stream) => quic_stream.upgrade(),
                None => {
                    slot.send(Err(DriverError::NotConnected));
                    return;
                }
            };

            let request = Request::new_webtransport();

            match stream
                .write_frame(request.headers().generate_frame(stream.id()))
                .await
            {
                Ok(()) => {}
                Err(ProtoWriteError::Stopped) => {
                    slot.send(Err(DriverError::Proto(ErrorCode::ClosedCriticalStream)));
                    return;
                }
                Err(ProtoWriteError::NotConnected) => {
                    slot.send(Err(DriverError::NotConnected));
                    return;
                }
            }

            let frame = match stream.read_frame().await {
                Ok(frame) => frame,
                Err(ProtoReadError::H3(error_code)) => {
                    slot.send(Err(DriverError::Proto(error_code)));
                    return;
                }
                Err(ProtoReadError::IO(io_error)) => match io_error {
                    bytes::IoReadError::ImmediateFin
                    | bytes::IoReadError::UnexpectedFin
                    | bytes::IoReadError::Reset => {
                        slot.send(Err(DriverError::Proto(ErrorCode::ClosedCriticalStream)));
                        return;
                    }
                    bytes::IoReadError::NotConnected => {
                        slot.send(Err(DriverError::NotConnected));
                        return;
                    }
                },
            };

            if !matches!(frame.kind(), FrameKind::Headers) {
                slot.send(Err(DriverError::Proto(ErrorCode::FrameUnexpected)));
                return;
            }

            let headers = match Headers::with_frame(&frame, stream.id()) {
                Ok(headers) => headers,
                Err(error_code) => {
                    slot.send(Err(DriverError::Proto(error_code)));
                    return;
                }
            };

            let response = Response::with_headers(headers);

            match response.status() {
                Some(status) if (200..300).contains(&status) => {
                    slot.send(Ok(SessionStream::client(stream)));
                }
                Some(_) => {
                    slot.send(Err(DriverError::Proto(ErrorCode::RequestRejected)));
                }
                None => {
                    slot.send(Err(DriverError::Proto(ErrorCode::Message)));
                }
            }
        }
    }
}

pub mod result {
    use super::*;
    use crate::driver::utils::varint_w2q;
    use crate::driver::utils::SharedResultGet;
    use crate::driver::utils::SharedResultSet;

    #[derive(Copy, Clone)]
    pub enum DriverError {
        Proto(ErrorCode),
        NotConnected,
    }

    #[derive(Clone)]
    pub struct DriverResultSet(SharedResultSet<DriverError>);

    impl DriverResultSet {
        pub fn set_proto_error(&self, error_code: ErrorCode, quic_connection: &quinn::Connection) {
            if self.0.set(DriverError::Proto(error_code)) {
                quic_connection.close(varint_w2q(error_code.to_code()), b"");
            }
        }

        pub fn set_not_connected(&self) {
            self.0.set(DriverError::NotConnected);
        }

        pub async fn closed(&self) {
            self.0.closed().await
        }
    }

    pub struct DriverHandler {
        result_set: DriverResultSet,
        result_get: SharedResultGet<DriverError>,
    }

    impl DriverHandler {
        pub fn new() -> Self {
            let result_set = DriverResultSet(SharedResultSet::new());
            let result_get = result_set.0.subscribe();

            Self {
                result_set,
                result_get,
            }
        }

        pub fn setter(&self) -> DriverResultSet {
            self.result_set.clone()
        }

        pub fn set_proto_error(&self, error_code: ErrorCode, quic_connection: &quinn::Connection) {
            self.result_set.set_proto_error(error_code, quic_connection)
        }

        pub async fn result(&self) -> DriverError {
            self.result_get
                .result()
                .await
                .expect("Sender cannot be dropped")
        }
    }
}

pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod streams;
pub(crate) mod utils;
