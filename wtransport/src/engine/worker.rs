use crate::engine::session::SessionRemoteRequest;
use crate::engine::stream::BiRemote;
use crate::engine::stream::FrameReadError;
use crate::engine::stream::FrameWriteError;
use crate::engine::stream::QuicRecvStream;
use crate::engine::stream::Raw;
use crate::engine::stream::Stream;
use crate::engine::stream::UniLocal;
use crate::engine::stream::UniRemote;
use crate::engine::stream::UpgradeError;
use crate::engine::stream::Wt;
use crate::engine::stream::H3;
use crate::error::H3Error;
use crate::error::StreamError;
use std::future::pending;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::headers::Headers;
use wtransport_proto::settings::Settings;
use wtransport_proto::stream_header::StreamHeader;
use wtransport_proto::stream_header::StreamKind;
use wtransport_proto::varint::VarInt;

type WorkerResult<T> = Result<T, WorkerError>;

#[derive(Clone, Debug)]
pub(crate) enum WorkerError {
    LocalClosed(H3Error),
    RemoteClosed,
}

pub(super) struct WorkerHandler {
    join_handle: Option<JoinHandle<WorkerResult<()>>>,
    result: Option<WorkerError>,
}

impl WorkerHandler {
    pub(super) fn run_worker(worker: Worker) -> Self {
        let join_handle = tokio::spawn(worker.run());

        Self {
            join_handle: Some(join_handle),
            result: None,
        }
    }

    /// Get the result of the worker. Waits if not completed yet.
    pub(super) async fn result(&mut self) -> WorkerError {
        if let Some(ref result) = self.result {
            return result.clone();
        }

        let result = match self
            .join_handle
            .take()
            .expect("Worker should be still executing")
            .await
        {
            Ok(result) => result.expect_err("Worker cannot return OK"),
            Err(_) => todo!(),
        };

        self.result = Some(result.clone());
        result
    }
}

pub(super) struct Worker {
    quic_connection: quinn::Connection,
    inc_settings_channel: watch::Sender<Option<Settings>>,
    inc_bi_wt_channel: mpsc::Sender<Stream<BiRemote, Wt>>,
    inc_uni_wt_channel: mpsc::Sender<Stream<UniRemote, Wt>>,
    inc_sessions_channel: mpsc::Sender<SessionRemoteRequest>,
}

impl Worker {
    pub(super) fn new(
        quic_connection: quinn::Connection,
        inc_settings_channel: watch::Sender<Option<Settings>>,
        inc_bi_wt_channel: mpsc::Sender<Stream<BiRemote, Wt>>,
        inc_uni_wt_channel: mpsc::Sender<Stream<UniRemote, Wt>>,
        inc_sessions_channel: mpsc::Sender<SessionRemoteRequest>,
    ) -> Self {
        Self {
            quic_connection,
            inc_settings_channel,
            inc_bi_wt_channel,
            inc_uni_wt_channel,
            inc_sessions_channel,
        }
    }

    async fn run(mut self) -> WorkerResult<()> {
        let mut inc_uni_h3_channel = mpsc::channel(1024);
        let mut inc_bi_h3_channel = mpsc::channel(1024);

        let mut local_settings_stream = LocalSettingsStream::new();
        let mut remote_settings_stream = RemoteSettingsStream::new();
        let mut remote_qpack_enc_stream = RemoteQPackEncStream::new();
        let mut remote_qpack_dec_stream = RemoteQPackDecStream::new();

        local_settings_stream
            .on_ready_connection(&self.quic_connection)
            .await?;

        loop {
            tokio::select! {  // TODO(bfesta): add bias to this select. maybe?
                h3_uni = inc_uni_h3_channel.1.recv() => {
                    let h3_uni = h3_uni.expect("Sender cannot be dropped");
                    self.handle_new_h3_uni(h3_uni,
                                           &mut remote_settings_stream,
                                           &mut remote_qpack_enc_stream,
                                           &mut remote_qpack_dec_stream,
                    ).await?;
                }

                h3_bi = inc_bi_h3_channel.1.recv() => {
                    let h3_bi = h3_bi.expect("Sender cannot be dropped");
                    self.handle_new_h3_bi(h3_bi.0, h3_bi.1).await?;
                }

                accept_uni = self.accept_uni(&inc_uni_h3_channel.0) => {
                    let (stream, h3slot, wtslot) = accept_uni?;
                    Self::process_inc_uni(stream, h3slot, wtslot);
                }

                accept_bi = self.accept_bi(&inc_bi_h3_channel.0) => {
                    let (stream, h3slot, wtslot) = accept_bi?;
                    Self::process_inc_bi(stream, h3slot, wtslot);
                }

                error = local_settings_stream.done() => {
                    debug_assert!(error.is_err());
                    return error;
                }

                error = remote_settings_stream.done() => {
                    debug_assert!(error.is_err());
                    return error;
                }

                error = remote_qpack_enc_stream.done() => {
                    debug_assert!(error.is_err());
                    return error;
                }

                error = remote_qpack_dec_stream.done() => {
                    debug_assert!(error.is_err());
                    return error;
                }
            }
        }
    }

    async fn handle_new_h3_uni(
        &mut self,
        stream: Stream<UniRemote, H3>,
        remote_settings_stream: &mut RemoteSettingsStream,
        remote_qpack_enc_stream: &mut RemoteQPackEncStream,
        remote_qpack_dec_stream: &mut RemoteQPackDecStream,
    ) -> WorkerResult<()> {
        match stream.header().kind() {
            StreamKind::Control => {
                remote_settings_stream
                    .on_stream_recv(&self.inc_settings_channel, stream)
                    .await
            }
            StreamKind::QPackEncoder => remote_qpack_enc_stream.on_stream_recv(stream),
            StreamKind::QPackDecoder => remote_qpack_dec_stream.on_stream_recv(stream),
            StreamKind::WebTransport => unreachable!(),
            StreamKind::Exercise(_) => Ok(()),
        }
    }

    async fn handle_new_h3_bi(
        &mut self,
        stream: Stream<BiRemote, H3>,
        first_frame: Frame<'_>,
    ) -> WorkerResult<()> {
        match first_frame.kind() {
            FrameKind::Data => Ok(()),
            FrameKind::Headers => {
                let headers = match Headers::with_frame(&first_frame, stream.id()) {
                    Ok(headers) => headers,
                    Err(h3code) => {
                        return Err(WorkerError::LocalClosed(H3Error::new(
                            h3code,
                            "Error on decoding headers on request",
                        )));
                    }
                };

                let slot = match self.inc_sessions_channel.try_reserve() {
                    Ok(slot) => slot,
                    Err(_) => {
                        stream.stop(ErrorCode::BufferedStreamRejected.to_code());
                        return Ok(());
                    }
                };

                slot.send(SessionRemoteRequest::new(stream, headers));
                Ok(())
            }
            FrameKind::Settings => Err(WorkerError::LocalClosed(H3Error::new(
                ErrorCode::FrameUnexpected,
                "Unexpected SETTINGS frame",
            ))),
            FrameKind::WebTransport => unreachable!(),
            FrameKind::Exercise(_) => Ok(()),
        }
    }

    async fn accept_uni(
        &self,
        h3_channel: &mpsc::Sender<Stream<UniRemote, H3>>,
    ) -> WorkerResult<(
        Stream<UniRemote, Raw>,
        mpsc::OwnedPermit<Stream<UniRemote, H3>>,
        mpsc::OwnedPermit<Stream<UniRemote, Wt>>,
    )> {
        loop {
            let stream = Stream::accept_uni(&self.quic_connection)
                .await
                .ok_or(WorkerError::RemoteClosed)?;

            let h3slot = match h3_channel.clone().try_reserve_owned() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    stream.stop(ErrorCode::BufferedStreamRejected.to_code());
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => unreachable!(),
            };

            let w3slot = match self.inc_uni_wt_channel.clone().try_reserve_owned() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    stream.stop(ErrorCode::BufferedStreamRejected.to_code());
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(WorkerError::RemoteClosed);
                }
            };

            return Ok((stream, h3slot, w3slot));
        }
    }

    async fn accept_bi<'a>(
        &self,
        h3_channel: &mpsc::Sender<(Stream<BiRemote, H3>, Frame<'a>)>,
    ) -> WorkerResult<(
        Stream<BiRemote, Raw>,
        mpsc::OwnedPermit<(Stream<BiRemote, H3>, Frame<'a>)>,
        mpsc::OwnedPermit<Stream<BiRemote, Wt>>,
    )> {
        loop {
            let stream = Stream::accept_bi(&self.quic_connection)
                .await
                .ok_or(WorkerError::RemoteClosed)?;

            let h3slot = match h3_channel.clone().try_reserve_owned() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    stream.stop(ErrorCode::BufferedStreamRejected.to_code());
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => unreachable!(),
            };

            let w3slot = match self.inc_bi_wt_channel.clone().try_reserve_owned() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    stream.stop(ErrorCode::BufferedStreamRejected.to_code());
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(WorkerError::RemoteClosed);
                }
            };

            return Ok((stream, h3slot, w3slot));
        }
    }

    fn process_inc_uni(
        stream: Stream<UniRemote, Raw>,
        h3slot: mpsc::OwnedPermit<Stream<UniRemote, H3>>,
        wtslot: mpsc::OwnedPermit<Stream<UniRemote, Wt>>,
    ) {
        tokio::spawn(async move {
            let stream = match stream.upgrade().await {
                Ok(stream) => stream,
                Err(UpgradeError::UnknownStream) => return,
                Err(UpgradeError::InvalidSessionId) => return,
                Err(UpgradeError::ConnectionClosed) => return,
                Err(UpgradeError::EndOfStream) => return,
            };

            match stream.header().kind() {
                StreamKind::WebTransport => {
                    wtslot.send(stream.upgrade());
                }
                _ => {
                    h3slot.send(stream);
                }
            }
        });
    }

    fn process_inc_bi(
        stream: Stream<BiRemote, Raw>,
        h3slot: mpsc::OwnedPermit<(Stream<BiRemote, H3>, Frame<'static>)>,
        wtslot: mpsc::OwnedPermit<Stream<BiRemote, Wt>>,
    ) {
        tokio::spawn(async move {
            let mut stream = stream.upgrade();

            let frame = match stream.read_frame().await {
                Ok(frame) => frame,
                Err(FrameReadError::UnknownFrame) => return,
                Err(FrameReadError::InvalidSessionId) => return,
                Err(FrameReadError::ConnectionClosed) => return,
                Err(FrameReadError::EndOfStream) => return,
            };

            match frame.session_id() {
                Some(session_id) => {
                    let stream = stream.upgrade(session_id);
                    wtslot.send(stream);
                }
                None => {
                    h3slot.send((stream, frame));
                }
            }
        });
    }
}

struct LocalSettingsStream(Option<Stream<UniLocal, H3>>);

impl LocalSettingsStream {
    fn new() -> Self {
        Self(None)
    }

    async fn on_ready_connection(
        &mut self,
        quic_connection: &quinn::Connection,
    ) -> WorkerResult<()> {
        debug_assert!(self.0.is_none());

        let local_settings = Settings::builder()
            .qpack_max_table_capacity(VarInt::from_u32(0))
            .qpack_blocked_streams(VarInt::from_u32(0))
            .enable_webtransport()
            .enable_h3_datagrams()
            .build();

        let mut stream = Stream::open_uni(quic_connection)
            .await
            .ok_or(WorkerError::RemoteClosed)?
            .upgrade(StreamHeader::new_control())
            .await
            .map_err(|upgrade_error| {
                WorkerError::with_upgrade_err(upgrade_error, "Unable to send SETTINGS")
            })?;

        stream
            .write_frame(local_settings.generate_frame())
            .await
            .map_err(|frame_write_error| {
                WorkerError::with_frame_write_err(frame_write_error, "Unable to send SETTINGS")
            })?;

        self.0 = Some(stream);

        Ok(())
    }

    async fn done(&mut self) -> WorkerResult<()> {
        match self.0 {
            Some(ref mut stream) => match stream.stopped().await {
                Err(StreamError::ConnectionClosed) => Err(WorkerError::RemoteClosed),
                Ok(()) | Err(StreamError::Stopped) => Err(WorkerError::LocalClosed(H3Error::new(
                    ErrorCode::ClosedCriticalStream,
                    "Closed local control stream",
                ))),
            },
            None => pending().await,
        }
    }
}

struct RemoteSettingsStream(Option<Stream<UniRemote, H3>>);

impl RemoteSettingsStream {
    fn new() -> Self {
        Self(None)
    }

    async fn on_stream_recv(
        &mut self,
        inc_settings_channel: &watch::Sender<Option<Settings>>,
        mut stream: Stream<UniRemote, H3>,
    ) -> WorkerResult<()> {
        debug_assert!(matches!(stream.header().kind(), StreamKind::Control));

        if self.0.is_some() {
            return Err(WorkerError::LocalClosed(H3Error::new(
                ErrorCode::StreamCreation,
                "Duplicate control stream",
            )));
        }

        let frame = stream.read_frame().await.map_err(|frame_read_error| {
            WorkerError::with_frame_read_err(frame_read_error, "Unable to receive SETTINGS")
        })?;

        let settings = match frame.kind() {
            FrameKind::Settings => match Settings::with_frame(&frame) {
                Ok(settings) => settings,
                Err(h3code) => {
                    return Err(WorkerError::LocalClosed(H3Error::new(
                        h3code,
                        "Unable to receive SETTINGS",
                    )));
                }
            },
            _ => {
                return Err(WorkerError::LocalClosed(H3Error::new(
                    ErrorCode::MissingSettings,
                    "Unexpected frame on control stream",
                )));
            }
        };

        match inc_settings_channel.send(Some(settings)) {
            Ok(()) => {
                self.0 = Some(stream);
                Ok(())
            }
            Err(watch::error::SendError(_)) => Err(WorkerError::RemoteClosed),
        }
    }

    async fn done(&mut self) -> WorkerResult<()> {
        match self.0 {
            Some(ref mut stream) => loop {
                let frame = stream.read_frame().await.map_err(|frame_read_error| {
                    WorkerError::with_frame_read_err(frame_read_error, "Error on control stream")
                })?;

                if !matches!(frame.kind(), FrameKind::Exercise(_)) {
                    return Err(WorkerError::LocalClosed(H3Error::new(
                        ErrorCode::FrameUnexpected,
                        "Unexpected frame on remote control stream",
                    )));
                }
            },
            None => pending().await,
        }
    }
}

struct RemoteQPackEncStream(Option<QuicRecvStream>);

impl RemoteQPackEncStream {
    fn new() -> Self {
        Self(None)
    }

    fn on_stream_recv(&mut self, stream: Stream<UniRemote, H3>) -> WorkerResult<()> {
        if self.0.is_some() {
            return Err(WorkerError::LocalClosed(H3Error::new(
                ErrorCode::StreamCreation,
                "Duplicate QPACK.ENC stream",
            )));
        }

        self.0 = Some(stream.raw());
        Ok(())
    }

    async fn done(&mut self) -> WorkerResult<()> {
        let mut buffer = [0; 64];

        match self.0 {
            Some(ref mut stream) => loop {
                match stream.read(&mut buffer).await {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(StreamError::Stopped) => {
                        return Err(WorkerError::LocalClosed(H3Error::new(
                            ErrorCode::ClosedCriticalStream,
                            "Closed remote QPACK.ENC stream",
                        )));
                    }
                    Err(StreamError::ConnectionClosed) => {
                        return Err(WorkerError::RemoteClosed);
                    }
                }
            },
            None => pending().await,
        }
    }
}

struct RemoteQPackDecStream(Option<QuicRecvStream>);

impl RemoteQPackDecStream {
    fn new() -> Self {
        Self(None)
    }

    fn on_stream_recv(&mut self, stream: Stream<UniRemote, H3>) -> WorkerResult<()> {
        if self.0.is_some() {
            return Err(WorkerError::LocalClosed(H3Error::new(
                ErrorCode::StreamCreation,
                "Duplicate QPACK.DEC stream",
            )));
        }

        self.0 = Some(stream.raw());
        Ok(())
    }

    async fn done(&mut self) -> WorkerResult<()> {
        let mut buffer = [0; 64];

        match self.0 {
            Some(ref mut stream) => loop {
                match stream.read(&mut buffer).await {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(StreamError::Stopped) => {
                        return Err(WorkerError::LocalClosed(H3Error::new(
                            ErrorCode::ClosedCriticalStream,
                            "Closed remote QPACK.DEC stream",
                        )));
                    }
                    Err(StreamError::ConnectionClosed) => {
                        return Err(WorkerError::RemoteClosed);
                    }
                }
            },
            None => pending().await,
        }
    }
}

impl WorkerError {
    fn with_upgrade_err<S>(upgrade_error: UpgradeError, reason: S) -> Self
    where
        S: ToString,
    {
        match upgrade_error {
            UpgradeError::UnknownStream => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::FrameUnexpected, reason))
            }
            UpgradeError::InvalidSessionId => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::FrameUnexpected, reason))
            }
            UpgradeError::ConnectionClosed => WorkerError::RemoteClosed,
            UpgradeError::EndOfStream => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::ClosedCriticalStream, reason))
            }
        }
    }

    fn with_frame_write_err<S>(frame_write_error: FrameWriteError, reason: S) -> Self
    where
        S: ToString,
    {
        match frame_write_error {
            FrameWriteError::EndOfStream => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::ClosedCriticalStream, reason))
            }
            FrameWriteError::ConnectionClosed => WorkerError::RemoteClosed,
        }
    }

    fn with_frame_read_err<S>(frame_read_error: FrameReadError, reason: S) -> Self
    where
        S: ToString,
    {
        match frame_read_error {
            FrameReadError::UnknownFrame => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::FrameUnexpected, reason))
            }
            FrameReadError::InvalidSessionId => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::FrameUnexpected, reason))
            }
            FrameReadError::EndOfStream => {
                WorkerError::LocalClosed(H3Error::new(ErrorCode::ClosedCriticalStream, reason))
            }
            FrameReadError::ConnectionClosed => WorkerError::RemoteClosed,
        }
    }
}
