use crate::driver::streams::biremote::StreamBiRemoteH3;
use crate::driver::streams::biremote::StreamBiRemoteWT;
use crate::driver::streams::uniremote::StreamUniRemoteH3;
use crate::driver::streams::uniremote::StreamUniRemoteWT;
use crate::driver::streams::ProtoReadError;
use crate::driver::streams::Stream;
use crate::driver::utils::WorkerHandler;
use crate::driver::DriverError;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::stream_header::StreamKind;

pub struct StreamAcceptor {
    worker_handler: Mutex<WorkerHandler<DriverError>>,
    bi_remote_h3: Mutex<mpsc::Receiver<(StreamBiRemoteH3, Frame<'static>)>>,
    uni_remote_h3: Mutex<mpsc::Receiver<StreamUniRemoteH3>>,
    bi_remote_wt: Mutex<mpsc::Receiver<StreamBiRemoteWT>>,
    uni_remote_wt: Mutex<mpsc::Receiver<StreamUniRemoteWT>>,
}

impl StreamAcceptor {
    pub fn start(buffered_stream_queue: usize, quic_connection: quinn::Connection) -> Self {
        let bi_remote_h3 = mpsc::channel(buffered_stream_queue);
        let uni_remote_h3 = mpsc::channel(buffered_stream_queue);
        let bi_remote_wt = mpsc::channel(buffered_stream_queue);
        let uni_remote_wt = mpsc::channel(buffered_stream_queue);

        let worker_handler = WorkerHandler::spawn(async move {
            StreamAcceptorWorker {
                quic_connection,
                bi_remote_h3: bi_remote_h3.0,
                uni_remote_h3: uni_remote_h3.0,
                bi_remote_wt: bi_remote_wt.0,
                uni_remote_wt: uni_remote_wt.0,
            }
            .run()
            .await
        });

        Self {
            worker_handler: Mutex::new(worker_handler),
            bi_remote_h3: Mutex::new(bi_remote_h3.1),
            uni_remote_h3: Mutex::new(uni_remote_h3.1),
            bi_remote_wt: Mutex::new(bi_remote_wt.1),
            uni_remote_wt: Mutex::new(uni_remote_wt.1),
        }
    }

    pub async fn accept_uni_h3(&self) -> Result<StreamUniRemoteH3, DriverError> {
        let mut lock = self.uni_remote_h3.lock().await;
        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn accept_bi_h3(&self) -> Result<(StreamBiRemoteH3, Frame<'static>), DriverError> {
        let mut lock = self.bi_remote_h3.lock().await;
        match lock.recv().await {
            Some(stream_frame) => Ok(stream_frame),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn accept_uni_wt(&self) -> Result<StreamUniRemoteWT, DriverError> {
        let mut lock = self.uni_remote_wt.lock().await;
        match lock.recv().await {
            Some(stream) => Ok(stream),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn accept_bi_wt(&self) -> Result<StreamBiRemoteWT, DriverError> {
        let mut lock = self.bi_remote_wt.lock().await;
        match lock.recv().await {
            Some(stream_frame) => Ok(stream_frame),
            None => {
                drop(lock);
                Err(self.result().await)
            }
        }
    }

    pub async fn result(&self) -> DriverError {
        let mut lock = self.worker_handler.lock().await;
        lock.result().await
    }
}

struct StreamAcceptorWorker {
    quic_connection: quinn::Connection,
    bi_remote_h3: mpsc::Sender<(StreamBiRemoteH3, Frame<'static>)>,
    uni_remote_h3: mpsc::Sender<StreamUniRemoteH3>,
    bi_remote_wt: mpsc::Sender<StreamBiRemoteWT>,
    uni_remote_wt: mpsc::Sender<StreamUniRemoteWT>,
}

impl StreamAcceptorWorker {
    async fn run(self) -> DriverError {
        let mut h3_error = mpsc::channel(1);

        loop {
            tokio::select! {
                result = self.accept_uni(&h3_error.0) => {
                    if let Err(error) = result {
                        return error;
                    }
                }
                result = self.accept_bi(&h3_error.0) => {
                    if let Err(error) = result {
                        return error;
                    }
                }
                error_code = h3_error.1.recv() => {
                    return DriverError::LocallyClosed(error_code.expect("Sender cannot be dropped"));
                }
            }
        }
    }

    async fn accept_uni(&self, h3_error: &mpsc::Sender<ErrorCode>) -> Result<(), DriverError> {
        let h3_slot = match self.uni_remote_h3.clone().reserve_owned().await {
            Ok(h3_slot) => h3_slot,
            Err(mpsc::error::SendError(_)) => return Err(DriverError::NotConnected),
        };

        let wt_slot = match self.uni_remote_wt.clone().reserve_owned().await {
            Ok(wt_slot) => wt_slot,
            Err(mpsc::error::SendError(_)) => return Err(DriverError::NotConnected),
        };

        let uni_remote_quic = Stream::accept_uni(&self.quic_connection)
            .await
            .ok_or(DriverError::NotConnected)?;

        let h3_error = h3_error.clone();

        tokio::spawn(async move {
            let uni_remote_h3 = match uni_remote_quic.upgrade().await {
                Ok(uni_remote_h3) => uni_remote_h3,
                Err(ProtoReadError::H3(error_code)) => {
                    let _ = h3_error.send(error_code).await;
                    return;
                }
                Err(ProtoReadError::IO(_io_error)) => {
                    return;
                }
            };

            if matches!(uni_remote_h3.kind(), StreamKind::WebTransport) {
                let uni_remote_wt = uni_remote_h3.upgrade();
                wt_slot.send(uni_remote_wt);
            } else {
                h3_slot.send(uni_remote_h3);
            }
        });

        Ok(())
    }

    async fn accept_bi(&self, h3_error: &mpsc::Sender<ErrorCode>) -> Result<(), DriverError> {
        let h3_slot = match self.bi_remote_h3.clone().reserve_owned().await {
            Ok(h3_slot) => h3_slot,
            Err(mpsc::error::SendError(_)) => {
                return Err(DriverError::NotConnected);
            }
        };

        let wt_slot = match self.bi_remote_wt.clone().reserve_owned().await {
            Ok(wt_slot) => wt_slot,
            Err(mpsc::error::SendError(_)) => {
                return Err(DriverError::NotConnected);
            }
        };

        let bi_remote_quic = Stream::accept_bi(&self.quic_connection)
            .await
            .ok_or(DriverError::NotConnected)?;

        let h3_error = h3_error.clone();

        tokio::spawn(async move {
            let mut bi_remote_h3 = bi_remote_quic.upgrade();

            let frame = match bi_remote_h3.read_frame().await {
                Ok(frame) => frame,
                Err(ProtoReadError::H3(error_code)) => {
                    let _ = h3_error.send(error_code).await;
                    return;
                }
                Err(ProtoReadError::IO(_io_error)) => {
                    return;
                }
            };

            match frame.session_id() {
                Some(session_id) => {
                    let bi_remote_wt = bi_remote_h3.upgrade(session_id);
                    wt_slot.send(bi_remote_wt);
                }
                None => {
                    h3_slot.send((bi_remote_h3, frame));
                }
            }
        });

        Ok(())
    }
}
