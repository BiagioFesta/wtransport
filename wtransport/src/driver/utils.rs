use std::future::Future;
use tokio::task::JoinHandle;
use wtransport_proto::ids::StreamId;
use wtransport_proto::varint::VarInt;

#[inline(always)]
pub fn varint_q2w(varint: quinn::VarInt) -> VarInt {
    // SAFETY: varint conversion
    unsafe {
        debug_assert!(varint.into_inner() <= VarInt::MAX.into_inner());
        VarInt::from_u64_unchecked(varint.into_inner())
    }
}

#[inline(always)]
pub fn varint_w2q(varint: VarInt) -> quinn::VarInt {
    // SAFETY: varint conversion
    unsafe {
        debug_assert!(varint.into_inner() <= quinn::VarInt::MAX.into_inner());
        quinn::VarInt::from_u64_unchecked(varint.into_inner())
    }
}

#[inline(always)]
pub fn streamid_q2w(stream_id: quinn::StreamId) -> StreamId {
    let varint = unsafe {
        debug_assert!(stream_id.0 <= VarInt::MAX.into_inner());
        VarInt::from_u64_unchecked(stream_id.0)
    };

    StreamId::new(varint)
}

pub struct WorkerHandler<T> {
    join_handle: Option<JoinHandle<T>>,
    result: Option<T>,
}

impl<T> WorkerHandler<T>
where
    T: Copy,
{
    pub fn spawn<W>(worker: W) -> Self
    where
        W: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let join_handle = tokio::spawn(worker);

        Self {
            join_handle: Some(join_handle),
            result: None,
        }
    }

    pub async fn abort_with_result(&mut self, try_result: T) -> T {
        if let Some(result) = self.result {
            return result;
        }

        let join_handle = self.join_handle.take().expect("Worker is executing");

        if join_handle.is_finished() {
            match join_handle.await {
                Ok(result) => {
                    self.result = Some(result);
                    result
                }
                Err(join_error) => {
                    std::panic::resume_unwind(join_error.into_panic());
                }
            }
        } else {
            join_handle.abort();
            self.result = Some(try_result);
            try_result
        }
    }

    pub async fn result(&mut self) -> T {
        if let Some(result) = self.result {
            return result;
        }

        let join_handle = self.join_handle.take().expect("Worker is executing");

        match join_handle.await {
            Ok(result) => {
                self.result = Some(result);
                result
            }
            Err(join_error) => {
                std::panic::resume_unwind(join_error.into_panic());
            }
        }
    }
}

impl<T> Drop for WorkerHandler<T> {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.abort()
        }
    }
}
