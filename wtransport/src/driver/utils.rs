use std::sync::Arc;
use tokio::sync::watch;
use tokio::sync::Mutex;
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

#[derive(Clone)]
pub struct SharedResultSet<T>(Arc<watch::Sender<Option<T>>>);

impl<T> SharedResultSet<T>
where
    T: Copy,
{
    pub fn new() -> Self {
        Self(Arc::new(watch::channel(None).0))
    }

    pub fn set(&self, result: T) -> bool {
        self.0.send_if_modified(|state| {
            if state.is_none() {
                *state = Some(result);
                true
            } else {
                false
            }
        })
    }

    pub async fn closed(&self) {
        self.0.closed().await
    }

    pub fn subscribe(&self) -> SharedResultGet<T> {
        SharedResultGet(Mutex::new(self.0.subscribe()))
    }
}

pub struct SharedResultGet<T>(Mutex<watch::Receiver<Option<T>>>);

impl<T> SharedResultGet<T>
where
    T: Copy,
{
    pub async fn result(&self) -> Option<T> {
        let mut lock = self.0.lock().await;

        loop {
            if let Some(result) = *lock.borrow() {
                return Some(result);
            }

            if lock.changed().await.is_err() {
                return None;
            }
        }
    }
}
