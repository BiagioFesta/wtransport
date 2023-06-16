use wtransport_proto::ids::SessionId;

/// WebTransport session information.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    id: SessionId,
}

impl SessionInfo {
    pub(crate) fn new(id: SessionId) -> Self {
        Self { id }
    }

    /// The identified associated with the WebTransport session.
    #[inline(always)]
    pub fn id(&self) -> SessionId {
        self.id
    }
}
