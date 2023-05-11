use crate::bytes::BufferReader;
use crate::bytes::BufferWriter;
use crate::bytes::BytesReader;
use crate::bytes::BytesWriter;
use crate::bytes::EndOfBuffer;
use crate::bytes::MAX_VARINT;
use crate::error::Error;
use crate::frame::Frame;
use crate::frame::FrameKind;
use std::collections::hash_map;
use std::collections::HashMap;

enum ParseError {
    ReservedSetting,
    UnknownSetting,
}

/// Settings IDs for an HTTP3 connection.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum SettingId {
    QPackMaxTableCapacity,
    MaxFieldSectionSize,
    QPackBlockedStreams,
    H3Datagram,
    EnableWebTransport,
    Exercise(u64),
}

impl SettingId {
    fn parse(id: u64) -> Result<Self, ParseError> {
        if Self::is_reserved(id) {
            return Err(ParseError::ReservedSetting);
        }

        if Self::is_exercise(id) {
            Ok(Self::Exercise(id))
        } else {
            match id {
                setting_ids::SETTINGS_QPACK_MAX_TABLE_CAPACITY => Ok(Self::QPackMaxTableCapacity),
                setting_ids::SETTINGS_MAX_FIELD_SECTION_SIZE => Ok(Self::MaxFieldSectionSize),
                setting_ids::SETTINGS_QPACK_BLOCKED_STREAMS => Ok(Self::QPackBlockedStreams),
                setting_ids::SETTINGS_H3_DATAGRAM => Ok(Self::H3Datagram),
                setting_ids::SETTINGS_ENABLE_WEBTRANSPORT => Ok(Self::EnableWebTransport),
                _ => Err(ParseError::UnknownSetting),
            }
        }
    }

    const fn id(self) -> u64 {
        match self {
            Self::QPackMaxTableCapacity => setting_ids::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            Self::MaxFieldSectionSize => setting_ids::SETTINGS_MAX_FIELD_SECTION_SIZE,
            Self::QPackBlockedStreams => setting_ids::SETTINGS_QPACK_BLOCKED_STREAMS,
            Self::H3Datagram => setting_ids::SETTINGS_H3_DATAGRAM,
            Self::EnableWebTransport => setting_ids::SETTINGS_ENABLE_WEBTRANSPORT,
            Self::Exercise(id) => id,
        }
    }

    // TODO(bfesta): do we need this?
    #[allow(unused)]
    const fn is_valid_value(self, value: u64) -> bool {
        match self {
            Self::QPackMaxTableCapacity | Self::MaxFieldSectionSize | Self::QPackBlockedStreams => {
                value <= MAX_VARINT
            }
            Self::H3Datagram | Self::EnableWebTransport => matches!(value, 0 | 1),
            Self::Exercise(_) => true,
        }
    }

    #[inline(always)]
    const fn is_reserved(id: u64) -> bool {
        matches!(id, 0x0 | 0x2 | 0x3 | 0x4 | 0x5)
    }

    #[inline(always)]
    const fn is_exercise(id: u64) -> bool {
        id >= 0x21 && ((id - 0x21) % 0x1f == 0)
    }
}

/// Collection of settings for an HTTP3 connection.
#[derive(Clone, Debug)]
pub struct Settings(HashMap<SettingId, u64>);

impl Settings {
    /// Produces a new [`SettingsBuilder`] for new [`Settings`] construction.
    pub fn builder() -> SettingsBuilder {
        SettingsBuilder(Settings::new())
    }

    /// Constructs [`Settings`] parsing payload of a [`Frame`].
    ///
    /// Returns an [`Err`] in case of invalid setting (id or value) or incomplete
    /// payload.
    ///
    /// Unknown settings-ids are ignored.
    ///
    /// **Note**: frame must be [`FrameKind::Settings`], otherwise behavior
    /// is unspecified.
    pub fn with_frame(frame: &Frame) -> Result<Self, Error> {
        debug_assert!(matches!(frame.kind(), FrameKind::Settings));

        let mut settings = Settings::new();
        let mut buffer_reader = BufferReader::new(frame.payload());

        while buffer_reader.capacity() > 0 {
            let id = buffer_reader.get_varint().ok_or(Error::Frame)?;
            let value = buffer_reader.get_varint().ok_or(Error::Frame)?;

            // TODO(bfesta): do we need to validate value?

            match SettingId::parse(id) {
                Ok(setting_id) => match settings.0.entry(setting_id) {
                    hash_map::Entry::Vacant(slot) => {
                        slot.insert(value);
                    }
                    hash_map::Entry::Occupied(_) => {
                        return Err(Error::Settings);
                    }
                },
                Err(ParseError::UnknownSetting) => {}
                Err(ParseError::ReservedSetting) => return Err(Error::Settings),
            }
        }

        Ok(settings)
    }

    /// Generates a [`Frame`] with these settings.
    ///
    /// This function allocates heap-memory, producing a [`Frame`] with owned payload.
    /// See [`Self::generate_frame_ref`] for a version without inner memory allocation.
    pub fn generate_frame(&self) -> Frame {
        let mut payload_writer = Vec::new();

        for (id, value) in &self.0 {
            payload_writer
                .put_varint(id.id())
                .expect("Vec does not have EOF");

            payload_writer
                .put_varint(*value)
                .expect("Vec does not have EOF");
        }

        let payload = payload_writer.into_boxed_slice();

        Frame::with_payload_own(FrameKind::Settings, payload)
    }

    /// Generates a [`Frame`] with these settings.
    ///
    /// This function does *not* allocates memory. It uses `buffer` for frame-payload
    /// serialization.
    /// See [`Self::generate_frame`] for a versione with inner memory allocation.
    pub fn generate_frame_ref<'a>(&self, buffer: &'a mut [u8]) -> Result<Frame<'a>, EndOfBuffer> {
        let mut bytes_writer = BufferWriter::new(buffer);

        for (id, value) in &self.0 {
            bytes_writer.put_varint(id.id())?;
            bytes_writer.put_varint(*value)?;
        }

        let offset = bytes_writer.offset();

        Ok(Frame::with_payload_ref(
            FrameKind::Settings,
            &buffer[..offset],
        ))
    }

    fn new() -> Self {
        Self(HashMap::new())
    }
}

/// Allows building [`Settings`].
pub struct SettingsBuilder(Settings);

impl SettingsBuilder {
    /// Sets the QPACK max table capacity.
    pub fn qpack_max_table_capacity(mut self, value: u32) -> Self {
        self.0
             .0
            .insert(SettingId::QPackMaxTableCapacity, value as u64);
        self
    }

    pub fn qpack_blocked_streams(mut self, value: u32) -> Self {
        self.0
             .0
            .insert(SettingId::QPackBlockedStreams, value as u64);
        self
    }

    /// Enables *WebTransport* support.
    pub fn enable_webtransport(mut self) -> Self {
        self.0 .0.insert(SettingId::EnableWebTransport, 1);
        self
    }

    /// Enables HTTP3 datagrams support.
    pub fn enable_h3_datagrams(mut self) -> Self {
        self.0 .0.insert(SettingId::H3Datagram, 1);
        self
    }

    /// Builds [`Settings`].
    pub fn build(self) -> Settings {
        self.0
    }
}

mod setting_ids {
    pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
    pub const SETTINGS_H3_DATAGRAM: u64 = 0xffd277;
    pub const SETTINGS_ENABLE_WEBTRANSPORT: u64 = 0x2b603742;
}
