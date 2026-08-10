use core::fmt;

use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    Capability, DeviceId, DisplayTopology, EventMeta, GrantEpoch, ProtocolVersion, SessionId,
};

/// Control-stream messages. Variant names describe protocol intent, not current
/// product availability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    Hello {
        versions: Vec<ProtocolVersion>,
        capabilities: Capability,
    },
    CapabilityGrant {
        peer: DeviceId,
        capabilities: Capability,
        epoch: GrantEpoch,
    },
    CapabilityRevoke {
        peer: DeviceId,
        capabilities: Capability,
        epoch: GrantEpoch,
    },
    SessionOpen {
        session_id: SessionId,
        peer: DeviceId,
        epoch: GrantEpoch,
    },
    SessionClose {
        session_id: SessionId,
        reason: u16,
    },
    FocusLeaseRequest {
        meta: EventMeta,
        lease_id: u64,
        ttl_ms: u32,
        pointer_enter_required: bool,
    },
    FocusLeaseGrant {
        meta: EventMeta,
        lease_id: u64,
        ttl_ms: u32,
        pointer_enter_required: bool,
    },
    FocusLeaseRelease {
        meta: EventMeta,
        lease_id: u64,
    },
    /// Complete display snapshot. Display identifiers are opaque and scoped to
    /// this authenticated session; they are never platform-native identifiers.
    DisplayTopology {
        meta: EventMeta,
        topology: DisplayTopology,
    },
    /// Confirms that a topology revision was validated and installed.
    DisplayTopologyAck {
        meta: EventMeta,
        revision: u64,
    },
    PointerEnterAck {
        meta: EventMeta,
        lease_id: u64,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    EmergencyDisconnect {
        session_id: SessionId,
    },
    Error {
        code: ProtocolErrorCode,
        related_tag: Option<u16>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum ProtocolErrorCode {
    #[n(0)]
    MalformedMessage,
    #[n(1)]
    UnsupportedVersion,
    #[n(2)]
    CapabilityDenied,
    #[n(3)]
    StaleGrant,
    #[n(4)]
    StaleSequence,
    #[n(5)]
    InvalidSession,
    #[n(6)]
    LeaseDenied,
    #[n(7)]
    RateLimited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum KeyState {
    #[n(0)]
    Up,
    #[n(1)]
    Down,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum ButtonState {
    #[n(0)]
    Up,
    #[n(1)]
    Down,
}

/// Units used for semantic scroll deltas on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum ScrollUnit {
    /// Discrete wheel detents or their platform-equivalent line unit.
    #[n(0)]
    Lines,
    /// High-resolution device-independent touch or pixel-like units.
    #[n(1)]
    Precise,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct KeyEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub usage_page: u16,
    #[n(2)]
    pub usage_id: u16,
    #[n(3)]
    pub state: KeyState,
    #[n(4)]
    pub modifiers: u16,
    #[n(5)]
    pub lease_id: u64,
}

impl fmt::Debug for KeyEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyEvent([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct PointerButtonEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub button: u8,
    #[n(2)]
    pub state: ButtonState,
    #[n(3)]
    pub lease_id: u64,
}

impl fmt::Debug for PointerButtonEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerButtonEvent([redacted])")
    }
}

/// Absolute normalized coordinates; zero and `u32::MAX` are the display edges.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct PointerMotionEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub display_id: u32,
    #[n(2)]
    pub x: u32,
    #[n(3)]
    pub y: u32,
    #[n(4)]
    pub lease_id: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct PointerDeltaEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub delta_x: i32,
    #[n(2)]
    pub delta_y: i32,
    #[n(3)]
    pub lease_id: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct PointerEnterEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub display_id: u32,
    #[n(2)]
    pub x: u32,
    #[n(3)]
    pub y: u32,
    #[n(4)]
    pub lease_id: u64,
}

impl fmt::Debug for PointerEnterEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerEnterEvent([redacted])")
    }
}

impl fmt::Debug for PointerDeltaEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerDeltaEvent([redacted])")
    }
}

impl fmt::Debug for PointerMotionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerMotionEvent([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct ScrollEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub delta_x: i32,
    #[n(2)]
    pub delta_y: i32,
    #[n(3)]
    pub unit: ScrollUnit,
    #[n(4)]
    pub lease_id: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct ReleaseAllEvent {
    #[n(0)]
    pub meta: EventMeta,
    #[n(1)]
    pub lease_id: u64,
}

impl fmt::Debug for ReleaseAllEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleaseAllEvent([redacted])")
    }
}

impl fmt::Debug for ScrollEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScrollEvent([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputMessage {
    Key(KeyEvent),
    PointerButton(PointerButtonEvent),
    PointerMotion(PointerMotionEvent),
    PointerDelta(PointerDeltaEvent),
    PointerEnter(PointerEnterEvent),
    Scroll(ScrollEvent),
    ReleaseAll(ReleaseAllEvent),
}

impl InputMessage {
    #[must_use]
    pub const fn meta(&self) -> &EventMeta {
        match self {
            Self::Key(event) => &event.meta,
            Self::PointerButton(event) => &event.meta,
            Self::PointerMotion(event) => &event.meta,
            Self::PointerDelta(event) => &event.meta,
            Self::PointerEnter(event) => &event.meta,
            Self::Scroll(event) => &event.meta,
            Self::ReleaseAll(event) => &event.meta,
        }
    }

    #[must_use]
    pub const fn lease_id(&self) -> u64 {
        match self {
            Self::Key(event) => event.lease_id,
            Self::PointerButton(event) => event.lease_id,
            Self::PointerMotion(event) => event.lease_id,
            Self::PointerDelta(event) => event.lease_id,
            Self::PointerEnter(event) => event.lease_id,
            Self::Scroll(event) => event.lease_id,
            Self::ReleaseAll(event) => event.lease_id,
        }
    }
}

impl fmt::Debug for InputMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(_) => formatter.write_str("Key([redacted])"),
            Self::PointerButton(_) => formatter.write_str("PointerButton([redacted])"),
            Self::PointerMotion(_) => formatter.write_str("PointerMotion([redacted])"),
            Self::PointerDelta(_) => formatter.write_str("PointerDelta([redacted])"),
            Self::PointerEnter(_) => formatter.write_str("PointerEnter([redacted])"),
            Self::Scroll(_) => formatter.write_str("Scroll([redacted])"),
            Self::ReleaseAll(_) => formatter.write_str("ReleaseAll([redacted])"),
        }
    }
}

/// Decoded top-level message. Unknown non-critical messages remain opaque so a
/// newer peer can extend the protocol without an older peer interpreting them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Control(ControlMessage),
    Input(InputMessage),
    Unknown { tag: u16, payload: Vec<u8> },
}
