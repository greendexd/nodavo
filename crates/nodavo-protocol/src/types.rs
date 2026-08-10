use core::fmt;

use bitflags::bitflags;
use minicbor::{Decode, Decoder, Encode, Encoder, decode, encode};
use serde::{Deserialize, Serialize};

macro_rules! fixed_id {
    ($name:ident, $length:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[repr(transparent)]
        pub struct $name([u8; $length]);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Identifiers are security-sensitive stable values. Do not make it
                // convenient for downstream logs to emit the underlying bytes.
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }

        impl<C> Encode<C> for $name {
            fn encode<W: encode::Write>(
                &self,
                encoder: &mut Encoder<W>,
                _context: &mut C,
            ) -> Result<(), encode::Error<W::Error>> {
                encoder.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, decode::Error> {
                let bytes = decoder.bytes()?;
                let bytes: [u8; $length] = bytes.try_into().map_err(|_| {
                    decode::Error::message(concat!(
                        stringify!($name),
                        " has an invalid byte length"
                    ))
                })?;
                Ok(Self(bytes))
            }
        }
    };
}

fixed_id!(DeviceId, 32);
fixed_id!(SessionId, 16);

macro_rules! integer_newtype {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
        )]
        #[repr(transparent)]
        pub struct $name(u64);

        impl $name {
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            #[must_use]
            pub const fn is_zero(self) -> bool {
                self.0 == 0
            }
        }

        impl<C> Encode<C> for $name {
            fn encode<W: encode::Write>(
                &self,
                encoder: &mut Encoder<W>,
                _context: &mut C,
            ) -> Result<(), encode::Error<W::Error>> {
                encoder.u64(self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, decode::Error> {
                Ok(Self(decoder.u64()?))
            }
        }
    };
}

integer_newtype!(GrantEpoch);
integer_newtype!(Sequence);

/// A negotiated protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct ProtocolVersion {
    #[n(0)]
    major: u16,
    #[n(1)]
    minor: u16,
}

impl ProtocolVersion {
    /// The only version understood by this pre-alpha codec.
    pub const CURRENT: Self = Self { major: 1, minor: 4 };

    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    #[must_use]
    pub const fn is_well_formed(self) -> bool {
        self.major != 0
    }
}

bitflags! {
    /// Explicit grants negotiated for a peer.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Capability: u64 {
        const REMOTE_INPUT = 1 << 0;
        const CLIPBOARD_READ = 1 << 1;
        const CLIPBOARD_WRITE = 1 << 2;
        const FILE_TRANSFER = 1 << 3;
    }
}

impl<C> Encode<C> for Capability {
    fn encode<W: encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        _context: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        encoder.u64(self.bits())?;
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for Capability {
    fn decode(decoder: &mut Decoder<'bytes>, _context: &mut C) -> Result<Self, decode::Error> {
        Self::from_bits(decoder.u64()?)
            .ok_or_else(|| decode::Error::message("unknown capability bits"))
    }
}

/// Security context carried by every input and bulk semantic message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct EventMeta {
    #[n(0)]
    session_id: SessionId,
    #[n(1)]
    origin: DeviceId,
    #[n(2)]
    sequence: Sequence,
    #[n(3)]
    grant_epoch: GrantEpoch,
    #[n(4)]
    capability: Capability,
}

impl EventMeta {
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        origin: DeviceId,
        sequence: Sequence,
        grant_epoch: GrantEpoch,
        capability: Capability,
    ) -> Self {
        Self {
            session_id,
            origin,
            sequence,
            grant_epoch,
            capability,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn origin(&self) -> DeviceId {
        self.origin
    }

    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    #[must_use]
    pub const fn grant_epoch(&self) -> GrantEpoch {
        self.grant_epoch
    }

    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }
}
