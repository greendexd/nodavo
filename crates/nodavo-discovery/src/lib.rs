//! Validation primitives for Nodavo peer discovery.
//!
//! Discovery answers only "where can I try to connect?". Neither an mDNS
//! instance name nor any TXT value is identity evidence. Persistent identity is
//! established separately by the pairing protocol and verified by the
//! authenticated transport on later connections.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;

mod runtime;

pub use runtime::{DiscoveryRuntimeEvent, MdnsBrowser, MdnsRuntime, SERVICE_TYPE};

/// Maximum encoded length of a single DNS-SD instance-name label.
pub const MAX_INSTANCE_NAME_BYTES: usize = 63;
/// Maximum number of TXT strings accepted from an untrusted advertisement.
pub const MAX_TXT_FIELDS: usize = 4;
/// Maximum encoded length of one DNS-SD TXT string.
pub const MAX_TXT_FIELD_BYTES: usize = 255;
/// Aggregate TXT data accepted before parsing.
pub const MAX_TOTAL_TXT_BYTES: usize = 512;

const VERSION_KEY: &str = "v";
const TRANSPORT_KEY: &str = "transport";
const QUIC_VALUE: &str = "quic";

/// A bounded, validated mDNS service record.
///
/// The record deliberately contains no device identifier, public key,
/// fingerprint, signature, pairing code, or capability information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRecord {
    instance_name: Box<str>,
    port: u16,
    protocol_version: u16,
}

impl DiscoveryRecord {
    /// Creates a record suitable for local advertisement.
    ///
    /// # Errors
    ///
    /// Rejects invalid instance names, port zero, or protocol version zero.
    pub fn new(
        instance_name: impl Into<String>,
        port: u16,
        protocol_version: u16,
    ) -> Result<Self, DiscoveryError> {
        let instance_name = validate_instance_name(instance_name.into().as_bytes())?;
        validate_port(port)?;
        validate_protocol_version(protocol_version)?;

        Ok(Self {
            instance_name,
            port,
            protocol_version,
        })
    }

    /// Parses the untrusted fields returned by an mDNS implementation.
    ///
    /// Unknown or duplicate TXT keys are rejected. This strict initial schema
    /// keeps the advertisement minimal and makes extensions deliberate.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, incomplete, duplicated, unsupported, or
    /// invalid discovery fields before they are exposed to the caller.
    pub fn parse_untrusted(
        instance_name: &[u8],
        port: u16,
        txt_fields: &[&[u8]],
    ) -> Result<Self, DiscoveryError> {
        let instance_name = validate_instance_name(instance_name)?;
        validate_port(port)?;
        let fields = parse_txt_fields(txt_fields)?;

        let version = fields
            .get(VERSION_KEY)
            .ok_or(DiscoveryError::MissingTxtField(VERSION_KEY))?;
        let transport = fields
            .get(TRANSPORT_KEY)
            .ok_or(DiscoveryError::MissingTxtField(TRANSPORT_KEY))?;

        if transport.as_slice() != QUIC_VALUE.as_bytes() {
            return Err(DiscoveryError::UnsupportedTransport);
        }

        let version =
            std::str::from_utf8(version).map_err(|_| DiscoveryError::InvalidProtocolVersion)?;
        if version.is_empty()
            || version.len() > 5
            || !version.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(DiscoveryError::InvalidProtocolVersion);
        }
        let protocol_version = version
            .parse::<u16>()
            .map_err(|_| DiscoveryError::InvalidProtocolVersion)?;
        validate_protocol_version(protocol_version)?;
        Ok(Self {
            instance_name,
            port,
            protocol_version,
        })
    }

    #[must_use]
    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the complete, bounded TXT strings for an mDNS backend.
    #[must_use]
    pub fn txt_fields(&self) -> [String; 2] {
        [
            format!("{VERSION_KEY}={}", self.protocol_version),
            format!("{TRANSPORT_KEY}={QUIC_VALUE}"),
        ]
    }
}

/// A validated connection location supplied either by mDNS or by the user.
///
/// Consumers must still perform pairing or pinned mutual authentication after
/// connecting. `Mdns` is not a stronger trust level than `Manual`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryLocation {
    Mdns {
        address: SocketAddr,
        record: DiscoveryRecord,
    },
    Manual(SocketAddr),
}

impl DiscoveryLocation {
    /// Creates a location from an mDNS result after checking address/port consistency.
    ///
    /// # Errors
    ///
    /// Rejects unusable addresses and a port that differs from the record.
    pub fn mdns(address: SocketAddr, record: DiscoveryRecord) -> Result<Self, DiscoveryError> {
        validate_address(address)?;
        if address.port() != record.port() {
            return Err(DiscoveryError::PortMismatch);
        }
        Ok(Self::Mdns { address, record })
    }

    /// Creates the explicit manual-address fallback.
    ///
    /// # Errors
    ///
    /// Rejects port zero, unspecified, multicast, and broadcast addresses.
    pub fn manual(address: SocketAddr) -> Result<Self, DiscoveryError> {
        validate_address(address)?;
        Ok(Self::Manual(address))
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        match self {
            Self::Mdns { address, .. } | Self::Manual(address) => *address,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DiscoveryError {
    #[error("the discovery instance name is empty")]
    EmptyInstanceName,
    #[error("the discovery instance name exceeds its encoded limit")]
    InstanceNameTooLong,
    #[error("the discovery instance name is not valid UTF-8")]
    InvalidInstanceNameEncoding,
    #[error("the discovery instance name contains disallowed characters")]
    InvalidInstanceName,
    #[error("the discovery port must be non-zero")]
    InvalidPort,
    #[error("the discovery protocol version must be non-zero")]
    InvalidProtocolVersion,
    #[error("too many discovery TXT fields")]
    TooManyTxtFields,
    #[error("a discovery TXT field exceeds its encoded limit")]
    TxtFieldTooLong,
    #[error("aggregate discovery TXT data exceeds its encoded limit")]
    TxtDataTooLong,
    #[error("a discovery TXT field is malformed")]
    MalformedTxtField,
    #[error("a discovery TXT key is duplicated")]
    DuplicateTxtField,
    #[error("an unsupported discovery TXT key was received")]
    UnsupportedTxtField,
    #[error("required discovery TXT field `{0}` is missing")]
    MissingTxtField(&'static str),
    #[error("only the QUIC transport advertisement is supported")]
    UnsupportedTransport,
    #[error("the discovery address is not a usable unicast endpoint")]
    InvalidAddress,
    #[error("the resolved address and discovery record ports differ")]
    PortMismatch,
    #[error("the mDNS runtime is unavailable")]
    RuntimeUnavailable,
}

fn validate_instance_name(bytes: &[u8]) -> Result<Box<str>, DiscoveryError> {
    if bytes.is_empty() {
        return Err(DiscoveryError::EmptyInstanceName);
    }
    if bytes.len() > MAX_INSTANCE_NAME_BYTES {
        return Err(DiscoveryError::InstanceNameTooLong);
    }
    let name =
        std::str::from_utf8(bytes).map_err(|_| DiscoveryError::InvalidInstanceNameEncoding)?;
    if name.trim() != name || name.chars().any(char::is_control) {
        return Err(DiscoveryError::InvalidInstanceName);
    }
    Ok(name.into())
}

fn validate_port(port: u16) -> Result<(), DiscoveryError> {
    if port == 0 {
        Err(DiscoveryError::InvalidPort)
    } else {
        Ok(())
    }
}

fn validate_protocol_version(version: u16) -> Result<(), DiscoveryError> {
    if version == 0 {
        Err(DiscoveryError::InvalidProtocolVersion)
    } else {
        Ok(())
    }
}

fn validate_address(address: SocketAddr) -> Result<(), DiscoveryError> {
    validate_port(address.port())?;
    let ip = address.ip();
    let unusable = ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ipv4) if ipv4.is_broadcast());
    if unusable {
        Err(DiscoveryError::InvalidAddress)
    } else {
        Ok(())
    }
}

fn parse_txt_fields(fields: &[&[u8]]) -> Result<BTreeMap<String, Vec<u8>>, DiscoveryError> {
    if fields.len() > MAX_TXT_FIELDS {
        return Err(DiscoveryError::TooManyTxtFields);
    }
    let total = fields.iter().try_fold(0_usize, |total, field| {
        if field.len() > MAX_TXT_FIELD_BYTES {
            return Err(DiscoveryError::TxtFieldTooLong);
        }
        total
            .checked_add(field.len())
            .ok_or(DiscoveryError::TxtDataTooLong)
    })?;
    if total > MAX_TOTAL_TXT_BYTES {
        return Err(DiscoveryError::TxtDataTooLong);
    }

    let mut parsed = BTreeMap::new();
    for field in fields {
        let separator = field
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(DiscoveryError::MalformedTxtField)?;
        let (raw_key, raw_value) = field.split_at(separator);
        let value = &raw_value[1..];
        let key = std::str::from_utf8(raw_key).map_err(|_| DiscoveryError::MalformedTxtField)?;
        if !matches!(key, VERSION_KEY | TRANSPORT_KEY) {
            return Err(DiscoveryError::UnsupportedTxtField);
        }
        if parsed.insert(key.to_owned(), value.to_vec()).is_some() {
            return Err(DiscoveryError::DuplicateTxtField);
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_overlong_instance_name_before_use() {
        let name = vec![b'a'; MAX_INSTANCE_NAME_BYTES + 1];
        let error = DiscoveryRecord::parse_untrusted(
            &name,
            4_431,
            &[b"v=1".as_slice(), b"transport=quic".as_slice()],
        )
        .unwrap_err();

        assert_eq!(error, DiscoveryError::InstanceNameTooLong);
    }

    #[test]
    fn rejects_duplicate_and_oversized_txt_data() {
        let duplicate = DiscoveryRecord::parse_untrusted(
            b"desk",
            4_431,
            &[
                b"v=1".as_slice(),
                b"v=2".as_slice(),
                b"transport=quic".as_slice(),
            ],
        )
        .unwrap_err();
        assert_eq!(duplicate, DiscoveryError::DuplicateTxtField);

        let oversized = vec![b'x'; MAX_TXT_FIELD_BYTES + 1];
        let error = DiscoveryRecord::parse_untrusted(
            b"desk",
            4_431,
            &[oversized.as_slice(), b"v=1".as_slice()],
        )
        .unwrap_err();
        assert_eq!(error, DiscoveryError::TxtFieldTooLong);
    }
}
