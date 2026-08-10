//! Bounded, session-scoped display topology values.
//!
//! Platform display identifiers never cross the peer protocol. Each endpoint
//! assigns opaque [`SessionDisplayId`] values for one authenticated session and
//! keeps the native mapping inside its platform boundary.

use core::fmt;

use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The only display-topology schema understood by this protocol version.
pub const DISPLAY_TOPOLOGY_SCHEMA_VERSION: u16 = 1;
/// Maximum number of displays advertised by one endpoint.
pub const MAX_TOPOLOGY_DISPLAYS: usize = 32;
/// Maximum pixel width or height accepted for one display.
pub const MAX_DISPLAY_PIXEL_DIMENSION: u32 = 65_535;
/// Minimum accepted scale factor, in thousandths (0.25x).
pub const MIN_DISPLAY_SCALE_MILLI: u16 = 250;
/// Maximum accepted scale factor, in thousandths (8x).
pub const MAX_DISPLAY_SCALE_MILLI: u16 = 8_000;
/// Maximum magnitude of a display origin in logical millipoints.
pub const MAX_DISPLAY_ORIGIN_MILLI: i32 = 1_000_000_000;

/// Opaque display identifier valid only for one authenticated session.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Encode, Decode,
)]
#[cbor(transparent)]
#[repr(transparent)]
pub struct SessionDisplayId(#[n(0)] u32);

impl SessionDisplayId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for SessionDisplayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The value is intentionally session-scoped, but redaction still keeps
        // topology identifiers out of routine diagnostic logs.
        formatter.write_str("SessionDisplayId([redacted])")
    }
}

/// Clockwise display rotation after the platform has applied its native mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum DisplayRotation {
    #[n(0)]
    Degrees0,
    #[n(1)]
    Degrees90,
    #[n(2)]
    Degrees180,
    #[n(3)]
    Degrees270,
}

/// One display in a session-scoped topology snapshot.
///
/// Origins are descriptive logical coordinates for arrangement UI. They never
/// authorize adjacency. Pixel dimensions and explicit scale factors provide a
/// deterministic mixed-DPI transform without exposing native handles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct DisplayDescriptor {
    #[n(0)]
    id: SessionDisplayId,
    #[n(1)]
    origin_x_milli: i32,
    #[n(2)]
    origin_y_milli: i32,
    #[n(3)]
    pixel_width: u32,
    #[n(4)]
    pixel_height: u32,
    #[n(5)]
    scale_x_milli: u16,
    #[n(6)]
    scale_y_milli: u16,
    #[n(7)]
    rotation: DisplayRotation,
}

impl DisplayDescriptor {
    /// Builds one bounded descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero session identifier or out-of-range geometry.
    #[allow(clippy::similar_names, clippy::too_many_arguments)]
    pub fn new(
        id: SessionDisplayId,
        origin_x_milli: i32,
        origin_y_milli: i32,
        pixel_width: u32,
        pixel_height: u32,
        scale_x_milli: u16,
        scale_y_milli: u16,
        rotation: DisplayRotation,
    ) -> Result<Self, TopologyValidationError> {
        let descriptor = Self {
            id,
            origin_x_milli,
            origin_y_milli,
            pixel_width,
            pixel_height,
            scale_x_milli,
            scale_y_milli,
            rotation,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    #[must_use]
    pub const fn id(&self) -> SessionDisplayId {
        self.id
    }

    #[must_use]
    pub const fn origin_x_milli(&self) -> i32 {
        self.origin_x_milli
    }

    #[must_use]
    pub const fn origin_y_milli(&self) -> i32 {
        self.origin_y_milli
    }

    #[must_use]
    pub const fn pixel_width(&self) -> u32 {
        self.pixel_width
    }

    #[must_use]
    pub const fn pixel_height(&self) -> u32 {
        self.pixel_height
    }

    #[must_use]
    pub const fn scale_x_milli(&self) -> u16 {
        self.scale_x_milli
    }

    #[must_use]
    pub const fn scale_y_milli(&self) -> u16 {
        self.scale_y_milli
    }

    #[must_use]
    pub const fn rotation(&self) -> DisplayRotation {
        self.rotation
    }

    /// Width in logical millipoints, rounded to the nearest integer.
    #[must_use]
    pub fn logical_width_milli(&self) -> u64 {
        logical_millipoints(self.pixel_width, self.scale_x_milli)
    }

    /// Height in logical millipoints, rounded to the nearest integer.
    #[must_use]
    pub fn logical_height_milli(&self) -> u64 {
        logical_millipoints(self.pixel_height, self.scale_y_milli)
    }

    pub(crate) fn validate(&self) -> Result<(), TopologyValidationError> {
        if self.id.is_zero() {
            return Err(TopologyValidationError::ZeroDisplayId);
        }
        if self.pixel_width == 0
            || self.pixel_height == 0
            || self.pixel_width > MAX_DISPLAY_PIXEL_DIMENSION
            || self.pixel_height > MAX_DISPLAY_PIXEL_DIMENSION
        {
            return Err(TopologyValidationError::InvalidPixelDimensions);
        }
        if !(MIN_DISPLAY_SCALE_MILLI..=MAX_DISPLAY_SCALE_MILLI).contains(&self.scale_x_milli)
            || !(MIN_DISPLAY_SCALE_MILLI..=MAX_DISPLAY_SCALE_MILLI).contains(&self.scale_y_milli)
        {
            return Err(TopologyValidationError::InvalidScale);
        }
        if self.origin_x_milli.unsigned_abs() > MAX_DISPLAY_ORIGIN_MILLI.unsigned_abs()
            || self.origin_y_milli.unsigned_abs() > MAX_DISPLAY_ORIGIN_MILLI.unsigned_abs()
        {
            return Err(TopologyValidationError::InvalidOrigin);
        }
        Ok(())
    }
}

/// A complete, revisioned snapshot for one endpoint in one session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct DisplayTopology {
    #[n(0)]
    schema_version: u16,
    #[n(1)]
    revision: u64,
    #[n(2)]
    displays: Vec<DisplayDescriptor>,
}

impl DisplayTopology {
    /// Builds a snapshot for the current topology schema.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/oversized graph, zero revision, duplicate
    /// identifiers, or invalid display geometry.
    pub fn new(
        revision: u64,
        displays: Vec<DisplayDescriptor>,
    ) -> Result<Self, TopologyValidationError> {
        let topology = Self {
            schema_version: DISPLAY_TOPOLOGY_SCHEMA_VERSION,
            revision,
            displays,
        };
        topology.validate()?;
        Ok(topology)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn displays(&self) -> &[DisplayDescriptor] {
        &self.displays
    }

    #[must_use]
    pub fn display(&self, id: SessionDisplayId) -> Option<&DisplayDescriptor> {
        self.displays.iter().find(|display| display.id == id)
    }

    pub(crate) fn validate(&self) -> Result<(), TopologyValidationError> {
        if self.schema_version != DISPLAY_TOPOLOGY_SCHEMA_VERSION {
            return Err(TopologyValidationError::UnsupportedSchemaVersion);
        }
        if self.revision == 0 {
            return Err(TopologyValidationError::ZeroRevision);
        }
        if self.displays.is_empty() || self.displays.len() > MAX_TOPOLOGY_DISPLAYS {
            return Err(TopologyValidationError::InvalidDisplayCount);
        }
        for (index, display) in self.displays.iter().enumerate() {
            display.validate()?;
            if self.displays[..index]
                .iter()
                .any(|seen| seen.id == display.id)
            {
                return Err(TopologyValidationError::DuplicateDisplayId);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TopologyValidationError {
    #[error("display topology schema version is unsupported")]
    UnsupportedSchemaVersion,
    #[error("display topology revision must be nonzero")]
    ZeroRevision,
    #[error("display topology count is outside the supported range")]
    InvalidDisplayCount,
    #[error("display topology contains a zero display identifier")]
    ZeroDisplayId,
    #[error("display topology contains a duplicate display identifier")]
    DuplicateDisplayId,
    #[error("display pixel dimensions are outside the supported range")]
    InvalidPixelDimensions,
    #[error("display scale is outside the supported range")]
    InvalidScale,
    #[error("display origin is outside the supported range")]
    InvalidOrigin,
}

fn logical_millipoints(pixels: u32, scale_milli: u16) -> u64 {
    // pixels / (scale_milli / 1000) logical points, expressed in thousandths.
    let numerator = u64::from(pixels) * 1_000_000;
    let scale = u64::from(scale_milli).max(1);
    (numerator + scale / 2) / scale
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(id: u32) -> DisplayDescriptor {
        DisplayDescriptor::new(
            SessionDisplayId::new(id),
            0,
            0,
            3_840,
            2_160,
            2_000,
            2_000,
            DisplayRotation::Degrees0,
        )
        .unwrap()
    }

    #[test]
    fn logical_geometry_is_scale_aware() {
        let display = display(1);
        assert_eq!(display.logical_width_milli(), 1_920_000);
        assert_eq!(display.logical_height_milli(), 1_080_000);
    }

    #[test]
    fn topology_rejects_duplicate_and_excessive_displays() {
        assert_eq!(
            DisplayTopology::new(1, vec![display(1), display(1)]),
            Err(TopologyValidationError::DuplicateDisplayId)
        );
        assert_eq!(
            DisplayTopology::new(
                1,
                (1..=u32::try_from(MAX_TOPOLOGY_DISPLAYS + 1).unwrap())
                    .map(display)
                    .collect(),
            ),
            Err(TopologyValidationError::InvalidDisplayCount)
        );
    }

    #[test]
    fn topology_rejects_zero_revision_and_out_of_range_geometry() {
        assert_eq!(
            DisplayTopology::new(0, vec![display(1)]),
            Err(TopologyValidationError::ZeroRevision)
        );
        assert_eq!(
            DisplayDescriptor::new(
                SessionDisplayId::new(1),
                0,
                0,
                0,
                1_080,
                1_000,
                1_000,
                DisplayRotation::Degrees0,
            ),
            Err(TopologyValidationError::InvalidPixelDimensions)
        );
    }
}
