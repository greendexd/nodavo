//! Pure validation and canonical conversion for Windows clipboard formats.

use crate::WindowsPlatformError;

const HTML_PREFIX: &[u8] = b"<html><body><!--StartFragment-->";
const HTML_SUFFIX: &[u8] = b"<!--EndFragment--></body></html>";
const MAX_CF_HTML_OVERHEAD: usize = 1024;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const BMP_FILE_HEADER_BYTES: usize = 14;
const BI_RGB: u32 = 0;
const BI_BITFIELDS: u32 = 3;
const BI_ALPHABITFIELDS: u32 = 6;

pub(crate) fn encode_cf_html(
    fragment: &[u8],
    maximum: u64,
) -> Result<Vec<u8>, WindowsPlatformError> {
    validate_utf8_fragment(fragment, maximum)?;
    let provisional = cf_html_header(0, 0, 0, 0);
    let start_html = provisional.len();
    let start_fragment = start_html
        .checked_add(HTML_PREFIX.len())
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    let end_fragment = start_fragment
        .checked_add(fragment.len())
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    let end_html = end_fragment
        .checked_add(HTML_SUFFIX.len())
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    let header = cf_html_header(start_html, end_html, start_fragment, end_fragment);
    if header.len() != start_html {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    let capacity = end_html
        .checked_add(1)
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(header.as_bytes());
    encoded.extend_from_slice(HTML_PREFIX);
    encoded.extend_from_slice(fragment);
    encoded.extend_from_slice(HTML_SUFFIX);
    encoded.push(0);
    Ok(encoded)
}

pub(crate) fn decode_cf_html(
    encoded: &[u8],
    maximum: u64,
) -> Result<Vec<u8>, WindowsPlatformError> {
    let encoded_len = encoded
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let encoded = &encoded[..encoded_len];
    if encoded.contains(&0) || encoded.len() > maximum_cf_html_bytes(maximum)? {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    let probe_len = encoded.len().min(MAX_CF_HTML_OVERHEAD);
    let header_probe = std::str::from_utf8(&encoded[..probe_len])
        .map_err(|_| WindowsPlatformError::InvalidClipboardHtml)?;
    if !header_probe.starts_with("Version:") {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    let start_html = header_offset(header_probe, "StartHTML")?;
    if start_html > probe_len {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    let header = std::str::from_utf8(
        encoded
            .get(..start_html)
            .ok_or(WindowsPlatformError::InvalidClipboardHtml)?,
    )
    .map_err(|_| WindowsPlatformError::InvalidClipboardHtml)?;
    let end_html = header_offset(header, "EndHTML")?;
    let start_fragment = header_offset(header, "StartFragment")?;
    let end_fragment = header_offset(header, "EndFragment")?;
    if start_html > start_fragment
        || start_fragment > end_fragment
        || end_fragment > end_html
        || end_html > encoded.len()
    {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    let fragment = encoded
        .get(start_fragment..end_fragment)
        .ok_or(WindowsPlatformError::InvalidClipboardHtml)?;
    validate_utf8_fragment(fragment, maximum)?;
    Ok(fragment.to_vec())
}

fn cf_html_header(
    start_html: usize,
    end_html: usize,
    start_fragment: usize,
    end_fragment: usize,
) -> String {
    format!(
        concat!(
            "Version:1.0\r\n",
            "StartHTML:{start_html:010}\r\n",
            "EndHTML:{end_html:010}\r\n",
            "StartFragment:{start_fragment:010}\r\n",
            "EndFragment:{end_fragment:010}\r\n",
        ),
        start_html = start_html,
        end_html = end_html,
        start_fragment = start_fragment,
        end_fragment = end_fragment,
    )
}

pub(crate) fn maximum_cf_html_bytes(maximum: u64) -> Result<usize, WindowsPlatformError> {
    usize::try_from(maximum)
        .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
        .checked_add(MAX_CF_HTML_OVERHEAD)
        .ok_or(WindowsPlatformError::ClipboardTooLarge)
}

fn header_offset(header: &str, name: &str) -> Result<usize, WindowsPlatformError> {
    let prefix = format!("{name}:");
    let value = header
        .lines()
        .find_map(|line| {
            line.strip_suffix('\r')
                .unwrap_or(line)
                .strip_prefix(&prefix)
        })
        .ok_or(WindowsPlatformError::InvalidClipboardHtml)?
        .trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    value
        .parse()
        .map_err(|_| WindowsPlatformError::InvalidClipboardHtml)
}

fn validate_utf8_fragment(bytes: &[u8], maximum: u64) -> Result<(), WindowsPlatformError> {
    if bytes.contains(&0)
        || u64::try_from(bytes.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
            > maximum
        || std::str::from_utf8(bytes).is_err()
    {
        return Err(WindowsPlatformError::InvalidClipboardHtml);
    }
    Ok(())
}

pub(crate) fn validate_png(bytes: &[u8], maximum: u64) -> Result<(), WindowsPlatformError> {
    if !bytes.starts_with(PNG_SIGNATURE)
        || u64::try_from(bytes.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
            > maximum
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let mut cursor = PNG_SIGNATURE.len();
    let mut chunk_index = 0_usize;
    let mut saw_idat = false;
    loop {
        let header_end = cursor
            .checked_add(8)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
        let header = bytes
            .get(cursor..header_end)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
        let data_len = usize::try_from(u32::from_be_bytes(
            header[..4]
                .try_into()
                .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
        ))
        .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?;
        let chunk_type: [u8; 4] = header[4..]
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?;
        if !chunk_type.iter().all(u8::is_ascii_alphabetic) || chunk_type[2].is_ascii_lowercase() {
            return Err(WindowsPlatformError::InvalidClipboardImage);
        }
        let data_end = header_end
            .checked_add(data_len)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
        let chunk_data = bytes
            .get(header_end..data_end)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
        let expected_crc = u32::from_be_bytes(
            bytes
                .get(data_end..chunk_end)
                .ok_or(WindowsPlatformError::InvalidClipboardImage)?
                .try_into()
                .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
        );
        if png_crc32(&bytes[cursor + 4..data_end]) != expected_crc {
            return Err(WindowsPlatformError::InvalidClipboardImage);
        }
        match &chunk_type {
            b"IHDR" if chunk_index == 0 => validate_png_header(chunk_data)?,
            b"IDAT" => saw_idat = true,
            b"IEND" if data_len == 0 && saw_idat && chunk_end == bytes.len() => return Ok(()),
            b"IHDR" | b"IEND" => return Err(WindowsPlatformError::InvalidClipboardImage),
            _ if chunk_index == 0 => return Err(WindowsPlatformError::InvalidClipboardImage),
            _ => {}
        }
        cursor = chunk_end;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    }
}

fn validate_png_header(data: &[u8]) -> Result<(), WindowsPlatformError> {
    if data.len() != 13 {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let width = u32::from_be_bytes(
        data[..4]
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
    );
    let height = u32::from_be_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
    );
    let valid_depth = match data[9] {
        0 => matches!(data[8], 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(data[8], 8 | 16),
        3 => matches!(data[8], 1 | 2 | 4 | 8),
        _ => false,
    };
    if width == 0
        || height == 0
        || !valid_depth
        || data[10] != 0
        || data[11] != 0
        || !matches!(data[12], 0 | 1)
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    Ok(())
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub(crate) fn dib_to_bmp(dib: &[u8], maximum: u64) -> Result<Vec<u8>, WindowsPlatformError> {
    let pixel_offset = validate_canonical_dib(dib, maximum)?;
    let file_size = BMP_FILE_HEADER_BYTES
        .checked_add(dib.len())
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    if u64::try_from(file_size).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > maximum {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    let file_pixel_offset = BMP_FILE_HEADER_BYTES
        .checked_add(pixel_offset)
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    let mut bmp = Vec::with_capacity(file_size);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(
        &u32::try_from(file_size)
            .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
            .to_le_bytes(),
    );
    bmp.extend_from_slice(&[0; 4]);
    bmp.extend_from_slice(
        &u32::try_from(file_pixel_offset)
            .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
            .to_le_bytes(),
    );
    bmp.extend_from_slice(dib);
    Ok(bmp)
}

pub(crate) fn bmp_to_dib(bmp: &[u8], maximum: u64) -> Result<Vec<u8>, WindowsPlatformError> {
    if bmp.len() < BMP_FILE_HEADER_BYTES
        || u64::try_from(bmp.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > maximum
        || &bmp[..2] != b"BM"
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let declared_size = usize::try_from(read_u32_le(bmp, 2)?)
        .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?;
    let pixel_offset = usize::try_from(read_u32_le(bmp, 10)?)
        .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?;
    if declared_size != bmp.len() || bmp[6..10] != [0; 4] {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let dib = &bmp[BMP_FILE_HEADER_BYTES..];
    let expected_pixel_offset = BMP_FILE_HEADER_BYTES
        .checked_add(validate_canonical_dib(dib, maximum)?)
        .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    if pixel_offset != expected_pixel_offset {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    Ok(dib.to_vec())
}

fn validate_canonical_dib(dib: &[u8], maximum: u64) -> Result<usize, WindowsPlatformError> {
    if dib.len() < 40
        || u64::try_from(dib.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > maximum
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let header_size = usize::try_from(read_u32_le(dib, 0)?)
        .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?;
    if !matches!(header_size, 40 | 52 | 56 | 108 | 124) || header_size > dib.len() {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let width = read_i32_le(dib, 4)?;
    let height = read_i32_le(dib, 8)?;
    let planes = read_u16_le(dib, 12)?;
    let bit_count = read_u16_le(dib, 14)?;
    let compression = read_u32_le(dib, 16)?;
    let colors_used = read_u32_le(dib, 32)?;
    if width <= 0
        || height == 0
        || height == i32::MIN
        || planes != 1
        || !matches!(bit_count, 1 | 4 | 8 | 16 | 24 | 32)
        || !matches!(compression, BI_RGB | BI_BITFIELDS | BI_ALPHABITFIELDS)
        || (compression != BI_RGB && !matches!(bit_count, 16 | 32))
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    if header_size == 124 && (read_u32_le(dib, 112)? != 0 || read_u32_le(dib, 116)? != 0) {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let maximum_colors = if bit_count <= 8 {
        1_u32 << bit_count
    } else {
        0
    };
    if (maximum_colors == 0 && colors_used != 0) || colors_used > maximum_colors {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let colors = if colors_used == 0 {
        maximum_colors
    } else {
        colors_used
    };
    let external_masks = if header_size == 40 {
        match compression {
            BI_BITFIELDS => 12,
            BI_ALPHABITFIELDS => 16,
            _ => 0,
        }
    } else {
        0
    };
    validate_color_masks(dib, header_size, compression, bit_count)?;
    let palette_bytes = usize::try_from(colors)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    let pixel_offset = header_size
        .checked_add(external_masks)
        .and_then(|offset| offset.checked_add(palette_bytes))
        .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    let row_bits = u64::from(bit_count)
        .checked_mul(u64::try_from(width).map_err(|_| WindowsPlatformError::InvalidClipboardImage)?)
        .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    let row_bytes = row_bits
        .checked_add(31)
        .map(|bits| (bits / 32) * 4)
        .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    let pixel_bytes = row_bytes
        .checked_mul(
            u64::try_from(height.abs()).map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
        )
        .ok_or(WindowsPlatformError::InvalidClipboardImage)?;
    let expected_len = pixel_offset
        .checked_add(
            usize::try_from(pixel_bytes).map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
        )
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    if expected_len != dib.len() {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let declared_image = read_u32_le(dib, 20)?;
    if declared_image != 0 && u64::from(declared_image) != pixel_bytes {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    Ok(pixel_offset)
}

fn validate_color_masks(
    dib: &[u8],
    header_size: usize,
    compression: u32,
    bit_count: u16,
) -> Result<(), WindowsPlatformError> {
    if compression == BI_RGB {
        return Ok(());
    }
    if compression == BI_ALPHABITFIELDS && !matches!(header_size, 40 | 56 | 108 | 124) {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let red = read_u32_le(dib, 40)?;
    let green = read_u32_le(dib, 44)?;
    let blue = read_u32_le(dib, 48)?;
    let alpha = if compression == BI_ALPHABITFIELDS {
        read_u32_le(dib, 52)?
    } else {
        0
    };
    let masks = [red, green, blue, alpha];
    let allowed_bits = if bit_count == 32 {
        u32::MAX
    } else {
        (1_u32 << bit_count) - 1
    };
    if red == 0
        || green == 0
        || blue == 0
        || (compression == BI_ALPHABITFIELDS && alpha == 0)
        || masks.iter().any(|mask| mask & !allowed_bits != 0)
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    for (index, mask) in masks.iter().enumerate() {
        if *mask != 0 && masks[index + 1..].iter().any(|other| mask & other != 0) {
            return Err(WindowsPlatformError::InvalidClipboardImage);
        }
    }
    Ok(())
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, WindowsPlatformError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
    ))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, WindowsPlatformError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
    ))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32, WindowsPlatformError> {
    Ok(i32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_PIXEL_PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52, 0,
        0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 0x49, 0x44,
        0x41, 0x54, 8, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0, 5, 0, 1, 0xff, 0x72, 0x9c,
        0x52, 0x67, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    #[test]
    fn cf_html_round_trip_uses_byte_offsets_and_rejects_tampering() {
        let fragment = "<b>Привет</b>".as_bytes();
        let encoded = encode_cf_html(fragment, 1024).unwrap();
        assert_eq!(decode_cf_html(&encoded, 1024).unwrap(), fragment);

        let mut invalid = encoded;
        let index = invalid
            .windows(b"EndFragment:".len())
            .position(|window| window == b"EndFragment:")
            .unwrap();
        invalid[index + "EndFragment:".len()] = b'9';
        assert_eq!(
            decode_cf_html(&invalid, 1024),
            Err(WindowsPlatformError::InvalidClipboardHtml)
        );
    }

    #[test]
    fn png_validator_checks_structure_and_crc() {
        assert!(validate_png(ONE_PIXEL_PNG, 1024).is_ok());
        let mut corrupt = ONE_PIXEL_PNG.to_vec();
        corrupt[40] ^= 1;
        assert_eq!(
            validate_png(&corrupt, 1024),
            Err(WindowsPlatformError::InvalidClipboardImage)
        );
    }

    #[test]
    fn canonical_bmp_round_trips_a_strict_rgb_dib() {
        let mut dib = vec![0_u8; 44];
        dib[0..4].copy_from_slice(&40_u32.to_le_bytes());
        dib[4..8].copy_from_slice(&1_i32.to_le_bytes());
        dib[8..12].copy_from_slice(&1_i32.to_le_bytes());
        dib[12..14].copy_from_slice(&1_u16.to_le_bytes());
        dib[14..16].copy_from_slice(&24_u16.to_le_bytes());
        dib[20..24].copy_from_slice(&4_u32.to_le_bytes());
        dib[40..44].copy_from_slice(&[0x11, 0x22, 0x33, 0]);

        let bmp = dib_to_bmp(&dib, 1024).unwrap();
        assert_eq!(bmp_to_dib(&bmp, 1024).unwrap(), dib);
        let mut invalid = bmp;
        invalid[10] = 0;
        assert_eq!(
            bmp_to_dib(&invalid, 1024),
            Err(WindowsPlatformError::InvalidClipboardImage)
        );
    }

    #[test]
    fn canonical_bmp_rejects_overlapping_bitfield_masks() {
        let mut dib = vec![0_u8; 56];
        dib[0..4].copy_from_slice(&40_u32.to_le_bytes());
        dib[4..8].copy_from_slice(&1_i32.to_le_bytes());
        dib[8..12].copy_from_slice(&1_i32.to_le_bytes());
        dib[12..14].copy_from_slice(&1_u16.to_le_bytes());
        dib[14..16].copy_from_slice(&16_u16.to_le_bytes());
        dib[16..20].copy_from_slice(&BI_BITFIELDS.to_le_bytes());
        dib[20..24].copy_from_slice(&4_u32.to_le_bytes());
        dib[40..44].copy_from_slice(&0x7c00_u32.to_le_bytes());
        dib[44..48].copy_from_slice(&0x7c00_u32.to_le_bytes());
        dib[48..52].copy_from_slice(&0x001f_u32.to_le_bytes());

        assert_eq!(
            dib_to_bmp(&dib, 1024),
            Err(WindowsPlatformError::InvalidClipboardImage)
        );
    }
}
