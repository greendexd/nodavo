use std::io::{Read, Take};
use std::sync::Arc;
use std::time::Duration;

use nodavo_update::{
    DownloadMetadata, DownloadRequest, DownloadStream, ExternalEffectError, HttpsDownloader,
    MAX_MANIFEST_BYTES,
};

pub(super) trait ManifestFetcher: Send {
    fn fetch_manifest(&mut self) -> Result<Vec<u8>, ExternalEffectError>;
}

/// Blocking HTTPS boundary using the operating system's TLS verifier and root
/// store through `native-tls`.
///
/// Redirects, ambient proxy discovery, cookies, credentials, and transparent
/// decompression are not enabled. Callers execute this adapter only on a Tokio
/// blocking thread.
pub(super) struct NativeHttpsClient {
    agent: ureq::Agent,
    manifest_url: String,
}

impl NativeHttpsClient {
    pub(super) fn new(manifest_url: String) -> Result<Self, ExternalEffectError> {
        let connector = native_tls::TlsConnector::builder()
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .build()
            .map_err(|_| ExternalEffectError)?;
        let agent = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(connector))
            .redirects(0)
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .build();
        Ok(Self {
            agent,
            manifest_url,
        })
    }
}

impl ManifestFetcher for NativeHttpsClient {
    fn fetch_manifest(&mut self) -> Result<Vec<u8>, ExternalEffectError> {
        let response = self
            .agent
            .get(&self.manifest_url)
            .set("Accept", "application/json")
            .set("Accept-Encoding", "identity")
            .set("User-Agent", "Nodavo-Updater/0.1")
            .call()
            .map_err(|_| ExternalEffectError)?;
        if response.status() != 200 || has_content_encoding(&response) {
            return Err(ExternalEffectError);
        }
        if response
            .header("Content-Length")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_MANIFEST_BYTES)
        {
            return Err(ExternalEffectError);
        }

        let mut reader = response
            .into_reader()
            .take(u64::try_from(MAX_MANIFEST_BYTES + 1).map_err(|_| ExternalEffectError)?);
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|_| ExternalEffectError)?;
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ExternalEffectError);
        }
        Ok(bytes)
    }
}

pub(super) struct NativeHttpsStream {
    metadata: DownloadMetadata,
    reader: Take<Box<dyn Read + Send + Sync>>,
}

impl DownloadStream for NativeHttpsStream {
    fn metadata(&self) -> &DownloadMetadata {
        &self.metadata
    }

    fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, ExternalEffectError> {
        self.reader.read(buffer).map_err(|_| ExternalEffectError)
    }
}

impl HttpsDownloader for NativeHttpsClient {
    type Stream = NativeHttpsStream;

    fn open(&mut self, request: &DownloadRequest) -> Result<Self::Stream, ExternalEffectError> {
        let range = if request.resume_from() == 0 {
            None
        } else {
            Some(format!("bytes={}-", request.resume_from()))
        };
        let mut outbound = self
            .agent
            .get(request.url())
            .set("Accept", "application/octet-stream")
            .set("Accept-Encoding", "identity")
            .set("User-Agent", "Nodavo-Updater/0.1");
        if let Some(range) = &range {
            outbound = outbound.set("Range", range);
        }
        let response = outbound.call().map_err(|_| ExternalEffectError)?;
        if has_content_encoding(&response) {
            return Err(ExternalEffectError);
        }

        let remaining = request
            .expected_size()
            .checked_sub(request.resume_from())
            .ok_or(ExternalEffectError)?;
        let content_length = response
            .header("Content-Length")
            .ok_or(ExternalEffectError)?
            .parse::<u64>()
            .map_err(|_| ExternalEffectError)?;
        if content_length != remaining {
            return Err(ExternalEffectError);
        }

        if request.resume_from() == 0 {
            if response.status() != 200 || response.header("Content-Range").is_some() {
                return Err(ExternalEffectError);
            }
        } else if response.status() != 206
            || !response.header("Content-Range").is_some_and(|value| {
                content_range_matches(value, request.resume_from(), request.expected_size())
            })
        {
            return Err(ExternalEffectError);
        }

        let metadata = DownloadMetadata::new(
            request.url().to_owned(),
            request.resume_from(),
            request.expected_size(),
        )
        .map_err(|_| ExternalEffectError)?;
        Ok(NativeHttpsStream {
            metadata,
            reader: response.into_reader().take(remaining),
        })
    }
}

fn has_content_encoding(response: &ureq::Response) -> bool {
    response
        .header("Content-Encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
}

fn content_range_matches(value: &str, start: u64, total: u64) -> bool {
    let Some(value) = value.strip_prefix("bytes ") else {
        return false;
    };
    let Some((range, encoded_total)) = value.split_once('/') else {
        return false;
    };
    let Some((encoded_start, encoded_end)) = range.split_once('-') else {
        return false;
    };
    let Some(expected_end) = total.checked_sub(1) else {
        return false;
    };
    encoded_start.parse::<u64>() == Ok(start)
        && encoded_end.parse::<u64>() == Ok(expected_end)
        && encoded_total.parse::<u64>() == Ok(total)
}

#[cfg(test)]
mod tests {
    use super::content_range_matches;

    #[test]
    fn resumed_range_must_cover_the_exact_signed_remainder() {
        assert!(content_range_matches("bytes 4-9/10", 4, 10));
        assert!(!content_range_matches("bytes 3-9/10", 4, 10));
        assert!(!content_range_matches("bytes 4-8/10", 4, 10));
        assert!(!content_range_matches("bytes 4-9/*", 4, 10));
    }
}
