use std::pin::pin;

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use futures::io::{AsyncRead, AsyncReadExt};

use crate::Result;

/// Represents the node's fingerprint (useful for caching purposes).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NodeFingerprint {
    /// The checksum bytes of the node.
    pub checksum: [u8; 16],
    /// The last modified date of the node.
    pub modified_at: i64,
}

impl NodeFingerprint {
    pub fn new(checksum: [u8; 16], modified_at: i64) -> Self {
        Self {
            checksum,
            modified_at,
        }
    }

    #[allow(unused)]
    pub async fn from_reader<R: AsyncRead>(
        reader: R,
        size: usize,
        modified_at: i64,
    ) -> Result<Self> {
        Ok(Self::new(
            compute_sparse_checksum(reader, size).await?,
            modified_at,
        ))
    }

    pub fn deserialize(checksum_str: &str) -> Option<Self> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(checksum_str).ok()?;

        let (checksum, mtime) = decoded.split_at(16);
        let checksum = checksum.try_into().ok()?;

        let modified_at = {
            let (byte_count, mtime) = mtime.split_first().map(|(a, b)| (usize::from(*a), b))?;

            if byte_count > 8 || byte_count > mtime.len() {
                // incorrect byte count.
                return None;
            }

            mtime[..byte_count]
                .into_iter()
                .rev()
                .copied()
                .fold(0, |acc, byte| (acc << 8) + i64::from(byte))
        };

        Some(Self::new(checksum, modified_at))
    }

    pub fn serialize(&self) -> String {
        let mut buffer = vec![0u8; 16 + 8];

        buffer[..16].copy_from_slice(&self.checksum);

        let mut value = self.modified_at;
        let mut byte_count: u8 = 0;
        while value > 0 {
            buffer[16 + usize::from(byte_count)] = u8::try_from(value & 0xFF).unwrap();
            value >>= 8;
            byte_count += 1;
        }
        buffer[16] = byte_count;

        let bytes_written = 16 + usize::from(byte_count) + 1;
        BASE64_URL_SAFE_NO_PAD.encode(&buffer[..bytes_written])
    }
}

/// This function computes a sparse CRC32-based checksum, in the exact same way that MEGA does it.
///
/// This allows to compute a checksum for any arbitrary data and compare it to the ones of remote MEGA nodes.
///
/// Here is an example of how to use this function:
/// ```rust,no_run
/// # fn main() {
/// let nodes = mega.fetch_own_nodes().await?;
///
/// let remote_checksum = {
///     let node = nodes.get_node_by_path("/Root/some-remote-file.txt").unwrap();
///     node.checksum().unwrap()
/// };
///
/// let local_checksum = {
///     let file = File::open("some-local-file.txt").await?;
///     let size = file.metadata().await?.len();
///     mega::compute_checksum(file, size).await?
/// };
///
/// if local_checksum == remote_checksum {
///     println!("OK ! (the checksums are identical)");
/// } else {
///     println!("FAILED ! (the checksums differ)");
/// }
/// # }
/// ```
pub async fn compute_sparse_checksum<R: AsyncRead>(reader: R, size: usize) -> Result<[u8; 16]> {
    const MAXFULL: usize = 8192;

    const CRC_SIZE: usize = 16;
    const BLOCK_SIZE: usize = CRC_SIZE * 4;

    match size {
        size if size <= 16 => {
            // tiny file: checksum is simply the file's content verbatim.
            let mut checksum = [0u8; 16];
            pin!(reader).read_exact(&mut checksum).await?;
            Ok(checksum)
        }
        size if size <= MAXFULL => {
            // small file: full coverage, four full CRC32s.
            let mut buffer = vec![0u8; size];
            pin!(reader).read_exact(&mut buffer).await?;

            let mut checksum = [0u8; 16];
            for i in 0..4 {
                let crc = {
                    let begin = i * size / 4;
                    let end = (i + 1) * size / 4;
                    crc32fast::hash(&buffer[begin..end])
                };

                let begin = i * 4;
                checksum[begin..(begin + 4)].copy_from_slice(&crc.to_be_bytes());
            }

            Ok(checksum)
        }
        size => {
            // large file: sparse coverage, four sparse CRC32s.
            let mut reader = pin!(reader);

            let mut block = [0u8; BLOCK_SIZE];
            let blocks = MAXFULL / (BLOCK_SIZE * 4);

            let mut checksum = [0u8; 16];

            let mut cursor = 0;
            for idx in 0..4 {
                let mut hasher = crc32fast::Hasher::new();
                for blk in 0..blocks {
                    let offset = (size - BLOCK_SIZE) * (idx * blocks + blk) / (4 * blocks - 1);
                    let gap = u64::try_from(offset - cursor).unwrap();
                    futures::io::copy((&mut reader).take(gap), &mut futures::io::sink()).await?;
                    (&mut reader).read_exact(&mut block).await?;
                    hasher.update(&block);
                    cursor = offset + BLOCK_SIZE;
                }

                let crc = hasher.finalize();

                let begin = idx * 4;
                checksum[begin..(begin + 4)].copy_from_slice(&crc.to_be_bytes());
            }

            Ok(checksum)
        }
    }
}
