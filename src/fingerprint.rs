use std::pin::pin;

use aes::Aes128;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use cipher::{BlockEncryptMut, KeyIvInit};
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
    pub async fn from_reader<R: AsyncRead>(reader: R, size: u64, modified_at: i64) -> Result<Self> {
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
/// Please be aware that, due to these checksums being sparse, two identical checksums can be identical to
/// one another despite being generated from very slightly different files.
///
/// Using condensed MACs is more accurate to assess file integrity than the sparse checksum method,
/// but it is both more CPU and disk intensive to do so.
///
/// Here is an example of how to use this function:
/// ```rust,no_run
/// # async fn example() -> mega::Result<()> {
/// # let http_client = reqwest::Client::new();
/// # let mega = mega::Client::builder().build(http_client)?;
/// use tokio_util::compat::TokioAsyncReadCompatExt;
///
/// let nodes = mega.fetch_own_nodes().await?;
///
/// let remote_checksum = {
///     let node = nodes.get_node_by_path("/Root/some-remote-file.txt").unwrap();
///     node.sparse_checksum().unwrap()
/// };
///
/// let local_checksum = {
///     let file = tokio::fs::File::open("some-local-file.txt").await?;
///     let size = file.metadata().await?.len();
///     mega::compute_sparse_checksum(file.compat(), size).await?
/// };
///
/// if local_checksum == *remote_checksum {
///     println!("OK ! (the checksums are identical)");
/// } else {
///     println!("FAILED ! (the checksums differ)");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn compute_sparse_checksum<R: AsyncRead>(reader: R, size: u64) -> Result<[u8; 16]> {
    const MAXFULL: u64 = 8192;

    const CRC_SIZE: u64 = 16;
    const BLOCK_SIZE: u64 = CRC_SIZE * 4;

    match size {
        size if size <= 16 => {
            // tiny file: checksum is simply the file's content verbatim.
            let mut checksum = [0u8; 16];
            pin!(reader).read_exact(&mut checksum).await?;
            Ok(checksum)
        }
        size if size <= MAXFULL => {
            // small file: full coverage, four full CRC32s.
            let size = usize::try_from(size).unwrap();
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
            let mut reader = {
                let size = u64::try_from(size).unwrap();
                pin!(reader.take(size))
            };

            let mut block = [0u8; BLOCK_SIZE as usize];
            let blocks = MAXFULL / (BLOCK_SIZE * 4);

            let mut checksum = [0u8; 16];

            let mut cursor = 0;
            for idx in 0..4 {
                let mut hasher = crc32fast::Hasher::new();
                for blk in 0..blocks {
                    let offset = (size - BLOCK_SIZE) * (idx * blocks + blk) / (4 * blocks - 1);
                    let gap = offset - cursor;
                    futures::io::copy((&mut reader).take(gap), &mut futures::io::sink()).await?;
                    (&mut reader).read_exact(&mut block).await?;
                    hasher.update(&block);
                    cursor = offset + BLOCK_SIZE;
                }

                let crc = hasher.finalize();

                let begin = usize::try_from(idx * 4).unwrap();
                checksum[begin..(begin + 4)].copy_from_slice(&crc.to_be_bytes());
            }

            Ok(checksum)
        }
    }
}

/// This function computes a full-coverage condensed MAC, in the exact same way that MEGA does it.
///
/// This allows to compute a condensed MAC for any arbitrary data and compare it to the ones of remote MEGA nodes.
///
/// Using these MACs is more accurate to assess file integrity than the sparse checksum method,
/// but it is both more CPU and disk intensive to do so.
///
/// Here is an example of how to use this function:
/// ```rust,no_run
/// # async fn example() -> mega::Result<()> {
/// # let http_client = reqwest::Client::new();
/// # let mega = mega::Client::builder().build(http_client)?;
/// use tokio_util::compat::TokioAsyncReadCompatExt;
///
/// let nodes = mega.fetch_own_nodes().await?;
///
/// let (remote_condensed_mac, key, iv) = {
///     let node = nodes.get_node_by_path("/Root/some-remote-file.txt").unwrap();
///     let condensed_mac = node.condensed_mac().unwrap();
///     let key = node.aes_key();
///     let iv = node.aes_iv().unwrap();
///     (condensed_mac, key, iv)
/// };
///
/// let local_condensed_mac = {
///     let file = tokio::fs::File::open("some-local-file.txt").await?;
///     let size = file.metadata().await?.len();
///     mega::compute_condensed_mac(file.compat(), size, key, iv).await?
/// };
///
/// if local_condensed_mac == *remote_condensed_mac {
///     println!("OK ! (the MACs are identical)");
/// } else {
///     println!("FAILED ! (the MACs differ)");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn compute_condensed_mac<R: AsyncRead>(
    reader: R,
    size: u64,
    aes_key: &[u8; 16],
    aes_iv: &[u8; 8],
) -> Result<[u8; 8]> {
    let mut chunk_size: u64 = 131_072; // 2^17
    let mut cur_mac = [0u8; 16];

    let mut final_mac_data = [0u8; 16];
    let mut final_mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&final_mac_data).into());

    let mut buffer = {
        let chunk_size = usize::try_from(chunk_size).unwrap();
        Vec::with_capacity(chunk_size)
    };

    let mut reader = pin!(reader.take(size));

    let aes_iv = {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(aes_iv);
        data[8..].copy_from_slice(aes_iv);
        data
    };

    loop {
        buffer.clear();

        let bytes_read = (&mut reader)
            .take(chunk_size)
            .read_to_end(&mut buffer)
            .await?;

        if bytes_read == 0 {
            break;
        }

        let (chunks, leftover) = buffer.split_at(buffer.len() - buffer.len() % 16);

        let mut mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&aes_iv).into());
        for chunk in chunks.chunks_exact(16) {
            mac.encrypt_block_b2b_mut(chunk.into(), (&mut cur_mac).into());
        }

        if !leftover.is_empty() {
            let mut padded_chunk = [0u8; 16];
            padded_chunk[..leftover.len()].copy_from_slice(leftover);
            mac.encrypt_block_b2b_mut((&padded_chunk).into(), (&mut cur_mac).into());
        }

        final_mac.encrypt_block_b2b_mut((&cur_mac).into(), (&mut final_mac_data).into());

        if chunk_size < 1_048_576 {
            chunk_size += 131_072;
        }
    }

    for i in 0..4 {
        final_mac_data[i] = final_mac_data[i] ^ final_mac_data[i + 4];
        final_mac_data[i + 4] = final_mac_data[i + 8] ^ final_mac_data[i + 12];
    }

    Ok(final_mac_data[..8].try_into().unwrap())
}
