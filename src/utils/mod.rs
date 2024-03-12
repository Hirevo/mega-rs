use std::collections::HashMap;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use cipher::BlockDecrypt;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac_array;
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};

pub mod rsa;

use crate::http::UserSession;
use crate::protocol::commands::UserAttributesResponse;
use crate::Result;

/// Represents storage quotas from MEGA.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageQuotas {
    /// The amount of memory used (in bytes).
    pub memory_used: u64,
    /// The total amount of memory, used or unused (in bytes).
    pub memory_total: u64,
}

pub(crate) fn prepare_key_v1(password: &[u8]) -> [u8; 16] {
    let mut data = GenericArray::from([
        0x93u8, 0xC4, 0x67, 0xE3, 0x7D, 0xB0, 0xC7, 0xA4, 0xD1, 0xBE, 0x3F, 0x81, 0x01, 0x52, 0xCB,
        0x56,
    ]);

    for _ in 0..65536 {
        for chunk in password.chunks(16) {
            let mut key = [0u8; 16];
            key[0..chunk.len()].copy_from_slice(chunk);
            let aes = Aes128::new(&GenericArray::from(key));
            aes.encrypt_block(&mut data);
        }
    }

    data.into()
}

pub(crate) fn prepare_key_v2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    pbkdf2_hmac_array::<Sha512, 32>(password, salt, 100_000)
}

pub(crate) fn encrypt_ebc_in_place(key: &[u8], data: &mut [u8]) {
    let aes = Aes128::new(key.into());
    for block in data.chunks_mut(16) {
        aes.encrypt_block(block.into())
    }
}

pub(crate) fn decrypt_ebc_in_place(key: &[u8], data: &mut [u8]) {
    let aes = Aes128::new(key.into());
    for block in data.chunks_mut(16) {
        aes.decrypt_block(block.into())
    }
}

pub(crate) fn unmerge_key_mac(key: &mut [u8]) {
    let (fst, snd) = key.split_at_mut(16);
    for (a, b) in fst.iter_mut().zip(snd) {
        *a ^= *b;
    }
}

pub(crate) fn merge_key_mac(key: &mut [u8]) {
    let (fst, snd) = key.split_at_mut(16);
    for (a, b) in fst.iter_mut().zip(snd) {
        *a ^= *b;
    }
}

pub(crate) fn random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    Alphanumeric.sample_string(&mut rng, len)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum KeysAttrTag {
    Version = 1,
    CreationTime = 2,
    Identity = 3,
    Generation = 4,
    Attr = 5,
    PrivEd25519 = 16,
    PrivCu25519 = 17,
    PrivRsa = 18,
    AuthringEd25519 = 32,
    AuthringCu25519 = 33,
    ShareKeys = 48,
    PendingOutshares = 64,
    PendingInshares = 65,
    Backups = 80,
    Warnings = 96,
}

impl TryFrom<u8> for KeysAttrTag {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(KeysAttrTag::Version),
            2 => Ok(KeysAttrTag::CreationTime),
            3 => Ok(KeysAttrTag::Identity),
            4 => Ok(KeysAttrTag::Generation),
            5 => Ok(KeysAttrTag::Attr),
            16 => Ok(KeysAttrTag::PrivEd25519),
            17 => Ok(KeysAttrTag::PrivCu25519),
            18 => Ok(KeysAttrTag::PrivRsa),
            32 => Ok(KeysAttrTag::AuthringEd25519),
            33 => Ok(KeysAttrTag::AuthringCu25519),
            48 => Ok(KeysAttrTag::ShareKeys),
            64 => Ok(KeysAttrTag::PendingOutshares),
            65 => Ok(KeysAttrTag::PendingInshares),
            80 => Ok(KeysAttrTag::Backups),
            96 => Ok(KeysAttrTag::Warnings),
            _ => Err(()),
        }
    }
}

pub(crate) fn extract_share_keys(
    session: &UserSession,
    attr: &UserAttributesResponse,
) -> Result<HashMap<String, Vec<u8>>> {
    let hkdf = Hkdf::<Sha256>::new(None, &session.key);
    let mut derived_key = [0u8; 16];
    hkdf.expand(&[1], &mut derived_key)?;

    let attr_value = BASE64_URL_SAFE_NO_PAD.decode(&attr.attr_value)?;

    // the attribute value consists of:
    // - 1 byte guaranteed to be `20`.
    // - 1 byte that is declared reserved (usually `0`).
    // - 12 bytes of IV data suitable for the AES-128-GCM algorithm.
    // - arbitrarily-sized payload to be decrypted using AES-128-GCM.

    assert_eq!(attr_value[0], 20);
    let (iv, data) = attr_value[2..].split_at(12);
    let gcm = Aes128Gcm::new(derived_key.as_slice().into());
    let mut data = data.to_vec();
    gcm.decrypt_in_place(iv.into(), &[], &mut data)?;

    // this attribute's payload consists of a variable number of "packets"
    // that are prefixed with a tag (1 byte) and the length of their payload (3 bytes).

    let mut share_keys = HashMap::default();

    let mut cursor = 0;
    while cursor < data.len() {
        let Ok(tag) = KeysAttrTag::try_from(data[cursor]) else {
            continue;
        };
        let len = (usize::from(data[cursor + 1]) << 16)
            + (usize::from(data[cursor + 2]) << 8)
            + usize::from(data[cursor + 3]);
        cursor += 4;

        if tag == KeysAttrTag::ShareKeys {
            // The share keys section consists of multiple 23 bytes long chunks,
            // each corresponding to a single share key.
            // Each chunk consists of:
            // - the shared node's handle (6 bytes)
            // - the node's share key (16 bytes)
            // - trust flag (1 byte)
            //   (this flag seems to have to do with whether the key has been "exposed" in some way?)

            for chunk in data[cursor..(cursor + len)].chunks(23) {
                let (handle, rest) = chunk.split_at(6);
                let (share_key, _trust) = rest.split_at(16);
                let handle = BASE64_URL_SAFE_NO_PAD.encode(handle);
                share_keys.insert(handle, share_key.to_vec());
            }

            break;
        }

        cursor += len;
    }

    Ok(share_keys)
}

pub(crate) fn extract_attachments(attrs_str: &str) -> (Option<String>, Option<String>) {
    let mut thumbnail_handle = None;
    let mut preview_image_handle = None;

    // format: {bundle_id}:{attr_type}*{attr_handle}
    let attrs = attrs_str
        .split('/')
        .filter_map(|it| it.split_once(':')?.1.split_once('*'));

    for (kind, handle) in attrs {
        match kind {
            "0" => {
                thumbnail_handle = Some(handle.to_string());
            }
            "1" => {
                preview_image_handle = Some(handle.to_string());
            }
            _ => continue,
        }
    }

    (thumbnail_handle, preview_image_handle)
}

/// Produces an infinite iterator of all the consecutive chunk bounds.
#[allow(unused)]
pub(crate) fn chunks_iterator() -> impl Iterator<Item = (u64, u64)> {
    std::iter::successors(Some(131_072), |&(mut chunk_size): &u64| {
        if chunk_size < 1_048_576 {
            chunk_size += 131_072;
        }
        Some(chunk_size)
    })
    .scan(0, |start, chunk_size| {
        let bounds = (*start, *start + chunk_size - 1);
        *start = bounds.1 + 1;
        Some(bounds)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_buffer(size: usize, start: usize, step: usize) -> Vec<u8> {
        (0..size)
            .map(|i| u8::try_from((start + i * step) % 255).unwrap())
            .collect()
    }

    #[test]
    fn prepare_key_v1_8_bytes_test() {
        let buffer = test_buffer(8, 0, 1);
        let result = prepare_key_v1(buffer.as_slice());
        let result = hex::encode(result);

        assert_eq!(result.as_str(), "c4589a459956887caf0b408635c3c03b");
    }

    #[test]
    fn prepare_key_v1_10_bytes_test() {
        let buffer = test_buffer(10, 0, 1);
        let result = prepare_key_v1(buffer.as_slice());
        let result = hex::encode(result);

        assert_eq!(result.as_str(), "59930b1c55d783ac77df4c4ff261b0f1");
    }

    #[test]
    fn prepare_key_v1_64_bytes_test() {
        let buffer = test_buffer(64, 0, 1);
        let result = prepare_key_v1(buffer.as_slice());
        let result = hex::encode(result);

        assert_eq!(result.as_str(), "83bd84689f057f9ed9834b3ecb81d80e");
    }
}
