//! This is an API client library for interacting with MEGA's API using Rust.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use aes::Aes128;
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeZone, Utc};
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

mod commands;
mod error;
mod http;
mod utils;

pub use crate::commands::NodeKind;
pub use crate::error::{Error, ErrorCode, Result};
pub use crate::utils::StorageQuotas;

use crate::commands::{Request, Response, UploadAttributes};
use crate::http::{ClientState, HttpClient, UserSession};
use crate::utils::FileAttributes;

pub(crate) const DEFAULT_API_ORIGIN: &str = "https://g.api.mega.co.nz/";

/// A builder to initialize a [`Client`] instance.
pub struct ClientBuilder {
    /// The API's origin.
    origin: Url,
    /// The number of allowed retries.
    max_retries: usize,
    /// The minimum amount of time between retries.
    min_retry_delay: Duration,
    /// The maximum amount of time between retries.
    max_retry_delay: Duration,
    /// The timeout duration to use for each request.
    timeout: Option<Duration>,
    /// Whether to use HTTPS for file downloads and uploads, instead of plain HTTP.
    ///
    /// Using plain HTTP for file transfers is fine because the file contents are already encrypted,
    /// making protocol-level encryption a bit redundant and potentially slowing down the transfer.
    https: bool,
}

impl ClientBuilder {
    /// Creates a default [`ClientBuilder`].
    pub fn new() -> Self {
        Self {
            origin: Url::parse(DEFAULT_API_ORIGIN).unwrap(),
            max_retries: 10,
            min_retry_delay: Duration::from_millis(10),
            max_retry_delay: Duration::from_secs(5),
            timeout: Some(Duration::from_secs(10)),
            https: false,
        }
    }

    /// Sets the API's origin.
    pub fn origin(mut self, origin: impl Into<Url>) -> Self {
        self.origin = origin.into();
        self
    }

    /// Sets the maximum amount of retries.
    pub fn max_retries(mut self, amount: usize) -> Self {
        self.max_retries = amount;
        self
    }

    /// Sets the minimum delay duration between retries.
    pub fn min_retry_delay(mut self, delay: Duration) -> Self {
        self.min_retry_delay = delay;
        self
    }

    /// Sets the maximum delay duration between retries.
    pub fn max_retry_delay(mut self, delay: Duration) -> Self {
        self.max_retry_delay = delay;
        self
    }

    /// Sets the timeout duration to use for each request.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Sets whether to use HTTPS for file uploads and downloads, instead of plain HTTP.
    pub fn https(mut self, value: bool) -> Self {
        self.https = value;
        self
    }

    /// Builds a [`Client`] instance with the current settings and the specified HTTP client.
    pub fn build<T: HttpClient + 'static>(self, client: T) -> Result<Client> {
        let state = ClientState {
            origin: self.origin,
            max_retries: self.max_retries,
            min_retry_delay: self.min_retry_delay,
            max_retry_delay: self.max_retry_delay,
            timeout: self.timeout,
            https: self.https,
            id_counter: AtomicU64::new(0),
            session: None,
        };

        Ok(Client {
            state,
            client: Box::new(client),
        })
    }
}

/// The MEGA API Client itself.
pub struct Client {
    /// The client's state.
    pub(crate) state: ClientState,
    /// The HTTP client.
    pub(crate) client: Box<dyn HttpClient>,
}

impl Client {
    /// Creates a builder to initialize a [`Client`] instance.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Sends a request to the MEGA API.
    pub(crate) async fn send_requests(&self, requests: &[Request]) -> Result<Vec<Response>> {
        self.client.send_requests(&self.state, requests, &[]).await
    }

    /// Authenticates this session with MEGA.
    pub async fn login(&mut self, email: &str, password: &str, mfa: Option<&str>) -> Result<()> {
        let email = email.to_lowercase();

        let request = Request::PreLogin {
            user: email.clone(),
        };
        let responses = self.send_requests(&[request]).await?;

        let response = match responses.as_slice() {
            [Response::PreLogin(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let (login_key, user_handle) = match (response.version, response.salt.as_ref()) {
            (1, _) => {
                let key = utils::prepare_key_v1(password.as_bytes());

                let mut hash = GenericArray::from([0u8; 16]);
                for (i, x) in email.bytes().enumerate() {
                    hash[i % 16] ^= x;
                }

                let aes = Aes128::new(key.as_slice().into());
                for _ in 0..16384 {
                    aes.encrypt_block(&mut hash);
                }

                let mut user_handle = [0u8; 8];
                user_handle[..4].copy_from_slice(&hash[0..4]);
                user_handle[4..].copy_from_slice(&hash[8..12]);

                let user_handle = BASE64_URL_SAFE_NO_PAD.encode(&user_handle);

                (key, user_handle)
            }
            (2, Some(salt)) => {
                // TODO: investigate if we really need to re-encode using standard base64 alphabet (for the `pbkdf2` crate).
                let salt = BASE64_URL_SAFE_NO_PAD.decode(salt)?;
                let salt = BASE64_STANDARD_NO_PAD.encode(salt);

                let key = utils::prepare_key_v2(password.as_bytes(), salt.as_str())?;

                let (key, user_handle) = key.split_at(16);

                let key = <[u8; 16]>::try_from(key).unwrap();
                let user_handle = BASE64_URL_SAFE_NO_PAD.encode(user_handle);

                (key, user_handle)
            }
            (2, None) => {
                // missing salt
                todo!()
            }
            (version, _) => {
                return Err(Error::UnknownUserLoginVersion(version));
            }
        };

        let request = Request::Login {
            user: email.clone(),
            hash: user_handle.clone(),
            si: None,
            mfa: mfa.map(|it| it.to_string()),
            session_key: None,
        };
        let responses = self.send_requests(&[request]).await?;

        let response = match responses.as_slice() {
            [Response::Login(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let mut key = BASE64_URL_SAFE_NO_PAD.decode(&response.k)?;
        utils::decrypt_ebc_in_place(&login_key, &mut key);

        let t = BASE64_URL_SAFE_NO_PAD.decode(&response.csid)?;
        let (m, _) = utils::get_mpi(&t);

        let mut privk = BASE64_URL_SAFE_NO_PAD.decode(&response.privk)?;
        utils::decrypt_ebc_in_place(&key, &mut privk);

        let (p, q, d) = utils::get_rsa_key(&privk);
        let r = utils::decrypt_rsa(m, p, q, d);

        let sid = BASE64_URL_SAFE_NO_PAD.encode(&r.to_bytes_be()[..43]);

        self.state.session = Some(UserSession {
            sid,
            key: key[..16].try_into().unwrap(),
        });

        Ok(())
    }

    /// Logs out of the current session with MEGA.
    pub async fn logout(&mut self) -> Result<()> {
        let request = Request::Logout {};
        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => {
                self.state.session = None;
                Ok(())
            }
            [Response::Error(code)] => Err(Error::from(*code)),
            _ => Err(Error::InvalidResponseType),
        }
    }

    /// Fetches all nodes from the user's own MEGA account.
    pub async fn fetch_own_nodes(&self) -> Result<Nodes> {
        let request = Request::FetchNodes { c: 1, r: None };
        let responses = self.send_requests(&[request]).await?;

        let files = match responses.as_slice() {
            [Response::FetchNodes(files)] => files,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let session = self.state.session.as_ref().unwrap();

        let mut nodes = HashMap::<String, Node>::default();

        for file in &files.nodes {
            match file.kind {
                NodeKind::File | NodeKind::Folder => {
                    let (file_user, file_key) = file.key.as_ref().unwrap().split_once(":").unwrap();

                    if file.user == file_user {
                        // self-owned file or folder

                        let mut file_key = BASE64_URL_SAFE_NO_PAD.decode(file_key)?;
                        utils::decrypt_ebc_in_place(&session.key, &mut file_key);

                        let attrs = {
                            let mut file_key = file_key.clone();
                            utils::unmerge_key_mac(&mut file_key);

                            let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                            FileAttributes::decrypt_and_unpack(
                                &file_key[..16],
                                buffer.as_mut_slice(),
                            )?
                        };

                        let node = Node {
                            name: attrs.name,
                            hash: file.hash.clone(),
                            size: file.sz.unwrap_or(0),
                            kind: file.kind,
                            parent: (!file.parent.is_empty()).then(|| file.parent.clone()),
                            children: nodes
                                .values()
                                .filter_map(|it| {
                                    let parent = it.parent.as_ref()?;
                                    (parent == &file.hash).then(|| file.hash.clone())
                                })
                                .collect(),
                            key: file_key,
                            created_at: Some(Utc.timestamp_opt(file.ts as i64, 0).unwrap()),
                            download_id: None,
                        };

                        if let Some(parent) = nodes.get_mut(&file.parent) {
                            parent.children.push(node.hash.clone());
                        }

                        nodes.insert(node.hash.clone(), node);
                    }
                }
                NodeKind::Root => {
                    let node = Node {
                        name: String::from("Root"),
                        hash: file.hash.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: NodeKind::Root,
                        parent: None,
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.hash).then(|| file.hash.clone())
                            })
                            .collect(),
                        key: <_>::default(),
                        created_at: Some(Utc.timestamp_opt(file.ts as i64, 0).unwrap()),
                        download_id: None,
                    };
                    nodes.insert(node.hash.clone(), node);
                }
                NodeKind::Inbox => {
                    let node = Node {
                        name: String::from("Inbox"),
                        hash: file.hash.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: NodeKind::Inbox,
                        parent: None,
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.hash).then(|| file.hash.clone())
                            })
                            .collect(),
                        key: <_>::default(),
                        created_at: Some(Utc.timestamp_opt(file.ts as i64, 0).unwrap()),
                        download_id: None,
                    };
                    nodes.insert(node.hash.clone(), node);
                }
                NodeKind::Trash => {
                    let node = Node {
                        name: String::from("Trash"),
                        hash: file.hash.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: NodeKind::Trash,
                        parent: None,
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.hash).then(|| file.hash.clone())
                            })
                            .collect(),
                        key: <_>::default(),
                        created_at: Some(Utc.timestamp_opt(file.ts as i64, 0).unwrap()),
                        download_id: None,
                    };
                    nodes.insert(node.hash.clone(), node);
                }
                NodeKind::Unknown => continue,
            }
        }

        Ok(Nodes::new(nodes))
    }

    /// Fetches all nodes from a public MEGA link.
    pub async fn fetch_public_nodes(&self, url: &str) -> Result<Nodes> {
        // supported URL formats:
        // - https://mega.nz/file/{node_id}#{node_key}
        // - https://mega.nz/folder/{node_id}#{node_key}

        let shared_url = Url::parse(url)?;
        let (node_kind, node_id) = {
            let segments: Vec<&str> = shared_url.path().split("/").skip(1).collect();
            match segments.as_slice() {
                ["file", file_id] => (NodeKind::File, file_id.to_string()),
                ["folder", folder_id] => (NodeKind::Folder, folder_id.to_string()),
                _ => {
                    // TODO: replace with its own error enum variant.
                    return Err(Error::Other("invalid URL format".into()));
                }
            }
        };

        let node_key = {
            let fragment = shared_url
                .fragment()
                .ok_or_else(|| Error::Other("invalid URL format".into()))?;
            let key = fragment.split_once("/").map_or(fragment, |it| it.0);
            BASE64_URL_SAFE_NO_PAD.decode(key)?
        };

        let mut nodes = HashMap::<String, Node>::default();

        match node_kind {
            NodeKind::File => {
                let request = Request::Download {
                    g: 1,
                    ssl: 0,
                    p: Some(node_id.clone()),
                    n: None,
                };
                let responses = self.send_requests(&[request]).await?;

                let file = match responses.as_slice() {
                    [Response::Download(file)] => file,
                    [Response::Error(code)] => {
                        return Err(Error::from(*code));
                    }
                    _ => {
                        return Err(Error::InvalidResponseType);
                    }
                };

                let attrs = {
                    let mut node_key = node_key.clone();
                    utils::unmerge_key_mac(&mut node_key);

                    let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                    FileAttributes::decrypt_and_unpack(&node_key[..16], buffer.as_mut_slice())?
                };

                let node = Node {
                    name: attrs.name,
                    hash: node_id.clone(),
                    size: file.size,
                    kind: NodeKind::File,
                    parent: None,
                    children: Vec::default(),
                    key: node_key,
                    created_at: None,
                    download_id: Some(node_id),
                };

                nodes.insert(node.hash.clone(), node);

                Ok(Nodes::new(nodes))
            }
            NodeKind::Folder => {
                let request = Request::FetchNodes { c: 1, r: Some(1) };
                let responses = self
                    .client
                    .send_requests(&self.state, &[request], &[("n", node_id.as_str())])
                    .await?;

                let files = match responses.as_slice() {
                    [Response::FetchNodes(files)] => files,
                    [Response::Error(code)] => {
                        return Err(Error::from(*code));
                    }
                    _ => {
                        return Err(Error::InvalidResponseType);
                    }
                };

                for file in &files.nodes {
                    match file.kind {
                        NodeKind::File | NodeKind::Folder => {
                            let (_, file_key) = file.key.as_ref().unwrap().split_once(":").unwrap();

                            let mut file_key = BASE64_URL_SAFE_NO_PAD.decode(file_key)?;
                            utils::decrypt_ebc_in_place(&node_key, &mut file_key);

                            let attrs = {
                                let mut file_key = file_key.clone();
                                utils::unmerge_key_mac(&mut file_key);

                                let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                                FileAttributes::decrypt_and_unpack(
                                    &file_key[..16],
                                    buffer.as_mut_slice(),
                                )?
                            };

                            let node = Node {
                                name: attrs.name,
                                hash: file.hash.clone(),
                                size: file.sz.unwrap_or(0),
                                kind: file.kind,
                                parent: (!file.parent.is_empty()).then(|| file.parent.clone()),
                                children: nodes
                                    .values()
                                    .filter_map(|it| {
                                        let parent = it.parent.as_ref()?;
                                        (parent == &file.hash).then(|| file.hash.clone())
                                    })
                                    .collect(),
                                key: file_key,
                                created_at: Some(Utc.timestamp_opt(file.ts as i64, 0).unwrap()),
                                download_id: Some(node_id.clone()),
                            };

                            if let Some(parent) = nodes.get_mut(&file.parent) {
                                parent.children.push(node.hash.clone());
                            }

                            nodes.insert(node.hash.clone(), node);
                        }
                        _ => unreachable!(),
                    }
                }

                Ok(Nodes::new(nodes))
            }
            _ => unreachable!(),
        }
    }

    /// Returns the status of the current storage quotas.
    pub async fn get_storage_quotas(&self) -> Result<StorageQuotas> {
        let responses = self
            .send_requests(&[Request::Quota { xfer: 1, strg: 1 }])
            .await?;

        let [Response::Quota(quota)] = responses.as_slice() else {
            return Err(Error::InvalidResponseType);
        };

        Ok(StorageQuotas {
            memory_used: quota.cstrg,
            memory_total: quota.mstrg,
        })
    }

    /// Downloads a file, identified by its hash, into the given writer.
    pub async fn download_node<W: AsyncWrite>(&self, node: &Node, writer: W) -> Result<()> {
        let responses = if let Some(download_id) = node.download_id() {
            let request = if node.hash.as_str() == download_id {
                Request::Download {
                    g: 1,
                    ssl: if self.state.https { 2 } else { 0 },
                    n: None,
                    p: Some(node.hash.clone()),
                }
            } else {
                Request::Download {
                    g: 1,
                    ssl: if self.state.https { 2 } else { 0 },
                    n: Some(node.hash.clone()),
                    p: None,
                }
            };

            self.client
                .send_requests(&self.state, &[request], &[("n", download_id)])
                .await?
        } else {
            let request = Request::Download {
                g: 1,
                ssl: if self.state.https { 2 } else { 0 },
                p: None,
                n: Some(node.hash.clone()),
            };

            self.send_requests(&[request]).await?
        };

        let response = match responses.as_slice() {
            [Response::Download(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let mut file_key = node.key.clone();
        utils::unmerge_key_mac(&mut file_key);

        let url =
            Url::parse(format!("{0}/{1}-{2}", response.download_url, 0, response.size).as_str())?;

        let mut reader = self.client.download(url).await?;

        let mut file_iv = [0u8; 16];

        file_iv[..8].copy_from_slice(&node.key[16..24]);
        let mut ctr = ctr::Ctr128BE::<Aes128>::new(file_key[..16].into(), (&file_iv).into());

        file_iv[8..].copy_from_slice(&node.key[16..24]);

        let mut final_mac_data = [0u8; 16];
        let mut final_mac =
            cbc::Encryptor::<Aes128>::new(file_key[..16].into(), (&final_mac_data).into());

        let mut chunk_size: u64 = 131_072; // 2^17
        let mut cur_mac = [0u8; 16];

        let mut buffer = Vec::with_capacity(chunk_size as usize);

        futures::pin_mut!(writer);
        loop {
            buffer.clear();

            let bytes_read = (&mut reader)
                .take(chunk_size)
                .read_to_end(&mut buffer)
                .await?;

            if bytes_read == 0 {
                break;
            }

            ctr.apply_keystream(&mut buffer);
            writer.write_all(&buffer).await?;

            let (chunks, leftover) = buffer.split_at(buffer.len() - buffer.len() % 16);

            let mut mac = cbc::Encryptor::<Aes128>::new(file_key[..16].into(), (&file_iv).into());

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

        if final_mac_data[..8] != node.key[24..32] {
            return Err(Error::MacMismatch);
        }

        Ok(())
    }

    /// Uploads a file within a parent folder.
    pub async fn upload_node<R: AsyncRead>(
        &self,
        parent: &Node,
        name: &str,
        size: u64,
        reader: R,
    ) -> Result<()> {
        let request = Request::Upload {
            s: size,
            ssl: if self.state.https { 2 } else { 0 },
        };
        let responses = self.send_requests(&[request]).await?;

        let response = match responses.as_slice() {
            [Response::Upload(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let (file_key, file_iv_seed): ([u8; 16], [u8; 8]) = rand::random();

        let mut file_iv = [0u8; 16];
        file_iv[..8].copy_from_slice(&file_iv_seed);

        let mut ctr = ctr::Ctr128BE::<Aes128>::new((&file_key).into(), (&file_iv).into());
        file_iv[8..].copy_from_slice(&file_iv_seed);

        let (pipe_reader, mut pipe_writer) = sluice::pipe::pipe();

        let fut_1 = async move {
            let mut chunk_size: u64 = 131_072; // 2^17
            let mut cur_mac = [0u8; 16];

            let mut final_mac_data = [0u8; 16];
            let mut final_mac =
                cbc::Encryptor::<Aes128>::new((&file_key).into(), (&final_mac_data).into());

            let mut buffer = Vec::with_capacity(chunk_size as usize);

            futures::pin_mut!(reader);
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

                let mut mac = cbc::Encryptor::<Aes128>::new((&file_key).into(), (&file_iv).into());

                for chunk in chunks.chunks_exact(16) {
                    mac.encrypt_block_b2b_mut(chunk.into(), (&mut cur_mac).into());
                }

                if !leftover.is_empty() {
                    let mut padded_chunk = [0u8; 16];
                    padded_chunk[..leftover.len()].copy_from_slice(leftover);
                    mac.encrypt_block_b2b_mut((&padded_chunk).into(), (&mut cur_mac).into());
                }

                final_mac.encrypt_block_b2b_mut((&cur_mac).into(), (&mut final_mac_data).into());

                ctr.apply_keystream(&mut buffer);
                pipe_writer.write_all(&buffer).await?;

                if chunk_size < 1_048_576 {
                    chunk_size += 131_072;
                }
            }

            Ok(final_mac_data)
        };

        let url = Url::parse(format!("{0}/{1}", response.upload_url, 0).as_str())?;
        let fut_2 = self.client.upload(url, size, Box::pin(pipe_reader));

        let (mut final_mac_data, maybe_completion_handle) = futures::try_join!(fut_1, fut_2)?;

        for i in 0..4 {
            final_mac_data[i] = final_mac_data[i] ^ final_mac_data[i + 4];
            final_mac_data[i + 4] = final_mac_data[i + 8] ^ final_mac_data[i + 12];
        }

        let file_attr = FileAttributes {
            name: name.to_string(),
            c: None,
        };

        let file_attr_buffer = {
            let buffer = file_attr.pack_and_encrypt(&file_key)?;
            BASE64_URL_SAFE_NO_PAD.encode(&buffer)
        };

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&file_key);
        key[16..24].copy_from_slice(&file_iv[..8]);
        key[24..].copy_from_slice(&final_mac_data[..8]);
        utils::merge_key_mac(&mut key);

        let session = self.state.session.as_ref().unwrap();
        utils::encrypt_ebc_in_place(&session.key, &mut key);

        let key_b64 = BASE64_URL_SAFE_NO_PAD.encode(&key);

        let attrs = UploadAttributes {
            kind: NodeKind::File,
            key: key_b64,
            attr: file_attr_buffer,
            completion_handle: maybe_completion_handle.unwrap_or_default(),
        };

        let idempotence_id = utils::random_string(10);

        let request = Request::UploadComplete {
            t: parent.hash.clone(),
            n: [attrs],
            i: idempotence_id,
        };

        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::UploadComplete(_)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        Ok(())
    }

    /// Creates a new directory.
    pub async fn create_dir(&self, parent: &Node, name: &str) -> Result<()> {
        let (file_key, file_iv_seed): ([u8; 16], [u8; 8]) = rand::random();

        let mut file_iv = [0u8; 16];
        file_iv[..8].copy_from_slice(&file_iv_seed);

        let file_attr = FileAttributes {
            name: name.to_string(),
            c: None,
        };

        let file_attr_buffer = {
            let buffer = file_attr.pack_and_encrypt(&file_key)?;
            BASE64_URL_SAFE_NO_PAD.encode(&buffer)
        };

        let mut key = [0u8; 24];
        key[..16].copy_from_slice(&file_key);
        key[16..].copy_from_slice(&file_iv[..8]);
        utils::merge_key_mac(&mut key);

        let session = self.state.session.as_ref().unwrap();
        utils::encrypt_ebc_in_place(&session.key, &mut key);

        let key_b64 = BASE64_URL_SAFE_NO_PAD.encode(&key);

        let attrs = UploadAttributes {
            kind: NodeKind::Folder,
            key: key_b64,
            attr: file_attr_buffer,
            completion_handle: String::from("xxxxxxxx"),
        };

        let idempotence_id = utils::random_string(10);

        let request = Request::UploadComplete {
            t: parent.hash.clone(),
            n: [attrs],
            i: idempotence_id,
        };

        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::UploadComplete(_)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        Ok(())
    }

    /// Renames a node.
    pub async fn rename_node(&self, node: &Node, name: &str) -> Result<()> {
        let file_key = {
            let mut file_key = node.key.clone();
            utils::unmerge_key_mac(&mut file_key);
            file_key
        };

        let file_attr = FileAttributes {
            name: name.to_string(),
            c: None,
        };

        let file_attr_buffer = {
            let buffer = file_attr.pack_and_encrypt(&file_key[..16])?;
            BASE64_URL_SAFE_NO_PAD.encode(&buffer)
        };

        let idempotence_id = utils::random_string(10);

        let request = Request::SetFileAttributes {
            n: node.hash.clone(),
            key: None,
            attr: file_attr_buffer,
            i: idempotence_id,
        };

        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        }

        Ok(())
    }

    /// Moves a node to a different folder.
    pub async fn move_node(&self, node: &Node, parent: &Node) -> Result<()> {
        let idempotence_id = utils::random_string(10);

        let request = Request::Move {
            n: node.hash.clone(),
            t: parent.hash.clone(),
            i: idempotence_id,
        };

        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        }

        Ok(())
    }

    /// Moves a node to the Rubbish Bin.
    pub async fn move_to_rubbish_bin(&self, node: &Node) -> Result<()> {
        let idempotence_id = utils::random_string(10);

        let request = Request::Move {
            n: node.hash.clone(),
            t: "4".to_string(),
            i: idempotence_id,
        };

        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        }

        Ok(())
    }

    /// Deletes a node.
    pub async fn delete_node(&self, node: &Node) -> Result<()> {
        let idempotence_id = utils::random_string(10);

        let request = Request::Delete {
            n: node.hash.clone(),
            i: idempotence_id,
        };

        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        }

        Ok(())
    }
}

/// Represents a node stored in MEGA (either a file or a folder).
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// The name of the node.
    pub(crate) name: String,
    /// The hash (or handle) of the node.
    pub(crate) hash: String,
    /// The size (in bytes) of the node.
    pub(crate) size: u64,
    /// The kind of the node.
    pub(crate) kind: NodeKind,
    /// The hash (or handle) of the node's parent.
    pub(crate) parent: Option<String>,
    /// The hashes (or handles) of the node's children.
    pub(crate) children: Vec<String>,
    /// The de-obfuscated file key of the node.
    pub(crate) key: Vec<u8>,
    /// The creation date of the node.
    pub(crate) created_at: Option<DateTime<Utc>>,
    /// The ID of the public link this node is from.
    pub(crate) download_id: Option<String>,
}

impl Node {
    /// Returns the name of the node.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the hash (or handle) of the node.
    pub fn hash(&self) -> &str {
        self.hash.as_str()
    }

    /// Returns the size (in bytes) of the node.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the kind of the node.
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// Returns the hash (or handle) of the node's parent.
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Returns the hashes (or handles) of the node's children.
    pub fn children(&self) -> &[String] {
        self.children.as_slice()
    }

    /// Returns the creation date of the node.
    pub fn created_at(&self) -> Option<&DateTime<Utc>> {
        self.created_at.as_ref()
    }

    /// Returns the ID of the public link this node is from.
    pub fn download_id(&self) -> Option<&str> {
        self.download_id.as_deref()
    }
}

/// Represents a collection of nodes from MEGA.
pub struct Nodes {
    /// The nodes from MEGA, keyed by their hash (or handle).
    pub(crate) nodes: HashMap<String, Node>,
    /// The hash (or handle) of the root node for the Cloud Drive.
    pub(crate) cloud_drive: Option<String>,
    /// The hash (or handle) of the root node for the Rubbish Bin.
    pub(crate) rubbish_bin: Option<String>,
    /// The hash (or handle) of the root node for the Inbox.
    pub(crate) inbox: Option<String>,
}

impl Nodes {
    pub(crate) fn new(nodes: HashMap<String, Node>) -> Self {
        let cloud_drive = nodes
            .values()
            .find_map(|node| (node.kind == NodeKind::Root).then(|| node.hash.clone()));
        let rubbish_bin = nodes
            .values()
            .find_map(|node| (node.kind == NodeKind::Trash).then(|| node.hash.clone()));
        let inbox = nodes
            .values()
            .find_map(|node| (node.kind == NodeKind::Inbox).then(|| node.hash.clone()));

        Self {
            nodes,
            cloud_drive,
            rubbish_bin,
            inbox,
        }
    }

    /// Returns the number of nodes in this collection.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Creates an iterator over all the root nodes.
    pub fn roots(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values().filter(|node| {
            node.parent.as_ref().map_or(true, |parent| {
                // Root nodes from public links can still have
                // a `parent` handle associated with them, but that
                // parent won't be found in the current collection.
                !self.nodes.contains_key(parent)
            })
        })
    }

    /// Gets a node, identified by its hash (or handle).
    pub fn get_node_by_hash(&self, hash: &str) -> Option<&Node> {
        self.nodes.get(hash)
    }

    /// Gets a node, identified by its path.
    pub fn get_node_by_path(&self, path: &str) -> Option<&Node> {
        let path = if path.starts_with('/') {
            &path[1..]
        } else {
            path
        };

        let Some((root, path)) = path.split_once('/') else {
            return self.roots().find(|node| node.name == path);
        };

        let root = self.roots().find(|node| node.name == root)?;
        path.split('/').fold(Some(root), |node, name| {
            node?.children.iter().find_map(|hash| {
                let found = self.get_node_by_hash(hash)?;
                (found.name == name).then_some(found)
            })
        })
    }

    /// Gets the root node for the Cloud Drive.
    pub fn cloud_drive(&self) -> Option<&Node> {
        let hash = self.cloud_drive.as_ref()?;
        self.nodes.get(hash)
    }

    /// Gets the root node for the Inbox.
    pub fn inbox(&self) -> Option<&Node> {
        let hash = self.inbox.as_ref()?;
        self.nodes.get(hash)
    }

    /// Gets the root node for the Rubbish Bin.
    pub fn rubbish_bin(&self) -> Option<&Node> {
        let hash = self.rubbish_bin.as_ref()?;
        self.nodes.get(hash)
    }

    /// Creates a borrowing iterator over the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// Creates a mutably-borrowing iterator over the nodes.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Node> {
        self.nodes.values_mut()
    }
}

impl IntoIterator for Nodes {
    type Item = Node;
    type IntoIter = std::collections::hash_map::IntoValues<String, Node>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_values()
    }
}
