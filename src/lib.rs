//! This is an API client library for interacting with MEGA's API using Rust.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use aes::Aes128;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use cipher::generic_array::GenericArray;
use cipher::{BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Sha256, Sha512};
use static_assertions::assert_impl_all;
use url::Url;

mod attributes;
mod error;
mod fingerprint;
mod http;
mod protocol;
mod sessions;
mod utils;

pub use crate::error::{Error, ErrorCode, Result};
pub use crate::fingerprint::{compute_condensed_mac, compute_sparse_checksum};
pub use crate::protocol::commands::{FileNode, NodeKind};
pub use crate::sessions::SessionInfo;
pub use crate::utils::StorageQuotas;

use crate::attributes::NodeAttributes;
use crate::fingerprint::NodeFingerprint;
use crate::http::{ClientState, HttpClient, UserSession};
use crate::protocol::commands::{Request, Response, UploadAttributes};
use crate::protocol::events::{EventBatchResponse, EventResponse, EventResponseKind};
use crate::protocol::{FILE_KEY_SIZE, FOLDER_KEY_SIZE, USER_KEY_SIZE, USER_SID_SIZE};
use crate::utils::rsa::RsaPrivateKey;

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
    pub fn timeout(mut self, duration: Option<Duration>) -> Self {
        self.timeout = duration;
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

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The MEGA API Client itself.
pub struct Client {
    /// The client's state.
    pub(crate) state: ClientState,
    /// The HTTP client.
    pub(crate) client: Box<dyn HttpClient>,
}

assert_impl_all!(Client: Send, Sync);

impl Client {
    /// Creates a builder to initialize a [`Client`] instance.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Sends a request to the MEGA API.
    pub(crate) async fn send_requests(&self, requests: &[Request]) -> Result<Vec<Response>> {
        self.client.send_requests(&self.state, requests, &[]).await
    }

    /// Authenticates this session with MEGA.
    pub async fn login(&mut self, email: &str, password: &str, mfa: Option<&str>) -> Result<()> {
        let email = email.to_lowercase();

        let request = Request::PreLogin {
            user: email.clone().into(),
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
                let salt = BASE64_URL_SAFE_NO_PAD.decode(salt)?;

                let key = utils::prepare_key_v2(password.as_bytes(), salt.as_slice());

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
                return Err(Error::UnknownUserLoginVersion { version });
            }
        };

        let sek: [u8; 16] = rand::random();

        let request = Request::Login {
            user: Some(email.clone().into()),
            user_handle: Some(user_handle.clone().into()),
            si: None,
            mfa: mfa.map(|it| it.to_string().into()),
            sek: Some(BASE64_URL_SAFE_NO_PAD.encode(&sek).into()),
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

        let key: [u8; 16] = {
            let key = (response.key.as_ref())
                .ok_or_else(|| Error::MissingResponseField { field: "k" })?;
            let mut key = BASE64_URL_SAFE_NO_PAD.decode(key)?;
            utils::decrypt_ebc_in_place(&login_key, &mut key);
            key.try_into().map_err(|_| Error::InvalidResponseFormat)?
        };

        let sek: [u8; 16] = {
            let sek = (response.sek.as_ref())
                .ok_or_else(|| Error::MissingResponseField { field: "sek" })?;
            let sek = BASE64_URL_SAFE_NO_PAD.decode(sek)?;
            sek.try_into().map_err(|_| Error::InvalidResponseFormat)?
        };

        let csid = {
            let csid = (response.csid.as_ref())
                .ok_or_else(|| Error::MissingResponseField { field: "csid" })?;
            BASE64_URL_SAFE_NO_PAD.decode(csid)?
        };

        let privk = {
            let mut privk = BASE64_URL_SAFE_NO_PAD.decode(&response.privk)?;
            utils::decrypt_ebc_in_place(&key, &mut privk);
            RsaPrivateKey::from_mpi_bytes(&privk)?
        };

        let sid = {
            let (m, _) = utils::rsa::get_mpi(&csid)?;
            let sid = privk.decrypt(m);
            BASE64_URL_SAFE_NO_PAD.encode(&sid[..43])
        };

        self.state.session = Some(SecretBox::new(Box::new(UserSession {
            sid,
            key,
            sek,
            user_handle: response.u.clone(),
            privk,
        })));

        Ok(())
    }

    /// Resumes a session with MEGA from its serialized representation.
    pub async fn resume_session(&mut self, session: &str) -> Result<()> {
        let session = BASE64_URL_SAFE_NO_PAD.decode(session)?;

        match session[0] {
            1 => {}
            2 => {
                // folder session, not supported.
                return Err(Error::InvalidSessionKind);
            }
            _ => {
                // unknown session kind, not supported.
                return Err(Error::InvalidSessionKind);
            }
        }

        let (key, sid) = session[1..].split_at(16);

        let mut key: [u8; 16] = key.try_into().unwrap();
        let sid = BASE64_URL_SAFE_NO_PAD.encode(sid);

        let sek: [u8; 16] = rand::random();

        let request = Request::Login {
            user: None,
            user_handle: None,
            si: None,
            mfa: None,
            sek: Some(BASE64_URL_SAFE_NO_PAD.encode(&sek).into()),
        };
        let responses = self
            .client
            .send_requests(&self.state, &[request], &[("sid", sid.as_str())])
            .await?;

        let response = match responses.as_slice() {
            [Response::Login(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let sek: [u8; 16] = {
            let sek = (response.sek.as_ref())
                .ok_or_else(|| Error::MissingResponseField { field: "sek" })?;
            let sek = BASE64_URL_SAFE_NO_PAD.decode(sek)?;
            sek.try_into().map_err(|_| Error::InvalidResponseFormat)?
        };

        utils::decrypt_ebc_in_place(&sek, &mut key);

        let privk = {
            let mut privk = BASE64_URL_SAFE_NO_PAD.decode(&response.privk)?;
            utils::decrypt_ebc_in_place(&key, &mut privk);
            RsaPrivateKey::from_mpi_bytes(&privk)?
        };

        self.state.session = Some(SecretBox::new(Box::new(UserSession {
            sid,
            key,
            sek,
            privk,
            user_handle: response.u.clone(),
        })));

        Ok(())
    }

    /// Serializes the current session with MEGA.
    pub async fn serialize_session(&self) -> Result<String> {
        let session = self
            .state
            .session
            .as_ref()
            .ok_or(Error::MissingUserSession)?
            .expose_secret();

        let mut serialized: Vec<u8> = Vec::with_capacity(1 + USER_KEY_SIZE + USER_SID_SIZE);
        serialized.push(1);

        let mut key = session.key;
        utils::encrypt_ebc_in_place(&session.sek, &mut key);
        serialized.extend(key);

        let mut sid = BASE64_URL_SAFE_NO_PAD.decode(&session.sid)?;
        serialized.append(&mut sid);

        Ok(BASE64_URL_SAFE_NO_PAD.encode(serialized))
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

    /// Returns whether this client currently has a user session.
    pub fn has_user_session(&self) -> bool {
        self.state.session.is_some()
    }

    /// Get information about the current user.
    pub async fn get_current_user_info(&self) -> Result<UserInfo> {
        let request = Request::UserInfo { v: None };
        let responses = self.send_requests(&[request]).await?;

        let response = match responses.as_slice() {
            [Response::UserInfo(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        Ok(UserInfo {
            id: response.u.clone(),
            first_name: {
                let decoded = BASE64_URL_SAFE_NO_PAD.decode(&response.firstname)?;
                String::from_utf8(decoded)?
            },
            last_name: {
                let decoded = BASE64_URL_SAFE_NO_PAD.decode(&response.lastname)?;
                String::from_utf8(decoded)?
            },
            email: response.email.clone(),
            country_code: 'result: {
                let Some(country) = &response.country else {
                    break 'result None;
                };
                let decoded = BASE64_URL_SAFE_NO_PAD.decode(&country)?;
                let country = String::from_utf8(decoded)?;
                Some(country)
            },
            birth_date: 'result: {
                let Some(day) = &response.birthday else {
                    break 'result None;
                };
                let Some(month) = &response.birthmonth else {
                    break 'result None;
                };
                let Some(year) = &response.birthyear else {
                    break 'result None;
                };

                let day: u32 = {
                    let decoded = BASE64_URL_SAFE_NO_PAD.decode(&day)?;
                    String::from_utf8(decoded)?.parse::<u32>()?
                };
                let month: u32 = {
                    let decoded = BASE64_URL_SAFE_NO_PAD.decode(&month)?;
                    String::from_utf8(decoded)?.parse::<u32>()?
                };
                let year: i32 = {
                    let decoded = BASE64_URL_SAFE_NO_PAD.decode(&year)?;
                    String::from_utf8(decoded)?.parse::<i32>()?
                };

                NaiveDate::from_ymd_opt(year, month, day)
            },
        })
    }

    /// Lists the user's MEGA sessions.
    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let request = Request::ListSessions { x: Some(1) };
        let responses = self.send_requests(&[request]).await?;

        let response = match responses.as_slice() {
            [Response::ListSessions(response)] => response,
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        Ok(response.sessions.iter().map(SessionInfo::from).collect())
    }

    /// Kills the specified MEGA sessions.
    pub async fn kill_sessions<I, T>(&self, session_ids: I) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let request = Request::KillSessions {
            ko: None,
            s: session_ids.into_iter().map(|it| it.into().into()).collect(),
        };
        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => Ok(()),
            [Response::Error(code)] => Err(Error::from(*code)),
            _ => Err(Error::InvalidResponseType),
        }
    }

    /// Kills all MEGA sessions (except the current one).
    pub async fn kill_all_sessions<I, T>(&self) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let request = Request::KillSessions {
            ko: Some(1),
            s: Vec::default(),
        };
        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::Error(ErrorCode::OK)] => Ok(()),
            [Response::Error(code)] => Err(Error::from(*code)),
            _ => Err(Error::InvalidResponseType),
        }
    }

    /// Fetches all nodes from the user's own MEGA account.
    pub async fn fetch_own_nodes(&self) -> Result<Nodes> {
        let session = self
            .state
            .session
            .as_ref()
            .ok_or(Error::MissingUserSession)?
            .expose_secret();

        let request_1 = Request::FetchNodes { c: 1, r: None };
        let request_2 = Request::UserAttributes {
            user_handle: session.user_handle.clone().into(),
            attribute: "^!keys".to_string(),
            v: 1,
        };
        let responses = self.send_requests(&[request_1, request_2]).await?;

        let (files, attr) = match responses.as_slice() {
            [Response::FetchNodes(files), Response::UserAttributes(attr)] => (files, attr),
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        };

        let mut nodes = HashMap::<String, Node>::default();
        let share_keys = utils::extract_share_keys(&session, attr)?;

        // This method of getting share keys seems to be unneeded.
        // (maybe an earlier implementation that got decommissionned/deprecated ?).
        //
        // for share in files.ok.iter().flatten() {
        //     let mut share_key = BASE64_URL_SAFE_NO_PAD.decode(&share.key)?;
        //     utils::decrypt_ebc_in_place(&session.key, &mut share_key);
        //     share_keys.insert(share.handle.clone(), share_key);
        // }

        for file in &files.nodes {
            let (thumbnail_handle, preview_image_handle) = file
                .file_attr
                .as_deref()
                .map(|attr| utils::extract_attachments(attr))
                .unwrap_or_default();

            match file.kind {
                NodeKind::File | NodeKind::Folder => {
                    // if let Some((_, s_key)) = file.s_user.as_deref().zip(file.s_key.as_deref()) {
                    //     let mut share_key = BASE64_URL_SAFE_NO_PAD.decode(s_key)?;
                    //     utils::decrypt_ebc_in_place(&session.key, &mut share_key);
                    //     utils::decrypt_ebc_in_place(&share_key, &mut file_key);
                    //     share_keys.insert(file.handle.clone(), share_key.clone());
                    // }

                    let Some(file_key) = file.key.as_deref() else {
                        continue;
                    };

                    let Some(mut file_key) = file_key.split('/').find_map(|key| {
                        let (file_user, file_key) = key.split_once(':')?;

                        if file_key.len() >= 44 {
                            // Keys bigger than this size are using RSA instead of AES.
                            let data = BASE64_URL_SAFE_NO_PAD.decode(file_key).ok()?;
                            let (encrypted, _) = utils::rsa::get_mpi(&data).ok()?;
                            let mut decrypted = session.privk.decrypt(encrypted);
                            if file.kind.is_file() {
                                decrypted.truncate(FILE_KEY_SIZE);
                            } else {
                                decrypted.truncate(FOLDER_KEY_SIZE);
                            }
                            return Some(decrypted);
                        }

                        let mut file_key = BASE64_URL_SAFE_NO_PAD.decode(file_key).ok()?;

                        // File keys are 32 bytes and folder keys are 16 bytes.
                        // Other sizes are considered invalid.
                        if (file.kind.is_file() && file_key.len() != FILE_KEY_SIZE)
                            || (!file.kind.is_file() && file_key.len() != FOLDER_KEY_SIZE)
                        {
                            return None;
                        }

                        // TODO: MEGA includes in its web client a check to see if both halves of `file_key`
                        //       are identical to each other. This is apparently done to prevent an attacker from
                        //       being able to produce an all-zeroes AES key (by XOR-ing the two halves after EBC decryption).
                        //       It's a bit unclear what we should do in our specific case, so it isn't yet implemented here.
                        //
                        //       Here would be how to implement such a check:
                        //       ```
                        //       if !self.state.allow_null_keys {
                        //           let (fst, snd) = file_key.split_at(16);
                        //           if fst == snd {
                        //               return None;
                        //           }
                        //       }
                        //       ```

                        if file_user == session.user_handle {
                            // regular owned file or folder
                            utils::decrypt_ebc_in_place(&session.key, &mut file_key);
                            return Some(file_key);
                        }

                        if let Some(share_key) = share_keys.get(file_user) {
                            // shared file or folder
                            utils::decrypt_ebc_in_place(&share_key, &mut file_key);
                            return Some(file_key);
                        }

                        None
                    }) else {
                        continue;
                    };

                    let (aes_key, aes_iv, condensed_mac) = if file.kind.is_file() {
                        utils::unmerge_key_mac(&mut file_key);

                        let (aes_key, rest) = file_key.split_at(16);
                        let (aes_iv, condensed_mac) = rest.split_at(8);

                        (
                            aes_key.try_into().unwrap(),
                            aes_iv.try_into().ok(),
                            condensed_mac.try_into().ok(),
                        )
                    } else {
                        (file_key.try_into().unwrap(), None, None)
                    };

                    let attrs = {
                        let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                        NodeAttributes::decrypt_and_unpack(&aes_key, buffer.as_mut_slice())?
                    };

                    let fingerprint = attrs.extract_fingerprint();

                    let modified_at = (attrs.modified_at)
                        .or_else(|| fingerprint.as_ref().map(|it| it.modified_at))
                        .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());

                    let node = Node {
                        name: attrs.name,
                        handle: file.handle.clone(),
                        owner: file.user.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: file.kind,
                        parent: (!file.parent.is_empty()).then(|| file.parent.clone()),
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.handle).then(|| file.handle.clone())
                            })
                            .collect(),
                        aes_key,
                        aes_iv,
                        condensed_mac,
                        sparse_checksum: fingerprint.map(|it| it.checksum),
                        created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
                        modified_at,
                        download_id: None,
                        thumbnail_handle,
                        preview_image_handle,
                    };

                    if let Some(parent) = nodes.get_mut(&file.parent) {
                        parent.children.push(node.handle.clone());
                    }

                    nodes.insert(node.handle.clone(), node);
                }
                NodeKind::Root => {
                    let node = Node {
                        name: String::from("Root"),
                        handle: file.handle.clone(),
                        owner: file.user.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: NodeKind::Root,
                        parent: None,
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.handle).then(|| file.handle.clone())
                            })
                            .collect(),
                        aes_key: <_>::default(),
                        aes_iv: None,
                        condensed_mac: None,
                        sparse_checksum: None,
                        created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
                        modified_at: None,
                        download_id: None,
                        thumbnail_handle,
                        preview_image_handle,
                    };
                    nodes.insert(node.handle.clone(), node);
                }
                NodeKind::Inbox => {
                    let node = Node {
                        name: String::from("Inbox"),
                        handle: file.handle.clone(),
                        owner: file.user.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: NodeKind::Inbox,
                        parent: None,
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.handle).then(|| file.handle.clone())
                            })
                            .collect(),
                        aes_key: <_>::default(),
                        aes_iv: None,
                        condensed_mac: None,
                        sparse_checksum: None,
                        created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
                        modified_at: None,
                        download_id: None,
                        thumbnail_handle,
                        preview_image_handle,
                    };
                    nodes.insert(node.handle.clone(), node);
                }
                NodeKind::Trash => {
                    let node = Node {
                        name: String::from("Trash"),
                        handle: file.handle.clone(),
                        owner: file.user.clone(),
                        size: file.sz.unwrap_or(0),
                        kind: NodeKind::Trash,
                        parent: None,
                        children: nodes
                            .values()
                            .filter_map(|it| {
                                let parent = it.parent.as_ref()?;
                                (parent == &file.handle).then(|| file.handle.clone())
                            })
                            .collect(),
                        aes_key: <_>::default(),
                        aes_iv: None,
                        condensed_mac: None,
                        sparse_checksum: None,
                        created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
                        modified_at: None,
                        download_id: None,
                        thumbnail_handle,
                        preview_image_handle,
                    };
                    nodes.insert(node.handle.clone(), node);
                }
                NodeKind::Unknown => {
                    continue;
                }
            }
        }

        Ok(Nodes::new(nodes, files.sn.clone(), None))
    }

    /// Fetches all nodes from a public MEGA link.
    ///
    /// Supported URL formats:
    /// - https://mega.nz/file/{node_id}#{node_key}
    /// - https://mega.nz/folder/{node_id}#{node_key}
    #[allow(rustdoc::bare_urls)]
    pub async fn fetch_public_nodes(&self, url: &str) -> Result<Nodes> {
        let payload = match url.split_at(16) {
            ("https://mega.nz/", payload) => payload,
            _ => {
                return Err(Error::InvalidPublicUrlFormat);
            }
        };

        let (node_kind, payload) = match payload.split_once("/") {
            Some(("file", payload)) => (NodeKind::File, payload),
            Some(("folder", payload)) => (NodeKind::Folder, payload),
            _ => {
                return Err(Error::InvalidPublicUrlFormat);
            }
        };

        let (node_id, node_key) = payload
            .split_once("#")
            .ok_or(Error::InvalidPublicUrlFormat)?;

        let mut node_key = {
            let key = node_key.split_once('/').map_or(node_key, |it| it.0);
            BASE64_URL_SAFE_NO_PAD.decode(key)?
        };

        let mut nodes = HashMap::<String, Node>::default();

        match node_kind {
            NodeKind::File => {
                let request = Request::Download {
                    g: 1,
                    ssl: 0,
                    p: Some(node_id.to_string().into()),
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

                // TODO: MEGA includes in its web client a check to see if both halves of `file_key`
                //       are identical to each other. This is apparently done to prevent an attacker from
                //       being able to produce an all-zeroes AES key (by XOR-ing the two halves after EBC decryption).
                //       It's a bit unclear what we should do in our specific case, so it isn't yet implemented here.
                //
                //       Here would be how to implement such a check:
                //       ```
                //       if !self.state.allow_null_keys {
                //           let (fst, snd) = node_key.split_at(16);
                //           if fst == snd {
                //               return Err(Error::NullKeysDisallowed);
                //           }
                //       }
                //       ```

                let (aes_key, aes_iv, condensed_mac) = {
                    utils::unmerge_key_mac(&mut node_key);

                    let (aes_key, rest) = node_key.split_at(16);
                    let (aes_iv, condensed_mac) = rest.split_at(8);

                    (
                        aes_key.try_into().unwrap(),
                        aes_iv.try_into().unwrap(),
                        condensed_mac.try_into().unwrap(),
                    )
                };

                let attrs = {
                    let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                    NodeAttributes::decrypt_and_unpack(&aes_key, buffer.as_mut_slice())?
                };

                let fingerprint = attrs.extract_fingerprint();

                let modified_at = (attrs.modified_at)
                    .or_else(|| fingerprint.as_ref().map(|it| it.modified_at))
                    .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());

                let node = Node {
                    name: attrs.name,
                    handle: node_id.to_string(),
                    owner: String::default(),
                    size: file.size,
                    kind: NodeKind::File,
                    parent: None,
                    children: Vec::default(),
                    aes_key,
                    aes_iv: Some(aes_iv),
                    condensed_mac: Some(condensed_mac),
                    sparse_checksum: fingerprint.map(|it| it.checksum),
                    created_at: None,
                    modified_at,
                    download_id: Some(node_id.to_string()),
                    thumbnail_handle: None,
                    preview_image_handle: None,
                };

                nodes.insert(node.handle.clone(), node);

                Ok(Nodes::new(
                    nodes,
                    String::default(),
                    Some(node_id.to_string()),
                ))
            }
            NodeKind::Folder => {
                let request = Request::FetchNodes { c: 1, r: Some(1) };
                let responses = self
                    .client
                    .send_requests(&self.state, &[request], &[("n", node_id)])
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
                            let Some(file_key) = file.key.as_deref() else {
                                continue;
                            };

                            let Some(mut file_key) = file_key.split('/').find_map(|key| {
                                let (_, file_key) = key.split_once(':')?;

                                if file_key.len() >= 44 {
                                    // Keys bigger than this size are using RSA instead of AES.
                                    // We don't support this as of right now.
                                    todo!();
                                }

                                let mut file_key = BASE64_URL_SAFE_NO_PAD.decode(file_key).ok()?;

                                // File keys are 32 bytes and folder keys are 16 bytes.
                                // Other sizes are considered invalid.
                                if (file.kind.is_file() && file_key.len() != FILE_KEY_SIZE)
                                    || (!file.kind.is_file() && file_key.len() != FOLDER_KEY_SIZE)
                                {
                                    return None;
                                }

                                // TODO: MEGA includes in its web client a check to see if both halves of `file_key`
                                //       are identical to each other. This is apparently done to prevent an attacker from
                                //       being able to produce an all-zeroes AES key (by XOR-ing the two halves after EBC decryption).
                                //       It's a bit unclear what we should do in our specific case, so it isn't yet implemented here.
                                //
                                //       Here would be how to implement such a check:
                                //       ```
                                //       if !self.state.allow_null_keys {
                                //           let (fst, snd) = file_key.split_at(16);
                                //           if fst == snd {
                                //               return None;
                                //           }
                                //       }
                                //       ```

                                utils::decrypt_ebc_in_place(&node_key, &mut file_key);
                                Some(file_key)
                            }) else {
                                continue;
                            };

                            let (aes_key, aes_iv, condensed_mac) = if file.kind.is_file() {
                                utils::unmerge_key_mac(&mut file_key);

                                let (aes_key, rest) = file_key.split_at(16);
                                let (aes_iv, condensed_mac) = rest.split_at(8);

                                (
                                    aes_key.try_into().unwrap(),
                                    aes_iv.try_into().ok(),
                                    condensed_mac.try_into().ok(),
                                )
                            } else {
                                (file_key.try_into().unwrap(), None, None)
                            };

                            let attrs = {
                                let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                                NodeAttributes::decrypt_and_unpack(&aes_key, buffer.as_mut_slice())?
                            };

                            let (thumbnail_handle, preview_image_handle) = file
                                .file_attr
                                .as_deref()
                                .map(|attr| utils::extract_attachments(attr))
                                .unwrap_or_default();

                            let fingerprint = attrs.extract_fingerprint();

                            let modified_at = (attrs.modified_at)
                                .or_else(|| fingerprint.as_ref().map(|it| it.modified_at))
                                .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());

                            let node = Node {
                                name: attrs.name,
                                handle: file.handle.clone(),
                                owner: file.user.clone(),
                                size: file.sz.unwrap_or(0),
                                kind: file.kind,
                                parent: (!file.parent.is_empty()).then(|| file.parent.clone()),
                                children: nodes
                                    .values()
                                    .filter_map(|it| {
                                        let parent = it.parent.as_ref()?;
                                        (parent == &file.handle).then(|| file.handle.clone())
                                    })
                                    .collect(),
                                aes_key,
                                aes_iv,
                                condensed_mac,
                                sparse_checksum: fingerprint.map(|it| it.checksum),
                                created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
                                modified_at,
                                download_id: Some(node_id.to_string()),
                                thumbnail_handle,
                                preview_image_handle,
                            };

                            if let Some(parent) = nodes.get_mut(&file.parent) {
                                parent.children.push(node.handle.clone());
                            }

                            nodes.insert(node.handle.clone(), node);
                        }
                        _ => unreachable!(),
                    }
                }

                Ok(Nodes::new(
                    nodes,
                    files.sn.clone(),
                    Some(node_id.to_string()),
                ))
            }
            _ => unreachable!(),
        }
    }

    /// Fetches all nodes from a password-protected MEGA link.
    ///
    /// Supported URL formats:
    /// - https://mega.nz/#P!{payload}
    #[allow(rustdoc::bare_urls)]
    pub async fn fetch_protected_nodes(&self, url: &str, password: &str) -> Result<Nodes> {
        let decoded_full = match url.split_at(19) {
            ("https://mega.nz/#P!", payload) => BASE64_URL_SAFE_NO_PAD.decode(payload)?,
            _ => {
                return Err(Error::InvalidUrlFormat);
            }
        };

        if decoded_full.len() < 2 {
            return Err(Error::UrlTooShort);
        }

        let (&algorithm, rest) = decoded_full.split_first().unwrap();
        let (&kind, rest) = rest.split_first().unwrap();

        let (key_size, is_folder) = match kind {
            0 => (FOLDER_KEY_SIZE, true),
            1 => (FILE_KEY_SIZE, false),
            _ => {
                return Err(Error::InvalidUrlFormat);
            }
        };

        if decoded_full.len() < 72 + key_size {
            return Err(Error::UrlTooShort);
        }

        let (handle, rest) = rest.split_at(6);
        let (salt, rest) = rest.split_at(32);
        let (key, mac) = rest.split_at(key_size);

        let dec_key = pbkdf2_hmac_array::<Sha512, 64>(password.as_bytes(), salt, 100_000);

        match algorithm {
            1 => {
                // It's fine to unwrap here, HMAC can take keys of any size.
                let mut hmac: Hmac<Sha256> =
                    Mac::new_from_slice(&decoded_full[..40 + key_size]).unwrap();
                hmac.update(&dec_key[32..64]);
                hmac.verify_slice(mac)?;
            }
            2 => {
                // It's fine to unwrap here, HMAC can take keys of any size.
                let mut hmac: Hmac<Sha256> = Mac::new_from_slice(&dec_key[32..64]).unwrap();
                hmac.update(&decoded_full[..40 + key_size]);
                hmac.verify_slice(mac)?;
            }
            version => {
                return Err(Error::InvalidAlgorithmVersion { version });
            }
        }

        let handle = BASE64_URL_SAFE_NO_PAD.encode(handle);
        let kind = if is_folder { "folder" } else { "file" };

        let derived_key = {
            let derived_key: Vec<u8> = key
                .iter()
                .copied()
                .zip(dec_key.into_iter())
                .map(|(a, b)| a ^ b)
                .collect();

            BASE64_URL_SAFE_NO_PAD.encode(&derived_key)
        };

        let url = format!("https://mega.nz/{kind}/{handle}#{derived_key}");
        self.fetch_public_nodes(&url).await
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

    /// Downloads a file into the given writer.
    pub async fn download_node<W: AsyncWrite>(&self, node: &Node, writer: W) -> Result<()> {
        let responses = if let Some(download_id) = node.download_id() {
            let request = if node.handle.as_str() == download_id {
                Request::Download {
                    g: 1,
                    ssl: if self.state.https { 2 } else { 0 },
                    n: None,
                    p: Some(node.handle.clone().into()),
                }
            } else {
                Request::Download {
                    g: 1,
                    ssl: if self.state.https { 2 } else { 0 },
                    n: Some(node.handle.clone().into()),
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
                n: Some(node.handle.clone().into()),
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

        let url =
            Url::parse(format!("{0}/{1}-{2}", response.download_url, 0, response.size).as_str())?;

        let mut reader = self.client.get(url).await?.take(node.size);

        let mut file_iv = [0u8; 16];

        file_iv[..8].copy_from_slice(node.aes_iv.unwrap_or_default().as_slice());
        let mut ctr = ctr::Ctr128BE::<Aes128>::new(node.aes_key[..].into(), (&file_iv).into());

        file_iv[8..].copy_from_slice(node.aes_iv.unwrap_or_default().as_slice());

        let (condensed_mac_reader, condensed_mac_writer) = sluice::pipe::pipe();

        let download_future = async move {
            let mut chunk_size: u64 = 131_072; // 2^17

            let mut buffer = {
                let chunk_size = usize::try_from(chunk_size).unwrap();
                Vec::with_capacity(chunk_size)
            };

            futures::pin_mut!(writer);
            futures::pin_mut!(condensed_mac_writer);

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
                condensed_mac_writer.write_all(&buffer).await?;

                if chunk_size < 1_048_576 {
                    chunk_size += 131_072;
                }
            }

            Ok(())
        };

        let condensed_mac_future = {
            let size = node.size;
            let aes_key = node.aes_key;
            let aes_iv = node.aes_iv.unwrap();
            async move {
                fingerprint::compute_condensed_mac(condensed_mac_reader, size, &aes_key, &aes_iv)
                    .await
            }
        };

        let (_, condensed_mac) = futures::try_join!(download_future, condensed_mac_future)?;

        if condensed_mac != node.condensed_mac.unwrap_or_default() {
            return Err(Error::CondensedMacMismatch);
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
        last_modified: LastModified,
    ) -> Result<()> {
        let session = self
            .state
            .session
            .as_ref()
            .ok_or(Error::MissingUserSession)?
            .expose_secret();

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

        let (aes_key, aes_iv_seed): ([u8; 16], [u8; 8]) = rand::random();

        let mut aes_iv = [0u8; 16];
        aes_iv[..8].copy_from_slice(&aes_iv_seed);

        let mut ctr = ctr::Ctr128BE::<Aes128>::new((&aes_key).into(), (&aes_iv).into());
        aes_iv[8..].copy_from_slice(&aes_iv_seed);

        let (upload_reader, mut upload_writer) = sluice::pipe::pipe();
        let (condensed_mac_reader, mut condensed_mac_writer) = sluice::pipe::pipe();
        let (sparse_checksum_reader, mut sparse_checksum_writer) = sluice::pipe::pipe();

        let dispatch_future = async move {
            let mut chunk_size: u64 = 131_072; // 2^17

            let mut buffer = {
                let chunk_size = usize::try_from(chunk_size).unwrap();
                Vec::with_capacity(chunk_size)
            };

            let reader = reader.take(size);

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

                // TODO: try to find out if it would be useful to `join!` these two.
                condensed_mac_writer.write_all(&buffer).await?;
                sparse_checksum_writer.write_all(&buffer).await?;

                ctr.apply_keystream(&mut buffer);
                upload_writer.write_all(&buffer).await?;

                if chunk_size < 1_048_576 {
                    chunk_size += 131_072;
                }
            }

            Ok(())
        };

        let condensed_mac_future = async move {
            let aes_iv = aes_iv[..8].try_into().unwrap();
            fingerprint::compute_condensed_mac(condensed_mac_reader, size, &aes_key, &aes_iv).await
        };

        let sparse_checksum_future =
            async move { fingerprint::compute_sparse_checksum(sparse_checksum_reader, size).await };

        let upload_future = async move {
            let url = Url::parse(format!("{0}/{1}", response.upload_url, 0).as_str())?;

            let mut reader = self
                .client
                .post(url, Box::pin(upload_reader), Some(size))
                .await?;

            let mut buffer = Vec::default();
            reader.read_to_end(&mut buffer).await?;

            Ok::<_, Error>(String::from_utf8_lossy(&buffer).into_owned())
        };

        let (_, condensed_mac, sparse_checksum, completion_handle) = futures::try_join!(
            dispatch_future,
            condensed_mac_future,
            sparse_checksum_future,
            upload_future,
        )?;

        let attributes = {
            let last_modified = last_modified.resolve().timestamp();
            let fingerprint = NodeFingerprint::new(sparse_checksum, last_modified);
            NodeAttributes {
                name: name.to_string(),
                fingerprint: Some(fingerprint.serialize()),
                modified_at: None,
                other: HashMap::default(),
            }
        };

        let file_attr_buffer = {
            let buffer = attributes.pack_and_encrypt(&aes_key)?;
            BASE64_URL_SAFE_NO_PAD.encode(&buffer)
        };

        let mut key = [0u8; FILE_KEY_SIZE];
        key[..16].copy_from_slice(&aes_key);
        key[16..24].copy_from_slice(&aes_iv[..8]);
        key[24..].copy_from_slice(&condensed_mac);
        utils::merge_key_mac(&mut key);

        utils::encrypt_ebc_in_place(&session.key, &mut key);

        let key_b64 = BASE64_URL_SAFE_NO_PAD.encode(&key);

        let attrs = UploadAttributes {
            kind: NodeKind::File,
            key: key_b64,
            attr: file_attr_buffer,
            completion_handle,
            file_attr: None,
        };

        let idempotence_id = utils::random_string(10);

        let request = Request::UploadComplete {
            t: parent.handle.clone().into(),
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

    /// Downloads the node's attribute payload into the given writer, if it exists.
    pub(crate) async fn download_attribute<W: AsyncWrite>(
        &self,
        kind: AttributeKind,
        attr_handle: &str,
        node: &Node,
        writer: W,
    ) -> Result<()> {
        let request = Request::UploadFileAttributes {
            h: None,
            fah: Some(attr_handle.to_string()),
            s: None,
            ssl: if self.state.https { 2 } else { 0 },
            r: Some(1),
        };
        let responses = self.send_requests(&[request]).await?;

        let [Response::UploadFileAttributes(response)] = responses.as_slice() else {
            return Err(Error::InvalidResponseType);
        };

        let attr_handle = BASE64_URL_SAFE_NO_PAD.decode(attr_handle)?;

        let mut reader = {
            let url = format!("{0}/{1}", response.p, u8::from(kind));
            let url = Url::parse(url.as_str())?;
            let len = attr_handle.len();
            let body = futures::io::Cursor::new(attr_handle);
            self.client
                .post(url, Box::pin(body), Some(u64::try_from(len).unwrap()))
                .await?
        };

        let _id = {
            let mut hash = [0u8; 8];
            reader.read_exact(&mut hash).await?;
            hash
        };

        let len = {
            let mut len_bytes = [0u8; 4];
            reader.read_exact(&mut len_bytes).await?;
            u32::from_le_bytes(len_bytes)
        };

        let mut cbc = cbc::Decryptor::<Aes128>::new(node.aes_key[..].into(), (&[0u8; 16]).into());

        futures::pin_mut!(writer);
        let mut reader = reader.take(len.into());

        let mut block = Vec::default();
        loop {
            block.clear();
            let bytes_read = (&mut reader).take(16).read_to_end(&mut block).await?;

            if bytes_read == 0 {
                break;
            }

            if bytes_read < 16 {
                let padding = std::iter::repeat(0).take(16 - bytes_read);
                block.extend(padding);
            }

            cbc.decrypt_block_mut(block.as_mut_slice().into());
            writer.write_all(&block[..bytes_read]).await?;
        }

        Ok(())
    }

    /// Downloads the node's thumbnail image into the given writer, if it exists.
    pub async fn download_thumbnail<W: AsyncWrite>(&self, node: &Node, writer: W) -> Result<()> {
        let Some(attr_handle) = node.thumbnail_handle.as_deref() else {
            return Err(Error::NodeAttributeNotFound);
        };

        self.download_attribute(AttributeKind::Thumbnail, attr_handle, node, writer)
            .await
    }

    /// Downloads the node's preview image into the given writer, if it exists.
    pub async fn download_preview_image<W: AsyncWrite>(
        &self,
        node: &Node,
        writer: W,
    ) -> Result<()> {
        let Some(preview_image_handle) = node.preview_image_handle.as_deref() else {
            return Err(Error::NodeAttributeNotFound);
        };

        self.download_attribute(
            AttributeKind::PreviewImage,
            preview_image_handle,
            node,
            writer,
        )
        .await
    }

    /// Uploads an attribute's payload for an existing node from a given reader.
    pub(crate) async fn upload_attribute<R: AsyncRead>(
        &self,
        kind: AttributeKind,
        node: &Node,
        size: u64,
        reader: R,
    ) -> Result<()> {
        let request = Request::UploadFileAttributes {
            h: Some(node.handle.clone().into()),
            fah: None,
            s: Some(size),
            ssl: if self.state.https { 2 } else { 0 },
            r: None,
        };
        let responses = self.send_requests(&[request]).await?;

        let [Response::UploadFileAttributes(response)] = responses.as_slice() else {
            return Err(Error::InvalidResponseType);
        };

        let mut cbc = cbc::Encryptor::<Aes128>::new(node.aes_key[..].into(), (&[0u8; 16]).into());

        let (pipe_reader, mut pipe_writer) = sluice::pipe::pipe();

        let fut_1 = async move {
            let reader = reader.take(size);
            futures::pin_mut!(reader);

            let mut block = Vec::default();
            loop {
                block.clear();
                let bytes_read = (&mut reader).take(16).read_to_end(&mut block).await?;

                if bytes_read == 0 {
                    break;
                }

                if bytes_read < 16 {
                    let padding = std::iter::repeat(0).take(16 - bytes_read);
                    block.extend(padding);
                }

                cbc.encrypt_block_mut(block.as_mut_slice().into());
                pipe_writer.write_all(&block[..bytes_read]).await?;
            }

            Ok(())
        };

        let url = Url::parse(format!("{0}/{1}", response.p, u8::from(kind)).as_str())?;
        let fut_2 = async move {
            let mut reader = self
                .client
                .post(url, Box::pin(pipe_reader), Some(size))
                .await?;

            let mut buffer = Vec::default();
            reader.read_to_end(&mut buffer).await?;

            Ok::<_, Error>(BASE64_URL_SAFE_NO_PAD.encode(&buffer))
        };

        let (_, fah) = futures::try_join!(fut_1, fut_2)?;

        let request = Request::PutFileAttributes {
            n: node.handle.clone().into(),
            fa: format!("{0}*{fah}", u8::from(kind)),
        };
        let responses = self.send_requests(&[request]).await?;

        match responses.as_slice() {
            [Response::PutFileAttributes(_)] => {}
            [Response::Error(code)] => {
                return Err(Error::from(*code));
            }
            _ => {
                return Err(Error::InvalidResponseType);
            }
        }

        Ok(())
    }

    /// Uploads a thumbnail image for an existing node from a given reader.
    pub async fn upload_thumbnail<R: AsyncRead>(
        &self,
        node: &Node,
        size: u64,
        reader: R,
    ) -> Result<()> {
        self.upload_attribute(AttributeKind::Thumbnail, node, size, reader)
            .await
    }

    /// Uploads a preview image for an existing node from a given reader.
    pub async fn upload_preview_image<R: AsyncRead>(
        &self,
        node: &Node,
        size: u64,
        reader: R,
    ) -> Result<()> {
        self.upload_attribute(AttributeKind::PreviewImage, node, size, reader)
            .await
    }

    /// Creates a new folder within MEGA.
    pub async fn create_folder(&self, parent: &Node, name: &str) -> Result<()> {
        let session = self
            .state
            .session
            .as_ref()
            .ok_or(Error::MissingUserSession)?
            .expose_secret();

        let mut aes_key: [u8; 16] = rand::random();

        let file_attr = NodeAttributes {
            name: name.to_string(),
            fingerprint: None,
            modified_at: None,
            other: HashMap::default(),
        };

        let file_attr_buffer = {
            let buffer = file_attr.pack_and_encrypt(&aes_key)?;
            BASE64_URL_SAFE_NO_PAD.encode(&buffer)
        };

        utils::encrypt_ebc_in_place(&session.key, &mut aes_key);

        let key_b64 = BASE64_URL_SAFE_NO_PAD.encode(&aes_key);

        let attrs = UploadAttributes {
            kind: NodeKind::Folder,
            key: key_b64,
            attr: file_attr_buffer,
            completion_handle: String::from("xxxxxxxx"),
            file_attr: None,
        };

        let idempotence_id = utils::random_string(10);

        let request = Request::UploadComplete {
            t: parent.handle.clone().into(),
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
        let attributes = {
            let fingerprint =
                (node.sparse_checksum.zip(node.modified_at)).map(|(checksum, modified_at)| {
                    NodeFingerprint::new(checksum, modified_at.timestamp()).serialize()
                });

            NodeAttributes {
                name: name.to_string(),
                fingerprint,
                modified_at: None,
                other: HashMap::default(),
            }
        };

        let attributes_buffer = {
            let buffer = attributes.pack_and_encrypt(&node.aes_key)?;
            BASE64_URL_SAFE_NO_PAD.encode(&buffer)
        };

        let idempotence_id = utils::random_string(10);

        let request = Request::SetFileAttributes {
            n: node.handle.clone().into(),
            key: None,
            attr: attributes_buffer,
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
            n: node.handle.clone().into(),
            t: parent.handle.clone().into(),
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
            n: node.handle.clone().into(),
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

    /// Performs a request for events, respecting the configured rules about timeouts and retries.
    async fn request_events(&self, event_cursor: &str) -> Result<EventBatchResponse> {
        let url = {
            let mut url = self.state.origin.join("/sc").unwrap();

            let mut qs = url.query_pairs_mut();
            qs.append_pair("sn", event_cursor);

            if let Some(session) = self.state.session.as_ref() {
                qs.append_pair("sid", session.expose_secret().sid.as_str());
            }

            qs.finish();
            drop(qs);

            url
        };

        let mut delay = self.state.min_retry_delay;
        for i in 0..self.state.max_retries {
            if i > 0 {
                tokio::time::sleep(delay).await;
                delay *= 2;
                // TODO: maybe add some small random jitter after the doubling.
                if delay > self.state.max_retry_delay {
                    delay = self.state.max_retry_delay;
                }
            }

            let mut response = self.client.get(url.clone()).await?;

            let mut buffer = Vec::default();
            response.read_to_end(&mut buffer).await?;

            let value: json::Value = json::from_slice(&buffer)?;
            if value.is_number() {
                let code = json::from_value(value)?;
                if code == ErrorCode::EAGAIN {
                    continue;
                }
                return Err(Error::MegaError { code });
            } else {
                let response = json::from_value(value)?;
                return Ok(response);
            }
        }

        Err(Error::MaxRetriesReached)
    }

    /// Retrieves MEGA events, if any are currently available (it does not wait for new events to come in).
    pub async fn poll_events(&self, nodes: &Nodes) -> Result<Option<EventBatch>> {
        let session = self
            .state
            .session
            .as_ref()
            .ok_or(Error::MissingUserSession)?
            .expose_secret();

        let EventBatchResponse::Ready(response) = self.request_events(&nodes.event_cursor).await?
        else {
            return Ok(None);
        };

        let mut events = Vec::new();
        for event in response.events {
            if event.is_number() {
                let code = json::from_value(event)?;
                return Err(Error::MegaError { code });
            }

            let event: EventResponse = json::from_value(event)?;
            match event.kind {
                EventResponseKind::NodeCreated(event) => {
                    let nodes = event
                        .nodes
                        .files
                        .into_iter()
                        .filter_map(|file| construct_event_node(&session, nodes, file).transpose())
                        .collect::<Result<_, _>>()?;

                    events.push(Event::NodeCreated { nodes });
                }
                EventResponseKind::NodeUpdated(event) => {
                    let Some(node) = nodes.get_node_by_handle(&event.handle) else {
                        // an event involving a node we don't currently know about?
                        continue;
                    };

                    let attrs = {
                        let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&event.attr)?;
                        NodeAttributes::decrypt_and_unpack(node.aes_key(), buffer.as_mut_slice())?
                    };

                    let fingerprint = attrs.extract_fingerprint();

                    let modified_at = (attrs.modified_at)
                        .or_else(|| fingerprint.as_ref().map(|it| it.modified_at))
                        .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());

                    let attrs = EventNodeAttributes {
                        handle: event.handle,
                        name: attrs.name,
                        owner: event.owner,
                        sparse_checksum: fingerprint.map(|it| it.checksum),
                        created_at: Some(Utc.timestamp_opt(event.ts, 0).unwrap()),
                        modified_at,
                    };

                    events.push(Event::NodeUpdated { attrs });
                }
                EventResponseKind::NodeDeleted(event) => {
                    events.push(Event::NodeDeleted {
                        handle: event.handle,
                    });
                }
                EventResponseKind::UnknownEvent => {
                    // Unsupported MEGA event
                }
            }
        }

        Ok(Some(EventBatch::new(
            events,
            nodes.event_cursor.clone(),
            response.sn,
        )))
    }

    /// Retrieves MEGA events, or efficiently waits for new ones if none are currently available.
    pub async fn wait_events(&self, nodes: &Nodes) -> Result<EventBatch> {
        let session = self
            .state
            .session
            .as_ref()
            .ok_or(Error::MissingUserSession)?
            .expose_secret();

        let response = loop {
            let response = self.request_events(&nodes.event_cursor).await?;
            match response {
                EventBatchResponse::Wait(response) => {
                    let wait_url = Url::parse(&response.wait_url)?;
                    self.client.get(wait_url).await?;
                }
                EventBatchResponse::Ready(response) => {
                    break response;
                }
            }
        };

        let mut events = Vec::new();
        for event in response.events {
            if event.is_number() {
                let code = json::from_value(event)?;
                return Err(Error::MegaError { code });
            }

            let event: EventResponse = json::from_value(event)?;
            match event.kind {
                EventResponseKind::NodeCreated(event) => {
                    let nodes = event
                        .nodes
                        .files
                        .into_iter()
                        .filter_map(|file| construct_event_node(&session, nodes, file).transpose())
                        .collect::<Result<_, _>>()?;

                    events.push(Event::NodeCreated { nodes });
                }
                EventResponseKind::NodeUpdated(event) => {
                    let Some(node) = nodes.get_node_by_handle(&event.handle) else {
                        // an event involving a node we don't currently know about?
                        continue;
                    };

                    let attrs = {
                        let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&event.attr)?;
                        NodeAttributes::decrypt_and_unpack(node.aes_key(), buffer.as_mut_slice())?
                    };

                    let fingerprint = attrs.extract_fingerprint();

                    let modified_at = (attrs.modified_at)
                        .or_else(|| fingerprint.as_ref().map(|it| it.modified_at))
                        .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());

                    let attrs = EventNodeAttributes {
                        handle: event.handle,
                        name: attrs.name,
                        owner: event.owner,
                        sparse_checksum: fingerprint.map(|it| it.checksum),
                        created_at: Some(Utc.timestamp_opt(event.ts, 0).unwrap()),
                        modified_at,
                    };

                    events.push(Event::NodeUpdated { attrs });
                }
                EventResponseKind::NodeDeleted(event) => {
                    events.push(Event::NodeDeleted {
                        handle: event.handle,
                    });
                }
                EventResponseKind::UnknownEvent => {
                    // Unsupported MEGA event
                }
            }
        }

        Ok(EventBatch::new(
            events,
            nodes.event_cursor.clone(),
            response.sn,
        ))
    }
}

fn construct_event_node(
    session: &UserSession,
    nodes: &Nodes,
    file: FileNode,
) -> Result<Option<EventNode>> {
    let (thumbnail_handle, preview_image_handle) = file
        .file_attr
        .as_deref()
        .map(|attr| utils::extract_attachments(attr))
        .unwrap_or_default();

    match file.kind {
        NodeKind::File | NodeKind::Folder => {
            // if let Some((_, s_key)) = file.s_user.as_deref().zip(file.s_key.as_deref()) {
            //     let mut share_key = BASE64_URL_SAFE_NO_PAD.decode(s_key)?;
            //     utils::decrypt_ebc_in_place(&session.key, &mut share_key);
            //     utils::decrypt_ebc_in_place(&share_key, &mut file_key);
            //     share_keys.insert(file.handle.clone(), share_key.clone());
            // }

            let Some(file_key) = file.key.as_deref() else {
                return Ok(None);
            };

            let Some(mut file_key) = file_key.split('/').find_map(|key| {
                let (file_user, file_key) = key.split_once(':')?;

                if file_key.len() >= 44 {
                    // Keys bigger than this size are using RSA instead of AES.
                    let data = BASE64_URL_SAFE_NO_PAD.decode(file_key).ok()?;
                    let (encrypted, _) = utils::rsa::get_mpi(&data).ok()?;
                    let mut decrypted = session.privk.decrypt(encrypted);
                    if file.kind.is_file() {
                        decrypted.truncate(FILE_KEY_SIZE);
                    } else {
                        decrypted.truncate(FOLDER_KEY_SIZE);
                    }
                    return Some(decrypted);
                }

                let mut file_key = BASE64_URL_SAFE_NO_PAD.decode(file_key).ok()?;

                // File keys are 32 bytes and folder keys are 16 bytes.
                // Other sizes are considered invalid.
                if (file.kind.is_file() && file_key.len() != FILE_KEY_SIZE)
                    || (!file.kind.is_file() && file_key.len() != FOLDER_KEY_SIZE)
                {
                    return None;
                }

                // TODO: MEGA includes in its web client a check to see if both halves of `file_key`
                //       are identical to each other. This is apparently done to prevent an attacker from
                //       being able to produce an all-zeroes AES key (by XOR-ing the two halves after EBC decryption).
                //       It's a bit unclear what we should do in our specific case, so it isn't yet implemented here.
                //
                //       Here would be how to implement such a check:
                //       ```
                //       if !self.state.allow_null_keys {
                //           let (fst, snd) = file_key.split_at(16);
                //           if fst == snd {
                //               return None;
                //           }
                //       }
                //       ```

                if let Some(node_id) = nodes.download_id.as_deref() {
                    let node = nodes.get_node_by_handle(node_id)?;
                    utils::decrypt_ebc_in_place(node.aes_key(), &mut file_key);
                    Some(file_key)
                } else {
                    if file_user == session.user_handle {
                        // regular owned file or folder
                        utils::decrypt_ebc_in_place(&session.key, &mut file_key);
                        return Some(file_key);
                    }

                    // if let Some(share_key) = share_keys.get(file_user) {
                    //     // shared file or folder
                    //     utils::decrypt_ebc_in_place(&share_key, &mut file_key);
                    //     return Some(file_key);
                    // }

                    None
                }
            }) else {
                return Ok(None);
            };

            let (aes_key, aes_iv, condensed_mac) = if file.kind.is_file() {
                utils::unmerge_key_mac(&mut file_key);

                let (aes_key, rest) = file_key.split_at(16);
                let (aes_iv, condensed_mac) = rest.split_at(8);

                (
                    aes_key.try_into().unwrap(),
                    aes_iv.try_into().ok(),
                    condensed_mac.try_into().ok(),
                )
            } else {
                (file_key.try_into().unwrap(), None, None)
            };

            let attrs = {
                let mut buffer = BASE64_URL_SAFE_NO_PAD.decode(&file.attr)?;
                NodeAttributes::decrypt_and_unpack(&aes_key, buffer.as_mut_slice())?
            };

            let fingerprint = attrs.extract_fingerprint();

            let modified_at = (attrs.modified_at)
                .or_else(|| fingerprint.as_ref().map(|it| it.modified_at))
                .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());

            Ok(Some(EventNode {
                name: attrs.name,
                handle: file.handle.clone(),
                owner: file.user,
                size: file.sz.unwrap_or(0),
                kind: file.kind,
                parent: (!file.parent.is_empty()).then(|| file.parent.clone()),
                aes_key,
                aes_iv,
                condensed_mac,
                checksum: fingerprint.map(|it| it.checksum),
                created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
                modified_at,
                download_id: nodes.download_id.clone(),
                thumbnail_handle,
                preview_image_handle,
            }))
        }
        NodeKind::Root => Ok(Some(EventNode {
            name: String::from("Root"),
            handle: file.handle.clone(),
            owner: file.user,
            size: file.sz.unwrap_or(0),
            kind: NodeKind::Root,
            parent: None,
            aes_key: <_>::default(),
            aes_iv: None,
            condensed_mac: None,
            checksum: None,
            created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
            modified_at: None,
            download_id: nodes.download_id.clone(),
            thumbnail_handle,
            preview_image_handle,
        })),
        NodeKind::Inbox => Ok(Some(EventNode {
            name: String::from("Inbox"),
            handle: file.handle.clone(),
            owner: file.user,
            size: file.sz.unwrap_or(0),
            kind: NodeKind::Inbox,
            parent: None,
            aes_key: <_>::default(),
            aes_iv: None,
            condensed_mac: None,
            checksum: None,
            created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
            modified_at: None,
            download_id: nodes.download_id.clone(),
            thumbnail_handle,
            preview_image_handle,
        })),
        NodeKind::Trash => Ok(Some(EventNode {
            name: String::from("Trash"),
            handle: file.handle.clone(),
            owner: file.user,
            size: file.sz.unwrap_or(0),
            kind: NodeKind::Trash,
            parent: None,
            aes_key: <_>::default(),
            aes_iv: None,
            condensed_mac: None,
            checksum: None,
            created_at: Some(Utc.timestamp_opt(file.ts, 0).unwrap()),
            modified_at: None,
            download_id: nodes.download_id.clone(),
            thumbnail_handle,
            preview_image_handle,
        })),
        NodeKind::Unknown => Ok(None),
    }
}

/// Represents a node, as part of an [`Event`].
#[derive(Debug, PartialEq)]
pub struct EventNode {
    /// The name of the node.
    pub(crate) name: String,
    /// The handle of the node.
    pub(crate) handle: String,
    /// The user handle of the owner of the node.
    pub(crate) owner: String,
    /// The size (in bytes) of the node.
    pub(crate) size: u64,
    /// The kind of the node.
    pub(crate) kind: NodeKind,
    /// The handle of the node's parent.
    pub(crate) parent: Option<String>,
    /// The AES key data of the node.
    pub(crate) aes_key: [u8; 16],
    /// The AES IV data of the node.
    pub(crate) aes_iv: Option<[u8; 8]>,
    /// The full-coverage condensed MAC of the node.
    pub(crate) condensed_mac: Option<[u8; 8]>,
    /// The sparse checksum of the node.
    pub(crate) checksum: Option<[u8; 16]>,
    /// The creation date of the node.
    pub(crate) created_at: Option<DateTime<Utc>>,
    /// The last modification date of the node.
    pub(crate) modified_at: Option<DateTime<Utc>>,
    /// The ID of the public link this node is from.
    pub(crate) download_id: Option<String>,
    /// The handle of the node's thumbnail.
    pub(crate) thumbnail_handle: Option<String>,
    /// The handle of the node's preview image.
    pub(crate) preview_image_handle: Option<String>,
}

impl EventNode {
    /// Returns the name of the node.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the handle of the node.
    pub fn handle(&self) -> &str {
        self.handle.as_str()
    }

    /// Returns the user handle of the owner of the node.
    pub fn owner(&self) -> &str {
        self.owner.as_str()
    }

    /// Returns the size (in bytes) of the node.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the kind of the node.
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// Returns the handle of the node's parent.
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Returns the last modified date of the node.
    pub fn modified_at(&self) -> Option<DateTime<Utc>> {
        self.modified_at
    }

    /// Returns the creation date of the node.
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        self.created_at
    }

    /// Returns the ID of the public link this node is from.
    pub fn download_id(&self) -> Option<&str> {
        self.download_id.as_deref()
    }

    /// Returns the AES key data of the node.
    pub fn aes_key(&self) -> &[u8; 16] {
        &self.aes_key
    }

    /// Returns the AES IV data of the node.
    pub fn aes_iv(&self) -> Option<&[u8; 8]> {
        self.aes_iv.as_ref()
    }

    /// Returns the full-coverage condensed MAC signature of the node.
    pub fn condensed_mac(&self) -> Option<&[u8; 8]> {
        self.condensed_mac.as_ref()
    }

    /// Returns the sparse CRC32-based checksum of the node.
    pub fn sparse_checksum(&self) -> Option<&[u8; 16]> {
        self.checksum.as_ref()
    }

    /// Returns whether this node has a associated thumbnail.
    pub fn has_thumbnail(&self) -> bool {
        self.thumbnail_handle.is_some()
    }

    /// Returns whether this node has an associated preview image.
    pub fn has_preview_image(&self) -> bool {
        self.preview_image_handle.is_some()
    }
}

/// Represents the updated attributes of a node, as part of an [`Event`].
#[derive(Debug, PartialEq)]
pub struct EventNodeAttributes {
    /// The handle of the node.
    pub(crate) handle: String,
    /// The name of the node.
    pub(crate) name: String,
    /// The user handle of the owner of this node.
    pub(crate) owner: String,
    /// The sparse checksum of the node.
    pub(crate) sparse_checksum: Option<[u8; 16]>,
    /// The creation date of the node.
    pub(crate) created_at: Option<DateTime<Utc>>,
    /// The last modification date of the node.
    pub(crate) modified_at: Option<DateTime<Utc>>,
}

impl EventNodeAttributes {
    /// The handle of the updated node.
    pub fn handle(&self) -> &str {
        self.handle.as_str()
    }

    /// The new name of the node.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the user handle of the new owner of the node.
    pub fn owner(&self) -> &str {
        self.owner.as_str()
    }

    /// Returns the new sparse CRC32-based checksum of the node.
    pub fn sparse_checksum(&self) -> Option<&[u8; 16]> {
        self.sparse_checksum.as_ref()
    }

    /// Returns the new last modified date of the node.
    pub fn modified_at(&self) -> Option<DateTime<Utc>> {
        self.modified_at
    }

    /// Returns the new creation date of the node.
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        self.created_at
    }
}

/// A MEGA-emitted event.
#[derive(Debug, PartialEq)]
pub enum Event {
    /// New nodes have been created.
    NodeCreated {
        /// The created nodes.
        nodes: Vec<EventNode>,
    },
    /// An existing node has been updated.
    NodeUpdated {
        /// The updated attributes for the node.
        attrs: EventNodeAttributes,
    },
    /// A node has been deleted.
    NodeDeleted {
        /// The handle of the deleted node.
        handle: String,
    },
}

/// A batch of MEGA-emitted events.
#[derive(Debug, PartialEq)]
pub struct EventBatch {
    /// The events for this batch.
    pub(crate) events: Vec<Event>,
    /// The `sn` this event batch is from.
    pub(crate) from: String,
    /// The `sn` this event batch goes to.
    pub(crate) to: String,
}

assert_impl_all!(EventBatch: Send, Sync);

impl EventBatch {
    pub(crate) fn new(events: Vec<Event>, from: String, to: String) -> Self {
        Self { events, from, to }
    }

    pub fn events(&self) -> &[Event] {
        self.events.as_slice()
    }
}

/// Represents a node stored in MEGA (either a file or a folder).
#[derive(Debug, PartialEq)]
pub struct Node {
    /// The name of the node.
    pub(crate) name: String,
    /// The handle of the node.
    pub(crate) handle: String,
    /// The user handle of the owner of the node.
    pub(crate) owner: String,
    /// The size (in bytes) of the node.
    pub(crate) size: u64,
    /// The kind of the node.
    pub(crate) kind: NodeKind,
    /// The handle of the node's parent.
    pub(crate) parent: Option<String>,
    /// The handles of the node's children.
    pub(crate) children: Vec<String>,
    /// The AES key data of the node.
    pub(crate) aes_key: [u8; 16],
    /// The AES IV data of the node.
    pub(crate) aes_iv: Option<[u8; 8]>,
    /// The full-coverage condensed MAC of the node.
    pub(crate) condensed_mac: Option<[u8; 8]>,
    /// The sparse checksum of the node.
    pub(crate) sparse_checksum: Option<[u8; 16]>,
    /// The creation date of the node.
    pub(crate) created_at: Option<DateTime<Utc>>,
    /// The last modification date of the node.
    pub(crate) modified_at: Option<DateTime<Utc>>,
    /// The ID of the public link this node is from.
    pub(crate) download_id: Option<String>,
    /// The handle of the node's thumbnail.
    pub(crate) thumbnail_handle: Option<String>,
    /// The handle of the node's preview image.
    pub(crate) preview_image_handle: Option<String>,
}

impl Node {
    /// Returns the name of the node.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the handle of the node.
    pub fn handle(&self) -> &str {
        self.handle.as_str()
    }

    /// Returns the user handle of the owner of the node.
    pub fn owner(&self) -> &str {
        self.owner.as_str()
    }

    /// Returns the size (in bytes) of the node.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the kind of the node.
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// Returns the handle of the node's parent.
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Returns the handles of the node's children.
    pub fn children(&self) -> &[String] {
        self.children.as_slice()
    }

    /// Returns the last modified date of the node.
    pub fn modified_at(&self) -> Option<DateTime<Utc>> {
        self.modified_at
    }

    /// Returns the creation date of the node.
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        self.created_at
    }

    /// Returns the ID of the public link this node is from.
    pub fn download_id(&self) -> Option<&str> {
        self.download_id.as_deref()
    }

    /// Returns the AES key data of the node.
    pub fn aes_key(&self) -> &[u8; 16] {
        &self.aes_key
    }

    /// Returns the AES IV data of the node.
    pub fn aes_iv(&self) -> Option<&[u8; 8]> {
        self.aes_iv.as_ref()
    }

    /// Returns the full-coverage condensed MAC signature of the node.
    pub fn condensed_mac(&self) -> Option<&[u8; 8]> {
        self.condensed_mac.as_ref()
    }

    /// Returns the sparse CRC32-based checksum of the node.
    pub fn sparse_checksum(&self) -> Option<&[u8; 16]> {
        self.sparse_checksum.as_ref()
    }

    /// Returns whether this node has a associated thumbnail.
    pub fn has_thumbnail(&self) -> bool {
        self.thumbnail_handle.is_some()
    }

    /// Returns whether this node has an associated preview image.
    pub fn has_preview_image(&self) -> bool {
        self.preview_image_handle.is_some()
    }
}

/// Represents a collection of nodes from MEGA.
pub struct Nodes {
    /// The nodes from MEGA, keyed by their handle.
    pub(crate) nodes: HashMap<String, Node>,
    /// The handle of the root node for the Cloud Drive.
    pub(crate) cloud_drive: Option<String>,
    /// The handle of the root node for the Rubbish Bin.
    pub(crate) rubbish_bin: Option<String>,
    /// The handle of the root node for the Inbox.
    pub(crate) inbox: Option<String>,
    /// The `sn` parameter for server-to-client events.
    pub(crate) event_cursor: String,
    /// The ID of the public link these nodes are from.
    pub(crate) download_id: Option<String>,
}

assert_impl_all!(Nodes: Send, Sync);

impl Nodes {
    pub(crate) fn new(
        nodes: HashMap<String, Node>,
        event_cursor: String,
        download_id: Option<String>,
    ) -> Self {
        let cloud_drive = nodes
            .values()
            .find_map(|node| node.kind.is_root().then(|| node.handle.clone()));
        let rubbish_bin = nodes
            .values()
            .find_map(|node| node.kind.is_rubbish_bin().then(|| node.handle.clone()));
        let inbox = nodes
            .values()
            .find_map(|node| node.kind.is_inbox().then(|| node.handle.clone()));

        Self {
            nodes,
            cloud_drive,
            rubbish_bin,
            inbox,
            event_cursor,
            download_id,
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

    /// Gets a node, identified by its handle.
    pub fn get_node_by_handle(&self, handle: &str) -> Option<&Node> {
        self.nodes.get(handle)
    }

    /// Gets a node, identified by its path.
    pub fn get_node_by_path(&self, path: &str) -> Option<&Node> {
        let path = path.strip_prefix('/').unwrap_or(path);

        let Some((root, path)) = path.split_once('/') else {
            return self.roots().find(|node| node.name == path);
        };

        let root = self.roots().find(|node| node.name == root)?;
        path.split('/').fold(Some(root), |node, name| {
            node?.children.iter().find_map(|handle| {
                let found = self.get_node_by_handle(handle)?;
                (found.name == name).then_some(found)
            })
        })
    }

    /// Gets the root node for the Cloud Drive.
    pub fn cloud_drive(&self) -> Option<&Node> {
        let handle = self.cloud_drive.as_ref()?;
        self.nodes.get(handle)
    }

    /// Gets the root node for the Inbox.
    pub fn inbox(&self) -> Option<&Node> {
        let handle = self.inbox.as_ref()?;
        self.nodes.get(handle)
    }

    /// Gets the root node for the Rubbish Bin.
    pub fn rubbish_bin(&self) -> Option<&Node> {
        let handle = self.rubbish_bin.as_ref()?;
        self.nodes.get(handle)
    }

    /// Creates a borrowing iterator over the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn apply_events(&mut self, events: EventBatch) -> Result<()> {
        if self.event_cursor != events.from {
            return Err(Error::EventCursorMismatch);
        }

        for event in events.events {
            match event {
                Event::NodeCreated { nodes } => {
                    for node in nodes {
                        self.insert_event_node(node);
                    }
                }
                Event::NodeUpdated { attrs } => {
                    self.update_node_attributes(attrs);
                }
                Event::NodeDeleted { handle } => {
                    self.delete_node(&handle);
                }
            }
        }

        // TODO: Are we supposed to recompute all impacted folder sizes?
        //       If so, we could maybe write a `self.invalidate_folder_sizes()` method.

        self.event_cursor = events.to;
        Ok(())
    }

    pub(crate) fn insert_event_node(&mut self, node: EventNode) {
        // compute new children for this node.
        let children = self
            .nodes
            .values()
            .filter_map(|it| {
                let parent = it.parent.as_ref()?;
                (parent == &node.handle).then(|| node.handle.clone())
            })
            .collect();

        let new_node = Node {
            name: node.name,
            handle: node.handle,
            owner: node.owner,
            size: node.size,
            kind: node.kind,
            parent: node.parent,
            children,
            aes_key: node.aes_key,
            aes_iv: node.aes_iv,
            condensed_mac: node.condensed_mac,
            sparse_checksum: node.checksum,
            created_at: node.created_at,
            modified_at: node.modified_at,
            download_id: node.download_id,
            thumbnail_handle: node.thumbnail_handle,
            preview_image_handle: node.preview_image_handle,
        };

        // Add this node to its parent's children.
        if let Some(parent_handle) = new_node.parent() {
            if let Some(parent_node) = self.nodes.get_mut(parent_handle) {
                if !parent_node.children.contains(&new_node.handle) {
                    parent_node.children.push(new_node.handle.clone());
                }
            }
        }

        let maybe_old_node = self.nodes.insert(new_node.handle.clone(), new_node);

        // Remove this node from its old parent's children.
        if let Some(old_node) = maybe_old_node {
            if let Some(parent_handle) = old_node.parent() {
                if let Some(parent_node) = self.nodes.get_mut(parent_handle) {
                    let maybe_position = parent_node
                        .children
                        .iter()
                        .position(|it| it == &old_node.handle);

                    if let Some(position) = maybe_position {
                        parent_node.children.remove(position);
                    }
                }
            }
        }
    }

    pub(crate) fn update_node_attributes(&mut self, attrs: EventNodeAttributes) {
        let Some(node) = self.nodes.get_mut(&attrs.handle) else {
            return;
        };

        node.name = attrs.name;
        node.owner = attrs.owner;
        node.sparse_checksum = attrs.sparse_checksum;
        node.created_at = attrs.created_at;
        node.modified_at = attrs.modified_at;
    }

    pub(crate) fn delete_node(&mut self, handle: &str) {
        let Some(node) = self.nodes.remove(handle) else {
            return;
        };

        for handle in node.children {
            self.delete_node(handle.as_str());
        }

        if let Some(parent_handle) = node.parent {
            if let Some(parent_node) = self.nodes.get_mut(&parent_handle) {
                let maybe_position = parent_node
                    .children
                    .iter()
                    .position(|it| it == &node.handle);

                if let Some(position) = maybe_position {
                    parent_node.children.remove(position);
                }
            }
        }
    }
}

impl IntoIterator for Nodes {
    type Item = Node;
    type IntoIter = std::collections::hash_map::IntoValues<String, Node>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_values()
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub(crate) enum AttributeKind {
    Thumbnail = 0,
    PreviewImage = 1,
}

impl From<AttributeKind> for u8 {
    fn from(value: AttributeKind) -> Self {
        value as u8
    }
}

/// Represents the last modified date to set for a newly uploaded MEGA node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastModified {
    /// Set the last modified date to the current time of the upload.
    Now,
    /// Set the last modified date to the explicitely-specified time.
    Set(DateTime<Utc>),
}

impl LastModified {
    pub fn resolve(self) -> DateTime<Utc> {
        match self {
            LastModified::Now => Utc::now(),
            LastModified::Set(datetime) => datetime,
        }
    }
}

/// Represents information about a MEGA user.
#[derive(Debug, Clone, PartialEq)]
pub struct UserInfo {
    /// The ID of the user.
    pub id: String,
    /// The first name of the user.
    pub first_name: String,
    /// The last name of the user.
    pub last_name: String,
    /// The main email of the user.
    pub email: String,
    /// The birth date of the user.
    pub birth_date: Option<NaiveDate>,
    /// The country code of the user.
    pub country_code: Option<String>,
}
