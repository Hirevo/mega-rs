use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use async_trait::async_trait;
use futures::io::AsyncRead;
use secrecy::SecretBox;
use url::Url;
use zeroize::Zeroize;

#[cfg(feature = "reqwest")]
mod reqwest;

use crate::error::Result;
use crate::protocol::commands::{Request, Response};
use crate::utils::rsa::RsaPrivateKey;

/// Stores the data representing a user's session.
#[derive(Debug, Clone, Zeroize)]
pub struct UserSession {
    /// The user's session id.
    pub(crate) sid: String,
    /// The user's master key.
    pub(crate) key: [u8; 16],
    /// The user's `sek`.
    pub(crate) sek: [u8; 16],
    /// The user's RSA private key (used for shares).
    pub(crate) privk: RsaPrivateKey,
    /// The user's handle.
    pub(crate) user_handle: String,
}

/// Stores the data representing the client's state.
#[derive(Debug)]
pub struct ClientState {
    /// The API's origin.
    pub(crate) origin: Url,
    /// The number of allowed retries.
    pub(crate) max_retries: usize,
    /// The minimum amount of time between retries.
    pub(crate) min_retry_delay: Duration,
    /// The maximum amount of time between retries.
    pub(crate) max_retry_delay: Duration,
    /// The timeout duration to use for each request.
    pub(crate) timeout: Option<Duration>,
    /// Whether to use HTTPS for file downloads and uploads, instead of plain HTTP.
    ///
    /// Using plain HTTP for file transfers is fine because the file contents are already encrypted,
    /// making protocol-level encryption a bit redundant and potentially slowing down the transfer.
    pub(crate) https: bool,
    /// The request counter, for idempotency.
    pub(crate) id_counter: AtomicU64,
    /// The user's session.
    pub(crate) session: Option<SecretBox<UserSession>>,
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Sends the given requests to MEGA's API and parses the responses accordingly.
    async fn send_requests(
        &self,
        state: &ClientState,
        requests: &[Request],
        query_params: &[(&str, &str)],
    ) -> Result<Vec<Response>>;

    /// Initiates a simple GET request, returning the response body as a reader.
    async fn get(&self, url: Url) -> Result<Pin<Box<dyn AsyncRead + Send>>>;

    /// Initiates a simple POST request, with body and optional `content-length`, returning the response body as a reader.
    async fn post(
        &self,
        url: Url,
        body: Pin<Box<dyn AsyncRead + Send + Sync>>,
        content_length: Option<u64>,
    ) -> Result<Pin<Box<dyn AsyncRead + Send>>>;
}
