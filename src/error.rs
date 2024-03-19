use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;

/// The `Result` type for this library.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The main error type for this library.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// Missing user session.
    #[error("missing user session (consider logging in first)")]
    MissingUserSession,
    /// Invalid URL format.
    #[error("invalid URL format")]
    InvalidUrlFormat,
    /// The URL too short.
    #[error("the URL too short")]
    UrlTooShort,
    /// Invalid algorithm version.
    #[error("invalid algorithm version")]
    InvalidAlgorithmVersion {
        /// The encountered algorithm version.
        version: u8,
    },
    /// Invalid session kind.
    #[error("invalid session kind")]
    InvalidSessionKind,
    /// Invalid (or unsupported) public URL format.
    #[error("invalid (or unsupported) public URL format")]
    InvalidPublicUrlFormat,
    /// Invalid node checksum format.
    #[error("invalid node checksum format")]
    InvalidChecksumFormat,
    /// Invalid server response type.
    #[error("invalid server response type")]
    InvalidResponseType,
    /// Invalid response format.
    #[error("invalid response format")]
    InvalidResponseFormat,
    /// Invalid response format.
    #[error("missing response field: `{field}`")]
    MissingResponseField {
        /// The name of the missing field.
        field: &'static str,
    },
    /// Unknown user login version.
    #[error("unknown user login version: `{version}`")]
    UnknownUserLoginVersion {
        /// The encountered login version.
        version: i32,
    },
    /// Invalid RSA private key format.
    #[error("invalid RSA private key format")]
    InvalidRsaPrivateKeyFormat,
    /// Failed condensed MAC verification.
    #[error("condensed MAC mismatch")]
    CondensedMacMismatch,
    /// Failed to find node.
    #[error("failed to find node")]
    NodeNotFound,
    /// Failed to find node attribute.
    #[error("failed to find node attribute")]
    NodeAttributeNotFound,
    /// Could not get a meaningful response after maximum retries.
    #[error("could not get a meaningful response after maximum retries")]
    MaxRetriesReached,
    /// The involved event cursors do not match, continuing would result in inconsistencies.
    #[error("the involved event cursors do not match, continuing would result in inconsistencies")]
    EventCursorMismatch,
    /// UTF-8 validation error.
    #[error("UTF-8 validation error: {source}")]
    FromUtf8Error {
        /// The source error.
        #[from]
        source: std::string::FromUtf8Error,
    },
    /// Integer parsing error.
    #[error("integer parse error: {source}")]
    ParseIntError {
        /// The source error.
        #[from]
        source: std::num::ParseIntError,
    },
    /// Reqwest error.
    #[cfg(feature = "reqwest")]
    #[error("`reqwest` error: {source}")]
    ReqwestError {
        /// The source `reqwest` error.
        #[from]
        source: reqwest::Error,
    },
    /// URL parse error.
    #[error("URL parse error: {source}")]
    UrlError {
        /// The source `url` error.
        #[from]
        source: url::ParseError,
    },
    /// JSON error.
    #[error("JSON error: {source}")]
    JsonError {
        /// The source `serde_json` error.
        #[from]
        source: json::Error,
    },
    /// Base64 encode error.
    #[error("base64 encode error: {source}")]
    Base64EncodeError {
        /// The source `base64` encode error.
        #[from]
        source: base64::EncodeSliceError,
    },
    /// Base64 decode error.
    #[error("base64 encode error: {source}")]
    Base64DecodeError {
        /// The source `base64` decode error.
        #[from]
        source: base64::DecodeError,
    },
    /// HKDF error (invalid length).
    #[error("HKDF error: {source}")]
    HkdfInvalidLengthError {
        /// The source `hkdf` invalid length error.
        #[from]
        source: hkdf::InvalidLength,
    },
    /// HKDF error (invalid PRK length).
    #[error("HKDF error: {source}")]
    HkdfInvalidPrkLengthError {
        /// The source `hkdf` invalid PRK length error.
        #[from]
        source: hkdf::InvalidPrkLength,
    },
    /// HMAC verification error.
    #[error("HMAC mismatch (invalid link or wrong password)")]
    HmacMismatch {
        /// The source `hmac` verification error.
        #[from]
        source: hmac::digest::MacError,
    },
    /// AES-GCM error.
    #[error("AES-GCM error: {source}")]
    AesGcmError {
        /// The source `aes_gcm` error.
        #[from]
        source: aes_gcm::Error,
    },
    /// MEGA error (error codes from API).
    #[error("MEGA error: {code}")]
    MegaError {
        /// The MEGA error code.
        #[from]
        code: ErrorCode,
    },
    /// I/O error.
    #[error("IO error: {source}")]
    IoError {
        /// The source `std::io` error.
        #[from]
        source: std::io::Error,
    },
    /// Other errors.
    #[error("other error: {source}")]
    Other {
        /// The source error.
        #[from]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Error code originating from MEGA's API.
#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error, Serialize_repr, Deserialize_repr)]
pub enum ErrorCode {
    /// Success
    #[error("no error")]
    OK = 0,
    /// Internal Error
    #[error("internal error")]
    EINTERNAL = -1,
    /// Invalid arguments
    #[error("invalid argument")]
    EARGS = -2,
    /// Request failed (but may be retried)
    #[error("request failed, retrying")]
    EAGAIN = -3,
    /// Rate-limited
    #[error("rate limit exceeded")]
    ERATELIMIT = -4,
    /// Upload failed
    #[error("failed permanently")]
    EFAILED = -5,
    /// Too many IPs are trying to access this resource
    #[error("too many concurrent connections or transfers")]
    ETOOMANY = -6,
    /// The file packet is out of range
    #[error("out of range")]
    ERANGE = -7,
    /// The upload target url has expired
    #[error("expired")]
    EEXPIRED = -8,
    /// Object not found
    #[error("not found")]
    ENOENT = -9,
    /// Attempted circular link
    #[error("circular linkage detected")]
    ECIRCULAR = -10,
    /// Access violation (like writing to a read-only share)
    #[error("access denied")]
    EACCESS = -11,
    /// Tried to create an object that already exists
    #[error("already exists")]
    EEXIST = -12,
    /// Tried to access an incomplete resource
    #[error("incomplete")]
    EINCOMPLETE = -13,
    /// A decryption operation failed
    #[error("invalid key / decryption error")]
    EKEY = -14,
    /// Invalid or expired user session
    #[error("bad session ID")]
    ESID = -15,
    /// User blocked
    #[error("blocked")]
    EBLOCKED = -16,
    /// Request over quota
    #[error("over quota")]
    EOVERQUOTA = -17,
    /// Resource temporarily unavailable
    #[error("temporarily not available")]
    ETEMPUNAVAIL = -18,
    /// Too many connections to this resource
    #[error("connection overflow")]
    ETOOMANYCONNECTIONS = -19,
    /// Write failed
    #[error("write error")]
    EWRITE = -20,
    /// Read failed
    #[error("read error")]
    EREAD = -21,
    /// Invalid App key
    #[error("invalid application key")]
    EAPPKEY = -22,
    /// SSL verification failed
    #[error("SSL verification failed")]
    ESSL = -23,
    /// Not enough quota
    #[error("not enough quota")]
    EGOINGOVERQUOTA = -24,
    /// Need multifactor authentication
    #[error("multi-factor authentication required")]
    EMFAREQUIRED = -26,
    /// Access denied for sub-users (buisness accounts only)
    #[error("access denied for users")]
    EMASTERONLY = -27,
    /// Business account expired
    #[error("business account has expired")]
    EBUSINESSPASTDUE = -28,
    /// Over Disk Quota Paywall
    #[error("storage quota exceeded")]
    EPAYWALL = -29,
    /// Unknown error
    #[serde(other)]
    #[error("unknown error")]
    UNKNOWN = 1,
}
