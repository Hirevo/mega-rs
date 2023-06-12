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
    MissingResponseField { field: &'static str },
    /// Unknown user login version.
    #[error("unknown user login version: `{version}`")]
    UnknownUserLoginVersion { version: i32 },
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
    /// Reqwest error.
    #[cfg(feature = "reqwest")]
    #[error("`reqwest` error: {source}")]
    ReqwestError {
        #[from]
        source: reqwest::Error,
    },
    /// URL parse error.
    #[error("URL parse error: {source}")]
    UrlError {
        #[from]
        source: url::ParseError,
    },
    /// JSON error.
    #[error("JSON error: {source}")]
    JsonError {
        #[from]
        source: json::Error,
    },
    /// Base64 encode error.
    #[error("base64 encode error: {source}")]
    Base64EncodeError {
        #[from]
        source: base64::EncodeSliceError,
    },
    /// Base64 decode error.
    #[error("base64 encode error: {source}")]
    Base64DecodeError {
        #[from]
        source: base64::DecodeError,
    },
    /// PBKDF2 error.
    #[error("PBKDF2 error: {source}")]
    Pbkdf2Error {
        #[from]
        source: pbkdf2::password_hash::Error,
    },
    /// HKDF error (invalid length).
    #[error("HKDF error: {source}")]
    HkdfInvalidLengthError {
        #[from]
        source: hkdf::InvalidLength,
    },
    /// HKDF error (invalid PRK length).
    #[error("HKDF error: {source}")]
    HkdfInvalidPrkLengthError {
        #[from]
        source: hkdf::InvalidPrkLength,
    },
    /// AES-GCM error.
    #[error("AES-GCM error: {source}")]
    AesGcmError {
        #[from]
        source: aes_gcm::Error,
    },
    /// MEGA error (error codes from API).
    #[error("MEGA error: {code}")]
    MegaError {
        #[from]
        code: ErrorCode,
    },
    /// I/O error.
    #[error("IO error: {source}")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    /// Other errors.
    #[error("other error: {source}")]
    Other {
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
