use chrono::{DateTime, TimeZone, Utc};

use crate::protocol::commands;

/// Represents information about a user session.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionInfo {
    /// The ID of the session.
    pub id: String,
    /// The creation date of the session.
    pub created_at: DateTime<Utc>,
    /// The date of last activity of the session.
    pub last_activity_at: DateTime<Utc>,
    /// The user agent string for the session.
    pub user_agent: String,
    /// The IP address of the session.
    pub ip: String,
    /// The country code for the session.
    pub country_code: String,
    /// Whether this session is the current one.
    pub current: bool,
    /// Whether this session is still alive.
    pub alive: bool,
}

impl From<commands::SessionInfo> for SessionInfo {
    fn from(value: commands::SessionInfo) -> Self {
        Self {
            id: value.id,
            created_at: Utc.timestamp_opt(value.timestamp, 0).unwrap(),
            last_activity_at: Utc.timestamp_opt(value.mru, 0).unwrap(),
            user_agent: value.user_agent,
            ip: value.ip,
            country_code: value.country,
            current: value.current == 1,
            alive: value.alive == 1,
        }
    }
}

impl From<&commands::SessionInfo> for SessionInfo {
    fn from(value: &commands::SessionInfo) -> Self {
        Self {
            id: value.id.clone(),
            created_at: Utc.timestamp_opt(value.timestamp, 0).unwrap(),
            last_activity_at: Utc.timestamp_opt(value.mru, 0).unwrap(),
            user_agent: value.user_agent.clone(),
            ip: value.ip.clone(),
            country_code: value.country.clone(),
            current: value.current == 1,
            alive: value.alive == 1,
        }
    }
}
