use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::protocol::commands::FileNode;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventResponseNodes {
    #[serde(rename = "f")]
    pub files: Vec<FileNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeCreatedEventResponse {
    /// The idempotence token of the operation for which this event is emitted.
    #[serde(rename = "i")]
    pub i: Option<String>,
    /// The owner of the nodes.
    #[serde(rename = "ou")]
    pub owner: String,
    /// The batch of created nodes.
    #[serde(rename = "t")]
    pub nodes: EventResponseNodes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeUpdatedEventResponse {
    /// The idempotence token of the operation for which this event is emitted.
    #[serde(rename = "i")]
    pub i: Option<String>,
    /// The handle of the updated node.
    #[serde(rename = "n")]
    pub handle: String,
    /// The user handle of the new owner of the node.
    #[serde(rename = "u")]
    pub owner: String,
    /// The new encoded attributes for the node.
    #[serde(rename = "at")]
    pub attr: String,
    // /// The updated key for the node.
    // ///
    // /// Key updates are no longer supported by MEGA, but still transmitted for backwards compatibility.
    // #[serde(rename = "k")]
    // pub key: String,
    /// The new creation date for the node.
    #[serde(rename = "ts")]
    pub ts: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeDeletedEventResponse {
    /// The idempotence token of the operation for which this event is emitted.
    #[serde(rename = "i")]
    pub i: Option<String>,
    /// The handle of the deleted node.
    #[serde(rename = "n")]
    pub handle: String,
    /// This field is set to `1` if this event is due to a moved node.
    #[serde(rename = "m")]
    pub mov: Option<i32>,
    /// The owner of the deleted node.
    #[serde(rename = "ou")]
    pub owner: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnknownEventResponse {
    #[serde(flatten)]
    pub other: HashMap<String, json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "a")]
pub enum EventResponseKind {
    /// One (or more) new nodes have been created.
    #[serde(rename = "t")]
    NodeCreated(NodeCreatedEventResponse),
    /// A node's attributes have been updated.
    #[serde(rename = "u")]
    NodeUpdated(NodeUpdatedEventResponse),
    /// One node (or more, if it had children) have been deleted.
    #[serde(rename = "d")]
    NodeDeleted(NodeDeletedEventResponse),
    // TODO: "s": share addition/update/revocation
    // TODO: "s2": share addition/update/revocation
    // TODO: "c": contact addition/update
    // TODO: "k": crypto key request
    // TODO: "fa": file attribute update
    // TODO: "ua": user attribute update
    // TODO: "psts": account updated
    // TODO: "ipc": incoming pending contact request (to us)
    // TODO: "opc": outgoing pending contact request (from us)
    // TODO: "upci": incoming pending contact request update (accept/deny/ignore)
    // TODO: "upco": outgoing pending contact request update (from them, accept/deny/ignore)
    // TODO: "ph": public links handles
    // TODO: "se": set email
    // TODO: "mcc": chat creation / peer's invitation / peer's removal
    // TODO: "mcna": granted / revoked access to a node
    // TODO: "uac": user access control
    #[serde(other)]
    UnknownEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventResponse {
    #[serde(flatten)]
    pub kind: EventResponseKind,
    #[serde(flatten)]
    pub other: HashMap<String, json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventBatchResponseReady {
    #[serde(rename = "sn")]
    pub sn: String,
    #[serde(rename = "a")]
    pub events: Vec<json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventBatchResponseWait {
    #[serde(rename = "w")]
    pub wait_url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventBatchResponse {
    Ready(EventBatchResponseReady),
    Wait(EventBatchResponseWait),
}
