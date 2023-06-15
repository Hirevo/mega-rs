//!
//! Integration test for resuming a MEGA session from its serialized representation.
//!

use std::env;

#[tokio::test]
async fn session_resumption() {
    let session = env::var("MEGA_SESSION").expect("missing MEGA_SESSION environment variable");

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.resume_session(&session)
        .await
        .expect("could not resume session with MEGA");

    let nodes = mega
        .fetch_own_nodes()
        .await
        .expect("could not fetch own nodes");

    nodes
        .cloud_drive()
        .expect("could not find Cloud Drive root node");
}
