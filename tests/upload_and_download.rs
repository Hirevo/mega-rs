//!
//! Integration test for uploading a file to MEGA and downloading it back.
//!

use std::env;

use rand::distributions::{Alphanumeric, DistString};

pub const BASE_PATH: &str = "/Root/mega-rs-tests";

#[tokio::test]
async fn upload_and_download_test() {
    let email = env::var("MEGA_EMAIL").expect("missing MEGA_EMAIL environment variable");
    let password = env::var("MEGA_PASSWORD").expect("missing MEGA_PASSWORD environment variable");

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.login(&email, &password, None)
        .await
        .expect("could not log in to MEGA");

    let nodes = mega
        .fetch_own_nodes()
        .await
        .expect("could not fetch own nodes");

    let root = nodes
        .get_node_by_path(BASE_PATH)
        .expect("could not find Cloud Drive root");

    let uploaded = {
        let mut rng = rand::thread_rng();
        Alphanumeric.sample_string(&mut rng, 1024)
    };

    let file_name = {
        let mut rng = rand::thread_rng();
        format!(
            "mega-rs-test-file-{0}.txt",
            Alphanumeric.sample_string(&mut rng, 10),
        )
    };

    let file_path = format!("{BASE_PATH}/{file_name}");
    let size = uploaded.len();

    mega.upload_node(
        root,
        file_name.as_str(),
        size.try_into().unwrap(),
        uploaded.as_bytes(),
        mega::LastModified::Now,
    )
    .await
    .expect("could not upload test file");

    let nodes = mega
        .fetch_own_nodes()
        .await
        .expect("could not fetch own nodes (after upload)");

    let node = nodes
        .get_node_by_path(&file_path)
        .expect("could not find test file node after upload");

    let mut downloaded = Vec::default();
    mega.download_node(node, &mut downloaded)
        .await
        .expect("could not download test file");

    assert_eq!(uploaded.as_bytes(), downloaded.as_slice());

    mega.delete_node(node)
        .await
        .expect("could not delete test file");

    mega.logout().await.expect("could not log out from MEGA");
}
