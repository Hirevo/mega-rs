//!
//! Integration test for using events to update local nodes and chain operations.
//!

use std::env;

use rand::distributions::{Alphanumeric, DistString};

#[tokio::test]
async fn event_updates_test() {
    let email = env::var("MEGA_EMAIL").expect("missing MEGA_EMAIL environment variable");
    let password = env::var("MEGA_PASSWORD").expect("missing MEGA_PASSWORD environment variable");
    let mfa = env::var("MEGA_MFA").ok();

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.login(&email, &password, mfa.as_deref())
        .await
        .expect("could not log in to MEGA");

    let mut nodes = mega
        .fetch_own_nodes()
        .await
        .expect("could not fetch own nodes");

    let root = nodes
        .get_node_by_path("/Root/mega-rs-tests")
        .expect("could not find Cloud Drive root");

    let cloud_drive_handle = root.handle().to_string();

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

    let uploaded_handle = loop {
        let batch = mega
            .wait_events(&nodes)
            .await
            .expect("could not fetch MEGA events");

        let maybe_uploaded_handle = batch.events().iter().find_map(|event| {
            let mega::Event::NodeCreated { nodes } = event else {
                return None;
            };

            nodes.iter().find_map(|node| {
                (node.parent() == Some(cloud_drive_handle.as_str()) && node.name() == file_name)
                    .then(|| node.handle().to_string())
            })
        });

        nodes
            .apply_events(batch)
            .expect("could not apply events to local nodes");

        if let Some(uploaded_handle) = maybe_uploaded_handle {
            break uploaded_handle;
        }
    };

    let node = nodes
        .get_node_by_handle(&uploaded_handle)
        .expect("could not find test file node after upload");

    let mut downloaded = Vec::default();
    mega.download_node(node, &mut downloaded)
        .await
        .expect("could not download test file");

    assert_eq!(uploaded.as_bytes(), downloaded.as_slice());

    let new_file_name = {
        let mut rng = rand::thread_rng();
        format!(
            "mega-rs-test-file-{0}.txt",
            Alphanumeric.sample_string(&mut rng, 10),
        )
    };

    mega.rename_node(node, &new_file_name)
        .await
        .expect("could not rename node");

    loop {
        let batch = mega
            .wait_events(&nodes)
            .await
            .expect("could not fetch MEGA events");

        let found_event = batch.events().iter().any(|event| {
            matches!(event, mega::Event::NodeUpdated { attrs } if attrs.handle() == uploaded_handle.as_str())
        });

        nodes
            .apply_events(batch)
            .expect("could not apply events to local nodes");

        if found_event {
            break;
        }
    }

    let node = nodes
        .get_node_by_handle(&uploaded_handle)
        .expect("could not find test file node after rename");

    mega.delete_node(node)
        .await
        .expect("could not delete test file");

    loop {
        let batch = mega
            .wait_events(&nodes)
            .await
            .expect("could not fetch MEGA events");

        let found_event = batch.events().iter().any(|event| {
            matches!(event, mega::Event::NodeDeleted { handle } if handle.as_str() == uploaded_handle.as_str())
        });

        nodes
            .apply_events(batch)
            .expect("could not apply events to local nodes");

        if found_event {
            break;
        }
    }

    mega.logout().await.expect("could not log out from MEGA");
}
