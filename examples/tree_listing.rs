//!
//! Example program that displays all of the available nodes in MEGA
//! in a textual tree format.
//!

use std::env;

use text_trees::{StringTreeNode, TreeFormatting, FormatCharacters};

fn construct_tree_node(mega: &mega::Client, node: &mega::Node) -> StringTreeNode {
    let children = node.children().iter().filter_map(|hash| {
        let node = mega.get_node_by_hash(hash)?;
        Some(construct_tree_node(mega, node))
    });
    StringTreeNode::with_child_nodes(node.name().to_string(), children)
}

async fn run(mega: &mut mega::Client) -> mega::Result<()> {
    mega.fetch_nodes().await?;

    let cloud_drive = mega.cloud_drive().expect("could not get Cloud Drive root");
    let inbox = mega.inbox().expect("could not get Inbox root");
    let rubbish_bin = mega.rubbish_bin().expect("could not get Rubbish Bin root");

    let cloud_drive_tree = construct_tree_node(mega, cloud_drive);
    let inbox_tree = construct_tree_node(mega, inbox);
    let rubbish_bin_tree = construct_tree_node(mega, rubbish_bin);
    
    let formatting = TreeFormatting::dir_tree(FormatCharacters::box_chars());

    println!();
    cloud_drive_tree.write_with_format(&mut std::io::stdout(), &formatting).unwrap();
    println!();
    inbox_tree.write_with_format(&mut std::io::stdout(), &formatting).unwrap();
    println!();
    rubbish_bin_tree.write_with_format(&mut std::io::stdout(), &formatting).unwrap();
    println!();

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let email = env::var("MEGA_EMAIL").expect("missing MEGA_EMAIL environment variable");
    let password = env::var("MEGA_PASSWORD").expect("missing MEGA_PASSWORD environment variable");

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.login(&email, &password, None).await.unwrap();

    let result = run(&mut mega).await;
    mega.logout().await.unwrap();

    result.unwrap();
}
