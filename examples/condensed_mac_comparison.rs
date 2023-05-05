//!
//! Example program that simply checks if a local file is similar to a MEGA file
//! using a condensed MAC, with progress reporting.
//!

use std::env;
use std::sync::Arc;
use std::time::Duration;

use async_read_progress::AsyncReadProgressExt;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs::File;
use tokio_util::compat::TokioAsyncReadCompatExt;

async fn run(
    mega: &mut mega::Client,
    local_file_path: &str,
    distant_file_path: &str,
) -> mega::Result<()> {
    let nodes = mega.fetch_own_nodes().await?;

    let node = nodes
        .get_node_by_path(distant_file_path)
        .expect("could not find node by path");

    let Some(remote_condensed_mac) = node.condensed_mac() else {
        println!("remote node doesn't have a checksum available");
        return Ok(());
    };

    let bar = ProgressBar::new(node.size());
    bar.set_style(progress_bar_style());
    bar.set_message(format!("computing checksum for {local_file_path}..."));

    let file = File::open(local_file_path).await?;
    let size = file.metadata().await?.len();

    let bar = Arc::new(bar);

    let reader = {
        let bar = bar.clone();
        file.compat()
            .report_progress(Duration::from_millis(100), move |bytes_read| {
                bar.set_position(bytes_read as u64);
            })
    };

    let local_condensed_mac = {
        let aes_key = node.aes_key();
        let aes_iv = node.aes_iv().unwrap();
        mega::compute_condensed_mac(reader, size, aes_key, aes_iv).await?
    };

    bar.finish_and_clear();

    if local_condensed_mac == *remote_condensed_mac {
        println!("OK ! (the MACs are identical)");
    } else {
        println!("FAILED ! (the MACs differ)");
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let email = env::var("MEGA_EMAIL").expect("missing MEGA_EMAIL environment variable");
    let password = env::var("MEGA_PASSWORD").expect("missing MEGA_PASSWORD environment variable");
    let mfa = env::var("MEGA_MFA").ok();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let [local_file_path, distant_file_path] = args.as_slice() else {
        panic!("expected 2 command-line arguments: {{local_file_path}} {{distant_file_path}}");
    };

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.login(&email, &password, mfa.as_deref()).await.unwrap();
    let result = run(&mut mega, local_file_path, distant_file_path).await;
    mega.logout().await.unwrap();

    result.unwrap();
}

pub fn progress_bar_style() -> ProgressStyle {
    let template = format!(
        "{}{{bar:30.magenta.bold/magenta/bold}}{} {{percent}} % (ETA {{eta}}): {{msg}}",
        style("▐").bold().magenta(),
        style("▌").bold().magenta(),
    );

    ProgressStyle::default_bar()
        .progress_chars("▨▨╌")
        .template(template.as_str())
        .unwrap()
}
