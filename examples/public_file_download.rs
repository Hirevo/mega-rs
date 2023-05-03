//!
//! Example program that simply downloads a file from a MEGA public link
//! with progress reporting.
//!

use std::sync::Arc;
use std::time::Duration;

use async_read_progress::AsyncReadProgressExt;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs::File;
use tokio_util::compat::TokioAsyncWriteCompatExt;

async fn run(
    mega: &mut mega::Client,
    public_url: &str,
    distant_file_path: Option<&str>,
) -> mega::Result<()> {
    let nodes = mega.fetch_public_nodes(public_url).await?;

    let files: Vec<_> = match distant_file_path {
        Some(distant_file_path) => {
            let node = nodes
                .get_node_by_path(distant_file_path)
                .expect("could not find distant node by path");

            vec![node]
        }
        None => nodes.roots().filter(|node| node.kind().is_file()).collect(),
    };

    for node in files {
        let (reader, writer) = sluice::pipe::pipe();

        let bar = ProgressBar::new(node.size());
        bar.set_style(progress_bar_style());
        bar.set_message(format!("downloading {0}...", node.name()));

        let file = File::create(node.name()).await?;

        let bar = Arc::new(bar);

        let reader = {
            let bar = bar.clone();
            reader.report_progress(Duration::from_millis(100), move |bytes_read| {
                bar.set_position(bytes_read as u64);
            })
        };

        let handle =
            tokio::spawn(async move { futures::io::copy(reader, &mut file.compat_write()).await });
        mega.download_node(node, writer).await?;
        handle.await.unwrap()?;

        bar.finish_with_message(format!("{0} downloaded !", node.name()));
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (public_url, distant_file_path) = match args.as_slice() {
        [public_url] => (public_url.as_str(), None),
        [public_url, distant_file_path] => (public_url.as_str(), Some(distant_file_path.as_str())),
        _ => {
            panic!("expected 1 or 2 command-line arguments: {{public_url}} {{distant_file_path}}");
        }
    };

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    run(&mut mega, public_url, distant_file_path).await.unwrap();
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
