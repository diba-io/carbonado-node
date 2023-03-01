use std::{env, process};

use anyhow::Result;
use clap::Parser;
use log::error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Carbonado Node
enum Commands {
    /// Start storage provider node with configured frontends
    Start,
}

pub async fn try_main() -> Result<()> {
    match Commands::parse() {
        Commands::Start => carbonado_node::start().await?,
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    pretty_env_logger::init();

    if let Err(err) = try_main().await {
        error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| eprintln!("because: {}", cause));
        process::exit(1);
    }

    Ok(())
}
