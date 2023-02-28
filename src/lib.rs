use anyhow::Result;
use log::info;
use tokio::signal;

pub mod backend;
pub mod config;
pub mod constants;
pub mod frontend;
pub mod structs;

pub mod prelude {
    use super::*;

    pub use constants::*;
    pub use structs::*;
}

pub async fn start() -> Result<()> {
    info!("Starting Carbonado node...");

    // Determine which storage frontends to use from configuration

    // Spawn storage frontends within their own threads

    signal::ctrl_c().await?;

    Ok(())
}
