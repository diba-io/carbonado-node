use anyhow::Result;
use log::{error, info};
use tokio::signal;

use crate::frontend::http;

pub mod backend;
pub mod config;
pub mod constants;
pub mod errors;
pub mod frontend;
pub mod header;
pub mod structs;

pub mod prelude {
    use super::*;

    pub use constants::*;
    pub use structs::*;
}

pub async fn start() -> Result<()> {
    info!("Starting Carbonado node...");

    // TODO: Determine which storage frontends to use from configuration

    // Spawn storage frontends within their own threads
    tokio::spawn(async {
        match http::start().await {
            Ok(_) => {
                info!("Graceful HTTP server shutdown")
            }
            Err(e) => {
                error!("Error in HTTP server: {e}")
            }
        };
    });

    signal::ctrl_c().await?;

    Ok(())
}
