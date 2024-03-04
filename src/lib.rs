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

pub fn parity_npub(nsec: &str) -> Result<()> {
    use nostr::{prelude::*, secp256k1::Parity};

    let secret_key = SecretKey::from_bech32(nsec)?;
    let (xonly_public_key, parity) = secret_key.x_only_public_key(&SECP256K1);
    let pk = PublicKey::from(xonly_public_key);

    println!(
        "Parity npub is: {}{}",
        match parity {
            Parity::Even => '+',
            Parity::Odd => '-',
        },
        pk.to_bech32()?
    );

    Ok(())
}
