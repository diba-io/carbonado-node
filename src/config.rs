use std::{env, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Result};
use directories::BaseDirs;
use once_cell::sync::Lazy;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{create_dir_all, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

pub struct EnvCfg {
    pub data_cfg_dir: PathBuf,
    pub data_cfg_file: PathBuf,
}

fn init_env_cfg() -> Result<EnvCfg> {
    let base_dirs = BaseDirs::new().ok_or_else(|| anyhow!("Error finding config directory"))?;

    let data_cfg_dir = env::var("DATA_CFG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base_dirs.config_dir().join("carbonado"));

    let data_cfg_file = data_cfg_dir.join("cfg.toml");

    Ok(EnvCfg {
        data_cfg_dir,
        data_cfg_file,
    })
}

pub static ENV_CFG: Lazy<EnvCfg> = Lazy::new(|| init_env_cfg().expect("Initial env config"));

#[derive(Serialize, Deserialize)]
pub struct Volume {
    pub path: PathBuf,  // Path to mounted volume
    pub allocated: u64, // Allocated capacity in megabytes
}

#[derive(Deserialize)]
struct SysCfgFile {
    private_key: Option<SecretKey>,
    volume: Option<Vec<Volume>>,
}

#[derive(Serialize)]
pub struct SysCfg {
    pub private_key: SecretKey,
    pub volumes: Vec<Volume>,
}

pub async fn init_cfg() -> Result<()> {
    create_dir_all(&ENV_CFG.data_cfg_dir).await?;

    let mut cfg_contents = String::new();

    // Creates new empty config file if it doesn't exist
    let mut cfg_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&ENV_CFG.data_cfg_file)
        .await?;

    cfg_file.read_to_string(&mut cfg_contents).await?;

    let sys_cfg: SysCfgFile = toml::from_str(&cfg_contents)?;

    let volumes: Vec<Volume> = sys_cfg
        .volume
        .map(|vols| {
            vols.iter()
                .map(|vol| Volume {
                    path: PathBuf::from(&vol.path),
                    allocated: vol.allocated,
                })
                .collect()
        })
        .unwrap_or_else(|| {
            (0..8)
                .map(|i| Volume {
                    path: PathBuf::from(format!("/tmp/carbonado-{i}")),
                    allocated: 1_000,
                })
                .collect()
        });

    for vol in volumes.iter() {
        create_dir_all(&vol.path).await?;
    }

    let private_key = sys_cfg
        .private_key
        .unwrap_or_else(|| SecretKey::new(&mut rand::thread_rng()));

    let config = SysCfg {
        private_key,
        volumes,
    };

    // Write parsed config back out to config file
    let toml = toml::to_string_pretty(&config)?;
    cfg_file.write_all(toml.as_bytes()).await?;

    *SYS_CFG.write().await = Arc::new(Some(config));

    Ok(())
}

pub static SYS_CFG: Lazy<RwLock<Arc<Option<SysCfg>>>> = Lazy::new(|| RwLock::new(Arc::new(None)));
