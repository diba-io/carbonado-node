use std::{
    env,
    fs::{create_dir_all, OpenOptions},
    io::{Read, Seek, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use directories::BaseDirs;
use log::trace;
use once_cell::sync::Lazy;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

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

pub static ENV_CFG: Lazy<EnvCfg> = Lazy::new(|| init_env_cfg().expect("Initialize env config"));

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

pub fn init_sys_cfg() -> Result<SysCfg> {
    create_dir_all(&ENV_CFG.data_cfg_dir)?;

    let mut cfg_contents = String::new();

    trace!("Creates new empty config file if it doesn't exist");
    let mut cfg_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&ENV_CFG.data_cfg_file)?;

    cfg_file.read_to_string(&mut cfg_contents)?;

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
        create_dir_all(&vol.path)?;
    }

    let private_key = sys_cfg
        .private_key
        .unwrap_or_else(|| SecretKey::new(&mut rand::thread_rng()));

    let config = SysCfg {
        private_key,
        volumes,
    };

    trace!("Write parsed config back out to config file");
    let toml = toml::to_string_pretty(&config)?;
    cfg_file.rewind()?;
    cfg_file.write_all(toml.as_bytes())?;

    Ok(config)
}

pub static SYS_CFG: Lazy<SysCfg> = Lazy::new(|| init_sys_cfg().expect("Initialize sys cfg"));
