use std::{
    env,
    fs::{create_dir_all, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use directories::BaseDirs;
use log::{info, trace};
use once_cell::sync::Lazy;
use secp256k1::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::prelude::{CATALOG_DIR, SEGMENT_DIR};

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

#[derive(Serialize, Deserialize, Clone)]
pub struct Volume {
    pub path: PathBuf, // Path to mounted volume
}

#[derive(Deserialize)]
struct SysCfgFile {
    http_port: Option<u16>,
    private_key: Option<SecretKey>,
    drive_redundancy: Option<usize>,
    volumes: Option<Vec<Volume>>,
    capacity: Option<u64>,
}

#[derive(Serialize)]
pub struct SysCfg {
    pub http_port: u16,
    pub private_key: SecretKey,
    pub drive_redundancy: usize,
    pub volumes: Vec<Volume>,
    /// Total allocated capacity for the node in megabytes
    pub capacity: u64,
}

pub fn init_sys_cfg() -> Result<SysCfg> {
    create_dir_all(&ENV_CFG.data_cfg_dir)?;

    let mut cfg_contents = String::new();

    trace!("Create new empty config file if it doesn't exist");
    let mut cfg_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&ENV_CFG.data_cfg_file)?;

    cfg_file.read_to_string(&mut cfg_contents)?;

    let sys_cfg: SysCfgFile = toml::from_str(&cfg_contents)?;

    let http_port = sys_cfg.http_port.unwrap_or(7000);

    let private_key = sys_cfg
        .private_key
        .unwrap_or_else(|| SecretKey::new(&mut rand::thread_rng()));

    let secp = Secp256k1::new();
    info!("Node Public Key: {}", private_key.public_key(&secp));

    let drive_redundancy = sys_cfg.drive_redundancy.unwrap_or(1);

    match drive_redundancy {
        1 | 2 | 4 | 8 => {}
        _ => {
            return Err(anyhow!("drive_redundancy must be either 1, 2, 4, or 8"));
        }
    }

    let orig_volumes = sys_cfg.volumes.unwrap_or_default();
    let mut volumes: Vec<Volume> = vec![];
    let base_dirs = BaseDirs::new();
    let base_dir = match base_dirs {
        Some(base_dir) => base_dir.home_dir().to_owned(),
        None => PathBuf::from("/tmp"),
    };

    for i in 0..drive_redundancy {
        let volume: Volume = orig_volumes.get(i).map(|v| v.to_owned()).unwrap_or(Volume {
            path: base_dir.join("Carbonado").join(format!("Volume_{i}")),
        });

        volumes.push(volume.to_owned());
    }

    for vol in volumes.iter() {
        create_dir_all(vol.path.join(SEGMENT_DIR))?;
        create_dir_all(vol.path.join(CATALOG_DIR))?;
    }

    let capacity = sys_cfg.capacity.unwrap_or(1_000);

    let config = SysCfg {
        http_port,
        private_key,
        drive_redundancy,
        volumes,
        capacity,
    };

    trace!("Write parsed config back out to config file");
    let toml = toml::to_string_pretty(&config)?;

    trace!("Overwrite existing file to preserve consistency");
    cfg_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&ENV_CFG.data_cfg_file)?;
    cfg_file.write_all(toml.as_bytes())?;
    cfg_file.flush()?;

    Ok(config)
}

pub static SYS_CFG: Lazy<SysCfg> =
    Lazy::new(|| init_sys_cfg().expect("Failed to initialize config"));
