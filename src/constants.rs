pub const NODE_FORMAT: u8 = 15;
pub const SEGMENT_SIZE: usize = 1024 * 1024;

pub const SEGMENT_DIR: &str = "segments";
pub const CATALOG_DIR: &str = "catalogs";

/// "Magic number" used by the Carbonado-node file format. 12 bytes: "CAT_MAGICNO", and a version, 00, plus a newline character
pub const CAT_MAGICNO: [u8; 16] = *b"CARBONADONODE00\n";
