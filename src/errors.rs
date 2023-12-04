use thiserror::Error;

#[derive(Error, Debug)]
pub enum CarbonadoNodeError {
    /// Invalid magic number
    #[error("File header lacks Carbonado magic number and may not be a proper Carbonado file. Magic number found was {0}.")]
    CatInvalidMagicNumber(String),
}
