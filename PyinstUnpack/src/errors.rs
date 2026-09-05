#[derive(Debug, PartialEq)]
pub enum PyInstallerError {
    FileNotFound,
    BufferTooSmall,
    InvalidPyinstallerArchive
}