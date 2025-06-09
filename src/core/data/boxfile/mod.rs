mod boxfile;
mod header;

pub use boxfile::Boxfile;
pub use header::*;

mod info {
    //! Constants for the header: current file format version and unique file
    //! identifier (magic)
    /// Unique identifier for the `boxfile` file format
    pub const MAGIC: [u8; 3] = [b'B', b'O', b'X'];
    /// The current version of the `boxfile` format being used for backwards compatibility
    pub const CURRENT_VERSION: u8 = 1;
}