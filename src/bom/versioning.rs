use serde::{Serialize,Deserialize};

/// This type is used to mark traces by their format and version so that the
/// loading code doesn't have to guess
#[derive(Debug,Serialize,Deserialize)]
pub enum DataFormat {
    Raw,
    Normalized
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Header {
    pub version : u32,
    pub data_format : DataFormat,
    pub root_task : i32
}

pub const CURRENT_VERSION : u32 = 0;
