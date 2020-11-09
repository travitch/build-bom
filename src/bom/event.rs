use std::path::{PathBuf};
use serde::{Serialize, Deserialize};

#[derive(Debug,Serialize,Deserialize)]
pub struct TraceEvent {
    pub pid : i32,
    pub evt : EventType
}

#[derive(Debug,Serialize,Deserialize)]
pub enum EventType {
    Fork { old_pid : i32, new_pid : i32 },
    Exec { command : String, args : Vec<String> },
    FailedExec { result : i32 },
    ChangeWorkingDirectory { new_cwd : PathBuf },
    OpenFile { path : PathBuf, flags : u32, mode : u32 },
    OpenFileAt { at_dir : i32, path : PathBuf, flags : u32, mode : u32 },
    OpenFileReturn { result : i32 },
    CloseFile { fd : i32 }
}
