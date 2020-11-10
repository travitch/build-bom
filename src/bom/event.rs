use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct TraceEvent<E> {
    pub pid : i32,
    pub evt : E
}

#[derive(Debug,Serialize,Deserialize,Clone,Hash,Eq,PartialEq,Ord,PartialOrd,Copy)]
pub struct EnvID(pub u32);

#[derive(Debug,Serialize,Deserialize)]
pub struct Environment {
    pub id : EnvID,
    pub bytes : Vec<u8>
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum EventType {
    Fork { old_pid : i32, new_pid : i32 },
    Exit { pid : i32, exit_code : i32 },
    Exec { command : String, args : Vec<String>, environment : EnvID, cwd : PathBuf },
    FailedExec { result : i32 },
    OpenFile { path : PathBuf, flags : u32, mode : u32 },
    OpenFileAt { at_dir : i32, path : PathBuf, flags : u32, mode : u32 },
    OpenFileReturn { result : i32 },
    CloseFile { fd : i32 }
}

/// FIXME: Track renames (and potentially copies)
#[derive (Debug,Serialize,Deserialize)]
pub enum RawEventType<E> {
    Fork { old_pid : i32, new_pid : i32 },
    Exit { pid : i32, exit_code : i32 },
    Exec { command : RawString, args : Vec<RawString>, cwd : PathBuf, environment : E },
    FailedExec { result : i32 },
    OpenFile { path : RawString, flags: u32, mode : u32 },
    OpenFileAt { at_dir : i32, path : RawString, flags : u32, mode : u32 },
    OpenFileReturn { result : i32 },
    CloseFile { fd : i32 }
}

#[derive(Debug,Clone,Hash,Eq,Ord,PartialEq,PartialOrd,Serialize,Deserialize)]
pub enum RawString {
    SafeString(String),
    BinaryString(Vec<u8>),
    UnreadableMemoryAddress(u64)
}
