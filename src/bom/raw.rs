use serde::{Serialize, Deserialize};

// We use this type to represent strings read from tracees (foreign processes)
//
// We expect the vast majority of these to be valid utf8 strings; however,
// there is no requirement that they are. In cases where we cannot decode them
// as utf8, we will simply preserve the (0-terminated) list of bytes.
#[derive(Debug,Clone,Hash,Eq,Ord,PartialEq,PartialOrd,Serialize,Deserialize)]
pub enum RawString {
    SafeString(String),
    BinaryString(Vec<u8>),
    UnreadableMemoryAddress(u64)
}

/// We have this "raw" representation of events because we don't want to
/// interrupt the real build process in the case where an argument is invalid in
/// a way that prevents us from properly decoding it.
///
/// We'll convert them to more structured events in the offline phases of the
/// analysis (see event.rs).
#[derive(Debug,Serialize,Deserialize)]
pub struct RawTraceEvent {
    pub pid : i32,
    pub evt : RawEventType
}

#[derive (Debug,Serialize,Deserialize)]
pub enum RawEventType {
    Fork { old_pid : i32, new_pid : i32 },
    Exec { command : RawString, args : Vec<RawString> },
    FailedExec { result : i32 },
    // FIXME: Don't track this - pull it out of /proc instead for each exec
    ChangeWorkingDirectory { new_cwd : RawString },
    OpenFile { path : RawString, flags: u32, mode : u32 },
    OpenFileAt { at_dir : i32, path : RawString, flags : u32, mode : u32 },
    OpenFileReturn { result : i32 },
    CloseFile { fd : i32 }
}
