use std::mem::{size_of};
use std::path::PathBuf;
use std::io::Read;

use byteorder::{NativeEndian, ByteOrder};
use pete::{Tracee};

use crate::bom::event::RawString;

// Read a NUL-terminated string from the given address in the tracee
//
// It would be nice to have a fast path that just tries to read a large string
// all at once; if that fails due to an IO error, do it one u8 at a time.  If
// the large chunk contains no NULs, try to just scan a few bytes at a time.
pub fn read_str_from(tracee: &mut Tracee, addr: u64) -> RawString {
    // We are going to try to read a large memory range (1 page). The
    // `read_memory` function returns short reads if it has to.
    match tracee.read_memory(addr, 4096) {
        Err(_) => { RawString::UnreadableMemoryAddress(addr) }
        Ok(mut bytes) => {
            let mut non_zero_len = 0;
            while non_zero_len < bytes.len() {
                if bytes[non_zero_len] == 0 {
                    break;
                } else {
                    non_zero_len += 1;
                }
            }
            // Shrink the byte buffer down to contain no NUL bytes
            bytes.resize(non_zero_len, 0);
            let orig_bytes = bytes.clone();
            match String::from_utf8(bytes) {
                Ok(s) => { RawString::SafeString(s) }
                Err(_) => { RawString::BinaryString(orig_bytes) }
            }
        }
    }
}

// Read a NULL-terminated list of strings from the given address
pub fn read_str_list_from(tracee: &mut Tracee, addr: u64) -> Vec<RawString> {
    let ptr_size = size_of::<usize>();
    let mut res = Vec::new();
    let mut cur_addr = addr;
    loop {
        match tracee.read_memory(cur_addr, ptr_size) {
            Err(_) => { break }
            Ok(bytes) => {
                let ptr = if ptr_size == 4 {
                    NativeEndian::read_u32(bytes.as_slice()) as u64
                } else {
                    NativeEndian::read_u64(bytes.as_slice())
                };
                if ptr == 0 {
                    break
                } else {
                    res.push(read_str_from(tracee, ptr));
                    cur_addr = cur_addr + ptr_size as u64;
                }
            }
        }
    }

    res
}

/// Read the environment for the paused process
///
/// This consults /proc, since there is no easy way to get the information via
/// ptrace.
///
/// In principle, this should not be able to fail...
///
/// FIXME: Consider only collecting some relevant variables here
pub fn read_environment(tracee : &Tracee) -> anyhow::Result<Vec<u8>> {
    let tid = tracee.pid.as_raw() as u32;
    let env_path = format!("/proc/{}/environ", tid);
    let mut env_file = std::fs::File::open(env_path)?;
    let mut env = Vec::new();
    let _num_bytes = env_file.read_to_end(&mut env)?;
    Ok(env)
}

/// Read the current working directory of the paused process
///
/// This consults /proc, as there is no easy way to get this information
/// directly with ptrace.
///
/// In principle, this should not be able to fail (though it isn't clear to me
/// that it is impossible to run into encoding issues with `PathBuf`.
pub fn read_cwd(tracee : &Tracee) -> anyhow::Result<PathBuf> {
    let tid = tracee.pid.as_raw() as u32;
    let cwd_link_path = format!("/proc/{}/cwd", tid);
    let link_target = std::fs::read_link(cwd_link_path)?;
    Ok(link_target)
}
