use std::collections::HashMap;
use std::io::{BufReader,BufRead};
use std::io::Write;
use std::fs::File;
use std::path::PathBuf;
use serde_json;

use crate::bom::options::{NormalizeOptions,StringNormalizeStrategy};
use crate::bom::raw::{RawTraceEvent,RawString,RawEventType};
use crate::bom::event::{EventType,TraceEvent,EnvID,Environment};
use crate::bom::versioning::{Header,DataFormat,CURRENT_VERSION};

/// The command-line entry point for the normalization process
///
/// Normalization takes a sequence of raw trace events and simplifies them in a
/// number of ways. The simplification strategy is driven by the options passed
/// in, but broadly attempts to at least turn the unsafe strings from the raw
/// representation into simplified Rust strings.
///
/// This part of the process can fail if arguments in strings are not valid utf-8.
///
/// If that normalization pass fails, users will need to provide their own
/// processing pipeline for the raw data.
///
/// Strings will be converted; traced values that are intended to be binary data
/// will be retained as binary data without conversion.
pub fn normalize_entrypoint(normalize_opts : &NormalizeOptions) -> anyhow::Result<()> {
    let f = File::open(&normalize_opts.input)?;
    let reader = BufReader::new(f);
    let mut line_it = reader.lines();
    let first_line = line_it.next();
    check_version(&normalize_opts.input, first_line)?;

    let mut raw_events = Vec::new();
    for line in line_it {
        let data = line.unwrap();
        let raw_event = serde_json::from_str::<RawTraceEvent>(&data)?;
        raw_events.push(raw_event);
    }

    let (envs, trace_events) = normalize(&normalize_opts.strategy, raw_events.as_slice())?;
    let out_file = std::fs::File::create(&normalize_opts.output)?;
    let mut buf_out = std::io::BufWriter::new(out_file);

    // Write out our updated header
    let header = Header { version : CURRENT_VERSION, data_format : DataFormat::Normalized };
    serde_json::to_writer(&mut buf_out, &header)?;
    buf_out.write("\n".as_bytes())?;

    // Write out all of the collected (uniquified) environments
    for (env, envid) in envs {
        let e = Environment { id : envid, bytes : env };
        serde_json::to_writer(&mut buf_out, &e)?;
        buf_out.write("\n".as_bytes())?;
    }

    // Write out all of our collected events (which refer to the environments above)
    for trace_event in trace_events {
        serde_json::to_writer(&mut buf_out, &trace_event)?;
        buf_out.write("\n".as_bytes())?;
    }

    Ok(())
}

/// Ensure that the file version is what we expect, and that the data is in fact raw
fn check_version(file_path : &PathBuf, first_line : Option<Result<String, std::io::Error>>) -> anyhow::Result<()> {
    match first_line {
        None => { Err(anyhow::Error::new(NormalizationError::EmptyFile(file_path.clone()))) }
        Some(data) => {
            match serde_json::from_str::<Header>(&data.unwrap()) {
                Err(_) => { Err(anyhow::Error::new(NormalizationError::MissingHeader(file_path.clone()))) }
                Ok(header) => {
                    if header.version != CURRENT_VERSION {
                        Err(anyhow::Error::new(NormalizationError::VersionMismatch(header.version, CURRENT_VERSION)))
                    } else {
                        match header.data_format {
                            DataFormat::Raw => { Ok(()) }
                            DataFormat::Normalized => { Err(anyhow::Error::new(NormalizationError::ExpectedRawData(header.data_format))) }
                            DataFormat::Analyzed => { Err(anyhow::Error::new(NormalizationError::ExpectedRawData(header.data_format))) }
                        }
                    }
                }
            }
        }
    }
}

/// Normalize a sequence of raw events
///
/// It uses the given normalization strategy when interpreting strings that are
/// not valid UTF-8.
///
/// The normalized form of the event trace includes tracking environments on the
/// side to increase sharing; the returned `HashMap` maps environments to their
/// unique identifiers.
pub fn normalize(strategy : &StringNormalizeStrategy, raw_events : &[RawTraceEvent]) -> Result<(HashMap<Vec<u8>, EnvID>, Vec<TraceEvent>), NormalizationError> {
    let mut envs = HashMap::new();
    let events = raw_events.iter().try_fold(Vec::new(), |mut acc, re| {
        let ev = raw_to_event(strategy, &mut envs, &re)?;
        acc.push(ev);
        Ok(acc)
    })?;
    Ok((envs, events))
}

#[derive(thiserror::Error,Debug)]
pub enum NormalizationError {
    #[error("Non-UTF8 string found in event '{0:?}'")]
    NonUTF8String(Vec<u8>),
    #[error("Invalid memory address found in event '{0:?}'")]
    InvalidMemoryAddress(u64),
    #[error("File missing or empty: '{0:?}'")]
    EmptyFile(PathBuf),
    #[error("Expected raw-format trace data, but got '{0:?}'")]
    ExpectedRawData(DataFormat),
    #[error("Version header missing in file '{0:?}'")]
    MissingHeader(PathBuf),
    #[error("Trace metadata version mismatch (got {0:?} but expected {1:?})")]
    VersionMismatch(u32, u32)
}

fn normalize_string(strategy : &StringNormalizeStrategy, rs : &RawString) -> Result<String, NormalizationError> {
    match rs {
        RawString::SafeString(s) => { Ok(s.clone()) }
        RawString::UnreadableMemoryAddress(a) => { Err(NormalizationError::InvalidMemoryAddress(*a)) }
        RawString::BinaryString(bytes) => {
            match strategy {
                StringNormalizeStrategy::Strict => { Err(NormalizationError::NonUTF8String(bytes.clone())) }
                StringNormalizeStrategy::Lenient => { Ok(std::string::String::from_utf8_lossy(bytes).to_mut().to_string()) }
            }
        }
    }
}

fn raw_to_event(strategy : &StringNormalizeStrategy, envs : &mut HashMap<Vec<u8>, EnvID>, raw : &RawTraceEvent) -> Result<TraceEvent, NormalizationError> {
    let new_event = match &raw.evt {
        RawEventType::CloseFile { fd } => { Ok(EventType::CloseFile { fd : *fd }) }
        RawEventType::OpenFileReturn { result } => { Ok(EventType::OpenFileReturn { result : *result }) }
        RawEventType::Fork { old_pid, new_pid } => { Ok(EventType::Fork { old_pid : *old_pid, new_pid : *new_pid }) }
        RawEventType::FailedExec { result } => { Ok(EventType::FailedExec { result : *result }) }
        RawEventType::OpenFile { path, flags, mode } => {
            let path_str = normalize_string(strategy, &path)?;
            let p = PathBuf::from(path_str);
            Ok(EventType::OpenFile { path : p, flags : *flags, mode : *mode })
        }
        RawEventType::OpenFileAt { at_dir, path, flags, mode } => {
            let path_str = normalize_string(strategy, &path)?;
            let p = PathBuf::from(path_str);
            Ok(EventType::OpenFileAt { at_dir : *at_dir, path : p, flags : *flags, mode : *mode })
        }
        RawEventType::Exec { command, args, environment, cwd } => {
            let command_str = normalize_string(strategy, &command)?;
            let arg_strs = args.iter().try_fold(Vec::new(), |mut acc, rs| {
                let str = normalize_string(strategy, &rs)?;
                acc.push(str);
                Ok(acc)
            })?;
            let envid = match envs.get(environment) {
                Some(eid) => { eid.clone() }
                None => {
                    let eid = EnvID(envs.len() as u32);
                    envs.insert(environment.clone(), eid.clone());
                    eid
                }
            };
            Ok(EventType::Exec { command : command_str, args : arg_strs, cwd : cwd.clone(), environment : envid })
        }
    }?;

    Ok(TraceEvent { pid : raw.pid, evt : new_event })
}
