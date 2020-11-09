use std::collections::HashMap;
use std::path::PathBuf;
use std::io::BufRead;
use serde_json;
use crate::bom::event::{EnvID,Environment,TraceEvent};
use crate::bom::raw::RawTraceEvent;
use crate::bom::versioning::{CURRENT_VERSION,DataFormat,Header};

pub enum LoadedTrace {
    RawTrace(Vec<RawTraceEvent>),
    NormalizedTrace(HashMap<EnvID, Vec<u8>>, Vec<TraceEvent>)
}

#[derive(thiserror::Error,Debug)]
pub enum LoadError {
    #[error("File missing or empty: '{0:?}'")]
    EmptyFile(PathBuf),
    #[error("Trace metadata version mismatch (got {0:?} but expected {1:?})")]
    VersionMismatch(u32, u32),
    #[error("Version header missing in file '{0:?}'")]
    MissingHeader(PathBuf)
}

pub fn load_trace(file_path : &PathBuf) -> anyhow::Result<LoadedTrace> {
    let f = std::fs::File::open(file_path)?;
    let reader = std::io::BufReader::new(f);
    let mut line_it = reader.lines();
    let first_line = line_it.next();
    let data_format = check_version(file_path, first_line)?;
    match data_format {
        DataFormat::Raw => {
            let trace = load_raw_trace(line_it)?;
            Ok(LoadedTrace::RawTrace(trace))
        }
        DataFormat::Normalized => {
            let (env, trace) = load_normalized_trace(line_it)?;
            Ok(LoadedTrace::NormalizedTrace(env, trace))
        }
    }
}

fn load_normalized_trace(it : std::io::Lines<std::io::BufReader<std::fs::File>>) -> anyhow::Result<(HashMap<EnvID,Vec<u8>>, Vec<TraceEvent>)> {
    let mut env = HashMap::new();
    let mut trace = Vec::new();
    for line in it {
        let data = line.unwrap();
        match serde_json::from_str::<TraceEvent>(&data) {
            Ok(trace_evt) => {
                trace.push(trace_evt)
            }
            Err(_) => {
                let env_entry = serde_json::from_str::<Environment>(&data)?;
                env.insert(env_entry.id, env_entry.bytes);
            }
        }
    }
    Ok((env, trace))
}

fn load_raw_trace(it : std::io::Lines<std::io::BufReader<std::fs::File>>) -> anyhow::Result<Vec<RawTraceEvent>> {
    let mut trace = Vec::new();
    for line in it {
        let data = line.unwrap();
        let raw_event = serde_json::from_str::<RawTraceEvent>(&data)?;
        trace.push(raw_event);
    }
    Ok(trace)
}

/// Ensure that the file version is what we expect, and that the data is in fact raw
fn check_version(file_path : &PathBuf, first_line : Option<Result<String, std::io::Error>>) -> anyhow::Result<DataFormat> {
    match first_line {
        None => { Err(anyhow::Error::new(LoadError::EmptyFile(file_path.clone()))) }
        Some(data) => {
            match serde_json::from_str::<Header>(&data.unwrap()) {
                Err(_) => { Err(anyhow::Error::new(LoadError::MissingHeader(file_path.clone()))) }
                Ok(header) => {
                    if header.version != CURRENT_VERSION {
                        Err(anyhow::Error::new(LoadError::VersionMismatch(header.version, CURRENT_VERSION)))
                    } else {
                        Ok(header.data_format)
                    }
                }
            }
        }
    }
}
