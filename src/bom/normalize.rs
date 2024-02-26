use log::info;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use serde_json;

use crate::bom::options::{NormalizeOptions,StringNormalizeStrategy,Normalization};
use crate::bom::event::{EventType,TraceEvent,EnvID,Environment,RawEventType,RawString};
use crate::bom::versioning::{Header,DataFormat,CURRENT_VERSION};
use crate::bom::loader::{load_trace,SomeLoadedTrace};

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
    let loaded_trace = load_trace(&normalize_opts.input)?;

    match loaded_trace {
        SomeLoadedTrace::RawTrace(raw_trace) => {
            let mut normalizations = Vec::new();
            if normalize_opts.all_normalizations {
                normalizations.push(Normalization::ElideClose);
                normalizations.push(Normalization::ElideFailedOpen);
                normalizations.push(Normalization::ElideFailedExec);
            } else {
                for n in &normalize_opts.normalize {
                    normalizations.push(*n);
                }
            }

            let grouped_trace_events = normalize(&normalize_opts.strategy, &normalizations, raw_trace.events.as_slice())?;
            let out_file = std::fs::File::create(&normalize_opts.output)?;
            let mut buf_out = std::io::BufWriter::new(out_file);

            // Write out our updated header
            let header = Header { version : CURRENT_VERSION, data_format : DataFormat::Normalized, root_task : raw_trace.root_task };
            serde_json::to_writer(&mut buf_out, &header)?;
            buf_out.write("\n".as_bytes())?;

            // Write out all of the collected (uniquified) environments
            for (envid, env) in raw_trace.environments {
                let e = Environment { id : envid, bytes : env };
                serde_json::to_writer(&mut buf_out, &e)?;
                buf_out.write("\n".as_bytes())?;
            }

            // Write out all of our collected events (which refer to the environments above)
            for (_task_id, trace_events) in grouped_trace_events {
                for trace_event in trace_events {
                    serde_json::to_writer(&mut buf_out, &trace_event)?;
                    buf_out.write("\n".as_bytes())?;
                }
            }

        }
        SomeLoadedTrace::NormalizedTrace(_) => {
            info!("Input file {:?} is already normalized", &normalize_opts.input);
        }
    }


    Ok(())
}

/// Normalize a sequence of raw events
///
/// It uses the given normalization strategy when interpreting strings that are
/// not valid UTF-8.
///
/// The normalized form of the event trace includes tracking environments on the
/// side to increase sharing; the returned `HashMap` maps environments to their
/// unique identifiers.
pub fn normalize(strategy : &StringNormalizeStrategy, normalizations : &[Normalization], raw_events : &[TraceEvent<RawEventType<EnvID>>]) -> Result<HashMap<i32, Vec<TraceEvent<EventType>>>, NormalizationError> {
    let events = raw_events.iter().try_fold(Vec::new(), |mut acc, re| {
        let ev = raw_to_event(strategy, &re)?;
        acc.push(ev);
        Ok(acc)
    })?;

    // Here, we have a linear sequence of events that have been parsed into a
    // decent form (with real Rust strings).
    //
    // Next, we need to group events by *task* (i.e., build step/event).
    //
    // FIXME: In the long term, we need to use surrogate IDs here because PIDs
    // can be reused (even though it takes a while).
    //
    // We need to group by task because, in a parallel build, related events
    // (e.g., exec / failed exec) might not be contiguous because they can be
    // interleaved with the events from multiple processes.
    //
    // We will scan through the linear sequence of events and sort them into
    // per-task Vecs (which can be normalized independently)
    let mut groups = HashMap::new();
    for event in events {
        match groups.get(&event.pid) {
            Some(_) => {}
            None => {
                groups.insert(event.pid, Vec::new());
            }
        }

        let task_vec = groups.get_mut(&event.pid).unwrap();
        task_vec.push(event);
    }

    let mut normed_groups = HashMap::new();
    for (event_id, event_trace) in &groups {
        let normed = apply_normalizations(&normalizations, &event_trace);
        normed_groups.insert(*event_id, normed);
    }

    Ok(normed_groups)
}

fn apply_normalizations<'a>(normalizations : &'a [Normalization], event_trace : &'a [TraceEvent<EventType>]) -> Vec<TraceEvent<EventType>> {
    let mut res = Vec::new();
    let initial_it = Box::new(event_trace.iter()) as Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a>;
    let mut it = normalizations.iter().fold(initial_it, add_normalization_iterator);
    while let Some(evt_ref) = it.next() {
        res.push(evt_ref.clone());
    }

    res
}

fn add_normalization_iterator<'a>(iter : Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a>, norm : &Normalization) -> Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a> {
    match norm {
        Normalization::ElideClose => { Box::new(iter.filter(|evt| !is_close_event(evt))) }
        Normalization::ElideFailedOpen => {
            let piter = iter.peekable() as std::iter::Peekable<Box<dyn Iterator<Item=&'a TraceEvent<EventType>>>>;
            Box::new(elide_failed_open(piter))
        }
        Normalization::ElideFailedExec => {
            let piter = iter.peekable() as std::iter::Peekable<Box<dyn Iterator<Item=&'a TraceEvent<EventType>>>>;
            Box::new(elide_failed_exec(piter))
        }
    }
}

struct ElideFailedOpen<'a> {
    base : std::iter::Peekable<Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a>>
}

impl <'a> Iterator for ElideFailedOpen<'a> {
    type Item = &'a TraceEvent<EventType>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // We return this item *if*:
            //
            // 1. It is not an open, or
            // 2. The next item is not an open failure
            let item = self.base.next();
            match item {
                None => { return None }
                Some(TraceEvent { evt : EventType::OpenFileAt { .. }, .. }) |
                Some(TraceEvent { evt : EventType::OpenFile { .. }, .. }) => {
                    let successor = self.base.peek();
                    match successor {
                        Some(TraceEvent { evt : EventType::OpenFileReturn { result }, ..}) => {
                            if *result < 0 {
                                // Skip the next item because it is just the failure
                                self.base.next();
                                // Don't return so we take another loop
                                // iteration and find the next item
                            } else {
                                return item
                            }
                        }
                        _ => { return item }
                    }
                }
                Some(_) => { return item }
            }
        }
    }
}

fn elide_failed_open<'a>(it : std::iter::Peekable<Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a>>) -> ElideFailedOpen<'a> {
    ElideFailedOpen { base : it }
}

struct ElideFailedExec<'a> {
    base : std::iter::Peekable<Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a>>
}

impl <'a> Iterator for ElideFailedExec<'a> {
    type Item = &'a TraceEvent<EventType>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // We return this item *if*:
            //
            // 1. It is not an exec, or
            // 2. The next item is not an exec failure
            let item = self.base.next();
            match item {
                None => { return None }
                Some(TraceEvent { evt : EventType::Exec { .. }, .. }) => {
                    let successor = self.base.peek();
                    match successor {
                        Some(TraceEvent { evt : EventType::FailedExec { .. }, ..}) => {
                            // Skip the next item because it is just the failure
                            // (and also try another loop iteration)
                            self.base.next();
                        }
                        _ => { return item }
                    }
                }
                Some(_) => { return item }
            }
        }
    }
}

fn elide_failed_exec<'a>(it : std::iter::Peekable<Box<dyn Iterator<Item=&'a TraceEvent<EventType>> + 'a>>) -> ElideFailedExec<'a> {
    ElideFailedExec { base : it }
}


fn is_close_event(trace_event : &TraceEvent<EventType>) -> bool {
    match trace_event.evt {
        EventType::CloseFile { .. } => { true }
        _ => { false }
    }
}

#[derive(thiserror::Error,Debug)]
pub enum NormalizationError {
    #[error("Non-UTF8 string found in event '{0:?}'")]
    NonUTF8String(Vec<u8>),
    #[error("Invalid memory address found in event '{0:?}'")]
    InvalidMemoryAddress(u64)
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

fn raw_to_event(strategy : &StringNormalizeStrategy, raw : &TraceEvent<RawEventType<EnvID>>) -> Result<TraceEvent<EventType>, NormalizationError> {
    let new_event = match &raw.evt {
        RawEventType::Exit { pid, exit_code } => { Ok(EventType::Exit { pid : *pid, exit_code : *exit_code }) }
        RawEventType::CloseFile { fd } => { Ok(EventType::CloseFile { fd : *fd }) }
        RawEventType::OpenFileReturn { result } => { Ok(EventType::OpenFileReturn { result : *result }) }
        RawEventType::Fork { old_pid, new_pid } => { Ok(EventType::Fork { old_pid : *old_pid, new_pid : *new_pid }) }
        RawEventType::FailedExec { result } => { Ok(EventType::FailedExec { result : *result }) }
        RawEventType::Rename { from, to } => {
            let from_str = normalize_string(strategy, &from)?;
            let to_str = normalize_string(strategy, &to)?;
            Ok(EventType::Rename { from : from_str, to : to_str })
        }
        RawEventType::RenameAt { from, to, from_dir, to_dir } => {
            let from_str = normalize_string(strategy, &from)?;
            let to_str = normalize_string(strategy, &to)?;
            Ok(EventType::RenameAt { from : from_str, to : to_str, from_dir : *from_dir, to_dir : *to_dir })
        }
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
            Ok(EventType::Exec { command : command_str, args : arg_strs, cwd : cwd.clone(), environment : *environment })
        }
    }?;

    Ok(TraceEvent { pid : raw.pid, evt : new_event })
}
