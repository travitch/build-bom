use chainsop::Executor;
use regex::Regex;
use structopt::StructOpt;
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ToString;

#[derive(Debug,StructOpt)]
#[structopt(version = "1.0", author = "Tristan Ravitch",
            about="Utility to extract LLVM bitcode from a build process.\n\nLogging is controlled with various -v options or via the RUST_LOG/RUST_log_style as described in https://docs.rs/env_logger documentation."
)]
pub struct Options {
    #[structopt(subcommand)]
    pub subcommand : Subcommand
}

#[derive(Debug,StructOpt)]
pub enum Subcommand {
    Trace(TraceOptions),
    Normalize(NormalizeOptions),
    GenerateBitcode(BitcodeOptions),
    ExtractBitcode(ExtractOptions)
}

#[derive(Debug,StructOpt)]
pub struct ExtractOptions {
    #[structopt(help="The file to extract bitcode from")]
    pub input : PathBuf,
    #[structopt(short="o", long="output", help="The file to save the resulting bitcode file to")]
    pub output : PathBuf,
    #[structopt(long="llvm-link-path", help="The path to the llvm-link tool (possibly version suffixed)")]
    pub llvm_link_path : Option<String>,
    #[structopt(short="v", long="verbose", help="Generate verbose output.  Twice for additional verbosity.")]
    pub verbose : Vec<bool>,
}

#[derive(Debug,StructOpt)]
pub struct BitcodeOptions {
    #[structopt(long="clang", help="Name of the clang binary to use to generate bitcode (default: `clang`)")]
    pub clang_path : Option<PathBuf>,
    #[structopt(short="b", long="bc-out", help="Directory to place LLVM bitcode (bc) output data.  The default is to place it next to the object file, but it must be accessible by a subsequent Extract operation and some build tools build in a temporary directory that is disposed of at the end of the build (e.g. CMake) ")]
    pub bcout_path : Option<PathBuf>,
    #[structopt(short="v", long="verbose", help="Generate verbose output. Twice for additional verbosity.")]
    pub verbose : Vec<bool>,
    #[structopt(long="suppress-automatic-debug", help="Prevent `build-bom` from automatically injecting flags to generate debug information in bitcode files")]
    pub suppress_automatic_debug : bool,
    #[structopt(long="inject-argument", help="Have `build-bom` inject the given argument into the argument list when generating bitcode")]
    pub inject_arguments : Vec<String>,
    #[structopt(long="remove-argument", help="Have `build-bom` remove arguments matching the given regular expression when generating bitcode")]
    pub remove_arguments : Vec<Regex>,
    #[structopt(last = true, help="The build command to run")]
    pub command : Vec<String>,
    #[structopt(long="strict", help="Generate bitcode that strictly adheres to the target object code (optimization levels, target architecture, etc.).")]
    pub strict : bool,

    // The following is for testing only: if set, it will fail if any portion of
    // the generate_bitcode operations fail.  In normal operation, this is false
    // which means that the build-bom operation proceeds as long as the main
    // compilation attempt is successful (i.e. any errors during bitcode
    // generation are logged and counted but do not cause an overall failure
    // result).
    #[structopt(skip)]
    pub any_fail : bool
}

#[derive(Debug,StructOpt)]
#[structopt(help="A normalization pass over traced build actions")]
pub struct NormalizeOptions {
    #[structopt(help = "A file containing raw traced build actions")]
    pub input : PathBuf,
    #[structopt(short = "o", long = "output", help = "The file to save normalized traced build actions to")]
    pub output : PathBuf,
    #[structopt(default_value, short = "s", long = "strategy", help = "The translation strategy for strings")]
    pub strategy : StringNormalizeStrategy,
    #[structopt(short = "n", long = "normalize", help = "Enable the named normalization strategy")]
    pub normalize : Vec<Normalization>,
    #[structopt(short = "a", long = "all", help = "Enable all normalization passes")]
    pub all_normalizations : bool
}

#[derive(Debug,StructOpt,Hash,Eq,PartialEq,PartialOrd,Ord,Copy,Clone)]
pub enum Normalization {
    ElideClose,
    ElideFailedOpen,
    ElideFailedExec
}

#[derive(Debug)]
pub struct InvalidNormalization(String);

impl FromStr for Normalization {
    type Err = InvalidNormalization;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "elide-close" => { Ok(Normalization::ElideClose) }
            "elide-failed-open" => { Ok(Normalization::ElideFailedOpen) }
            "elide-failed-exec" => { Ok(Normalization::ElideFailedExec) }
            err => { Err(InvalidNormalization(err.to_owned())) }
        }
    }
}

impl ToString for Normalization {
    fn to_string(&self) -> String {
        match self {
            Normalization::ElideClose => { "elide-close".to_owned() }
            Normalization::ElideFailedOpen => { "elide-failed-open".to_owned() }
            Normalization::ElideFailedExec => { "elide-failed-exec".to_owned() }
        }
    }
}

#[derive(Debug,StructOpt)]
#[structopt(help="Trace the actions of a build command")]
pub struct TraceOptions {
    #[structopt(short = "o", long = "output", help = "The file to save traced build actions to")]
    pub output : PathBuf,
    #[structopt(last = true)]
    pub command : Vec<String>
}

#[derive(Debug)]
pub struct InvalidStrategy(String);

impl FromStr for StringNormalizeStrategy {
    type Err = InvalidStrategy;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => { Ok(StringNormalizeStrategy::Strict) }
            "lenient" => { Ok(StringNormalizeStrategy::Lenient) }
            "Strict" => { Ok(StringNormalizeStrategy::Strict) }
            "Lenient" => { Ok(StringNormalizeStrategy::Lenient) }
            err => { Err(InvalidStrategy(err.to_owned())) }
        }
    }
}

impl ToString for StringNormalizeStrategy {
    fn to_string(&self) -> String {
        match self {
            StringNormalizeStrategy::Strict => { "Strict".to_owned() }
            StringNormalizeStrategy::Lenient => { "Lenient".to_owned() }
        }
    }
}

impl ToString for InvalidStrategy {
    fn to_string(&self) -> String {
        match self {
            InvalidStrategy(s) => { format!("InvalidStrategy({})", s) }
        }
    }
}

impl ToString for InvalidNormalization {
    fn to_string(&self) -> String {
        match self {
            InvalidNormalization(s) => { format!("InvalidNormalization({})", s) }
        }
    }
}

#[derive(Debug,StructOpt)]
pub enum StringNormalizeStrategy {
    #[structopt(help="Require no encoding errors when converting strings from raw form to their Rust forms")]
    Strict,
    #[structopt(help="Replace invalid utf-8 encoded data with defaults; this can make builds non-replayable")]
    Lenient
}

impl Default for StringNormalizeStrategy {
    fn default () -> Self { StringNormalizeStrategy ::Strict }
}

pub fn get_executor(verbosity: usize) -> Executor {
    match verbosity {
        0 => Executor::NormalRun,
        1 => Executor::NormalWithLabel,
        _ => Executor::NormalWithEcho,
    }
}
