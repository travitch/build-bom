use chainsop::Executor;
use regex::Regex;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ToString;

#[derive(Debug,Parser)]
#[command(version, about)]
#[command(after_long_help="Logging is controlled with various -v options or via the RUST_LOG/RUST_LOG_STYLE\nas described in https://docs.rs/env_logger documentation.")]
pub struct Options {
    #[command(subcommand)]
    pub subcommand : BbCommand
}

#[derive(Debug,Subcommand)]
pub enum BbCommand {
    /// Trace the actions of a build command
    #[command(display_order=3)]
    Trace(TraceOptions),
    /// A normalization pass over traced build actions
    #[command(display_order=2)]
    Normalize(NormalizeOptions),
    /// Generate bitcode into build outputs during build tool run
    #[command(display_order=0)]
    GenerateBitcode(BitcodeOptions),
    /// Extract bitcode from build outputs
    #[command(display_order=1)]
    ExtractBitcode(ExtractOptions)
}

#[derive(Debug,Parser)]
pub struct ExtractOptions {
    /// The file to extract the generated bitcode from
    pub input : PathBuf,
    /// Output bitcode file
    #[arg(short, long)]
    pub output : PathBuf,
    /// The path to the llvm-link tool (possibly version suffixed)
    #[arg(long="llvm-link", value_hint=clap::ValueHint::FilePath)]
    pub llvm_link_path : Option<PathBuf>,
    /// The path to the objcopy tool (possibly version suffixed)
    #[arg(long="objcopy")]
    pub objcopy_path : Option<PathBuf>,
    /// Generate verbose output.  Twice for additional verbosity.
    #[arg(short, long, action=clap::ArgAction::Count)]
    pub verbose : u8,
}

#[derive(Clone,Debug,Parser)]
pub struct BitcodeOptions {
    /// Name of the clang binary to use to generate bitcode (default: `clang`)
    #[arg(long="clang")]
    pub clang_path : Option<PathBuf>,
    /// The path to the objcopy tool (default: `objcopy`)
    #[arg(long="objcopy")]
    pub objcopy_path : Option<PathBuf>,
    /// Generate bitcode that strictly adheres to the target object code
    /// (optimization levels, target architecture, etc.)
    #[arg(long)]
    pub strict : bool,
    /// Generate verbose output.  Twice for additional verbosity.
    #[arg(short, long, action=clap::ArgAction::Count)]
    pub verbose : u8,
    /// Prevent `build-bom` from automatically injecting flags to generate debug
    /// information in bitcode files
    #[arg(long="suppress-automatic-debug")]
    pub suppress_automatic_debug : bool,
    /// Inject the given argument into the clang argument list when generating bitcode (e.g. --inject-argument=-march=i386)
    #[arg(long="inject-argument")]
    pub inject_arguments : Vec<String>,
    /// Remove clang arguments matching the given regular expression when generating bitcode
    #[arg(long="remove-argument")]
    pub remove_arguments : Vec<Regex>,
    /// Pre-process with native compiler before generating bitcode.  This can be helpful for customized native compilers or cross-compilation.
    #[arg(long="preproc-native", short='E')]
    pub preproc_native : bool,
    /// Directory to place LLVM bitcode (bc) output data.
    ///
    /// The default is to place it next to the object file, but it must be
    /// accessible by a subsequent Extract operation and some build tools build
    /// in a temporary directory that is disposed of at the end of the build
    /// (e.g. CMake)
    #[arg(short='b', long="bc-out")]
    pub bcout_path : Option<PathBuf>,
    /// The build command to run
    #[arg(last = true)]
    pub command : Vec<String>,

    // The following is for testing only: if set, it will fail if any portion of
    // the generate_bitcode operations fail.  In normal operation, this is false
    // which means that the build-bom operation proceeds as long as the main
    // compilation attempt is successful (i.e. any errors during bitcode
    // generation are logged and counted but do not cause an overall failure
    // result).
    #[arg(skip)]
    pub any_fail : bool
}

#[derive(Debug,Parser)]
pub struct NormalizeOptions {
    /// File containing raw traced build actions
    pub input : PathBuf,
    /// The file to save normalized traced build actions to"
    #[arg(short, long)]
    pub output : PathBuf,
    /// The translation strategy for strings
    #[arg(short, long, default_value_t = StringNormalizeStrategy::Strict)]
    pub strategy : StringNormalizeStrategy,
    /// Enable the named normalization strategy
    #[arg(short, long)]
    pub normalize : Vec<Normalization>,
    /// Enable all normalization passes
    #[arg(short, long = "all")]
    pub all_normalizations : bool
}

#[derive(Debug,Parser,Hash,Eq,PartialEq,PartialOrd,Ord,Copy,Clone)]
#[derive(ValueEnum)]
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

#[derive(Debug,Parser)]
pub struct TraceOptions {
    /// The file to save traced build actions to
    #[arg(short, long)]
    pub output : PathBuf,
    /// The build command to perform
    #[arg(last = true)]
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

#[derive(Clone,Debug)]
#[derive(ValueEnum)]
pub enum StringNormalizeStrategy {
    /// Require no encoding errors when converting strings from raw form to their
    /// Rust forms
    Strict,
    /// Replace invalid utf-8 encoded data with defaults; this can make builds
    /// non-replayable
    Lenient
}

impl Default for StringNormalizeStrategy {
    fn default () -> Self { StringNormalizeStrategy ::Strict }
}

pub fn get_executor(verbosity: u8) -> Executor {
    match verbosity {
        0 => Executor::NormalRun,
        1 => Executor::NormalWithLabel,
        _ => Executor::NormalWithEcho,
    }
}
