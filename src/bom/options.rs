use structopt::StructOpt;
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ToString;

#[derive(Debug,StructOpt)]
#[structopt(version = "1.0", author = "Tristan Ravitch")]
pub struct Options {
    #[structopt(subcommand)]
    pub subcommand : Subcommand
}

#[derive(Debug,StructOpt)]
pub enum Subcommand {
    Trace(TraceOptions),
    Normalize(NormalizeOptions)
}

#[derive(Debug,StructOpt)]
#[structopt(help="A normalization pass over traced build actions")]
pub struct NormalizeOptions {
    #[structopt(short = "i", long = "input", help = "A file containing raw traced build actions")]
    pub input : PathBuf,
    #[structopt(short = "o", long = "output", help = "The file to save normalized traced build actions to")]
    pub output : PathBuf,
    #[structopt(default_value, short = "s", long = "strategy", help = "The translation strategy for strings")]
    pub strategy : StringNormalizeStrategy
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
