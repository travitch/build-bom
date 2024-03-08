use clap::Parser;

use bom;
use bom::bom::options::Options;

fn main() -> anyhow::Result<()> {
    let opt = Options::parse();
    let ec = bom::run_bom(opt)?;
    std::process::exit(ec);
}



