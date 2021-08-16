use structopt::StructOpt;

use bom;
use bom::bom::options::Options;

fn main() -> anyhow::Result<()> {
    let opt = Options::from_args();
    let ec = bom::run_bom(opt)?;
    std::process::exit(ec);
}



