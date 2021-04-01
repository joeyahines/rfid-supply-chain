use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "RFID Supply Chain",
    about = "Implementation of a block chain for IC supply chains"
)]
pub struct Args {
    #[structopt(subcommand)]
    pub mode: Mode,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, StructOpt)]
pub enum Mode {
    DistributorServer(DistributorServerArgs),
    CentralServer(CentralServerArgs),
}

#[derive(Debug, StructOpt)]
pub struct DistributorServerArgs {
    pub key_id: u32,
    #[structopt(parse(from_os_str))]
    pub private_key: PathBuf,
    pub central_server_addr: String,
}

#[derive(Debug, StructOpt)]
pub struct CentralServerArgs {
    #[structopt(
        short = "d",
        long = "database",
        default_value = "db",
        parse(from_os_str)
    )]
    pub database_path: PathBuf,
    pub private_key: PathBuf,
    #[structopt(short = "i", long = "import", parse(from_os_str))]
    pub import_path: Option<PathBuf>,
}
