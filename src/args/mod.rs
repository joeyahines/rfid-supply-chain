use structopt::StructOpt;
use std::path::{PathBuf};

#[derive(Debug, StructOpt)]
#[structopt(name = "RFID Supply Chain", about = "Implementation of a block chain for IC supply chains")]
pub struct Args {
    #[structopt(subcommand)]
    pub mode: Mode,
    pub address: String,
    pub port: u16,
    #[structopt(short = "d", long = "database", default_value = "db", parse(from_os_str))]
    pub database_path: PathBuf,
}

#[derive(Debug, StructOpt)]
pub enum Mode {
    DistributorServer,
    CentralServer
}