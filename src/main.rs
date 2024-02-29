use clap::Parser;

use chat_demo::{cli::Cli, client, server};

fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Cli::parse();
    log::debug!("Parsed CLI args:\n{args:#?}");
    match args {
        Cli::Client(args) => client::Client::run(args)?,
        Cli::Server(args) => server::run(args)?,
    };
    Ok(())
}

fn main() {
    if let Err(err) = try_main() {
        log::error!("Failed to launch demo chat: {err}");
        std::process::exit(1);
    }
}
