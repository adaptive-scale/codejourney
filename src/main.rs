mod analytics;
mod cli;
mod display;
mod git;
mod scan;
mod security;
mod server;

use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Init { path } => git::init(path),
        Commands::Status => git::status(),
        Commands::Add { files } => git::add(files),
        Commands::Commit { message } => git::commit(message),
        Commands::Log { count } => git::log(*count),
        Commands::Branch { name } => git::branch(name),
        Commands::Checkout { name } => git::checkout(name),
        Commands::Diff => git::diff(),
        Commands::Scan {
            path,
            security_only,
            analytics_only,
        } => scan::run(path, *security_only, *analytics_only),
        Commands::Serve { port } => {
            server::serve(*port).await;
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
