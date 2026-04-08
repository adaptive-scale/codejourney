mod analytics;
mod cli;
mod complexity;
mod display;
mod license;
mod pdf;
mod report_html;
mod sast;
mod scan;
mod sca;
mod security;
mod server;

use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Scan {
            path,
            security_only,
            analytics_only,
            pdf,
            html,
            ignore_dirs,
        } => scan::run(
            path,
            *security_only,
            *analytics_only,
            pdf.as_deref(),
            html.as_deref(),
            ignore_dirs,
        ),
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
