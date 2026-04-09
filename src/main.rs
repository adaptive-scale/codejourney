mod analytics;
mod autofix;
mod cli;
mod complexity;
mod depgraph;
mod display;
mod history;
mod license;
mod pdf;
mod report_html;
mod report_json;
mod report_markdown;
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
            json,
            markdown,
            dot,
            history_db,
            show_trends,
            ignore_dirs,
        } => scan::run(
            path,
            *security_only,
            *analytics_only,
            pdf.as_deref(),
            html.as_deref(),
            json.as_deref(),
            markdown.as_deref(),
            dot.as_deref(),
            history_db.as_deref(),
            *show_trends,
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
