use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "codejourney", about = "Git repository analytics & security scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run comprehensive git analytics and security audit
    Scan {
        /// Path to the git repository (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        path: String,
        /// Only run security audit
        #[arg(long)]
        security_only: bool,
        /// Only run analytics
        #[arg(long)]
        analytics_only: bool,
        /// Export report to PDF at the given file path
        #[arg(long)]
        pdf: Option<String>,
        /// Export report to HTML at the given file path
        #[arg(long)]
        html: Option<String>,
        /// Comma-separated list of directories to ignore during scanning
        #[arg(long, value_delimiter = ',')]
        ignore_dirs: Vec<String>,
    },
    /// Start an HTTP server exposing git operations
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
}
