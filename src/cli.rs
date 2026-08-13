use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "codejourney",
    version,
    about = "Git repository analytics & security scanner"
)]
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
        /// Export report to JSON at the given file path
        #[arg(long)]
        json: Option<String>,
        /// Export report to Markdown at the given file path (suitable for PR comments)
        #[arg(long)]
        markdown: Option<String>,
        /// Export dependency graph as DOT file (convert to SVG with: dot -Tsvg -o deps.svg deps.dot)
        #[arg(long)]
        dot: Option<String>,
        /// Store scan results in SQLite history database at the given path
        #[arg(long)]
        history_db: Option<String>,
        /// Show trend charts from historical scan data
        #[arg(long)]
        show_trends: bool,
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
