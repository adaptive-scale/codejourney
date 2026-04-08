use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "codejourney", about = "Native git operations in Rust")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new git repository
    Init {
        /// Path to initialize (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,
    },
    /// Show repository status
    Status,
    /// Add files to the index
    Add {
        /// Files to add (use "." for all)
        files: Vec<String>,
    },
    /// Create a commit
    Commit {
        /// Commit message
        #[arg(short, long)]
        message: String,
    },
    /// Show commit log
    Log {
        /// Number of commits to show
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
    /// Create a new branch
    Branch {
        /// Branch name
        name: String,
    },
    /// Checkout a branch
    Checkout {
        /// Branch name
        name: String,
    },
    /// Show diff of working directory changes
    Diff,
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
    },
    /// Start an HTTP server exposing git operations
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
}
