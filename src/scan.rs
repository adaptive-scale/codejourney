use git2::Repository;

use crate::{analytics, display, security};

pub fn run(path: &str, security_only: bool, analytics_only: bool) -> Result<(), git2::Error> {
    let repo = Repository::discover(path)?;

    println!("\x1b[1;37m");
    println!("   ██████╗ ██████╗ ██████╗ ███████╗     ██╗ ██████╗ ██╗   ██╗██████╗ ███╗   ██╗███████╗██╗   ██╗");
    println!("  ██╔════╝██╔═══██╗██╔══██╗██╔════╝     ██║██╔═══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝");
    println!("  ██║     ██║   ██║██║  ██║█████╗       ██║██║   ██║██║   ██║██████╔╝██╔██╗ ██║█████╗   ╚████╔╝ ");
    println!("  ██║     ██║   ██║██║  ██║██╔══╝  ██   ██║██║   ██║██║   ██║██╔══██╗██║╚██╗██║██╔══╝    ╚██╔╝  ");
    println!("  ╚██████╗╚██████╔╝██████╔╝███████╗╚█████╔╝╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║███████╗   ██║   ");
    println!("   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ");
    println!("\x1b[0m");
    println!("  \x1b[2mGit Repository Analytics & Security Scanner\x1b[0m\n");

    // Phase 1: compute all metrics with spinners, buffer output
    let mut collected_output = String::new();

    if !security_only {
        println!("\x1b[1;36m  Scanning repository analytics...\x1b[0m\n");
        collected_output += &run_analytics(&repo);
    }

    if !analytics_only {
        println!("\n\n\x1b[1;36m  Running security audit...\x1b[0m\n");
        collected_output += &run_security(&repo);
    }

    // Phase 2: display all results
    println!("\n{}", "═".repeat(64));
    println!("\x1b[1;37m  RESULTS\x1b[0m");
    println!("{}\n", "═".repeat(64));
    print!("{collected_output}");

    println!("\n\x1b[1;32m  ✓ Scan complete!\x1b[0m\n");

    Ok(())
}

/// Run a single step: show spinner, buffer output, return buffered string.
fn run_step(label: &str, f: impl FnOnce() -> Result<(), git2::Error>) -> String {
    let sp = display::spinner(label);
    display::start_buffering();

    let result = f();

    let output = display::flush_buffer();

    match result {
        Ok(()) => display::finish_spinner(&sp, label),
        Err(e) => display::fail_spinner(&sp, &format!("{label} (error: {e})")),
    }

    output
}

fn run_analytics(repo: &Repository) -> String {
    let mut output = String::new();

    output += &section_header("REPOSITORY ANALYTICS");
    output += &run_step("Repository overview", || analytics::repo_overview(repo));
    output += &run_step("Commit velocity", || analytics::commits_per_day(repo));
    output += &run_step("Top contributors", || analytics::top_contributors(repo));
    output += &run_step("Commit frequency by month", || analytics::commit_frequency_by_month(repo));
    output += &run_step("Activity by day of week", || analytics::activity_by_day_of_week(repo));
    output += &run_step("Activity by hour", || analytics::activity_by_hour(repo));
    output += &run_step("Emergency commits", || analytics::emergency_commits(repo));
    output += &run_step("Merge frequency", || analytics::merge_frequency(repo));
    output += &run_step("Largest tracked files", || analytics::largest_tracked_files(repo, 20));

    output
}

fn run_security(repo: &Repository) -> String {
    let mut output = String::new();

    output += &section_header("SECURITY AUDIT");
    output += &run_step("Scanning for secrets", || security::scan_secrets(repo));
    output += &run_step("Checking dangerous patterns", || security::dangerous_patterns(repo));
    output += &run_step("Checking sensitive files", || security::sensitive_files(repo));
    output += &run_step("Scanning for hardcoded IPs", || security::hardcoded_ips(repo));
    output += &run_step("Checking secret-related commits", || security::secret_related_commits(repo));
    output += &run_step("Checking security-sensitive commits", || security::security_sensitive_commits(repo));
    output += &run_step("Checking .gitignore coverage", || security::gitignore_coverage(repo));

    output
}

fn section_header(title: &str) -> String {
    let line = "═".repeat(60);
    format!(
        "\n\x1b[1;36m╔{line}╗\x1b[0m\n\x1b[1;36m║\x1b[0m \x1b[1;37m{title:<58}\x1b[0m \x1b[1;36m║\x1b[0m\n\x1b[1;36m╚{line}╝\x1b[0m\n"
    )
}
