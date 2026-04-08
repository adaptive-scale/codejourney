use git2::{ObjectType, Repository, Sort, TreeWalkMode, TreeWalkResult};
use regex::Regex;
use std::collections::HashSet;

use crate::display;

/// Scan tracked files for patterns that may indicate hardcoded secrets
pub fn scan_secrets(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Secrets & Credential Detection");

    let head = repo.head()?.peel_to_tree()?;

    let secret_patterns = vec![
        (
            "API keys/tokens",
            Regex::new(r"(?i)(password|secret|api_key|apikey|access_token|private_key|SECRET_KEY|AWS_ACCESS|AKIA[0-9A-Z]{16})").unwrap(),
        ),
        (
            "Base64 blobs (potential embedded secrets)",
            Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap(),
        ),
    ];

    let skip_dirs = ["vendor/", "node_modules/", ".git/"];
    let scan_exts = [
        ".go", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml", ".toml", ".py", ".rs", ".env",
        ".cfg", ".conf", ".ini",
    ];

    let mut findings: Vec<(String, String, usize)> = Vec::new(); // (file, pattern_name, line)

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let path = format!("{}{}", dir, entry.name().unwrap_or(""));

        // Skip vendored/dependency dirs
        if skip_dirs.iter().any(|d| path.starts_with(d)) {
            return TreeWalkResult::Ok;
        }

        // Only scan relevant file types
        if !scan_exts.iter().any(|ext| path.ends_with(ext)) {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for (line_num, line) in content.lines().enumerate() {
                    // Skip test/mock/fixture lines
                    let lower = line.to_lowercase();
                    if lower.contains("test") || lower.contains("mock") || lower.contains("fixture") || lower.contains("example") {
                        continue;
                    }
                    for (name, pattern) in &secret_patterns {
                        if pattern.is_match(line) {
                            findings.push((path.clone(), name.to_string(), line_num + 1));
                        }
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    if findings.is_empty() {
        display::print_ok("No potential secrets detected in tracked files");
    } else {
        display::print_warning(&format!(
            "Found {} potential secret references:",
            findings.len()
        ));
        let rows: Vec<Vec<String>> = findings
            .iter()
            .take(30)
            .map(|(file, pattern, line)| vec![file.clone(), format!("L{line}"), pattern.clone()])
            .collect();
        display::print_table(&["File", "Line", "Pattern"], &rows);
    }

    Ok(())
}

/// Check for dangerous code patterns
pub fn dangerous_patterns(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Dangerous Code Patterns");

    let head = repo.head()?.peel_to_tree()?;

    let patterns: Vec<(&str, Regex, &[&str])> = vec![
        (
            "SQL injection risk",
            Regex::new(r#"(Exec|Raw|Query)\(.*fmt\.Sprintf|Exec\(.*\+.*\)|Raw\(.*\+.*\)"#).unwrap(),
            &[".go"],
        ),
        (
            "Command injection",
            Regex::new(r"(exec\.Command|os\.system|subprocess|child_process)\(").unwrap(),
            &[".go", ".py", ".js", ".ts"],
        ),
        (
            "Disabled TLS verification",
            Regex::new(
                r"(InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED|verify=False|ssl_verify.*false)",
            )
            .unwrap(),
            &[".go", ".py", ".js", ".ts", ".yaml", ".yml"],
        ),
        (
            "Weak crypto usage",
            Regex::new(r"\b(md5|sha1|DES|RC4|Math\.random)\b").unwrap(),
            &[".go", ".ts", ".js", ".rs"],
        ),
        (
            "CORS wildcard",
            Regex::new(r"(Access-Control-Allow-Origin.*\*|AllowAllOrigins|cors\.Default)").unwrap(),
            &[".go", ".ts", ".js", ".rs", ".yaml"],
        ),
        (
            "Debug/dev flags in production code",
            Regex::new(r"(?i)(DEBUG.*=.*true|SWAGGER_ENABLED|devMode|development.*true)").unwrap(),
            &[".go", ".ts", ".yaml", ".yml", ".rs"],
        ),
    ];

    let skip_dirs = ["vendor/", "node_modules/", ".git/", "target/"];
    let mut findings: Vec<(String, String, usize)> = Vec::new();

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let path = format!("{}{}", dir, entry.name().unwrap_or(""));

        if skip_dirs.iter().any(|d| path.starts_with(d)) {
            return TreeWalkResult::Ok;
        }

        // Skip test files
        if path.contains("_test.") || path.contains(".test.") || path.contains("/test/") {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for (name, pattern, exts) in &patterns {
                    if !exts.iter().any(|ext| path.ends_with(ext)) {
                        continue;
                    }
                    for (line_num, line) in content.lines().enumerate() {
                        if pattern.is_match(line) {
                            findings.push((path.clone(), name.to_string(), line_num + 1));
                        }
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    if findings.is_empty() {
        display::print_ok("No dangerous code patterns detected");
    } else {
        display::print_warning(&format!("{} dangerous patterns found:", findings.len()));
        let rows: Vec<Vec<String>> = findings
            .iter()
            .take(30)
            .map(|(file, pattern, line)| vec![file.clone(), format!("L{line}"), pattern.clone()])
            .collect();
        display::print_table(&["File", "Line", "Issue"], &rows);
    }

    Ok(())
}

/// Check for sensitive files that shouldn't be tracked
pub fn sensitive_files(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Sensitive Files in Repository");

    let head = repo.head()?.peel_to_tree()?;

    let sensitive_patterns = Regex::new(
        r"(?i)(\.env$|\.env\.|secret|credential|\.key$|\.pem$|\.p12$|\.pfx$|\.jks$|\.keystore$|\.credentials|token)",
    )
    .unwrap();

    let mut found_files: Vec<String> = Vec::new();

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let path = format!("{}{}", dir, entry.name().unwrap_or(""));

        if path.starts_with("vendor/") || path.starts_with("node_modules/") {
            return TreeWalkResult::Ok;
        }

        if sensitive_patterns.is_match(&path) {
            found_files.push(path);
        }

        TreeWalkResult::Ok
    })?;

    if found_files.is_empty() {
        display::print_ok("No sensitive files found in tracked tree");
    } else {
        display::print_warning(&format!(
            "{} potentially sensitive files tracked:",
            found_files.len()
        ));
        for f in &found_files {
            display::out(&format!("      \x1b[31m•\x1b[0m {f}"));
        }
    }

    Ok(())
}

/// Check commits that touch security-sensitive files
pub fn security_sensitive_commits(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Recent Commits Touching Security-Sensitive Files");

    let sensitive = Regex::new(r"(?i)(auth|login|session|crypto|middleware|permission|authorization)")
        .unwrap();

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut entries: Vec<(String, String, String)> = Vec::new();
    let mut count = 0;

    for oid in revwalk {
        if count >= 500 || entries.len() >= 20 {
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let tree = commit.tree()?;
        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let mut diff_opts = git2::DiffOptions::new();
        let diff =
            repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_opts))?;

        let mut touched_sensitive = false;
        let mut sensitive_paths: Vec<String> = Vec::new();

        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    let p = path.to_string_lossy();
                    if sensitive.is_match(&p) {
                        touched_sensitive = true;
                        sensitive_paths.push(p.to_string());
                    }
                }
                true
            },
            None,
            None,
            None,
        )?;

        if touched_sensitive {
            let msg = commit.message().unwrap_or("").trim().to_string();
            let short_msg = if msg.len() > 50 {
                format!("{}…", &msg[..49])
            } else {
                msg
            };
            entries.push((
                oid.to_string()[..7].to_string(),
                short_msg,
                sensitive_paths.join(", "),
            ));
        }

        count += 1;
    }

    if entries.is_empty() {
        display::print_info("No security-sensitive file changes found in recent history");
    } else {
        let rows: Vec<Vec<String>> = entries
            .iter()
            .map(|(h, m, f)| vec![h.clone(), m.clone(), f.clone()])
            .collect();
        display::print_table(&["Hash", "Message", "Files"], &rows);
    }

    Ok(())
}

/// Check .gitignore for common sensitive patterns
pub fn gitignore_coverage(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header(".gitignore Coverage Check");

    let required_patterns = [".env", "*.key", "*.pem", "*.p12", ".credentials", "*.secret"];

    let workdir = repo.workdir().unwrap_or(std::path::Path::new("."));
    let gitignore_path = workdir.join(".gitignore");

    if !gitignore_path.exists() {
        display::print_warning("No .gitignore file found!");
        return Ok(());
    }

    let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();

    for pattern in &required_patterns {
        if content.contains(pattern) {
            display::print_ok(&format!("{pattern} is ignored"));
        } else {
            display::print_warning(&format!("{pattern} is NOT in .gitignore"));
        }
    }

    Ok(())
}

/// Check for hardcoded IPs
pub fn hardcoded_ips(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Hardcoded IP Addresses");

    let head = repo.head()?.peel_to_tree()?;
    let ip_pattern = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
    let safe_ips: HashSet<&str> = ["127.0.0.1", "0.0.0.0", "255.255.255.0", "255.255.255.255"]
        .into_iter()
        .collect();

    let scan_exts = [".go", ".ts", ".tsx", ".js", ".yaml", ".yml", ".toml", ".rs", ".py"];
    let skip_dirs = ["vendor/", "node_modules/", ".git/", "target/"];
    let mut findings: Vec<(String, usize, String)> = Vec::new();

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let path = format!("{}{}", dir, entry.name().unwrap_or(""));

        if skip_dirs.iter().any(|d| path.starts_with(d)) {
            return TreeWalkResult::Ok;
        }
        if !scan_exts.iter().any(|ext| path.ends_with(ext)) {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains("example") || line.contains("test") || line.contains("//") && line.contains("localhost") {
                        continue;
                    }
                    for cap in ip_pattern.captures_iter(line) {
                        let ip = cap.get(1).unwrap().as_str();
                        if !safe_ips.contains(ip) {
                            findings.push((path.clone(), line_num + 1, ip.to_string()));
                        }
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    if findings.is_empty() {
        display::print_ok("No hardcoded IP addresses found");
    } else {
        display::print_warning(&format!("{} hardcoded IPs found:", findings.len()));
        let rows: Vec<Vec<String>> = findings
            .iter()
            .take(20)
            .map(|(file, line, ip)| vec![file.clone(), format!("L{line}"), ip.clone()])
            .collect();
        display::print_table(&["File", "Line", "IP"], &rows);
    }

    Ok(())
}

/// Commits mentioning secrets/credentials/leaks
pub fn secret_related_commits(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Commits Mentioning Secrets/Credentials");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let pattern = Regex::new(r"(?i)(secret|credential|password|api.key|token|leak)").unwrap();
    let mut entries: Vec<(String, String)> = Vec::new();

    for oid in revwalk {
        if entries.len() >= 20 {
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let msg = commit.message().unwrap_or("").trim().to_string();
        if pattern.is_match(&msg) {
            let short_msg = if msg.len() > 70 {
                format!("{}…", &msg[..69])
            } else {
                msg
            };
            entries.push((oid.to_string()[..7].to_string(), short_msg));
        }
    }

    if entries.is_empty() {
        display::print_ok("No commits mentioning secrets or credentials");
    } else {
        display::print_warning(&format!(
            "{} commits reference secrets/credentials:",
            entries.len()
        ));
        let rows: Vec<Vec<String>> = entries
            .iter()
            .map(|(h, m)| vec![h.clone(), m.clone()])
            .collect();
        display::print_table(&["Hash", "Message"], &rows);
    }

    Ok(())
}
