use rusqlite::{params, Connection};
use crate::display;

/// A snapshot of scan findings at a point in time.
#[derive(Debug, Clone)]
pub struct ScanSnapshot {
    pub timestamp: String,
    pub repo_path: String,
    pub commit_hash: String,
    pub sast_high: usize,
    pub sast_medium: usize,
    pub sast_info: usize,
    pub sca_total_deps: usize,
    pub sca_unpinned: usize,
    pub sca_cve_count: usize,
    pub complexity_avg: f64,
    pub complexity_above_threshold: usize,
    pub license_copyleft: usize,
    pub license_permissive: usize,
    pub secrets_found: usize,
}

/// Initialize the SQLite database and create tables if needed.
pub fn init_db(db_path: &str) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(db_path)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            commit_hash TEXT NOT NULL,
            sast_high INTEGER DEFAULT 0,
            sast_medium INTEGER DEFAULT 0,
            sast_info INTEGER DEFAULT 0,
            sca_total_deps INTEGER DEFAULT 0,
            sca_unpinned INTEGER DEFAULT 0,
            sca_cve_count INTEGER DEFAULT 0,
            complexity_avg REAL DEFAULT 0.0,
            complexity_above_threshold INTEGER DEFAULT 0,
            license_copyleft INTEGER DEFAULT 0,
            license_permissive INTEGER DEFAULT 0,
            secrets_found INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_scan_history_repo ON scan_history(repo_path);
        CREATE INDEX IF NOT EXISTS idx_scan_history_ts ON scan_history(timestamp);",
    )?;

    Ok(conn)
}

/// Store a scan snapshot into the database.
pub fn store_snapshot(conn: &Connection, snap: &ScanSnapshot) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO scan_history (
            timestamp, repo_path, commit_hash,
            sast_high, sast_medium, sast_info,
            sca_total_deps, sca_unpinned, sca_cve_count,
            complexity_avg, complexity_above_threshold,
            license_copyleft, license_permissive, secrets_found
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            snap.timestamp,
            snap.repo_path,
            snap.commit_hash,
            snap.sast_high,
            snap.sast_medium,
            snap.sast_info,
            snap.sca_total_deps,
            snap.sca_unpinned,
            snap.sca_cve_count,
            snap.complexity_avg,
            snap.complexity_above_threshold,
            snap.license_copyleft,
            snap.license_permissive,
            snap.secrets_found,
        ],
    )?;
    Ok(())
}

/// Load past scan snapshots for a repository.
pub fn load_history(
    conn: &Connection,
    repo_path: &str,
    limit: usize,
) -> Result<Vec<ScanSnapshot>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT timestamp, repo_path, commit_hash,
                sast_high, sast_medium, sast_info,
                sca_total_deps, sca_unpinned, sca_cve_count,
                complexity_avg, complexity_above_threshold,
                license_copyleft, license_permissive, secrets_found
         FROM scan_history
         WHERE repo_path = ?1
         ORDER BY timestamp DESC
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![repo_path, limit], |row| {
        Ok(ScanSnapshot {
            timestamp: row.get(0)?,
            repo_path: row.get(1)?,
            commit_hash: row.get(2)?,
            sast_high: row.get(3)?,
            sast_medium: row.get(4)?,
            sast_info: row.get(5)?,
            sca_total_deps: row.get(6)?,
            sca_unpinned: row.get(7)?,
            sca_cve_count: row.get(8)?,
            complexity_avg: row.get(9)?,
            complexity_above_threshold: row.get(10)?,
            license_copyleft: row.get(11)?,
            license_permissive: row.get(12)?,
            secrets_found: row.get(13)?,
        })
    })?;

    let mut snapshots = Vec::new();
    for row in rows {
        snapshots.push(row?);
    }

    // Reverse so oldest is first (for trend display)
    snapshots.reverse();
    Ok(snapshots)
}

/// Display trend charts from historical scan data.
pub fn display_trends(snapshots: &[ScanSnapshot]) {
    if snapshots.is_empty() {
        display::print_info("No historical data available yet. Run more scans to see trends.");
        return;
    }

    display::print_sub_header("Findings Trends Over Time");

    // Display as table
    let rows: Vec<Vec<String>> = snapshots
        .iter()
        .map(|s| {
            vec![
                s.timestamp[..10.min(s.timestamp.len())].to_string(),
                s.commit_hash[..7.min(s.commit_hash.len())].to_string(),
                s.sast_high.to_string(),
                s.sast_medium.to_string(),
                format!("{:.1}", s.complexity_avg),
                s.sca_cve_count.to_string(),
                s.secrets_found.to_string(),
            ]
        })
        .collect();

    display::print_table(
        &[
            "Date",
            "Commit",
            "SAST High",
            "SAST Med",
            "Avg Complexity",
            "CVEs",
            "Secrets",
        ],
        &rows,
    );

    // Sparkline for SAST high severity
    if snapshots.len() >= 2 {
        display::out("");
        display::out("    \x1b[1mVulnerability Trend (SAST HIGH):\x1b[0m");
        let sast_data: Vec<(String, usize)> = snapshots
            .iter()
            .map(|s| {
                (
                    s.timestamp[..10.min(s.timestamp.len())].to_string(),
                    s.sast_high,
                )
            })
            .collect();
        display::print_sparkline(&sast_data);

        display::out("");
        display::out("    \x1b[1mComplexity Trend:\x1b[0m");
        let complexity_data: Vec<(String, usize)> = snapshots
            .iter()
            .map(|s| {
                (
                    s.timestamp[..10.min(s.timestamp.len())].to_string(),
                    (s.complexity_avg * 10.0) as usize,
                )
            })
            .collect();
        display::print_sparkline(&complexity_data);

        display::out("");
        display::out("    \x1b[1mCVE Count Trend:\x1b[0m");
        let cve_data: Vec<(String, usize)> = snapshots
            .iter()
            .map(|s| {
                (
                    s.timestamp[..10.min(s.timestamp.len())].to_string(),
                    s.sca_cve_count,
                )
            })
            .collect();
        display::print_sparkline(&cve_data);

        // Show direction
        let first = &snapshots[0];
        let last = snapshots.last().unwrap();

        display::out("");
        display::out("    \x1b[1mDirection Summary:\x1b[0m");
        show_direction(
            "SAST HIGH findings",
            first.sast_high,
            last.sast_high,
        );
        show_direction(
            "Avg complexity",
            (first.complexity_avg * 10.0) as usize,
            (last.complexity_avg * 10.0) as usize,
        );
        show_direction("CVE count", first.sca_cve_count, last.sca_cve_count);
        show_direction("Secrets found", first.secrets_found, last.secrets_found);
    }
}

fn show_direction(label: &str, old: usize, new: usize) {
    let (arrow, color) = if new < old {
        ("↓", "\x1b[32m") // green = improving
    } else if new > old {
        ("↑", "\x1b[31m") // red = worsening
    } else {
        ("→", "\x1b[33m") // yellow = stable
    };
    display::out(&format!(
        "      {color}{arrow}\x1b[0m {label}: {old} → {new}"
    ));
}

/// Collect current scan metrics from repository for snapshot.
pub fn collect_current_metrics(
    repo: &git2::Repository,
    repo_path: &str,
    ignore_dirs: &[String],
) -> ScanSnapshot {
    let commit_hash = repo
        .head()
        .ok()
        .and_then(|h| h.peel_to_commit().ok())
        .map(|c| c.id().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Count SAST findings
    let (sast_high, sast_medium, sast_info) = count_sast_findings(repo, ignore_dirs);

    // Count SCA metrics
    let (sca_total, sca_unpinned) = count_sca_metrics(repo, ignore_dirs);

    // Count complexity
    let (complexity_avg, complexity_above) = count_complexity_metrics(repo, ignore_dirs);

    // Count secrets
    let secrets_found = count_secrets(repo, ignore_dirs);

    ScanSnapshot {
        timestamp,
        repo_path: repo_path.to_string(),
        commit_hash,
        sast_high,
        sast_medium,
        sast_info,
        sca_total_deps: sca_total,
        sca_unpinned,
        sca_cve_count: 0, // would need network access
        complexity_avg,
        complexity_above_threshold: complexity_above,
        license_copyleft: 0,
        license_permissive: 0,
        secrets_found,
    }
}

fn count_sast_findings(
    repo: &git2::Repository,
    ignore_dirs: &[String],
) -> (usize, usize, usize) {
    use git2::{ObjectType, TreeWalkMode, TreeWalkResult};
    use regex::Regex;

    let head = match repo.head().and_then(|h| h.peel_to_tree()) {
        Ok(t) => t,
        Err(_) => return (0, 0, 0),
    };

    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    let rules: Vec<(&str, Regex, &[&str])> = vec![
        (
            "HIGH",
            Regex::new(r#"(?i)(execute|query|raw)\s*\(.*(\+|format!|f"|fmt\.Sprintf)"#).unwrap(),
            &[".rs", ".go", ".py", ".ts", ".js", ".java"],
        ),
        (
            "HIGH",
            Regex::new(r"\beval\s*\(").unwrap(),
            &[".js", ".ts", ".py", ".php"],
        ),
        (
            "HIGH",
            Regex::new(r#"(?i)(SECRET_KEY|API_KEY|PASSWORD)\s*=\s*['"][^'"]{4,}['"]"#).unwrap(),
            &[".py", ".js", ".ts", ".java"],
        ),
        (
            "MEDIUM",
            Regex::new(r"\.innerHTML\s*=").unwrap(),
            &[".js", ".ts", ".tsx"],
        ),
        (
            "MEDIUM",
            Regex::new(r"(?i)(md5|sha-?1)\s*\(").unwrap(),
            &[".py", ".java", ".go"],
        ),
        (
            "INFO",
            Regex::new(r"\bunsafe\s*\{").unwrap(),
            &[".rs"],
        ),
    ];

    let mut high = 0usize;
    let mut medium = 0usize;
    let mut info = 0usize;

    let _ = head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        let path = format!("{}{}", dir, entry.name().unwrap_or(""));
        if skip_dirs.iter().any(|d| path.starts_with(d))
            || ignore_dirs.iter().any(|d| {
                let n = if d.ends_with('/') {
                    d.clone()
                } else {
                    format!("{d}/")
                };
                path.starts_with(&n)
            })
        {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for line in content.lines() {
                    for (severity, pattern, exts) in &rules {
                        if exts.iter().any(|ext| path.ends_with(ext)) && pattern.is_match(line) {
                            match *severity {
                                "HIGH" => high += 1,
                                "MEDIUM" => medium += 1,
                                _ => info += 1,
                            }
                        }
                    }
                }
            }
        }
        TreeWalkResult::Ok
    });

    (high, medium, info)
}

fn count_sca_metrics(repo: &git2::Repository, ignore_dirs: &[String]) -> (usize, usize) {
    use git2::{ObjectType, TreeWalkMode, TreeWalkResult};

    let head = match repo.head().and_then(|h| h.peel_to_tree()) {
        Ok(t) => t,
        Err(_) => return (0, 0),
    };

    let mut total = 0usize;
    let mut unpinned = 0usize;

    let _ = head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        let name = entry.name().unwrap_or("");
        if name != "requirements.txt" {
            return TreeWalkResult::Ok;
        }
        let path = format!("{}{}", dir, name);
        if ignore_dirs.iter().any(|d| path.starts_with(d)) {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    total += 1;
                    if !trimmed.contains("==") {
                        unpinned += 1;
                    }
                }
            }
        }
        TreeWalkResult::Ok
    });

    // Also count from Cargo.lock
    let _ = head.walk(TreeWalkMode::PreOrder, |_dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        let name = entry.name().unwrap_or("");
        if name != "Cargo.lock" && name != "package-lock.json" {
            return TreeWalkResult::Ok;
        }
        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                if name == "Cargo.lock" {
                    total += content.matches("[[package]]").count();
                } else if name == "package-lock.json" {
                    // Rough count of packages
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                        if let Some(pkgs) = val.get("packages").and_then(|v| v.as_object()) {
                            total += pkgs.len().saturating_sub(1); // exclude root
                        }
                    }
                }
            }
        }
        TreeWalkResult::Ok
    });

    (total, unpinned)
}

fn count_complexity_metrics(
    repo: &git2::Repository,
    ignore_dirs: &[String],
) -> (f64, usize) {
    use git2::{ObjectType, TreeWalkMode, TreeWalkResult};
    use regex::Regex;

    let head = match repo.head().and_then(|h| h.peel_to_tree()) {
        Ok(t) => t,
        Err(_) => return (0.0, 0),
    };

    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    let func_pat = Regex::new(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)").unwrap();
    let branch_kws = ["if", "else if", "while", "for", "loop", "match", "=>", "&&", "||", "?"];

    let mut complexities: Vec<usize> = Vec::new();

    let _ = head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        let path = format!("{}{}", dir, entry.name().unwrap_or(""));
        if !path.ends_with(".rs")
            && !path.ends_with(".go")
            && !path.ends_with(".py")
            && !path.ends_with(".ts")
            && !path.ends_with(".js")
        {
            return TreeWalkResult::Ok;
        }
        if skip_dirs.iter().any(|d| path.starts_with(d))
            || ignore_dirs.iter().any(|d| path.starts_with(d))
        {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                let lines: Vec<&str> = content.lines().collect();
                let mut i = 0;
                while i < lines.len() {
                    if func_pat.is_match(lines[i]) {
                        let mut complexity = 1usize;
                        let mut brace_depth = 0i32;
                        let mut found_open = false;
                        let mut j = i;
                        while j < lines.len() {
                            for ch in lines[j].chars() {
                                if ch == '{' {
                                    brace_depth += 1;
                                    found_open = true;
                                } else if ch == '}' {
                                    brace_depth -= 1;
                                }
                            }
                            if found_open && j > i {
                                for kw in &branch_kws {
                                    if lines[j].contains(kw) {
                                        complexity += 1;
                                    }
                                }
                            }
                            if found_open && brace_depth <= 0 {
                                break;
                            }
                            j += 1;
                        }
                        complexities.push(complexity);
                        i = j + 1;
                    } else {
                        i += 1;
                    }
                }
            }
        }
        TreeWalkResult::Ok
    });

    if complexities.is_empty() {
        return (0.0, 0);
    }

    let avg = complexities.iter().sum::<usize>() as f64 / complexities.len() as f64;
    let above = complexities.iter().filter(|&&c| c > 10).count();
    (avg, above)
}

fn count_secrets(repo: &git2::Repository, ignore_dirs: &[String]) -> usize {
    use git2::{ObjectType, TreeWalkMode, TreeWalkResult};
    use regex::Regex;

    let head = match repo.head().and_then(|h| h.peel_to_tree()) {
        Ok(t) => t,
        Err(_) => return 0,
    };

    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    let secret_pattern =
        Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token)\s*[=:]\s*['"][^'"]{8,}['"]"#)
            .unwrap();

    let mut count = 0usize;

    let _ = head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        let path = format!("{}{}", dir, entry.name().unwrap_or(""));
        if skip_dirs.iter().any(|d| path.starts_with(d))
            || ignore_dirs.iter().any(|d| path.starts_with(d))
        {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for line in content.lines() {
                    if secret_pattern.is_match(line) {
                        count += 1;
                    }
                }
            }
        }
        TreeWalkResult::Ok
    });

    count
}
