use git2::{ObjectType, Repository, TreeWalkMode, TreeWalkResult};
use std::collections::HashMap;

use crate::display;

struct Dependency {
    name: String,
    version: String,
    source: String, // which lockfile it came from
}

/// Parse Cargo.lock to extract dependencies
fn parse_cargo_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                deps.push(Dependency {
                    name,
                    version,
                    source: "Cargo.lock".to_string(),
                });
            }
            current_name = None;
            current_version = None;
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        }
    }
    // Don't forget the last entry
    if let (Some(name), Some(version)) = (current_name, current_version) {
        deps.push(Dependency {
            name,
            version,
            source: "Cargo.lock".to_string(),
        });
    }

    deps
}

/// Parse package-lock.json to extract dependencies
fn parse_package_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        // package-lock.json v2/v3 uses "packages" field
        if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
            for (path, pkg_info) in packages {
                if path.is_empty() {
                    continue; // skip root package
                }
                // Extract package name from path (e.g., "node_modules/lodash" -> "lodash")
                let name = path
                    .rsplit("node_modules/")
                    .next()
                    .unwrap_or(path)
                    .to_string();
                let version = pkg_info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                deps.push(Dependency {
                    name,
                    version,
                    source: "package-lock.json".to_string(),
                });
            }
        }
        // Fallback: package-lock.json v1 uses "dependencies"
        else if let Some(dependencies) = value.get("dependencies").and_then(|v| v.as_object()) {
            fn extract_deps(deps_obj: &serde_json::Map<String, serde_json::Value>, result: &mut Vec<Dependency>) {
                for (name, info) in deps_obj {
                    let version = info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    result.push(Dependency {
                        name: name.clone(),
                        version,
                        source: "package-lock.json".to_string(),
                    });
                    // Recurse into nested dependencies
                    if let Some(nested) = info.get("dependencies").and_then(|v| v.as_object()) {
                        extract_deps(nested, result);
                    }
                }
            }
            extract_deps(dependencies, &mut deps);
        }
    }

    deps
}

/// Parse go.sum to extract dependencies
fn parse_go_sum(content: &str) -> Vec<Dependency> {
    let mut seen = HashMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let version = parts[1].trim_end_matches("/go.mod").to_string();
            seen.entry(name).or_insert(version);
        }
    }

    seen.into_iter()
        .map(|(name, version)| Dependency {
            name,
            version,
            source: "go.sum".to_string(),
        })
        .collect()
}

/// Parse requirements.txt to extract dependencies
fn parse_requirements_txt(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Handle formats: package==1.0, package>=1.0, package~=1.0, package
        let (name, version) = if let Some(pos) = trimmed.find("==") {
            (trimmed[..pos].trim().to_string(), trimmed[pos + 2..].trim().to_string())
        } else if let Some(pos) = trimmed.find(">=") {
            (trimmed[..pos].trim().to_string(), format!(">={}", trimmed[pos + 2..].trim()))
        } else if let Some(pos) = trimmed.find("~=") {
            (trimmed[..pos].trim().to_string(), format!("~={}", trimmed[pos + 2..].trim()))
        } else if let Some(pos) = trimmed.find("<=") {
            (trimmed[..pos].trim().to_string(), format!("<={}", trimmed[pos + 2..].trim()))
        } else if let Some(pos) = trimmed.find("!=") {
            (trimmed[..pos].trim().to_string(), format!("!={}", trimmed[pos + 2..].trim()))
        } else {
            // No version pin
            (trimmed.to_string(), "unpinned".to_string())
        };

        // Strip extras like package[extra]
        let clean_name = if let Some(pos) = name.find('[') {
            name[..pos].to_string()
        } else {
            name
        };

        deps.push(Dependency {
            name: clean_name,
            version,
            source: "requirements.txt".to_string(),
        });
    }

    deps
}

/// Run Software Composition Analysis
pub fn sca_scan(repo: &Repository, ignore_dirs: &[String]) -> Result<(), git2::Error> {
    display::print_sub_header("Software Composition Analysis (SCA)");

    let head = repo.head()?.peel_to_tree()?;
    let mut all_deps: Vec<Dependency> = Vec::new();
    let mut lockfiles_found: Vec<String> = Vec::new();

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let name = entry.name().unwrap_or("");
        let path = format!("{}{}", dir, name);

        // Skip vendored dirs and user-specified ignore dirs
        let default_skip = ["vendor/", "node_modules/", "target/"];
        if default_skip.iter().any(|d| path.starts_with(d))
            || ignore_dirs.iter().any(|d| {
                let normalized = if d.ends_with('/') { d.clone() } else { format!("{d}/") };
                path.starts_with(&normalized)
            })
        {
            return TreeWalkResult::Ok;
        }

        let is_lockfile = matches!(name, "Cargo.lock" | "package-lock.json" | "go.sum" | "requirements.txt");
        if !is_lockfile {
            return TreeWalkResult::Ok;
        }

        lockfiles_found.push(path.clone());

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                let mut deps = match name {
                    "Cargo.lock" => parse_cargo_lock(content),
                    "package-lock.json" => parse_package_lock(content),
                    "go.sum" => parse_go_sum(content),
                    "requirements.txt" => parse_requirements_txt(content),
                    _ => Vec::new(),
                };
                // Tag with full path for nested lockfiles
                for dep in &mut deps {
                    if dir != "" {
                        dep.source = path.clone();
                    }
                }
                all_deps.extend(deps);
            }
        }

        TreeWalkResult::Ok
    })?;

    if lockfiles_found.is_empty() {
        display::print_info("No lockfiles found (Cargo.lock, package-lock.json, go.sum, requirements.txt)");
        return Ok(());
    }

    // Summary
    display::print_summary_stat("Lockfiles found", &lockfiles_found.len().to_string());
    display::print_summary_stat("Total dependencies", &all_deps.len().to_string());

    // Group by source
    let mut by_source: HashMap<String, Vec<&Dependency>> = HashMap::new();
    for dep in &all_deps {
        by_source.entry(dep.source.clone()).or_default().push(dep);
    }

    // Dependency tree per lockfile
    for (source, deps) in &by_source {
        display::out("");
        display::out(&format!("    \x1b[1m{source}\x1b[0m ({} dependencies)", deps.len()));

        // Show first 30 deps
        let rows: Vec<Vec<String>> = deps
            .iter()
            .take(30)
            .map(|d| vec![d.name.clone(), d.version.clone()])
            .collect();
        display::print_table(&["Package", "Version"], &rows);

        if deps.len() > 30 {
            display::print_info(&format!("... and {} more", deps.len() - 30));
        }
    }

    // Risk analysis
    display::out("");
    display::out("    \x1b[1mRisk Analysis:\x1b[0m");

    // Check for unpinned versions
    let unpinned: Vec<&Dependency> = all_deps
        .iter()
        .filter(|d| d.version == "unpinned" || d.version.starts_with(">=") || d.version.starts_with("~="))
        .collect();

    if !unpinned.is_empty() {
        display::print_warning(&format!("{} dependencies with unpinned or loose versions:", unpinned.len()));
        let rows: Vec<Vec<String>> = unpinned
            .iter()
            .take(15)
            .map(|d| vec![d.name.clone(), d.version.clone(), d.source.clone()])
            .collect();
        display::print_table(&["Package", "Version", "Source"], &rows);
    } else {
        display::print_ok("All dependencies have pinned versions");
    }

    // Check for pre-release / 0.x versions (potentially unstable)
    let prerelease: Vec<&Dependency> = all_deps
        .iter()
        .filter(|d| {
            d.version.starts_with("0.") ||
            d.version.contains("-alpha") ||
            d.version.contains("-beta") ||
            d.version.contains("-rc") ||
            d.version.contains("-dev")
        })
        .collect();

    if !prerelease.is_empty() {
        display::out("");
        display::print_info(&format!("{} dependencies are pre-release or 0.x (potentially unstable):", prerelease.len()));
        let rows: Vec<Vec<String>> = prerelease
            .iter()
            .take(15)
            .map(|d| vec![d.name.clone(), d.version.clone(), d.source.clone()])
            .collect();
        display::print_table(&["Package", "Version", "Source"], &rows);
    }

    // Note about CVE checking
    display::out("");
    display::print_info("Note: CVE database lookup requires network access.");
    display::print_info("Run `cargo audit` (Rust), `npm audit` (Node.js), or `pip-audit` (Python) for vulnerability scanning.");

    Ok(())
}
