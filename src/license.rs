use git2::{ObjectType, Oid, Repository, TreeWalkMode, TreeWalkResult};
use regex::Regex;
use std::collections::HashMap;

use crate::display;

/// Known SPDX license identifiers and their categories
fn license_category(spdx: &str) -> &'static str {
    let upper = spdx.to_uppercase();
    match upper.as_str() {
        "AGPL-3.0-ONLY" | "AGPL-3.0-OR-LATER" | "AGPL-3.0" => "copyleft (strong)",
        "GPL-2.0-ONLY" | "GPL-2.0-OR-LATER" | "GPL-2.0" | "GPL-3.0-ONLY"
        | "GPL-3.0-OR-LATER" | "GPL-3.0" => "copyleft (strong)",
        "LGPL-2.1-ONLY" | "LGPL-2.1-OR-LATER" | "LGPL-2.1" | "LGPL-3.0-ONLY"
        | "LGPL-3.0-OR-LATER" | "LGPL-3.0" => "copyleft (weak)",
        "MPL-2.0" | "EPL-1.0" | "EPL-2.0" | "CDDL-1.0" | "CDDL-1.1" => "copyleft (weak)",
        "MIT" | "ISC" | "BSD-2-CLAUSE" | "BSD-3-CLAUSE" | "APACHE-2.0" | "ZLIB" | "UNLICENSE"
        | "CC0-1.0" | "BSL-1.0" | "0BSD" => "permissive",
        _ => "unknown",
    }
}

fn is_copyleft(spdx: &str) -> bool {
    let cat = license_category(spdx);
    cat.starts_with("copyleft")
}

fn is_permissive(spdx: &str) -> bool {
    license_category(spdx) == "permissive"
}

/// Normalize common license strings to SPDX identifiers
fn normalize_license(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    match trimmed.to_uppercase().as_str() {
        "MIT" => "MIT".to_string(),
        "ISC" => "ISC".to_string(),
        "APACHE-2.0" | "APACHE 2.0" | "APACHE2" => "Apache-2.0".to_string(),
        "BSD-2-CLAUSE" | "BSD2" => "BSD-2-Clause".to_string(),
        "BSD-3-CLAUSE" | "BSD3" => "BSD-3-Clause".to_string(),
        "GPL-2.0" | "GPL2" | "GPLV2" | "GPL-2.0-ONLY" => "GPL-2.0-only".to_string(),
        "GPL-3.0" | "GPL3" | "GPLV3" | "GPL-3.0-ONLY" => "GPL-3.0-only".to_string(),
        "AGPL-3.0" | "AGPL3" | "AGPLV3" | "AGPL-3.0-ONLY" => "AGPL-3.0-only".to_string(),
        "LGPL-2.1" | "LGPL-2.1-ONLY" => "LGPL-2.1-only".to_string(),
        "LGPL-3.0" | "LGPL-3.0-ONLY" => "LGPL-3.0-only".to_string(),
        "MPL-2.0" | "MPL2" => "MPL-2.0".to_string(),
        "UNLICENSE" => "Unlicense".to_string(),
        "CC0-1.0" | "CC0" => "CC0-1.0".to_string(),
        "BSL-1.0" => "BSL-1.0".to_string(),
        _ => trimmed.to_string(),
    }
}

/// Detect the license type from the text content of a LICENSE/COPYING file.
/// Returns (SPDX identifier, confidence) where confidence is "high" or "medium".
fn detect_license_from_content(content: &str) -> (String, &'static str) {
    let text = content.to_lowercase();

    // Ordered from most specific to least specific to avoid false positives.
    // Each entry: (SPDX id, required phrases, disqualifying phrases, confidence)
    let signatures: Vec<(&str, Vec<&str>, Vec<&str>)> = vec![
        // AGPL must be checked before GPL since "GNU GENERAL PUBLIC" appears in both
        (
            "AGPL-3.0",
            vec![
                "gnu affero general public license",
                "version 3",
            ],
            vec![],
        ),
        (
            "GPL-3.0",
            vec![
                "gnu general public license",
                "version 3",
            ],
            vec!["lesser", "affero"],
        ),
        (
            "GPL-2.0",
            vec![
                "gnu general public license",
                "version 2",
            ],
            vec!["lesser", "affero"],
        ),
        (
            "LGPL-3.0",
            vec![
                "gnu lesser general public license",
                "version 3",
            ],
            vec![],
        ),
        (
            "LGPL-2.1",
            vec![
                "gnu lesser general public license",
                "version 2.1",
            ],
            vec![],
        ),
        (
            "MPL-2.0",
            vec![
                "mozilla public license",
                "version 2.0",
            ],
            vec![],
        ),
        (
            "EPL-2.0",
            vec![
                "eclipse public license",
                "version 2.0",
            ],
            vec![],
        ),
        (
            "EPL-1.0",
            vec![
                "eclipse public license",
                "version 1.0",
            ],
            vec![],
        ),
        (
            "Apache-2.0",
            vec![
                "apache license",
                "version 2.0",
            ],
            vec![],
        ),
        (
            "MIT",
            vec![
                "permission is hereby granted, free of charge",
                "the above copyright notice and this permission notice",
            ],
            vec![],
        ),
        (
            "ISC",
            vec![
                "permission to use, copy, modify, and/or distribute this software",
                "isc license",
            ],
            vec![],
        ),
        (
            "BSD-2-Clause",
            vec![
                "redistribution and use in source and binary forms",
            ],
            // BSD-3-Clause has an additional "neither the name" clause
            vec!["neither the name"],
        ),
        (
            "BSD-3-Clause",
            vec![
                "redistribution and use in source and binary forms",
                "neither the name",
            ],
            vec![],
        ),
        (
            "Unlicense",
            vec![
                "this is free and unencumbered software released into the public domain",
            ],
            vec![],
        ),
        (
            "CC0-1.0",
            vec![
                "cc0 1.0 universal",
            ],
            vec![],
        ),
        (
            "BSL-1.0",
            vec![
                "boost software license",
            ],
            vec![],
        ),
        (
            "0BSD",
            vec![
                "permission to use, copy, modify, and/or distribute this software",
                "0-clause bsd",
            ],
            vec![],
        ),
        (
            "Zlib",
            vec![
                "the origin of this software must not be misrepresented",
                "altered source versions must be plainly marked",
            ],
            vec![],
        ),
        (
            "WTFPL",
            vec![
                "do what the fuck you want to public license",
            ],
            vec![],
        ),
        (
            "Artistic-2.0",
            vec![
                "the artistic license 2.0",
            ],
            vec![],
        ),
        (
            "CDDL-1.0",
            vec![
                "common development and distribution license",
            ],
            vec![],
        ),
    ];

    for (spdx, required, disqualified) in &signatures {
        let all_required = required.iter().all(|phrase| text.contains(phrase));
        let any_disqualified = disqualified.iter().any(|phrase| text.contains(phrase));

        if all_required && !any_disqualified {
            return (spdx.to_string(), "high");
        }
    }

    // Fallback: try SPDX identifier line (e.g. "SPDX-License-Identifier: MIT")
    let spdx_re = Regex::new(r"(?i)SPDX-License-Identifier:\s*(.+)").unwrap();
    if let Some(caps) = spdx_re.captures(content) {
        let id = caps.get(1).unwrap().as_str().trim().to_string();
        return (normalize_license(&id), "high");
    }

    // Last-resort keyword matching
    let keyword_hints = [
        ("mit license", "MIT"),
        ("apache license", "Apache-2.0"),
        ("bsd license", "BSD-3-Clause"),
        ("gnu general public", "GPL"),
        ("mozilla public", "MPL-2.0"),
        ("public domain", "Public Domain"),
    ];

    for (keyword, spdx) in &keyword_hints {
        if text.contains(keyword) {
            return (spdx.to_string(), "medium");
        }
    }

    ("Unknown".to_string(), "low")
}

struct LicenseFileInfo {
    path: String,
    blob_id: Oid,
}

struct ManifestInfo {
    path: String,
    project_license: Option<String>,
    dependencies: Vec<(String, Option<String>)>, // (name, license if available)
}

/// Parse a Cargo.toml to extract license and dependency names
fn parse_cargo_toml(content: &str) -> ManifestInfo {
    let mut project_license = None;
    let mut dependencies = Vec::new();

    if let Ok(value) = content.parse::<toml::Value>() {
        // Extract project license
        if let Some(pkg) = value.get("package") {
            if let Some(lic) = pkg.get("license").and_then(|v| v.as_str()) {
                project_license = Some(normalize_license(lic));
            }
        }

        // Extract dependencies
        for section in &["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(deps) = value.get(section).and_then(|v| v.as_table()) {
                for (name, _) in deps {
                    dependencies.push((name.clone(), None));
                }
            }
        }
    }

    ManifestInfo {
        path: String::new(),
        project_license,
        dependencies,
    }
}

/// Parse a package.json to extract license and dependency names
fn parse_package_json(content: &str) -> ManifestInfo {
    let mut project_license = None;
    let mut dependencies = Vec::new();

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        // Extract project license
        if let Some(lic) = value.get("license").and_then(|v| v.as_str()) {
            project_license = Some(normalize_license(lic));
        }

        // Extract dependencies
        for section in &["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(deps) = value.get(section).and_then(|v| v.as_object()) {
                for (name, _) in deps {
                    dependencies.push((name.clone(), None));
                }
            }
        }
    }

    ManifestInfo {
        path: String::new(),
        project_license,
        dependencies,
    }
}

/// Parse a go.mod to extract module name and dependencies
fn parse_go_mod(content: &str) -> ManifestInfo {
    let mut dependencies = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") || trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" {
            in_require = false;
            continue;
        }
        if in_require {
            // Lines like: github.com/foo/bar v1.2.3
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(name) = parts.first() {
                if !name.starts_with("//") {
                    dependencies.push((name.to_string(), None));
                }
            }
        }
        // Single-line require
        if trimmed.starts_with("require ") && !trimmed.contains('(') {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                dependencies.push((parts[1].to_string(), None));
            }
        }
    }

    ManifestInfo {
        path: String::new(),
        project_license: None, // go.mod doesn't have a license field
        dependencies,
    }
}

/// Scan for license compliance issues
pub fn license_scan(repo: &Repository, ignore_dirs: &[String]) -> Result<(), git2::Error> {
    display::print_sub_header("License Compliance");

    let head = repo.head()?.peel_to_tree()?;
    let mut manifests: Vec<ManifestInfo> = Vec::new();
    let mut license_files: Vec<LicenseFileInfo> = Vec::new();

    // Walk the tree to find manifest and license files
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

        // Detect license files
        let name_upper = name.to_uppercase();
        if name_upper.starts_with("LICENSE") || name_upper.starts_with("LICENCE") || name_upper == "COPYING" {
            license_files.push(LicenseFileInfo {
                path: path.clone(),
                blob_id: entry.id(),
            });
        }

        // Parse manifest files
        if name == "Cargo.toml" || name == "package.json" || name == "go.mod" {
            if let Ok(blob) = repo.find_blob(entry.id()) {
                if let Ok(content) = std::str::from_utf8(blob.content()) {
                    let mut info = match name {
                        "Cargo.toml" => parse_cargo_toml(content),
                        "package.json" => parse_package_json(content),
                        "go.mod" => parse_go_mod(content),
                        _ => return TreeWalkResult::Ok,
                    };
                    info.path = path;
                    manifests.push(info);
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    if manifests.is_empty() {
        display::print_info("No dependency manifests found (Cargo.toml, package.json, go.mod)");
        return Ok(());
    }

    // Report per manifest
    let mut total_deps = 0usize;
    let mut copyleft_warnings: Vec<(String, String)> = Vec::new();
    let mut missing_license_manifests: Vec<String> = Vec::new();
    let mut project_licenses: HashMap<String, String> = HashMap::new();

    for manifest in &manifests {
        total_deps += manifest.dependencies.len();

        if let Some(ref lic) = manifest.project_license {
            project_licenses.insert(manifest.path.clone(), lic.clone());

            // Check for copyleft
            // Handle compound licenses like "MIT OR Apache-2.0"
            let parts: Vec<&str> = lic.split(" OR ").flat_map(|s| s.split('/').flat_map(|s| s.split(" AND "))).collect();
            for part in &parts {
                let normalized = normalize_license(part.trim());
                if is_copyleft(&normalized) {
                    copyleft_warnings.push((manifest.path.clone(), normalized));
                }
            }
        } else if manifest.path.ends_with("Cargo.toml") || manifest.path.ends_with("package.json") {
            // go.mod doesn't have license field, so only warn for Cargo.toml and package.json
            missing_license_manifests.push(manifest.path.clone());
        }
    }

    // License summary
    display::print_summary_stat("Manifests found", &manifests.len().to_string());
    display::print_summary_stat("Total dependencies", &total_deps.to_string());
    display::print_summary_stat("License files in repo", &license_files.len().to_string());

    // Project license report
    if !project_licenses.is_empty() {
        display::out("");
        display::out("    \x1b[1mProject Licenses (SPDX):\x1b[0m");
        let rows: Vec<Vec<String>> = project_licenses
            .iter()
            .map(|(path, lic)| {
                let cat = license_category(lic);
                vec![path.clone(), lic.clone(), cat.to_string()]
            })
            .collect();
        display::print_table(&["Manifest", "SPDX License", "Category"], &rows);
    }

    // Determine if project is permissive
    let project_is_permissive = project_licenses.values().any(|lic| {
        let parts: Vec<&str> = lic.split(" OR ").flat_map(|s| s.split('/')).collect();
        parts.iter().all(|p| is_permissive(&normalize_license(p.trim())))
    });

    // Copyleft warnings
    if !copyleft_warnings.is_empty() {
        display::out("");
        display::print_warning("Copyleft licenses detected:");
        for (path, lic) in &copyleft_warnings {
            display::out(&format!("      \x1b[31m•\x1b[0m {path}: {lic}"));
        }
    } else if project_is_permissive {
        display::print_ok("No copyleft license conflicts — project uses permissive licensing");
    }

    // Missing license warnings
    if !missing_license_manifests.is_empty() {
        display::out("");
        display::print_warning("Missing license declaration in:");
        for path in &missing_license_manifests {
            display::out(&format!("      \x1b[33m•\x1b[0m {path}"));
        }
    }

    // License files — read content and detect license type
    if license_files.is_empty() {
        display::out("");
        display::print_warning("No LICENSE/COPYING file found in repository root");
    } else {
        display::out("");
        display::out("    \x1b[1mLicense Files Detected:\x1b[0m");
        let mut rows: Vec<Vec<String>> = Vec::new();
        for lf in &license_files {
            let (detected_spdx, confidence) = if let Ok(blob) = repo.find_blob(lf.blob_id) {
                if let Ok(text) = std::str::from_utf8(blob.content()) {
                    detect_license_from_content(text)
                } else {
                    ("Binary file".to_string(), "low")
                }
            } else {
                ("Unreadable".to_string(), "low")
            };

            let dir = if lf.path.contains('/') {
                lf.path.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
            } else {
                "(root)"
            };
            let filename = lf.path.rsplit('/').next().unwrap_or(&lf.path);
            let cat = license_category(&detected_spdx);

            rows.push(vec![
                filename.to_string(),
                dir.to_string(),
                detected_spdx,
                cat.to_string(),
                confidence.to_string(),
            ]);
        }
        display::print_table(
            &["File", "Location", "Detected License", "Category", "Confidence"],
            &rows,
        );

        // Warn about detected copyleft in license files
        for row in &rows {
            let cat = &row[3];
            if cat.starts_with("copyleft") {
                display::print_warning(&format!(
                    "{}/{} is {} ({})",
                    row[1], row[0], row[2], cat
                ));
            }
        }
    }

    // Dependency summary per manifest
    display::out("");
    display::out("    \x1b[1mDependency Summary:\x1b[0m");
    let rows: Vec<Vec<String>> = manifests
        .iter()
        .map(|m| {
            vec![
                m.path.clone(),
                m.dependencies.len().to_string(),
                m.project_license.clone().unwrap_or_else(|| "not declared".to_string()),
            ]
        })
        .collect();
    display::print_table(&["Manifest", "Dependencies", "License"], &rows);

    Ok(())
}
