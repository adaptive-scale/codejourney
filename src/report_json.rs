use crate::history::ScanSnapshot;
use crate::pdf::strip_ansi;
use serde_json::{json, Value};
use std::fs;

/// Generate a structured JSON report from the scan output and metrics snapshot.
pub fn generate(
    content: &str,
    snapshot: &ScanSnapshot,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plain = strip_ansi(content);

    // Parse sections from the plain text
    let sections = parse_sections(&plain);

    let report = json!({
        "report": {
            "generator": "CodeJourney",
            "version": "0.1.0",
            "timestamp": snapshot.timestamp,
            "repository": snapshot.repo_path,
            "commit": snapshot.commit_hash,
        },
        "summary": {
            "sast": {
                "high": snapshot.sast_high,
                "medium": snapshot.sast_medium,
                "info": snapshot.sast_info,
                "total": snapshot.sast_high + snapshot.sast_medium + snapshot.sast_info,
            },
            "sca": {
                "total_dependencies": snapshot.sca_total_deps,
                "unpinned": snapshot.sca_unpinned,
                "known_cves": snapshot.sca_cve_count,
            },
            "complexity": {
                "average": snapshot.complexity_avg,
                "above_threshold": snapshot.complexity_above_threshold,
            },
            "licenses": {
                "copyleft": snapshot.license_copyleft,
                "permissive": snapshot.license_permissive,
            },
            "secrets": {
                "found": snapshot.secrets_found,
            },
        },
        "sections": sections,
    });

    let json_str = serde_json::to_string_pretty(&report)?;
    fs::write(output_path, json_str)?;
    Ok(())
}

/// Parse the report content into structured sections.
fn parse_sections(content: &str) -> Vec<Value> {
    let mut sections = Vec::new();
    let mut current_title = String::new();
    let mut current_findings: Vec<Value> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Section header detection (inside box-drawing characters)
        if trimmed.starts_with('║') && trimmed.ends_with('║') {
            // Flush previous section
            if !current_title.is_empty() {
                sections.push(json!({
                    "title": current_title,
                    "findings": current_findings,
                }));
            }
            current_title = trimmed
                .trim_start_matches('║')
                .trim_end_matches('║')
                .trim()
                .to_string();
            current_findings = Vec::new();
            continue;
        }

        // Skip decorative lines
        if trimmed.starts_with('╔')
            || trimmed.starts_with('╚')
            || trimmed.starts_with('─')
            || trimmed.starts_with('═')
        {
            continue;
        }

        // Warning lines
        if trimmed.starts_with('⚠') {
            let msg = trimmed.trim_start_matches('⚠').trim();
            current_findings.push(json!({
                "type": "warning",
                "message": msg,
            }));
            continue;
        }

        // OK lines
        if trimmed.starts_with('✓') {
            let msg = trimmed.trim_start_matches('✓').trim();
            current_findings.push(json!({
                "type": "ok",
                "message": msg,
            }));
            continue;
        }

        // Stat lines (Label: Value)
        if let Some(colon_pos) = trimmed.find(':') {
            let label = trimmed[..colon_pos].trim();
            let value = trimmed[colon_pos + 1..].trim();
            if !label.is_empty()
                && !value.is_empty()
                && label.len() <= 40
                && !label.contains('/')
                && !label.contains('.')
            {
                current_findings.push(json!({
                    "type": "stat",
                    "label": label,
                    "value": value,
                }));
                continue;
            }
        }

        // Other non-empty lines
        if !trimmed.is_empty()
            && !trimmed.starts_with('▸')
            && !trimmed.chars().all(|c| c == '─' || c == '═')
        {
            current_findings.push(json!({
                "type": "info",
                "message": trimmed,
            }));
        }
    }

    // Flush last section
    if !current_title.is_empty() {
        sections.push(json!({
            "title": current_title,
            "findings": current_findings,
        }));
    }

    sections
}
