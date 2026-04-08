use git2::{ObjectType, Repository, TreeWalkMode, TreeWalkResult};
use regex::Regex;
use std::collections::HashMap;

use crate::display;

const DEFAULT_THRESHOLD: usize = 10;

struct FunctionComplexity {
    file: String,
    name: String,
    line: usize,
    complexity: usize,
}

/// Supported languages and their function-detection patterns
struct LanguageRules {
    extensions: &'static [&'static str],
    func_pattern: Regex,
    /// Keywords/operators that add to cyclomatic complexity
    branch_patterns: Vec<Regex>,
}

fn language_rules() -> Vec<LanguageRules> {
    vec![
        // Rust
        LanguageRules {
            extensions: &[".rs"],
            func_pattern: Regex::new(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)").unwrap(),
            branch_patterns: vec![
                Regex::new(r"\bif\b").unwrap(),
                Regex::new(r"\belse\s+if\b").unwrap(),
                Regex::new(r"\bwhile\b").unwrap(),
                Regex::new(r"\bfor\b").unwrap(),
                Regex::new(r"\bloop\b").unwrap(),
                Regex::new(r"\bmatch\b").unwrap(),
                Regex::new(r"=>").unwrap(), // match arms
                Regex::new(r"&&").unwrap(),
                Regex::new(r"\|\|").unwrap(),
                Regex::new(r"\?").unwrap(), // error propagation
            ],
        },
        // Go
        LanguageRules {
            extensions: &[".go"],
            func_pattern: Regex::new(r"^\s*func\s+(?:\([^)]*\)\s+)?(\w+)").unwrap(),
            branch_patterns: vec![
                Regex::new(r"\bif\b").unwrap(),
                Regex::new(r"\belse\s+if\b").unwrap(),
                Regex::new(r"\bfor\b").unwrap(),
                Regex::new(r"\bcase\b").unwrap(),
                Regex::new(r"\bselect\b").unwrap(),
                Regex::new(r"&&").unwrap(),
                Regex::new(r"\|\|").unwrap(),
            ],
        },
        // TypeScript / JavaScript
        LanguageRules {
            extensions: &[".ts", ".tsx", ".js", ".jsx"],
            func_pattern: Regex::new(
                r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>)",
            )
            .unwrap(),
            branch_patterns: vec![
                Regex::new(r"\bif\b").unwrap(),
                Regex::new(r"\belse\s+if\b").unwrap(),
                Regex::new(r"\bfor\b").unwrap(),
                Regex::new(r"\bwhile\b").unwrap(),
                Regex::new(r"\bcase\b").unwrap(),
                Regex::new(r"\bcatch\b").unwrap(),
                Regex::new(r"\?\?").unwrap(), // nullish coalescing
                Regex::new(r"\?\.\w").unwrap(), // optional chaining
                Regex::new(r"&&").unwrap(),
                Regex::new(r"\|\|").unwrap(),
                Regex::new(r"\?[^?.:}]").unwrap(), // ternary
            ],
        },
        // Python
        LanguageRules {
            extensions: &[".py"],
            func_pattern: Regex::new(r"^\s*(?:async\s+)?def\s+(\w+)").unwrap(),
            branch_patterns: vec![
                Regex::new(r"\bif\b").unwrap(),
                Regex::new(r"\belif\b").unwrap(),
                Regex::new(r"\bfor\b").unwrap(),
                Regex::new(r"\bwhile\b").unwrap(),
                Regex::new(r"\bexcept\b").unwrap(),
                Regex::new(r"\band\b").unwrap(),
                Regex::new(r"\bor\b").unwrap(),
            ],
        },
        // Java
        LanguageRules {
            extensions: &[".java"],
            func_pattern: Regex::new(
                r"^\s*(?:public|private|protected|static|final|abstract|synchronized|native)*\s*(?:\w+(?:<[^>]*>)?)\s+(\w+)\s*\(",
            )
            .unwrap(),
            branch_patterns: vec![
                Regex::new(r"\bif\b").unwrap(),
                Regex::new(r"\belse\s+if\b").unwrap(),
                Regex::new(r"\bfor\b").unwrap(),
                Regex::new(r"\bwhile\b").unwrap(),
                Regex::new(r"\bcase\b").unwrap(),
                Regex::new(r"\bcatch\b").unwrap(),
                Regex::new(r"&&").unwrap(),
                Regex::new(r"\|\|").unwrap(),
                Regex::new(r"\?[^?.:}]").unwrap(), // ternary
            ],
        },
    ]
}

/// Compute cyclomatic complexity for functions in a source file.
/// Uses brace-counting to track function boundaries.
fn analyze_file(content: &str, rules: &LanguageRules, is_python: bool) -> Vec<(String, usize, usize)> {
    let lines: Vec<&str> = content.lines().collect();
    let mut results: Vec<(String, usize, usize)> = Vec::new(); // (name, line, complexity)

    if is_python {
        // Python: use indentation to determine function scope
        let mut i = 0;
        while i < lines.len() {
            if let Some(caps) = rules.func_pattern.captures(lines[i]) {
                let func_name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                if func_name.is_empty() {
                    i += 1;
                    continue;
                }
                let func_line = i + 1;

                // Determine the indentation of the def line
                let def_indent = lines[i].len() - lines[i].trim_start().len();
                let body_indent = def_indent + 1; // anything indented more than def

                let mut complexity = 1usize;
                let mut j = i + 1;
                while j < lines.len() {
                    let line = lines[j];
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        j += 1;
                        continue;
                    }
                    let cur_indent = line.len() - line.trim_start().len();
                    if cur_indent <= def_indent && !trimmed.is_empty() {
                        break; // left the function
                    }
                    if cur_indent >= body_indent {
                        for pattern in &rules.branch_patterns {
                            complexity += pattern.find_iter(line).count();
                        }
                    }
                    j += 1;
                }
                results.push((func_name, func_line, complexity));
                i = j;
            } else {
                i += 1;
            }
        }
    } else {
        // Brace-based languages: track { } depth
        let mut i = 0;
        while i < lines.len() {
            if let Some(caps) = rules.func_pattern.captures(lines[i]) {
                let func_name = caps.get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                if func_name.is_empty() {
                    i += 1;
                    continue;
                }
                let func_line = i + 1;

                // Find the opening brace
                let mut brace_depth = 0i32;
                let mut found_open = false;
                let mut complexity = 1usize;
                let mut j = i;

                while j < lines.len() {
                    let line = lines[j];
                    for ch in line.chars() {
                        if ch == '{' {
                            brace_depth += 1;
                            found_open = true;
                        } else if ch == '}' {
                            brace_depth -= 1;
                        }
                    }

                    if found_open && j > i {
                        // Count branch patterns in function body
                        for pattern in &rules.branch_patterns {
                            complexity += pattern.find_iter(line).count();
                        }
                    }

                    if found_open && brace_depth <= 0 {
                        break;
                    }
                    j += 1;
                }

                results.push((func_name, func_line, complexity));
                i = j + 1;
            } else {
                i += 1;
            }
        }
    }

    results
}

/// Compute and report cyclomatic complexity for source files
pub fn complexity_scan(repo: &Repository, threshold: usize, top_n: usize, ignore_dirs: &[String]) -> Result<(), git2::Error> {
    display::print_sub_header("Cyclomatic Complexity Analysis");

    let head = repo.head()?.peel_to_tree()?;
    let rules = language_rules();
    let skip_dirs = ["vendor/", "node_modules/", ".git/", "target/", "dist/", "build/"];

    let mut all_functions: Vec<FunctionComplexity> = Vec::new();
    let mut file_stats: HashMap<String, (usize, usize)> = HashMap::new(); // ext -> (files, functions)

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let path = format!("{}{}", dir, entry.name().unwrap_or(""));

        if skip_dirs.iter().any(|d| path.starts_with(d))
            || ignore_dirs.iter().any(|d| {
                let normalized = if d.ends_with('/') { d.clone() } else { format!("{d}/") };
                path.starts_with(&normalized)
            })
        {
            return TreeWalkResult::Ok;
        }

        // Find matching language rules
        let matching_rules = rules.iter().find(|r| {
            r.extensions.iter().any(|ext| path.ends_with(ext))
        });

        let lang_rules = match matching_rules {
            Some(r) => r,
            None => return TreeWalkResult::Ok,
        };

        let is_python = lang_rules.extensions.contains(&".py");
        let ext = lang_rules.extensions[0].to_string();

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                let functions = analyze_file(content, lang_rules, is_python);
                if !functions.is_empty() {
                    let stats = file_stats.entry(ext).or_insert((0, 0));
                    stats.0 += 1;
                    stats.1 += functions.len();

                    for (name, line, complexity) in functions {
                        all_functions.push(FunctionComplexity {
                            file: path.clone(),
                            name,
                            line,
                            complexity,
                        });
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    if all_functions.is_empty() {
        display::print_info("No functions found to analyze");
        return Ok(());
    }

    // Summary
    let total_functions = all_functions.len();
    let above_threshold = all_functions.iter().filter(|f| f.complexity > threshold).count();
    let avg_complexity: f64 = all_functions.iter().map(|f| f.complexity as f64).sum::<f64>() / total_functions as f64;

    display::print_summary_stat("Functions analyzed", &total_functions.to_string());
    display::print_summary_stat("Average complexity", &format!("{avg_complexity:.1}"));
    display::print_summary_stat("Complexity threshold", &threshold.to_string());

    if above_threshold > 0 {
        display::print_warning(&format!("{above_threshold} functions exceed threshold of {threshold}"));
    } else {
        display::print_ok(&format!("All functions are within complexity threshold ({threshold})"));
    }

    // Language breakdown
    display::out("");
    display::out("    \x1b[1mFiles analyzed by language:\x1b[0m");
    let lang_rows: Vec<Vec<String>> = file_stats
        .iter()
        .map(|(ext, (files, funcs))| vec![ext.clone(), files.to_string(), funcs.to_string()])
        .collect();
    display::print_table(&["Extension", "Files", "Functions"], &lang_rows);

    // Top N most complex functions
    all_functions.sort_by(|a, b| b.complexity.cmp(&a.complexity));
    let top: Vec<&FunctionComplexity> = all_functions.iter().take(top_n).collect();

    display::out("");
    display::out(&format!("    \x1b[1mTop {top_n} Most Complex Functions:\x1b[0m"));
    let rows: Vec<Vec<String>> = top
        .iter()
        .map(|f| {
            let status = if f.complexity > threshold {
                format!("\x1b[31m{}\x1b[0m", f.complexity)
            } else {
                f.complexity.to_string()
            };
            vec![
                f.file.clone(),
                f.name.clone(),
                format!("L{}", f.line),
                status,
            ]
        })
        .collect();
    display::print_table(&["File", "Function", "Line", "Complexity"], &rows);

    Ok(())
}

/// Run complexity scan with default settings
pub fn run(repo: &Repository, ignore_dirs: &[String]) -> Result<(), git2::Error> {
    complexity_scan(repo, DEFAULT_THRESHOLD, 20, ignore_dirs)
}
