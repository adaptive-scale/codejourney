use git2::{ObjectType, Repository, TreeWalkMode, TreeWalkResult};
use regex::Regex;

use crate::display;

// ── Version bump suggestions ─────────────────────────────────────

/// Known CVE database (embedded – a practical subset for common packages).
/// In production this would query an external advisory database.
struct KnownCve {
    package: &'static str,
    ecosystem: &'static str,
    affected_below: &'static str,
    fixed_version: &'static str,
    cve_id: &'static str,
    severity: &'static str,
    summary: &'static str,
}

fn known_cves() -> Vec<KnownCve> {
    vec![
        // Node.js
        KnownCve {
            package: "lodash",
            ecosystem: "npm",
            affected_below: "4.17.21",
            fixed_version: "4.17.21",
            cve_id: "CVE-2021-23337",
            severity: "HIGH",
            summary: "Command injection via template function",
        },
        KnownCve {
            package: "minimist",
            ecosystem: "npm",
            affected_below: "1.2.6",
            fixed_version: "1.2.6",
            cve_id: "CVE-2021-44906",
            severity: "CRITICAL",
            summary: "Prototype pollution",
        },
        KnownCve {
            package: "node-fetch",
            ecosystem: "npm",
            affected_below: "2.6.7",
            fixed_version: "2.6.7",
            cve_id: "CVE-2022-0235",
            severity: "HIGH",
            summary: "Exposure of sensitive information to an unauthorized actor",
        },
        KnownCve {
            package: "express",
            ecosystem: "npm",
            affected_below: "4.19.2",
            fixed_version: "4.19.2",
            cve_id: "CVE-2024-29041",
            severity: "MEDIUM",
            summary: "Open redirect via URL parsing",
        },
        KnownCve {
            package: "json5",
            ecosystem: "npm",
            affected_below: "2.2.2",
            fixed_version: "2.2.2",
            cve_id: "CVE-2022-46175",
            severity: "HIGH",
            summary: "Prototype pollution in parse()",
        },
        KnownCve {
            package: "axios",
            ecosystem: "npm",
            affected_below: "1.6.0",
            fixed_version: "1.6.0",
            cve_id: "CVE-2023-45857",
            severity: "MEDIUM",
            summary: "CSRF token exposure via XSRF-TOKEN cookie",
        },
        KnownCve {
            package: "semver",
            ecosystem: "npm",
            affected_below: "7.5.2",
            fixed_version: "7.5.2",
            cve_id: "CVE-2022-25883",
            severity: "MEDIUM",
            summary: "Regular expression denial of service",
        },
        // Python
        KnownCve {
            package: "requests",
            ecosystem: "pypi",
            affected_below: "2.31.0",
            fixed_version: "2.31.0",
            cve_id: "CVE-2023-32681",
            severity: "MEDIUM",
            summary: "Unintended leak of Proxy-Authorization header",
        },
        KnownCve {
            package: "urllib3",
            ecosystem: "pypi",
            affected_below: "2.0.7",
            fixed_version: "2.0.7",
            cve_id: "CVE-2023-45803",
            severity: "MEDIUM",
            summary: "Request body not stripped after cross-origin redirect",
        },
        KnownCve {
            package: "django",
            ecosystem: "pypi",
            affected_below: "4.2.11",
            fixed_version: "4.2.11",
            cve_id: "CVE-2024-27351",
            severity: "HIGH",
            summary: "ReDoS in Truncator.words()",
        },
        KnownCve {
            package: "flask",
            ecosystem: "pypi",
            affected_below: "2.3.2",
            fixed_version: "2.3.2",
            cve_id: "CVE-2023-30861",
            severity: "HIGH",
            summary: "Session cookie set on every response when vary: cookie not set",
        },
        KnownCve {
            package: "pillow",
            ecosystem: "pypi",
            affected_below: "10.2.0",
            fixed_version: "10.2.0",
            cve_id: "CVE-2023-50447",
            severity: "CRITICAL",
            summary: "Arbitrary code execution via PIL.ImageMath.eval",
        },
        KnownCve {
            package: "jinja2",
            ecosystem: "pypi",
            affected_below: "3.1.3",
            fixed_version: "3.1.3",
            cve_id: "CVE-2024-22195",
            severity: "MEDIUM",
            summary: "XSS via xmlattr filter",
        },
        KnownCve {
            package: "cryptography",
            ecosystem: "pypi",
            affected_below: "42.0.0",
            fixed_version: "42.0.0",
            cve_id: "CVE-2023-49083",
            severity: "HIGH",
            summary: "NULL-dereference when loading PKCS7 certificates",
        },
        // Rust
        KnownCve {
            package: "hyper",
            ecosystem: "crates.io",
            affected_below: "0.14.27",
            fixed_version: "0.14.27",
            cve_id: "CVE-2023-26964",
            severity: "HIGH",
            summary: "HTTP/2 peer can cause excessive memory growth",
        },
        KnownCve {
            package: "regex",
            ecosystem: "crates.io",
            affected_below: "1.5.5",
            fixed_version: "1.5.5",
            cve_id: "CVE-2022-24713",
            severity: "HIGH",
            summary: "Regex denial of service",
        },
        KnownCve {
            package: "openssl",
            ecosystem: "crates.io",
            affected_below: "0.10.48",
            fixed_version: "0.10.48",
            cve_id: "CVE-2023-0286",
            severity: "HIGH",
            summary: "X.400 address type confusion in X.509 GeneralName",
        },
        // Go
        KnownCve {
            package: "golang.org/x/net",
            ecosystem: "go",
            affected_below: "0.17.0",
            fixed_version: "0.17.0",
            cve_id: "CVE-2023-44487",
            severity: "HIGH",
            summary: "HTTP/2 rapid reset attack",
        },
        KnownCve {
            package: "golang.org/x/crypto",
            ecosystem: "go",
            affected_below: "0.17.0",
            fixed_version: "0.17.0",
            cve_id: "CVE-2023-48795",
            severity: "MEDIUM",
            summary: "SSH prefix truncation attack (Terrapin)",
        },
        KnownCve {
            package: "github.com/gin-gonic/gin",
            ecosystem: "go",
            affected_below: "1.9.1",
            fixed_version: "1.9.1",
            cve_id: "CVE-2023-29401",
            severity: "HIGH",
            summary: "Improper handling of non-standard HTTP methods",
        },
    ]
}

/// Simple version comparison (semver-like). Returns true if `current < target`.
fn version_less_than(current: &str, target: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .filter_map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .ok()
            })
            .collect()
    };

    let a = parse(current);
    let b = parse(target);

    for i in 0..a.len().max(b.len()) {
        let va = a.get(i).copied().unwrap_or(0);
        let vb = b.get(i).copied().unwrap_or(0);
        if va < vb {
            return true;
        }
        if va > vb {
            return false;
        }
    }
    false
}

/// Dependency info extracted from lockfiles.
struct DepInfo {
    name: String,
    version: String,
    source: String,
}

fn collect_deps(repo: &Repository, ignore_dirs: &[String]) -> Result<Vec<DepInfo>, git2::Error> {
    let head = repo.head()?.peel_to_tree()?;
    let mut deps = Vec::new();
    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        let name = entry.name().unwrap_or("");
        let path = format!("{}{}", dir, name);

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

        let is_lockfile = matches!(
            name,
            "Cargo.lock" | "package-lock.json" | "go.sum" | "requirements.txt"
        );
        if !is_lockfile {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                match name {
                    "Cargo.lock" => parse_cargo_lock_deps(content, &mut deps),
                    "package-lock.json" => parse_npm_lock_deps(content, &mut deps),
                    "go.sum" => parse_go_sum_deps(content, &mut deps),
                    "requirements.txt" => parse_requirements_deps(content, &mut deps),
                    _ => {}
                }
            }
        }
        TreeWalkResult::Ok
    })?;

    Ok(deps)
}

fn parse_cargo_lock_deps(content: &str, deps: &mut Vec<DepInfo>) {
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                deps.push(DepInfo {
                    name: n,
                    version: v,
                    source: "Cargo.lock".into(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        }
    }
    if let (Some(n), Some(v)) = (current_name, current_version) {
        deps.push(DepInfo {
            name: n,
            version: v,
            source: "Cargo.lock".into(),
        });
    }
}

fn parse_npm_lock_deps(content: &str, deps: &mut Vec<DepInfo>) {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(packages) = val.get("packages").and_then(|v| v.as_object()) {
            for (path, info) in packages {
                if path.is_empty() {
                    continue;
                }
                let name = path
                    .rsplit("node_modules/")
                    .next()
                    .unwrap_or(path)
                    .to_string();
                let version = info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                deps.push(DepInfo {
                    name,
                    version,
                    source: "package-lock.json".into(),
                });
            }
        }
    }
}

fn parse_go_sum_deps(content: &str, deps: &mut Vec<DepInfo>) {
    let mut seen = std::collections::HashSet::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let version = parts[1].trim_end_matches("/go.mod").to_string();
            if seen.insert(name.clone()) {
                deps.push(DepInfo {
                    name,
                    version,
                    source: "go.sum".into(),
                });
            }
        }
    }
}

fn parse_requirements_deps(content: &str, deps: &mut Vec<DepInfo>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        let (name, version) = if let Some(pos) = trimmed.find("==") {
            (
                trimmed[..pos].trim().to_string(),
                trimmed[pos + 2..].trim().to_string(),
            )
        } else if let Some(pos) = trimmed.find(">=") {
            (
                trimmed[..pos].trim().to_string(),
                format!(">={}", trimmed[pos + 2..].trim()),
            )
        } else {
            (trimmed.to_string(), "unpinned".to_string())
        };

        let clean_name = if let Some(pos) = name.find('[') {
            name[..pos].to_string()
        } else {
            name
        };
        deps.push(DepInfo {
            name: clean_name,
            version,
            source: "requirements.txt".into(),
        });
    }
}

// ── Complexity refactoring hints ─────────────────────────────────

struct ComplexFunction {
    file: String,
    name: String,
    line: usize,
    complexity: usize,
}

fn find_complex_functions(
    repo: &Repository,
    threshold: usize,
    ignore_dirs: &[String],
) -> Result<Vec<ComplexFunction>, git2::Error> {
    let head = repo.head()?.peel_to_tree()?;
    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    let func_patterns: Vec<(&[&str], Regex, bool)> = vec![
        (
            &[".rs"],
            Regex::new(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)").unwrap(),
            false,
        ),
        (
            &[".go"],
            Regex::new(r"^\s*func\s+(?:\([^)]*\)\s+)?(\w+)").unwrap(),
            false,
        ),
        (
            &[".py"],
            Regex::new(r"^\s*(?:async\s+)?def\s+(\w+)").unwrap(),
            true,
        ),
        (
            &[".ts", ".tsx", ".js", ".jsx"],
            Regex::new(r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=)").unwrap(),
            false,
        ),
        (
            &[".java"],
            Regex::new(r"^\s*(?:public|private|protected|static|final|abstract|synchronized|native)*\s*(?:\w+(?:<[^>]*>)?)\s+(\w+)\s*\(").unwrap(),
            false,
        ),
    ];

    let branch_kws = [
        "if", "else if", "elif", "for", "while", "loop", "match", "case", "catch", "except",
    ];

    let mut results = Vec::new();

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
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

        let matching = func_patterns
            .iter()
            .find(|(exts, _, _)| exts.iter().any(|ext| path.ends_with(ext)));
        let (_, ref func_pat, is_python) = match matching {
            Some(m) => m,
            None => return TreeWalkResult::Ok,
        };

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                let lines: Vec<&str> = content.lines().collect();
                let mut i = 0;
                while i < lines.len() {
                    if let Some(caps) = func_pat.captures(lines[i]) {
                        let func_name = caps
                            .get(1)
                            .or_else(|| caps.get(2))
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default();
                        if func_name.is_empty() {
                            i += 1;
                            continue;
                        }
                        let func_line = i + 1;
                        let mut complexity = 1usize;

                        if *is_python {
                            let def_indent = lines[i].len() - lines[i].trim_start().len();
                            let mut j = i + 1;
                            while j < lines.len() {
                                let line = lines[j];
                                let trimmed = line.trim();
                                if trimmed.is_empty() || trimmed.starts_with('#') {
                                    j += 1;
                                    continue;
                                }
                                let cur_indent = line.len() - line.trim_start().len();
                                if cur_indent <= def_indent {
                                    break;
                                }
                                for kw in &branch_kws {
                                    if trimmed.contains(kw) {
                                        complexity += 1;
                                    }
                                }
                                j += 1;
                            }
                            i = j;
                        } else {
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
                            i = j + 1;
                        }

                        if complexity > threshold {
                            results.push(ComplexFunction {
                                file: path.clone(),
                                name: func_name,
                                line: func_line,
                                complexity,
                            });
                        }
                    } else {
                        i += 1;
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    results.sort_by(|a, b| b.complexity.cmp(&a.complexity));
    Ok(results)
}

/// Generate refactoring hints for complex functions.
fn refactoring_hint(func: &ComplexFunction) -> String {
    let mut hints = Vec::new();

    if func.complexity > 30 {
        hints.push("Consider splitting this function into multiple smaller functions");
        hints.push("Extract distinct logical blocks into separate helper functions");
    } else if func.complexity > 20 {
        hints.push("Extract conditional branches into well-named helper functions");
        hints.push("Consider using early returns to reduce nesting depth");
    } else if func.complexity > 10 {
        hints.push("Look for repeated patterns that can be extracted into helpers");
        hints.push("Consider using guard clauses (early returns) for preconditions");
    }

    if func.file.ends_with(".rs") {
        hints.push("Consider using match arms with extracted functions");
    } else if func.file.ends_with(".py") {
        hints.push("Consider using dictionary dispatch instead of long if/elif chains");
    } else if func.file.ends_with(".go") {
        hints.push("Consider using table-driven tests or switch with extracted functions");
    } else if func.file.ends_with(".ts")
        || func.file.ends_with(".tsx")
        || func.file.ends_with(".js")
        || func.file.ends_with(".jsx")
    {
        hints.push("Consider using a strategy/map pattern instead of complex conditionals");
    }

    hints.join("; ")
}

// ── SAST remediation guidance ────────────────────────────────────

struct SastRemediation {
    pattern_name: &'static str,
    guidance: &'static str,
    code_example: &'static str,
}

fn sast_remediations() -> Vec<SastRemediation> {
    vec![
        SastRemediation {
            pattern_name: "SQL injection",
            guidance: "Use parameterized queries instead of string interpolation",
            code_example: "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
        },
        SastRemediation {
            pattern_name: "command injection",
            guidance: "Use subprocess with shell=False and pass arguments as a list",
            code_example: "subprocess.run([\"cmd\", arg1, arg2], shell=False)",
        },
        SastRemediation {
            pattern_name: "pickle",
            guidance: "Use json or msgpack for serialization instead of pickle",
            code_example: "data = json.loads(untrusted_input)",
        },
        SastRemediation {
            pattern_name: "yaml.load",
            guidance: "Use yaml.safe_load() or specify SafeLoader",
            code_example: "data = yaml.load(stream, Loader=yaml.SafeLoader)",
        },
        SastRemediation {
            pattern_name: "ObjectInputStream",
            guidance: "Implement ObjectInputFilter to validate deserialized classes",
            code_example: "ObjectInputFilter.Config.setSerialFilter(filter);",
        },
        SastRemediation {
            pattern_name: "eval",
            guidance: "Avoid eval(); use safer alternatives like JSON.parse or AST-based parsing",
            code_example: "const data = JSON.parse(input);",
        },
        SastRemediation {
            pattern_name: "innerHTML",
            guidance: "Use textContent for plain text or sanitize with DOMPurify",
            code_example: "element.textContent = userInput; // or DOMPurify.sanitize(html)",
        },
        SastRemediation {
            pattern_name: "dangerouslySetInnerHTML",
            guidance: "Sanitize the HTML before rendering with DOMPurify",
            code_example: "dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}",
        },
        SastRemediation {
            pattern_name: "prototype pollution",
            guidance: "Validate and sanitize object keys; use Object.create(null) for dictionaries",
            code_example: "const safeObj = Object.create(null);",
        },
        SastRemediation {
            pattern_name: "path traversal",
            guidance: "Use path.resolve() and verify the result is within an allowed directory",
            code_example: "const resolved = path.resolve(basedir, userInput); if (!resolved.startsWith(basedir)) throw Error();",
        },
        SastRemediation {
            pattern_name: "weak hash",
            guidance: "Replace MD5/SHA1 with SHA-256 or stronger",
            code_example: "hashlib.sha256(data).hexdigest()",
        },
        SastRemediation {
            pattern_name: "Math.random",
            guidance: "Use crypto.getRandomValues() or crypto.randomBytes() for security-sensitive values",
            code_example: "const token = crypto.randomBytes(32).toString('hex');",
        },
        SastRemediation {
            pattern_name: "TLS",
            guidance: "Never disable TLS certificate verification in production",
            code_example: "// Remove NODE_TLS_REJECT_UNAUTHORIZED=0 and rejectUnauthorized: false",
        },
        SastRemediation {
            pattern_name: "CORS",
            guidance: "Specify allowed origins explicitly instead of using wildcard",
            code_example: "res.setHeader('Access-Control-Allow-Origin', 'https://trusted.example.com');",
        },
        SastRemediation {
            pattern_name: "JWT",
            guidance: "Store JWT secrets in environment variables, never hardcode them",
            code_example: "const secret = process.env.JWT_SECRET; jwt.sign(payload, secret);",
        },
        SastRemediation {
            pattern_name: "SSRF",
            guidance: "Validate and allowlist URLs before making requests; block internal IPs",
            code_example: "if (!isAllowedUrl(url)) throw new Error('URL not allowed');",
        },
        SastRemediation {
            pattern_name: "XSS",
            guidance: "Sanitize all user input before rendering; use framework auto-escaping",
            code_example: "{{ user_input | escape }}",
        },
        SastRemediation {
            pattern_name: "SSTI",
            guidance: "Never pass user input directly to template engines; use sandboxed environments",
            code_example: "env = SandboxedEnvironment(); template = env.from_string(safe_template)",
        },
        SastRemediation {
            pattern_name: "debug",
            guidance: "Disable debug mode in production; use environment variables to control",
            code_example: "app.run(debug=os.environ.get('FLASK_DEBUG', 'false') == 'true')",
        },
        SastRemediation {
            pattern_name: "unsafe",
            guidance: "Minimize unsafe blocks; document invariants; consider safe abstractions",
            code_example: "// SAFETY: pointer is valid and aligned because ...",
        },
    ]
}

// ── SAST finding structure (simplified re-scan) ──────────────────

struct SastFinding {
    file: String,
    line: usize,
    rule_name: String,
    severity: String,
    description: String,
    source_line: String,
}

fn collect_sast_findings(
    repo: &Repository,
    ignore_dirs: &[String],
) -> Result<Vec<SastFinding>, git2::Error> {
    let head = repo.head()?.peel_to_tree()?;
    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    // Simplified rules for matching
    let rules: Vec<(&str, &str, Regex, &[&str], &str)> = vec![
        (
            "SQL injection",
            "HIGH",
            Regex::new(r#"(?i)(execute|query|raw)\s*\(.*(\+|format!|f"|fmt\.Sprintf)"#).unwrap(),
            &[".rs", ".go", ".py", ".ts", ".js", ".java"],
            "User input may flow into SQL query",
        ),
        (
            "Insecure deserialization (pickle)",
            "HIGH",
            Regex::new(r"pickle\.(loads?|Unpickler)\(").unwrap(),
            &[".py"],
            "pickle can execute arbitrary code from untrusted data",
        ),
        (
            "eval() usage",
            "HIGH",
            Regex::new(r"\beval\s*\(").unwrap(),
            &[".js", ".ts", ".py", ".php"],
            "eval() executes arbitrary code",
        ),
        (
            "innerHTML assignment",
            "MEDIUM",
            Regex::new(r"\.innerHTML\s*=").unwrap(),
            &[".js", ".ts", ".tsx", ".jsx"],
            "innerHTML can lead to XSS",
        ),
        (
            "Weak hash (MD5/SHA1)",
            "MEDIUM",
            Regex::new(r"(?i)(md5|sha-?1)\s*\(").unwrap(),
            &[".py", ".java", ".go", ".js", ".ts"],
            "MD5/SHA1 are cryptographically weak",
        ),
        (
            "Hardcoded secret",
            "HIGH",
            Regex::new(r#"(?i)(SECRET_KEY|API_KEY|PASSWORD)\s*=\s*['"][^'"]{4,}['"]"#).unwrap(),
            &[".py", ".js", ".ts", ".java", ".rb"],
            "Secret appears hardcoded",
        ),
        (
            "Disabled TLS verification",
            "HIGH",
            Regex::new(r"(?i)(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)").unwrap(),
            &[".js", ".ts", ".py", ".go"],
            "TLS verification is disabled",
        ),
        (
            "Unsafe block (Rust)",
            "INFO",
            Regex::new(r"\bunsafe\s*\{").unwrap(),
            &[".rs"],
            "Unsafe block requires careful review",
        ),
    ];

    let mut findings = Vec::new();

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
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
        if path.contains("_test.")
            || path.contains(".test.")
            || path.contains("/test/")
            || path.contains("/tests/")
        {
            return TreeWalkResult::Ok;
        }

        let any = rules
            .iter()
            .any(|(_, _, _, exts, _)| exts.iter().any(|ext| path.ends_with(ext)));
        if !any {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for (line_num, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//")
                        || trimmed.starts_with('#')
                        || trimmed.starts_with("/*")
                        || trimmed.starts_with('*')
                    {
                        continue;
                    }
                    for (name, severity, pattern, exts, desc) in &rules {
                        if !exts.iter().any(|ext| path.ends_with(ext)) {
                            continue;
                        }
                        if pattern.is_match(line) {
                            findings.push(SastFinding {
                                file: path.clone(),
                                line: line_num + 1,
                                rule_name: name.to_string(),
                                severity: severity.to_string(),
                                description: desc.to_string(),
                                source_line: trimmed.to_string(),
                            });
                        }
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    Ok(findings)
}

// ── Public API ───────────────────────────────────────────────────

/// Run fix suggestions & autofix analysis.
pub fn autofix_scan(repo: &Repository, ignore_dirs: &[String]) -> Result<(), git2::Error> {
    display::print_sub_header("Fix Suggestions & Autofix");

    // 1. CVE version bump suggestions
    display::out("");
    display::out("    \x1b[1mDependency CVE Check:\x1b[0m");

    let deps = collect_deps(repo, ignore_dirs)?;
    let cves = known_cves();
    let mut cve_findings: Vec<(&KnownCve, &DepInfo)> = Vec::new();

    for dep in &deps {
        let dep_lower = dep.name.to_lowercase();
        for cve in &cves {
            if cve.package.to_lowercase() == dep_lower
                && version_less_than(&dep.version, cve.affected_below)
            {
                cve_findings.push((cve, dep));
            }
        }
    }

    if cve_findings.is_empty() {
        display::print_ok("No known CVEs found in current dependencies");
    } else {
        display::print_warning(&format!(
            "{} dependencies with known CVEs:",
            cve_findings.len()
        ));
        display::out("");

        let rows: Vec<Vec<String>> = cve_findings
            .iter()
            .map(|(cve, dep)| {
                vec![
                    dep.name.clone(),
                    dep.version.clone(),
                    format!("→ {}", cve.fixed_version),
                    cve.cve_id.to_string(),
                    cve.severity.to_string(),
                ]
            })
            .collect();
        display::print_table(
            &["Package", "Current", "Upgrade To", "CVE", "Severity"],
            &rows,
        );

        // Detailed remediation
        display::out("");
        display::out("    \x1b[1mRemediation Steps:\x1b[0m");
        for (cve, dep) in &cve_findings {
            display::out(&format!(
                "      \x1b[33m{}\x1b[0m {} → {}",
                dep.name, dep.version, cve.fixed_version
            ));
            display::out(&format!("        {}: {}", cve.cve_id, cve.summary));

            // Generate update command
            let cmd = match dep.source.as_str() {
                "Cargo.lock" => format!(
                    "        Run: cargo update -p {} --precise {}",
                    dep.name, cve.fixed_version
                ),
                "package-lock.json" => format!(
                    "        Run: npm install {}@{}",
                    dep.name, cve.fixed_version
                ),
                "go.sum" => format!(
                    "        Run: go get {}@v{}",
                    dep.name, cve.fixed_version
                ),
                "requirements.txt" => format!(
                    "        Run: pip install {}=={}",
                    dep.name, cve.fixed_version
                ),
                _ => String::new(),
            };
            if !cmd.is_empty() {
                display::out(&format!("\x1b[2m{cmd}\x1b[0m"));
            }
            display::out("");
        }
    }

    // 2. Complexity refactoring hints
    display::out("");
    display::out("    \x1b[1mRefactoring Suggestions (Complex Functions):\x1b[0m");

    let complex_fns = find_complex_functions(repo, 10, ignore_dirs)?;
    if complex_fns.is_empty() {
        display::print_ok("No functions exceed the complexity threshold");
    } else {
        display::print_warning(&format!(
            "{} functions exceed complexity threshold of 10:",
            complex_fns.len()
        ));
        display::out("");

        for func in complex_fns.iter().take(15) {
            display::out(&format!(
                "      \x1b[33m{}:{}\x1b[0m  fn \x1b[1m{}\x1b[0m (complexity: \x1b[31m{}\x1b[0m)",
                func.file, func.line, func.name, func.complexity
            ));
            let hint = refactoring_hint(func);
            display::out(&format!("        \x1b[2m→ {hint}\x1b[0m"));
            display::out("");
        }

        if complex_fns.len() > 15 {
            display::print_info(&format!(
                "... and {} more complex functions",
                complex_fns.len() - 15
            ));
        }
    }

    // 3. SAST inline remediation guidance
    display::out("");
    display::out("    \x1b[1mSAST Remediation Guidance:\x1b[0m");

    let sast_findings = collect_sast_findings(repo, ignore_dirs)?;
    let remediations = sast_remediations();

    if sast_findings.is_empty() {
        display::print_ok("No SAST findings requiring remediation");
    } else {
        display::print_warning(&format!(
            "{} SAST findings with remediation guidance:",
            sast_findings.len()
        ));
        display::out("");

        for finding in sast_findings.iter().take(20) {
            display::out(&format!(
                "      \x1b[33m{}:L{}\x1b[0m [{}] {}",
                finding.file, finding.line, finding.severity, finding.rule_name
            ));
            display::out(&format!(
                "        \x1b[2mCode: {}\x1b[0m",
                if finding.source_line.len() > 80 {
                    format!("{}...", &finding.source_line[..77])
                } else {
                    finding.source_line.clone()
                }
            ));

            // Find matching remediation
            let remediation = remediations.iter().find(|r| {
                finding
                    .rule_name
                    .to_lowercase()
                    .contains(&r.pattern_name.to_lowercase())
            });

            if let Some(rem) = remediation {
                display::out(&format!("        \x1b[32m→ Fix: {}\x1b[0m", rem.guidance));
                display::out(&format!(
                    "        \x1b[2m  Example: {}\x1b[0m",
                    rem.code_example
                ));
            } else {
                display::out(&format!(
                    "        \x1b[32m→ {}\x1b[0m",
                    finding.description
                ));
            }
            display::out("");
        }

        if sast_findings.len() > 20 {
            display::print_info(&format!(
                "... and {} more findings",
                sast_findings.len() - 20
            ));
        }
    }

    Ok(())
}
