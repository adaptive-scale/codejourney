# Codejourney

A Rust CLI tool that combines native git operations with deep repository analytics and security auditing. Analyze commit history, contributor activity, code health, and security posture — all from your terminal.

## Features

- **Native Git Client** — init, status, add, commit, log, branch, checkout, and diff powered by `libgit2` (no shell dependency on git)
- **Repository Analytics** — commit velocity, contributor stats, code churn, bug-fix hotspots, stale files, and more
- **Security Audit** — detects leaked secrets, dangerous code patterns, sensitive files, hardcoded IPs, and `.gitignore` coverage gaps
- **HTTP Server Mode** — expose git status, log, and diff as JSON REST endpoints

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/codejourney`.

## Usage

### Git Operations

```bash
codejourney init [path]              # Initialize a new repository
codejourney status                   # Show working tree status
codejourney add <files...>           # Stage files (use . for all)
codejourney commit -m "message"      # Create a commit
codejourney log [-c 20]              # Show recent commits (default: 10)
codejourney branch <name>            # Create a new branch
codejourney checkout <name>          # Switch branches
codejourney diff                     # Show working directory diff
```

### Repository Scan

```bash
codejourney scan                     # Full analytics + security audit
codejourney scan --analytics-only    # Analytics only
codejourney scan --security-only     # Security audit only
codejourney scan --path /other/repo  # Scan a different repository
```

#### Analytics

The scan produces rich terminal output covering:

- Repository overview (total commits, branches, tags, active span)
- Commit velocity (yearly, daily, and weekly averages)
- Top contributors with bar charts
- Lines added/removed per author
- Monthly commit frequency with sparklines
- Activity by day of week and hour of day
- Most frequently changed files
- Code churn across recent commits
- Bug-fix hotspot files
- Emergency commits (reverts, hotfixes, rollbacks)
- Merge frequency by month
- Largest tracked files
- Stale files sorted by last modification

#### Security Audit

The security scan checks for:

- Secrets and credentials in source files (passwords, API keys, AWS keys, Base64 blobs)
- Dangerous code patterns (SQL injection, command injection, disabled TLS, weak crypto, CORS wildcards)
- Sensitive files committed to the repository (`.env`, `*.key`, `*.pem`, etc.)
- Hardcoded IP addresses
- Commits mentioning secrets or credentials
- Commits touching security-sensitive files (auth, session, crypto, permissions)
- `.gitignore` coverage for common sensitive file patterns

### HTTP Server

```bash
codejourney serve              # Start on port 3000
codejourney serve --port 8080  # Custom port
```

Endpoints:

| Endpoint | Description |
|---|---|
| `GET /health` | Health check |
| `GET /status` | Repository file status |
| `GET /log?count=N` | Recent commits |
| `GET /diff` | Working directory diff |

All responses follow `{"ok": true, "data": ...}` / `{"ok": false, "error": "..."}`.

## Dependencies

- [git2](https://crates.io/crates/git2) — libgit2 bindings
- [clap](https://crates.io/crates/clap) — CLI argument parsing
- [axum](https://crates.io/crates/axum) + [tokio](https://crates.io/crates/tokio) — HTTP server
- [chrono](https://crates.io/crates/chrono) — date/time handling
- [regex](https://crates.io/crates/regex) — pattern matching for security scans
- [serde](https://crates.io/crates/serde) + [serde_json](https://crates.io/crates/serde_json) — JSON serialization

## Roadmap

- [ ] **License compliance checks** — detect and report license types across dependencies
- [ ] **Cyclomatic complexity analysis** — measure code complexity per function/module
- [ ] **SAST (Static Application Security Testing)** — deeper static analysis for vulnerability detection
- [ ] **SCA (Software Composition Analysis)** — scan dependencies for known CVEs and outdated packages
