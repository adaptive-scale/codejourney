# CodeJourney

A comprehensive Rust CLI that audits any git repository for code quality, security, license compliance, and project health — producing rich terminal output and exportable reports in PDF, HTML, JSON, and Markdown.

## Why CodeJourney

As part of funding due diligence, companies are often asked to provide an overview of their intellectual property. Too often, that overview is assembled ad hoc and fails to reflect the true state of the codebase. CodeJourney delivers real, reproducible metrics on your code and other IP assets, giving investors an accurate and verifiable picture.

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/codejourney`.

## Features

### Repository Analytics
- Repository overview — total commits, branches, tags, first/last commit, active span
- Commit velocity — yearly, daily, and weekly averages
- Top contributors with bar charts
- Lines added/removed per author
- Monthly commit frequency with sparklines
- Activity heatmaps by day of week and hour of day
- Most frequently changed files and code churn analysis
- Bug-fix hotspot files
- Emergency commits (reverts, hotfixes, rollbacks)
- Merge frequency by month
- Largest tracked files
- Stale files sorted by last modification

### Security Audit
- Secret and credential detection in source files (passwords, API keys, AWS keys, Base64 blobs)
- Dangerous code patterns — SQL injection, command injection, disabled TLS, weak crypto, CORS wildcards
- Sensitive files committed to the repository (`.env`, `*.key`, `*.pem`, keystores)
- Hardcoded IP address detection
- Commits mentioning secrets or credentials
- Commits touching security-sensitive files (auth, session, crypto, permissions)
- `.gitignore` coverage check for common sensitive patterns

### License Compliance
- Detects project license from manifest files (`Cargo.toml`, `package.json`, `go.mod`)
- **Reads `LICENSE`/`COPYING` files and identifies the actual license type** by matching against known SPDX license text signatures
- Supports MIT, Apache-2.0, GPL-2.0/3.0, AGPL-3.0, LGPL-2.1/3.0, BSD-2/3-Clause, MPL-2.0, EPL-1.0/2.0, Unlicense, CC0, BSL-1.0, Zlib, WTFPL, Artistic-2.0, CDDL, ISC, 0BSD
- SPDX-License-Identifier header detection as fallback
- Confidence scoring (high / medium / low)
- Categorizes licenses as permissive, weak copyleft, or strong copyleft
- Warns on copyleft conflicts and missing license declarations

### Cyclomatic Complexity Analysis
- Per-function complexity scoring across Rust, Go, TypeScript/JavaScript, Python, and Java
- Configurable threshold with warnings for functions exceeding limits
- Top N most complex functions report
- Per-language file and function counts

### SAST (Static Application Security Testing)
- Taint analysis for SQL injection (string interpolation in queries)
- Insecure deserialization (Python pickle, yaml.load, Java ObjectInputStream, PHP unserialize)
- Path traversal detection
- Unsafe `eval()`, `exec()`, `Function` constructor, dynamic imports
- Rust `unsafe` blocks and raw pointer usage
- JavaScript prototype pollution patterns
- Go template injection
- Shell command execution with user input
- Findings grouped by severity (HIGH / MEDIUM / INFO)

### SCA (Software Composition Analysis)
- Parses lockfiles: `Cargo.lock`, `package-lock.json`, `go.sum`, `requirements.txt`
- Full dependency listing per lockfile
- Detection of unpinned or loose version constraints
- Pre-release / 0.x version flagging for stability risk

### Dependency Graph & Reachability
- Builds an inter-package dependency graph across the repo
- Exports as DOT format (convert to SVG with `dot -Tsvg -o deps.svg deps.dot`)
- Detects circular dependencies and unused phantom dependencies

### Fix Suggestions & Autofix
- Generates remediation hints for SAST findings
- Suggests version bumps for vulnerable dependencies
- Refactoring proposals for high-complexity functions

### Historical Tracking
- Stores scan results in a local SQLite database
- Trend charts for complexity, vulnerability count, and license drift over time

### Report Generation
- **PDF** — styled multi-page report with charts and tables
- **HTML** — interactive report with Tailwind CSS, Chart.js bar charts, and **collapsible sections**
- **JSON** — structured machine-readable output for CI/CD integration
- **Markdown** — concise summary suitable for PR comments

## Usage

### Repository Scan

```bash
codejourney scan                           # Full analytics + security + advanced analysis
codejourney scan --analytics-only          # Analytics only
codejourney scan --security-only           # Security audit only
codejourney scan --path /other/repo        # Scan a different repository
```

### Report Exports

```bash
codejourney scan --pdf report.pdf          # Export to PDF
codejourney scan --html report.html        # Export to interactive HTML
codejourney scan --json report.json        # Export to JSON
codejourney scan --markdown report.md      # Export to Markdown (PR-friendly)
codejourney scan --dot deps.dot            # Export dependency graph as DOT
```

You can combine multiple export flags in a single run:

```bash
codejourney scan --pdf report.pdf --html report.html --json report.json
```

### Filtering

```bash
codejourney scan --ignore-dirs docs,examples,fixtures
```

Built-in skip directories (`vendor/`, `node_modules/`, `target/`, `.git/`, `dist/`, `build/`) are always excluded; `--ignore-dirs` adds to this list.

### Historical Tracking

```bash
codejourney scan --history-db ./scans.db   # Store this scan in SQLite history
codejourney scan --show-trends             # Display trend charts from history
```

### HTTP Server

```bash
codejourney serve --port 3000              # Start HTTP API server
```

All responses follow `{"ok": true, "data": ...}` / `{"ok": false, "error": "..."}`.
