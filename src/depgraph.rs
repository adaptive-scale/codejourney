use git2::{ObjectType, Repository, TreeWalkMode, TreeWalkResult};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use std::fs;

use crate::display;

/// A node in the dependency graph.
#[derive(Debug, Clone)]
struct DepNode {
    name: String,
    version: String,
    source: String, // which lockfile
}

/// An edge from one dependency to another.
#[derive(Debug, Clone)]
struct DepEdge {
    from: String,
    to: String,
}

/// Full dependency graph for a repository.
struct DepGraph {
    nodes: HashMap<String, DepNode>,
    edges: Vec<DepEdge>,
    /// Which packages are directly declared (manifest-level dependencies)
    direct_deps: HashSet<String>,
}

// ── Lockfile → graph builders ────────────────────────────────────

/// Build graph from Cargo.lock + Cargo.toml
fn build_cargo_graph(lock_content: &str, manifest_content: Option<&str>) -> DepGraph {
    let mut nodes = HashMap::new();
    let mut edges = Vec::new();
    let mut direct_deps = HashSet::new();

    // Parse Cargo.toml for direct dependencies
    if let Some(manifest) = manifest_content {
        if let Ok(val) = manifest.parse::<toml::Value>() {
            if let Some(deps) = val.get("dependencies").and_then(|v| v.as_table()) {
                for key in deps.keys() {
                    direct_deps.insert(key.clone());
                }
            }
            if let Some(deps) = val.get("dev-dependencies").and_then(|v| v.as_table()) {
                for key in deps.keys() {
                    direct_deps.insert(key.clone());
                }
            }
            if let Some(deps) = val.get("build-dependencies").and_then(|v| v.as_table()) {
                for key in deps.keys() {
                    direct_deps.insert(key.clone());
                }
            }
        }
    }

    // Parse Cargo.lock
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_deps: Vec<String> = Vec::new();

    let flush =
        |name: &Option<String>,
         version: &Option<String>,
         deps: &[String],
         nodes: &mut HashMap<String, DepNode>,
         edges: &mut Vec<DepEdge>| {
            if let (Some(n), Some(v)) = (name, version) {
                nodes.insert(
                    n.clone(),
                    DepNode {
                        name: n.clone(),
                        version: v.clone(),
                        source: "Cargo.lock".into(),
                    },
                );
                for d in deps {
                    // dep line format: "name version (source)" – extract just the name
                    let dep_name = d.split_whitespace().next().unwrap_or(d).to_string();
                    edges.push(DepEdge {
                        from: n.clone(),
                        to: dep_name,
                    });
                }
            }
        };

    let mut in_deps = false;

    for line in lock_content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            flush(
                &current_name,
                &current_version,
                &current_deps,
                &mut nodes,
                &mut edges,
            );
            current_name = None;
            current_version = None;
            current_deps = Vec::new();
            in_deps = false;
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
            in_deps = false;
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
            in_deps = false;
        } else if trimmed == "dependencies = [" {
            in_deps = true;
        } else if in_deps {
            if trimmed == "]" {
                in_deps = false;
            } else {
                let dep = trimmed.trim_matches(|c| c == '"' || c == ',').to_string();
                if !dep.is_empty() {
                    current_deps.push(dep);
                }
            }
        }
    }
    flush(
        &current_name,
        &current_version,
        &current_deps,
        &mut nodes,
        &mut edges,
    );

    DepGraph {
        nodes,
        edges,
        direct_deps,
    }
}

/// Build graph from package-lock.json + package.json
fn build_npm_graph(lock_content: &str, manifest_content: Option<&str>) -> DepGraph {
    let mut nodes = HashMap::new();
    let mut edges = Vec::new();
    let mut direct_deps = HashSet::new();

    // Parse package.json for direct deps
    if let Some(manifest) = manifest_content {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(manifest) {
            for section in &["dependencies", "devDependencies", "peerDependencies"] {
                if let Some(deps) = val.get(section).and_then(|v| v.as_object()) {
                    for key in deps.keys() {
                        direct_deps.insert(key.clone());
                    }
                }
            }
        }
    }

    // Parse package-lock.json v2/v3
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(lock_content) {
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

                nodes.insert(
                    name.clone(),
                    DepNode {
                        name: name.clone(),
                        version,
                        source: "package-lock.json".into(),
                    },
                );

                // Extract sub-dependencies
                for dep_section in &["dependencies", "devDependencies", "peerDependencies"] {
                    if let Some(deps) = info.get(dep_section).and_then(|v| v.as_object()) {
                        for dep_name in deps.keys() {
                            edges.push(DepEdge {
                                from: name.clone(),
                                to: dep_name.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    DepGraph {
        nodes,
        edges,
        direct_deps,
    }
}

/// Build graph from go.sum + go.mod
fn build_go_graph(sum_content: &str, mod_content: Option<&str>) -> DepGraph {
    let mut nodes = HashMap::new();
    let mut edges = Vec::new();
    let mut direct_deps = HashSet::new();
    let mut root_module = String::new();

    // Parse go.mod for direct vs indirect
    if let Some(mod_src) = mod_content {
        let mut in_require = false;
        for line in mod_src.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("module ") {
                root_module = rest.trim().to_string();
            }
            if trimmed == "require (" {
                in_require = true;
                continue;
            }
            if trimmed == ")" {
                in_require = false;
                continue;
            }
            if in_require || trimmed.starts_with("require ") {
                let req = if let Some(r) = trimmed.strip_prefix("require ") {
                    r
                } else {
                    trimmed
                };
                if !req.contains("// indirect") {
                    if let Some(name) = req.split_whitespace().next() {
                        direct_deps.insert(name.to_string());
                    }
                }
            }
        }
    }

    // Parse go.sum
    let mut seen = HashSet::new();
    for line in sum_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let version = parts[1].trim_end_matches("/go.mod").to_string();
            if seen.insert(name.clone()) {
                nodes.insert(
                    name.clone(),
                    DepNode {
                        name: name.clone(),
                        version,
                        source: "go.sum".into(),
                    },
                );
                // In go, the root module depends on all listed packages
                if !root_module.is_empty() {
                    edges.push(DepEdge {
                        from: root_module.clone(),
                        to: name,
                    });
                }
            }
        }
    }

    if !root_module.is_empty() {
        nodes.insert(
            root_module.clone(),
            DepNode {
                name: root_module,
                version: "root".into(),
                source: "go.mod".into(),
            },
        );
    }

    DepGraph {
        nodes,
        edges,
        direct_deps,
    }
}

/// Build graph from requirements.txt (flat – no transitive info)
fn build_python_graph(req_content: &str) -> DepGraph {
    let mut nodes = HashMap::new();
    let direct_deps = HashSet::new();

    for line in req_content.lines() {
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

        nodes.insert(
            clean_name.clone(),
            DepNode {
                name: clean_name,
                version,
                source: "requirements.txt".into(),
            },
        );
    }

    DepGraph {
        nodes,
        edges: Vec::new(),
        direct_deps,
    }
}

// ── Graph analysis ───────────────────────────────────────────────

/// Detect circular dependencies using DFS.
fn find_cycles(graph: &DepGraph) -> Vec<Vec<String>> {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
    }

    let mut visited: HashSet<&str> = HashSet::new();
    let mut on_stack: HashSet<&str> = HashSet::new();
    let mut cycles: Vec<Vec<String>> = Vec::new();
    let mut path: Vec<&str> = Vec::new();

    fn dfs<'a>(
        node: &'a str,
        adj: &HashMap<&'a str, Vec<&'a str>>,
        visited: &mut HashSet<&'a str>,
        on_stack: &mut HashSet<&'a str>,
        path: &mut Vec<&'a str>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node);
        on_stack.insert(node);
        path.push(node);

        if let Some(neighbors) = adj.get(node) {
            for &next in neighbors {
                if !visited.contains(next) {
                    dfs(next, adj, visited, on_stack, path, cycles);
                } else if on_stack.contains(next) {
                    // Found a cycle – extract it
                    if let Some(start) = path.iter().position(|&n| n == next) {
                        let cycle: Vec<String> =
                            path[start..].iter().map(|s| s.to_string()).collect();
                        if cycle.len() >= 2 {
                            cycles.push(cycle);
                        }
                    }
                }
            }
        }

        path.pop();
        on_stack.remove(node);
    }

    for node_name in graph.nodes.keys() {
        if !visited.contains(node_name.as_str()) {
            dfs(
                node_name.as_str(),
                &adj,
                &mut visited,
                &mut on_stack,
                &mut path,
                &mut cycles,
            );
        }
    }

    cycles
}

/// Detect phantom (unused) dependencies: declared in manifest but never imported in source.
fn find_phantom_deps(graph: &DepGraph, repo: &Repository, ignore_dirs: &[String]) -> Vec<String> {
    if graph.direct_deps.is_empty() {
        return Vec::new();
    }

    // Collect all import statements from source files to see which deps are actually used
    let mut imported_names: HashSet<String> = HashSet::new();
    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];
    let source_exts = [
        ".rs", ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".rb", ".php",
    ];

    if let Ok(head) = repo.head().and_then(|h| h.peel_to_tree()) {
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
            if !source_exts.iter().any(|ext| path.ends_with(ext)) {
                return TreeWalkResult::Ok;
            }

            if let Ok(blob) = repo.find_blob(entry.id()) {
                if let Ok(content) = std::str::from_utf8(blob.content()) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        // Rust: use crate_name / extern crate
                        if trimmed.starts_with("use ") || trimmed.starts_with("extern crate ") {
                            let tok = trimmed
                                .trim_start_matches("extern crate ")
                                .trim_start_matches("use ")
                                .split("::")
                                .next()
                                .unwrap_or("")
                                .trim_end_matches(';')
                                .replace('-', "_");
                            if !tok.is_empty() {
                                imported_names.insert(tok);
                            }
                        }
                        // JS/TS: import ... from 'pkg' / require('pkg')
                        if trimmed.contains("from ") || trimmed.contains("require(") {
                            // Extract package name from quotes
                            for delim in &['\'', '"'] {
                                if let Some(start) = trimmed.find(*delim) {
                                    if let Some(end) =
                                        trimmed[start + 1..].find(*delim).map(|e| e + start + 1)
                                    {
                                        let pkg = &trimmed[start + 1..end];
                                        // npm scoped packages: @scope/name
                                        let name = if pkg.starts_with('.') {
                                            continue; // relative import
                                        } else if pkg.starts_with('@') {
                                            // @scope/name → @scope/name
                                            pkg.splitn(3, '/')
                                                .take(2)
                                                .collect::<Vec<_>>()
                                                .join("/")
                                        } else {
                                            pkg.split('/').next().unwrap_or(pkg).to_string()
                                        };
                                        imported_names.insert(name);
                                        break;
                                    }
                                }
                            }
                        }
                        // Python: import pkg / from pkg import ...
                        if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                            let parts: Vec<&str> = trimmed.split_whitespace().collect();
                            if parts.len() >= 2 {
                                let pkg = parts[1].split('.').next().unwrap_or(parts[1]);
                                imported_names.insert(pkg.to_string());
                            }
                        }
                        // Go: import "pkg" or import ( "pkg" )
                        if trimmed.contains('"') && (trimmed.starts_with("import") || trimmed.starts_with('"'))
                        {
                            for delim in &['"'] {
                                if let Some(start) = trimmed.find(*delim) {
                                    if let Some(end) =
                                        trimmed[start + 1..].find(*delim).map(|e| e + start + 1)
                                    {
                                        let pkg = &trimmed[start + 1..end];
                                        // Use last path segment as the package name
                                        if let Some(last) = pkg.rsplit('/').next() {
                                            imported_names.insert(last.to_string());
                                        }
                                        imported_names.insert(pkg.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            TreeWalkResult::Ok
        });
    }

    // Check which direct deps are never referenced
    let mut phantom = Vec::new();
    for dep in &graph.direct_deps {
        let normalized = dep.replace('-', "_");
        let dep_lower = dep.to_lowercase();
        let norm_lower = normalized.to_lowercase();

        let found = imported_names.iter().any(|imp| {
            let imp_lower = imp.to_lowercase();
            let imp_norm = imp.replace('-', "_").to_lowercase();
            imp_lower == dep_lower
                || imp_norm == norm_lower
                || imp_lower.contains(&dep_lower)
                || dep_lower.contains(&imp_lower)
        });

        if !found {
            phantom.push(dep.clone());
        }
    }

    phantom.sort();
    phantom
}

/// Compute reachability: which transitive dependencies are reachable from the direct deps.
fn reachability(graph: &DepGraph) -> (HashSet<String>, Vec<String>) {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
    }

    let mut reachable: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();

    // Seed from direct dependencies
    for dep in &graph.direct_deps {
        if graph.nodes.contains_key(dep) {
            queue.push_back(dep.as_str());
            reachable.insert(dep.clone());
        }
    }

    // If no direct deps known, seed from all nodes that have outgoing edges but no incoming
    if queue.is_empty() {
        let has_incoming: HashSet<&str> = graph.edges.iter().map(|e| e.to.as_str()).collect();
        for name in graph.nodes.keys() {
            if !has_incoming.contains(name.as_str()) {
                queue.push_back(name.as_str());
                reachable.insert(name.clone());
            }
        }
    }

    // BFS
    while let Some(node) = queue.pop_front() {
        if let Some(neighbors) = adj.get(node) {
            for &next in neighbors {
                if reachable.insert(next.to_string()) {
                    queue.push_back(next);
                }
            }
        }
    }

    let unreachable: Vec<String> = graph
        .nodes
        .keys()
        .filter(|n| !reachable.contains(n.as_str()))
        .cloned()
        .collect();

    (reachable, unreachable)
}

// ── DOT output ───────────────────────────────────────────────────

/// Generate DOT graph representation.
fn generate_dot(graph: &DepGraph, cycles: &[Vec<String>]) -> String {
    let mut dot = String::new();
    writeln!(dot, "digraph dependencies {{").unwrap();
    writeln!(dot, "  rankdir=LR;").unwrap();
    writeln!(
        dot,
        "  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=10];"
    )
    .unwrap();
    writeln!(
        dot,
        "  edge [color=\"#666666\", arrowsize=0.7];"
    )
    .unwrap();
    writeln!(dot).unwrap();

    // Collect cycle edges for highlighting
    let mut cycle_edges: HashSet<(String, String)> = HashSet::new();
    for cycle in cycles {
        for i in 0..cycle.len() {
            let from = &cycle[i];
            let to = &cycle[(i + 1) % cycle.len()];
            cycle_edges.insert((from.clone(), to.clone()));
        }
    }

    // Nodes
    for (name, node) in &graph.nodes {
        let color = if graph.direct_deps.contains(name) {
            "#4FC3F7" // direct dep – blue
        } else {
            "#E0E0E0" // transitive – grey
        };
        let label = format!("{}\\n{}", node.name, node.version);
        writeln!(
            dot,
            "  \"{}\" [label=\"{}\", fillcolor=\"{}\"];",
            name, label, color
        )
        .unwrap();
    }

    writeln!(dot).unwrap();

    // Edges
    for edge in &graph.edges {
        if cycle_edges.contains(&(edge.from.clone(), edge.to.clone())) {
            writeln!(
                dot,
                "  \"{}\" -> \"{}\" [color=\"#FF5252\", penwidth=2.0, label=\"cycle\"];",
                edge.from, edge.to
            )
            .unwrap();
        } else {
            writeln!(dot, "  \"{}\" -> \"{}\";", edge.from, edge.to).unwrap();
        }
    }

    writeln!(dot, "}}").unwrap();
    dot
}

// ── Public API ───────────────────────────────────────────────────

/// Run full dependency graph analysis.
pub fn depgraph_scan(
    repo: &Repository,
    ignore_dirs: &[String],
    dot_output: Option<&str>,
) -> Result<(), git2::Error> {
    display::print_sub_header("Dependency Graph & Reachability Analysis");

    let head = repo.head()?.peel_to_tree()?;
    let skip_dirs = [
        "vendor/",
        "node_modules/",
        ".git/",
        "target/",
        "dist/",
        "build/",
    ];

    // Collect lockfiles and manifests
    let mut files: HashMap<String, String> = HashMap::new();

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

        let dominated = matches!(
            name,
            "Cargo.lock"
                | "Cargo.toml"
                | "package-lock.json"
                | "package.json"
                | "go.sum"
                | "go.mod"
                | "requirements.txt"
        );
        if !dominated {
            return TreeWalkResult::Ok;
        }

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                files.insert(path, content.to_string());
            }
        }
        TreeWalkResult::Ok
    })?;

    if files.is_empty() {
        display::print_info(
            "No dependency files found (Cargo.lock, package-lock.json, go.sum, requirements.txt)",
        );
        return Ok(());
    }

    // Build graphs per ecosystem
    let mut all_graphs: Vec<(String, DepGraph)> = Vec::new();

    // Cargo
    if let Some(lock) = files.get("Cargo.lock") {
        let manifest = files.get("Cargo.toml").map(|s| s.as_str());
        all_graphs.push(("Rust (Cargo)".into(), build_cargo_graph(lock, manifest)));
    }

    // npm
    if let Some(lock) = files.get("package-lock.json") {
        let manifest = files.get("package.json").map(|s| s.as_str());
        all_graphs.push(("Node.js (npm)".into(), build_npm_graph(lock, manifest)));
    }

    // Go
    if let Some(sum) = files.get("go.sum") {
        let mod_file = files.get("go.mod").map(|s| s.as_str());
        all_graphs.push(("Go".into(), build_go_graph(sum, mod_file)));
    }

    // Python
    if let Some(req) = files.get("requirements.txt") {
        all_graphs.push(("Python".into(), build_python_graph(req)));
    }

    // Also check for nested lockfiles
    for (path, content) in &files {
        if path == "Cargo.lock"
            || path == "package-lock.json"
            || path == "go.sum"
            || path == "requirements.txt"
        {
            continue; // already handled root-level
        }
        if path.ends_with("Cargo.lock") {
            let manifest_path = path.replace("Cargo.lock", "Cargo.toml");
            let manifest = files.get(&manifest_path).map(|s| s.as_str());
            all_graphs.push((format!("Rust ({})", path), build_cargo_graph(content, manifest)));
        } else if path.ends_with("package-lock.json") {
            let manifest_path = path.replace("package-lock.json", "package.json");
            let manifest = files.get(&manifest_path).map(|s| s.as_str());
            all_graphs.push((format!("Node.js ({})", path), build_npm_graph(content, manifest)));
        }
    }

    if all_graphs.is_empty() {
        display::print_info("No dependency graphs could be built");
        return Ok(());
    }

    let mut combined_dot = String::new();

    for (ecosystem, graph) in &all_graphs {
        display::out("");
        display::out(&format!("    \x1b[1m{ecosystem}\x1b[0m"));

        display::print_summary_stat("Packages", &graph.nodes.len().to_string());
        display::print_summary_stat("Dependency edges", &graph.edges.len().to_string());
        display::print_summary_stat("Direct dependencies", &graph.direct_deps.len().to_string());

        // Circular dependency detection
        let cycles = find_cycles(graph);
        if cycles.is_empty() {
            display::print_ok("No circular dependencies detected");
        } else {
            display::print_warning(&format!(
                "{} circular dependency chain(s) detected:",
                cycles.len()
            ));
            for (i, cycle) in cycles.iter().enumerate().take(10) {
                let chain: String = cycle.join(" → ");
                display::out(&format!(
                    "      {}. {} → {}",
                    i + 1,
                    chain,
                    cycle.first().unwrap_or(&String::new())
                ));
            }
        }

        // Phantom dependencies
        let phantom = find_phantom_deps(graph, repo, ignore_dirs);
        if phantom.is_empty() {
            display::print_ok("No phantom (unused) dependencies detected");
        } else {
            display::print_warning(&format!(
                "{} potentially unused dependencies:",
                phantom.len()
            ));
            let rows: Vec<Vec<String>> = phantom
                .iter()
                .take(20)
                .map(|p| {
                    let ver = graph
                        .nodes
                        .get(p)
                        .map(|n| n.version.clone())
                        .unwrap_or_default();
                    vec![p.clone(), ver]
                })
                .collect();
            display::print_table(&["Package", "Version"], &rows);
        }

        // Reachability
        let (reachable, unreachable) = reachability(graph);
        display::print_summary_stat("Reachable packages", &reachable.len().to_string());
        if !unreachable.is_empty() {
            display::print_info(&format!(
                "{} packages are not reachable from direct dependencies",
                unreachable.len()
            ));
            if unreachable.len() <= 10 {
                for u in &unreachable {
                    display::out(&format!("      - {u}"));
                }
            }
        }

        // Generate DOT
        let dot = generate_dot(graph, &cycles);
        combined_dot.push_str(&dot);
    }

    // Write DOT file if requested
    if let Some(dot_path) = dot_output {
        match fs::write(dot_path, &combined_dot) {
            Ok(()) => display::out(&format!(
                "\n    \x1b[1;32m✓  DOT graph saved to {dot_path}\x1b[0m"
            )),
            Err(e) => display::out(&format!(
                "\n    \x1b[1;31m✗  Failed to write DOT file: {e}\x1b[0m"
            )),
        }
        display::print_info("Convert to SVG with: dot -Tsvg -o deps.svg deps.dot");
    }

    Ok(())
}
