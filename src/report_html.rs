use crate::pdf::strip_ansi;
use std::fmt::Write;
use std::fs;

/// Parsed report element
enum Element {
    SectionHeader(String),
    SubHeader(String),
    BarChart(Vec<(String, usize)>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Stat(String, String),
    Warning(String),
    Ok(String),
    Info(String),
}

/// Parse the ANSI-stripped report output into structured elements.
fn parse_report(content: &str) -> Vec<Element> {
    let plain = strip_ansi(content);
    let lines: Vec<&str> = plain.lines().collect();
    let mut elements: Vec<Element> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip empty lines
        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Section header: ╔═══...═══╗ / ║ TITLE ║ / ╚═══...═══╝
        if trimmed.starts_with('╔') && trimmed.ends_with('╗') {
            if i + 2 < lines.len() {
                let title_line = lines[i + 1].trim();
                if title_line.starts_with('║') && title_line.ends_with('║') {
                    let title = title_line
                        .trim_start_matches('║')
                        .trim_end_matches('║')
                        .trim()
                        .to_string();
                    elements.push(Element::SectionHeader(title));
                    i += 3; // skip all 3 lines of the box
                    continue;
                }
            }
            i += 1;
            continue;
        }

        // Sub-header: ▸ Title
        if trimmed.starts_with('▸') {
            let title = trimmed.trim_start_matches('▸').trim().to_string();
            elements.push(Element::SubHeader(title));
            // Skip the separator line that follows
            if i + 1 < lines.len() && lines[i + 1].trim().starts_with('─') {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        // Separator line (standalone)
        if trimmed.chars().all(|c| c == '─' || c == '═') {
            i += 1;
            continue;
        }

        // Warning: ⚠  message
        if trimmed.starts_with('⚠') {
            let msg = trimmed.trim_start_matches('⚠').trim().to_string();
            elements.push(Element::Warning(msg));
            i += 1;
            continue;
        }

        // Ok: ✓  message
        if trimmed.starts_with('✓') {
            let msg = trimmed.trim_start_matches('✓').trim().to_string();
            elements.push(Element::Ok(msg));
            i += 1;
            continue;
        }

        // Bar chart line: label ████...█ number
        if trimmed.contains('█') {
            let mut chart_items: Vec<(String, usize)> = Vec::new();
            while i < lines.len() {
                let l = lines[i].trim();
                if l.is_empty() {
                    break;
                }
                if !l.contains('█') {
                    break;
                }
                if let Some(item) = parse_bar_chart_line(l) {
                    chart_items.push(item);
                }
                i += 1;
            }
            if !chart_items.is_empty() {
                elements.push(Element::BarChart(chart_items));
            }
            continue;
        }

        // Sparkline (skip — charts replace these)
        if trimmed.contains('▁')
            || trimmed.contains('▂')
            || trimmed.contains('▃')
            || trimmed.contains('▄')
            || trimmed.contains('▅')
            || trimmed.contains('▆')
            || trimmed.contains('▇')
        {
            i += 1;
            // Also skip the labels line below
            if i < lines.len() {
                i += 1;
            }
            continue;
        }

        // Stat line: Label: Value
        if let Some(stat) = parse_stat_line(trimmed) {
            elements.push(Element::Stat(stat.0, stat.1));
            i += 1;
            continue;
        }

        // Table detection: look for a header line followed by a ─── separator
        if i + 1 < lines.len() {
            let next_trimmed = lines[i + 1].trim();
            if next_trimmed.starts_with('─') && next_trimmed.len() > 5 {
                // This line is a table header
                let headers = parse_table_columns(trimmed);
                let col_widths = detect_column_positions(trimmed);

                let mut rows: Vec<Vec<String>> = Vec::new();
                i += 2; // skip header + separator
                while i < lines.len() {
                    let row_line = lines[i].trim();
                    if row_line.is_empty()
                        || row_line.starts_with('▸')
                        || row_line.starts_with('╔')
                        || row_line.starts_with('⚠')
                        || row_line.starts_with('✓')
                        || row_line.starts_with('•')
                    {
                        break;
                    }
                    // Check if this is a stat line or other non-table content
                    if row_line.starts_with('─') {
                        i += 1;
                        continue;
                    }
                    let cols = split_by_positions(row_line, &col_widths, headers.len());
                    rows.push(cols);
                    i += 1;
                }
                elements.push(Element::Table { headers, rows });
                continue;
            }
        }

        // Bullet point: • item
        if trimmed.starts_with('•') {
            let msg = trimmed.trim_start_matches('•').trim().to_string();
            elements.push(Element::Warning(msg));
            i += 1;
            continue;
        }

        // (no data)
        if trimmed == "(no data)" {
            elements.push(Element::Info("No data available".to_string()));
            i += 1;
            continue;
        }

        // Bold-style label lines (e.g. "Project Licenses (SPDX):")
        if trimmed.ends_with(':') && !trimmed.contains("  ") {
            elements.push(Element::Info(trimmed.to_string()));
            i += 1;
            continue;
        }

        // Fallback: general text/info
        if !trimmed.is_empty() {
            elements.push(Element::Info(trimmed.to_string()));
        }
        i += 1;
    }

    elements
}

/// Parse a bar chart line like "label  ████████ 42"
fn parse_bar_chart_line(line: &str) -> Option<(String, usize)> {
    // Find the block of █ chars
    let bar_start = line.find('█')?;
    let label = line[..bar_start].trim().to_string();

    let after_bar = &line[bar_start..];
    let bar_end = after_bar.rfind('█').unwrap_or(0);
    let rest = after_bar[bar_end + '█'.len_utf8()..].trim();

    // The number is at the end
    let value: usize = rest.split_whitespace().last()?.parse().ok()?;

    Some((label, value))
}

/// Parse a stat line like "Label: Value" or "Label:  Value"
fn parse_stat_line(line: &str) -> Option<(String, String)> {
    let colon_pos = line.find(':')?;
    let label = line[..colon_pos].trim();
    let value = line[colon_pos + 1..].trim();

    // Must have both a label and value, and the label shouldn't be too long
    if label.is_empty() || value.is_empty() || label.len() > 40 {
        return None;
    }
    // Avoid matching things that look like file paths or URLs
    if label.contains('/') || label.contains('.') || value.contains("──") {
        return None;
    }

    Some((label.to_string(), value.to_string()))
}

/// Split a table header line into column names
fn parse_table_columns(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

/// Detect column start positions from a header line based on multi-space gaps
fn detect_column_positions(header: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let trimmed = header.trim_start();
    let offset = header.len() - trimmed.len();

    positions.push(offset);
    let mut in_space = false;
    let mut space_count = 0;

    for (i, ch) in header.char_indices().skip(offset) {
        if ch == ' ' {
            space_count += 1;
            in_space = true;
        } else {
            if in_space && space_count >= 2 {
                positions.push(i);
            }
            in_space = false;
            space_count = 0;
        }
    }

    positions
}

/// Split a row line based on detected column positions
fn split_by_positions(line: &str, positions: &[usize], expected_cols: usize) -> Vec<String> {
    if positions.len() < 2 {
        return line
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
    }

    let mut cols = Vec::new();
    for i in 0..positions.len() {
        let start = positions[i];
        let end = if i + 1 < positions.len() {
            positions[i + 1]
        } else {
            line.len()
        };
        if start < line.len() {
            let actual_end = end.min(line.len());
            cols.push(line[start..actual_end].trim().to_string());
        } else {
            cols.push(String::new());
        }
    }

    // If we got fewer columns than expected, try whitespace split instead
    if cols.len() < expected_cols {
        return line
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
    }

    cols
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render a single element to HTML, appending chart JS when needed.
fn render_element(
    elem: &Element,
    body: &mut String,
    chart_id: &mut usize,
    chart_scripts: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    match elem {
        Element::SectionHeader(_) => {} // handled by section grouping
        Element::SubHeader(title) => {
            write!(
                body,
                r#"<h3 class="text-base font-semibold text-amber-400 mt-6 mb-3 flex items-center gap-2">
  <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z"/></svg>
  {}
</h3>
"#,
                html_escape(title)
            )?;
        }
        Element::BarChart(items) => {
            let cid = format!("chart_{}", *chart_id);
            *chart_id += 1;

            write!(
                body,
                r#"<div class="bg-slate-800/50 rounded-xl p-4 my-3 border border-slate-700/50">
  <canvas id="{cid}" height="{height}"></canvas>
</div>
"#,
                height = (items.len() * 28).max(120).min(600),
            )?;

            let labels: Vec<String> = items
                .iter()
                .map(|(l, _)| format!("\"{}\"", html_escape(l)))
                .collect();
            let values: Vec<String> = items.iter().map(|(_, v)| v.to_string()).collect();

            write!(
                chart_scripts,
                r#"
new Chart(document.getElementById('{cid}'), {{
  type: 'bar',
  data: {{
    labels: [{labels}],
    datasets: [{{
      data: [{values}],
      backgroundColor: 'rgba(56, 189, 248, 0.6)',
      borderColor: 'rgba(56, 189, 248, 0.9)',
      borderWidth: 1,
      borderRadius: 4,
      barThickness: 18,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{
        backgroundColor: '#1e293b',
        titleColor: '#e2e8f0',
        bodyColor: '#94a3b8',
        borderColor: '#334155',
        borderWidth: 1,
        cornerRadius: 8,
        padding: 10,
      }}
    }},
    scales: {{
      x: {{
        grid: {{ color: 'rgba(148,163,184,0.08)' }},
        ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }}
      }},
      y: {{
        grid: {{ display: false }},
        ticks: {{ color: '#cbd5e1', font: {{ family: "'JetBrains Mono', 'Fira Code', monospace", size: 11 }} }}
      }}
    }}
  }}
}});
"#,
                labels = labels.join(","),
                values = values.join(","),
            )?;
        }
        Element::Table { headers, rows } => {
            write!(
                body,
                r#"<div class="overflow-x-auto my-3">
<table class="w-full text-sm">
  <thead>
    <tr class="border-b border-slate-700">"#
            )?;
            for h in headers {
                write!(
                    body,
                    r#"
      <th class="text-left py-2 px-3 text-slate-300 font-semibold text-xs uppercase tracking-wider">{}</th>"#,
                    html_escape(h)
                )?;
            }
            write!(
                body,
                r#"
    </tr>
  </thead>
  <tbody>"#
            )?;
            for (ri, row) in rows.iter().enumerate() {
                let bg = if ri % 2 == 0 {
                    "bg-slate-800/30"
                } else {
                    "bg-slate-800/60"
                };
                write!(
                    body,
                    r#"
    <tr class="{bg} hover:bg-slate-700/40 transition-colors">"#
                )?;
                for cell in row {
                    write!(
                        body,
                        r#"
      <td class="py-2 px-3 text-slate-400 font-mono text-xs">{}</td>"#,
                        html_escape(cell)
                    )?;
                }
                write!(
                    body,
                    r#"
    </tr>"#
                )?;
            }
            write!(
                body,
                r#"
  </tbody>
</table>
</div>
"#
            )?;
        }
        Element::Stat(label, value) => {
            write!(
                body,
                r#"<div class="flex items-center gap-2 py-1.5 px-3">
  <span class="text-slate-400 text-sm">{}</span>
  <span class="text-slate-500">&middot;</span>
  <span class="text-slate-200 font-semibold text-sm font-mono">{}</span>
</div>
"#,
                html_escape(label),
                html_escape(value)
            )?;
        }
        Element::Warning(msg) => {
            write!(
                body,
                r#"<div class="flex items-start gap-2 py-1.5 px-3 my-1 bg-red-500/10 border border-red-500/20 rounded-lg">
  <svg class="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
  <span class="text-red-300 text-sm">{}</span>
</div>
"#,
                html_escape(msg)
            )?;
        }
        Element::Ok(msg) => {
            write!(
                body,
                r#"<div class="flex items-start gap-2 py-1.5 px-3 my-1 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
  <svg class="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
  <span class="text-emerald-300 text-sm">{}</span>
</div>
"#,
                html_escape(msg)
            )?;
        }
        Element::Info(msg) => {
            write!(
                body,
                r#"<p class="text-slate-500 text-sm py-1 px-3">{}</p>
"#,
                html_escape(msg)
            )?;
        }
    }
    Ok(())
}

/// Generate an HTML report from ANSI-colored content and save it to `output_path`.
pub fn generate(content: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let elements = parse_report(content);
    let mut body = String::new();
    let mut chart_id = 0usize;
    let mut chart_scripts = String::new();

    // Group elements into sections for collapsible rendering
    let mut in_section = false;
    for elem in &elements {
        if let Element::SectionHeader(title) = elem {
            // Close previous section
            if in_section {
                write!(&mut body, "</div>\n</details>\n")?;
            }
            // Open new collapsible section
            write!(
                &mut body,
                r#"<details open class="mt-6 group">
  <summary class="cursor-pointer list-none flex items-center gap-3 py-3 px-4 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all select-none">
    <svg class="w-4 h-4 text-slate-500 transition-transform group-open:rotate-90" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd"/></svg>
    <span class="h-2 w-2 rounded-full bg-cyan-400 inline-block"></span>
    <h2 class="text-lg font-bold text-slate-100">{}</h2>
  </summary>
  <div class="pl-4 pt-2 pb-4 border-l-2 border-slate-800 ml-5 mt-2">
"#,
                html_escape(title)
            )?;
            in_section = true;
            continue;
        }
        render_element(elem, &mut body, &mut chart_id, &mut chart_scripts)?;
    }
    // Close last section
    if in_section {
        write!(&mut body, "</div>\n</details>\n")?;
    }

    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");

    let mut html = String::with_capacity(body.len() + chart_scripts.len() + 4096);
    write!(
        &mut html,
        r##"<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CodeJourney Report</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script>
tailwind.config = {{
  darkMode: 'class',
  theme: {{
    extend: {{
      fontFamily: {{
        mono: ["'JetBrains Mono'", "'Fira Code'", "'Cascadia Code'", "monospace"],
      }}
    }}
  }}
}}
</script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
  body {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: #0f172a; }}
  ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 3px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: #475569; }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary::marker {{ display: none; content: ''; }}
</style>
</head>
<body class="bg-slate-950 text-slate-300 min-h-screen">

<!-- Top gradient bar -->
<div class="h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500"></div>

<div class="max-w-5xl mx-auto px-6 py-8">

  <!-- Header -->
  <header class="mb-10">
    <div class="flex items-center gap-4 mb-2">
      <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
        </svg>
      </div>
      <div>
        <h1 class="text-2xl font-bold text-white tracking-tight">CodeJourney Report</h1>
        <p class="text-slate-500 text-xs">Generated {timestamp}</p>
      </div>
    </div>
    <div class="flex items-center justify-between mt-4">
      <div class="h-px flex-1 bg-gradient-to-r from-slate-700 via-slate-600 to-transparent"></div>
      <div class="flex gap-2 ml-4">
        <button onclick="document.querySelectorAll('details').forEach(d=>d.open=true)" class="text-xs text-slate-500 hover:text-slate-300 border border-slate-700 hover:border-slate-600 rounded-md px-2.5 py-1 transition-colors">Expand all</button>
        <button onclick="document.querySelectorAll('details').forEach(d=>d.open=false)" class="text-xs text-slate-500 hover:text-slate-300 border border-slate-700 hover:border-slate-600 rounded-md px-2.5 py-1 transition-colors">Collapse all</button>
      </div>
    </div>
  </header>

  <!-- Report body -->
  <main>
{body}
  </main>

  <!-- Footer -->
  <footer class="mt-16 pt-6 border-t border-slate-800">
    <div class="flex items-center justify-between text-xs text-slate-600">
      <span>Generated by CodeJourney</span>
      <span>{timestamp}</span>
    </div>
  </footer>

</div>

<script>
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(148,163,184,0.1)';
{chart_scripts}
</script>
</body>
</html>"##
    )?;

    fs::write(output_path, html)?;
    Ok(())
}
