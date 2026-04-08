use std::cell::RefCell;
use std::fmt::Write;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

const MAX_BAR_WIDTH: usize = 40;

// ── Output buffering ──────────────────────────────────────────

thread_local! {
    static BUFFER: RefCell<Option<String>> = RefCell::new(None);
}

pub fn start_buffering() {
    BUFFER.with(|b| *b.borrow_mut() = Some(String::new()));
}

pub fn flush_buffer() -> String {
    BUFFER.with(|b| b.borrow_mut().take().unwrap_or_default())
}

/// Write a line to either the buffer (if active) or stdout.
pub fn out(msg: &str) {
    BUFFER.with(|b| {
        let mut borrow = b.borrow_mut();
        if let Some(ref mut buf) = *borrow {
            buf.push_str(msg);
            buf.push('\n');
        } else {
            println!("{msg}");
        }
    });
}

// ── Spinners ──────────────────────────────────────────────────

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn finish_spinner(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  \x1b[32m✓\x1b[0m {msg}")
            .unwrap(),
    );
    pb.finish_with_message(msg.to_string());
}

pub fn fail_spinner(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  \x1b[31m✗\x1b[0m {msg}")
            .unwrap(),
    );
    pb.finish_with_message(msg.to_string());
}

// ── Display helpers ───────────────────────────────────────────

pub fn print_section_header(title: &str) {
    let line = "═".repeat(60);
    out(&format!("\n\x1b[1;36m╔{line}╗\x1b[0m"));
    out(&format!(
        "\x1b[1;36m║\x1b[0m \x1b[1;37m{title:<58}\x1b[0m \x1b[1;36m║\x1b[0m"
    ));
    out(&format!("\x1b[1;36m╚{line}╝\x1b[0m"));
}

pub fn print_sub_header(title: &str) {
    out(&format!("\n  \x1b[1;33m▸ {title}\x1b[0m"));
    out(&format!("  {}", "─".repeat(50)));
}

pub fn print_bar_chart(items: &[(String, usize)], color: &str) {
    if items.is_empty() {
        out("    \x1b[2m(no data)\x1b[0m");
        return;
    }

    let max_val = items.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1);
    let max_label_len = items.iter().map(|(k, _)| k.len()).max().unwrap_or(10).min(30);

    for (label, value) in items {
        let truncated: String = if label.len() > 30 {
            format!("{}…", &label[..29])
        } else {
            label.clone()
        };

        let bar_width = (*value as f64 / max_val as f64 * MAX_BAR_WIDTH as f64) as usize;
        let bar: String = "█".repeat(bar_width);

        out(&format!(
            "    {:<width$} {color}{bar}\x1b[0m {value}",
            truncated,
            width = max_label_len,
        ));
    }
}

pub fn print_sparkline(data: &[(String, usize)]) {
    if data.is_empty() {
        return;
    }
    let sparks = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max_val = data.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1);

    let mut line = String::new();
    let mut labels = String::new();
    for (label, value) in data {
        let idx = (*value as f64 / max_val as f64 * 7.0) as usize;
        let idx = idx.min(7);
        write!(&mut line, " {} ", sparks[idx]).unwrap();

        let short_label = if label.len() > 3 {
            &label[..3]
        } else {
            label
        };
        write!(&mut labels, "{short_label} ").unwrap();
    }

    out(&format!("    \x1b[32m{line}\x1b[0m"));
    out(&format!("    \x1b[2m{labels}\x1b[0m"));
}

pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        out("    \x1b[2m(no data)\x1b[0m");
        return;
    }

    let col_widths: Vec<usize> = (0..headers.len())
        .map(|i| {
            let max_data = rows
                .iter()
                .map(|r| r.get(i).map(|s| s.len()).unwrap_or(0))
                .max()
                .unwrap_or(0);
            headers[i].len().max(max_data).min(50)
        })
        .collect();

    // Header
    let mut header_line = String::from("    ");
    for (i, h) in headers.iter().enumerate() {
        write!(&mut header_line, "\x1b[1m{:<width$}\x1b[0m  ", h, width = col_widths[i]).unwrap();
    }
    out(&header_line);

    let sep: String = col_widths.iter().map(|w| "─".repeat(*w)).collect::<Vec<_>>().join("──");
    out(&format!("    {sep}"));

    for row in rows {
        let mut line = String::from("    ");
        for (i, cell) in row.iter().enumerate() {
            let w = col_widths.get(i).copied().unwrap_or(10);
            let truncated = if cell.len() > 50 {
                format!("{}…", &cell[..49])
            } else {
                cell.clone()
            };
            write!(&mut line, "{:<width$}  ", truncated, width = w).unwrap();
        }
        out(&line);
    }
}

pub fn print_summary_stat(label: &str, value: &str) {
    out(&format!("    \x1b[1m{label}:\x1b[0m {value}"));
}

pub fn print_warning(msg: &str) {
    out(&format!("    \x1b[1;31m⚠  {msg}\x1b[0m"));
}

pub fn print_ok(msg: &str) {
    out(&format!("    \x1b[1;32m✓  {msg}\x1b[0m"));
}

pub fn print_info(msg: &str) {
    out(&format!("    \x1b[2m{msg}\x1b[0m"));
}
