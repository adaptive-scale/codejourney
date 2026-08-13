use printpdf::*;
use regex::Regex;
use std::fs::File;
use std::io::BufWriter;

/// Strip ANSI escape sequences from a string.
pub fn strip_ansi(input: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(input, "").to_string()
}

// ── Colors ──────────────────────────────────────────────────────────────────
//
// Light palette. Reports are printed and circulated during due diligence, so
// the page stays white and every ink colour is chosen to keep contrast on it.

fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(Rgb::new(
        r as f32 / 255.0,
        g as f32 / 255.0,
        b as f32 / 255.0,
        None,
    ))
}

fn color_page_bg() -> Color {
    rgb(255, 255, 255)
}

fn color_section_bg() -> Color {
    rgb(241, 245, 249)
}

fn color_accent() -> Color {
    rgb(2, 132, 199)
}

fn color_heading_text() -> Color {
    rgb(15, 23, 42)
}

fn color_body_text() -> Color {
    rgb(51, 65, 85)
}

fn color_muted_text() -> Color {
    rgb(100, 116, 139)
}

fn color_warning() -> Color {
    rgb(180, 83, 9)
}

fn color_error() -> Color {
    rgb(220, 38, 38)
}

fn color_success() -> Color {
    rgb(5, 150, 105)
}

fn color_error_bg() -> Color {
    rgb(254, 242, 242)
}

fn color_success_bg() -> Color {
    rgb(236, 253, 245)
}

fn color_table_header_bg() -> Color {
    rgb(226, 232, 240)
}

fn color_table_row_even() -> Color {
    rgb(255, 255, 255)
}

fn color_table_row_odd() -> Color {
    rgb(248, 250, 252)
}

fn color_table_border() -> Color {
    rgb(203, 213, 225)
}

fn color_sub_header() -> Color {
    rgb(180, 83, 9)
}

fn color_gradient_cyan() -> Color {
    rgb(8, 145, 178)
}

fn color_gradient_purple() -> Color {
    rgb(147, 51, 234)
}

// ── Parsed elements (shared with the HTML and Markdown reports) ─────────────

pub(crate) enum Element {
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

// ── Report parser ───────────────────────────────────────────────────────────

pub(crate) fn parse_report(content: &str) -> Vec<Element> {
    let plain = strip_ansi(content);
    let lines: Vec<&str> = plain.lines().collect();
    let mut elements: Vec<Element> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Section header box
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
                    i += 3;
                    continue;
                }
            }
            i += 1;
            continue;
        }

        // Sub-header
        if trimmed.starts_with('▸') {
            let title = trimmed.trim_start_matches('▸').trim().to_string();
            elements.push(Element::SubHeader(title));
            if i + 1 < lines.len() && lines[i + 1].trim().starts_with('─') {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        // Separator
        if trimmed.chars().all(|c| c == '─' || c == '═') {
            i += 1;
            continue;
        }

        // Warning
        if trimmed.starts_with('⚠') {
            let msg = trimmed.trim_start_matches('⚠').trim().to_string();
            elements.push(Element::Warning(msg));
            i += 1;
            continue;
        }

        // Ok
        if trimmed.starts_with('✓') {
            let msg = trimmed.trim_start_matches('✓').trim().to_string();
            elements.push(Element::Ok(msg));
            i += 1;
            continue;
        }

        // Bar chart
        if trimmed.contains('█') {
            let mut chart_items: Vec<(String, usize)> = Vec::new();
            while i < lines.len() {
                let l = lines[i].trim();
                if l.is_empty() || !l.contains('█') {
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

        // Sparkline (skip)
        if trimmed.contains('▁')
            || trimmed.contains('▂')
            || trimmed.contains('▃')
            || trimmed.contains('▄')
            || trimmed.contains('▅')
            || trimmed.contains('▆')
            || trimmed.contains('▇')
        {
            i += 1;
            if i < lines.len() {
                i += 1;
            }
            continue;
        }

        // Stat line
        if let Some(stat) = parse_stat_line(trimmed) {
            elements.push(Element::Stat(stat.0, stat.1));
            i += 1;
            continue;
        }

        // Table
        if i + 1 < lines.len() {
            let next_trimmed = lines[i + 1].trim();
            if next_trimmed.starts_with('─') && next_trimmed.len() > 5 {
                let headers = parse_table_columns(trimmed);
                let col_widths = detect_column_positions(trimmed);
                let mut rows: Vec<Vec<String>> = Vec::new();
                i += 2;
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

        // Bullet
        if trimmed.starts_with('•') {
            let msg = trimmed.trim_start_matches('•').trim().to_string();
            elements.push(Element::Warning(msg));
            i += 1;
            continue;
        }

        if trimmed == "(no data)" {
            elements.push(Element::Info("No data available".to_string()));
            i += 1;
            continue;
        }

        // Bold label
        if trimmed.ends_with(':') && !trimmed.contains("  ") {
            elements.push(Element::Info(trimmed.to_string()));
            i += 1;
            continue;
        }

        if !trimmed.is_empty() {
            elements.push(Element::Info(trimmed.to_string()));
        }
        i += 1;
    }

    elements
}

fn parse_bar_chart_line(line: &str) -> Option<(String, usize)> {
    let bar_start = line.find('█')?;
    let label = line[..bar_start].trim().to_string();
    let after_bar = &line[bar_start..];
    let bar_end = after_bar.rfind('█').unwrap_or(0);
    let rest = after_bar[bar_end + '█'.len_utf8()..].trim();
    let value: usize = rest.split_whitespace().last()?.parse().ok()?;
    Some((label, value))
}

fn parse_stat_line(line: &str) -> Option<(String, String)> {
    let colon_pos = line.find(':')?;
    let label = line[..colon_pos].trim();
    let value = line[colon_pos + 1..].trim();
    if label.is_empty() || value.is_empty() || label.len() > 40 {
        return None;
    }
    if label.contains('/') || label.contains('.') || value.contains("──") {
        return None;
    }
    Some((label.to_string(), value.to_string()))
}

fn parse_table_columns(line: &str) -> Vec<String> {
    line.split_whitespace().map(|s| s.to_string()).collect()
}

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

fn split_by_positions(line: &str, positions: &[usize], expected_cols: usize) -> Vec<String> {
    if positions.len() < 2 {
        return line.split_whitespace().map(|s| s.to_string()).collect();
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
    if cols.len() < expected_cols {
        return line.split_whitespace().map(|s| s.to_string()).collect();
    }
    cols
}

// ── PDF renderer ────────────────────────────────────────────────────────────

struct PdfRenderer {
    doc: PdfDocumentReference,
    font_regular: IndirectFontRef,
    font_bold: IndirectFontRef,
    font_heading: IndirectFontRef,
    current_layer: PdfLayerReference,
    y: Mm,
    page_width: Mm,
    page_height: Mm,
    margin_left: Mm,
    margin_right: Mm,
    margin_top: Mm,
    margin_bottom: Mm,
}

impl PdfRenderer {
    fn new() -> Self {
        let page_width = Mm(210.0);
        let page_height = Mm(297.0);
        let (doc, page1, layer1) =
            PdfDocument::new("CodeJourney Report", page_width, page_height, "Layer 1");

        let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();
        let font_heading = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();

        let current_layer = doc.get_page(page1).get_layer(layer1);
        let margin_top = Mm(282.0);

        PdfRenderer {
            doc,
            font_regular,
            font_bold,
            font_heading,
            current_layer,
            y: margin_top,
            page_width,
            page_height,
            margin_left: Mm(20.0),
            margin_right: Mm(20.0),
            margin_top,
            margin_bottom: Mm(20.0),
        }
    }

    fn content_width(&self) -> f32 {
        self.page_width.0 - self.margin_left.0 - self.margin_right.0
    }

    fn ensure_space(&mut self, needed: Mm) {
        if self.y - needed < self.margin_bottom {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        let (page, layer) = self
            .doc
            .add_page(self.page_width, self.page_height, "Layer 1");
        self.current_layer = self.doc.get_page(page).get_layer(layer);
        self.y = self.margin_top;

        // Page background
        self.draw_rect(
            Mm(0.0),
            Mm(0.0),
            self.page_width,
            self.page_height,
            color_page_bg(),
        );

        // Footer line
        self.draw_rect(
            self.margin_left,
            Mm(14.0),
            Mm(self.content_width()),
            Mm(0.3),
            color_table_border(),
        );
        self.current_layer.set_fill_color(color_muted_text());
        self.current_layer.use_text(
            "CodeJourney Report",
            6.0,
            self.margin_left,
            Mm(9.0),
            &self.font_regular,
        );
    }

    fn draw_rect(&self, x: Mm, y: Mm, w: Mm, h: Mm, fill: Color) {
        let rect = Rect::new(x, y, x + w, y + h);
        self.current_layer.set_fill_color(fill.clone());
        self.current_layer.set_outline_color(fill);
        self.current_layer.set_outline_thickness(0.0);
        self.current_layer.add_rect(rect);
    }

    fn draw_line(&self, x1: Mm, y1: Mm, x2: Mm, y2: Mm, color: Color, thickness: f32) {
        let line = Line {
            points: vec![(Point::new(x1, y1), false), (Point::new(x2, y2), false)],
            is_closed: false,
        };
        self.current_layer.set_outline_color(color);
        self.current_layer.set_outline_thickness(thickness);
        self.current_layer.add_line(line);
    }

    /// Truncate text to fit within `max_width_mm` at `font_size`.
    /// Rough approximation: Helvetica is ~0.5 * font_size per char in pt → mm.
    fn truncate_text(&self, text: &str, font_size: f32, max_width_mm: f32) -> String {
        let char_width_mm = font_size * 0.24; // approximate width per char in mm
        let max_chars = (max_width_mm / char_width_mm) as usize;
        if text.len() <= max_chars {
            text.to_string()
        } else if max_chars > 3 {
            format!("{}...", &text[..max_chars - 3])
        } else {
            text[..max_chars.min(text.len())].to_string()
        }
    }

    // ── Render the title page header ────────────────────────────────────────

    fn render_header(&mut self) {
        // Full-page background
        self.draw_rect(
            Mm(0.0),
            Mm(0.0),
            self.page_width,
            self.page_height,
            color_page_bg(),
        );

        // Top gradient bar
        let bar_h = Mm(3.0);
        self.draw_rect(
            Mm(0.0),
            Mm(self.page_height.0 - bar_h.0),
            Mm(70.0),
            bar_h,
            color_gradient_cyan(),
        );
        self.draw_rect(
            Mm(70.0),
            Mm(self.page_height.0 - bar_h.0),
            Mm(70.0),
            bar_h,
            color_accent(),
        );
        self.draw_rect(
            Mm(140.0),
            Mm(self.page_height.0 - bar_h.0),
            Mm(70.0),
            bar_h,
            color_gradient_purple(),
        );

        self.y = Mm(self.page_height.0 - 20.0);

        // Title
        self.current_layer.set_fill_color(color_heading_text());
        self.current_layer.use_text(
            "CodeJourney",
            22.0,
            self.margin_left,
            self.y,
            &self.font_heading,
        );
        self.y -= Mm(7.0);

        self.current_layer.set_fill_color(color_accent());
        self.current_layer.use_text(
            "Security & Analytics Report",
            11.0,
            self.margin_left,
            self.y,
            &self.font_regular,
        );
        self.y -= Mm(5.0);

        // Timestamp
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        self.current_layer.set_fill_color(color_muted_text());
        self.current_layer.use_text(
            &format!("Generated {timestamp}"),
            7.0,
            self.margin_left,
            self.y,
            &self.font_regular,
        );
        self.y -= Mm(4.0);

        // Divider line
        self.draw_line(
            self.margin_left,
            self.y,
            Mm(self.page_width.0 - self.margin_right.0),
            self.y,
            color_table_border(),
            0.5,
        );
        self.y -= Mm(8.0);

        // Footer line
        self.draw_rect(
            self.margin_left,
            Mm(14.0),
            Mm(self.content_width()),
            Mm(0.3),
            color_table_border(),
        );
        self.current_layer.set_fill_color(color_muted_text());
        self.current_layer.use_text(
            "CodeJourney Report",
            6.0,
            self.margin_left,
            Mm(9.0),
            &self.font_regular,
        );
    }

    // ── Section header ──────────────────────────────────────────────────────

    fn render_section_header(&mut self, title: &str) {
        self.ensure_space(Mm(18.0));

        let box_h = Mm(10.0);
        let cw = self.content_width();

        // Background
        self.draw_rect(
            self.margin_left,
            self.y - box_h,
            Mm(cw),
            box_h,
            color_section_bg(),
        );

        // Left accent bar
        self.draw_rect(
            self.margin_left,
            self.y - box_h,
            Mm(2.5),
            box_h,
            color_accent(),
        );

        // Dot indicator
        self.draw_rect(
            Mm(self.margin_left.0 + 8.0),
            self.y - Mm(6.5),
            Mm(2.5),
            Mm(2.5),
            color_accent(),
        );

        // Title text
        self.current_layer.set_fill_color(color_heading_text());
        self.current_layer.use_text(
            title,
            11.0,
            Mm(self.margin_left.0 + 14.0),
            self.y - Mm(7.0),
            &self.font_heading,
        );

        self.y -= box_h + Mm(5.0);
    }

    // ── Sub header ──────────────────────────────────────────────────────────

    fn render_sub_header(&mut self, title: &str) {
        self.ensure_space(Mm(12.0));

        self.current_layer.set_fill_color(color_sub_header());
        self.current_layer.use_text(
            &format!("▸  {title}"),
            9.0,
            Mm(self.margin_left.0 + 4.0),
            self.y,
            &self.font_bold,
        );
        self.y -= Mm(3.0);

        // Underline
        self.draw_line(
            Mm(self.margin_left.0 + 4.0),
            self.y,
            Mm(self.margin_left.0 + 80.0),
            self.y,
            color_sub_header(),
            0.3,
        );

        self.y -= Mm(5.0);
    }

    // ── Stat ────────────────────────────────────────────────────────────────

    fn render_stat(&mut self, label: &str, value: &str) {
        self.ensure_space(Mm(6.0));

        self.current_layer.set_fill_color(color_muted_text());
        self.current_layer.use_text(
            label,
            8.0,
            Mm(self.margin_left.0 + 6.0),
            self.y,
            &self.font_regular,
        );

        self.current_layer.set_fill_color(color_body_text());
        self.current_layer.use_text(
            value,
            8.0,
            Mm(self.margin_left.0 + 70.0),
            self.y,
            &self.font_bold,
        );

        self.y -= Mm(5.0);
    }

    // ── Warning ─────────────────────────────────────────────────────────────

    fn render_warning(&mut self, msg: &str) {
        self.ensure_space(Mm(8.0));
        let cw = self.content_width();

        // Background
        self.draw_rect(
            Mm(self.margin_left.0 + 4.0),
            self.y - Mm(4.5),
            Mm(cw - 4.0),
            Mm(7.0),
            color_error_bg(),
        );

        // Left bar
        self.draw_rect(
            Mm(self.margin_left.0 + 4.0),
            self.y - Mm(4.5),
            Mm(1.5),
            Mm(7.0),
            color_error(),
        );

        // Icon text
        self.current_layer.set_fill_color(color_warning());
        self.current_layer.use_text(
            "!",
            9.0,
            Mm(self.margin_left.0 + 9.0),
            self.y - Mm(1.0),
            &self.font_bold,
        );

        // Message
        let truncated = self.truncate_text(msg, 7.5, cw - 24.0);
        self.current_layer.set_fill_color(color_error());
        self.current_layer.use_text(
            &truncated,
            7.5,
            Mm(self.margin_left.0 + 14.0),
            self.y - Mm(1.0),
            &self.font_regular,
        );

        self.y -= Mm(9.0);
    }

    // ── Ok ───────────────────────────────────────────────────────────────────

    fn render_ok(&mut self, msg: &str) {
        self.ensure_space(Mm(8.0));
        let cw = self.content_width();

        // Background
        self.draw_rect(
            Mm(self.margin_left.0 + 4.0),
            self.y - Mm(4.5),
            Mm(cw - 4.0),
            Mm(7.0),
            color_success_bg(),
        );

        // Left bar
        self.draw_rect(
            Mm(self.margin_left.0 + 4.0),
            self.y - Mm(4.5),
            Mm(1.5),
            Mm(7.0),
            color_success(),
        );

        // Checkmark
        self.current_layer.set_fill_color(color_success());
        self.current_layer.use_text(
            "OK",
            6.0,
            Mm(self.margin_left.0 + 8.0),
            self.y - Mm(1.0),
            &self.font_bold,
        );

        // Message
        let truncated = self.truncate_text(msg, 7.5, cw - 24.0);
        self.current_layer.set_fill_color(color_success());
        self.current_layer.use_text(
            &truncated,
            7.5,
            Mm(self.margin_left.0 + 16.0),
            self.y - Mm(1.0),
            &self.font_regular,
        );

        self.y -= Mm(9.0);
    }

    // ── Info ─────────────────────────────────────────────────────────────────

    fn render_info(&mut self, msg: &str) {
        self.ensure_space(Mm(5.0));
        let cw = self.content_width();

        let truncated = self.truncate_text(msg, 7.5, cw - 10.0);
        self.current_layer.set_fill_color(color_muted_text());
        self.current_layer.use_text(
            &truncated,
            7.5,
            Mm(self.margin_left.0 + 6.0),
            self.y,
            &self.font_regular,
        );

        self.y -= Mm(4.5);
    }

    // ── Table ───────────────────────────────────────────────────────────────

    fn render_table(&mut self, headers: &[String], rows: &[Vec<String>]) {
        if headers.is_empty() {
            return;
        }

        let row_h = Mm(6.0);
        let total_h = row_h * (rows.len() as f32 + 1.0) + Mm(4.0);
        self.ensure_space(Mm(total_h.0.min(80.0)));

        let cw = self.content_width();
        let col_count = headers.len();
        let col_w = cw / col_count as f32;
        let table_x = self.margin_left.0 + 4.0;

        // Header background
        self.draw_rect(
            Mm(table_x),
            self.y - row_h,
            Mm(cw - 4.0),
            row_h,
            color_table_header_bg(),
        );

        // Header text
        self.current_layer.set_fill_color(color_body_text());
        for (ci, header) in headers.iter().enumerate() {
            let x = table_x + (ci as f32 * col_w);
            let truncated = self.truncate_text(header, 7.0, col_w - 4.0);
            self.current_layer.use_text(
                &truncated.to_uppercase(),
                6.5,
                Mm(x + 3.0),
                self.y - Mm(4.0),
                &self.font_bold,
            );
        }
        self.y -= row_h;

        // Header bottom border
        self.draw_line(
            Mm(table_x),
            self.y,
            Mm(table_x + cw - 4.0),
            self.y,
            color_table_border(),
            0.5,
        );

        // Data rows
        let mono_font = self.doc.add_builtin_font(BuiltinFont::Courier).unwrap();
        for (ri, row) in rows.iter().enumerate() {
            self.ensure_space(row_h);

            let bg = if ri % 2 == 0 {
                color_table_row_even()
            } else {
                color_table_row_odd()
            };

            self.draw_rect(Mm(table_x), self.y - row_h, Mm(cw - 4.0), row_h, bg);

            for (ci, cell) in row.iter().enumerate() {
                let x = table_x + (ci as f32 * col_w);
                let truncated = self.truncate_text(cell, 6.5, col_w - 4.0);

                // Color severity keywords
                let color = if cell == "HIGH" {
                    color_error()
                } else if cell == "MEDIUM" {
                    color_warning()
                } else if cell == "INFO" {
                    color_accent()
                } else {
                    color_muted_text()
                };

                self.current_layer.set_fill_color(color);
                self.current_layer.use_text(
                    &truncated,
                    6.5,
                    Mm(x + 3.0),
                    self.y - Mm(4.0),
                    &mono_font,
                );
            }
            self.y -= row_h;
        }

        // Bottom border
        self.draw_line(
            Mm(table_x),
            self.y,
            Mm(table_x + cw - 4.0),
            self.y,
            color_table_border(),
            0.3,
        );

        self.y -= Mm(4.0);
    }

    // ── Bar chart ───────────────────────────────────────────────────────────

    fn render_bar_chart(&mut self, items: &[(String, usize)]) {
        if items.is_empty() {
            return;
        }

        let bar_h = Mm(5.0);
        let gap = Mm(2.0);
        let total_h = (bar_h + gap) * items.len() as f32 + Mm(4.0);
        self.ensure_space(Mm(total_h.0.min(120.0)));

        let max_val = items.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1);
        let chart_x = self.margin_left.0 + 60.0;
        let chart_w = self.content_width() - 68.0;

        for (label, value) in items {
            self.ensure_space(bar_h + gap);

            // Label
            let truncated = self.truncate_text(label, 7.0, 50.0);
            self.current_layer.set_fill_color(color_body_text());
            self.current_layer.use_text(
                &truncated,
                7.0,
                Mm(self.margin_left.0 + 6.0),
                self.y - Mm(3.5),
                &self.font_regular,
            );

            // Bar background
            self.draw_rect(
                Mm(chart_x),
                self.y - bar_h,
                Mm(chart_w),
                bar_h,
                color_section_bg(),
            );

            // Bar fill
            let fill_w = (*value as f32 / max_val as f32) * chart_w;
            if fill_w > 0.0 {
                self.draw_rect(
                    Mm(chart_x),
                    self.y - bar_h,
                    Mm(fill_w),
                    bar_h,
                    color_accent(),
                );
            }

            // Value label
            self.current_layer.set_fill_color(color_heading_text());
            self.current_layer.use_text(
                &value.to_string(),
                6.5,
                Mm(chart_x + fill_w + 3.0),
                self.y - Mm(3.5),
                &self.font_bold,
            );

            self.y -= bar_h + gap;
        }

        self.y -= Mm(3.0);
    }

    // ── Main render ─────────────────────────────────────────────────────────

    fn render(&mut self, elements: &[Element]) {
        self.render_header();

        for elem in elements {
            match elem {
                Element::SectionHeader(title) => self.render_section_header(title),
                Element::SubHeader(title) => self.render_sub_header(title),
                Element::Stat(label, value) => self.render_stat(label, value),
                Element::Warning(msg) => self.render_warning(msg),
                Element::Ok(msg) => self.render_ok(msg),
                Element::Info(msg) => self.render_info(msg),
                Element::Table { headers, rows } => self.render_table(headers, rows),
                Element::BarChart(items) => self.render_bar_chart(items),
            }
        }
    }

    fn save(self, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.doc
            .save(&mut BufWriter::new(File::create(output_path)?))?;
        Ok(())
    }
}

/// Generate a PDF report from plain-text content and save it to `output_path`.
pub fn generate(content: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let elements = parse_report(content);
    let mut renderer = PdfRenderer::new();
    renderer.render(&elements);
    renderer.save(output_path)?;
    Ok(())
}
