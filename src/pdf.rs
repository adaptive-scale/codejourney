use printpdf::*;
use regex::Regex;
use std::fs::File;
use std::io::BufWriter;

/// Strip ANSI escape sequences from a string.
pub fn strip_ansi(input: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(input, "").to_string()
}

/// Generate a PDF report from plain-text content and save it to `output_path`.
pub fn generate(content: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (doc, page1, layer1) =
        PdfDocument::new("CodeJourney Report", Mm(210.0), Mm(297.0), "Layer 1");
    let font = doc.add_builtin_font(BuiltinFont::Courier)?;

    let font_size = 7.5;
    let line_height = Mm(3.5);
    let margin_left = Mm(10.0);
    let margin_top = Mm(282.0);
    let page_bottom = Mm(15.0);

    let mut current_y = margin_top;
    let mut current_layer = doc.get_page(page1).get_layer(layer1);

    // Title
    let title_font = doc.add_builtin_font(BuiltinFont::CourierBold)?;
    current_layer.use_text("CodeJourney Report", 16.0, Mm(60.0), current_y, &title_font);
    current_y -= Mm(10.0);

    let plain = strip_ansi(content);

    for line in plain.lines() {
        if current_y < page_bottom {
            let (page, layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
            current_layer = doc.get_page(page).get_layer(layer);
            current_y = margin_top;
        }

        current_layer.use_text(line, font_size, margin_left, current_y, &font);
        current_y -= line_height;
    }

    doc.save(&mut BufWriter::new(File::create(output_path)?))?;
    Ok(())
}
