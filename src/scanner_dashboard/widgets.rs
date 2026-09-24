/*
 * Custom Widgets for Scanner Dashboard
 *
 * Provides specialized UI components for the scanner dashboard
 */

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// Create an ASCII bar chart from a value and maximum
///
/// # Arguments
/// * `value` - The current value
/// * `max_value` - The maximum value (for scaling)
/// * `width` - The total width in characters
///
/// # Returns
/// A string with filled and empty blocks representing the bar
pub fn create_bar(value: usize, max_value: usize, width: usize) -> String {
    if max_value == 0 {
        return "░".repeat(width);
    }

    let filled = ((value as f64 / max_value as f64) * width as f64) as usize;
    let filled = filled.min(width);

    format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    )
}

/// Create a percentage bar with label
///
/// # Arguments
/// * `label` - The label for the bar
/// * `value` - The current value
/// * `total` - The total value (for percentage calculation)
/// * `bar_width` - The width of the bar in characters
/// * `color` - The color for the bar
pub fn create_labeled_bar(
    label: &str,
    value: usize,
    total: usize,
    bar_width: usize,
    color: Color,
) -> Line<'static> {
    let percentage = if total > 0 {
        (value as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let bar = create_bar(value, total, bar_width);

    Line::from(vec![
        Span::raw(format!("{:<15} ", label)),
        Span::styled(bar, Style::default().fg(color)),
        Span::raw(format!(" {:>3}%", percentage.round() as u32)),
    ])
}

/// Create a horizontal bar chart from a list of (label, value) pairs
///
/// # Arguments
/// * `data` - Vector of (label, value, color) tuples
/// * `bar_width` - The width of each bar in characters
pub fn create_bar_chart(data: Vec<(&str, usize, Color)>, bar_width: usize) -> Vec<Line<'static>> {
    if data.is_empty() {
        return vec![Line::from(Span::styled(
            "  No data available",
            Style::default().fg(Color::Gray),
        ))];
    }

    let total: usize = data.iter().map(|(_, v, _)| *v).sum();

    data.into_iter()
        .map(|(label, value, color)| create_labeled_bar(label, value, total, bar_width, color))
        .collect()
}

/// Format a file size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if size >= 100.0 {
        format!("{:.0} {}", size, UNITS[unit_idx])
    } else if size >= 10.0 {
        format!("{:.1} {}", size, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Format a duration in human-readable format
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_bar() {
        assert_eq!(create_bar(0, 100, 10), "░░░░░░░░░░");
        assert_eq!(create_bar(50, 100, 10), "█████░░░░░");
        assert_eq!(create_bar(100, 100, 10), "██████████");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3665), "1h 01m 05s");
    }
}
