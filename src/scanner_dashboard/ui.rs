/*
 * UI Rendering for Scanner Dashboard
 *
 * Renders different view modes using Ratatui widgets
 */

use crate::scanner_dashboard::state::{ScanStatus, ScannerDashboardState, ViewMode};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, state: &ScannerDashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(2), // Footer
        ])
        .split(f.size());

    render_header(f, state, chunks[0]);

    match state.current_view {
        ViewMode::LiveScan => render_live_scan(f, state, chunks[1]),
        ViewMode::Category => render_category_view(f, state, chunks[1]),
        ViewMode::Statistics => render_statistics_view(f, state, chunks[1]),
        ViewMode::Migration => render_migration_view(f, state, chunks[1]),
    }

    render_footer(f, state, chunks[2]);

    // Render overlays (completion notification has highest priority, then help, then detail)
    if state.completion_notification_shown {
        render_completion_notification(f, state);
    } else if state.help_overlay_open {
        render_help_overlay(f, state);
    } else if state.detail_view_open {
        render_detail_view(f, state);
    }
}

fn render_header(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    let status_text = match &state.scan_status {
        ScanStatus::Running => "SCANNING",
        ScanStatus::Paused => "PAUSED",
        ScanStatus::Completed => "COMPLETED",
        ScanStatus::Error(_) => "ERROR",
    };

    let status_color = match &state.scan_status {
        ScanStatus::Running => Color::Green,
        ScanStatus::Paused => Color::Yellow,
        ScanStatus::Completed => Color::Blue,
        ScanStatus::Error(_) => Color::Red,
    };

    let depth_str = state
        .scan_depth
        .map(|d| format!("depth: {}", d))
        .unwrap_or_else(|| "depth: unlimited".to_string());

    let title = format!(
        " Crypto Scanner - {} ({}) - {} ",
        state.scan_path.display(),
        depth_str,
        status_text
    );

    let header = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(Style::default().fg(status_color));

    f.render_widget(header, area);
}

fn render_live_scan(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_scan_progress(f, state, chunks[0]);
    render_recent_discoveries(f, state, chunks[1]);
}

fn render_scan_progress(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    let runtime = state.get_runtime();
    let runtime_str = format!("{}m {:02}s", runtime.as_secs() / 60, runtime.as_secs() % 60);

    let progress_info = vec![
        Line::from(vec![
            Span::styled("Current: ", Style::default().fg(Color::Cyan)),
            Span::raw(state.scan_progress.current_path.display().to_string()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Files: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{}", state.scan_progress.files_scanned)),
        ]),
        Line::from(vec![
            Span::styled("Dirs:  ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{}", state.scan_progress.dirs_scanned)),
        ]),
        Line::from(vec![
            Span::styled("Speed: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{:.0} files/sec", state.scan_progress.scan_rate)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Runtime: ", Style::default().fg(Color::Cyan)),
            Span::raw(runtime_str),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "Libraries Found: ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{}", state.library_count())),
        ]),
    ];

    // Add category breakdown
    let mut category_lines = vec![Line::from("")];
    for (category, count) in &state.category_counts {
        category_lines.push(Line::from(vec![
            Span::raw(format!("  {} ", category.icon())),
            Span::raw(format!("{}: ", category.name())),
            Span::styled(format!("{}", count), Style::default().fg(Color::Yellow)),
        ]));
    }

    let all_lines = [progress_info, category_lines].concat();

    let progress_widget = Paragraph::new(all_lines).block(
        Block::default()
            .title(" Scan Progress ")
            .borders(Borders::ALL),
    );

    f.render_widget(progress_widget, area);
}

fn render_recent_discoveries(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    let items: Vec<ListItem> = state
        .recent_libraries
        .iter()
        .rev() // Newest first
        .map(|lib| {
            let risk_color = match lib.risk_level {
                crate::scanner_dashboard::state::RiskLevel::None => Color::Green,
                crate::scanner_dashboard::state::RiskLevel::Low => Color::Cyan,
                crate::scanner_dashboard::state::RiskLevel::Medium => Color::Yellow,
                crate::scanner_dashboard::state::RiskLevel::High => Color::LightRed,
                crate::scanner_dashboard::state::RiskLevel::Critical => Color::Red,
            };

            let version_str = lib
                .version
                .as_ref()
                .map(|v| format!(" ({})", v))
                .unwrap_or_default();

            let lines = vec![
                Line::from(vec![
                    Span::raw(format!("{} ", lib.category.icon())),
                    Span::styled(&lib.name, Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(version_str),
                ]),
                Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        lib.path.display().to_string(),
                        Style::default().fg(Color::Gray),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("   Category: "),
                    Span::styled(lib.category.name(), Style::default().fg(Color::Cyan)),
                    Span::raw("  Risk: "),
                    Span::styled(
                        format!("{} {}", lib.risk_level.icon(), lib.risk_level.label()),
                        Style::default().fg(risk_color),
                    ),
                ]),
                Line::from(""),
            ];

            ListItem::new(lines)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" Recently Discovered ")
            .borders(Borders::ALL),
    );

    f.render_widget(list, area);
}

fn render_category_view(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    use crate::scanner_dashboard::state::RiskLevel;

    let categories_data = state.get_libraries_by_category();

    let mut items = Vec::new();

    for (category, libs) in categories_data {
        let is_expanded = state.is_category_expanded(&category);
        let count = libs.len();

        // Category header
        let expand_symbol = if is_expanded { "▼" } else { "▶" };
        let header_line = Line::from(vec![
            Span::styled(
                format!(" {} ", expand_symbol),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{} ", category.icon())),
            Span::styled(
                format!("{} ", category.name()),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({} found)", count),
                Style::default().fg(Color::Gray),
            ),
        ]);

        items.push(ListItem::new(vec![header_line, Line::from("")]));

        // If expanded, show libraries in this category
        if is_expanded {
            for lib in libs.iter().take(20) {
                // Limit to 20 per category for display
                let risk_color = match lib.risk_level {
                    RiskLevel::None => Color::Green,
                    RiskLevel::Low => Color::Cyan,
                    RiskLevel::Medium => Color::Yellow,
                    RiskLevel::High => Color::LightRed,
                    RiskLevel::Critical => Color::Red,
                };

                let version_str = lib
                    .version
                    .as_ref()
                    .map(|v| format!(" v{}", v))
                    .unwrap_or_default();

                let vendor_str = lib
                    .vendor
                    .as_ref()
                    .map(|v| format!(" [{}]", v))
                    .unwrap_or_default();

                let lib_line = Line::from(vec![
                    Span::raw("   ● "),
                    Span::styled(&lib.name, Style::default().fg(Color::White)),
                    Span::styled(version_str, Style::default().fg(Color::Gray)),
                    Span::styled(vendor_str, Style::default().fg(Color::DarkGray)),
                    Span::raw("  "),
                    Span::styled(
                        format!("{} {}", lib.risk_level.icon(), lib.risk_level.label()),
                        Style::default().fg(risk_color),
                    ),
                ]);

                items.push(ListItem::new(vec![lib_line]));
            }

            if libs.len() > 20 {
                items.push(ListItem::new(vec![
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(
                            format!("... and {} more", libs.len() - 20),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]),
                    Line::from(""),
                ]));
            } else {
                items.push(ListItem::new(vec![Line::from("")]));
            }
        }
    }

    if items.is_empty() {
        items.push(ListItem::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  No libraries found",
                Style::default().fg(Color::Yellow),
            )]),
        ]));
    }

    let title = if state.filter.is_active() {
        format!(
            " Category Breakdown (Filtered: {}/{}) ",
            state.get_filtered_count(),
            state.library_count()
        )
    } else {
        " Category Breakdown ".to_string()
    };

    let list = List::new(items).block(Block::default().title(title).borders(Borders::ALL));

    f.render_widget(list, area);
}

fn render_statistics_view(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left panel: Library and Risk distributions
    render_distribution_stats(f, state, chunks[0]);

    // Right panel: Summary statistics
    render_summary_stats(f, state, chunks[1]);
}

fn render_distribution_stats(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    use crate::scanner_dashboard::state::{LibraryCategory, RiskLevel};
    use crate::scanner_dashboard::widgets::create_bar_chart;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Category distribution
    let mut category_lines = vec![
        Line::from(Span::styled(
            " Category Distribution",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    let category_data: Vec<(&str, usize, Color)> = vec![
        (
            "SSL/TLS",
            state
                .category_counts
                .get(&LibraryCategory::SslTls)
                .copied()
                .unwrap_or(0),
            Color::LightBlue,
        ),
        (
            "General Crypto",
            state
                .category_counts
                .get(&LibraryCategory::GeneralCrypto)
                .copied()
                .unwrap_or(0),
            Color::Magenta,
        ),
        (
            "Post-Quantum",
            state
                .category_counts
                .get(&LibraryCategory::PostQuantum)
                .copied()
                .unwrap_or(0),
            Color::Green,
        ),
        (
            "Hash Functions",
            state
                .category_counts
                .get(&LibraryCategory::HashFunction)
                .copied()
                .unwrap_or(0),
            Color::Cyan,
        ),
        (
            "Rust Crypto",
            state
                .category_counts
                .get(&LibraryCategory::RustCrypto)
                .copied()
                .unwrap_or(0),
            Color::LightYellow,
        ),
        (
            "Node.js Crypto",
            state
                .category_counts
                .get(&LibraryCategory::NodeCrypto)
                .copied()
                .unwrap_or(0),
            Color::Yellow,
        ),
        (
            "Python Crypto",
            state
                .category_counts
                .get(&LibraryCategory::PythonCrypto)
                .copied()
                .unwrap_or(0),
            Color::LightGreen,
        ),
        (
            "Other",
            state
                .category_counts
                .get(&LibraryCategory::Other)
                .copied()
                .unwrap_or(0),
            Color::Gray,
        ),
    ];

    let chart = create_bar_chart(category_data, 12);
    category_lines.extend(chart);

    let category_widget =
        Paragraph::new(category_lines).block(Block::default().borders(Borders::ALL));

    f.render_widget(category_widget, chunks[0]);

    // Risk distribution
    let mut risk_lines = vec![
        Line::from(Span::styled(
            " Quantum Risk Assessment",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    let risk_data: Vec<(&str, usize, Color)> = vec![
        (
            "Critical Risk",
            state
                .risk_counts
                .get(&RiskLevel::Critical)
                .copied()
                .unwrap_or(0),
            Color::Red,
        ),
        (
            "High Risk",
            state
                .risk_counts
                .get(&RiskLevel::High)
                .copied()
                .unwrap_or(0),
            Color::LightRed,
        ),
        (
            "Medium Risk",
            state
                .risk_counts
                .get(&RiskLevel::Medium)
                .copied()
                .unwrap_or(0),
            Color::Yellow,
        ),
        (
            "Low Risk",
            state.risk_counts.get(&RiskLevel::Low).copied().unwrap_or(0),
            Color::Cyan,
        ),
        (
            "PQ-Ready",
            state
                .risk_counts
                .get(&RiskLevel::None)
                .copied()
                .unwrap_or(0),
            Color::Green,
        ),
    ];

    let risk_chart = create_bar_chart(risk_data, 12);
    risk_lines.extend(risk_chart);

    let risk_widget = Paragraph::new(risk_lines).block(Block::default().borders(Borders::ALL));

    f.render_widget(risk_widget, chunks[1]);
}

fn render_summary_stats(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    use crate::scanner_dashboard::widgets::{format_duration, format_size};

    let runtime = state.get_runtime();
    let quantum_vulnerable = state.get_quantum_vulnerable_count();
    let pq_ready = state.get_pq_ready_count();

    let mut summary_lines = vec![
        Line::from(Span::styled(
            " Scan Summary",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Total Libraries:     ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", state.library_count()),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total Size:          ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_size(state.total_size),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Unique Vendors:      ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", state.unique_vendors.len()),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Quantum Risk Summary",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Vulnerable:          ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "{} ({:.1}%)",
                    quantum_vulnerable,
                    if state.library_count() > 0 {
                        (quantum_vulnerable as f64 / state.library_count() as f64) * 100.0
                    } else {
                        0.0
                    }
                ),
                Style::default().fg(Color::LightRed),
            ),
        ]),
        Line::from(vec![
            Span::styled("PQ-Ready:            ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "{} ({:.1}%)",
                    pq_ready,
                    if state.library_count() > 0 {
                        (pq_ready as f64 / state.library_count() as f64) * 100.0
                    } else {
                        0.0
                    }
                ),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Scan Performance",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Files Scanned:       ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", state.scan_progress.files_scanned),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Directories:         ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", state.scan_progress.dirs_scanned),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Scan Rate:           ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.1} files/sec", state.scan_progress.scan_rate),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Runtime:             ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_duration(runtime.as_secs()),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    // Add final scan speed metric (only when scan is complete)
    if matches!(
        state.scan_status,
        crate::scanner_dashboard::state::ScanStatus::Completed
    ) {
        let runtime_secs = runtime.as_secs();
        if runtime_secs > 0 {
            let files_per_second = state.scan_progress.files_scanned as f64 / runtime_secs as f64;
            summary_lines.push(Line::from(vec![
                Span::styled("Final Scan Speed:    ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{:.1} files/sec", files_per_second),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
    }

    summary_lines.extend(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Status:              ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:?}", state.scan_status),
                match state.scan_status {
                    crate::scanner_dashboard::state::ScanStatus::Running => {
                        Style::default().fg(Color::Green)
                    }
                    crate::scanner_dashboard::state::ScanStatus::Paused => {
                        Style::default().fg(Color::Yellow)
                    }
                    crate::scanner_dashboard::state::ScanStatus::Completed => {
                        Style::default().fg(Color::Blue)
                    }
                    crate::scanner_dashboard::state::ScanStatus::Error(_) => {
                        Style::default().fg(Color::Red)
                    }
                },
            ),
        ]),
    ]);

    let summary_widget = Paragraph::new(summary_lines).block(
        Block::default()
            .title(" Statistics & Analysis ")
            .borders(Borders::ALL),
    );

    f.render_widget(summary_widget, area);
}

fn render_migration_view(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    use crate::scanner_dashboard::state::{MigrationPriority, MigrationStatus};

    let priorities_data = state.get_libraries_by_priority();
    let (not_started, in_progress, completed) = state.get_migration_stats();
    let total_vulnerable = not_started + in_progress + completed;

    // If no migration recommendations yet, show prompt to generate them
    if state.migration_recommendations.is_empty() {
        let prompt = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Post-Quantum Migration Planner",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::raw(
                "  Press 'g' to generate migration recommendations",
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  This will analyze all quantum-vulnerable libraries",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "  and create a prioritized migration plan.",
                Style::default().fg(Color::Gray),
            )),
        ])
        .block(
            Block::default()
                .title(" Post-Quantum Migration Planner ")
                .borders(Borders::ALL),
        );
        f.render_widget(prompt, area);
        return;
    }

    // Split into header and content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Summary header
            Constraint::Min(0),    // Priority sections
        ])
        .split(area);

    // Render summary header
    render_migration_summary(
        f,
        state,
        total_vulnerable,
        not_started,
        in_progress,
        completed,
        chunks[0],
    );

    // Render priority sections
    let mut items = Vec::new();

    for (priority, libs) in priorities_data {
        // Priority section header
        let priority_color = match priority {
            MigrationPriority::Critical => Color::Red,
            MigrationPriority::High => Color::LightRed,
            MigrationPriority::Medium => Color::Yellow,
            MigrationPriority::Low => Color::Cyan,
            MigrationPriority::None => Color::Green,
        };

        let header_line = Line::from(vec![
            Span::styled(
                format!(" {} ", priority.icon()),
                Style::default()
                    .fg(priority_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} PRIORITY ", priority.label()),
                Style::default()
                    .fg(priority_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({} libraries)", libs.len()),
                Style::default().fg(Color::Gray),
            ),
        ]);

        items.push(ListItem::new(vec![
            Line::from(""),
            header_line,
            Line::from(""),
        ]));

        // Show libraries in this priority (limit to 10 per section for readability)
        for lib in libs.iter().take(10) {
            if let Some(rec) = state.migration_recommendations.get(&lib.name) {
                let status = state
                    .migration_statuses
                    .get(&lib.name)
                    .unwrap_or(&MigrationStatus::NotStarted);

                let status_color = match status {
                    MigrationStatus::NotStarted => Color::Gray,
                    MigrationStatus::InProgress => Color::Yellow,
                    MigrationStatus::Completed => Color::Green,
                };

                // Library name with status
                let lib_header = Line::from(vec![
                    Span::raw("  "),
                    Span::styled(status.icon(), Style::default().fg(status_color)),
                    Span::raw(" "),
                    Span::styled(
                        &lib.name,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        format!("[{}]", status.label()),
                        Style::default().fg(status_color),
                    ),
                ]);

                // Current algorithm
                let current_algo = Line::from(vec![
                    Span::raw("     Current:     "),
                    Span::styled(&rec.current_algorithm, Style::default().fg(Color::LightRed)),
                ]);

                // Recommended migration
                let recommended = Line::from(vec![
                    Span::raw("     Migration:   "),
                    Span::styled(
                        &rec.recommended_algorithm,
                        Style::default().fg(Color::LightGreen),
                    ),
                ]);

                // Strategy and timeline
                let strategy_label = match rec.migration_strategy {
                    crate::scanner_dashboard::state::MigrationStrategy::DirectReplacement => {
                        "Direct Replacement"
                    }
                    crate::scanner_dashboard::state::MigrationStrategy::HybridMode => {
                        "Hybrid Classical+PQ"
                    }
                    crate::scanner_dashboard::state::MigrationStrategy::PurePostQuantum => {
                        "Pure Post-Quantum"
                    }
                    crate::scanner_dashboard::state::MigrationStrategy::NoMigrationNeeded => {
                        "No Migration Needed"
                    }
                };

                let timeline_info = Line::from(vec![
                    Span::raw("     Timeline:    "),
                    Span::styled(
                        format!("{} months", rec.timeline_months),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw("  |  Strategy: "),
                    Span::styled(strategy_label, Style::default().fg(Color::Magenta)),
                    Span::raw("  |  Effort: "),
                    Span::styled(rec.effort_level.label(), Style::default().fg(Color::Yellow)),
                ]);

                // Notes
                let notes = Line::from(vec![
                    Span::raw("     Notes:       "),
                    Span::styled(&rec.notes, Style::default().fg(Color::Gray)),
                ]);

                items.push(ListItem::new(vec![
                    lib_header,
                    current_algo,
                    recommended,
                    timeline_info,
                    notes,
                    Line::from(""),
                ]));
            }
        }

        if libs.len() > 10 {
            items.push(ListItem::new(vec![
                Line::from(vec![
                    Span::raw("     "),
                    Span::styled(
                        format!(
                            "... and {} more libraries in this priority",
                            libs.len() - 10
                        ),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(""),
            ]));
        }
    }

    if items.is_empty() {
        items.push(ListItem::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No migration recommendations available",
                Style::default().fg(Color::Yellow),
            )),
        ]));
    }

    let list = List::new(items).block(Block::default().borders(Borders::ALL));

    f.render_widget(list, chunks[1]);
}

fn render_migration_summary(
    f: &mut Frame,
    state: &ScannerDashboardState,
    total_vulnerable: usize,
    not_started: usize,
    in_progress: usize,
    completed: usize,
    area: Rect,
) {
    let timeline = state.get_estimated_timeline();
    let completion_pct = if total_vulnerable > 0 {
        (completed as f64 / total_vulnerable as f64) * 100.0
    } else {
        0.0
    };

    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                "  Libraries Needing Migration: ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                format!("{}", total_vulnerable),
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  "),
            Span::styled("Not Started: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", not_started),
                Style::default().fg(Color::White),
            ),
            Span::raw("  |  "),
            Span::styled("In Progress: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}", in_progress),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("  |  "),
            Span::styled("Completed: ", Style::default().fg(Color::Green)),
            Span::styled(format!("{}", completed), Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("  Estimated Timeline: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} months", timeline),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  "),
            Span::styled("Completion: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.1}%", completion_pct),
                Style::default().fg(if completion_pct > 50.0 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]),
    ];

    let summary = Paragraph::new(summary_lines).block(
        Block::default()
            .title(" Migration Overview ")
            .borders(Borders::ALL),
    );

    f.render_widget(summary, area);
}

fn render_footer(f: &mut Frame, state: &ScannerDashboardState, area: Rect) {
    let quantum_vulnerable = state.get_quantum_vulnerable_count();
    let pq_ready = state.get_pq_ready_count();

    let status_line = format!(
        " Quantum Risk: {} libs vulnerable | PQ-Ready: {} libs ",
        quantum_vulnerable, pq_ready
    );

    // View-specific controls
    let view_controls = match state.current_view {
        ViewMode::LiveScan => {
            " q:Quit h:Help Space:Pause Tab:Views d:Details e:JSON v:CSV f:Filter s:Sort "
        }
        ViewMode::Category => {
            " q:Quit h:Help Tab:Views d:Details e:JSON v:CSV a:Expand c:Collapse "
        }
        ViewMode::Statistics => " q:Quit h:Help Tab:Views e:JSON v:CSV 1-4:Jump ",
        ViewMode::Migration => " q:Quit h:Help Tab:Views g:Generate e:Plan v:CSV m:Mark ",
    };

    let filter_status = if state.filter.is_active() {
        format!(
            " [Filter Active: {}/{}] ",
            state.get_filtered_count(),
            state.library_count()
        )
    } else {
        String::new()
    };

    let sort_status = format!(" [Sort: {:?}] ", state.sort_by);

    let footer_text = vec![
        Line::from(vec![
            Span::raw(status_line),
            Span::styled(filter_status, Style::default().fg(Color::Yellow)),
            Span::styled(sort_status, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(view_controls),
    ];

    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::White));

    f.render_widget(footer, area);
}

fn render_detail_view(f: &mut Frame, state: &ScannerDashboardState) {
    use crate::scanner_dashboard::widgets::format_size;

    // If no library is selected, don't render
    let lib = match &state.detail_library {
        Some(lib) => lib,
        None => return,
    };

    // Create a centered modal overlay (80% width, 85% height)
    let area = f.size();
    let popup_width = (area.width as f32 * 0.80) as u16;
    let popup_height = (area.height as f32 * 0.85) as u16;

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_width,
        height: popup_height,
    };

    // Clear the background area completely (removes underlying content)
    f.render_widget(Clear, popup_area);

    // Risk color coding
    let risk_color = match lib.risk_level {
        crate::scanner_dashboard::state::RiskLevel::None => Color::Green,
        crate::scanner_dashboard::state::RiskLevel::Low => Color::Cyan,
        crate::scanner_dashboard::state::RiskLevel::Medium => Color::Yellow,
        crate::scanner_dashboard::state::RiskLevel::High => Color::LightRed,
        crate::scanner_dashboard::state::RiskLevel::Critical => Color::Red,
    };

    // Build detail content
    let mut detail_lines = vec![
        Line::from(vec![Span::styled(
            "Library Details",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Name:         ", Style::default().fg(Color::Gray)),
            Span::styled(
                &lib.name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Path:         ", Style::default().fg(Color::Gray)),
            Span::raw(lib.path.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Category:     ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} ", lib.category.icon())),
            Span::styled(lib.category.name(), Style::default().fg(Color::Cyan)),
        ]),
    ];

    // Add vendor if available
    if let Some(ref vendor) = lib.vendor {
        detail_lines.push(Line::from(vec![
            Span::styled("Vendor:       ", Style::default().fg(Color::Gray)),
            Span::raw(vendor),
        ]));
    }

    // Add version if available
    if let Some(ref version) = lib.version {
        detail_lines.push(Line::from(vec![
            Span::styled("Version:      ", Style::default().fg(Color::Gray)),
            Span::raw(version),
        ]));
    }

    // Add size and type
    detail_lines.push(Line::from(vec![
        Span::styled("Size:         ", Style::default().fg(Color::Gray)),
        Span::raw(format_size(lib.size)),
    ]));

    detail_lines.push(Line::from(vec![
        Span::styled("Type:         ", Style::default().fg(Color::Gray)),
        Span::raw(format!("{:?}", lib.library_type)),
    ]));

    // Add modified date
    // The guard rejects pre-epoch timestamps, which `DateTime::from` would render
    // misleadingly; the duration itself is not needed, only its validity.
    if lib.modified.duration_since(std::time::UNIX_EPOCH).is_ok() {
        use chrono::{DateTime, Utc};
        let datetime = DateTime::<Utc>::from(lib.modified);
        detail_lines.push(Line::from(vec![
            Span::styled("Modified:     ", Style::default().fg(Color::Gray)),
            Span::raw(datetime.format("%Y-%m-%d %H:%M:%S").to_string()),
        ]));
    }

    detail_lines.push(Line::from(""));

    // Risk Assessment Section
    detail_lines.push(Line::from(vec![Span::styled(
        "Risk Assessment",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )]));
    detail_lines.push(Line::from(""));
    detail_lines.push(Line::from(vec![
        Span::styled("Risk Level:          ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{} {}", lib.risk_level.icon(), lib.risk_level.label()),
            Style::default().fg(risk_color).add_modifier(Modifier::BOLD),
        ),
    ]));
    detail_lines.push(Line::from(vec![
        Span::styled("Quantum Vulnerable:  ", Style::default().fg(Color::Gray)),
        Span::styled(
            if lib.quantum_vulnerable { "Yes" } else { "No" },
            Style::default().fg(if lib.quantum_vulnerable {
                Color::LightRed
            } else {
                Color::Green
            }),
        ),
    ]));

    // Migration Recommendation (if available)
    if let Some(rec) = state.migration_recommendations.get(&lib.name) {
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(vec![Span::styled(
            "Migration Recommendation",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )]));
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(vec![
            Span::styled("Current Algorithm:   ", Style::default().fg(Color::Gray)),
            Span::styled(&rec.current_algorithm, Style::default().fg(Color::LightRed)),
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("Recommended:         ", Style::default().fg(Color::Gray)),
            Span::styled(
                &rec.recommended_algorithm,
                Style::default().fg(Color::LightGreen),
            ),
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("Strategy:            ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{:?}", rec.migration_strategy)),
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("Timeline:            ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} months", rec.timeline_months),
                Style::default().fg(Color::Cyan),
            ),
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("Effort Level:        ", Style::default().fg(Color::Gray)),
            Span::raw(rec.effort_level.label()),
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("Priority:            ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} {}", rec.priority.icon(), rec.priority.label()),
                Style::default().fg(match rec.priority {
                    crate::scanner_dashboard::state::MigrationPriority::Critical => Color::Red,
                    crate::scanner_dashboard::state::MigrationPriority::High => Color::LightRed,
                    crate::scanner_dashboard::state::MigrationPriority::Medium => Color::Yellow,
                    crate::scanner_dashboard::state::MigrationPriority::Low => Color::Cyan,
                    crate::scanner_dashboard::state::MigrationPriority::None => Color::Green,
                }),
            ),
        ]));
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(vec![Span::styled(
            "Notes:",
            Style::default().fg(Color::Gray),
        )]));
        detail_lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(&rec.notes, Style::default().fg(Color::DarkGray)),
        ]));

        // Migration status
        if let Some(status) = state.migration_statuses.get(&lib.name) {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![
                Span::styled("Migration Status:    ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{} {}", status.icon(), status.label()),
                    Style::default().fg(match status {
                        crate::scanner_dashboard::state::MigrationStatus::NotStarted => Color::Gray,
                        crate::scanner_dashboard::state::MigrationStatus::InProgress => {
                            Color::Yellow
                        }
                        crate::scanner_dashboard::state::MigrationStatus::Completed => Color::Green,
                    }),
                ),
            ]));
        }
    }

    // Dependency information (if available)
    if let Some(deps) = state.dependency_map.get(&lib.name) {
        if !deps.is_empty() {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![Span::styled(
                "Dependencies",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]));
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![
                Span::styled("Used by ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{} binaries:", deps.len()),
                    Style::default().fg(Color::White),
                ),
            ]));

            for (i, dep) in deps.iter().take(10).enumerate() {
                detail_lines.push(Line::from(vec![
                    Span::raw("  • "),
                    Span::raw(dep.display().to_string()),
                ]));

                if i == 9 && deps.len() > 10 {
                    detail_lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(
                            format!("... and {} more", deps.len() - 10),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }
        }
    }

    let title = format!(" {} - Library Details [q/Esc:Close] ", lib.name);

    let detail_widget = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    f.render_widget(detail_widget, popup_area);
}

fn render_completion_notification(f: &mut Frame, state: &ScannerDashboardState) {
    use crate::scanner_dashboard::widgets::format_duration;

    // Create a centered modal overlay (65% width, 75% height)
    let area = f.size();
    let popup_width = (area.width as f32 * 0.65) as u16;
    let popup_height = (area.height as f32 * 0.75) as u16;

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_width,
        height: popup_height,
    };

    // Clear the background area completely (removes underlying content)
    f.render_widget(Clear, popup_area);

    // Calculate statistics
    let total_libraries = state.library_count();
    let quantum_vulnerable = state.get_quantum_vulnerable_count();
    let pq_ready = state.get_pq_ready_count();
    let runtime = state.get_runtime();

    // Build notification content
    let notification_lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "🎉  SCAN COMPLETE  🎉",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(""),
        Line::from(vec![Span::styled(
            "SCAN SUMMARY",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Total Libraries Found:      ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                format!("{}", total_libraries),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  Quantum-Vulnerable:         ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                format!(
                    "{} ({:.1}%)",
                    quantum_vulnerable,
                    if total_libraries > 0 {
                        (quantum_vulnerable as f64 / total_libraries as f64) * 100.0
                    } else {
                        0.0
                    }
                ),
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  Post-Quantum Ready:         ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                format!(
                    "{} ({:.1}%)",
                    pq_ready,
                    if total_libraries > 0 {
                        (pq_ready as f64 / total_libraries as f64) * 100.0
                    } else {
                        0.0
                    }
                ),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  Scan Duration:              ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                format_duration(runtime.as_secs()),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(vec![Span::styled(
            "EXPORT OPTIONS",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(Color::Gray)),
            Span::styled(
                "'e'",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" to export results to ", Style::default().fg(Color::Gray)),
            Span::styled("JSON", Style::default().fg(Color::Cyan)),
            Span::styled(" (full scan data)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("      → ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "scan_results_YYYYMMDD_HHMMSS.json",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(Color::Gray)),
            Span::styled(
                "'v'",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " to export library inventory to ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled("CSV", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("      → ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "library_inventory_YYYYMMDD_HHMMSS.csv",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(Color::Gray)),
            Span::styled(
                "'4'",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " to view Migration Planner",
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("      (then press ", Style::default().fg(Color::DarkGray)),
            Span::styled("'e'", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " for migration_plan_YYYYMMDD_HHMMSS.md)",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Files saved to current directory: ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| ".".to_string()),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled("Press ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Space",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" or ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Enter",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" to continue...", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let notification_widget = Paragraph::new(notification_lines)
        .block(
            Block::default()
                .title(" Scan Complete ")
                .borders(Borders::ALL)
                .border_style(
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
                .style(Style::default().bg(Color::Black)),
        )
        .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(notification_widget, popup_area);
}

fn render_help_overlay(f: &mut Frame, _state: &ScannerDashboardState) {
    // Create a centered modal overlay (70% width, 80% height)
    let area = f.size();
    let popup_width = (area.width as f32 * 0.70) as u16;
    let popup_height = (area.height as f32 * 0.80) as u16;

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_width,
        height: popup_height,
    };

    // Clear the background area completely (removes underlying content)
    f.render_widget(Clear, popup_area);

    // Build help content
    let help_lines = vec![
        Line::from(vec![Span::styled(
            "Keyboard Shortcuts Reference",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        // Global Controls
        Line::from(vec![Span::styled(
            "GLOBAL CONTROLS",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  q / Esc       ", Style::default().fg(Color::Green)),
            Span::raw("Quit application (or close overlays)"),
        ]),
        Line::from(vec![
            Span::styled("  h / F1        ", Style::default().fg(Color::Green)),
            Span::raw("Toggle this help screen"),
        ]),
        Line::from(vec![
            Span::styled("  Space         ", Style::default().fg(Color::Green)),
            Span::raw("Pause/Resume scan"),
        ]),
        Line::from(vec![
            Span::styled("  Tab           ", Style::default().fg(Color::Green)),
            Span::raw("Cycle through view modes"),
        ]),
        Line::from(vec![
            Span::styled("  1/2/3/4       ", Style::default().fg(Color::Green)),
            Span::raw("Jump to specific view (Live/Category/Statistics/Migration)"),
        ]),
        Line::from(""),
        // Navigation
        Line::from(vec![Span::styled(
            "NAVIGATION",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ↑ / k         ", Style::default().fg(Color::Green)),
            Span::raw("Scroll up"),
        ]),
        Line::from(vec![
            Span::styled("  ↓ / j         ", Style::default().fg(Color::Green)),
            Span::raw("Scroll down"),
        ]),
        Line::from(vec![
            Span::styled("  Home / g      ", Style::default().fg(Color::Green)),
            Span::raw("Jump to top"),
        ]),
        Line::from(vec![
            Span::styled("  End / G       ", Style::default().fg(Color::Green)),
            Span::raw("Jump to bottom"),
        ]),
        Line::from(""),
        // Export
        Line::from(vec![Span::styled(
            "EXPORT",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  e             ", Style::default().fg(Color::Green)),
            Span::raw("Export to JSON (or Markdown plan in Migration view)"),
        ]),
        Line::from(vec![
            Span::styled("  v             ", Style::default().fg(Color::Green)),
            Span::raw("Export to CSV (library inventory)"),
        ]),
        Line::from(""),
        // View-Specific
        Line::from(vec![Span::styled(
            "VIEW-SPECIFIC CONTROLS",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Live Scan & Category Views:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("    d / Enter   ", Style::default().fg(Color::Green)),
            Span::raw("Open library detail view"),
        ]),
        Line::from(vec![
            Span::styled("    f           ", Style::default().fg(Color::Green)),
            Span::raw("Toggle quantum-vulnerable filter"),
        ]),
        Line::from(vec![
            Span::styled("    x           ", Style::default().fg(Color::Green)),
            Span::raw("Clear all filters"),
        ]),
        Line::from(vec![
            Span::styled("    s           ", Style::default().fg(Color::Green)),
            Span::raw("Cycle sort order (name/category/risk/size/date)"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Category View Only:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("    a           ", Style::default().fg(Color::Green)),
            Span::raw("Expand all categories"),
        ]),
        Line::from(vec![
            Span::styled("    c           ", Style::default().fg(Color::Green)),
            Span::raw("Collapse all categories"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Migration Planner View:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("    g           ", Style::default().fg(Color::Green)),
            Span::raw("Generate migration recommendations"),
        ]),
        Line::from(vec![
            Span::styled("    m           ", Style::default().fg(Color::Green)),
            Span::raw("Toggle migration status (Not Started → In Progress → Completed)"),
        ]),
        Line::from(""),
        // Tips
        Line::from(vec![Span::styled(
            "TIPS",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  • Press "),
            Span::styled(
                "d",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" on any library to see full details, risk assessment, and migration plan"),
        ]),
        Line::from(vec![
            Span::raw("  • Use "),
            Span::styled(
                "e",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" for JSON export or "),
            Span::styled(
                "v",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" for CSV export for external analysis"),
        ]),
        Line::from(vec![
            Span::raw("  • Filter quantum-vulnerable libraries with "),
            Span::styled(
                "f",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to focus on migration priorities"),
        ]),
        Line::from(vec![Span::raw(
            "  • Generated files are saved with timestamps in the current directory",
        )]),
    ];

    let help_widget = Paragraph::new(help_lines)
        .block(
            Block::default()
                .title(" Keyboard Shortcuts - Press h/F1 or q/Esc to close ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .style(Style::default().bg(Color::Black)),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    f.render_widget(help_widget, popup_area);
}
