/*
 * Event Handling for Scanner Dashboard
 *
 * Manages keyboard input and user interactions for the scanner dashboard
 */

use crate::scanner_dashboard::state::{ScannerDashboardState, ViewMode};
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use std::time::Duration;

pub enum AppAction {
    Continue,
    Quit,
}

/// Poll for keyboard events and handle them
pub fn handle_events(
    state: &mut ScannerDashboardState,
    timeout: Duration,
) -> Result<AppAction, Box<dyn std::error::Error>> {
    if event::poll(timeout)? {
        if let Event::Key(key) = event::read()? {
            return handle_key_event(state, key);
        }
    }
    Ok(AppAction::Continue)
}

fn handle_key_event(
    state: &mut ScannerDashboardState,
    key: KeyEvent,
) -> Result<AppAction, Box<dyn std::error::Error>> {
    use crate::scanner_dashboard::state::LibraryCategory;

    // If completion notification is shown, Space or Enter dismisses it
    if state.completion_notification_shown
        && matches!(key.code, KeyCode::Char(' ') | KeyCode::Enter)
    {
        state.dismiss_completion_notification();
        return Ok(AppAction::Continue);
    }
    // Allow 'e' and 'v' for exports even when notification is shown
    // (handled in the match below)

    match key.code {
        // Quit - but close overlays first if open (completion, help, detail, then quit)
        KeyCode::Char('q') | KeyCode::Esc => {
            if state.completion_notification_shown {
                state.dismiss_completion_notification();
                Ok(AppAction::Continue)
            } else if state.help_overlay_open {
                state.close_help_overlay();
                Ok(AppAction::Continue)
            } else if state.detail_view_open {
                state.close_detail_view();
                Ok(AppAction::Continue)
            } else {
                Ok(AppAction::Quit)
            }
        }

        // Pause/Resume (or dismiss completion notification)
        KeyCode::Char(' ') => {
            if state.completion_notification_shown {
                state.dismiss_completion_notification();
            } else {
                state.toggle_pause();
            }
            Ok(AppAction::Continue)
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            state.scroll_up();
            Ok(AppAction::Continue)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.scroll_down();
            Ok(AppAction::Continue)
        }
        KeyCode::Home => {
            state.scroll_to_top();
            Ok(AppAction::Continue)
        }
        KeyCode::Char('g') => {
            // In Migration view, 'g' generates recommendations
            if state.current_view == ViewMode::Migration {
                state.generate_migration_recommendations();
            } else {
                // In other views, 'g' scrolls to top
                state.scroll_to_top();
            }
            Ok(AppAction::Continue)
        }
        KeyCode::End | KeyCode::Char('G') => {
            state.scroll_to_bottom();
            Ok(AppAction::Continue)
        }

        // View switching
        KeyCode::Tab => {
            state.cycle_view();
            Ok(AppAction::Continue)
        }
        KeyCode::Char('1') => {
            state.current_view = ViewMode::LiveScan;
            Ok(AppAction::Continue)
        }
        KeyCode::Char('2') => {
            state.current_view = ViewMode::Category;
            Ok(AppAction::Continue)
        }
        KeyCode::Char('3') => {
            state.current_view = ViewMode::Statistics;
            Ok(AppAction::Continue)
        }
        KeyCode::Char('4') => {
            state.current_view = ViewMode::Migration;
            Ok(AppAction::Continue)
        }

        // Detail view / Category view controls
        KeyCode::Enter | KeyCode::Char('d') => {
            if state.current_view == ViewMode::Category && key.code == KeyCode::Enter {
                // In Category view, Enter toggles categories
                // Toggle the first category for now (in future, use selected_index)
                // This is a simplified version - a full implementation would track which category is selected
                state.toggle_category(LibraryCategory::SslTls);
            } else {
                // In other views, 'd' or Enter opens detail view
                if let Some(library) = state.get_selected_library() {
                    state.open_detail_view(library.clone());
                }
            }
            Ok(AppAction::Continue)
        }
        KeyCode::Char('a') => {
            if state.current_view == ViewMode::Category {
                state.expand_all_categories();
            }
            Ok(AppAction::Continue)
        }
        KeyCode::Char('c') => {
            if state.current_view == ViewMode::Category {
                state.collapse_all_categories();
            }
            Ok(AppAction::Continue)
        }

        // Filtering controls
        KeyCode::Char('f') => {
            state.toggle_quantum_vulnerable_filter();
            Ok(AppAction::Continue)
        }
        KeyCode::Char('x') => {
            state.clear_filter();
            Ok(AppAction::Continue)
        }

        // Sorting controls
        KeyCode::Char('s') => {
            state.cycle_sort();
            Ok(AppAction::Continue)
        }

        // Migration planner controls
        KeyCode::Char('m') => {
            if state.current_view == ViewMode::Migration {
                // Toggle migration status for the first vulnerable library (simplified)
                // In a full implementation, this would use selected_index to pick the library
                let library_name = state
                    .get_all_libraries()
                    .iter()
                    .find(|l| l.quantum_vulnerable)
                    .map(|lib| lib.name.clone());

                if let Some(name) = library_name {
                    state.toggle_migration_status(&name);
                }
            }
            Ok(AppAction::Continue)
        }

        // Export: 'e' key - JSON in most views, Markdown in Migration view
        KeyCode::Char('e') => {
            if state.current_view == ViewMode::Migration {
                // Export migration plan to markdown file
                let markdown = state.export_migration_plan();
                let filename = format!(
                    "migration_plan_{}.md",
                    chrono::Local::now().format("%Y%m%d_%H%M%S")
                );

                if let Err(e) = std::fs::write(&filename, markdown) {
                    eprintln!("Failed to export migration plan: {}", e);
                }
            } else {
                // Export full scan results to JSON
                match state.export_to_json() {
                    Ok(json) => {
                        let filename = format!(
                            "scan_results_{}.json",
                            chrono::Local::now().format("%Y%m%d_%H%M%S")
                        );

                        if let Err(e) = std::fs::write(&filename, json) {
                            eprintln!("Failed to export JSON: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to generate JSON: {}", e);
                    }
                }
            }
            Ok(AppAction::Continue)
        }

        // Export to CSV: 'v' key (all views)
        KeyCode::Char('v') => {
            let csv = state.export_to_csv();
            let filename = format!(
                "library_inventory_{}.csv",
                chrono::Local::now().format("%Y%m%d_%H%M%S")
            );

            if let Err(e) = std::fs::write(&filename, csv) {
                eprintln!("Failed to export CSV: {}", e);
            }
            Ok(AppAction::Continue)
        }

        // Help overlay: 'h' or F1 key
        KeyCode::Char('h') | KeyCode::F(1) => {
            state.toggle_help_overlay();
            Ok(AppAction::Continue)
        }

        _ => Ok(AppAction::Continue),
    }
}
