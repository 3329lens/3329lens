/*
 * Scanner Dashboard Module - Real-time Cryptographic Library Scanner
 *
 * Provides an interactive terminal dashboard for real-time visualization
 * and analysis of cryptographic library discovery during filesystem scans.
 *
 * Features:
 * - Live scan progress with library discovery
 * - Category-based organization
 * - Post-quantum migration planning
 * - Statistical analysis and charts
 * - Interactive controls (pause, filtering, view switching)
 */

pub mod events;
pub mod state;
pub mod ui;
pub mod widgets;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::{handle_events, AppAction};
use ratatui::{backend::CrosstermBackend, Terminal};
use state::{ScannerDashboardState, ScannerMessage};
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

pub struct ScannerDashboardConfig {
    pub path: PathBuf,
    pub depth: Option<usize>,
    pub refresh_rate: u64,
}

/// Run the interactive scanner dashboard
pub fn run_scanner_dashboard(
    config: ScannerDashboardConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize dashboard state
    let mut state = ScannerDashboardState::new(config.path.clone(), config.depth);

    // Create channels for scanner communication
    let (tx_scanner, rx_scanner): (Sender<ScannerMessage>, Receiver<ScannerMessage>) =
        mpsc::channel();
    let (tx_command, rx_command) = mpsc::channel();

    // Spawn scanner thread
    let scan_path = config.path.clone();
    let scan_depth = config.depth;
    let scanner_handle =
        thread::spawn(move || run_scanner_thread(scan_path, scan_depth, tx_scanner, rx_command));

    // Main application loop
    let result = run_app(&mut terminal, &mut state, rx_scanner, config.refresh_rate);

    // Cleanup: stop scanner thread
    drop(tx_command); // Close command channel to signal scanner to stop
    let _ = scanner_handle.join();

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut ScannerDashboardState,
    rx_scanner: Receiver<ScannerMessage>,
    refresh_rate: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame_duration = Duration::from_millis(1000 / refresh_rate);

    loop {
        // Process scanner messages (non-blocking)
        while let Ok(msg) = rx_scanner.try_recv() {
            state.handle_scanner_message(msg);
        }

        // Draw UI
        terminal.draw(|f| ui::render(f, state))?;

        // Handle events with timeout
        match handle_events(state, frame_duration)? {
            AppAction::Quit => break,
            AppAction::Continue => {}
        }
    }

    Ok(())
}

fn run_scanner_thread(
    path: PathBuf,
    depth: Option<usize>,
    tx: Sender<ScannerMessage>,
    rx_commands: Receiver<()>,
) {
    use scanner_core::scanner::{CryptoScanner, StreamingScanEvent};
    use std::time::Instant;

    let mut scanner = CryptoScanner::new();
    let start_time = Instant::now();

    let path_str = path.display().to_string();

    // Run streaming scan with callback
    let result = scanner.scan_streaming(&path_str, depth, |event| {
        // Check for stop command (non-blocking)
        if rx_commands.try_recv().is_ok() {
            return; // Exit early
        }

        match event {
            StreamingScanEvent::Progress {
                files_scanned,
                dirs_scanned,
                estimated_total,
                current_path,
            } => {
                let elapsed = start_time.elapsed();
                let scan_rate = if elapsed.as_secs() > 0 {
                    files_scanned as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                let _ = tx.send(ScannerMessage::ProgressUpdate(state::ScanProgress {
                    files_scanned,
                    dirs_scanned,
                    estimated_total_files: estimated_total,
                    current_path,
                    scan_rate,
                }));
            }
            StreamingScanEvent::LibraryFound(library_info) => {
                let _ = tx.send(ScannerMessage::LibraryDiscovered(library_info));
            }
            StreamingScanEvent::Complete { total_libraries } => {
                let duration = start_time.elapsed();
                let _ = tx.send(ScannerMessage::ScanComplete {
                    total_libraries,
                    duration,
                });
            }
        }
    });

    // Handle error if scan failed
    if let Err(e) = result {
        let _ = tx.send(ScannerMessage::ScanError(e.to_string()));
    }
}
