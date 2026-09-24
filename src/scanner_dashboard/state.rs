/*
 * Scanner Dashboard State Management
 *
 * Manages the real-time state of the cryptographic library scanner including:
 * - Discovered libraries collection
 * - Scan progress tracking
 * - Category and risk statistics
 * - UI state (view mode, selection, filters)
 */

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// Scan-result data types now live in the scanner crate; re-exported here so
// existing dashboard code and consumers keep their import paths.
#[allow(unused_imports)]
pub use scanner_core::library::{LibraryCategory, LibraryInfo, LibraryType, RiskLevel};

const MAX_RECENT_LIBRARIES: usize = 50; // Ring buffer size for recent discoveries

// Indexed library storage for O(1) lookups
pub struct LibraryStore {
    libraries: Vec<LibraryInfo>,
    by_category: HashMap<LibraryCategory, Vec<usize>>,
    by_risk: HashMap<RiskLevel, Vec<usize>>,
    by_name: BTreeMap<String, usize>,
}

impl LibraryStore {
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            by_category: HashMap::new(),
            by_risk: HashMap::new(),
            by_name: BTreeMap::new(),
        }
    }

    /// Add a library and update all indexes
    pub fn add(&mut self, library: LibraryInfo) {
        let idx = self.libraries.len();

        // Update category index
        self.by_category
            .entry(library.category.clone())
            .or_insert_with(Vec::new)
            .push(idx);

        // Update risk index
        self.by_risk
            .entry(library.risk_level.clone())
            .or_insert_with(Vec::new)
            .push(idx);

        // Update name index
        self.by_name.insert(library.name.clone(), idx);

        // Add to main storage
        self.libraries.push(library);
    }

    /// Get all libraries
    pub fn get_all(&self) -> &[LibraryInfo] {
        &self.libraries
    }

    /// Get libraries by category (O(1) lookup)
    pub fn get_by_category(&self, category: &LibraryCategory) -> Vec<&LibraryInfo> {
        self.by_category
            .get(category)
            .map(|indexes| indexes.iter().map(|&i| &self.libraries[i]).collect())
            .unwrap_or_default()
    }

    /// Get libraries by risk level (O(1) lookup)
    pub fn get_by_risk(&self, risk: &RiskLevel) -> Vec<&LibraryInfo> {
        self.by_risk
            .get(risk)
            .map(|indexes| indexes.iter().map(|&i| &self.libraries[i]).collect())
            .unwrap_or_default()
    }

    /// Get library by name (O(log n) lookup)
    pub fn get_by_name(&self, name: &str) -> Option<&LibraryInfo> {
        self.by_name.get(name).map(|&idx| &self.libraries[idx])
    }

    /// Get total count
    pub fn len(&self) -> usize {
        self.libraries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.libraries.is_empty()
    }

    /// Get category count
    pub fn category_count(&self, category: &LibraryCategory) -> usize {
        self.by_category.get(category).map(|v| v.len()).unwrap_or(0)
    }

    /// Get risk count
    pub fn risk_count(&self, risk: &RiskLevel) -> usize {
        self.by_risk.get(risk).map(|v| v.len()).unwrap_or(0)
    }

    /// Iterator over all libraries
    pub fn iter(&self) -> impl Iterator<Item = &LibraryInfo> {
        self.libraries.iter()
    }
}

// Migration-specific data structures

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum MigrationStatus {
    NotStarted,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, Serialize)]
pub struct MigrationRecommendation {
    pub current_algorithm: String,
    pub recommended_algorithm: String,
    pub migration_strategy: MigrationStrategy,
    pub timeline_months: u32,
    pub effort_level: EffortLevel,
    pub priority: MigrationPriority,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum MigrationStrategy {
    DirectReplacement, // Simple swap (e.g., SHA-256 is fine)
    HybridMode,        // Classical + PQ (e.g., RSA + Kyber)
    PurePostQuantum,   // Full PQ replacement
    NoMigrationNeeded, // Already PQ-ready
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum MigrationPriority {
    Critical, // Immediate action required
    High,     // 0-6 months
    Medium,   // 6-18 months
    Low,      // 18-36 months
    None,     // No migration needed
}

pub struct ScannerDashboardState {
    // Scan configuration
    pub scan_path: PathBuf,
    pub scan_depth: Option<usize>,

    // Scan status
    pub scan_status: ScanStatus,
    pub start_time: Instant,
    pub completion_time: Option<Duration>, // Frozen runtime when scan completes

    // Discovered data (indexed for performance)
    library_store: LibraryStore,
    pub recent_libraries: VecDeque<LibraryInfo>, // Ring buffer for display
    pub scan_progress: ScanProgress,

    // UI state
    pub current_view: ViewMode,
    pub selected_index: usize,
    pub scroll_offset: usize,

    // Category view state
    pub expanded_categories: HashSet<LibraryCategory>,

    // Filtering and sorting
    pub filter: LibraryFilter,
    pub sort_by: SortBy,

    // Statistics (streaming)
    pub category_counts: HashMap<LibraryCategory, usize>,
    pub risk_counts: HashMap<RiskLevel, usize>,
    pub total_size: u64,
    pub unique_vendors: HashSet<String>,

    // Migration planning state
    pub migration_statuses: HashMap<String, MigrationStatus>, // library name -> status
    pub migration_recommendations: HashMap<String, MigrationRecommendation>, // library name -> recommendation
    pub dependency_map: HashMap<String, Vec<PathBuf>>, // library name -> dependent binaries

    // Detail view state
    pub detail_view_open: bool,
    pub detail_library: Option<LibraryInfo>,

    // Help overlay state
    pub help_overlay_open: bool,

    // Completion notification state
    pub completion_notification_shown: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    Running,
    Paused,
    Completed,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub files_scanned: usize,
    pub dirs_scanned: usize,
    pub estimated_total_files: Option<usize>,
    pub current_path: PathBuf,
    pub scan_rate: f64, // files per second
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ViewMode {
    LiveScan,
    Category,
    Migration,
    Statistics,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LibraryFilter {
    pub categories: Option<Vec<LibraryCategory>>,
    pub risk_levels: Option<Vec<RiskLevel>>,
    pub show_quantum_vulnerable_only: bool,
    pub name_pattern: Option<String>,
}

impl Default for LibraryFilter {
    fn default() -> Self {
        Self {
            categories: None,
            risk_levels: None,
            show_quantum_vulnerable_only: false,
            name_pattern: None,
        }
    }
}

impl LibraryFilter {
    pub fn matches(&self, library: &LibraryInfo) -> bool {
        // Check category filter
        if let Some(ref categories) = self.categories {
            if !categories.contains(&library.category) {
                return false;
            }
        }

        // Check risk level filter
        if let Some(ref risk_levels) = self.risk_levels {
            if !risk_levels.contains(&library.risk_level) {
                return false;
            }
        }

        // Check quantum vulnerable filter
        if self.show_quantum_vulnerable_only && !library.quantum_vulnerable {
            return false;
        }

        // Check name pattern
        if let Some(ref pattern) = self.name_pattern {
            if !library
                .name
                .to_lowercase()
                .contains(&pattern.to_lowercase())
            {
                return false;
            }
        }

        true
    }

    pub fn is_active(&self) -> bool {
        self.categories.is_some()
            || self.risk_levels.is_some()
            || self.show_quantum_vulnerable_only
            || self.name_pattern.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortBy {
    Name,
    Category,
    Risk,
    Size,
    Date,
}

// Messages sent from scanner thread to UI thread
#[derive(Debug, Clone)]
pub enum ScannerMessage {
    LibraryDiscovered(LibraryInfo),
    ProgressUpdate(ScanProgress),
    ScanComplete {
        total_libraries: usize,
        duration: Duration,
    },
    ScanError(String),
}

impl ScannerDashboardState {
    pub fn new(scan_path: PathBuf, scan_depth: Option<usize>) -> Self {
        Self {
            scan_path,
            scan_depth,
            scan_status: ScanStatus::Running,
            start_time: Instant::now(),
            completion_time: None,
            library_store: LibraryStore::new(),
            recent_libraries: VecDeque::with_capacity(MAX_RECENT_LIBRARIES),
            scan_progress: ScanProgress {
                files_scanned: 0,
                dirs_scanned: 0,
                estimated_total_files: None,
                current_path: PathBuf::new(),
                scan_rate: 0.0,
            },
            current_view: ViewMode::LiveScan,
            selected_index: 0,
            scroll_offset: 0,
            expanded_categories: HashSet::new(),
            filter: LibraryFilter::default(),
            sort_by: SortBy::Name,
            category_counts: HashMap::new(),
            risk_counts: HashMap::new(),
            total_size: 0,
            unique_vendors: HashSet::new(),
            migration_statuses: HashMap::new(),
            migration_recommendations: HashMap::new(),
            dependency_map: HashMap::new(),
            detail_view_open: false,
            detail_library: None,
            help_overlay_open: false,
            completion_notification_shown: false,
        }
    }

    /// Handle a message from the scanner thread
    pub fn handle_scanner_message(&mut self, msg: ScannerMessage) {
        match msg {
            ScannerMessage::LibraryDiscovered(library) => {
                self.add_library(library);
            }
            ScannerMessage::ProgressUpdate(progress) => {
                self.scan_progress = progress;
            }
            ScannerMessage::ScanComplete {
                total_libraries,
                duration: _,
            } => {
                self.scan_status = ScanStatus::Completed;
                self.completion_time = Some(self.start_time.elapsed()); // Freeze runtime
                self.completion_notification_shown = true; // Show completion notification
                                                           // Verify count matches
                debug_assert_eq!(self.library_store.len(), total_libraries);
            }
            ScannerMessage::ScanError(error) => {
                self.scan_status = ScanStatus::Error(error);
            }
        }
    }

    /// Add a newly discovered library (streaming update)
    pub fn add_library(&mut self, library: LibraryInfo) {
        // Update counts
        *self
            .category_counts
            .entry(library.category.clone())
            .or_insert(0) += 1;
        *self
            .risk_counts
            .entry(library.risk_level.clone())
            .or_insert(0) += 1;

        // Update statistics
        self.total_size += library.size;
        if let Some(vendor) = &library.vendor {
            self.unique_vendors.insert(vendor.clone());
        }

        // Add to recent libraries (ring buffer)
        if self.recent_libraries.len() >= MAX_RECENT_LIBRARIES {
            self.recent_libraries.pop_front();
        }
        self.recent_libraries.push_back(library.clone());

        // Add to indexed store (O(1) indexing)
        self.library_store.add(library);
    }

    pub fn toggle_pause(&mut self) {
        self.scan_status = match &self.scan_status {
            ScanStatus::Running => ScanStatus::Paused,
            ScanStatus::Paused => ScanStatus::Running,
            other => other.clone(),
        };
    }

    pub fn cycle_view(&mut self) {
        self.current_view = match self.current_view {
            ViewMode::LiveScan => ViewMode::Category,
            ViewMode::Category => ViewMode::Statistics,
            ViewMode::Statistics => ViewMode::Migration,
            ViewMode::Migration => ViewMode::LiveScan,
        };
    }

    pub fn get_runtime(&self) -> Duration {
        // If scan is completed, return frozen time; otherwise return elapsed time
        self.completion_time
            .unwrap_or_else(|| self.start_time.elapsed())
    }

    // Library store accessor methods
    pub fn get_all_libraries(&self) -> &[LibraryInfo] {
        self.library_store.get_all()
    }

    pub fn get_library_by_name(&self, name: &str) -> Option<&LibraryInfo> {
        self.library_store.get_by_name(name)
    }

    pub fn library_count(&self) -> usize {
        self.library_store.len()
    }

    pub fn get_quantum_vulnerable_count(&self) -> usize {
        self.library_store
            .iter()
            .filter(|lib| lib.quantum_vulnerable)
            .count()
    }

    pub fn get_pq_ready_count(&self) -> usize {
        self.category_counts
            .get(&LibraryCategory::PostQuantum)
            .copied()
            .unwrap_or(0)
    }

    pub fn scroll_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        let max_index = self.recent_libraries.len().saturating_sub(1);
        if self.selected_index < max_index {
            self.selected_index += 1;
        }
    }

    pub fn scroll_to_top(&mut self) {
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.selected_index = self.recent_libraries.len().saturating_sub(1);
    }

    // Category view methods
    pub fn toggle_category(&mut self, category: LibraryCategory) {
        if self.expanded_categories.contains(&category) {
            self.expanded_categories.remove(&category);
        } else {
            self.expanded_categories.insert(category);
        }
    }

    pub fn expand_all_categories(&mut self) {
        self.expanded_categories.clear();
        for category in &[
            LibraryCategory::SslTls,
            LibraryCategory::GeneralCrypto,
            LibraryCategory::PostQuantum,
            LibraryCategory::HashFunction,
            LibraryCategory::RustCrypto,
            LibraryCategory::NodeCrypto,
            LibraryCategory::PythonCrypto,
            LibraryCategory::Other,
        ] {
            self.expanded_categories.insert(category.clone());
        }
    }

    pub fn collapse_all_categories(&mut self) {
        self.expanded_categories.clear();
    }

    pub fn is_category_expanded(&self, category: &LibraryCategory) -> bool {
        self.expanded_categories.contains(category)
    }

    // Get libraries grouped by category (O(1) lookup per category)
    pub fn get_libraries_by_category(&self) -> Vec<(LibraryCategory, Vec<&LibraryInfo>)> {
        let mut result = Vec::new();

        for category in &[
            LibraryCategory::SslTls,
            LibraryCategory::GeneralCrypto,
            LibraryCategory::PostQuantum,
            LibraryCategory::HashFunction,
            LibraryCategory::RustCrypto,
            LibraryCategory::NodeCrypto,
            LibraryCategory::PythonCrypto,
            LibraryCategory::Other,
        ] {
            // Use indexed lookup - O(1) instead of O(n)
            let mut libs: Vec<&LibraryInfo> = self
                .library_store
                .get_by_category(category)
                .into_iter()
                .filter(|lib| self.filter.matches(lib))
                .collect();

            if !libs.is_empty() {
                self.sort_libraries(&mut libs);
                result.push((category.clone(), libs));
            }
        }

        result
    }

    // Sorting
    pub fn cycle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            SortBy::Name => SortBy::Category,
            SortBy::Category => SortBy::Risk,
            SortBy::Risk => SortBy::Size,
            SortBy::Size => SortBy::Date,
            SortBy::Date => SortBy::Name,
        };
    }

    fn sort_libraries(&self, libs: &mut [&LibraryInfo]) {
        match self.sort_by {
            SortBy::Name => libs.sort_by(|a, b| a.name.cmp(&b.name)),
            SortBy::Category => libs.sort_by(|a, b| a.category.name().cmp(b.category.name())),
            SortBy::Risk => libs.sort_by(|a, b| b.risk_level.cmp(&a.risk_level)), // High to low
            SortBy::Size => libs.sort_by(|a, b| b.size.cmp(&a.size)),             // Large to small
            SortBy::Date => libs.sort_by(|a, b| b.modified.cmp(&a.modified)),     // Newest first
        }
    }

    // Get filtered and sorted libraries
    pub fn get_filtered_libraries(&self) -> Vec<&LibraryInfo> {
        let mut libs: Vec<&LibraryInfo> = self
            .library_store
            .iter()
            .filter(|lib| self.filter.matches(lib))
            .collect();

        self.sort_libraries(&mut libs);
        libs
    }

    // Filtering methods
    pub fn toggle_quantum_vulnerable_filter(&mut self) {
        self.filter.show_quantum_vulnerable_only = !self.filter.show_quantum_vulnerable_only;
    }

    pub fn clear_filter(&mut self) {
        self.filter = LibraryFilter::default();
    }

    pub fn get_filtered_count(&self) -> usize {
        self.library_store
            .iter()
            .filter(|lib| self.filter.matches(lib))
            .count()
    }

    // Detail view methods
    pub fn open_detail_view(&mut self, library: LibraryInfo) {
        self.detail_library = Some(library);
        self.detail_view_open = true;
    }

    pub fn close_detail_view(&mut self) {
        self.detail_view_open = false;
        self.detail_library = None;
    }

    pub fn get_selected_library(&self) -> Option<&LibraryInfo> {
        // Get the currently selected library from recent_libraries based on selected_index
        if self.recent_libraries.is_empty() {
            return None;
        }

        let reversed_index = self
            .recent_libraries
            .len()
            .saturating_sub(1)
            .saturating_sub(self.selected_index);
        self.recent_libraries.get(reversed_index)
    }

    // Help overlay methods
    pub fn toggle_help_overlay(&mut self) {
        self.help_overlay_open = !self.help_overlay_open;
    }

    pub fn close_help_overlay(&mut self) {
        self.help_overlay_open = false;
    }

    // Completion notification methods
    pub fn dismiss_completion_notification(&mut self) {
        self.completion_notification_shown = false;
    }

    // Migration planning methods

    /// Generate migration recommendations for all vulnerable libraries
    pub fn generate_migration_recommendations(&mut self) {
        for lib in self.library_store.iter() {
            if lib.quantum_vulnerable {
                let recommendation = self.create_recommendation_for_library(lib);
                self.migration_recommendations
                    .insert(lib.name.clone(), recommendation);

                // Initialize migration status
                if !self.migration_statuses.contains_key(&lib.name) {
                    self.migration_statuses
                        .insert(lib.name.clone(), MigrationStatus::NotStarted);
                }
            }
        }
    }

    /// Create a migration recommendation for a specific library
    fn create_recommendation_for_library(&self, lib: &LibraryInfo) -> MigrationRecommendation {
        // Determine algorithm type based on library name and category
        let (current_algorithm, recommended_algorithm, strategy, timeline, effort, priority, notes) =
            match (&lib.category, lib.risk_level.clone()) {
                // High-risk RSA/DSA libraries
                (LibraryCategory::SslTls, RiskLevel::High) |
                (LibraryCategory::GeneralCrypto, RiskLevel::High) => {
                    if lib.name.contains("openssl") || lib.name.contains("libssl") {
                        (
                            "RSA-2048/4096, DHE".to_string(),
                            "Hybrid: X25519 + ML-KEM-768 (Kyber)".to_string(),
                            MigrationStrategy::HybridMode,
                            6,
                            EffortLevel::High,
                            MigrationPriority::High,
                            "OpenSSL 3.2+ supports hybrid PQ. Upgrade recommended within 6-12 months.".to_string(),
                        )
                    } else if lib.name.contains("gnutls") {
                        (
                            "RSA-2048, DHE".to_string(),
                            "ML-KEM-768 (NIST approved)".to_string(),
                            MigrationStrategy::HybridMode,
                            12,
                            EffortLevel::High,
                            MigrationPriority::High,
                            "GnuTLS PQ support planned. Monitor for updates.".to_string(),
                        )
                    } else {
                        (
                            "RSA/DSA key exchange".to_string(),
                            "ML-KEM or hybrid classical+PQ".to_string(),
                            MigrationStrategy::HybridMode,
                            12,
                            EffortLevel::VeryHigh,
                            MigrationPriority::Critical,
                            "Legacy library with high quantum risk. Consider replacement.".to_string(),
                        )
                    }
                },

                // Medium-risk ECDH/ECDSA libraries
                (LibraryCategory::SslTls, RiskLevel::Medium) |
                (LibraryCategory::GeneralCrypto, RiskLevel::Medium) => {
                    (
                        "ECDH/ECDSA (P-256, X25519)".to_string(),
                        "Hybrid: X25519 + ML-KEM-768".to_string(),
                        MigrationStrategy::HybridMode,
                        18,
                        EffortLevel::Medium,
                        MigrationPriority::Medium,
                        "Modern ECC has some quantum resistance. Hybrid mode recommended in 12-24 months.".to_string(),
                    )
                },

                // Critical legacy algorithms
                (_, RiskLevel::Critical) => {
                    (
                        "MD5, DES, or other legacy crypto".to_string(),
                        "Modern alternatives (AES-256, SHA-3)".to_string(),
                        MigrationStrategy::DirectReplacement,
                        3,
                        EffortLevel::VeryHigh,
                        MigrationPriority::Critical,
                        "IMMEDIATE ACTION REQUIRED: Legacy algorithms are already broken.".to_string(),
                    )
                },

                // Low-risk hash functions
                (LibraryCategory::HashFunction, RiskLevel::Low) => {
                    (
                        "SHA-256, SHA-3".to_string(),
                        "No migration needed".to_string(),
                        MigrationStrategy::NoMigrationNeeded,
                        0,
                        EffortLevel::Low,
                        MigrationPriority::None,
                        "Hash functions are quantum-resistant. Continue monitoring standards.".to_string(),
                    )
                },

                // Post-quantum libraries
                (LibraryCategory::PostQuantum, _) => {
                    (
                        "Post-Quantum algorithms".to_string(),
                        "Already PQ-ready".to_string(),
                        MigrationStrategy::NoMigrationNeeded,
                        0,
                        EffortLevel::Low,
                        MigrationPriority::None,
                        "Library is post-quantum ready. No migration needed.".to_string(),
                    )
                },

                // Default case
                _ => {
                    (
                        "Unknown algorithm".to_string(),
                        "Evaluate and assess".to_string(),
                        MigrationStrategy::DirectReplacement,
                        12,
                        EffortLevel::Medium,
                        MigrationPriority::Medium,
                        "Review library documentation for specific algorithms used.".to_string(),
                    )
                }
            };

        MigrationRecommendation {
            current_algorithm,
            recommended_algorithm,
            migration_strategy: strategy,
            timeline_months: timeline,
            effort_level: effort,
            priority,
            notes,
        }
    }

    /// Get libraries grouped by migration priority
    pub fn get_libraries_by_priority(&self) -> Vec<(MigrationPriority, Vec<&LibraryInfo>)> {
        let mut result: Vec<(MigrationPriority, Vec<&LibraryInfo>)> = vec![
            (MigrationPriority::Critical, Vec::new()),
            (MigrationPriority::High, Vec::new()),
            (MigrationPriority::Medium, Vec::new()),
            (MigrationPriority::Low, Vec::new()),
        ];

        for lib in self.library_store.iter() {
            if let Some(rec) = self.migration_recommendations.get(&lib.name) {
                for (priority, libs) in &mut result {
                    if priority == &rec.priority {
                        libs.push(lib);
                        break;
                    }
                }
            }
        }

        // Remove empty priority levels and sort within each priority
        result
            .into_iter()
            .filter(|(_, libs)| !libs.is_empty())
            .map(|(priority, mut libs)| {
                libs.sort_by(|a, b| a.name.cmp(&b.name));
                (priority, libs)
            })
            .collect()
    }

    /// Mark a library as migrated
    pub fn mark_library_migrated(&mut self, library_name: &str) {
        self.migration_statuses
            .insert(library_name.to_string(), MigrationStatus::Completed);
    }

    /// Mark a library migration as in progress
    pub fn mark_library_in_progress(&mut self, library_name: &str) {
        self.migration_statuses
            .insert(library_name.to_string(), MigrationStatus::InProgress);
    }

    /// Toggle migration status between NotStarted -> InProgress -> Completed -> NotStarted
    pub fn toggle_migration_status(&mut self, library_name: &str) {
        let current = self
            .migration_statuses
            .get(library_name)
            .cloned()
            .unwrap_or(MigrationStatus::NotStarted);

        let new_status = match current {
            MigrationStatus::NotStarted => MigrationStatus::InProgress,
            MigrationStatus::InProgress => MigrationStatus::Completed,
            MigrationStatus::Completed => MigrationStatus::NotStarted,
        };

        self.migration_statuses
            .insert(library_name.to_string(), new_status);
    }

    /// Get migration statistics
    pub fn get_migration_stats(&self) -> (usize, usize, usize) {
        let mut not_started = 0;
        let mut in_progress = 0;
        let mut completed = 0;

        for status in self.migration_statuses.values() {
            match status {
                MigrationStatus::NotStarted => not_started += 1,
                MigrationStatus::InProgress => in_progress += 1,
                MigrationStatus::Completed => completed += 1,
            }
        }

        (not_started, in_progress, completed)
    }

    /// Get estimated total migration timeline (months)
    pub fn get_estimated_timeline(&self) -> u32 {
        self.migration_recommendations
            .values()
            .filter(|rec| rec.priority != MigrationPriority::None)
            .map(|rec| rec.timeline_months)
            .max()
            .unwrap_or(0)
    }

    /// Export migration plan as Markdown
    pub fn export_migration_plan(&self) -> String {
        use std::fmt::Write;

        let mut output = String::new();
        let (not_started, in_progress, completed) = self.get_migration_stats();
        let total_vulnerable = not_started + in_progress + completed;
        let timeline = self.get_estimated_timeline();
        let total_libs = self.library_store.len();

        // Header
        writeln!(output, "# Post-Quantum Cryptography Migration Plan").unwrap();
        writeln!(output).unwrap();
        writeln!(
            output,
            "**Generated:** {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        )
        .unwrap();
        writeln!(output, "**Scan Path:** {}", self.scan_path.display()).unwrap();
        writeln!(output).unwrap();

        // Executive Summary
        writeln!(output, "## Executive Summary").unwrap();
        writeln!(output).unwrap();
        writeln!(output, "- **Total Libraries Scanned:** {}", total_libs).unwrap();
        writeln!(
            output,
            "- **Quantum-Vulnerable Libraries:** {} ({:.1}%)",
            total_vulnerable,
            if total_libs > 0 {
                (total_vulnerable as f64 / total_libs as f64) * 100.0
            } else {
                0.0
            }
        )
        .unwrap();
        writeln!(output, "- **Migration Timeline:** {} months", timeline).unwrap();
        writeln!(output, "- **Migration Progress:**").unwrap();
        writeln!(output, "  - Not Started: {}", not_started).unwrap();
        writeln!(output, "  - In Progress: {}", in_progress).unwrap();
        writeln!(output, "  - Completed: {}", completed).unwrap();
        writeln!(output).unwrap();

        // Risk Assessment Summary
        writeln!(output, "## Risk Assessment Summary").unwrap();
        writeln!(output).unwrap();
        writeln!(output, "| Risk Level | Count | Percentage |").unwrap();
        writeln!(output, "|------------|-------|------------|").unwrap();

        let total_libs = self.library_store.len();
        for risk in &[
            RiskLevel::Critical,
            RiskLevel::High,
            RiskLevel::Medium,
            RiskLevel::Low,
            RiskLevel::None,
        ] {
            let count = self.risk_counts.get(risk).copied().unwrap_or(0);
            let pct = if total_libs > 0 {
                (count as f64 / total_libs as f64) * 100.0
            } else {
                0.0
            };
            writeln!(
                output,
                "| {} {} | {} | {:.1}% |",
                risk.icon(),
                risk.label(),
                count,
                pct
            )
            .unwrap();
        }
        writeln!(output).unwrap();

        // Migration Priorities
        let priorities = self.get_libraries_by_priority();

        for (priority, libs) in priorities {
            if priority == MigrationPriority::None {
                continue; // Skip PQ-ready libraries
            }

            writeln!(
                output,
                "## {} {} Priority ({} libraries)",
                priority.icon(),
                priority.label(),
                libs.len()
            )
            .unwrap();
            writeln!(output).unwrap();

            for lib in libs {
                if let Some(rec) = self.migration_recommendations.get(&lib.name) {
                    let status = self
                        .migration_statuses
                        .get(&lib.name)
                        .unwrap_or(&MigrationStatus::NotStarted);

                    writeln!(
                        output,
                        "### {} {} {}",
                        status.icon(),
                        lib.name,
                        status.label()
                    )
                    .unwrap();
                    writeln!(output).unwrap();
                    writeln!(output, "**Library Details:**").unwrap();
                    writeln!(output, "- **Path:** `{}`", lib.path.display()).unwrap();
                    writeln!(output, "- **Category:** {}", lib.category.name()).unwrap();
                    writeln!(
                        output,
                        "- **Risk Level:** {} {}",
                        lib.risk_level.icon(),
                        lib.risk_level.label()
                    )
                    .unwrap();
                    if let Some(ref version) = lib.version {
                        writeln!(output, "- **Version:** {}", version).unwrap();
                    }
                    if let Some(ref vendor) = lib.vendor {
                        writeln!(output, "- **Vendor:** {}", vendor).unwrap();
                    }
                    writeln!(output).unwrap();

                    writeln!(output, "**Migration Recommendation:**").unwrap();
                    writeln!(output, "- **Current Algorithm:** {}", rec.current_algorithm).unwrap();
                    writeln!(
                        output,
                        "- **Recommended Migration:** {}",
                        rec.recommended_algorithm
                    )
                    .unwrap();
                    writeln!(output, "- **Strategy:** {:?}", rec.migration_strategy).unwrap();
                    writeln!(output, "- **Timeline:** {} months", rec.timeline_months).unwrap();
                    writeln!(output, "- **Effort Level:** {}", rec.effort_level.label()).unwrap();
                    writeln!(output).unwrap();

                    writeln!(output, "**Notes:**").unwrap();
                    writeln!(output, "{}", rec.notes).unwrap();
                    writeln!(output).unwrap();
                    writeln!(output, "---").unwrap();
                    writeln!(output).unwrap();
                }
            }
        }

        // Post-Quantum Ready Libraries
        let pq_ready: Vec<_> = self
            .library_store
            .iter()
            .filter(|lib| lib.category == LibraryCategory::PostQuantum)
            .collect();

        if !pq_ready.is_empty() {
            writeln!(
                output,
                "## {} Post-Quantum Ready Libraries ({} libraries)",
                "✅",
                pq_ready.len()
            )
            .unwrap();
            writeln!(output).unwrap();
            writeln!(output, "These libraries are already quantum-resistant:").unwrap();
            writeln!(output).unwrap();

            for lib in pq_ready {
                writeln!(output, "- **{}** - `{}`", lib.name, lib.path.display()).unwrap();
            }
            writeln!(output).unwrap();
        }

        // Recommendations
        writeln!(output, "## General Recommendations").unwrap();
        writeln!(output).unwrap();
        writeln!(output, "1. **Immediate Actions (0-3 months):**").unwrap();
        writeln!(output, "   - Address all CRITICAL priority libraries").unwrap();
        writeln!(
            output,
            "   - Replace legacy cryptographic algorithms (MD5, DES)"
        )
        .unwrap();
        writeln!(
            output,
            "   - Assess dependencies and impact for high-priority migrations"
        )
        .unwrap();
        writeln!(output).unwrap();
        writeln!(output, "2. **Short-term Actions (3-12 months):**").unwrap();
        writeln!(
            output,
            "   - Migrate HIGH priority libraries to hybrid classical+PQ modes"
        )
        .unwrap();
        writeln!(
            output,
            "   - Begin testing post-quantum algorithms in non-production environments"
        )
        .unwrap();
        writeln!(
            output,
            "   - Update libraries to versions with PQ support (e.g., OpenSSL 3.2+)"
        )
        .unwrap();
        writeln!(output).unwrap();
        writeln!(output, "3. **Medium-term Actions (12-24 months):**").unwrap();
        writeln!(output, "   - Complete MEDIUM priority migrations").unwrap();
        writeln!(
            output,
            "   - Deploy hybrid cryptography in production systems"
        )
        .unwrap();
        writeln!(output, "   - Monitor NIST post-quantum standards updates").unwrap();
        writeln!(output).unwrap();
        writeln!(output, "4. **Long-term Actions (24-36 months):**").unwrap();
        writeln!(output, "   - Complete all LOW priority migrations").unwrap();
        writeln!(
            output,
            "   - Transition from hybrid to pure post-quantum where appropriate"
        )
        .unwrap();
        writeln!(output, "   - Conduct regular cryptographic audits").unwrap();
        writeln!(output).unwrap();

        // Footer
        writeln!(output, "---").unwrap();
        writeln!(output).unwrap();
        writeln!(
            output,
            "*Generated by Slow Lynx Cryptography Discovery - Scanner Dashboard*"
        )
        .unwrap();

        output
    }

    /// Export scan results to JSON
    pub fn export_to_json(&self) -> Result<String, Box<dyn std::error::Error>> {
        let export_data = ScanExport {
            scan_metadata: ScanMetadata {
                path: self.scan_path.clone(),
                depth: self.scan_depth,
                duration_seconds: self.get_runtime().as_secs(),
                timestamp: chrono::Local::now().to_rfc3339(),
                total_libraries: self.library_store.len(),
                scan_status: format!("{:?}", self.scan_status),
            },
            libraries: self.library_store.get_all().to_vec(),
            statistics: Statistics {
                category_breakdown: self.category_counts.clone(),
                risk_assessment: self.risk_counts.clone(),
                total_size: self.total_size,
                unique_vendors: self.unique_vendors.len(),
                quantum_vulnerable_count: self.get_quantum_vulnerable_count(),
                pq_ready_count: self.get_pq_ready_count(),
            },
            scan_performance: ScanPerformance {
                files_scanned: self.scan_progress.files_scanned,
                dirs_scanned: self.scan_progress.dirs_scanned,
                scan_rate: self.scan_progress.scan_rate,
            },
            migration_recommendations: if !self.migration_recommendations.is_empty() {
                Some(self.migration_recommendations.clone())
            } else {
                None
            },
            migration_statuses: if !self.migration_statuses.is_empty() {
                Some(self.migration_statuses.clone())
            } else {
                None
            },
        };

        let json = serde_json::to_string_pretty(&export_data)?;
        Ok(json)
    }

    /// Export library inventory to CSV format
    pub fn export_to_csv(&self) -> String {
        use chrono::{DateTime, Utc};
        let mut csv = String::new();

        // CSV Header
        csv.push_str("Name,Path,Category,Type,Version,Vendor,Size (bytes),Modified Date,Risk Level,Quantum Vulnerable,Migration Priority,Migration Status,Current Algorithm,Recommended Algorithm,Timeline (months)\n");

        // Data rows
        for lib in self.library_store.iter() {
            // Format modified date
            let modified_date =
                if let Ok(_duration) = lib.modified.duration_since(std::time::UNIX_EPOCH) {
                    let datetime = DateTime::<Utc>::from(lib.modified);
                    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                } else {
                    "Unknown".to_string()
                };

            // Get migration data if available
            let (migration_priority, migration_status, current_algo, recommended_algo, timeline) =
                if let Some(rec) = self.migration_recommendations.get(&lib.name) {
                    let status = self
                        .migration_statuses
                        .get(&lib.name)
                        .map(|s| s.label())
                        .unwrap_or("Not Started");

                    (
                        rec.priority.label(),
                        status,
                        rec.current_algorithm.as_str(),
                        rec.recommended_algorithm.as_str(),
                        rec.timeline_months.to_string(),
                    )
                } else {
                    ("N/A", "N/A", "N/A", "N/A", "N/A".to_string())
                };

            // Escape CSV fields (handle commas and quotes)
            let name = escape_csv_field(&lib.name);
            let path = escape_csv_field(&lib.path.display().to_string());
            let category = escape_csv_field(lib.category.name());
            let lib_type = escape_csv_field(&format!("{:?}", lib.library_type));
            let version = escape_csv_field(&lib.version.as_deref().unwrap_or("N/A"));
            let vendor = escape_csv_field(&lib.vendor.as_deref().unwrap_or("N/A"));
            let risk_level = escape_csv_field(lib.risk_level.label());
            let quantum_vuln = if lib.quantum_vulnerable { "Yes" } else { "No" };
            let current_algo_escaped = escape_csv_field(current_algo);
            let recommended_algo_escaped = escape_csv_field(recommended_algo);

            // Write row
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                name,
                path,
                category,
                lib_type,
                version,
                vendor,
                lib.size,
                modified_date,
                risk_level,
                quantum_vuln,
                migration_priority,
                migration_status,
                current_algo_escaped,
                recommended_algo_escaped,
                timeline
            ));
        }

        csv
    }
}

/// Escape CSV field (wrap in quotes if contains comma, quote, or newline)
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

// Export data structures

#[derive(Debug, Serialize)]
struct ScanExport {
    scan_metadata: ScanMetadata,
    libraries: Vec<LibraryInfo>,
    statistics: Statistics,
    scan_performance: ScanPerformance,
    #[serde(skip_serializing_if = "Option::is_none")]
    migration_recommendations: Option<HashMap<String, MigrationRecommendation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    migration_statuses: Option<HashMap<String, MigrationStatus>>,
}

#[derive(Debug, Serialize)]
struct ScanMetadata {
    path: PathBuf,
    depth: Option<usize>,
    duration_seconds: u64,
    timestamp: String,
    total_libraries: usize,
    scan_status: String,
}

#[derive(Debug, Serialize)]
struct Statistics {
    category_breakdown: HashMap<LibraryCategory, usize>,
    risk_assessment: HashMap<RiskLevel, usize>,
    total_size: u64,
    unique_vendors: usize,
    quantum_vulnerable_count: usize,
    pq_ready_count: usize,
}

#[derive(Debug, Serialize)]
struct ScanPerformance {
    files_scanned: usize,
    dirs_scanned: usize,
    scan_rate: f64,
}

impl MigrationPriority {
    pub fn label(&self) -> &'static str {
        match self {
            MigrationPriority::Critical => "CRITICAL",
            MigrationPriority::High => "HIGH",
            MigrationPriority::Medium => "MEDIUM",
            MigrationPriority::Low => "LOW",
            MigrationPriority::None => "NONE",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            MigrationPriority::Critical => "🚨",
            MigrationPriority::High => "⚠️",
            MigrationPriority::Medium => "⚠",
            MigrationPriority::Low => "ℹ️",
            MigrationPriority::None => "✅",
        }
    }
}

impl EffortLevel {
    pub fn label(&self) -> &'static str {
        match self {
            EffortLevel::Low => "Low",
            EffortLevel::Medium => "Medium",
            EffortLevel::High => "High",
            EffortLevel::VeryHigh => "Very High",
        }
    }
}

impl MigrationStatus {
    pub fn icon(&self) -> &'static str {
        match self {
            MigrationStatus::NotStarted => "○",
            MigrationStatus::InProgress => "◐",
            MigrationStatus::Completed => "●",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            MigrationStatus::NotStarted => "Not Started",
            MigrationStatus::InProgress => "In Progress",
            MigrationStatus::Completed => "Completed",
        }
    }
}
