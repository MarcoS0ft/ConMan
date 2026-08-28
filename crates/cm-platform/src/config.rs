//! Line-preserving storage for ConMan's user-editable configuration.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cm_core::{AppConfigError, AppConfigStore};

const WRITER_LOCK_WAIT: Duration = Duration::from_secs(5);
const WRITER_LOCK_INITIAL_BACKOFF: Duration = Duration::from_millis(5);
const WRITER_LOCK_MAX_BACKOFF: Duration = Duration::from_millis(100);

/// Severity of a configuration parser diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDiagnosticLevel {
    Warning,
    Error,
}

/// A syntax error or non-fatal duplicate-key warning in a config document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiagnostic {
    pub line: usize,
    pub level: ConfigDiagnosticLevel,
    pub key: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
struct Assignment {
    line_index: usize,
    key: String,
    value: String,
}

#[derive(Debug, Clone)]
struct SourceLine {
    content: String,
    ending: String,
}

/// Parsed configuration with source layout retained for targeted edits.
#[derive(Debug, Clone)]
pub struct ConfigDocument {
    lines: Vec<SourceLine>,
    assignments: Vec<Assignment>,
    diagnostics: Vec<ConfigDiagnostic>,
}

impl ConfigDocument {
    /// Parses a complete UTF-8 document. Duplicate assignments are accepted
    /// and reported as warnings; syntax errors reject the document.
    pub fn parse(source: &str) -> Result<Self, Vec<ConfigDiagnostic>> {
        let (document, has_errors) = parse_document(source);
        if has_errors {
            Err(document.diagnostics)
        } else {
            Ok(document)
        }
    }

    /// Parser warnings associated with the document.
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        &self.diagnostics
    }

    /// All assignments in source order as `(line, key, value)` tuples.
    /// Consumers can use this to diagnose unknown keys without giving the
    /// syntax layer knowledge of the current settings schema.
    pub fn assignments(&self) -> impl Iterator<Item = (usize, &str, &str)> {
        self.assignments.iter().map(|assignment| {
            (
                assignment.line_index + 1,
                assignment.key.as_str(),
                assignment.value.as_str(),
            )
        })
    }

    /// Returns one owned `(key, value)` pair per key using last-assignment
    /// semantics. Pairs follow the source order of their effective (final)
    /// assignments, making CLI diagnostics and output deterministic.
    pub fn effective_assignments(&self) -> Vec<(String, String)> {
        let mut seen = HashSet::new();
        let mut effective = self
            .assignments
            .iter()
            .rev()
            .filter(|assignment| seen.insert(assignment.key.as_str()))
            .map(|assignment| (assignment.key.clone(), assignment.value.clone()))
            .collect::<Vec<_>>();
        effective.reverse();
        effective
    }

    /// Returns the final assigned value for `key`.
    pub fn effective_value(&self, key: &str) -> Option<&str> {
        self.assignments
            .iter()
            .rev()
            .find(|assignment| assignment.key == key)
            .map(|assignment| assignment.value.as_str())
    }

    /// Replaces the final occurrence of `key`, or appends an assignment.
    pub fn set_value(&mut self, key: &str, value: &str) -> Result<(), AppConfigError> {
        validate_key(key).map_err(|message| AppConfigError::Syntax { line: 1, message })?;
        let encoded = encode_value(value)?;
        let replacement = format!("{key} = {encoded}");

        if let Some(assignment) = self
            .assignments
            .iter_mut()
            .rev()
            .find(|assignment| assignment.key == key)
        {
            self.lines[assignment.line_index].content = replacement;
            assignment.value = value.to_owned();
            return Ok(());
        }

        let line_ending = preferred_line_ending(&self.lines);
        if let Some(last) = self.lines.last_mut().filter(|line| line.ending.is_empty()) {
            last.ending = line_ending.to_owned();
        }
        let line_index = self.lines.len();
        self.lines.push(SourceLine {
            content: replacement,
            ending: String::new(),
        });
        self.assignments.push(Assignment {
            line_index,
            key: key.to_owned(),
            value: value.to_owned(),
        });
        Ok(())
    }

    /// Reconstructs the source document exactly, except for assignments that
    /// were deliberately changed through [`Self::set_value`].
    pub fn text(&self) -> String {
        let capacity = self
            .lines
            .iter()
            .map(|line| line.content.len() + line.ending.len())
            .sum();
        let mut text = String::with_capacity(capacity);
        for line in &self.lines {
            text.push_str(&line.content);
            text.push_str(&line.ending);
        }
        text
    }
}

/// Returns all parser diagnostics without modifying or persisting a document.
pub fn validate_config_document(source: &str) -> Vec<ConfigDiagnostic> {
    parse_document(source).0.diagnostics
}

/// Reads a UTF-8 config file. A missing file is the empty document.
pub fn read_config_file(path: impl AsRef<Path>) -> Result<String, AppConfigError> {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(document) => Ok(document),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(backend_error("read", path, error)),
    }
}

/// Creates a validated config file without replacing an existing destination.
/// Used by CLI export workflows that must not clobber user data.
pub fn write_config_file_noclobber(
    path: impl AsRef<Path>,
    document: &str,
) -> Result<(), AppConfigError> {
    let path = path.as_ref();
    validate_for_write(document)?;
    let _writer_lock = ConfigWriterLock::acquire(path)?;
    reject_symlink_target(path)?;
    atomic_write(path, document, false)
}

/// File-backed implementation of [`AppConfigStore`].
pub struct TextConfigStore {
    path: PathBuf,
}

impl fmt::Debug for TextConfigStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TextConfigStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TextConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_document(&self) -> Result<ConfigDocument, AppConfigError> {
        parse_strict(&read_config_file(&self.path)?)
    }
}

impl AppConfigStore for TextConfigStore {
    fn get_value(&self, key: &str) -> Result<Option<String>, AppConfigError> {
        let document = self.read_document()?;
        Ok(document.effective_value(key).map(str::to_owned))
    }

    fn set_value(&self, key: &str, value: &str) -> Result<(), AppConfigError> {
        self.set_values(&[(key, value)])
    }

    fn set_values(&self, values: &[(&str, &str)]) -> Result<(), AppConfigError> {
        if values.is_empty() {
            return Ok(());
        }
        let _writer_lock = ConfigWriterLock::acquire(&self.path)?;
        reject_symlink_target(&self.path)?;
        let mut document = self.read_document()?;
        for &(key, value) in values {
            document.set_value(key, value)?;
        }
        atomic_write(&self.path, &document.text(), true)
    }

    fn document_text(&self) -> Result<String, AppConfigError> {
        read_config_file(&self.path)
    }

    fn replace_document(&self, document: &str) -> Result<(), AppConfigError> {
        validate_for_write(document)?;
        let _writer_lock = ConfigWriterLock::acquire(&self.path)?;
        reject_symlink_target(&self.path)?;
        atomic_write(&self.path, document, true)
    }
}

/// Cross-process writer exclusion backed by the standard library's OS file
/// lock. The sibling lock file is intentionally persistent: kernel ownership
/// is released automatically when a process exits, so there is no stale lock
/// to steal or time-based lease that can expire during a slow valid write.
struct ConfigWriterLock {
    file: fs::File,
}

impl ConfigWriterLock {
    fn acquire(config_path: &Path) -> Result<Self, AppConfigError> {
        Self::acquire_with_timeout(config_path, WRITER_LOCK_WAIT)
    }

    fn acquire_with_timeout(
        config_path: &Path,
        wait_timeout: Duration,
    ) -> Result<Self, AppConfigError> {
        let parent = config_parent(config_path);
        fs::create_dir_all(parent)
            .map_err(|error| backend_error("create parent directory for", config_path, error))?;
        let lock_path = writer_lock_path(config_path)?;
        reject_lock_path_symlink(&lock_path)?;
        let file = open_writer_lock_file(&lock_path, config_path)?;
        let started = Instant::now();
        let mut backoff = WRITER_LOCK_INITIAL_BACKOFF;

        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if started.elapsed() >= wait_timeout {
                        return Err(AppConfigError::Backend(format!(
                            "timed out waiting for configuration writer lock {}",
                            lock_path.display()
                        )));
                    }
                    std::thread::sleep(backoff);
                    backoff = backoff.saturating_mul(2).min(WRITER_LOCK_MAX_BACKOFF);
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(backend_error(
                        "acquire configuration writer lock for",
                        config_path,
                        error,
                    ));
                }
            }
        }
    }
}

impl Drop for ConfigWriterLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            tracing::warn!(%error, "failed to release configuration writer lock");
        }
    }
}

fn config_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn writer_lock_path(config_path: &Path) -> Result<PathBuf, AppConfigError> {
    let Some(file_name) = config_path.file_name().filter(|name| !name.is_empty()) else {
        return Err(AppConfigError::Backend(
            "configuration path has no file name".to_owned(),
        ));
    };
    let mut lock_name = OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".lock");
    Ok(config_parent(config_path).join(lock_name))
}

fn reject_lock_path_symlink(path: &Path) -> Result<(), AppConfigError> {
    crate::safe_lock::reject_non_regular_lock_path(path)
        .map_err(|error| backend_error("inspect configuration writer lock", path, error))
}

fn open_writer_lock_file(lock_path: &Path, config_path: &Path) -> Result<fs::File, AppConfigError> {
    open_writer_lock_file_with_post_open(lock_path, config_path, || Ok(()))
}

fn open_writer_lock_file_with_post_open<F>(
    lock_path: &Path,
    config_path: &Path,
    after_open: F,
) -> Result<fs::File, AppConfigError>
where
    F: FnOnce() -> Result<(), AppConfigError>,
{
    let file = crate::safe_lock::open_lock_file_unverified(lock_path).map_err(|error| {
        backend_error(
            "open no-follow configuration writer lock beside",
            config_path,
            error,
        )
    })?;
    after_open()?;
    crate::safe_lock::verify_opened_lock_file(&file, lock_path).map_err(|error| {
        backend_error(
            "verify opened configuration writer lock beside",
            config_path,
            error,
        )
    })?;
    Ok(file)
}

fn parse_strict(source: &str) -> Result<ConfigDocument, AppConfigError> {
    ConfigDocument::parse(source).map_err(|diagnostics| {
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.level == ConfigDiagnosticLevel::Error)
            .expect("parse failure must contain an error diagnostic");
        AppConfigError::Syntax {
            line: diagnostic.line,
            message: diagnostic.message.clone(),
        }
    })
}

fn validate_for_write(source: &str) -> Result<(), AppConfigError> {
    parse_strict(source).map(|_| ())
}

fn parse_document(source: &str) -> (ConfigDocument, bool) {
    let lines = source_lines(source);
    let mut assignments = Vec::new();
    let mut diagnostics = Vec::new();
    let mut first_occurrence = HashMap::<String, usize>::new();
    let mut has_errors = false;

    for (line_index, line) in lines.iter().enumerate() {
        let line_number = line_index + 1;
        let trimmed = line.content.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match parse_assignment(&line.content) {
            Ok((key, value)) => {
                if let Some(first_line) = first_occurrence.get(&key) {
                    diagnostics.push(ConfigDiagnostic {
                        line: line_number,
                        level: ConfigDiagnosticLevel::Warning,
                        key: Some(key.clone()),
                        message: format!("duplicate assignment; final value wins (first assigned on line {first_line})"),
                    });
                } else {
                    first_occurrence.insert(key.clone(), line_number);
                }
                assignments.push(Assignment {
                    line_index,
                    key,
                    value,
                });
            }
            Err(message) => {
                has_errors = true;
                diagnostics.push(ConfigDiagnostic {
                    line: line_number,
                    level: ConfigDiagnosticLevel::Error,
                    key: None,
                    message,
                });
            }
        }
    }

    (
        ConfigDocument {
            lines,
            assignments,
            diagnostics,
        },
        has_errors,
    )
}

fn parse_assignment(line: &str) -> Result<(String, String), String> {
    let Some((raw_key, raw_value)) = line.split_once('=') else {
        return Err("expected `key = value` assignment".to_owned());
    };
    let key = raw_key.trim();
    validate_key(key)?;
    let value = parse_value(raw_value)?;
    Ok((key.to_owned(), value))
}

fn validate_key(key: &str) -> Result<(), String> {
    let mut chars = key.chars();
    if !matches!(chars.next(), Some('a'..='z'))
        || !chars.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err("key must start with a lowercase ASCII letter and contain only lowercase letters, digits, or `-`".to_owned());
    }
    Ok(())
}

fn parse_value(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('"') {
        return Ok(trimmed.to_owned());
    }

    let mut value = String::new();
    let mut characters = trimmed.char_indices();
    let _opening_quote = characters.next();
    while let Some((index, character)) = characters.next() {
        match character {
            '"' => {
                if !trimmed[index + character.len_utf8()..].trim().is_empty() {
                    return Err("unexpected characters after closing quote".to_owned());
                }
                return Ok(value);
            }
            '\\' => match characters.next() {
                Some((_, '"')) => value.push('"'),
                Some((_, '\\')) => value.push('\\'),
                Some((_, _)) => {
                    return Err("only `\\\"` and `\\\\` escapes are supported".to_owned());
                }
                None => return Err("unterminated escape sequence".to_owned()),
            },
            other => value.push(other),
        }
    }
    Err("unterminated quoted value".to_owned())
}

fn encode_value(value: &str) -> Result<String, AppConfigError> {
    if value.contains(['\n', '\r']) {
        return Err(AppConfigError::Backend(
            "configuration values cannot contain line breaks".to_owned(),
        ));
    }
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.trim() == value && !value.starts_with('"') {
        return Ok(value.to_owned());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn source_lines(source: &str) -> Vec<SourceLine> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in source.bytes().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let (content_end, ending) = if index > start && source.as_bytes()[index - 1] == b'\r' {
            (index - 1, "\r\n")
        } else {
            (index, "\n")
        };
        lines.push(SourceLine {
            content: source[start..content_end].to_owned(),
            ending: ending.to_owned(),
        });
        start = index + 1;
    }
    if start < source.len() {
        lines.push(SourceLine {
            content: source[start..].to_owned(),
            ending: String::new(),
        });
    }
    lines
}

fn preferred_line_ending(lines: &[SourceLine]) -> &'static str {
    lines
        .iter()
        .find(|line| !line.ending.is_empty())
        .map_or(
            "\n",
            |line| {
                if line.ending == "\r\n" { "\r\n" } else { "\n" }
            },
        )
}

fn reject_symlink_target(path: &Path) -> Result<(), AppConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AppConfigError::Backend(format!(
            "refusing to write configuration through symbolic link {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(backend_error("inspect configuration target", path, error)),
    }
}

fn atomic_write(path: &Path, document: &str, overwrite: bool) -> Result<(), AppConfigError> {
    atomic_write_with_pre_persist(path, document, overwrite, || Ok(()))
}

fn atomic_write_with_pre_persist<F>(
    path: &Path,
    document: &str,
    overwrite: bool,
    before_final_check: F,
) -> Result<(), AppConfigError>
where
    F: FnOnce() -> Result<(), AppConfigError>,
{
    reject_symlink_target(path)?;
    let parent = config_parent(path);
    fs::create_dir_all(parent)
        .map_err(|error| backend_error("create parent directory for", path, error))?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| backend_error("create temporary file beside", path, error))?;
    restrict_file(temporary.as_file(), path);
    temporary
        .write_all(document.as_bytes())
        .map_err(|error| backend_error("write temporary file for", path, error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| backend_error("synchronize temporary file for", path, error))?;

    before_final_check()?;
    let persisted = if overwrite {
        reject_symlink_target(path)?;
        // `persist` is a same-directory rename. Even if a hostile actor swaps
        // in a link after the final check, rename replaces the directory entry
        // itself and never opens or writes through the link target.
        temporary.persist(path).map_err(|error| error.error)
    } else {
        reject_symlink_target(path)?;
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)
    };
    persisted.map_err(|error| {
        backend_error(if overwrite { "replace" } else { "create" }, path, error)
    })?;
    sync_parent(parent);
    Ok(())
}

#[cfg(unix)]
fn restrict_file(file: &fs::File, path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
        tracing::warn!(path = %path.display(), %error, "could not restrict config file permissions");
    }
}

#[cfg(not(unix))]
fn restrict_file(_file: &fs::File, _path: &Path) {}

#[cfg(unix)]
fn sync_parent(parent: &Path) {
    if let Ok(directory) = fs::File::open(parent)
        && let Err(error) = directory.sync_all()
    {
        tracing::warn!(path = %parent.display(), %error, "could not synchronize config directory");
    }
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) {}

fn backend_error(action: &str, path: &Path, error: std::io::Error) -> AppConfigError {
    AppConfigError::Backend(format!("failed to {action} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_quotes_literal_hashes_and_empty_values() {
        let source = "# hello\nfont-family = JetBrains Mono # literal\ncommand = \"say \\\"hi\\\" \\\\\"\nworking-directory =\n";
        let document = ConfigDocument::parse(source).expect("valid config");
        assert_eq!(
            document.effective_value("font-family"),
            Some("JetBrains Mono # literal")
        );
        assert_eq!(document.effective_value("command"), Some("say \"hi\" \\"));
        assert_eq!(document.effective_value("working-directory"), Some(""));
        assert_eq!(document.text(), source);
    }

    #[test]
    fn reports_all_syntax_errors_and_rejects_unsupported_escapes() {
        let diagnostics = validate_config_document("NOPE = value\ncommand = \"bad\\n\"\nbroken\n");
        assert_eq!(
            diagnostics
                .iter()
                .filter(|item| item.level == ConfigDiagnosticLevel::Error)
                .count(),
            3
        );
        assert_eq!(diagnostics[0].line, 1);
        assert_eq!(diagnostics[1].line, 2);
        assert_eq!(diagnostics[2].line, 3);
    }

    #[test]
    fn duplicate_keys_are_retained_warned_and_last_wins() {
        let source = "theme = light\n# in between\ntheme = dark\n";
        let document = ConfigDocument::parse(source).expect("duplicates are valid");
        assert_eq!(document.effective_value("theme"), Some("dark"));
        assert_eq!(document.diagnostics().len(), 1);
        assert_eq!(
            document.diagnostics()[0].level,
            ConfigDiagnosticLevel::Warning
        );
        assert_eq!(document.text(), source);
    }

    #[test]
    fn effective_assignments_are_unique_last_wins_and_source_ordered() {
        let document = ConfigDocument::parse(
            "theme = light\nunknown-first = retained\ntheme = dark\nunknown-last = value\n",
        )
        .expect("valid config");

        assert_eq!(
            document.effective_assignments(),
            vec![
                ("unknown-first".to_owned(), "retained".to_owned()),
                ("theme".to_owned(), "dark".to_owned()),
                ("unknown-last".to_owned(), "value".to_owned()),
            ],
        );
    }

    #[test]
    fn set_replaces_only_final_assignment_and_preserves_crlf() {
        let source = "theme=light\r\n# preserve me\r\ntheme = dark\r\nunknown-key = yes\r\n";
        let mut document = ConfigDocument::parse(source).expect("valid config");
        document.set_value("theme", "system").unwrap();
        document.set_value("font-family", "  padded  ").unwrap();
        assert_eq!(
            document.text(),
            "theme=light\r\n# preserve me\r\ntheme = system\r\nunknown-key = yes\r\nfont-family = \"  padded  \"",
        );
    }

    #[test]
    fn store_reads_missing_as_empty_and_updates_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("config.conman");
        let store = TextConfigStore::new(&path);
        assert_eq!(store.document_text().unwrap(), "");
        assert_eq!(store.get_value("theme").unwrap(), None);

        store.set_value("theme", "dark").unwrap();
        store.set_value("font-family", "JetBrains Mono").unwrap();
        assert_eq!(store.get_value("theme").unwrap().as_deref(), Some("dark"));
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "theme = dark\nfont-family = JetBrains Mono"
        );
    }

    #[test]
    fn batch_update_is_all_or_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.conman");
        fs::write(&path, "theme = dark\n").unwrap();
        let store = TextConfigStore::new(&path);

        let result = store.set_values(&[("theme", "light"), ("command", "bad\nvalue")]);
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "theme = dark\n");
    }

    #[test]
    fn independent_stores_do_not_lose_concurrent_updates() {
        use std::sync::{Arc, Barrier};

        const WRITERS: usize = 12;
        let directory = tempfile::tempdir().unwrap();
        let path = Arc::new(directory.path().join("config.conman"));
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut threads = Vec::new();
        for index in 0..WRITERS {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let store = TextConfigStore::new(path.as_ref());
                let key = format!("writer-{index}");
                barrier.wait();
                store.set_value(&key, "retained").unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let document = ConfigDocument::parse(&fs::read_to_string(path.as_ref()).unwrap()).unwrap();
        for index in 0..WRITERS {
            assert_eq!(
                document.effective_value(&format!("writer-{index}")),
                Some("retained")
            );
        }
    }

    #[test]
    fn writer_lock_survives_repeated_high_contention_handoffs() {
        use std::sync::{Arc, Barrier};

        const ROUNDS: usize = 10;
        const WRITERS_PER_ROUND: usize = 16;
        let directory = tempfile::tempdir().unwrap();
        let path = Arc::new(directory.path().join("config.conman"));

        for round in 0..ROUNDS {
            let barrier = Arc::new(Barrier::new(WRITERS_PER_ROUND));
            let mut threads = Vec::new();
            for writer in 0..WRITERS_PER_ROUND {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                threads.push(std::thread::spawn(move || {
                    let store = TextConfigStore::new(path.as_ref());
                    let key = format!("round-{round}-writer-{writer}");
                    barrier.wait();
                    store.set_value(&key, "retained").unwrap();
                }));
            }
            for thread in threads {
                thread.join().unwrap();
            }
            let retained = ConfigDocument::parse(&fs::read_to_string(path.as_ref()).unwrap())
                .unwrap()
                .effective_assignments()
                .len();
            assert_eq!(
                retained,
                (round + 1) * WRITERS_PER_ROUND,
                "round {round} lost updates"
            );
        }

        let document = ConfigDocument::parse(&fs::read_to_string(path.as_ref()).unwrap()).unwrap();
        for round in 0..ROUNDS {
            for writer in 0..WRITERS_PER_ROUND {
                assert_eq!(
                    document.effective_value(&format!("round-{round}-writer-{writer}")),
                    Some("retained"),
                    "missing round {round} writer {writer}; retained {} of {} updates",
                    document.effective_assignments().len(),
                    ROUNDS * WRITERS_PER_ROUND,
                );
            }
        }
    }

    #[test]
    fn writer_lock_wait_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.conman");
        let first = ConfigWriterLock::acquire_with_timeout(&path, Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        let result = ConfigWriterLock::acquire_with_timeout(&path, Duration::from_millis(25));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(first);
    }

    #[test]
    fn persistent_lock_file_has_no_stale_ownership_after_guard_drop() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.conman");
        let lock_path = writer_lock_path(&path).unwrap();
        let first =
            ConfigWriterLock::acquire_with_timeout(&path, Duration::from_millis(100)).unwrap();
        assert!(lock_path.is_file());
        drop(first); // models kernel cleanup when a holder exits

        let second = ConfigWriterLock::acquire_with_timeout(&path, Duration::from_millis(100))
            .expect("an unlocked persistent lock file must be immediately reusable");
        drop(second);
        assert!(lock_path.is_file(), "lock files are inert persistent state");
    }

    #[test]
    fn ancient_lockfile_contents_never_steal_a_live_os_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.conman");
        let lock_path = writer_lock_path(&path).unwrap();
        fs::write(&lock_path, "created-unix-ms=0\n").unwrap();
        let first =
            ConfigWriterLock::acquire_with_timeout(&path, Duration::from_millis(100)).unwrap();

        let result = ConfigWriterLock::acquire_with_timeout(&path, Duration::from_millis(25));
        assert!(
            result.is_err(),
            "file age/content must not override a live lock"
        );
        drop(first);
    }

    #[test]
    fn writer_lock_child_helper() {
        let Some(config_path) = std::env::var_os("CONMAN_TEST_LOCK_CHILD_CONFIG") else {
            return;
        };
        let ready_path = std::env::var_os("CONMAN_TEST_LOCK_CHILD_READY").unwrap();
        let _lock =
            ConfigWriterLock::acquire_with_timeout(Path::new(&config_path), Duration::from_secs(1))
                .unwrap();
        fs::write(ready_path, b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn killed_process_releases_writer_lock_without_stale_cleanup() {
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.conman");
        let ready = directory.path().join("child-ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("config::tests::writer_lock_child_helper")
            .arg("--nocapture")
            .env("CONMAN_TEST_LOCK_CHILD_CONFIG", &path)
            .env("CONMAN_TEST_LOCK_CHILD_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let started = Instant::now();
        while !ready.is_file() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("lock-holder child exited before readiness: {status}");
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "lock-holder child did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();

        let recovered = ConfigWriterLock::acquire_with_timeout(&path, Duration::from_secs(1))
            .expect("the OS must release a killed process's file lock");
        drop(recovered);
    }

    #[test]
    fn replacement_rejects_invalid_syntax_without_changing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.conman");
        fs::write(&path, "theme = dark\n").unwrap();
        let store = TextConfigStore::new(&path);
        assert!(matches!(
            store.replace_document("not an assignment"),
            Err(AppConfigError::Syntax { line: 1, .. })
        ));
        assert_eq!(fs::read_to_string(path).unwrap(), "theme = dark\n");
    }

    #[test]
    fn noclobber_writer_preserves_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.conman");
        write_config_file_noclobber(&path, "theme = dark\n").unwrap();
        assert!(write_config_file_noclobber(&path, "theme = light\n").is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "theme = dark\n");
    }

    #[cfg(unix)]
    #[test]
    fn every_write_path_rejects_a_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("real-config.conman");
        let link = directory.path().join("config.conman");
        fs::write(&target, "theme = dark\n").unwrap();
        symlink(&target, &link).unwrap();
        let store = TextConfigStore::new(&link);

        assert!(store.set_value("theme", "light").is_err());
        assert!(store.set_values(&[("theme", "light")]).is_err());
        assert!(store.replace_document("theme = light\n").is_err());
        assert!(write_config_file_noclobber(&link, "theme = light\n").is_err());
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(target).unwrap(), "theme = dark\n");
    }

    #[cfg(unix)]
    #[test]
    fn hostile_config_symlink_swap_before_persist_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("victim");
        let path = directory.path().join("config.conman");
        fs::write(&target, "do not touch\n").unwrap();

        let result = atomic_write_with_pre_persist(&path, "theme = light\n", true, || {
            symlink(&target, &path)
                .map_err(|error| backend_error("inject test symlink", &path, error))
        });

        assert!(result.is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(target).unwrap(), "do not touch\n");
    }

    #[cfg(unix)]
    #[test]
    fn lockfile_open_cannot_follow_a_symlink_swapped_after_precheck() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.conman");
        let lock_path = writer_lock_path(&config_path).unwrap();
        let target = directory.path().join("victim");
        fs::write(&target, "do not touch\n").unwrap();
        // Models an attacker swapping the name after the advisory precheck but
        // before OpenOptions::open. O_NOFOLLOW is the security boundary.
        symlink(&target, &lock_path).unwrap();

        assert!(open_writer_lock_file(&lock_path, &config_path).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "do not touch\n");
    }

    #[cfg(unix)]
    #[test]
    fn lockfile_identity_check_rejects_a_regular_file_swap_after_open() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.conman");
        let lock_path = writer_lock_path(&config_path).unwrap();
        let displaced = directory.path().join("displaced-lock");
        fs::write(&lock_path, b"original").unwrap();

        let result = open_writer_lock_file_with_post_open(&lock_path, &config_path, || {
            fs::rename(&lock_path, &displaced)
                .and_then(|()| fs::write(&lock_path, b"replacement"))
                .map_err(|error| backend_error("inject test lockfile swap", &lock_path, error))
        });

        assert!(result.is_err());
        assert_eq!(fs::read(displaced).unwrap(), b"original");
        assert_eq!(fs::read(lock_path).unwrap(), b"replacement");
    }
}
