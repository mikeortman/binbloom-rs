//! Minimal leveled logger.
//!
//! Replaces binbloom's global `g_log_level` + `info`/`warning`/`error`/`debug`
//! free functions with a small struct. Verbosity follows the original scheme:
//! higher levels are noisier. Messages go to stderr so they never pollute the
//! analysis results printed on stdout.

/// Logging verbosity, ordered from quietest to loudest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LogLevel {
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
}

impl LogLevel {
    /// Map a `-v` repeat count to a level. binbloom starts at `Warning` and
    /// each `-v` bumps the level by one, capped at `Debug`.
    pub fn from_verbosity(verbose: u8) -> Self {
        match (LogLevel::Warning as u8).saturating_add(verbose) {
            0 => LogLevel::None,
            1 => LogLevel::Error,
            2 => LogLevel::Warning,
            3 => LogLevel::Info,
            _ => LogLevel::Debug,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            LogLevel::None => "",
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARNING",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }
}

/// A logger configured with a maximum level to emit.
#[derive(Clone, Copy, Debug)]
pub struct Logger {
    level: LogLevel,
}

impl Default for Logger {
    fn default() -> Self {
        Logger {
            level: LogLevel::Warning,
        }
    }
}

impl Logger {
    /// Create a logger that emits messages at or below `level`.
    pub fn new(level: LogLevel) -> Self {
        Logger { level }
    }

    fn emit(&self, level: LogLevel, msg: &str) {
        if level <= self.level {
            if level == LogLevel::None {
                eprintln!("{msg}");
            } else {
                eprintln!("{}: {}", level.tag(), msg);
            }
        }
    }

    /// Always-visible message (the C `logm`, level "none").
    pub fn message(&self, msg: &str) {
        self.emit(LogLevel::None, msg);
    }

    pub fn info(&self, msg: &str) {
        self.emit(LogLevel::Info, msg);
    }

    pub fn warning(&self, msg: &str) {
        self.emit(LogLevel::Warning, msg);
    }

    pub fn error(&self, msg: &str) {
        self.emit(LogLevel::Error, msg);
    }

    pub fn debug(&self, msg: &str) {
        self.emit(LogLevel::Debug, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_mapping() {
        assert_eq!(LogLevel::from_verbosity(0), LogLevel::Warning);
        assert_eq!(LogLevel::from_verbosity(1), LogLevel::Info);
        assert_eq!(LogLevel::from_verbosity(2), LogLevel::Debug);
        assert_eq!(LogLevel::from_verbosity(10), LogLevel::Debug);
    }

    #[test]
    fn level_ordering() {
        assert!(LogLevel::Error < LogLevel::Debug);
        assert!(LogLevel::None < LogLevel::Error);
    }
}
