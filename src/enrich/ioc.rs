//! IOC set loaded from a local CSV.
//!
//! Format (comma-separated, UTF-8, one record per line):
//!
//! ```text
//! indicator,source,severity
//! 10.0.0.5,CERT-FR,high
//! malicious.example.com,abuseipdb,medium
//! deadbeef...,hashlookup,low
//! ```
//!
//! Blank lines and lines starting with `#` are ignored. Fields with
//! embedded commas or quotes aren't supported (keep IOC CSV clean;
//! a real feed should be preprocessed). Case-sensitive match for
//! hashes and domains; IP matching is literal only (no CIDR yet).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use color_eyre::eyre::{Context, Result};
use compact_str::CompactString;

/// A loaded IOC indicator with its metadata.
#[derive(Debug, Clone)]
pub struct IocMatch {
    pub indicator: CompactString,
    pub source: CompactString,
    pub severity: CompactString,
}

/// Lookup table for IOC indicators.
#[derive(Debug, Default)]
pub struct IocSet {
    by_value: HashMap<CompactString, IocMatch>,
}

impl IocSet {
    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("opening IOC file {}", path.display()))?;
        let reader = BufReader::new(f);
        let mut set = IocSet::default();
        for (lineno, line) in reader.lines().enumerate() {
            let line =
                line.with_context(|| format!("reading {}:{}", path.display(), lineno + 1))?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Keep parsing cheap: a serious feed should preprocess.
            let mut parts = trimmed.splitn(3, ',');
            let indicator = parts.next().unwrap_or("").trim();
            let source = parts.next().unwrap_or("").trim();
            let severity = parts.next().unwrap_or("info").trim();
            if indicator.is_empty() {
                continue;
            }
            set.by_value.insert(
                CompactString::new(indicator),
                IocMatch {
                    indicator: CompactString::new(indicator),
                    source: CompactString::new(source),
                    severity: CompactString::new(severity),
                },
            );
        }
        tracing::info!(
            path = %path.display(),
            count = set.by_value.len(),
            "loaded IOCs"
        );
        Ok(set)
    }

    pub fn lookup(&self, value: &str) -> Option<&IocMatch> {
        self.by_value.get(value)
    }

    pub fn len(&self) -> usize {
        self.by_value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_value.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "logfold-ioc-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("iocs.csv");
        let mut f = File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_simple_csv() {
        let p = write_tmp(
            "# header\n\
             10.0.0.5,CERT-FR,high\n\
             evil.example.com,abuseipdb,medium\n\
             \n\
             deadbeef,hashlookup,low\n",
        );
        let set = IocSet::load(&p).unwrap();
        assert_eq!(set.len(), 3);
        let m = set.lookup("10.0.0.5").unwrap();
        assert_eq!(m.source.as_str(), "CERT-FR");
        assert_eq!(m.severity.as_str(), "high");
    }

    #[test]
    fn missing_severity_defaults_to_info() {
        let p = write_tmp("1.2.3.4,CERT-FR\n");
        let set = IocSet::load(&p).unwrap();
        let m = set.lookup("1.2.3.4").unwrap();
        assert_eq!(m.severity.as_str(), "info");
    }

    #[test]
    fn blank_and_comment_lines_skipped() {
        let p = write_tmp("# comment\n\n   \n1.1.1.1,x,low\n");
        let set = IocSet::load(&p).unwrap();
        assert_eq!(set.len(), 1);
    }
}
