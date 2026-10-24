//! ArcSight CEF (Common Event Format) parser.
//!
//! Format: `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`
//!
//! The extension is a sequence of `key=value` pairs. We treat `Name`
//! as the fold-key (short human-readable description of the event),
//! `Signature ID` as a stable per-event identifier, and let the
//! engine's variable extractor pick up the rest.
//!
//! Lines that don't start with `CEF:` return `None`.

/// A CEF-parsed line, pointing into the original string.
#[derive(Debug, Clone)]
pub struct ParsedCef<'a> {
    pub version: &'a str,
    pub vendor: &'a str,
    pub product: &'a str,
    pub product_version: &'a str,
    pub signature_id: &'a str,
    pub name: &'a str,
    pub severity: &'a str,
    pub extension: &'a str,
}

impl<'a> ParsedCef<'a> {
    /// Fold-key: the human-readable event name. The caller tokenises
    /// this instead of the full line.
    pub fn msg(&self) -> &'a str {
        self.name
    }
}

/// Parse a CEF line. Returns `None` if the `CEF:` header is missing
/// or any of the first seven pipe-separated fields is absent.
///
/// CEF escapes literal pipe in header fields as `\|`, so we split on
/// unescaped `|` only.
pub fn parse(line: &str) -> Option<ParsedCef<'_>> {
    let rest = line.strip_prefix("CEF:")?;

    // Find the first seven unescaped '|' positions in `rest`, which
    // give us the eight header fields (last one is extension).
    let bytes = rest.as_bytes();
    let mut cuts = [0usize; 7];
    let mut found = 0;
    let mut i = 0;
    while i < bytes.len() && found < 7 {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Escape: skip the pair.
            i += 2;
            continue;
        }
        if bytes[i] == b'|' {
            cuts[found] = i;
            found += 1;
        }
        i += 1;
    }
    if found < 7 {
        return None;
    }

    let version = &rest[..cuts[0]];
    let vendor = &rest[cuts[0] + 1..cuts[1]];
    let product = &rest[cuts[1] + 1..cuts[2]];
    let product_version = &rest[cuts[2] + 1..cuts[3]];
    let signature_id = &rest[cuts[3] + 1..cuts[4]];
    let name = &rest[cuts[4] + 1..cuts[5]];
    let severity = &rest[cuts[5] + 1..cuts[6]];
    let extension = &rest[cuts[6] + 1..];

    Some(ParsedCef {
        version,
        vendor,
        product,
        product_version,
        signature_id,
        name,
        severity,
        extension,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_arcsight_sample() {
        let line = "CEF:0|Security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked dst=2.1.2.2";
        let p = parse(line).unwrap();
        assert_eq!(p.version, "0");
        assert_eq!(p.vendor, "Security");
        assert_eq!(p.product, "threatmanager");
        assert_eq!(p.signature_id, "100");
        assert_eq!(p.name, "detected a \\| in message");
        assert_eq!(p.severity, "10");
        assert!(p.extension.contains("src=10.0.0.1"));
    }

    #[test]
    fn parses_minimal_cef() {
        let line = "CEF:0|Vendor|Product|1.0|SIG123|SomeEvent|5|";
        let p = parse(line).unwrap();
        assert_eq!(p.name, "SomeEvent");
        assert_eq!(p.extension, "");
    }

    #[test]
    fn returns_none_without_cef_prefix() {
        assert!(parse("not a cef line").is_none());
        assert!(parse("|Vendor|Product|1.0|SIG|Name|5|").is_none());
    }

    #[test]
    fn returns_none_on_truncated_header() {
        // Missing severity + extension.
        let line = "CEF:0|Vendor|Product|1.0|SIG|Name";
        assert!(parse(line).is_none());
    }
}
