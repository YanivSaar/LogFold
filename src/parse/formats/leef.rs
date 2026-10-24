//! IBM LEEF (Log Event Extended Format) parser.
//!
//! LEEF 1.0: `LEEF:Version|Vendor|Product|Version|EventID|Delim <extension>`
//!   (Delim is skipped when absent and defaults to tab.)
//! LEEF 2.0: `LEEF:2.0|Vendor|Product|Version|EventID|Delim|<extension>`
//!
//! The EventID is used as the fold-key, since LEEF (unlike CEF) has
//! no free-form `Name` field.

/// A LEEF-parsed line.
#[derive(Debug, Clone)]
pub struct ParsedLeef<'a> {
    pub version: &'a str,
    pub vendor: &'a str,
    pub product: &'a str,
    pub product_version: &'a str,
    pub event_id: &'a str,
    /// Delimiter character for extension fields. `\t` if absent.
    pub delim: char,
    pub extension: &'a str,
}

impl<'a> ParsedLeef<'a> {
    /// Fold-key: event identifier. The caller tokenises this.
    pub fn msg(&self) -> &'a str {
        self.event_id
    }
}

pub fn parse(line: &str) -> Option<ParsedLeef<'_>> {
    let rest = line.strip_prefix("LEEF:")?;
    let mut parts = rest.splitn(7, '|');
    let version = parts.next()?;
    let vendor = parts.next()?;
    let product = parts.next()?;
    let product_version = parts.next()?;
    let event_id = parts.next()?;

    // LEEF 2.0 has an explicit delimiter field right after event_id.
    // LEEF 1.0 goes straight to the extension (tab-delimited).
    let is_v2 = version.starts_with('2');
    let (delim, extension) = if is_v2 {
        let delim_str = parts.next()?;
        // Delimiter can be a bare char or an escape like `x09`.
        let delim = parse_delim(delim_str).unwrap_or('\t');
        let ext = parts.next().unwrap_or("");
        (delim, ext)
    } else {
        let ext = parts.next().unwrap_or("");
        ('\t', ext)
    };

    Some(ParsedLeef {
        version,
        vendor,
        product,
        product_version,
        event_id,
        delim,
        extension,
    })
}

fn parse_delim(s: &str) -> Option<char> {
    if s.is_empty() {
        return None;
    }
    // Allow `\t`, `\x09`, `x09`, or a literal single character.
    if let Some(rest) = s.strip_prefix(r"\x").or_else(|| s.strip_prefix('x')) {
        let code = u32::from_str_radix(rest, 16).ok()?;
        return char::from_u32(code);
    }
    if s == r"\t" {
        return Some('\t');
    }
    s.chars().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_leef_1_0() {
        let line = "LEEF:1.0|QRadar|QFlow|1.0|6013|src=10.0.0.1\tdst=2.1.2.2\tproto=tcp";
        let p = parse(line).unwrap();
        assert_eq!(p.version, "1.0");
        assert_eq!(p.event_id, "6013");
        assert_eq!(p.delim, '\t');
        assert!(p.extension.contains("src=10.0.0.1"));
    }

    #[test]
    fn parses_leef_2_0_with_delim() {
        let line = "LEEF:2.0|QRadar|QFlow|2.0|6013|^|src=10.0.0.1^dst=2.1.2.2";
        let p = parse(line).unwrap();
        assert_eq!(p.version, "2.0");
        assert_eq!(p.delim, '^');
        assert!(p.extension.contains("dst=2.1.2.2"));
    }

    #[test]
    fn returns_none_without_leef_prefix() {
        assert!(parse("CEF:0|...").is_none());
        assert!(parse("not a leef line").is_none());
    }

    #[test]
    fn truncated_header_rejected() {
        let line = "LEEF:1.0|QRadar|QFlow";
        assert!(parse(line).is_none());
    }
}
