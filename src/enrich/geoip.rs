//! MaxMind GeoIP annotations. v0.7, behind the `geoip` feature.
//!
//! Accepts a GeoLite2-ASN or GeoLite2-Country database (both have
//! identical loader semantics; the lookup picks the fields it finds).
//! The database isn't shipped with logfold - the user supplies their
//! own via `--geoip`.

#![cfg(feature = "geoip")]

use std::net::IpAddr;
use std::path::Path;

use color_eyre::eyre::{Context, Result};
use maxminddb::Reader;

/// A GeoIP reader for ASN and Country lookups.
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn open(path: &Path) -> Result<Self> {
        let reader = Reader::open_readfile(path)
            .with_context(|| format!("opening GeoIP database {}", path.display()))?;
        tracing::info!(path = %path.display(), kind = reader.metadata.database_type, "loaded GeoIP database");
        Ok(GeoIp { reader })
    }

    /// Return an ASN annotation (e.g. `"AS15169 Google LLC"`) if the
    /// database carries ASN data for `ip`.
    pub fn lookup_asn(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = ip.parse().ok()?;
        let result = self.reader.lookup(addr).ok()?;
        let asn: maxminddb::geoip2::Asn = result.decode().ok()??;
        let number = asn.autonomous_system_number?;
        let org = asn.autonomous_system_organization.unwrap_or("unknown");
        Some(format!("AS{number} {org}"))
    }

    /// Return a country code (ISO-3166 alpha-2) if the database
    /// carries country data for `ip`.
    pub fn lookup_country(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = ip.parse().ok()?;
        let result = self.reader.lookup(addr).ok()?;
        let rec: maxminddb::geoip2::Country = result.decode().ok()??;
        rec.country.iso_code.map(String::from)
    }
}
