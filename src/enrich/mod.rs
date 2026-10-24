//! Blue-team variable enrichment. v0.7.
//!
//! Decorates per-variable values with external context so operators
//! read anomaly rows in the terminal they already know. Nothing in
//! here does network I/O: both IOC and GeoIP sources are local
//! files loaded once at startup.
//!
//! * [`IocSet`] - CSV of `indicator,source,severity`. Any variable
//!   value that matches an indicator picks up its tags and a
//!   small score bump.
//! * [`GeoIp`] - MaxMind-format mmdb (ASN or City). Behind the
//!   `geoip` feature. IP variables pick up `country` and `asn`
//!   annotations in the Detail view.

pub mod ioc;

#[cfg(feature = "geoip")]
pub mod geoip;

use std::path::Path;

use color_eyre::eyre::Result;

/// Combined enrichment context. Each component is optional; the
/// hot path (`annotate_value`) returns early when nothing is loaded.
pub struct Enricher {
    pub iocs: Option<ioc::IocSet>,
    #[cfg(feature = "geoip")]
    pub geoip: Option<geoip::GeoIp>,
}

impl Enricher {
    pub fn empty() -> Self {
        Enricher {
            iocs: None,
            #[cfg(feature = "geoip")]
            geoip: None,
        }
    }

    pub fn load(iocs_path: Option<&Path>, geoip_path: Option<&Path>) -> Result<Self> {
        let iocs = match iocs_path {
            Some(p) => Some(ioc::IocSet::load(p)?),
            None => None,
        };

        #[cfg(feature = "geoip")]
        let geoip = match geoip_path {
            Some(p) => Some(geoip::GeoIp::open(p)?),
            None => None,
        };
        #[cfg(not(feature = "geoip"))]
        {
            if geoip_path.is_some() {
                tracing::warn!("--geoip set but logfold was built without --features geoip");
            }
        }

        Ok(Enricher {
            iocs,
            #[cfg(feature = "geoip")]
            geoip,
        })
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "geoip")]
        {
            self.iocs.is_none() && self.geoip.is_none()
        }
        #[cfg(not(feature = "geoip"))]
        {
            self.iocs.is_none()
        }
    }

    /// Lookup annotations for a single variable value. Returns an
    /// empty vector when nothing matches; cheap no-op when nothing
    /// is loaded.
    pub fn annotate_value(&self, value: &str) -> Vec<Annotation> {
        let mut out = Vec::new();
        if let Some(iocs) = &self.iocs {
            if let Some(m) = iocs.lookup(value) {
                out.push(Annotation::Ioc(m.clone()));
            }
        }
        #[cfg(feature = "geoip")]
        if let Some(g) = &self.geoip {
            if let Some(asn) = g.lookup_asn(value) {
                out.push(Annotation::Asn(asn));
            }
            if let Some(country) = g.lookup_country(value) {
                out.push(Annotation::Country(country));
            }
        }
        out
    }
}

/// One enrichment hit for a variable value.
#[derive(Debug, Clone)]
pub enum Annotation {
    Ioc(ioc::IocMatch),
    #[cfg(feature = "geoip")]
    Asn(String),
    #[cfg(feature = "geoip")]
    Country(String),
}

impl Annotation {
    pub fn as_tag(&self) -> String {
        match self {
            Annotation::Ioc(m) => format!("IOC:{}:{}", m.source, m.severity),
            #[cfg(feature = "geoip")]
            Annotation::Asn(s) => format!("ASN:{s}"),
            #[cfg(feature = "geoip")]
            Annotation::Country(c) => format!("CC:{c}"),
        }
    }
}

/// Additional score bump when the pattern has an IOC-matched variable.
pub const IOC_SCORE_BUMP: u32 = 25;

/// Walk every top-K value of every variable on `snap`, return the
/// annotations the enricher produces for them. Deduplicated by tag.
pub fn pattern_annotations(
    snap: &crate::engine::pattern::PatternSnapshot,
    enricher: &Enricher,
) -> Vec<Annotation> {
    if enricher.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Annotation> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for v in &snap.vars {
        for (val, _) in &v.top {
            for ann in enricher.annotate_value(val.as_str()) {
                let tag = ann.as_tag();
                if seen.insert(tag) {
                    out.push(ann);
                }
            }
        }
    }
    out
}

/// Score bump given the enricher context. Caller adds this to the
/// base `compute_score` result. IOC hits contribute [`IOC_SCORE_BUMP`]
/// (once per pattern); GeoIP annotations are informational only
/// and don't nudge the score.
pub fn score_bump(snap: &crate::engine::pattern::PatternSnapshot, enricher: &Enricher) -> u32 {
    if enricher.iocs.is_none() {
        return 0;
    }
    for v in &snap.vars {
        for (val, _) in &v.top {
            if let Some(iocs) = &enricher.iocs {
                if iocs.lookup(val.as_str()).is_some() {
                    return IOC_SCORE_BUMP;
                }
            }
        }
    }
    0
}
