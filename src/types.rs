//! Shared primitive types.

use serde::{Deserialize, Serialize};

/// Classification of a lexical token.
///
/// Order matters: higher-numbered variants should "win" a tie when a token
/// could plausibly be classified multiple ways, but today the classifier
/// doesn't rely on this — it picks the first positive match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TokenType {
    Word,
    Ip,
    Port,
    Num,
    Date,
    Hash,
    Path,
    User,
    Email,
    Url,
    Uuid,
}

impl TokenType {
    /// Short tag used in skeleton substitution: `{IP}`, `{NUM}` etc.
    pub const fn tag(self) -> &'static str {
        match self {
            TokenType::Word => "WORD",
            TokenType::Ip => "IP",
            TokenType::Port => "PORT",
            TokenType::Num => "NUM",
            TokenType::Date => "DATE",
            TokenType::Hash => "HASH",
            TokenType::Path => "PATH",
            TokenType::User => "USER",
            TokenType::Email => "EMAIL",
            TokenType::Url => "URL",
            TokenType::Uuid => "UUID",
        }
    }

    /// Whether this token is treated as a variable (substituted into the
    /// skeleton as `{TAG}`) or kept as a literal (anchor).
    pub const fn is_variable(self) -> bool {
        !matches!(self, TokenType::Word)
    }
}

/// Severity hint carried by named patterns in bundle TOML files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn score_bonus(self) -> u32 {
        match self {
            Severity::Info | Severity::Low => 0,
            Severity::Medium => 10,
            Severity::High => 20,
            Severity::Critical => 30,
        }
    }
}

/// Anomaly badge classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// First time ever seeing this pattern.
    New,
    /// Rare (very low total count).
    Rare,
    /// Sudden rate spike in the latest bucket.
    Spike,
    /// Correlates with another pattern via a shared variable.
    Cross,
    /// Nothing interesting.
    Norm,
    /// High-volume folded pattern.
    Fold,
}

impl Badge {
    pub const fn label(self) -> &'static str {
        match self {
            Badge::New => "NEW",
            Badge::Rare => "RARE",
            Badge::Spike => "SPIKE",
            Badge::Cross => "CROSS",
            Badge::Norm => "NORM",
            Badge::Fold => "FOLD",
        }
    }
}
