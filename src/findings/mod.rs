//! Findings: rules applied to a [`ScanReport`], optionally under a policy pack.
//!
//! Rule metadata (titles, remediation, references with verbatim quotes) is in
//! `rules/rules.toml`; policy packs are in `policies/*.toml`. Both are
//! embedded at build time. Rule logic is in [`rules`]. Every finding carries
//! the observed report fields it was derived from. A rule that cannot be
//! evaluated for a scan (for example a probe rule without `--probe`) is
//! listed in `not_evaluated` with the reason, never silently passed.
//!
//! The score is derived from the findings only.

pub mod rules;

use crate::report::ScanReport;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Finding severity, lowest to highest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => {
                return Err(format!(
                    "unknown severity '{s}' (info, low, medium, high, critical)"
                ))
            }
        })
    }
}

/// A primary-source reference with a verbatim quote.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub source: String,
    pub url: String,
    pub section: String,
    pub quote: String,
}

/// One rule's metadata, from `rules/rules.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMeta {
    pub id: String,
    pub title: String,
    pub default_severity: Severity,
    pub description: String,
    pub remediation: String,
    /// "handshake", "probe" or "chain": which part of the report it reads.
    pub evaluated_on: String,
    pub reference: Vec<Reference>,
}

#[derive(Deserialize)]
struct Catalogue {
    rule: Vec<RuleMeta>,
}

/// A policy pack: which rules apply, at which severity, under which clause.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPack {
    pub id: String,
    pub title: String,
    pub url: String,
    pub retrieved: String,
    pub rule: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub severity: Severity,
    pub clause: String,
    pub deadline: Option<String>,
    pub quote: String,
}

const RULES_TOML: &str = include_str!("../../rules/rules.toml");
/// (id, TOML) for every shipped policy pack.
const POLICIES: &[(&str, &str)] = &[(
    "nist-ir-8547",
    include_str!("../../policies/nist-ir-8547.toml"),
)];

/// The rule catalogue. Panics only if the embedded TOML is invalid, which
/// the test suite rules out.
pub fn catalogue() -> &'static [RuleMeta] {
    static CATALOGUE: OnceLock<Vec<RuleMeta>> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        toml::from_str::<Catalogue>(RULES_TOML)
            .map(|c| c.rule)
            .unwrap_or_else(|e| panic!("rules/rules.toml is invalid: {e}"))
    })
}

/// Ids of the shipped policy packs.
pub fn policy_ids() -> Vec<&'static str> {
    POLICIES.iter().map(|(id, _)| *id).collect()
}

/// A shipped policy pack by id.
pub fn policy(id: &str) -> Option<&'static PolicyPack> {
    static PACKS: OnceLock<Vec<PolicyPack>> = OnceLock::new();
    PACKS
        .get_or_init(|| {
            POLICIES
                .iter()
                .map(|(name, text)| {
                    toml::from_str(text)
                        .unwrap_or_else(|e| panic!("policies/{name}.toml is invalid: {e}"))
                })
                .collect()
        })
        .iter()
        .find(|p| p.id == id)
}

/// An observed report field a finding was derived from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Path in this report, e.g. "tls.key_exchange.name".
    pub field: String,
    pub value: String,
}

impl Evidence {
    pub fn new(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: value.into(),
        }
    }
}

/// The policy clause a finding falls under.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyClause {
    pub policy: String,
    pub clause: String,
    pub deadline: Option<String>,
    pub quote: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Stable rule id, e.g. "QS-KEX-001".
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// Always "derived": a rule applied to the observed `evidence`.
    pub provenance: String,
    pub evidence: Vec<Evidence>,
    pub description: String,
    pub remediation: String,
    pub references: Vec<Reference>,
    /// Present when a policy pack was applied.
    pub policy: Option<PolicyClause>,
    /// QuantaSeek version that introduced the rule.
    pub introduced_in: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotEvaluated {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyInfo {
    pub id: String,
    pub title: String,
    pub url: String,
    pub retrieved: String,
}

/// Score derived from findings. Not an independent measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Score {
    /// 0..=100.
    pub value: u8,
    /// Always "derived".
    pub provenance: String,
    pub method: String,
}

pub const SCORE_METHOD: &str = "100 minus 0 per info, 2 per low, 10 per medium, 25 per high and \
50 per critical finding, floored at 0; capped at 40 if any finding is critical. Rules listed in \
not_evaluated do not affect the score.";

/// Score for a set of findings (see [`SCORE_METHOD`]).
pub fn score(findings: &[Finding]) -> Score {
    let penalty: u32 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 10,
            Severity::High => 25,
            Severity::Critical => 50,
        })
        .sum();
    let mut value = 100u32.saturating_sub(penalty);
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        value = value.min(40);
    }
    Score {
        value: value as u8,
        provenance: "derived".to_string(),
        method: SCORE_METHOD.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    /// The policy pack applied, or null for QuantaSeek's default severities.
    pub policy: Option<PolicyInfo>,
    pub findings: Vec<Finding>,
    pub not_evaluated: Vec<NotEvaluated>,
    pub score: Score,
}

/// Apply the catalogue (all rules at default severity) or a policy pack
/// (its rules at its severities) to a report.
pub fn assess(report: &ScanReport, policy: Option<&PolicyPack>) -> Assessment {
    let mut findings = Vec::new();
    let mut not_evaluated = Vec::new();
    for meta in catalogue() {
        let clause = match policy {
            Some(p) => match p.rule.iter().find(|r| r.id == meta.id) {
                Some(r) => Some(r),
                None => continue, // not part of this policy
            },
            None => None,
        };
        match rules::evaluate(&meta.id, report) {
            rules::Outcome::Pass => {}
            rules::Outcome::NotEvaluated(reason) => not_evaluated.push(NotEvaluated {
                id: meta.id.clone(),
                reason,
            }),
            rules::Outcome::Finding(evidence) => findings.push(Finding {
                id: meta.id.clone(),
                title: meta.title.clone(),
                severity: clause.map(|c| c.severity).unwrap_or(meta.default_severity),
                provenance: "derived".to_string(),
                evidence,
                description: meta.description.clone(),
                remediation: meta.remediation.clone(),
                references: meta.reference.clone(),
                policy: clause.zip(policy).map(|(c, p)| PolicyClause {
                    policy: p.id.clone(),
                    clause: c.clause.clone(),
                    deadline: c.deadline.clone(),
                    quote: c.quote.clone(),
                    url: p.url.clone(),
                }),
                introduced_in: "0.1.0".to_string(),
            }),
        }
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    Assessment {
        policy: policy.map(|p| PolicyInfo {
            id: p.id.clone(),
            title: p.title.clone(),
            url: p.url.clone(),
            retrieved: p.retrieved.clone(),
        }),
        score: score(&findings),
        findings,
        not_evaluated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: "QS-TEST".into(),
            title: String::new(),
            severity,
            provenance: "derived".into(),
            evidence: vec![],
            description: String::new(),
            remediation: String::new(),
            references: vec![],
            policy: None,
            introduced_in: "0.1.0".into(),
        }
    }

    #[test]
    fn catalogue_and_policies_parse() {
        assert!(catalogue().len() >= 10);
        for id in policy_ids() {
            assert!(policy(id).is_some(), "{id}");
        }
        assert!(policy("cnsa-2.0").is_none());
    }

    #[test]
    fn score_is_derived_from_findings_only() {
        assert_eq!(score(&[]).value, 100);
        assert_eq!(score(&[finding(Severity::Info)]).value, 100);
        assert_eq!(score(&[finding(Severity::Low)]).value, 98);
        assert_eq!(
            score(&[finding(Severity::High), finding(Severity::Medium)]).value,
            65
        );
        assert_eq!(score(&vec![finding(Severity::High); 5]).value, 0);
    }

    #[test]
    fn one_critical_finding_caps_the_score_whatever_else_is_present() {
        // Property: for any set of findings, adding a critical one caps the
        // score at 40, and the score never increases when a finding is added.
        let all = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for mask in 0u32..(1 << 10) {
            // Up to two findings of each severity, chosen by the bit mask.
            let base: Vec<Finding> = (0..10)
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| finding(all[bit / 2]))
                .collect();
            let before = score(&base).value;
            for s in all {
                let mut more = base.clone();
                more.push(finding(s));
                let after = score(&more).value;
                assert!(after <= before, "{mask:#b} + {s:?}");
                if s == Severity::Critical {
                    assert!(after <= 40, "{mask:#b}");
                }
            }
        }
    }
}
