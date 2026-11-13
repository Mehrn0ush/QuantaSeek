//! Every rule and policy entry must cite a primary source with a verbatim
//! quote. Run directly or via scripts/check-rule-metadata.

use quanta_seek::findings::{catalogue, policy, policy_ids};

/// Hosts accepted as primary sources: the publishing body's own site.
const PRIMARY_HOSTS: &[&str] = &[
    "https://www.rfc-editor.org/",
    "https://datatracker.ietf.org/",
    "https://www.iana.org/",
    "https://nvlpubs.nist.gov/",
    "https://csrc.nist.gov/",
];

fn primary(url: &str) -> bool {
    PRIMARY_HOSTS.iter().any(|h| url.starts_with(h))
}

#[test]
fn every_rule_cites_a_primary_source_with_a_quote() {
    let mut seen = std::collections::HashSet::new();
    for r in catalogue() {
        assert!(seen.insert(r.id.clone()), "duplicate rule id {}", r.id);
        let parts: Vec<&str> = r.id.split('-').collect();
        assert!(
            parts.len() == 3
                && parts[0] == "QS"
                && parts[2].len() == 3
                && parts[2].bytes().all(|b| b.is_ascii_digit()),
            "rule id {} does not match QS-<AREA>-<nnn>",
            r.id
        );
        assert!(
            !r.title.trim().is_empty() && !r.description.trim().is_empty(),
            "{}",
            r.id
        );
        assert!(!r.remediation.trim().is_empty(), "{}: no remediation", r.id);
        assert!(
            ["handshake", "probe", "chain"].contains(&r.evaluated_on.as_str()),
            "{}",
            r.id
        );
        assert!(!r.reference.is_empty(), "{}: no reference", r.id);
        for reference in &r.reference {
            assert!(
                primary(&reference.url),
                "{}: {} is not a primary source",
                r.id,
                reference.url
            );
            assert!(!reference.source.trim().is_empty(), "{}", r.id);
            assert!(
                !reference.section.trim().is_empty(),
                "{}: reference without section",
                r.id
            );
            assert!(
                reference.quote.trim().len() >= 20,
                "{}: missing or trivial quote",
                r.id
            );
        }
    }
}

#[test]
fn every_policy_entry_cites_its_clause() {
    let ids: Vec<String> = catalogue().iter().map(|r| r.id.clone()).collect();
    assert!(!policy_ids().is_empty());
    for pid in policy_ids() {
        let p = policy(pid).unwrap();
        assert!(primary(&p.url), "{pid}: {} is not a primary source", p.url);
        assert!(!p.retrieved.trim().is_empty(), "{pid}: no retrieval date");
        for r in &p.rule {
            assert!(ids.contains(&r.id), "{pid}: unknown rule {}", r.id);
            assert!(!r.clause.trim().is_empty(), "{pid}/{}: no clause", r.id);
            assert!(
                r.quote.trim().len() >= 20,
                "{pid}/{}: missing or trivial quote",
                r.id
            );
        }
    }
}
