//! Drift detector between `core/policy/tools.yaml` (the human-readable mirror)
//! and `PolicyEngine::new` (the enforcing in-binary allowlist).
//!
//! If this test fails, you almost certainly edited one side of the contract
//! and forgot the other. The error messages below name the exact tool that
//! diverges so the fix is mechanical.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use aegis_gatekeeper::PolicyEngine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct YamlEntry {
    requires_human: bool,
    #[serde(default)]
    dual_mfa: bool,
}

/// Locate `core/policy/tools.yaml` from CARGO_MANIFEST_DIR
/// (= `core/rust/aegis-gatekeeper`). Walking up two levels lands at `core/`.
fn tools_yaml_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // core/rust
        .and_then(|p| p.parent()) // core
        .expect("CARGO_MANIFEST_DIR has unexpected shape")
        .join("policy")
        .join("tools.yaml")
}

/// Flatten every section of tools.yaml (defensive/offensive/restricted/...)
/// into a single map keyed by tool name. Top-level keys that are not
/// section maps (e.g. `version`) are skipped.
fn load_yaml_entries() -> BTreeMap<String, YamlEntry> {
    let path = tools_yaml_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid YAML at {}: {e}", path.display()));

    let map = doc
        .as_mapping()
        .expect("tools.yaml top-level must be a mapping");

    let mut out = BTreeMap::new();
    for (section_name, section_val) in map {
        // Skip scalars like `version: 1`.
        let Some(section_map) = section_val.as_mapping() else { continue };
        let section_name_str = section_name
            .as_str()
            .unwrap_or("<non-string section>");

        for (tool_name, tool_val) in section_map {
            let tool_name = tool_name
                .as_str()
                .unwrap_or_else(|| panic!("non-string tool key in section {section_name_str}"))
                .to_string();
            let entry: YamlEntry = serde_yaml::from_value(tool_val.clone())
                .unwrap_or_else(|e| panic!("malformed entry for {tool_name}: {e}"));
            if out.insert(tool_name.clone(), entry).is_some() {
                panic!("duplicate tool name across sections: {tool_name}");
            }
        }
    }
    out
}

#[test]
fn allowlist_keys_match_yaml() {
    let yaml = load_yaml_entries();
    let engine = PolicyEngine::new();

    let yaml_keys: BTreeSet<String> = yaml.keys().cloned().collect();
    let engine_keys: BTreeSet<String> = engine.allowlist_keys().into_iter().collect();

    let only_in_yaml: Vec<&String> = yaml_keys.difference(&engine_keys).collect();
    let only_in_engine: Vec<&String> = engine_keys.difference(&yaml_keys).collect();

    assert!(
        only_in_yaml.is_empty() && only_in_engine.is_empty(),
        "allowlist drift detected\n  declared in tools.yaml but missing from PolicyEngine::new: {:?}\n  declared in PolicyEngine::new but missing from tools.yaml: {:?}",
        only_in_yaml,
        only_in_engine,
    );
}

#[test]
fn requires_human_flags_match_yaml() {
    let yaml = load_yaml_entries();
    let engine = PolicyEngine::new();

    for (name, entry) in &yaml {
        let policy = engine
            .policy_for(name)
            .unwrap_or_else(|| panic!("PolicyEngine missing tool '{name}' present in tools.yaml"));
        assert_eq!(
            policy.requires_human, entry.requires_human,
            "requires_human mismatch for '{name}': yaml={} engine={}",
            entry.requires_human, policy.requires_human
        );
    }
}

#[test]
fn dual_mfa_tools_are_restricted() {
    let yaml = load_yaml_entries();
    let engine = PolicyEngine::new();

    for (name, entry) in &yaml {
        if entry.dual_mfa {
            assert!(
                engine.is_restricted(name),
                "tool '{name}' has dual_mfa=true in tools.yaml but is not in PolicyEngine restricted_tools",
            );
        } else {
            assert!(
                !engine.is_restricted(name),
                "tool '{name}' is in PolicyEngine restricted_tools but tools.yaml has dual_mfa=false",
            );
        }
    }
}
