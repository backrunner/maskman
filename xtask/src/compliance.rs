use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ComplianceError {
    #[error("failed to read compliance matrix {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("failed to parse compliance matrix {path}: {source}")]
    Parse { path: PathBuf, source: toml::de::Error },
    #[error("compliance matrix is invalid: {0}")]
    Invalid(String),
    #[error("failed to start compliance tests: {0}")]
    TestStart(std::io::Error),
    #[error("compliance tests failed")]
    TestsFailed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    profile: Profile,
    requirement: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    name: String,
    scope: String,
    http_versions: Vec<String>,
    excluded_http_versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    id: String,
    rfc: u16,
    section: String,
    level: String,
    summary: String,
    status: Status,
    source: Vec<String>,
    tests: Vec<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Implemented,
    Partial,
    NotApplicable,
}

pub fn run(check_only: bool) -> Result<(), ComplianceError> {
    let root = repository_root();
    let path = root.join("compliance/rfc.toml");
    let input = fs::read_to_string(&path)
        .map_err(|source| ComplianceError::Read { path: path.clone(), source })?;
    let matrix: Matrix = toml::from_str(&input)
        .map_err(|source| ComplianceError::Parse { path: path.clone(), source })?;
    validate(&root, &matrix)?;
    println!(
        "validated {} {} requirements for {}",
        matrix.requirement.len(),
        matrix.profile.scope,
        matrix.profile.name
    );
    if !check_only {
        run_tests(&root)?;
    }
    Ok(())
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn validate(root: &Path, matrix: &Matrix) -> Result<(), ComplianceError> {
    validate_profile(&matrix.profile)?;
    if matrix.requirement.is_empty() {
        return invalid("matrix contains no requirements");
    }
    let mut identifiers = HashSet::new();
    for requirement in &matrix.requirement {
        if !identifiers.insert(requirement.id.as_str()) {
            return invalid(format!("duplicate requirement ID {}", requirement.id));
        }
        validate_requirement(root, requirement)?;
    }
    Ok(())
}

fn validate_profile(profile: &Profile) -> Result<(), ComplianceError> {
    if profile.name.trim().is_empty()
        || !matches!(profile.scope.as_str(), "m2-codec" | "v1-cumulative")
    {
        return invalid("profile must name the m2-codec or v1-cumulative scope");
    }
    if profile.http_versions != ["h3"] {
        return invalid("v1 compliance profile must contain only h3");
    }
    for excluded in ["http/1.1", "h2"] {
        if !profile.excluded_http_versions.iter().any(|value| value == excluded) {
            return invalid(format!("profile must explicitly exclude {excluded}"));
        }
    }
    Ok(())
}

fn validate_requirement(root: &Path, requirement: &Requirement) -> Result<(), ComplianceError> {
    if requirement.id.trim().is_empty()
        || requirement.section.trim().is_empty()
        || requirement.summary.trim().is_empty()
        || requirement.rfc == 0
    {
        return invalid(format!("{} has an empty required field", requirement.id));
    }
    if !matches!(requirement.level.as_str(), "MUST" | "MUST NOT" | "SHALL" | "SHALL NOT") {
        return invalid(format!("{} has unsupported normative level", requirement.id));
    }
    match requirement.status {
        Status::Implemented => {
            if requirement.source.is_empty() || requirement.tests.is_empty() {
                return invalid(format!("{} lacks source or tests", requirement.id));
            }
        }
        Status::Partial => return invalid(format!("{} is still partial", requirement.id)),
        Status::NotApplicable => {
            if requirement.reason.as_deref().is_none_or(str::is_empty) {
                return invalid(format!("{} lacks a not-applicable reason", requirement.id));
            }
        }
    }
    for source in &requirement.source {
        validate_relative_file(root, source, &requirement.id)?;
    }
    for test in &requirement.tests {
        validate_test_reference(root, test, &requirement.id)?;
    }
    Ok(())
}

fn validate_relative_file(root: &Path, relative: &str, id: &str) -> Result<(), ComplianceError> {
    let path = Path::new(relative);
    if path.is_absolute() || path.components().any(|part| part.as_os_str() == "..") {
        return invalid(format!("{id} contains unsafe path {relative}"));
    }
    if !root.join(path).is_file() {
        return invalid(format!("{id} references missing file {relative}"));
    }
    Ok(())
}

fn validate_test_reference(root: &Path, reference: &str, id: &str) -> Result<(), ComplianceError> {
    let Some((relative, test_name)) = reference.rsplit_once("::") else {
        return invalid(format!("{id} has malformed test reference {reference}"));
    };
    validate_relative_file(root, relative, id)?;
    if test_name.is_empty() {
        return invalid(format!("{id} has an empty test name"));
    }
    let path = root.join(relative);
    let source =
        fs::read_to_string(&path).map_err(|error| ComplianceError::Read { path, source: error })?;
    if !source.contains(&format!("fn {test_name}")) {
        return invalid(format!("{id} references missing test {test_name}"));
    }
    Ok(())
}

fn run_tests(root: &Path) -> Result<(), ComplianceError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(root)
        .args(["test", "--locked", "-p", "maskman-protocol", "-p", "maskman-server"])
        .status()
        .map_err(ComplianceError::TestStart)?;
    if !status.success() {
        return Err(ComplianceError::TestsFailed);
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ComplianceError> {
    Err(ComplianceError::Invalid(message.into()))
}
