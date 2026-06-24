use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A supply-chain vulnerability that a package may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vulnerability {
    Malware,
    Typosquatting,
    DependencyConfusion,
}

impl Vulnerability {
    /// The vulnerability's name as it appears in the data file.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::Typosquatting => "typosquatting",
            Self::DependencyConfusion => "dependency_confusion",
        }
    }
}

/// In-memory model of package vulnerability data, keyed by [purl].
///
/// Built from a YAML file and used to look up whether a package pulled through
/// the proxy is known to carry a vulnerability.
///
/// [purl]: https://github.com/package-url/purl-spec
#[derive(Debug, Default)]
pub struct PackageData {
    packages: HashMap<String, HashSet<Vulnerability>>,
}

impl PackageData {
    /// Loads package data from a YAML file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, or if its contents cannot be
    /// parsed as the expected package-data format.
    pub fn from_file(path: &Path) -> Result<Self, BoxError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_yaml(&contents)
    }

    /// Parses package data from a YAML string.
    ///
    /// # Errors
    /// Returns an error if the string is not valid YAML in the expected format
    /// (including unknown vulnerability names).
    pub fn from_yaml(yaml: &str) -> Result<Self, BoxError> {
        let raw: RawPackageData = serde_yaml::from_str(yaml)?;
        Ok(Self::from(raw))
    }

    /// Looks up the vulnerabilities recorded for a package by its purl,
    /// returning `None` when the package is not present in the data.
    #[must_use]
    pub fn lookup(&self, purl: &str) -> Option<&HashSet<Vulnerability>> {
        self.packages.get(purl)
    }

    /// Number of distinct packages recorded.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }
}

/// Wire format of the package-data file: a list of single-entry maps, each
/// mapping a purl to its list of vulnerability types.
#[derive(Debug, Default, Deserialize)]
struct RawPackageData {
    #[serde(default)]
    packages: Vec<HashMap<String, Vec<Vulnerability>>>,
}

impl From<RawPackageData> for PackageData {
    fn from(raw: RawPackageData) -> Self {
        let mut packages: HashMap<String, HashSet<Vulnerability>> = HashMap::new();
        for entry in raw.packages {
            for (purl, vulns) in entry {
                packages.entry(purl).or_default().extend(vulns);
            }
        }
        Self { packages }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    const SAMPLE: &str = r"
packages:
  - pkg:npm/axios@1.9.3:
    - malware
    - dependency_confusion
  - pkg:npm/lodash@4.17.21:
    - malware
  - pkg:npm/react@18.3.1:
    - malware
    - typosquatting
";

    /// Writes `contents` to a unique temporary file and returns its path.
    fn temp_yaml(contents: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("pcg-{}-{n}.yaml", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_packages_and_their_vulnerabilities() {
        let data = PackageData::from_yaml(SAMPLE).unwrap();
        assert_eq!(data.package_count(), 3);

        assert_eq!(
            data.lookup("pkg:npm/lodash@4.17.21"),
            Some(&HashSet::from([Vulnerability::Malware]))
        );
        assert_eq!(
            data.lookup("pkg:npm/react@18.3.1"),
            Some(&HashSet::from([
                Vulnerability::Malware,
                Vulnerability::Typosquatting
            ]))
        );
    }

    #[test]
    fn records_multiple_vulnerabilities_for_a_package() {
        let data = PackageData::from_yaml(SAMPLE).unwrap();
        assert_eq!(
            data.lookup("pkg:npm/axios@1.9.3"),
            Some(&HashSet::from([
                Vulnerability::Malware,
                Vulnerability::DependencyConfusion
            ]))
        );
    }

    #[test]
    fn lookup_returns_none_for_unknown_package() {
        let data = PackageData::from_yaml(SAMPLE).unwrap();
        assert!(data.lookup("pkg:npm/unknown@1.0.0").is_none());
    }

    #[test]
    fn empty_document_yields_no_packages() {
        let data = PackageData::from_yaml("packages: []").unwrap();
        assert_eq!(data.package_count(), 0);
    }

    #[test]
    fn missing_packages_key_defaults_to_empty() {
        let data = PackageData::from_yaml("{}").unwrap();
        assert_eq!(data.package_count(), 0);
    }

    #[test]
    fn duplicate_purl_entries_are_merged() {
        let yaml = r"
packages:
  - pkg:npm/dup@1.0.0:
    - malware
  - pkg:npm/dup@1.0.0:
    - typosquatting
";
        let data = PackageData::from_yaml(yaml).unwrap();
        assert_eq!(data.package_count(), 1);
        assert_eq!(
            data.lookup("pkg:npm/dup@1.0.0"),
            Some(&HashSet::from([
                Vulnerability::Malware,
                Vulnerability::Typosquatting
            ]))
        );
    }

    #[test]
    fn invalid_yaml_is_an_error() {
        assert!(PackageData::from_yaml("packages: : :").is_err());
    }

    #[test]
    fn unknown_vulnerability_name_is_an_error() {
        let yaml = r"
packages:
  - pkg:npm/x@1.0.0:
    - not_a_real_vulnerability
";
        assert!(PackageData::from_yaml(yaml).is_err());
    }

    #[test]
    fn from_file_loads_existing_file() {
        let path = temp_yaml(SAMPLE);
        let data = PackageData::from_file(&path).unwrap();
        assert_eq!(data.package_count(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vulnerability_labels_match_data_file_names() {
        assert_eq!(Vulnerability::Malware.label(), "malware");
        assert_eq!(Vulnerability::Typosquatting.label(), "typosquatting");
        assert_eq!(
            Vulnerability::DependencyConfusion.label(),
            "dependency_confusion"
        );
    }

    #[test]
    fn from_file_errors_for_missing_file() {
        let path = std::env::temp_dir().join("pcg-does-not-exist-xyz.yaml");
        assert!(PackageData::from_file(&path).is_err());
    }
}
