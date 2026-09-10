use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

use crate::Error;

pub mod instance;
pub mod route;
pub mod template;
pub mod tls_route;

pub mod util;

pub use aincrad_macros::PatchValue;
pub use instance::*;
pub use route::*;
pub use template::*;
pub use tls_route::*;
pub use util::PatchValue;

pub fn generate_crd(format: &str, crd: CustomResourceDefinition) -> Result<String, Error> {
    match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&crd)
            .map_err(|e| format!("failed to serialize CRD to JSON: {e}").into()),
        "yaml" | "yml" => serde_yaml::to_string(&crd)
            .map_err(|e| format!("failed to serialize CRD to YAML: {e}").into()),
        other => Err(format!("unsupported CRD format '{other}', expected 'yaml' or 'json'").into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::crd::{Instance, generate_crd};
    use kube::CustomResourceExt;

    #[test]
    fn test_generate_crd() {
        let crd = Instance::crd();
        let yaml = generate_crd("yaml", crd.clone()).unwrap();
        assert!(yaml.contains("kind: CustomResourceDefinition"));

        let json = generate_crd("json", crd.clone()).unwrap();
        assert!(json.contains("\"kind\": \"CustomResourceDefinition\""));

        assert!(generate_crd("invalid", crd).is_err());
    }
}
