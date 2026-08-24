use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

use crate::Error;

pub mod route;
pub mod template;
mod util;

pub use route::*;
pub use template::*;

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
    use crate::crd::{generate_crd, route::CTFRoute};
    use kube::CustomResourceExt;

    #[test]
    fn test_generate_crd() {
        let crd = CTFRoute::crd();
        let yaml = generate_crd("yaml", crd.clone()).unwrap();
        assert!(yaml.contains("kind: CustomResourceDefinition"));
        assert!(yaml.contains("name: ctfroutes.aincrad.noctf.dev"));

        let json = generate_crd("json", crd.clone()).unwrap();
        assert!(json.contains("\"kind\": \"CustomResourceDefinition\""));

        assert!(generate_crd("invalid", crd).is_err());
    }
}
