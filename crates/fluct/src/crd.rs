use chrono::{DateTime, FixedOffset};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

fn clamp_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    i64::deserialize(d).map(|v| v.max(0) as u64)
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteStatus {
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

pub type CTFRouteSpecPair = (String, CTFRouteSpec);

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "aincrad.noctf.dev",
    version = "v1",
    kind = "CTFRoute",
    namespaced,
    status = CTFRouteStatus,
)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteSpec {
    #[serde(default)]
    pub flag: Option<String>,
    pub available_at: Option<DateTime<FixedOffset>>,
    pub secret: Option<String>,
    #[serde(default)]
    pub request_uid: bool,
    pub pow: Option<CTFRouteSpecPOW>,
    #[serde(default)]
    pub logs: bool,
    pub backend: String,
    pub tls: Option<CTFRouteSpecTLS>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteSpecPOW {
    #[serde(deserialize_with = "clamp_u64")]
    pub difficulty: u64,
    #[serde(default)]
    pub enable_admin_bypass: bool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteSpecTLS {
    pub key: Option<String>,
}

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "aincrad.noctf.dev",
    version = "v1",
    kind = "CTFPort",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CTFPortSpec {
    pub route: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_spec_deserialization() {
        let json_omitted = serde_json::json!({
            "backend": "127.0.0.1:8080"
        });
        let spec_omitted: CTFRouteSpec = serde_json::from_value(json_omitted).unwrap();
        assert_eq!(spec_omitted.backend, "127.0.0.1:8080");
        assert_eq!(spec_omitted.flag, None);
        assert_eq!(spec_omitted.tls, None);

        let json_empty_tag = serde_json::json!({
            "backend": "127.0.0.1:8080",
            "tls": {},
        });
        let spec_empty_tag: CTFRouteSpec = serde_json::from_value(json_empty_tag).unwrap();
        assert_eq!(spec_empty_tag.tls, Some(CTFRouteSpecTLS { key: None }));

        let json_false = serde_json::json!({
            "backend": "127.0.0.1:8080",
        });
        let spec_false: CTFRouteSpec = serde_json::from_value(json_false).unwrap();
        assert_eq!(spec_false.tls, None);

        let json_full = serde_json::json!({
            "backend": "127.0.0.1:8080",
            "flag": "my_flag",
            "tls": {
                "key": "web"
            },
        });
        let spec_full: CTFRouteSpec = serde_json::from_value(json_full).unwrap();
        assert_eq!(spec_full.flag, Some("my_flag".to_string()));
        assert_eq!(
            spec_full.tls,
            Some(CTFRouteSpecTLS {
                key: Some("web".to_string())
            })
        );
    }
}
