use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use schemars::{JsonSchema, Schema, SchemaGenerator};

pub const fn default_val<const V: i64>() -> i32 {
    V as i32
}

pub trait KubeListKey {
    const KEY: &'static str;
}

impl KubeListKey for Condition {
    const KEY: &'static str = "type";
}

pub fn list_schema<T: JsonSchema + KubeListKey>(r: &mut SchemaGenerator) -> Schema {
    let mut schema = <Vec<T>>::json_schema(r);

    let obj = schema.ensure_object();
    obj.insert(
        "x-kubernetes-list-type".to_string(),
        serde_json::json!("map"),
    );
    obj.insert(
        "x-kubernetes-list-map-keys".to_string(),
        serde_json::json!([T::KEY]),
    );
    schema
}

pub fn embedded_resource_schema<T>(_r: &mut SchemaGenerator) -> Schema {
    let mut schema = Schema::default();
    let obj = schema.ensure_object();
    obj.insert("type".to_string(), serde_json::json!("object"));
    obj.insert(
        "x-kubernetes-embedded-resource".to_string(),
        serde_json::json!(true),
    );
    obj.insert(
        "x-kubernetes-preserve-unknown-fields".to_string(),
        serde_json::json!(true),
    );
    schema
}
