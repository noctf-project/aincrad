use schemars::{JsonSchema, Schema, SchemaGenerator};

pub const fn default_val<const V: i64>() -> i32 {
    V as i32
}

pub trait KubeListKey {
    const KEY: &'static str;
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
