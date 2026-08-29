use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const fn default_val<const V: i64>() -> i32 {
    V as i32
}

pub trait KubeListKey {
    const KEYS: &'static [&'static str];
}

impl KubeListKey for Condition {
    const KEYS: &'static [&'static str] = &["type"];
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
        serde_json::json!(T::KEYS),
    );
    obj.insert("maxItems".to_string(), serde_json::json!(32));
    schema
}

#[allow(clippy::extra_unused_type_parameters)]
pub fn embedded_resource_schema<T>(_r: &mut SchemaGenerator) -> Schema {
    let mut schema = Schema::default();
    let obj = schema.ensure_object();
    obj.insert("type".to_string(), serde_json::json!("object"));
    obj.insert(
        "x-kubernetes-preserve-unknown-fields".to_string(),
        serde_json::json!(true),
    );
    schema
}

pub fn immutable_property_schema(r: &mut SchemaGenerator) -> Schema {
    let mut schema = String::json_schema(r);
    let obj = schema.ensure_object();
    obj.insert(
        "x-kubernetes-validations".to_string(),
        serde_json::json!([
            {
                "rule": "self == oldSelf",
                "message": "property is immutable and cannot be changed after creation"
            }
        ]),
    );
    schema
}

pub fn json_patch_schema(_r: &mut SchemaGenerator) -> Schema {
    let mut schema = Schema::default();
    let obj = schema.ensure_object();
    obj.insert("type".to_string(), serde_json::json!("array"));
    obj.insert(
        "items".to_string(),
        serde_json::json!({
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": true
        }),
    );
    schema
}

/// 3-state Nullable enum for JSON Merge Patch / override semantics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PatchValue<T> {
    /// Key omitted in JSON (no change / inherit from template).
    #[default]
    Unset,
    /// Explicit null in JSON (clear field / reset to default).
    Null,
    /// Explicit value in JSON.
    Value(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PatchValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Option<T>>::deserialize(deserializer).map(|opt| match opt {
            None | Some(None) => PatchValue::Null,
            Some(Some(v)) => PatchValue::Value(v),
        })
    }
}

impl<T: Serialize> Serialize for PatchValue<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PatchValue::Unset => serializer.serialize_none(),
            PatchValue::Null => serializer.serialize_none(),
            PatchValue::Value(v) => v.serialize(serializer),
        }
    }
}

impl<T: JsonSchema> JsonSchema for PatchValue<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn json_schema(r: &mut SchemaGenerator) -> Schema {
        let mut schema = T::json_schema(r);
        let obj = schema.ensure_object();
        obj.insert("nullable".to_string(), serde_json::Value::Bool(true));
        schema
    }
}
