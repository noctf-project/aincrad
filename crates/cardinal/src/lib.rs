pub mod context;
pub mod controller;
pub mod error;
pub mod reconcilers;
pub mod resources;
pub mod utils;

pub use context::Context;
pub use error::Error;

#[macro_export]
macro_rules! btreemap {
    ($( $key:expr => $val:expr ),* $(,)?) => {{
        let mut map = std::collections::BTreeMap::new();
        $( map.insert($key.into(), $val.into()); )*
        map
    }};
}
