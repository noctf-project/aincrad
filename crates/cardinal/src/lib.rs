pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

#[macro_export]
macro_rules! btreemap {
    ($( $key:expr => $val:expr ),* $(,)?) => {{
        let mut map = BTreeMap::new();
        $( map.insert($key.into(), $val.into()); )*
        map
    }};
}
