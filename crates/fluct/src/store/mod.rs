pub mod ports;
pub mod routes;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteKey {
    pub namespace: String,
    pub name: String,
}

impl std::fmt::Display for RouteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.name)
    }
}

impl std::str::FromStr for RouteKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (namespace, name) = s.split_once(':').ok_or("missing colon delimiter")?;
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
        })
    }
}
