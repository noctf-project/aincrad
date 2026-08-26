use aincrad_macros::{BorrowedHash, BorrowedKey, Equivalent};

pub mod ports;
pub mod routes;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, BorrowedKey, BorrowedHash, Equivalent,
)]
pub struct RouteKey {
    pub namespace: String,
    pub name: String,
}

impl std::fmt::Display for RouteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}
