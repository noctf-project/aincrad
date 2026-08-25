use k8s_common::crd::{CTFInstance, CTFRoute};

/// Builds a CTFRoute manifest for a given CTFInstance.
pub fn build_route(_instance: &CTFInstance) -> Option<CTFRoute> {
    // TODO: Build CTFRoute manifest based on CTFTemplate specification
    None
}
