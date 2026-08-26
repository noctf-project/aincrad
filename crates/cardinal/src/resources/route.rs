use k8s_common::crd::{CTFInstanceSpecRouteOverride, CTFRouteSpec, PatchValue};

/// Builds a merged `CTFRouteSpec` from a base template specification and optional instance overrides.
pub fn build_ctfroute_spec(
    base: &CTFRouteSpec,
    override_spec: Option<&CTFInstanceSpecRouteOverride>,
) -> CTFRouteSpec {
    let mut merged = base.clone();

    if let Some(ov) = override_spec {
        match ov.port {
            PatchValue::Value(port) => {
                merged.port = Some(port);
            }
            PatchValue::Null => {
                merged.port = None;
            }
            PatchValue::Unset => {}
        }

        match &ov.tls {
            PatchValue::Value(tls_patch) => {
                let mut tls = merged.tls.unwrap_or_default();
                match &tls_patch.prefix {
                    PatchValue::Value(prefix) => {
                        tls.prefix = Some(prefix.clone());
                    }
                    PatchValue::Null => {
                        tls.prefix = None;
                    }
                    PatchValue::Unset => {}
                }
                merged.tls = Some(tls);
            }
            PatchValue::Null => {
                merged.tls = None;
            }
            PatchValue::Unset => {}
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFRouteBackend, CTFRouteSpecTLS, CTFRouteSpecTLSPatch};

    #[test]
    fn test_build_ctfroute_spec_port_and_tls_overrides() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            port: Some(443),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            port: PatchValue::Value(8443),
            tls: PatchValue::Value(CTFRouteSpecTLSPatch {
                prefix: PatchValue::Value("custom-prefix".into()),
            }),
        };

        let merged = build_ctfroute_spec(&base_spec, Some(&override_spec));

        assert_eq!(merged.port, Some(8443));
        assert_eq!(
            merged.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("custom-prefix".into()),
            })
        );
    }

    #[test]
    fn test_build_ctfroute_spec_disable_port_via_null() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            port: Some(443),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            port: PatchValue::Unset,
            tls: PatchValue::Null,
        };

        let merged = build_ctfroute_spec(&base_spec, Some(&override_spec));

        assert_eq!(merged.port, Some(443));
        assert_eq!(merged.tls, None);
    }

    #[test]
    fn test_build_ctfroute_spec_no_override() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            port: Some(443),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let merged = build_ctfroute_spec(&base_spec, None);

        assert_eq!(merged.port, Some(443));
        assert_eq!(
            merged.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            })
        );
    }
}
