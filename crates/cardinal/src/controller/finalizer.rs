use k8s_common::crd::CTFInstance;
use tracing::instrument;

use crate::{Context, Error};

pub const FINALIZER_NAME: &str = "aincrad.noctf.dev/finalizer";

/// Handles finalizer registration and resource cleanup upon CTFInstance deletion.
#[instrument(skip(_ctx, _instance))]
pub async fn reconcile_finalizer(_instance: &CTFInstance, _ctx: &Context) -> Result<bool, Error> {
    // TODO: Finalizer cleanup steps
    Ok(false)
}
