//! GCP vTPM pre-provisioned AK loading using tss-esapi
//!
//! This module provides native Rust implementation for loading GCP's
//! pre-provisioned Attestation Key using the TSS2 ESAPI.

#[cfg(feature = "gcp-vtpm")]
use anyhow::{Context as _, Result};
#[cfg(feature = "gcp-vtpm")]
use tss_esapi::{
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        resource_handles::{Hierarchy, NvAuth},
    },
    structures::Public,
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::UnMarshall,
    Context as TssContext,
};
#[cfg(feature = "gcp-vtpm")]
use tracing::info;

/// GCP vTPM NV indices for pre-provisioned AK
#[cfg(feature = "gcp-vtpm")]
pub mod gcp_nv_index {
    /// RSA AK certificate (DER format)
    pub const AK_RSA_CERT: u32 = 0x01C10000;
    /// RSA AK template (TPM2B_PUBLIC format)
    pub const AK_RSA_TEMPLATE: u32 = 0x01C10001;
    /// ECC AK certificate (DER format)
    pub const AK_ECC_CERT: u32 = 0x01C10002;
    /// ECC AK template (TPM2B_PUBLIC format)
    pub const AK_ECC_TEMPLATE: u32 = 0x01C10003;
}

/// Load GCP pre-provisioned RSA AK using tss-esapi
///
/// This function:
/// 1. Reads the AK template from NV index 0x01C10001
/// 2. Creates a primary key under Endorsement hierarchy with the template
/// 3. TPM deterministically recreates the same key pair (same template + same parent)
///
/// # Parameters
/// - `tcti_path`: Path to TPM device (e.g., "/dev/tpmrm0" or None for default)
///
/// # Returns
/// - `Ok((TssContext, KeyHandle))` - TSS context and handle to the loaded AK
/// - `Err(_)` - Failed to load AK (not on GCP vTPM, or access error)
#[cfg(feature = "gcp-vtpm")]
pub fn load_gcp_ak_rsa(tcti_path: Option<&str>) -> Result<(TssContext, KeyHandle)> {
    info!("loading GCP pre-provisioned RSA AK with tss-esapi...");

    // Create TSS context
    use std::str::FromStr;
    let tcti_str = tcti_path.unwrap_or("/dev/tpmrm0");
    let device_config = DeviceConfig::from_str(tcti_str)
        .context("failed to parse device config")?;
    let tcti = TctiNameConf::Device(device_config);
    let mut context = TssContext::new(tcti).context("failed to create TSS context")?;

    // Read AK template from NV
    let template_bytes = read_nv_data(&mut context, gcp_nv_index::AK_RSA_TEMPLATE)
        .context("failed to read AK template from NV 0x01C10001")?;

    info!("read AK template from NV: {} bytes", template_bytes.len());

    // Parse template as TPM2B_PUBLIC
    let public = Public::unmarshall(&template_bytes)
        .context("failed to parse AK template as TPM2B_PUBLIC")?;

    // Create primary key under Endorsement hierarchy with null auth session
    // This recreates the pre-provisioned AK because TPM CreatePrimary is deterministic
    let ak_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Endorsement,
                public,
                None,  // auth_value
                None,  // sensitive_data
                None,  // outside_info
                None,  // creation_pcr
            )
        })
        .context("failed to create primary AK")?
        .key_handle;

    info!("✓ successfully loaded GCP pre-provisioned AK (handle: {:?})", ak_handle);

    Ok((context, ak_handle))
}

/// Read data from TPM NV index
#[cfg(feature = "gcp-vtpm")]
fn read_nv_data(context: &mut TssContext, nv_index: u32) -> Result<Vec<u8>> {
    use tss_esapi::abstraction::nv;

    // Create NV index TPM handle
    let nv_idx = NvIndexTpmHandle::new(nv_index)
        .context("invalid NV index")?;

    // Get NV index handle from TPM
    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context
        .execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(nv_auth_handle)
                .map(|v| NvAuth::NvIndex(v.into()))
        })
        .context("failed to get NV index handle")?;

    // Read NV data with null auth session
    let data = context
        .execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))
        .context("failed to read NV data")?;

    Ok(data.to_vec())
}
