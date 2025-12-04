//! Test GCP vTPM pre-provisioned AK loading
//!
//! This example demonstrates loading GCP's pre-provisioned Attestation Key
//! using the native Rust tss-esapi implementation.
//!
//! Usage:
//!   cargo run --example gcp_ak_test --features gcp-vtpm

#[cfg(feature = "gcp-vtpm")]
fn main() -> anyhow::Result<()> {
    println!("=== GCP vTPM Pre-provisioned AK Loading Test ===\n");

    // Load GCP pre-provisioned RSA AK
    println!("Loading GCP pre-provisioned RSA AK...");
    let (mut context, ak_handle) = dstack_tpm::load_gcp_ak_rsa(None)?;

    println!("✓ Successfully loaded GCP pre-provisioned AK!");
    println!("  AK handle: {:?}", ak_handle);

    // Read AK public key
    println!("\nReading AK public key...");
    let (ak_public, _, _) = context.read_public(ak_handle)?;
    println!("✓ AK public key:");
    println!("  Type: {:?}", ak_public.object_attributes());

    // Read AK certificate from NV
    println!("\nReading AK certificate from NV index 0x01C10000...");
    use tss_esapi::abstraction::nv;
    use tss_esapi::handles::{NvIndexTpmHandle, TpmHandle};
    use tss_esapi::interface_types::resource_handles::NvAuth;

    let nv_idx = NvIndexTpmHandle::new(dstack_tpm::gcp_nv_index::AK_RSA_CERT)?;
    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(nv_auth_handle)
            .map(|v| NvAuth::NvIndex(v.into()))
    })?;

    let cert_der = context.execute_with_nullauth_session(|ctx| {
        nv::read_full(ctx, nv_auth_handle, nv_idx)
    })?;

    println!("✓ Read AK certificate: {} bytes", cert_der.len());

    // Parse and display certificate info
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|e| anyhow::anyhow!("failed to parse certificate: {}", e))?;

    println!("\n=== AK Certificate Info ===");
    println!("Subject: {}", cert.subject());
    println!("Issuer: {}", cert.issuer());
    println!("Serial: {}", cert.raw_serial_as_string());
    println!("Valid from: {} to {}",
        cert.validity().not_before,
        cert.validity().not_after);

    println!("\n=== Test Passed ===");

    Ok(())
}

#[cfg(not(feature = "gcp-vtpm"))]
fn main() {
    eprintln!("This example requires the 'gcp-vtpm' feature.");
    eprintln!("Run with: cargo run --example gcp_ak_test --features gcp-vtpm");
    std::process::exit(1);
}
