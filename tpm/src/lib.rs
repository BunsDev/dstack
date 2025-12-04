// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 library using tss-esapi
//!
//! This module provides a clean Rust API for TPM 2.0 operations using the
//! tss-esapi library (TPM2 Software Stack Enhanced System API).
//! It handles PCR operations, sealing, unsealing, NV storage, and attestation.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use std::path::Path;
use tracing::{info, warn};

mod esapi_impl;
use esapi_impl::EsapiContext;

/// Primary key handle for sealing operations
pub const PRIMARY_KEY_HANDLE: u32 = 0x81000100;
/// NV index for sealed root key storage
pub const SEALED_NV_INDEX: u32 = 0x01801101;
/// App identity PCR number
pub const APP_PCR: u32 = 14;

/// Default PCR selection for dstack (boot chain PCR 0-9 + app PCR 14)
pub fn default_pcr_policy() -> PcrSelection {
    PcrSelection::sha256(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, APP_PCR])
}

/// Structured TPM quote containing all verification materials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// TPM quote message (TPMS_ATTEST structure)
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,
    /// Quote signature by Attestation Key
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// PCR values at the time of quote generation
    pub pcr_values: Vec<PcrValue>,
    /// Qualifying data (nonce) used in the quote
    #[serde(with = "hex_bytes")]
    pub qualifying_data: Vec<u8>,
    /// Attestation Key (AK) certificate (DER format)
    /// On GCP, this is stored in TPM NV index 0x01C10000 (RSA) or 0x01C10002 (ECC)
    /// and is signed by Google Private CA (GCE Intermediate CA)
    #[serde(with = "hex_bytes")]
    pub ak_cert: Vec<u8>,
}

/// Quote collateral - certificates and CRLs required for verification
///
/// Following dcap-qvl architecture, this structure contains all the external
/// data needed to verify a TPM quote certificate chain.
///
/// # Architecture (dcap-qvl pattern)
/// - **Step 1**: `get_collateral()` - Extract cert chain and download CRLs (if CRL DP present)
/// - **Step 2**: `verify_quote()` - Verify quote with collateral (CRL verification is conditional)
///
/// # Certificate Chain
/// The TPM AK certificate chain follows this structure:
/// - **Leaf cert**: AK (Attestation Key) certificate from TPM
/// - **Cert chain**: Intermediate CA(s) + Root CA (PEM format, concatenated)
/// - **CRLs**: Certificate Revocation Lists for all certs (DER format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteCollateral {
    /// Certificate chain in PEM format (intermediate CA(s) + root CA concatenated)
    /// This serves as the trust anchor for verification
    pub cert_chain_pem: String,
    /// Certificate Revocation Lists in DER format (conditional)
    /// Order: CRLs for certificates that have CRL Distribution Points
    /// CRL verification is enforced only for certs that provide CRL DP
    pub crls: Vec<Vec<u8>>,
}

/// PCR value for a specific PCR register
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR index
    pub index: u32,
    /// Hash algorithm (e.g., "sha256")
    pub algorithm: String,
    /// PCR value (hash)
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

/// TPM context for managing a connection to a TPM device
pub struct TpmContext {
    tcti: String,
}

impl std::fmt::Debug for TpmContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmContext")
            .field("tcti", &self.tcti)
            .finish()
    }
}

/// PCR (Platform Configuration Register) selection for policy binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSelection {
    pub bank: String,
    pub pcrs: Vec<u32>,
}

impl PcrSelection {
    pub fn new(bank: &str, pcrs: &[u32]) -> Self {
        Self {
            bank: bank.to_string(),
            pcrs: pcrs.to_vec(),
        }
    }

    pub fn sha256(pcrs: &[u32]) -> Self {
        Self::new("sha256", pcrs)
    }

    pub fn to_arg(&self) -> String {
        let pcr_list: Vec<String> = self.pcrs.iter().map(|p| p.to_string()).collect();
        format!("{}:{}", self.bank, pcr_list.join(","))
    }
}

impl Default for PcrSelection {
    fn default() -> Self {
        Self::sha256(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    }
}

/// Sealed data blob containing public and private parts
#[derive(Debug, Clone)]
pub struct SealedBlob {
    pub data: Vec<u8>,
}

impl SealedBlob {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_parts(pub_data: &[u8], priv_data: &[u8]) -> Self {
        let mut data = Vec::with_capacity(pub_data.len() + priv_data.len());
        data.extend_from_slice(pub_data);
        data.extend_from_slice(priv_data);
        Self { data }
    }

    pub fn split(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.data.len() < 4 {
            bail!("sealed blob too small");
        }

        let pub_size = u16::from_be_bytes([self.data[0], self.data[1]]) as usize;
        if self.data.len() < 2 + pub_size + 2 {
            bail!("sealed blob truncated at pub");
        }

        let priv_offset = 2 + pub_size;
        let priv_size =
            u16::from_be_bytes([self.data[priv_offset], self.data[priv_offset + 1]]) as usize;
        if self.data.len() < priv_offset + 2 + priv_size {
            bail!("sealed blob truncated at priv");
        }

        let pub_data = self.data[..2 + pub_size].to_vec();
        let priv_data = self.data[priv_offset..priv_offset + 2 + priv_size].to_vec();

        Ok((pub_data, priv_data))
    }
}

impl TpmContext {
    /// Open a TPM context with optional TCTI string (auto-detect if None)
    pub fn open(tcti: Option<&str>) -> Result<Self> {
        match tcti {
            Some(t) => Self::new(t),
            None => Self::detect(),
        }
    }

    /// Detect and connect to an available TPM device
    pub fn detect() -> Result<Self> {
        let tcti = if Path::new("/dev/tpmrm0").exists() {
            "/dev/tpmrm0"
        } else if Path::new("/dev/tpm0").exists() {
            "/dev/tpm0"
        } else {
            bail!("TPM device not found");
        };
        Self::new(tcti)
    }

    /// Create a new TPM context with a specific TCTI string
    pub fn new(tcti: &str) -> Result<Self> {
        Ok(Self {
            tcti: tcti.to_string(),
        })
    }

    fn create_esapi_context(&self) -> Result<EsapiContext> {
        EsapiContext::new(Some(&self.tcti))
    }

    // ==================== NV Operations ====================

    /// Check if an NV index exists
    pub fn nv_exists(&self, index: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_exists(index)
    }

    /// Define a new NV index
    pub fn nv_define(&self, index: u32, size: usize, _attributes: &str) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_define(index, size, true) // owner read/write
    }

    /// Undefine (delete) an NV index
    pub fn nv_undefine(&self, index: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_undefine(index)
    }

    /// Read data from an NV index
    pub fn nv_read(&self, index: u32) -> Result<Option<Vec<u8>>> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_read(index)
    }

    /// Write data to an NV index
    pub fn nv_write(&self, index: u32, data: &[u8]) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_write(index, data)
    }

    // ==================== Handle Operations ====================

    /// Check if a handle (persistent or transient) exists
    pub fn handle_exists(&self, handle: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.handle_exists(handle)
    }

    /// Ensure a persistent primary key exists at the given handle
    pub fn ensure_primary_key(&self, handle: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.ensure_primary_key(handle)
    }

    // ==================== PCR Operations ====================

    /// Extend a PCR with a hash value
    pub fn pcr_extend(&self, pcr: u32, hash: &[u8], bank: &str) -> Result<()> {
        let mut ctx = self.create_esapi_context()?;
        ctx.pcr_extend(pcr, hash, bank)
    }

    /// Extend a PCR with a SHA256 hash
    pub fn pcr_extend_sha256(&self, pcr: u32, hash: &[u8; 32]) -> Result<()> {
        self.pcr_extend(pcr, hash, "sha256")
    }

    /// Dump PCR values to log for debugging
    pub fn dump_pcr_values(&self, selection: &PcrSelection) {
        match self.create_esapi_context().and_then(|mut ctx| ctx.pcr_read(selection)) {
            Ok(values) => {
                info!("PCR values ({}):", selection.to_arg());
                for pv in values {
                    info!("  PCR[{}] = {}", pv.index, hex::encode(&pv.value));
                }
            }
            Err(e) => {
                warn!("failed to read PCR values: {}", e);
            }
        }
    }

    // ==================== Random Number Generation ====================

    /// Generate random bytes using the TPM's hardware RNG
    pub fn get_random<const N: usize>(&self) -> Result<[u8; N]> {
        let mut ctx = self.create_esapi_context()?;
        ctx.get_random::<N>()
    }

    // ==================== High-Level Convenience Methods ====================

    /// Seal data and store in NV storage
    pub fn seal(
        &self,
        _data: &[u8],
        _nv_index: u32,
        _parent_handle: u32,
        _pcr_selection: &PcrSelection,
    ) -> Result<()> {
        // TODO: Implement sealing with tss-esapi
        bail!("sealing not yet implemented with tss-esapi")
    }

    /// Read and unseal data from NV storage
    pub fn unseal_to_vec(
        &self,
        _nv_index: u32,
        _parent_handle: u32,
        _pcr_selection: &PcrSelection,
    ) -> Result<Option<Vec<u8>>> {
        // TODO: Implement unsealing with tss-esapi
        bail!("unsealing not yet implemented with tss-esapi")
    }

    /// Read and unseal fixed-size data from NV storage
    pub fn unseal<const N: usize>(
        &self,
        _nv_index: u32,
        _parent_handle: u32,
        _pcr_selection: &PcrSelection,
    ) -> Result<Option<[u8; N]>> {
        // TODO: Implement unsealing with tss-esapi
        bail!("unsealing not yet implemented with tss-esapi")
    }

    // ==================== Quote Operations ====================

    /// Generate a TPM quote with the given qualifying data and PCR selection
    pub fn create_quote(
        &self,
        qualifying_data: &[u8],
        pcr_selection: &PcrSelection,
    ) -> Result<TpmQuote> {
        // Use GCP AK implementation
        gcp_ak::create_quote_with_gcp_ak(Some(&self.tcti), qualifying_data, pcr_selection)
    }

    /// Read the Attestation Key certificate from TPM NV
    ///
    /// On GCP vTPM, the AK certificate is stored in NV index:
    /// - 0x01C10000 (RSA AK cert)
    /// - 0x01C10002 (ECC AK cert)
    ///
    /// The AK certificate is signed by Google Private CA (GCE Intermediate CA)
    /// which establishes the trust chain: Google Root CA → GCE Intermediate CA → AK
    ///
    /// Returns None if not available (e.g., on non-GCP TPMs or hardware TPMs without pre-provisioning).
    pub fn read_ak_cert(&self) -> Result<Option<Vec<u8>>> {
        // GCP vTPM AK certificate NV indices (from go-tpm-tools)
        const AK_RSA_CERT_NV_INDEX: u32 = 0x01C10000;
        const AK_ECC_CERT_NV_INDEX: u32 = 0x01C10002;

        let mut ctx = self.create_esapi_context()?;

        if let Some(cert) = ctx.nv_read(AK_RSA_CERT_NV_INDEX)? {
            info!(
                "read AK certificate from NV index 0x{:08x} ({} bytes)",
                AK_RSA_CERT_NV_INDEX,
                cert.len()
            );
            return Ok(Some(cert));
        }

        if let Some(cert) = ctx.nv_read(AK_ECC_CERT_NV_INDEX)? {
            info!(
                "read AK certificate from NV index 0x{:08x} ({} bytes)",
                AK_ECC_CERT_NV_INDEX,
                cert.len()
            );
            return Ok(Some(cert));
        }

        warn!("AK certificate not found in TPM NV storage (expected on GCP vTPM)");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_selection_to_string() {
        let sel = PcrSelection::sha256(&[0, 1, 2, 7]);
        assert_eq!(sel.to_arg(), "sha256:0,1,2,7");
    }

    #[test]
    fn test_sealed_blob_split() {
        // Create a mock sealed blob: 2-byte pub_size + pub_data + 2-byte priv_size + priv_data
        let pub_data = vec![0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]; // size=5
        let priv_data = vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]; // size=3
        let mut blob_data = Vec::new();
        blob_data.extend_from_slice(&pub_data);
        blob_data.extend_from_slice(&priv_data);

        let blob = SealedBlob::new(blob_data);
        let (pub_part, priv_part) = blob.split().unwrap();

        assert_eq!(pub_part, pub_data);
        assert_eq!(priv_part, priv_data);
    }

    #[test]
    fn test_default_pcr_policy() {
        let policy = default_pcr_policy();
        assert_eq!(policy.to_arg(), "sha256:0,1,2,3,4,5,6,7,8,9,14");
    }
}

// ==================== Pure Rust Verification ====================

mod verify;
pub use verify::{verify_quote, VerificationResult};

#[cfg(feature = "crl-download")]
pub use verify::get_collateral;

// ==================== GCP vTPM Support ====================

mod gcp_ak;
pub use gcp_ak::{create_quote_with_gcp_ak, gcp_nv_index, load_gcp_ak_rsa};
