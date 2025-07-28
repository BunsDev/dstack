use anyhow::Result;
use hex::{encode as hex_encode, FromHexError};
use http_client_unix_domain_socket::{ClientUnix, Method};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::env;

const INIT_MR: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn replay_rtmr(history: Vec<String>) -> Result<String, FromHexError> {
    if history.is_empty() {
        return Ok(INIT_MR.to_string());
    }
    let mut mr = hex::decode(INIT_MR)?;
    for content in history {
        let mut content_bytes = hex::decode(content)?;
        if content_bytes.len() < 48 {
            content_bytes.resize(48, 0);
        }
        mr.extend_from_slice(&content_bytes);
        mr = sha2::Sha384::digest(&mr).to_vec();
    }
    Ok(hex_encode(mr))
}

fn get_endpoint(endpoint: Option<&str>) -> String {
    if let Some(e) = endpoint {
        return e.to_string();
    }
    if let Ok(sim_endpoint) = env::var("DSTACK_SIMULATOR_ENDPOINT") {
        return sim_endpoint;
    }
    "/var/run/dstack.sock".to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApiVersion {
    V03x, // Legacy Tappd API (0.3.x)
    V05x, // Current API (0.5.x)
}

impl ApiVersion {
    fn detect_from_endpoint(endpoint: &str) -> Self {
        // If endpoint mentions tappd, it's likely the legacy version
        if endpoint.contains("tappd") {
            return ApiVersion::V03x;
        }
        
        // Check for legacy socket path
        if endpoint == "/var/run/tappd.sock" {
            return ApiVersion::V03x;
        }
        
        // Default to current version for new socket path or HTTP endpoints
        ApiVersion::V05x
    }
    
    fn get_socket_path(&self) -> &'static str {
        match self {
            ApiVersion::V03x => "/var/run/tappd.sock",
            ApiVersion::V05x => "/var/run/dstack.sock",
        }
    }
}

#[derive(Debug)]
pub enum ClientKind {
    Http,
    Unix,
}

/// Represents an event log entry in the system
#[derive(Serialize, Deserialize)]
pub struct EventLog {
    /// The index of the IMR (Integrity Measurement Register)
    pub imr: u32,
    /// The type of event being logged
    pub event_type: u32,
    /// The cryptographic digest of the event
    pub digest: String,
    /// The type of event as a string
    pub event: String,
    /// The payload data associated with the event
    pub event_payload: String,
}

/// Configuration for TLS key generation
#[derive(bon::Builder, Serialize)]
pub struct TlsKeyConfig {
    /// The subject name for the certificate
    #[builder(into, default = String::new())]
    pub subject: String,
    /// Alternative names for the certificate
    #[builder(default = Vec::new())]
    pub alt_names: Vec<String>,
    /// Whether the key should be used for remote attestation TLS
    #[builder(default = false)]
    pub usage_ra_tls: bool,
    /// Whether the key should be used for server authentication
    #[builder(default = true)]
    pub usage_server_auth: bool,
    /// Whether the key should be used for client authentication
    #[builder(default = false)]
    pub usage_client_auth: bool,
}

/// Response containing a key and its signature chain
#[derive(Serialize, Deserialize)]
pub struct GetKeyResponse {
    /// The key in hexadecimal format
    pub key: String,
    /// The chain of signatures verifying the key
    pub signature_chain: Vec<String>,
}

/// Legacy response structure for the 0.3.x API
#[derive(Serialize, Deserialize)]
pub struct LegacyGetKeyResponse {
    /// The key in hexadecimal format (legacy field name)
    pub k256_key: String,
    /// The chain of signatures verifying the key (legacy field name)
    pub k256_signature_chain: Vec<String>,
}

impl From<LegacyGetKeyResponse> for GetKeyResponse {
    fn from(legacy: LegacyGetKeyResponse) -> Self {
        GetKeyResponse {
            key: legacy.k256_key,
            signature_chain: legacy.k256_signature_chain,
        }
    }
}

impl GetKeyResponse {
    pub fn decode_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.key)
    }

    pub fn decode_signature_chain(&self) -> Result<Vec<Vec<u8>>, FromHexError> {
        self.signature_chain.iter().map(hex::decode).collect()
    }
}

/// Response containing a quote and associated event log
#[derive(Serialize, Deserialize, Debug)]
pub struct GetQuoteResponse {
    /// The attestation quote in hexadecimal format
    pub quote: String,
    /// The event log associated with the quote
    pub event_log: String,
}

impl GetQuoteResponse {
    pub fn decode_quote(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.quote)
    }

    pub fn decode_event_log(&self) -> Result<Vec<EventLog>, serde_json::Error> {
        serde_json::from_str(&self.event_log)
    }

    pub fn replay_rtmrs(&self) -> Result<HashMap<u8, String>> {
        let parsed_event_log: Vec<EventLog> = self.decode_event_log()?;
        let mut rtmrs = HashMap::new();
        for idx in 0..4 {
            let mut history = vec![];
            for event in &parsed_event_log {
                if event.imr == idx {
                    history.push(event.digest.clone());
                }
            }
            rtmrs.insert(idx as u8, replay_rtmr(history)?);
        }
        Ok(rtmrs)
    }
}

/// Response containing instance information and attestation data
#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    /// The application identifier
    pub app_id: String,
    /// The instance identifier
    pub instance_id: String,
    /// The application certificate
    pub app_cert: String,
    /// Trusted Computing Base information
    pub tcb_info: TcbInfo,
    /// The name of the application
    pub app_name: String,
    /// The device identifier
    pub device_id: String,
    /// The hash of the OS image
    /// Optional: empty if OS image is not measured by KMS
    #[serde(default)]
    pub os_image_hash: String,
    /// Information about the key provider
    pub key_provider_info: String,
    /// The hash of the compose configuration
    pub compose_hash: String,
}

impl InfoResponse {
    pub fn validated_from_value(mut obj: Value) -> Result<Self, serde_json::Error> {
        if let Some(tcb_info_str) = obj.get("tcb_info").and_then(Value::as_str) {
            let parsed_tcb_info: TcbInfo = from_str(tcb_info_str)?;
            obj["tcb_info"] = serde_json::to_value(parsed_tcb_info)?;
        }
        serde_json::from_value(obj)
    }
}

/// Trusted Computing Base information structure
#[derive(Serialize, Deserialize)]
pub struct TcbInfo {
    /// The measurement root of trust
    pub mrtd: String,
    /// The value of RTMR0 (Runtime Measurement Register 0)
    pub rtmr0: String,
    /// The value of RTMR1 (Runtime Measurement Register 1)
    pub rtmr1: String,
    /// The value of RTMR2 (Runtime Measurement Register 2)
    pub rtmr2: String,
    /// The value of RTMR3 (Runtime Measurement Register 3)
    pub rtmr3: String,
    /// The hash of the OS image. This is empty if the OS image is not measured by KMS.
    #[serde(default)]
    pub os_image_hash: String,
    /// The hash of the compose configuration
    pub compose_hash: String,
    /// The device identifier
    pub device_id: String,
    /// The app compose
    pub app_compose: String,
    /// The event log entries
    pub event_log: Vec<EventLog>,
}

/// Response containing TLS key and certificate chain
#[derive(Serialize, Deserialize)]
pub struct GetTlsKeyResponse {
    /// The TLS key in hexadecimal format
    pub key: String,
    /// The chain of certificates
    pub certificate_chain: Vec<String>,
}

pub trait BaseClient {}

/// The main client for interacting with the dstack service
pub struct DstackClient {
    /// The base URL for HTTP requests
    base_url: String,
    /// The endpoint for Unix domain socket communication
    endpoint: String,
    /// The type of client (HTTP or Unix domain socket)
    client: ClientKind,
    /// The API version being used
    api_version: ApiVersion,
}

impl BaseClient for DstackClient {}

impl DstackClient {
    /// Attempts to detect the API version by checking if the service responds to a simple request
    pub async fn detect_version(endpoint: Option<&str>) -> Result<ApiVersion> {
        // Try with 0.5.x API first (newer)
        let client_v5 = DstackClient::new_with_version(endpoint, ApiVersion::V05x);
        if client_v5.test_connection().await.is_ok() {
            return Ok(ApiVersion::V05x);
        }
        
        // Fall back to 0.3.x API
        let client_v3 = DstackClient::new_with_version(endpoint, ApiVersion::V03x);
        if client_v3.test_connection().await.is_ok() {
            return Ok(ApiVersion::V03x);
        }
        
        // If neither works, default to 0.5.x
        Ok(ApiVersion::V05x)
    }
    
    /// Test connection to the service
    async fn test_connection(&self) -> Result<()> {
        // Try to call info endpoint - it exists in both APIs
        self.info().await.map(|_| ())
    }
    
    /// Get the current API version being used
    pub fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }
    
    /// Check if a feature is supported in the current API version
    pub fn supports_emit_event(&self) -> bool {
        matches!(self.api_version, ApiVersion::V05x)
    }
    
    pub fn new(endpoint: Option<&str>) -> Self {
        let endpoint = get_endpoint(endpoint);
        let api_version = ApiVersion::detect_from_endpoint(&endpoint);
        
        // If no explicit endpoint provided, use the socket path based on detected/default version
        let final_endpoint = if endpoint == "/var/run/dstack.sock" && api_version == ApiVersion::V03x {
            api_version.get_socket_path().to_string()
        } else if endpoint.starts_with("/var/run/") && !endpoint.contains("http") {
            // For socket paths, ensure we use the correct one for the version
            api_version.get_socket_path().to_string()
        } else {
            endpoint
        };
        
        let (base_url, client) = match final_endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), ClientKind::Http)
            }
            _ => ("http://localhost".to_string(), ClientKind::Unix),
        };

        DstackClient {
            base_url,
            endpoint: final_endpoint,
            client,
            api_version,
        }
    }
    
    pub fn new_with_version(endpoint: Option<&str>, version: ApiVersion) -> Self {
        let endpoint = endpoint.map(|e| e.to_string()).unwrap_or_else(|| version.get_socket_path().to_string());
        
        let (base_url, client) = match endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), ClientKind::Http)
            }
            _ => ("http://localhost".to_string(), ClientKind::Unix),
        };

        DstackClient {
            base_url,
            endpoint,
            client,
            api_version: version,
        }
    }

    async fn send_rpc_request<S: Serialize, D: DeserializeOwned>(
        &self,
        path: &str,
        payload: &S,
    ) -> anyhow::Result<D> {
        match &self.client {
            ClientKind::Http => {
                let client = Client::new();
                let url = format!(
                    "{}/{}",
                    self.base_url.trim_end_matches('/'),
                    path.trim_start_matches('/')
                );
                let res = client
                    .post(&url)
                    .json(payload)
                    .header("Content-Type", "application/json")
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(res.json().await?)
            }
            ClientKind::Unix => {
                let mut unix_client = ClientUnix::try_new(&self.endpoint).await?;
                let res = unix_client
                    .send_request_json::<_, _, Value>(
                        path,
                        Method::POST,
                        &[("Content-Type", "application/json")],
                        Some(&payload),
                    )
                    .await?;
                Ok(res.1)
            }
        }
    }

    pub async fn get_key(
        &self,
        path: Option<String>,
        purpose: Option<String>,
    ) -> Result<GetKeyResponse> {
        match self.api_version {
            ApiVersion::V05x => {
                let data = json!({
                    "path": path.unwrap_or_default(),
                    "purpose": purpose.unwrap_or_default(),
                });
                let response = self.send_rpc_request("/GetKey", &data).await?;
                let response = serde_json::from_value::<GetKeyResponse>(response)?;
                Ok(response)
            },
            ApiVersion::V03x => {
                let data = json!({
                    "path": path.unwrap_or_default(),
                    "purpose": purpose.unwrap_or_default(),
                });
                let response = self.send_rpc_request("/prpc/Tappd.DeriveK256Key", &data).await?;
                let legacy_response = serde_json::from_value::<LegacyGetKeyResponse>(response)?;
                Ok(legacy_response.into())
            }
        }
    }

    pub async fn get_quote(&self, report_data: Vec<u8>) -> Result<GetQuoteResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            anyhow::bail!("Invalid report data length")
        }
        let hex_data = hex_encode(&report_data);
        
        match self.api_version {
            ApiVersion::V05x => {
                let data = json!({ "report_data": hex_data });
                let response = self.send_rpc_request("/GetQuote", &data).await?;
                let response = serde_json::from_value::<GetQuoteResponse>(response)?;
                Ok(response)
            },
            ApiVersion::V03x => {
                // For legacy API, use RawQuote if exactly 64 bytes, otherwise TdxQuote with raw hash
                let data = if report_data.len() == 64 {
                    json!({ "report_data": hex_data })
                } else {
                    json!({ 
                        "report_data": hex_data,
                        "hash_algorithm": "raw",
                        "prefix": ""
                    })
                };
                
                let endpoint = if report_data.len() == 64 {
                    "/prpc/Tappd.RawQuote"
                } else {
                    "/prpc/Tappd.TdxQuote"
                };
                
                let response = self.send_rpc_request(endpoint, &data).await?;
                let response = serde_json::from_value::<GetQuoteResponse>(response)?;
                Ok(response)
            }
        }
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let endpoint = match self.api_version {
            ApiVersion::V05x => "/Info",
            ApiVersion::V03x => "/prpc/Tappd.Info",
        };
        
        let response = self.send_rpc_request(endpoint, &json!({})).await?;
        Ok(InfoResponse::validated_from_value(response)?)
    }

    pub async fn emit_event(&self, event: String, payload: Vec<u8>) -> Result<()> {
        match self.api_version {
            ApiVersion::V05x => {
                if event.is_empty() {
                    anyhow::bail!("Event name cannot be empty")
                }
                let hex_payload = hex_encode(payload);
                let data = json!({ "event": event, "payload": hex_payload });
                self.send_rpc_request::<_, ()>("/EmitEvent", &data).await?;
                Ok(())
            },
            ApiVersion::V03x => {
                anyhow::bail!("EmitEvent is not supported in API version 0.3.x. Please upgrade to dstack 0.5.0 or later.")
            }
        }
    }

    pub async fn get_tls_key(&self, tls_key_config: TlsKeyConfig) -> Result<GetTlsKeyResponse> {
        match self.api_version {
            ApiVersion::V05x => {
                let response = self.send_rpc_request("/GetTlsKey", &tls_key_config).await?;
                let response = serde_json::from_value::<GetTlsKeyResponse>(response)?;
                Ok(response)
            },
            ApiVersion::V03x => {
                // For legacy API, we need to map to DeriveKey with additional fields
                let data = json!({
                    "path": "",  // Default empty path for TLS keys
                    "subject": tls_key_config.subject,
                    "alt_names": tls_key_config.alt_names,
                    "usage_ra_tls": tls_key_config.usage_ra_tls,
                    "usage_server_auth": tls_key_config.usage_server_auth,
                    "usage_client_auth": tls_key_config.usage_client_auth,
                    "random_seed": false
                });
                
                let response = self.send_rpc_request("/prpc/Tappd.DeriveKey", &data).await?;
                let response = serde_json::from_value::<GetTlsKeyResponse>(response)?;
                Ok(response)
            }
        }
    }
}
