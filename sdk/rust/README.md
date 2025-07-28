# Dstack Rust SDK

This crate provides a Rust client for communicating with dstack services. It supports both legacy (0.3.x) and current (0.5.x) API versions, allowing seamless usage regardless of your dstack deployment version.

## Installation

```toml
[dependencies]
dstack-rust = { git = "https://github.com/Dstack-TEE/dstack.git", package = "dstack-rust" }
```

## Basic Usage

```rust
use dstack_sdk::{DstackClient, ApiVersion};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Auto-detect API version (recommended)
    let client = DstackClient::new(None);
    
    // Or specify explicit version if needed
    // let client = DstackClient::new_with_version(None, ApiVersion::V05x);

    // Get system info
    let info = client.info().await?;
    println!("Instance ID: {}", info.instance_id);
    println!("Using API version: {:?}", client.api_version());

    // Derive a key
    let key_resp = client.get_key(Some("my-app".to_string()), None).await?;
    println!("Key: {}", key_resp.key);
    println!("Signature Chain: {:?}", key_resp.signature_chain);

    // Generate TDX quote
    let quote_resp = client.get_quote(b"test-data".to_vec()).await?;
    println!("Quote: {}", quote_resp.quote);
    let rtmrs = quote_resp.replay_rtmrs()?;
    println!("Replayed RTMRs: {:?}", rtmrs);

    // Emit an event (only available in v0.5.x)
    if client.supports_emit_event() {
        client.emit_event("BootComplete".to_string(), b"payload-data".to_vec()).await?;
    } else {
        println!("EmitEvent not supported in this API version");
    }

    Ok(())
}
```

## API Version Compatibility

This SDK automatically handles differences between dstack API versions:

### Version Detection
- **Automatic**: The client detects API version based on socket paths and endpoint patterns
- **Manual**: You can explicitly specify the version using `new_with_version()`
- **Runtime detection**: Use `DstackClient::detect_version()` to probe the service

### Supported Versions
- **0.3.x (Legacy)**: Uses `/var/run/tappd.sock` socket and `/prpc/Tappd.*` endpoints
- **0.5.x (Current)**: Uses `/var/run/dstack.sock` socket and direct REST endpoints

### Version Differences
| Feature | 0.3.x | 0.5.x | Notes |
|---------|-------|-------|-------|
| get_key | ✅ | ✅ | Response field names differ but are normalized |
| get_quote | ✅ | ✅ | Parameter handling differs internally |
| info | ✅ | ✅ | Consistent across versions |
| get_tls_key | ✅ | ✅ | Different endpoint mapping |
| emit_event | ❌ | ✅ | Returns error with helpful message in 0.3.x |

## Features
### Initialization

```rust
// Auto-detect version (recommended)
let client = DstackClient::new(None);

// Specify endpoint and version
let client = DstackClient::new_with_version(Some("/var/run/tappd.sock"), ApiVersion::V03x);

// HTTP endpoint
let client = DstackClient::new(Some("http://localhost:8000"));
```

- `endpoint`: Optional HTTP URL or Unix socket path (auto-detects appropriate default)
- Will use the `DSTACK_SIMULATOR_ENDPOINT` environment variable if set
- Automatically detects API version from endpoint patterns

## Methods

### `info(): InfoResponse`

Fetches metadata and measurements about the CVM instance.

### `get_key(path: Option<String>, purpose: Option<String>) -> GetKeyResponse`

Derives a key for a specified path and optional purpose.

- `key`: Private key in hex format

- `signature_chain`: Vec of X.509 certificate chain entries

### `get_quote(report_data: Vec<u8>) -> GetQuoteResponse`

Generates a TDX quote with a custom 64-byte payload.

- `quote`: Hex-encoded quote

- `event_log`: Serialized list of events

- `replay_rtmrs()`: Reconstructs RTMR values from the event log

### `emit_event(event: String, payload: Vec<u8>)`
Sends an event log with associated binary payload to the runtime.

### `get_tls_key(...) -> GetTlsKeyResponse`
Requests a key and X.509 certificate chain for RA-TLS or server/client authentication.

### Structures
- `GetKeyResponse`: Holds derived key and signature chain

- `GetQuoteResponse`: Contains the TDX quote and event log, with RTMR replay support

- `InfoResponse`: CVM instance metadata, including image and runtime measurements

## API Reference

### Running the Simulator

For local development without TDX devices, you can use the simulator under `sdk/simulator`.

Run the simulator with:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```
Set the endpoint in your environment:

```
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8000
```

## License

Apache License
