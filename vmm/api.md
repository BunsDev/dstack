API Reference – dstack‑vmm
===========================
This document describes the API of dstack-vmm. You need to set the `VMM_URL` environment variable to the base URL of the dstack-vmm server before following the examples.

Base URL (example):
```bash
export VMM_URL=http://localhost:12000
```

All endpoints expect a **`Content-Type: application/json`** header and return **JSON** bodies.
Failure status codes (4xx/5xx) also return a JSON object `{"code":int,"message":"…"}`.

You can look at [vmm_rpc.proto](rpc/proto/vmm_rpc.proto) for the full API specification.

---

1. Create a VM
----------------
**POST /prpc/CreateVm**

**Example**

```bash
cat > docker-compose.yml <<EOF
services:
  app:
    image: my-image
EOF

cat > app-compose.json << EOF
{
    "manifest_version": 2,
    "name": "dstack-example",
    "runner": "docker-compose",
    "docker_compose_file": $(jq -Rs . < docker-compose.yml),
    "kms_enabled": true,
    "gateway_enabled": true,
    "local_key_provider_enabled": false,
    "key_provider_id": "",
    "public_logs": true,
    "public_sysinfo": true,
    "allowed_envs": [],
    "no_instance_id": false,
    "secure_time": false
}
EOF

cat > request.json <<EOF
{
  "name":            "my-app",
  "image":           "dstack-0.5.2",
  "compose_file":    $(jq -Rs . app-compose.json),
  "vcpu":            2,
  "memory":          2048,
  "disk_size":       10,
  "ports": [
    { "protocol":"tcp","host_port":8080,"vm_port":80,"host_address":"0.0.0.0" }
  ],
  "encrypted_env":   "",
  "app_id":          "",
  "user_config":     "{}",
  "hugepages":       false,
  "pin_numa":        false,
  "gpus": {
    "gpus": [ { "slot": "65:00.0" } ],
    "attach_mode": "listed"
  }
}
EOF

curl -sS -X POST "$VMM_URL/prpc/CreateVm" \
     -H "Content-Type: application/json" \
     -d @request.json
```

Returns `200 OK`

```
{ "id": "63f3177b-bae6-..." }
```

---

2. Start / Stop / Shutdown / Remove a VM
----------------------------------------

| Action        | Method | Path                    | Body               |
|---------------|--------|-------------------------|--------------------|
| **StartVm**   | POST   | /prpc/StartVm           | `{ "id": "<vm-id>" }` |
| **StopVm**    | POST   | /prpc/StopVm            | `{ "id": "<vm-id>" }` |
| **ShutdownVm**| POST   | /prpc/ShutdownVm        | `{ "id": "<vm-id>" }` |
| **RemoveVm**  | POST   | /prpc/RemoveVm          | `{ "id": "<vm-id>" }` |

Example: restart silently

```bash
curl -sS -X POST "$VMM_URL/prpc/ShutdownVm" \
     -H "Content-Type: application/json" \
     -d '{"id":"63f3177b-bae6-..."}'
```

All these endpoints return `204 No Content` on success.

---

3. Upgrade App
----------------
**POST /prpc/UpgradeApp**

Example:

```bash
cat > request.json <<EOF
{
  "id":           "<vm-id>",
  "compose_file": "<JSON-escaped new-compose.yml>",
  "encrypted_env": "...",          // empty = keep previous
  "user_config": "{}",             // empty = keep previous
  "update_ports": true,            // optional
  "ports": [ { ... } ],           // only if update_ports=true
  "gpus": { ... }                 // optional GPU override
}
EOF
curl -sS -X POST "$VMM_URL/prpc/UpgradeApp" \
     -H "Content-Type: application/json" \
     -d @request.json
```

Returns `200 OK` with

```
{ "id": "<vm-id>" }
```

---

4. Resize VM
--------------
**POST /prpc/ResizeVm**

```
{
  "id":        "<vm-id>",
  "vcpu":      4,
  "memory":    4096,
  "disk_size": 20,
  "image":     "dstack-0.5.2"
}
```

(All fields optional except `id`; omitted values keep current.)

Example:

```bash
curl -sS -X POST "$VMM_URL/prpc/ResizeVm" \
     -H "Content-Type: application/json" \
     -d '{"id":"63f3177b-bae6-...","vcpu":4,"memory":4096}'
```

Returns `204 No Content`.

---

5. List VMs
-------------
**POST /prpc/Status**
Payload (all optional):

```
{
  "ids": [],           // list vm-ids to filter
  "brief": true,       // skip full configurations
  "keyword": "my-app",
  "page": 0,
  "page_size": 100
}
```

Example:

```bash
curl -sS -X POST "$VMM_URL/prpc/Status" \
     -H "Content-Type: application/json" \
     -d '{"keyword":"dstack-attestation-example"}' | jq .
```

Response includes `"vms"` array and `"total"` count.

---

6. Get single VM info
----------------------
**GET /prpc/GetInfo?id=<vm-id>**

Example:

```bash
curl -sS "$VMM_URL/prpc/GetInfo?id=63f3177b-bae6-..."
```

---

7. List Available Images
--------------------------
**GET /prpc/ListImages**

Example:

```bash
curl -sS "$VMM_URL/prpc/ListImages" | jq '.images[]'
```

Response structure:

```
{
  "name": "dstack-0.5.2",
  "description": "Dstack base image",
  "version": "0.5.2",
  "is_dev": false
}
```

---

8. Fetch dstack-vmm build information
--------------------------------

**GET /prpc/Version**

```bash
curl -sS "$VMM_URL/prpc/Version"
```

Returns

```
{ "version": "0.6.0", "rev": "abc1234" }
```

---

9. Get Runtime Metadata
-----------------------
**GET /prpc/GetMeta**

Example:

```bash
curl -sS "$VMM_URL/prpc/GetMeta" | jq .
```

Reply includes KMS & Gateway URLs, max resource limits, etc.

---

10. Retrieve Env Encryption Public Key
---------------------------------------

**POST /prpc/GetAppEnvEncryptPubKey**

Body:

```
{ "app_id": "<hex/app ID>" }   // base64 bytes
```

Example:

```bash
curl -sS -X POST "$VMM_URL/prpc/GetAppEnvEncryptPubKey" \
     -H "Content-Type: application/json" \
     -d '{"app_id":"exL2fciTM6n..."}'
```

---

11. List GPUs
---------------
**GET /prpc/ListGpus**

```bash
curl -sS "$VMM_URL/prpc/ListGpus" | jq '.gpus'
```

Returns slot, product ID, description, free/busy flag and `allow_attach_all`.

---
