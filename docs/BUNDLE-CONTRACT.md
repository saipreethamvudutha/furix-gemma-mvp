# Furix Cloud ↔ Appliance — Bundle Contract (v1.0)

> The single integration point between **Furix Cloud** (emitter) and the **customer
> appliance** (the MVP, receiver). The Cloud extracts a tenant subgraph from its
> master knowledge graph, serializes it into a **signed bundle**, and serves it.
> The appliance **pulls** the bundle, **verifies** it, and **loads** it as the
> baseline graph that the SIEM/SCAN engines ground their findings to.
>
> This document is the spec the **Cloud (Go) emitter** must produce against. The
> **appliance (Python) receiver** is already implemented in `furix_mvp/cloud_sync.py`.

---

## 1. Transport — HTTP pull (chosen)

The appliance polls the Cloud (C4 intel-sync style). The Cloud exposes:

```
GET  {CLOUD_BUNDLE_URL}/bundle/latest      → 200, body = the Bundle JSON (below)
```

- `CLOUD_BUNDLE_URL` is set on the appliance via env (e.g. `http://furix-cloud:9000`).
- Response `Content-Type: application/json`, body is **one Bundle object**.
- (Optional later: `GET /bundle/manifest` for a cheap freshness check before download,
  and `If-None-Match`/`ETag` so the appliance skips unchanged bundles.)

The appliance trigger today is manual (`POST /api/bundle/sync`) or on a schedule;
the air-gap "file drop" variant just points `load_local()` at a dropped file.

---

## 2. Bundle format

A bundle is **one JSON object** with two keys:

```jsonc
{
  "manifest": { ... },        // metadata + integrity + signature
  "graph":    { "nodes": [...], "edges": [...] }   // the payload
}
```

### 2.1 `manifest`

| Field | Type | Notes |
|---|---|---|
| `bundle_id` | string | Unique id for this bundle, e.g. `bundle-exargen-2026-06-28` |
| `tenant_id` | string | Tenant slug, e.g. `exargen` |
| `version` | string | Monotonic version, e.g. `2026.06.28-1` |
| `schema_version` | string | Contract version, currently `"1.0"` |
| `created_at` | string | ISO-8601 UTC |
| `frameworks` | string[] | Frameworks in the graph, e.g. `["CIS","NIST","HIPAA","MITRE"]` |
| `node_count` | int | Convenience count |
| `edge_count` | int | Convenience count |
| `graph_sha256` | string | **REQUIRED.** Hex SHA-256 of the canonical graph (see §3) |
| `signature` | string | Detached signature over the manifest. **Stubbed** (`"STUB"`) in the walking skeleton; Ed25519 later (see §4) |

### 2.2 `graph.nodes[]`

| Field | Type | Notes |
|---|---|---|
| `id` | string | **REQUIRED, unique.** Stable id used to GROUND findings (see §5) |
| `type` | string | `control` \| `technique` \| `host` \| `firewall` \| `user` \| `subnet` \| … |
| `label` | string | Human label |
| `framework` | string | For control/technique nodes: `CIS`/`NIST`/`HIPAA`/`MITRE` |
| `props` | object | Optional free-form (os, role, dept, …) |

### 2.3 `graph.edges[]`

| Field | Type | Notes |
|---|---|---|
| `src` | string | Source node `id` |
| `dst` | string | Destination node `id` |
| `rel` | string | `maps_to` (crosswalk) \| `mitigated_by` \| `uses` \| `in_subnet` \| `protects` \| … |
| `props` | object | Optional |

See `deploy/sample-bundle.json` for a complete, verifying example.

---

## 3. Integrity — `graph_sha256` (REQUIRED to match)

The appliance recomputes the hash and compares it to `manifest.graph_sha256`.
**The Cloud MUST compute it identically:**

```
graph_sha256 = hex( SHA256( JSON(graph, sorted_keys=true, separators=(",",":")) ) )
```

i.e. canonical JSON of the **`graph` object only** — keys sorted recursively, no
whitespace (compact separators), UTF-8. (Python reference: `json.dumps(graph,
sort_keys=True, separators=(",",":"))`. Go: marshal with sorted map keys / a
canonical-JSON encoder.)

A mismatch is currently **loaded but flagged `unverified`** (walking skeleton). It
will become a hard reject once the Cloud emits real hashes.

---

## 4. Signature (stubbed now → Ed25519 later)

Walking skeleton: `manifest.signature = "STUB"` and the appliance treats it as OK.

Production target: a detached **Ed25519** signature over the canonical manifest
(with `signature` removed/blanked), verified against a Cloud public key pinned on
the appliance. The air-gap boundary means **only the signed bundle crosses** —
nothing else.

---

## 5. Grounding contract (how findings attach to the baseline)

Once loaded, the appliance grounds findings to baseline nodes by `id`. Convention:

- host → `host-<HOSTNAME>` (e.g. `host-WS-SYS-000`)
- user → `user-<USERNAME>`
- subnet → `subnet-<CIDR with / as _>`
- control → `cis-<n>` / `nist-<id>` / `hipaa-<id>`
- technique → `mitre-<TID>` (e.g. `mitre-T1078.004`)

The appliance's `cloud_sync.get_node(id)` resolves these. SIEM/SCAN engines set a
`grounded_node_id` on findings that matches a baseline node — that is what turns
isolated events into graph-anchored, correlatable findings.

---

## 6. Appliance endpoints (already built)

| Endpoint | Purpose |
|---|---|
| `GET  /api/bundle/status` | Current baseline: loaded?, verified?, counts, tenant, version, sample nodes/edges |
| `POST /api/bundle/sync` | HTTP-pull `{CLOUD_BUNDLE_URL}/bundle/latest`, verify, load |
| `POST /api/bundle/load-sample` | Load the bundled `deploy/sample-bundle.json` (pre-Cloud demo) |

Dashboard: the **☁️ Baseline (Cloud)** tab drives these and shows the loaded graph.

---

## 7. What the Cloud team needs to deliver

1. `GET /bundle/latest` returning a Bundle that conforms to §2.
2. `graph_sha256` computed per §3 (must match).
3. `signature: "STUB"` for now (§4).
4. Node `id`s following §5 so grounding works.

That's the whole contract. Anything conforming will load on the appliance today.
