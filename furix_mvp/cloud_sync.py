# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CLOUD ↔ APPLIANCE BRIDGE — pull a signed bundle, load the baseline graph   ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : The appliance side of the walking-skeleton flow. Furix Cloud extracts a
#        tenant subgraph from its master knowledge graph (CIS/HIPAA/MITRE + the
#        tenant's assets), serializes it into a SIGNED BUNDLE, and serves it. This
#        module PULLS that bundle (HTTP, C4 intel-sync style), VERIFIES it, and
#        LOADS it as the appliance's baseline graph ("Learned Abstraction") that
#        the SIEM/SCAN engines later ground their findings to.
# WHY  : One integration point between the two systems — the bundle. Everything
#        downstream (graph-grounded findings, correlation) hangs off this baseline.
# CONTRACT: see docs/BUNDLE-CONTRACT.md. A bundle is one JSON object:
#        { "manifest": {...}, "graph": { "nodes": [...], "edges": [...] } }.
# WALKING SKELETON: signature verification is STUBBED (the Cloud signs for real
#        later); we DO verify the graph hash. A bundle that fails the hash still
#        loads but is flagged unverified — so the bridge is demoable end to end now.
from __future__ import annotations
import hashlib
import json
import os
import threading
import time
import urllib.request

from .containers import c12_operations as ops

CLOUD_BUNDLE_URL = os.environ.get("CLOUD_BUNDLE_URL", "").strip()   # e.g. http://furix-cloud:9000

_LOCK = threading.Lock()
_STATE: dict = {
    "loaded": False, "verified": False, "source": None,
    "bundle_id": None, "tenant_id": None, "version": None, "schema_version": None,
    "frameworks": [], "node_count": 0, "edge_count": 0,
    "node_types": {}, "edge_rels": {}, "loaded_at": None, "error": None,
    "_nodes": {},   # id -> node (kept out of status payload)
    "_edges": [],
}


def _sha256_graph(graph: dict) -> str:
    """Canonical hash of the graph payload — MUST match how the Cloud computes the
    manifest's graph_sha256 (sorted keys, compact separators). See BUNDLE-CONTRACT."""
    return hashlib.sha256(
        json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_bundle(bundle: dict, source: str) -> dict:
    """Verify + load a bundle as the baseline graph. Returns status()."""
    manifest = bundle.get("manifest") or {}
    graph = bundle.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    # 1. Integrity: recompute the graph hash and compare to the manifest.
    digest = _sha256_graph(graph)
    expected = manifest.get("graph_sha256")
    hash_ok = bool(expected) and digest == expected
    # 2. Signature: STUBBED for the walking skeleton (Cloud signs for real later).
    sig = manifest.get("signature")
    sig_ok = sig in (None, "", "STUB", "STUBBED")
    verified = hash_ok and sig_ok

    node_index = {n.get("id"): n for n in nodes if isinstance(n, dict) and n.get("id")}
    node_types: dict = {}
    for n in node_index.values():
        t = n.get("type", "unknown"); node_types[t] = node_types.get(t, 0) + 1
    edge_rels: dict = {}
    for e in edges:
        r = (e or {}).get("rel", "rel"); edge_rels[r] = edge_rels.get(r, 0) + 1

    err = None
    if not expected:
        err = "no graph_sha256 in manifest (unsigned/unverified sample)"
    elif not hash_ok:
        err = "graph hash MISMATCH — loaded anyway (walking skeleton)"

    with _LOCK:
        _STATE.update({
            "loaded": True, "verified": verified, "source": source,
            "bundle_id": manifest.get("bundle_id"), "tenant_id": manifest.get("tenant_id"),
            "version": manifest.get("version"), "schema_version": manifest.get("schema_version"),
            "frameworks": manifest.get("frameworks", []),
            "node_count": len(node_index), "edge_count": len(edges),
            "node_types": node_types, "edge_rels": edge_rels,
            "loaded_at": time.time(), "error": err,
            "_nodes": node_index, "_edges": edges,
        })
    ops.incr("baseline_bundle_loads_total")
    return status()


def sync_from_cloud(url: str | None = None) -> dict:
    """HTTP-pull the latest bundle from Furix Cloud and load it (C4 intel-sync style).
    The Cloud serves it at GET {CLOUD_BUNDLE_URL}/bundle/latest."""
    base = (url or CLOUD_BUNDLE_URL or "").rstrip("/")
    if not base:
        raise ValueError("CLOUD_BUNDLE_URL is not set — configure the Cloud endpoint "
                         "(env CLOUD_BUNDLE_URL) or load the local sample bundle instead")
    endpoint = f"{base}/bundle/latest"
    req = urllib.request.Request(endpoint, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:        # noqa: S310 (configured URL)
        bundle = json.loads(r.read().decode())
    return load_bundle(bundle, source=f"cloud:{endpoint}")


def load_local(path: str) -> dict:
    """Load a bundle from a file on the appliance (testing / air-gap drop / sample)."""
    if not os.path.isfile(path):
        raise ValueError(f"bundle file not found on appliance: {path}")
    with open(path, encoding="utf-8") as f:
        bundle = json.load(f)
    return load_bundle(bundle, source=f"file:{os.path.basename(path)}")


def status() -> dict:
    """Public baseline status (without the full node/edge payload)."""
    with _LOCK:
        s = {k: v for k, v in _STATE.items() if not k.startswith("_")}
        s["sample_nodes"] = list(_STATE["_nodes"].values())[:10]
        s["sample_edges"] = _STATE["_edges"][:10]
        s["cloud_url"] = CLOUD_BUNDLE_URL or None
    return s


def get_node(node_id: str):
    """Look up a baseline node by id — used later to GROUND findings to the graph."""
    with _LOCK:
        return _STATE["_nodes"].get(node_id)
