#!/usr/bin/env python3
"""Build a VERIFIABLE sample Cloud bundle for the appliance bridge.

Furix Cloud will produce the real bundle from its master knowledge graph; this is
a stand-in so the appliance side (verify + load baseline) is demoable before the
Cloud is reachable. The graph_sha256 is computed the SAME way cloud_sync does, so
it verifies cleanly.  Run:  python scripts/make_sample_bundle.py
"""
import hashlib
import json
import os

# A small but representative baseline subgraph: compliance crosswalk (CIS→NIST→
# HIPAA) + MITRE techniques mitigated by controls + the tenant's asset reality.
GRAPH = {
    "nodes": [
        {"id": "cis-6",  "type": "control",   "framework": "CIS",   "label": "Control 6 — Access Control Management"},
        {"id": "cis-10", "type": "control",   "framework": "CIS",   "label": "Control 10 — Malware Defenses"},
        {"id": "nist-PR.AA-01", "type": "control", "framework": "NIST", "label": "PR.AA-01 — Identities & credentials"},
        {"id": "hipaa-164.312a", "type": "control", "framework": "HIPAA", "label": "164.312(a) — Access control"},
        {"id": "mitre-T1078.004", "type": "technique", "framework": "MITRE", "label": "T1078.004 Valid Accounts: Cloud"},
        {"id": "mitre-T1071.001", "type": "technique", "framework": "MITRE", "label": "T1071.001 C2: Web Protocols"},
        {"id": "host-WS-SYS-000", "type": "host", "label": "WS-SYS-000", "props": {"os": "Windows", "role": "workstation"}},
        {"id": "host-FW01", "type": "firewall", "label": "FW01", "props": {"vendor": "Palo Alto"}},
        {"id": "user-mwilliams72", "type": "user", "label": "mwilliams72", "props": {"dept": "finance"}},
        {"id": "subnet-10.2.0.0_16", "type": "subnet", "label": "10.2.0.0/16"},
    ],
    "edges": [
        {"src": "cis-6", "dst": "nist-PR.AA-01", "rel": "maps_to"},
        {"src": "nist-PR.AA-01", "dst": "hipaa-164.312a", "rel": "maps_to"},
        {"src": "mitre-T1078.004", "dst": "cis-6", "rel": "mitigated_by"},
        {"src": "mitre-T1071.001", "dst": "cis-10", "rel": "mitigated_by"},
        {"src": "user-mwilliams72", "dst": "host-WS-SYS-000", "rel": "uses"},
        {"src": "host-WS-SYS-000", "dst": "subnet-10.2.0.0_16", "rel": "in_subnet"},
        {"src": "host-FW01", "dst": "subnet-10.2.0.0_16", "rel": "protects"},
    ],
}


def sha256_graph(graph: dict) -> str:
    return hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main() -> None:
    bundle = {
        "manifest": {
            "bundle_id": "bundle-sample-0001",
            "tenant_id": "exargen",
            "version": "2026.06.28-1",
            "schema_version": "1.0",
            "created_at": "2026-06-28T00:00:00Z",
            "frameworks": ["CIS", "NIST", "HIPAA", "MITRE"],
            "node_count": len(GRAPH["nodes"]),
            "edge_count": len(GRAPH["edges"]),
            "graph_sha256": sha256_graph(GRAPH),
            "signature": "STUB",   # Cloud signs for real later (Ed25519); stubbed here
        },
        "graph": GRAPH,
    }
    out = os.path.join(os.path.dirname(__file__), "..", "deploy", "sample-bundle.json")
    out = os.path.abspath(out)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    print(f"wrote {out}")
    print(f"  graph_sha256 = {bundle['manifest']['graph_sha256']}")
    print(f"  nodes={len(GRAPH['nodes'])} edges={len(GRAPH['edges'])}")


if __name__ == "__main__":
    main()
