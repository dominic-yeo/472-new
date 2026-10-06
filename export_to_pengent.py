#!/usr/bin/env python3
import argparse, json
from pathlib import Path
import yaml

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--l1", required=True)
    ap.add_argument("--l2", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    l1 = load_yaml(args.l1)
    l2 = load_yaml(args.l2)

    l1_nodes = list(l1.get("nodes") or [])
    l1_edges = list(l1.get("edges") or [])
    l2_nodes = list(l2.get("nodes") or [])

    # Runtime-only fields present in Pengent serialization.
    for n in l1_nodes:
        n.setdefault("first_round", 0)
        n.setdefault("last_round", 0)
        n.setdefault("first_seen", "")
        n.setdefault("last_seen", "")
        n.setdefault("visit_count", 0)

    for e in l1_edges:
        e.setdefault("count", 1)
        e.setdefault("first_seen", "")
        e.setdefault("last_seen", "")

    for n in l2_nodes:
        n.setdefault("origin", "human-ground-truth")
        n.setdefault("vuln_type", None)
        n.setdefault("severity", "")
        n.setdefault("created_at", "")
        n.setdefault("test_log", [])

    payload = {
        "layer1": {
            "nodes": l1_nodes,
            "edges": l1_edges,
            "dead_routes": {},
            "summary": {
                "nodes": len(l1_nodes),
                "api": sum(1 for n in l1_nodes if n.get("kind") == "api"),
                "page": sum(1 for n in l1_nodes if n.get("kind") == "page"),
                "static": sum(1 for n in l1_nodes if n.get("kind") == "static"),
                "edges": len(l1_edges),
                "dead_routes_pruned": 0,
            },
        },
        "layer2": {
            "nodes": l2_nodes,
            "edges": [],
            "metadata": {
                "kind": "action-semantic-state-flow",
                "schema_version": "3.0",
                "origin": "human-ground-truth",
                "note": "Semantic edges are rebuilt by Pengent from typed Req/Eff.",
            },
        },
    }

    Path(args.out).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
