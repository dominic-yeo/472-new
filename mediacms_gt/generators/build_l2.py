# -*- coding: utf-8 -*-
"""Assemble l2_gt.yaml and coverage-check against L1. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as L1  # noqa: E402
import l2_data  # noqa: F401,E402  (importing builds the action list)
from l2lib import nodes  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l2_gt.yaml"))
ENV_ID = "mediacms-9.2.1"


def main():
    acts = nodes()
    keys = [a["action_key"] for a in acts]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        print("DUPLICATE ACTION KEYS:", dupes)
        sys.exit(1)

    candidates = {n["key"] for n in L1.API_NODES if n["io_variants"]}
    l1_keys = {n["key"] for n in (L1.API_NODES + L1.PAGE_NODES)}
    covered = set()
    for a in acts:
        for b in a["l1_bindings"]:
            if b["l1_key"] not in l1_keys:
                print("UNKNOWN L1 KEY in", a["action_key"], ":", b["l1_key"])
                sys.exit(1)
            covered.add(b["l1_key"])

    missing = sorted(candidates - covered)
    if missing:
        print("L2 COVERAGE MISSING for", len(missing), "candidates:")
        for m in missing:
            print("  -", m)
        sys.exit(1)

    doc = {"schema_version": "pengent-web-gt-v1", "environment_id": ENV_ID,
           "nodes": acts, "edges": [], "annotation_issues": []}
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
    print(f"L2: {len(acts)} actions; all {len(candidates)} candidate L1 nodes covered -> {OUT}")


if __name__ == "__main__":
    main()
