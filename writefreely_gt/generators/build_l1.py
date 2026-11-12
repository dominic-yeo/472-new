# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "writefreely-multi-user"

EXCLUDED = [
    {"item": "OAuth provider callbacks (/oauth/callback/{slack,writeas,gitlab,gitea,generic})",
     "reason": "Client-initiated SSO; completing the flow needs an external identity provider "
               "(EXTERNAL DEPENDENCY). The local /oauth/signup entry point is kept as a page node."},
    {"item": "gopher:// interface (handler.Gopher)",
     "reason": "Served on a separate gopher listener, not the HTTP attack surface; out of scope for web GT."},
    {"item": "static asset tree (/css, /js, /img, ... via InitStaticRoutes PathPrefix('/'))",
     "reason": "File server for bundled assets; no business-data flow. robots.txt/manifest.json kept as static nodes."},
]


def main():
    nodes = list(D.API_NODES) + list(D.PAGE_NODES)
    keys = [n["key"] for n in nodes]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        print("DUPLICATE L1 KEYS:", dupes)
        sys.exit(1)
    candidates = [n["key"] for n in D.API_NODES if n["io_variants"]]
    doc = {"schema_version": "pengent-web-gt-v1", "environment_id": ENV_ID,
           "nodes": nodes, "edges": D.EDGES, "excluded_items": EXCLUDED}
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
    print(f"L1: {len(nodes)} nodes ({len(D.API_NODES)} api, {len(D.PAGE_NODES)} page); "
          f"{len(candidates)} L2 candidates; {len(D.EDGES)} edges -> {OUT}")


if __name__ == "__main__":
    main()
