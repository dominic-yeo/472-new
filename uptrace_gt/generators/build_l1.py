# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "uptrace-oss"

EXCLUDED = [
    {"item": "OTLP/gRPC services on :14317 (TraceService/LogsService/MetricsService via grpc.Server)",
     "reason": "gRPC transport, not the HTTP attack surface; the HTTP OTLP mirrors (/v1/traces,/v1/logs,/v1/metrics) ARE modeled."},
    {"item": "/debug/pprof/* (only mounted when conf.Debug=true)",
     "reason": "Debug-only profiler endpoints; not present in a production config. Enumerated here as a note, not a candidate."},
    {"item": "Vue SPA static assets + index.html fallback (embedded FS)",
     "reason": "Client bundle / SPA shell; no server business-data flow. The JSON APIs it calls are the real surface."},
    {"item": "SSO/OIDC + Cloudflare Access providers (config-gated user_providers)",
     "reason": "External IdP dependency; reachability depends on auth.oidc / auth.cloudflare config blocks being set."},
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
