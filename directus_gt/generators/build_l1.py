# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "directus-oss"

EXCLUDED = [
    {"item": "Per-collection Content API is served by ONE generic controller (/items/:collection[/:pk]); "
             "modeled once, not per user-defined collection",
     "reason": "Directus has no per-collection route files -- /items/:collection dispatches every collection "
               "through the same handler + policy engine. A real project's collections multiply the item nodes "
               "but share the identical auth model."},
    {"item": "System-collection convenience controllers already modeled (users, roles, policies, permissions, "
             "access, files, folders, flows, operations, presets, dashboards, panels, versions, comments, "
             "notifications, translations, revisions, activity, settings)",
     "reason": "These wrap the directus_* system collections with the same policy engine; the security-critical "
               "ones are L2-covered, the rest enumerated as L1 nodes."},
    {"item": "AI routes (/ai, /ai/files), MCP server (/mcp, /mcp-oauth/clients), deployment (/deployments, "
             "/deployments/webhooks), license (/license), TUS resumable upload (/files/tus)",
     "reason": "Feature-flagged / edition-specific surfaces (ENABLE_* envs). They share the token+policy auth "
               "model already captured; enumerated rather than modeled per-route."},
    {"item": "Data Studio SPA bundle (/admin/*) and raw asset bytes served under /assets/:pk",
     "reason": "Client assets / stored file bytes; the REST+GraphQL API that manages them is the modeled surface."},
    {"item": "Realtime (WebSocket/SSE) subscriptions and the GraphQL subscription transport",
     "reason": "A separate realtime channel carrying the same collections+permissions; out of scope for the "
               "REST/GraphQL request GT."},
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
