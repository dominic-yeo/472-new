# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "anything-llm-local"


EXCLUDED = [
    {"item": "Internal UI API (/api/* non-v1: /api/system/*, /api/workspace/*, /api/admin/*, "
             "/api/embed/*, /api/agents/*, /api/mobile/*, ...)",
     "reason": "Session/JWT-authenticated browser-app API consumed by the frontend; large separate surface. "
               "Tracked as remaining work in environment.yaml (web_gt_status). Not yet enumerated here."},
    {"item": "Developer API (/api/v1/*) modules not yet modeled: workspace, workspaceThread, document, "
             "openai, admin, userManagement, embed, mcp-servers",
     "reason": "In-progress. This checkpoint models the System Settings + Authentication module; the remaining "
               "/api/v1 modules are enumerated in environment.yaml and will be added incrementally."},
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
           "scope": "AnythingLLM Developer API (/api/v1) -- module: System Settings + Authentication",
           "nodes": nodes, "edges": D.EDGES, "excluded_items": EXCLUDED}
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
    print(f"L1: {len(nodes)} nodes ({len(D.API_NODES)} api, {len(D.PAGE_NODES)} page); "
          f"{len(candidates)} L2 candidates; {len(D.EDGES)} edges -> {OUT}")


if __name__ == "__main__":
    main()
