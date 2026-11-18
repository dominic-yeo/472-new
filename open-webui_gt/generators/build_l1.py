# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "open-webui-local"


EXCLUDED = [
    {"item": "WebSocket transport (/ws, socket.io) and static mounts (/static, /pyodide, SPA fallback)",
     "reason": "Not HTTP request/response attack-surface nodes in the pengent-web-gt-v1 sense; the realtime "
               "channel is covered by the agentic layer. Out of scope for L1/L2."},
    {"item": "Open WebUI routers not yet modeled (34 of 36): users, chats, models, files, knowledge, "
             "folders, groups, prompts, tools, functions, memories, notes, channels, comments, retrieval, "
             "images, audio, ollama, openai, pipelines, tasks, configs, evaluations, mfa, sessions, scim, "
             "skills, apps, automations, calendar, notifications, analytics, terminals, utils, search, tether",
     "reason": "In-progress, module by module. This checkpoint models the Authentication + Account router "
               "(/api/v1/auths). Remaining routers + route counts are tracked in environment.yaml web_gt:."},
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
           "scope": "Open WebUI 0.13.3 HTTP API -- module: Authentication + Account (/api/v1/auths)",
           "nodes": nodes, "edges": D.EDGES, "excluded_items": EXCLUDED}
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
    print(f"L1: {len(nodes)} nodes ({len(D.API_NODES)} api, {len(D.PAGE_NODES)} page); "
          f"{len(candidates)} L2 candidates; {len(D.EDGES)} edges -> {OUT}")


if __name__ == "__main__":
    main()
