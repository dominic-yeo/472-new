# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "discourse-local"


EXCLUDED = [
    {"item": "Static/SPA + asset routes (static#show login/signup/faq/tos pages, /assets, Ember app shell)",
     "reason": "HTML shells rendered for the Ember SPA; the JSON API behind them is what carries the attack "
               "surface and is modeled directly. Page shells are not enumerated as api nodes."},
    {"item": "Discourse controllers/namespaces not yet modeled (~160 controllers): users, posts, topics, "
             "categories, tags, groups, invites, notifications, uploads, admin/* (site_settings, users, "
             "backups, api keys, web_hooks, themes, ...), reviewables, drafts, bookmarks, chat/* plugins, ...",
     "reason": "In-progress, module by module. This checkpoint models the Session + Authentication surface "
               "(SessionController). Remaining controllers + route groups are tracked in environment.yaml web_gt:."},
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
           "scope": "Discourse 2026.11 HTTP API -- module: Session + Authentication (SessionController)",
           "nodes": nodes, "edges": D.EDGES, "excluded_items": EXCLUDED}
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
    print(f"L1: {len(nodes)} nodes ({len(D.API_NODES)} api, {len(D.PAGE_NODES)} page); "
          f"{len(candidates)} L2 candidates; {len(D.EDGES)} edges -> {OUT}")


if __name__ == "__main__":
    main()
