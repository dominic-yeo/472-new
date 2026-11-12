# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "ghost-oss"

EXCLUDED = [
    {"item": "Admin API long tail: stats/*, automations/*, automated_emails/*, emails/*, offers, labels, "
             "snippets, recommendations, newsletters, links, oembed, actions, email_previews, slack, "
             "tinybird, featurebase, mentions, custom_theme_settings, apps/*, members/metafields/*",
     "reason": "Enumerated as L1 api nodes (surface-complete) but NOT given io_variants / L2 coverage; "
               "they share the authAdminApi gate already modeled by the covered resources."},
    {"item": "Front-end theme rendering (/, /:slug, /tag/*, /author/*, RSS, sitemap, AMP) + Ghost Admin SPA (/ghost/)",
     "reason": "Theme-rendered HTML + SPA shell; the JSON APIs they call are the modeled surface."},
    {"item": "Stripe / Slack / oembed / webmention outbound callbacks to external services",
     "reason": "External dependency; reachability needs third-party services configured."},
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
