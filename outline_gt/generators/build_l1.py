# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "outline-oss"

EXCLUDED = [
    {"item": "SSO auth-provider start/callback routes are modeled generically as /auth/:provider[.callback] "
             "(the concrete providers: google, azure, oidc, discord, slack, github, gitlab, gitea, linear, "
             "notion, figma, email magic-link)",
     "reason": "Each plugin registers the identical passport start+callback pair under /auth; the two generic "
               "nodes capture the shared flow + its open-redirect / account-linking surface. Email is modeled "
               "explicitly (/auth/email) as it is the password-less default."},
    {"item": "Realtime collaboration + websockets service (y-websocket /collaboration, socket.io /realtime) and "
             "the background worker/cron queues",
     "reason": "A separate transport carrying the same documents + policies; out of scope for the HTTP request GT. "
               "cron.* is modeled as one enumerated node (internal, token-gated)."},
    {"item": "Static/asset + SPA surfaces: the Vite app bundle, /images|/fonts|/email static, document/attachment "
             "redirect routes that 302 to pre-signed S3/local storage URLs",
     "reason": "Client assets / storage bytes; the /api that mints the pre-signed URLs (attachments.create, "
               "documents.export) is the modeled surface."},
    {"item": "Plugin/integration webhook receivers and provider callbacks (plugins/*: slack, github, gitlab, "
             "linear, notion events; zapier; webhooks delivery)",
     "reason": "Edition-/config-gated inbound integrations that reuse the same team + policy model; integrations.* "
               "and the webhook subscription CRUD are modeled, the per-provider receivers enumerated."},
    {"item": "MCP server (/mcp) and OAuth dynamic client registration internals beyond the modeled endpoints",
     "reason": "Feature-flagged AI transport reusing the OAuth access-token + policy model already captured."},
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
