# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "rocketchat-oss"

EXCLUDED = [
    {"item": "Omnichannel / Livechat API (~150 routes: livechat/*, omnichannel/*) incl. EE variants",
     "reason": "Large separate product surface; shares the /api/v1 + X-Auth-Token model already captured. "
               "Enumerated as excluded rather than modeled per-route."},
    {"item": "Enterprise (ee/server/api/*): apps engine (/apps/*), canned-responses, omnichannel EE, licensing",
     "reason": "EE-licensed surface; reachability depends on a license. Out of scope for the OSS core GT."},
    {"item": "Secondary core groups enumerated but not L2-covered: teams.*, video-conference.*, calendar.*, "
             "moderation.*, cloud.*, import.*, e2e.*, oauth-apps.*, custom-sounds/emoji/status, banners, "
             "push, presence, commands, autotranslate, ai-search, media-calls, email-inbox, subscriptions.*",
     "reason": "Enumerated as L1 api nodes (surface-complete) without io_variants; same auth model as the "
               "covered core (auth/users/channels/groups/chat/rooms/settings/permissions/roles/integrations)."},
    {"item": "DDP/Meteor websocket methods + the method.call REST bridge payload space",
     "reason": "method.call/:method proxies hundreds of server methods; modeled as ONE high-risk node, not expanded."},
    {"item": "Ember/React web client static assets + theme/avatar file serving",
     "reason": "Client bundle; the REST API it calls is the modeled surface."},
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
