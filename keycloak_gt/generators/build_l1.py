# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "keycloak-oss"

EXCLUDED = [
    {"item": "{realm} is a path template -- one node per route, not per realm. The whole protocol + admin + account "
             "surface is replicated under every realm (master + each created realm)",
     "reason": "Keycloak dispatches every realm through the same RealmsResource + resource tree; the GT models each "
               "route once with {realm} as a parameter. Realms differ only in config, not in the route/auth model."},
    {"item": "The deep admin sub-resource tree is enumerated at the resource ROOT + security-critical sub-paths; the "
             "full per-item CRUD leaf set (e.g. every roles/{role}/composites, clients/{id}/nodes, "
             "client-scopes/{id}/scope-mappings/*, group hierarchy leaves) is summarized, not expanded",
     "reason": "Hundreds of admin leaves share the identical realm-management-role authorization; the roots + the "
               "high-value leaves (impersonation, credentials, client-secret, service-account, SSRF test endpoints) "
               "are L2-covered and the rest enumerated as L1 nodes."},
    {"item": "Theme/static assets, the Admin Console SPA (/admin/{realm}/console), the Account Console SPA, welcome "
             "page resources, and JS adapter resources",
     "reason": "Client assets; the OIDC + REST APIs they drive are the modeled surface."},
    {"item": "SAML protocol internals beyond the endpoint + descriptor (artifact resolution, ECP, SOAP binding "
             "details) and the WS-Fed/Docker/CIBA-channel protocol variants",
     "reason": "Protocol-specific message handling reusing the same realm/client model; the SAML endpoint + metadata "
               "and the OIDC core are modeled, the variants enumerated."},
    {"item": "The separate management port (9000): /health, /health/ready|live, /metrics",
     "reason": "A distinct bind on a different port (KC_HTTP_MANAGEMENT_PORT), not part of the 8080 request surface; "
               "enumerated as out-of-scope for this origin."},
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
