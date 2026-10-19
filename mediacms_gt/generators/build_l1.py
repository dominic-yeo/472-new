# -*- coding: utf-8 -*-
"""Assemble l1_gt.yaml from l1_data. Run with PYTHONIOENCODING=utf-8."""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l1_data as D  # noqa: E402

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "l1_gt.yaml"))
ENV_ID = "mediacms-9.2.1"


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


EXCLUDED = [
    {"item": "Django admin generic CRUD (admin/<app>/<model>/{,add,<id>/change,<id>/delete,<id>/history})",
     "reason": "Framework-generated generic admin views (~180 routes over auth/account/socialaccount/sites/"
               "authtoken/files/users/lti/migrationservice models). Real staff surface but not MediaCMS "
               "application business actions with a JSON IO contract; represented collectively, not per-route."},
    {"item": "debug_toolbar routes (^__debug__/...)",
     "reason": "django-debug-toolbar; only active when DEBUG=True. This deployment runs DEBUG=False, so they are inert."},
    {"item": "allauth socialaccount/SAML provider routes (accounts/3rdparty/*, accounts/social/*, accounts/saml/*)",
     "reason": "No social application is configured and USE_SAML=False; provider endpoints cannot complete."},
    {"item": "api-auth/ (DRF browsable-API login/logout)",
     "reason": "DRF browsable-API session login helper, not a MediaCMS application endpoint."},
    {"item": "tinymce utility routes (tinymce/compressor|filebrowser|flatpages_link_list, tinymce/upload/)",
     "reason": "TinyMCE editor helper endpoints for admin flat-page editing; editor-plugin utilities."},
    {"item": "i18n/setlanguage, i18n/setlang, setlanguage",
     "reason": "Locale cookie setters; no business data flow."},
    {"item": "LTI launch/OIDC/select-media/my-media/embed",
     "reason": "USE_LTI=False in this deployment and no LTIPlatform configured; the launch/OIDC flow needs an "
               "external LMS platform (EXTERNAL DEPENDENCY). jwks/public-key are kept (publicly served). See issue-004."},
]

if __name__ == "__main__":
    main()
