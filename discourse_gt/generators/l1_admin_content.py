# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Admin / Content + Customize (themes, badges, flags,
watched words, embeddable hosts, color schemes, permalinks, user fields, emoji,
screened lists, staff action logs, site texts). AdminConstraint. Routes ~279-596."""
from common import (key as K, snode, V, rf, of, resp_json, resp_empty, dec, IDST_ADMIN)

TH = "app/controllers/admin/themes_controller.rb"
BD = "app/controllers/admin/badges_controller.rb"
FL = "app/controllers/admin/flags_controller.rb"
WW = "app/controllers/admin/watched_words_controller.rb"
EH = "app/controllers/admin/embeddable_hosts_controller.rb"
SC = "app/controllers/admin/color_schemes_controller.rb"
PL = "app/controllers/admin/permalinks_controller.rb"
UF = "app/controllers/admin/user_fields_controller.rb"
EJ = "app/controllers/admin/emoji_controller.rb"
SIP = "app/controllers/admin/screened_ip_addresses_controller.rb"
SAL = "app/controllers/admin/staff_action_logs_controller.rb"
ST = "app/controllers/admin/site_texts_controller.rb"
IDP = lambda name="id": [{"name": name, "in": "path", "type": "string", "required": True, "flow": True, "description": f"{name}."}]

NODES = [
    # ---- Themes / components (RCE-relevant) ----
    snode("/admin/themes", ["GET", "POST"], "themes_index_create", IDST_ADMIN,
          [V("GET", resp=resp_json([of("themes", "array", True, "Installed themes/components.")]), reason="Lists themes.", src=f"{TH}:1"),
           V("POST", [rf("theme", "body", "object", required=True, flow=True, description="Theme fields (JS/CSS/templates).")],
             resp_json([of("theme", "object", True, "Created theme.")]),
             reason="Creates a theme/component (ships client-side JS to all users).", src=f"{TH}:1")],
          "Admin.", f"{TH}:1",
          notes="Theme fields include JS/handlebars executed in every visitor's browser (stored-XSS-by-design surface).",
          sin=[dec("theme", "ThemeSource(content)", "content", reason="Theme JS/CSS/templates served to users.")]),
    snode("/admin/themes/{id}", ["GET", "PUT", "DELETE"], "theme_crud", IDST_ADMIN,
          [V("GET", resp=resp_json([of("theme", "object", True, "Theme detail.")]), reason="Reads a theme.", src=f"{TH}:1"),
           V("PUT", [rf("theme", "body", "object", required=True, flow=True, description="Updated theme fields.")],
             reason="Updates a theme's fields/settings.", src=f"{TH}:1"),
           V("DELETE", reason="Deletes a theme.", src=f"{TH}:1")],
          "Admin.", f"{TH}:1", params=IDP(), notes="Groups /source, /setting, /site-setting, export, upload_asset."),
    snode("/admin/themes/import", ["POST"], "theme_import", IDST_ADMIN,
          [V("POST", [rf("remote", "body", "string", required=False, flow=True, description="Remote git repo URL to import."),
                      rf("bundle", "body", "file", required=False, flow=True, description="Theme .tar.gz bundle."),
                      rf("branch", "body", "string", required=False, flow=False, description="Git branch.")],
             resp_json([of("theme", "object", True, "Imported theme.")]),
             reason="Imports a theme from a remote git repo or an uploaded bundle.", src=f"{TH}:1",
             cts=["multipart/form-data", "application/json"])],
          "Admin.", f"{TH}:1",
          notes="SSRF + code-ingestion: `remote` is cloned server-side; imported JS runs in every browser. "
                "Private-repo import uses a generated SSH key pair.",
          sin=[dec("remote", "RemoteRepoUrl(locator)", "locator", reference_capable=True, reason="Server-cloned git URL.")]),
    # ---- Badges (SQL-backed triggers) ----
    snode("/admin/badges", ["GET", "POST"], "badges_index_create", IDST_ADMIN,
          [V("GET", resp=resp_json([of("badges", "array", True, "Badges.")]), reason="Lists badges.", src=f"{BD}:1"),
           V("POST", [rf("name", "body", "string", required=True, flow=True, description="Badge name."),
                      rf("query", "body", "string", required=False, flow=True, description="SQL granting query (if custom queries enabled)."),
                      rf("icon", "body", "string", required=False, flow=False, description="Icon.")],
             reason="Creates a badge (optionally with a SQL granting query).", src=f"{BD}:1", ex={"name": "Helper"})],
          "Admin.", f"{BD}:1",
          notes="Custom badge `query` runs SQL (read-only, gated by enable_badge_sql) -- data-exposure surface.",
          sin=[dec("query", "BadgeSql(content)", "content", reason="Admin-authored SQL granting query.")]),
    snode("/admin/badges/{id}", ["PUT", "DELETE"], "badge_update_delete", IDST_ADMIN,
          [V("PUT", [rf("query", "body", "string", required=False, flow=True, description="Updated SQL query.")],
             reason="Updates a badge.", src=f"{BD}:1"),
           V("DELETE", reason="Deletes a badge.", src=f"{BD}:1")],
          "Admin.", f"{BD}:1", params=IDP()),
    # ---- Flags (custom flag types) ----
    snode("/admin/config/flags", ["GET", "POST"], "flags_index_create", IDST_ADMIN,
          [V("GET", resp=resp_json([of("flags", "array", True, "Flag types.")]), reason="Lists flag types.", src=f"{FL}:1"),
           V("POST", [rf("name", "body", "string", required=True, flow=True, description="Flag name."),
                      rf("applies_to", "body", "array", required=True, flow=True, description="Post/Topic/Chat.")],
             reason="Creates a custom flag type.", src=f"{FL}:1", ex={"name": "Illegal"})],
          "Admin.", f"{FL}:1", notes="Groups PUT/DELETE/reorder."),
    snode("/admin/config/flags/{id}", ["PUT", "DELETE"], "flag_update_delete", IDST_ADMIN,
          [V("PUT", reason="Updates a flag type.", src=f"{FL}:1"), V("DELETE", reason="Deletes a flag type.", src=f"{FL}:1")],
          "Admin.", f"{FL}:1", params=IDP()),
    # ---- Watched words (regex -> ReDoS) ----
    snode("/admin/watched_words", ["GET", "POST"], "watched_words_index_create", IDST_ADMIN,
          [V("GET", resp=resp_json([of("watched_words", "array", True, "Configured watched words.")]), reason="Lists watched words.", src=f"{WW}:1"),
           V("POST", [rf("word", "body", "string", required=True, flow=True, description="Word or regex."),
                      rf("action", "body", "string", required=True, flow=True, description="block/censor/require_approval/flag/..."),
                      rf("replacement", "body", "string", required=False, flow=True, description="Replacement/link.")],
             reason="Adds a watched word/regex rule.", src=f"{WW}:1", ex={"word": "spam", "action": "block"})],
          "Admin.", f"{WW}:1",
          notes="`word` may be a regex applied to all posts (ReDoS surface); replacement can auto-link.",
          sin=[dec("word", "WatchedPattern(content)", "content", reason="Word/regex matched against content.")]),
    snode("/admin/watched_words/{id}", ["DELETE"], "watched_word_delete", IDST_ADMIN,
          [V("DELETE", reason="Deletes a watched word.", src=f"{WW}:1")], "Admin.", f"{WW}:1", params=IDP(),
          notes="Groups /upload (CSV import) + action clear_all."),
    snode("/admin/watched_words/upload", ["POST"], "watched_words_upload", IDST_ADMIN,
          [V("POST", [rf("file", "body", "file", required=True, flow=True, description="CSV of words.")],
             reason="Bulk-imports watched words from CSV.", src=f"{WW}:1", cts=["multipart/form-data"])],
          "Admin.", f"{WW}:1"),
    # ---- Embeddable hosts (SSRF on embedding/crawl) ----
    snode("/admin/embeddable_hosts", ["POST"], "embeddable_hosts_create", IDST_ADMIN,
          [V("POST", [rf("host", "body", "string", required=True, flow=True, description="Allowed embedding host."),
                      rf("path_whitelist", "body", "string", required=False, flow=True, description="Path allowlist.")],
             reason="Registers a host allowed to embed/crawl content.", src=f"{EH}:1", ex={"host": "example.com"})],
          "Admin.", f"{EH}:1",
          notes="Controls which remote hosts Discourse will crawl/embed (SSRF/embed-trust surface); groups PUT/DELETE.",
          sin=[dec("host", "EmbedHost(locator)", "locator", reference_capable=True, reason="Trusted embedding host.")]),
    # ---- Color schemes ----
    snode("/admin/color_schemes", ["POST"], "color_schemes_create", IDST_ADMIN,
          [V("POST", [rf("color_scheme", "body", "object", required=True, flow=True, description="Palette.")],
             reason="Creates a color scheme.", src=f"{SC}:1")], "Admin.", f"{SC}:1", notes="Groups PUT/DELETE."),
    # ---- Permalinks (redirects) ----
    snode("/admin/permalinks", ["GET", "POST"], "permalinks_index_create", IDST_ADMIN,
          [V("GET", resp=resp_json([of("permalinks", "array", True, "Configured permalinks.")]), reason="Lists permalinks.", src=f"{PL}:1"),
           V("POST", [rf("url", "body", "string", required=True, flow=True, description="Source path."),
                      rf("permalink_type_value", "body", "string", required=True, flow=True, description="Target (topic/category/external url).")],
             reason="Creates a permalink/redirect.", src=f"{PL}:1", ex={"url": "/old"})],
          "Admin.", f"{PL}:1", notes="External-URL permalinks are a redirect surface; groups DELETE."),
    # ---- User fields ----
    snode("/admin/config/user_fields", ["GET", "POST"], "user_fields_index_create", IDST_ADMIN,
          [V("GET", resp=resp_json([of("user_fields", "array", True, "Custom profile fields.")]), reason="Lists user fields.", src=f"{UF}:1"),
           V("POST", [rf("user_field", "body", "object", required=True, flow=True, description="Field (name, type, required).")],
             reason="Creates a custom user profile field.", src=f"{UF}:1")],
          "Admin.", f"{UF}:1", notes="Groups PUT/DELETE; field values are user-supplied + displayed."),
    # ---- Emoji ----
    snode("/admin/config/emoji", ["POST", "DELETE"], "emoji_create_delete", IDST_ADMIN,
          [V("POST", [rf("name", "body", "string", required=True, flow=True, description="Emoji name."),
                      rf("file", "body", "file", required=True, flow=True, description="Image file.")],
             reason="Adds a custom emoji (image upload).", src=f"{EJ}:1", cts=["multipart/form-data"]),
           V("DELETE", reason="Removes a custom emoji.", src=f"{EJ}:1")],
          "Admin.", f"{EJ}:1", notes="File ingestion; groups import_preview/import_confirm."),
    # ---- Screened IPs ----
    snode("/admin/logs/screened_ip_addresses", ["GET", "POST"], "screened_ips", IDST_ADMIN,
          [V("GET", resp=resp_json([of("screened_ip_addresses", "array", True, "Blocked/allowed IPs.")]), reason="Lists screened IPs.", src=f"{SIP}:1"),
           V("POST", [rf("ip_address", "body", "string", required=True, flow=True, description="CIDR/IP."),
                      rf("action_name", "body", "string", required=True, flow=True, description="block/allow_admin.")],
             reason="Adds an IP screening rule.", src=f"{SIP}:1", ex={"ip_address": "1.2.3.4"})],
          "Admin.", f"{SIP}:1", notes="Network ACL; groups PUT/DELETE and screened_emails/urls."),
    # ---- Staff action logs (audit) ----
    snode("/admin/logs/staff_action_logs", ["GET"], "staff_action_logs", IDST_ADMIN,
          [V("GET", resp=resp_json([of("staff_action_logs", "array", True, "Audit log entries.")]),
             reason="Reads the staff audit log.", src=f"{SAL}:1")], "Admin.", f"{SAL}:1",
          notes="The moderation/admin audit trail (tamper/visibility target)."),
    # ---- Site texts (UI string overrides) ----
    snode("/admin/customize/site_texts/{id}", ["PUT"], "update_site_text", IDST_ADMIN,
          [V("PUT", [rf("value", "body", "string", required=True, flow=True, description="Override string (rendered in UI).")],
             reason="Overrides a localized UI string.", src=f"{ST}:1")], "Admin.", f"{ST}:1", params=IDP(),
          notes="Overridden strings render in the UI/emails (content-injection surface); groups revert.",
          sin=[dec("value", "SiteTextOverride(content)", "content", reason="Admin-authored UI string.")]),
]
