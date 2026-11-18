# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Admin / Content + Customize."""
from common import key as K
from l2lib import qa

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

qa("disc_list_themes", "List themes", "Read", "list_themes", "Admin", K("/admin/themes"), ["GET"], "ThemeList",
   vis_reason="Admin.", src=f"{TH}:1", description="Lists themes/components.")
qa("disc_create_theme", "Create theme", "Create", "create_theme", "Admin", K("/admin/themes"), ["POST"], "Theme",
   vis_reason="Admin.", src=f"{TH}:1", description="Creates a theme (ships client JS).",
   notes="Theme JS runs in every browser (stored-XSS-by-design).")
qa("disc_read_theme", "Read theme", "Read", "read_theme", "Admin", K("/admin/themes/{id}"), ["GET"], "Theme",
   vis_reason="Admin.", src=f"{TH}:1", description="Reads a theme.")
qa("disc_update_theme", "Update theme", "Update", "update_theme", "Admin", K("/admin/themes/{id}"), ["PUT"], "Theme",
   vis_reason="Admin.", src=f"{TH}:1", description="Updates theme fields/settings.", notes="Groups source/setting.")
qa("disc_delete_theme", "Delete theme", "Delete", "delete_theme", "Admin", K("/admin/themes/{id}"), ["DELETE"], "Theme",
   vis_reason="Admin.", src=f"{TH}:1", description="Deletes a theme.")
qa("disc_import_theme", "Import theme", "Create", "import_theme", "Admin", K("/admin/themes/import"), ["POST"], "Theme",
   vis_reason="Admin.", src=f"{TH}:1", description="Imports a theme from a remote repo or bundle.",
   notes="SSRF + code-ingestion: remote cloned server-side; JS runs in all browsers.")
qa("disc_list_badges", "List badges", "Read", "list_badges", "Admin", K("/admin/badges"), ["GET"], "BadgeList",
   vis_reason="Admin.", src=f"{BD}:1", description="Lists badges.")
qa("disc_create_badge", "Create badge", "Create", "create_badge", "Admin", K("/admin/badges"), ["POST"], "Badge",
   vis_reason="Admin.", src=f"{BD}:1", description="Creates a badge (optional SQL query).", notes="Custom SQL -> data exposure.")
qa("disc_update_badge", "Update badge", "Update", "update_badge", "Admin", K("/admin/badges/{id}"), ["PUT"], "Badge",
   vis_reason="Admin.", src=f"{BD}:1", description="Updates a badge.")
qa("disc_delete_badge", "Delete badge", "Delete", "delete_badge", "Admin", K("/admin/badges/{id}"), ["DELETE"], "Badge",
   vis_reason="Admin.", src=f"{BD}:1", description="Deletes a badge.")
qa("disc_list_flags", "List flag types", "Read", "list_flags", "Admin", K("/admin/config/flags"), ["GET"], "FlagList",
   vis_reason="Admin.", src=f"{FL}:1", description="Lists flag types.")
qa("disc_create_flag", "Create flag type", "Create", "create_flag", "Admin", K("/admin/config/flags"), ["POST"], "Flag",
   vis_reason="Admin.", src=f"{FL}:1", description="Creates a custom flag type.", notes="Groups reorder.")
qa("disc_update_flag", "Update flag type", "Update", "update_flag", "Admin", K("/admin/config/flags/{id}"), ["PUT"], "Flag",
   vis_reason="Admin.", src=f"{FL}:1", description="Updates a flag type.")
qa("disc_delete_flag", "Delete flag type", "Delete", "delete_flag", "Admin", K("/admin/config/flags/{id}"), ["DELETE"], "Flag",
   vis_reason="Admin.", src=f"{FL}:1", description="Deletes a flag type.")
qa("disc_list_watched_words", "List watched words", "Read", "list_watched_words", "Admin", K("/admin/watched_words"), ["GET"],
   "WatchedWordList", vis_reason="Admin.", src=f"{WW}:1", description="Lists watched words.")
qa("disc_create_watched_word", "Add watched word", "Create", "create_watched_word", "Admin", K("/admin/watched_words"), ["POST"],
   "WatchedWord", vis_reason="Admin.", src=f"{WW}:1", description="Adds a watched word/regex rule.", notes="Regex -> ReDoS surface.")
qa("disc_delete_watched_word", "Delete watched word", "Delete", "delete_watched_word", "Admin", K("/admin/watched_words/{id}"),
   ["DELETE"], "WatchedWord", vis_reason="Admin.", src=f"{WW}:1", description="Deletes a watched word.")
qa("disc_upload_watched_words", "Import watched words", "Create", "upload_watched_words", "Admin",
   K("/admin/watched_words/upload"), ["POST"], "WatchedWord", vis_reason="Admin.", src=f"{WW}:1",
   description="Bulk-imports watched words from CSV.")
qa("disc_create_embeddable_host", "Add embeddable host", "Create", "create_embeddable_host", "Admin",
   K("/admin/embeddable_hosts"), ["POST"], "EmbeddableHost", vis_reason="Admin.", src=f"{EH}:1",
   description="Registers a host allowed to embed/crawl content.", notes="SSRF/embed-trust; groups PUT/DELETE.")
qa("disc_create_color_scheme", "Create color scheme", "Create", "create_color_scheme", "Admin", K("/admin/color_schemes"),
   ["POST"], "ColorScheme", vis_reason="Admin.", src=f"{SC}:1", description="Creates a color scheme.", notes="Groups PUT/DELETE.")
qa("disc_list_permalinks", "List permalinks", "Read", "list_permalinks", "Admin", K("/admin/permalinks"), ["GET"], "PermalinkList",
   vis_reason="Admin.", src=f"{PL}:1", description="Lists permalinks.")
qa("disc_create_permalink", "Create permalink", "Create", "create_permalink", "Admin", K("/admin/permalinks"), ["POST"],
   "Permalink", vis_reason="Admin.", src=f"{PL}:1", description="Creates a permalink/redirect.", notes="External-URL redirect surface.")
qa("disc_list_user_fields", "List user fields", "Read", "list_user_fields", "Admin", K("/admin/config/user_fields"), ["GET"],
   "UserFieldList", vis_reason="Admin.", src=f"{UF}:1", description="Lists custom profile fields.")
qa("disc_create_user_field", "Create user field", "Create", "create_user_field", "Admin", K("/admin/config/user_fields"),
   ["POST"], "UserField", vis_reason="Admin.", src=f"{UF}:1", description="Creates a custom user field.", notes="Groups PUT/DELETE.")
qa("disc_create_emoji", "Add custom emoji", "Create", "create_emoji", "Admin", K("/admin/config/emoji"), ["POST"], "Emoji",
   vis_reason="Admin.", src=f"{EJ}:1", description="Adds a custom emoji (image upload).", notes="File ingestion.")
qa("disc_delete_emoji", "Delete custom emoji", "Delete", "delete_emoji", "Admin", K("/admin/config/emoji"), ["DELETE"], "Emoji",
   vis_reason="Admin.", src=f"{EJ}:1", description="Removes a custom emoji.")
qa("disc_list_screened_ips", "List screened IPs", "Read", "list_screened_ips", "Admin",
   K("/admin/logs/screened_ip_addresses"), ["GET"], "ScreenedIpList", vis_reason="Admin.", src=f"{SIP}:1",
   description="Lists screened IPs.")
qa("disc_create_screened_ip", "Add screened IP", "Create", "create_screened_ip", "Admin",
   K("/admin/logs/screened_ip_addresses"), ["POST"], "ScreenedIp", vis_reason="Admin.", src=f"{SIP}:1",
   description="Adds an IP screening rule.", notes="Network ACL; groups screened_emails/urls.")
qa("disc_staff_action_logs", "Read audit log", "Read", "staff_action_logs", "Admin", K("/admin/logs/staff_action_logs"), ["GET"],
   "StaffActionLog", vis_reason="Admin.", src=f"{SAL}:1", description="Reads the staff audit log.")
qa("disc_update_site_text", "Override UI string", "Update", "update_site_text", "Admin",
   K("/admin/customize/site_texts/{id}"), ["PUT"], "SiteText", vis_reason="Admin.", src=f"{ST}:1",
   description="Overrides a localized UI string.", notes="Rendered in UI/emails; groups revert.")
