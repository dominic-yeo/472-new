# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Admin / Core."""
from common import key as K
from l2lib import qa

SS = "app/controllers/admin/site_settings_controller.rb"
AP = "app/controllers/admin/api_controller.rb"
WH = "app/controllers/admin/web_hooks_controller.rb"
BK = "app/controllers/admin/backups_controller.rb"
EM = "app/controllers/admin/email_controller.rb"

qa("disc_list_site_settings", "List site settings", "Read", "list_site_settings", "Admin", K("/admin/site_settings"), ["GET"],
   "SiteSettings", vis_reason="Admin.", src=f"{SS}:1", description="Lists all site settings.", notes="Full config disclosure.")
qa("disc_update_site_setting", "Update site setting", "Update", "update_site_setting", "Admin",
   K("/admin/site_settings/{id}"), ["PUT"], "SiteSetting", vis_reason="Admin.", src=f"{SS}:1",
   description="Updates a site setting.", notes="HIGH-IMPACT: governs auth/uploads/embedding/CSP/outbound.")
qa("disc_admin_dashboard", "Read dashboard", "Read", "admin_dashboard", "Admin", K("/admin/dashboard"), ["GET"], "Dashboard",
   vis_reason="Admin.", src="app/controllers/admin/dashboard_controller.rb:1", description="Instance metrics.")
qa("disc_list_api_keys", "List API keys", "Read", "list_api_keys", "Admin", K("/admin/api/keys"), ["GET"], "ApiKeyList",
   vis_reason="Admin.", src=f"{AP}:1", description="Lists API keys.")
qa("disc_create_api_key", "Create API key", "Create", "create_api_key", "Admin", K("/admin/api/keys"), ["POST"], "ApiKey",
   vis_reason="Admin.", src=f"{AP}:1", description="Mints an API key.", notes="Long-lived credential; scopes define authority.")
qa("disc_read_api_key", "Read API key", "Read", "read_api_key", "Admin", K("/admin/api/keys/{id}"), ["GET"], "ApiKey",
   vis_reason="Admin.", src=f"{AP}:1", description="Reads a key.")
qa("disc_update_api_key", "Update API key", "Update", "update_api_key", "Admin", K("/admin/api/keys/{id}"), ["PUT"], "ApiKey",
   vis_reason="Admin.", src=f"{AP}:1", description="Updates a key.", notes="Groups revoke/undo-revoke.")
qa("disc_delete_api_key", "Delete API key", "Delete", "delete_api_key", "Admin", K("/admin/api/keys/{id}"), ["DELETE"], "ApiKey",
   vis_reason="Admin.", src=f"{AP}:1", description="Deletes a key.")
qa("disc_list_web_hooks", "List webhooks", "Read", "list_web_hooks", "Admin", K("/admin/api/web_hooks"), ["GET"], "WebHookList",
   vis_reason="Admin.", src=f"{WH}:1", description="Lists webhooks.")
qa("disc_create_web_hook", "Create webhook", "Create", "create_web_hook", "Admin", K("/admin/api/web_hooks"), ["POST"], "WebHook",
   vis_reason="Admin.", src=f"{WH}:1", description="Creates an outbound-event webhook.",
   notes="SSRF/exfil: payload_url receives server-side POSTs.")
qa("disc_read_web_hook", "Read webhook", "Read", "read_web_hook", "Admin", K("/admin/api/web_hooks/{id}"), ["GET"], "WebHook",
   vis_reason="Admin.", src=f"{WH}:1", description="Reads a webhook.")
qa("disc_update_web_hook", "Update webhook", "Update", "update_web_hook", "Admin", K("/admin/api/web_hooks/{id}"), ["PUT"], "WebHook",
   vis_reason="Admin.", src=f"{WH}:1", description="Updates a webhook.")
qa("disc_delete_web_hook", "Delete webhook", "Delete", "delete_web_hook", "Admin", K("/admin/api/web_hooks/{id}"), ["DELETE"],
   "WebHook", vis_reason="Admin.", src=f"{WH}:1", description="Deletes a webhook.")
qa("disc_ping_web_hook", "Ping webhook", "Create", "ping_web_hook", "Admin", K("/admin/api/web_hooks/{id}/ping"), ["POST"],
   "WebHookEvent", vis_reason="Admin.", src=f"{WH}:1", description="Sends a test event (outbound request).",
   notes="On-demand SSRF test vector.")
qa("disc_redeliver_web_hook", "Redeliver webhook event", "Create", "redeliver_web_hook_event", "Admin",
   K("/admin/api/web_hooks/{id}/events/{event_id}/redeliver"), ["POST"], "WebHookEvent", vis_reason="Admin.",
   src=f"{WH}:1", description="Re-delivers a stored webhook event.", notes="Groups bulk/failed redeliver.")
qa("disc_list_backups", "List backups", "Read", "list_backups", "Admin", K("/admin/backups"), ["GET"], "BackupList",
   vis_reason="Admin.", src=f"{BK}:1", description="Lists backups.")
qa("disc_create_backup", "Create backup", "Create", "create_backup", "Admin", K("/admin/backups"), ["POST"], "Backup",
   vis_reason="Admin.", src=f"{BK}:1", description="Starts a full database backup.", notes="Backup = entire DB.")
qa("disc_download_backup", "Download backup", "Read", "download_backup", "Admin", K("/admin/backups/{id}"), ["GET"], "Backup",
   vis_reason="Admin.", src=f"{BK}:1", description="Downloads a backup archive.", notes="Full-database exfiltration.")
qa("disc_email_backup", "Email backup link", "Update", "email_backup", "Admin", K("/admin/backups/{id}"), ["PUT"], "Backup",
   vis_reason="Admin.", src=f"{BK}:1", description="Emails a backup download link.")
qa("disc_delete_backup", "Delete backup", "Delete", "delete_backup", "Admin", K("/admin/backups/{id}"), ["DELETE"], "Backup",
   vis_reason="Admin.", src=f"{BK}:1", description="Deletes a backup.")
qa("disc_restore_backup", "Restore backup", "Update", "restore_backup", "Admin", K("/admin/backups/{id}/restore"), ["POST"],
   "Instance", vis_reason="Admin.", src=f"{BK}:1", description="Restores the instance from a backup.",
   notes="FULL TAKEOVER: replaces the whole instance.")
qa("disc_upload_backup", "Upload backup check", "Read", "check_backup_chunk", "Admin", K("/admin/backups/upload"), ["GET"],
   "BackupChunk", vis_reason="Admin.", src=f"{BK}:1", description="Backup-chunk existence check.")
qa("disc_upload_backup_chunk", "Upload backup chunk", "Create", "upload_backup_chunk", "Admin", K("/admin/backups/upload"),
   ["POST"], "Backup", vis_reason="Admin.", src=f"{BK}:1", description="Uploads a backup archive chunk.",
   notes="Ingests an archive later used by /restore.")
qa("disc_backup_readonly", "Toggle read-only", "Update", "backup_readonly", "Admin", K("/admin/backups/readonly"), ["PUT"],
   "Instance", vis_reason="Admin.", src=f"{BK}:1", description="Toggles site read-only mode.", notes="Groups rollback/cancel.")
qa("disc_admin_email_index", "Read email settings", "Read", "admin_email_index", "Admin", K("/admin/email"), ["GET"], "EmailConfig",
   vis_reason="Admin.", src=f"{EM}:1", description="Reads email delivery settings.", notes="Groups email-logs.")
qa("disc_admin_email_test", "Send test email", "Create", "admin_email_test", "Admin", K("/admin/email/test"), ["POST"],
   "Email", vis_reason="Admin.", src=f"{EM}:1", description="Sends a test email.", notes="Outbound SMTP trigger.")
qa("disc_update_email_template", "Update email template", "Update", "update_email_template", "Admin",
   K("/admin/email/templates/{id}"), ["PUT"], "EmailTemplate", vis_reason="Admin.",
   src="app/controllers/admin/email_templates_controller.rb:1", description="Overrides an email template.",
   notes="Content sent to users; groups revert.")
