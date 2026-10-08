"""L2 cores, part 3: admin/system, admin config, admin/user, notifications, pages, cloudflared, agora, bot."""
from l2lib import *
from l2_spec import A, OBJ, authed, U, API, BASE

AD = SUBJ()

def server_state(attr, resource="IntegrationConfig(server)"):
    return OBJ("state", "server", "Server", f"Server setting ({attr})", "Server", "target", "implicit", "", resource,
               attribute=attr, state_field=attr)

def admin_read_config(key, attr, outs, akey, name, resource="IntegrationConfig(server)", subject="admin", conf=0.9, reasoning=None):
    A(key, "GET", akey=akey, name=name, business="read_" + attr + "_config", crud="Read", subject=subject,
      obj=server_state(attr, resource), req_facts=[authed()] if subject == "admin" else [],
      io_out={o: "observed" for o in outs}, conf=conf, reasoning=reasoning)

def admin_set_config(key, attr, ins, akey, name, resource="IntegrationConfig(server)", conf=0.9, reasoning=None):
    A(key, "POST", akey=akey, name=name, business="update_" + attr + "_config", crud="Update", subject="admin",
      obj=server_state(attr, resource), req_facts=[authed()],
      kill=[eff(FACT("State", ENT("server", "Server", "target"), attr, "previous"), "state_transition", "Previous config replaced.")],
      gen=[eff(FACT("State", ENT("server", "Server", "target"), attr, "updated"), "state_transition", f"{name} applied.")],
      io_in={i: "attr_state" for i in ins}, conf=conf, reasoning=reasoning)

# ---- admin/system ------------------------------------------------------------
A(API + "/admin/system/version", "GET", akey="anonymous_read_server_version", name="Read server version", business="read_server_version",
  crud="Read", subject="anon", obj=server_state("version", "ServerVersion(server)"), io_out={"version": "observed"})
A(API + "/admin/system/initialized", "GET", akey="anonymous_read_server_initialized", name="Read initialized flag",
  business="read_server_initialized", crud="Read", subject="anon", obj=server_state("initialized", "ServerInitialized(server)"),
  io_out={"initialized": "observed"})
A(API + "/admin/system/create_admin", "POST", akey="anonymous_bootstrap_admin_account", name="Bootstrap the first admin",
  business="bootstrap_admin_account", crud="Create", subject="anon",
  obj=OBJ("entity", "user", "User", "First administrator", "User", "created", "response", "uid", "UserID(user)"),
  gen=[eff(FACT("Exists", ENT("user", "User", "created")), "action_semantics", "Creates the founding admin (only while no user exists)."),
       eff(FACT("Know", AD, REF("UserID", ENT("user", "User", "created"))), "io_reference", "Returns the new uid.")],
  io_in={"email": "attr", "name": "attr", "password": "attr"}, io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"},
  conf=0.85, reasoning="Only succeeds before initialization (admin_system.rs:106).")
A(API + "/admin/system/metrics", "GET", akey="admin_read_server_metrics", name="Read server metrics", business="read_server_metrics",
  crud="Read", subject="admin", obj=server_state("metrics", "ServerMetric(server)"), req_facts=[authed()],
  io_out={"version": "observed"})
A(API + "/admin/system/organization", "GET", akey="anonymous_read_organization", name="Read organization info",
  business="read_organization", crud="Read", subject="anon", obj=server_state("organization", "OrganizationName(server)"),
  gen=[], io_out={"org_name": "observed", "org_description": "observed", "server_id": "observed"})
admin_set_config(API + "/admin/system/organization", "organization", ["org_name", "org_description"],
                 "admin_update_organization", "Update organization info", "OrganizationName(server)")
# PUT variant (frontend on newer servers)
A(API + "/admin/system/organization", "PUT", akey="admin_update_organization_put", name="Update organization info (PUT)",
  business="update_organization", crud="Update", subject="admin", obj=server_state("organization", "OrganizationName(server)"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("server", "Server", "target"), "organization", "previous"), "state_transition", "Previous org info replaced.")],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "organization", "updated"), "state_transition", "Organization info updated (PUT used by servers > 0.3.8).")],
  io_in={"org_name": "attr_state", "org_description": "attr_state"})
A(API + "/admin/system/organization/logo", "POST", akey="admin_upload_organization_logo", name="Upload organization logo",
  business="upload_organization_logo", crud="Update", subject="admin", obj=server_state("logo", "OrganizationLogo(server)"),
  req_facts=[authed()], gen=[eff(FACT("State", ENT("server", "Server", "target"), "logo", "updated"), "state_transition", "Logo replaced.")],
  io_in={"logo": "attr_state"})
A(API + "/admin/system/send_mail", "POST", akey="admin_send_test_mail", name="Send a test e-mail", business="send_test_mail", crud="Create",
  subject="admin", obj=OBJ("entity", "mail", "Mail", "Outgoing e-mail", "Mail", "created", "request", "", "EmailRecipient(mail)"),
  req_facts=[authed()], gen=[eff(FACT("Exists", ENT("mail", "Mail", "created")), "action_semantics", "An e-mail is dispatched via SMTP.")],
  io_in={"mail_to": "attr", "mail_subject": "attr", "mail_content": "attr"}, conf=0.8)
A(API + "/admin/system/third_party_secret", "GET", akey="admin_read_third_party_secret", name="Read third-party secret",
  business="read_third_party_secret", crud="Read", subject="admin", obj=server_state("third_party_secret", "ThirdPartySecret(server)"),
  req_facts=[authed()], gen=[eff(FACT("Know", AD, REF("ThirdPartySecret", ENT("server", "Server", "target"))), "io_reference", "Secret returned.")],
  io_out={"third_party_secret": "know"})
A(API + "/admin/system/third_party_secret", "POST", akey="admin_rotate_third_party_secret", name="Rotate third-party secret",
  business="rotate_third_party_secret", crud="Update", subject="admin", obj=server_state("third_party_secret", "ThirdPartySecret(server)"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("server", "Server", "target"), "third_party_secret", "previous"), "state_transition", "Old secret invalidated.")],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "third_party_secret", "updated"), "state_transition", "New secret generated."),
       eff(FACT("Know", AD, REF("ThirdPartySecret", ENT("server", "Server", "target"))), "io_reference", "New secret returned.")],
  io_out={"third_party_secret": "know"})
A(API + "/admin/system/frontend_url", "GET", akey="admin_read_frontend_url", name="Read frontend URL", business="read_frontend_url",
  crud="Read", subject="admin", obj=server_state("frontend_url", "FrontendURL(server)"), req_facts=[authed()],
  io_out={"frontend_url": "observed"})
A(API + "/admin/system/update_frontend_url", "POST", akey="admin_update_frontend_url", name="Update frontend URL",
  business="update_frontend_url", crud="Update", subject="admin", obj=server_state("frontend_url", "FrontendURL(server)"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("server", "Server", "target"), "frontend_url", "previous"), "state_transition", "Old URL replaced.")],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "frontend_url", "updated"), "state_transition", "Frontend URL (used in magic links) updated.")],
  io_in={"frontend_url": "attr_state"})
A(API + "/admin/system/common", "GET", akey="user_read_system_settings", name="Read system settings", business="read_system_settings",
  crud="Read", subject="user", obj=server_state("common", "SystemSetting(server)"), req_facts=[authed()],
  reasoning="Runtime shows a non-admin user succeeds (auth.har#54 and #93, uid 10 is_admin=false -> 200); the read is therefore a CurrentUser action, not Admin-only. The PUT counterpart remains admin.",
  io_out={f: "observed" for f in ["show_user_online_status", "webclient_auto_update", "contact_verification_enable", "chat_layout_mode",
          "max_file_expiry_mode", "only_admin_can_create_group", "ext_setting", "msg_smtp_notify_enable", "msg_smtp_notify_delay_seconds",
          "dm_enable", "add_friend_enable", "search_user_enable"]})
A(API + "/admin/system/common", "PUT", akey="admin_update_system_settings", name="Update system settings", business="update_system_settings",
  crud="Update", subject="admin", obj=server_state("common", "SystemSetting(server)"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("server", "Server", "target"), "common", "previous"), "state_transition", "Previous settings replaced.")],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "common", "updated"), "state_transition", "Server-wide settings updated.")],
  io_in={f: "attr_state" for f in ["show_user_online_status", "webclient_auto_update", "contact_verification_enable", "chat_layout_mode",
         "max_file_expiry_mode", "only_admin_can_create_group", "ext_setting", "msg_smtp_notify_enable", "msg_smtp_notify_delay_seconds",
         "dm_enable", "add_friend_enable", "search_user_enable"]})
A(API + "/admin/system/files", "GET", akey="admin_list_files", name="List uploaded files", business="admin_list_files", crud="Read",
  subject="admin", obj=OBJ("collection", "file_list", "File", "Uploaded files", "File", "target", "response", "content", "FilePath(file)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", AD, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "File rows expose their carrying message id.")],
  participants=[ENT("message", "Message", "target")],
  io_in={"uid": "attr_ref_user", "gid": "attr_ref_group"},
  io_out={"file_list_mid": "know", "from_uid": "observed", "gid": "observed", "content": "observed"}, conf=0.75)
A(API + "/admin/system/message/clear", "DELETE", akey="admin_clear_all_messages", name="Clear all messages", business="admin_clear_all_messages",
  crud="Delete", subject="admin", obj=OBJ("collection", "message_list", "Message", "All messages", "Message", "target", "implicit", "", "MessageID(message)"),
  req_facts=[authed()], kill=[eff(FACT("Exists", ENT("message", "Message", "target")), "action_semantics", "All messages removed server-wide.")], conf=0.7)

# ---- admin integration config (GET public/admin, POST admin) ----------------
admin_read_config(API + "/admin/agora/config", "agora", ["enabled", "url", "project_id", "app_id", "app_certificate", "rtm_key", "rtm_secret"],
                  "user_read_agora_config", "Read Agora config", "IntegrationConfig(server)", subject="user", conf=0.85,
                  reasoning="Admin check is commented out: any session reads app_certificate/rtm_secret (admin_agora.rs:106).")
admin_set_config(API + "/admin/agora/config", "agora", ["enabled", "url", "project_id", "app_id", "app_certificate", "rtm_key", "rtm_secret"],
                 "admin_update_agora_config", "Update Agora config")
A(API + "/admin/agora/usages", "GET", akey="admin_read_agora_usage", name="Read Agora usage", business="read_agora_usage", crud="Read",
  subject="admin", obj=server_state("agora_usage", "ServerMetric(server)"), req_facts=[authed()], conf=0.7)
A(API + "/admin/agora/enabled", "GET", akey="user_read_agora_enabled", name="Read Agora enabled flag", business="read_agora_enabled",
  crud="Read", subject="user", obj=server_state("agora_enabled", "FeatureEnabled(server)"), req_facts=[authed()], io_out={"enabled": "observed"})
A(API + "/admin/agora/token", "POST", akey="user_create_call_token", name="Generate a call token", business="create_call_token", crud="Create",
  subject="user", obj=OBJ("entity", "call_token", "CallToken", "Agora RTC token", "CallToken", "created", "response", "", "AgoraToken(call)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", AD, REF("AgoraToken", ENT("call_token", "CallToken", "created"))), "io_reference", "RTC token returned.")],
  io_in={"rtc_target_uid": "attr_ref_user", "rtc_target_gid": "attr_ref_group"},
  io_out={"agora_token": "know", "uid": "observed", "channel_name": "observed", "app_id": "observed"}, conf=0.75)
A(API + "/admin/agora/channel/{page_no}/{page_size}", "GET", akey="user_list_voice_channels", name="List active voice channels",
  business="list_voice_channels", crud="Read", subject="user",
  obj=OBJ("collection", "call_list", "CallChannel", "Active voice channels", "CallChannel", "target", "response", "agora_channels", "AgoraChannelName(call)"),
  req_facts=[authed()], io_out={"agora_channels": "observed"}, conf=0.7)
A(API + "/admin/agora/channel/user/{channel_name}/{hosts_only}", "GET", akey="user_list_voice_channel_users", name="List users in a voice channel",
  business="list_voice_channel_users", crud="Read", subject="user",
  obj=OBJ("collection", "call_users", "User", "Users in a voice channel", "User", "target", "request", "channel_name", "AgoraChannelName(call)"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("AgoraChannelName", ENT("call", "CallChannel", "target"))), "Caller supplies the channel name.")],
  gen=[eff(FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Uids present in the channel.")],
  participants=[ENT("call", "CallChannel", "target")],
  io_in={"channel_name": "req_know", "hosts_only": "attr"}, io_out={"agora_users": "know", "bool_result": "observed"}, conf=0.65,
  reasoning="Canonical spec route; the web client hard-codes hosts_only=false (server.ts getAgoraUsersByChannel).")

admin_read_config(API + "/admin/fcm/config", "fcm", ["enabled", "use_official", "token_url", "project_id", "private_key", "client_email"],
                  "admin_read_fcm_config", "Read Firebase config")
admin_set_config(API + "/admin/fcm/config", "fcm", ["enabled", "use_official", "token_url", "project_id", "private_key", "client_email"],
                 "admin_update_fcm_config", "Update Firebase config")
admin_read_config(API + "/admin/smtp/config", "smtp", ["enabled", "host", "port", "from", "username", "password"],
                  "admin_read_smtp_config", "Read SMTP config")
admin_set_config(API + "/admin/smtp/config", "smtp", ["enabled", "host", "port", "from", "username", "password"],
                 "admin_update_smtp_config", "Update SMTP config")
A(API + "/admin/smtp/enabled", "GET", akey="anonymous_read_smtp_enabled", name="Read SMTP enabled flag", business="read_smtp_enabled",
  crud="Read", subject="anon", obj=server_state("smtp_enabled", "FeatureEnabled(server)"), io_out={"enabled": "observed"})
admin_read_config(API + "/admin/login/config", "login", ["who_can_sign_up", "guest", "password", "magic_link", "google", "github", "metamask", "third_party", "oidc"],
                  "anonymous_read_login_policy", "Read login policy", "LoginPolicy(server)", subject="anon")
admin_set_config(API + "/admin/login/config", "login", ["who_can_sign_up", "guest", "password", "magic_link", "google", "github", "metamask", "third_party", "oidc"],
                 "admin_update_login_policy", "Update login policy", "LoginPolicy(server)")
admin_read_config(API + "/admin/google_auth/config", "google_auth", ["client_id"], "anonymous_read_google_auth_config", "Read Google-auth config",
                  subject="anon", conf=0.8, reasoning="Source handler is unauthenticated (admin_google_auth.rs:57).")
admin_set_config(API + "/admin/google_auth/config", "google_auth", ["client_id"], "admin_update_google_auth_config", "Update Google-auth config")
admin_read_config(API + "/admin/github_auth/config", "github_auth", ["client_id", "client_secret"], "anonymous_read_github_auth_config",
                  "Read GitHub-auth config", subject="anon", conf=0.8, reasoning="Source handler is unauthenticated and returns client_secret (admin_github_auth.rs:59).")
admin_set_config(API + "/admin/github_auth/config", "github_auth", ["client_id", "client_secret"], "admin_update_github_auth_config", "Update GitHub-auth config")
admin_read_config(API + "/admin/google_auth/public_config", "google_auth_public", ["client_id"], "anonymous_read_google_auth_public_config",
                  "Read Google-auth public config", subject="anon")
admin_read_config(API + "/admin/github_auth/public_config", "github_auth_public", ["client_id"], "anonymous_read_github_auth_public_config",
                  "Read GitHub-auth public config", subject="anon")
admin_read_config(API + "/admin/vocespace/config", "vocespace", ["enabled", "password", "url", "license", "state"],
                  "admin_read_vocespace_config", "Read VoceSpace config", conf=0.8)
admin_set_config(API + "/admin/vocespace/config", "vocespace", ["enabled", "password", "url", "license", "state"],
                 "admin_update_vocespace_config", "Update VoceSpace config", conf=0.8)
A(API + "/admin/vocespace/health/{url}", "GET", akey="admin_check_vocespace_health", name="Probe VoceSpace health",
  business="check_vocespace_health", crud="Read", subject="admin",
  obj=OBJ("entity", "url", "ExternalURL", "VoceSpace URL", "ExternalURL", "target", "request", "url", "ExternalURL(url)"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("ExternalURL", ENT("url", "ExternalURL", "target"))), "Caller supplies the URL.")],
  io_in={"url": "req_know"}, io_out={"bool_result": "observed"}, conf=0.65)

# ---- cloudflared -------------------------------------------------------------
A(API + "/admin/cloudflared/status", "GET", akey="admin_read_tunnel_status", name="Read tunnel status", business="read_tunnel_status",
  crud="Read", subject="admin", obj=server_state("tunnel", "TunnelStatus(server)"), req_facts=[authed()],
  io_out={"tunnel": "observed", "tunnel_url": "observed"}, conf=0.7)
A(API + "/admin/cloudflared/auto_info", "GET", akey="admin_read_auto_tunnel_info", name="Read auto-tunnel info", business="read_auto_tunnel_info",
  crud="Read", subject="admin", obj=server_state("tunnel", "TunnelStatus(server)"), io_out={"tunnel": "observed", "tunnel_url": "observed"}, conf=0.7)
A(API + "/admin/cloudflared/stop", "POST", akey="admin_stop_tunnel", name="Stop the tunnel", business="stop_tunnel", crud="Update",
  subject="admin", obj=server_state("tunnel", "TunnelStatus(server)"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("server", "Server", "target"), "tunnel", "running"), "state_transition", "Tunnel stopped.")],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "tunnel", "idle"), "state_transition", "Tunnel state set to idle.")],
  io_out={"tunnel": "observed"}, conf=0.7)
A(API + "/admin/cloudflared/start", "POST", akey="admin_start_tunnel", name="Start the tunnel", business="start_tunnel", crud="Update",
  subject="admin", obj=server_state("tunnel", "TunnelStatus(server)"), req_facts=[authed()],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "tunnel", "running"), "state_transition", "Tunnel started; public URL streamed.")],
  io_out={"tunnel": "observed"}, conf=0.7)
A(API + "/admin/cloudflared/auto_stream", "GET", akey="anonymous_stream_auto_tunnel", name="Stream auto-tunnel progress",
  business="stream_auto_tunnel", crud="Read", subject="anon", obj=server_state("tunnel", "TunnelStatus(server)"),
  io_out={"tunnel": "observed"}, conf=0.6)

# ---- custom pages ------------------------------------------------------------
A(API + "/page/apikey", "GET", akey="admin_read_page_api_key", name="Read page API key", business="read_page_api_key", crud="Read",
  subject="admin", obj=server_state("page_api_key", "PageAPIKey(custom_page)"), req_facts=[authed()],
  gen=[eff(FACT("Know", AD, REF("PageAPIKey", ENT("server", "Server", "target"))), "io_reference", "Page API key returned.")],
  io_out={"page_api_key": "know"}, conf=0.75)
A(API + "/page/apikey", "POST", akey="admin_rotate_page_api_key", name="Rotate page API key", business="rotate_page_api_key", crud="Update",
  subject="admin", obj=server_state("page_api_key", "PageAPIKey(custom_page)"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("server", "Server", "target"), "page_api_key", "previous"), "state_transition", "Old key invalidated.")],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "page_api_key", "updated"), "state_transition", "New key generated."),
       eff(FACT("Know", AD, REF("PageAPIKey", ENT("server", "Server", "target"))), "io_reference", "New key returned.")],
  io_out={"page_api_key": "know"}, conf=0.75)
A(API + "/page/{page}", "GET", akey="anonymous_read_custom_page", name="Read a custom page", business="read_custom_page", crud="Read",
  subject="anon", obj=OBJ("entity", "page", "CustomPage", "Custom HTML page", "CustomPage", "target", "request", "page", "CustomPageName(custom_page)"),
  req_facts=[req("knowledge", FACT("Know", AD, REF("CustomPageName", ENT("page", "CustomPage", "target"))), "Caller names the page slot (landing|after_signin).")],
  io_in={"page": "req_know"}, io_out={"html": "observed"}, conf=0.8)
A(API + "/page/{page}", "PUT", akey="admin_update_custom_page", name="Set a custom page", business="update_custom_page", crud="Update",
  subject="admin", obj=OBJ("entity", "page", "CustomPage", "Custom HTML page", "CustomPage", "target", "request", "page", "CustomPageName(custom_page)", state_field="html"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("CustomPageName", ENT("page", "CustomPage", "target"))), "Caller names the page slot.")],
  gen=[eff(FACT("State", ENT("page", "CustomPage", "target"), "html", "updated"), "state_transition", "Custom HTML stored.")],
  io_in={"page": "req_know", "html": "attr_state"}, conf=0.75)
A(API + "/page/{page}", "DELETE", akey="admin_reset_custom_page", name="Reset a custom page", business="reset_custom_page", crud="Delete",
  subject="admin", obj=OBJ("entity", "page", "CustomPage", "Custom HTML page", "CustomPage", "target", "request", "page", "CustomPageName(custom_page)"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("CustomPageName", ENT("page", "CustomPage", "target"))), "Caller names the page slot.")],
  kill=[eff(FACT("State", ENT("page", "CustomPage", "target"), "html", "custom"), "state_transition", "Custom HTML reset to default.")],
  io_in={"page": "req_know"}, conf=0.75)

# ---- notifications -----------------------------------------------------------
A(API + "/admin/notification/channel-types", "GET", akey="admin_list_notification_types", name="List enabled notification types",
  business="admin_list_notification_types", crud="Read", subject="admin",
  obj=OBJ("collection", "ntype_list", "NotificationType", "Notification channel types", "NotificationType", "target", "response", "channel_type", "NotificationChannelType(notification_type)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", AD, REF("NotificationChannelType", ENT("ntype", "NotificationType", "target"))), "io_reference", "Type keys returned.")],
  io_out={"channel_type": "know", "enabled": "observed"}, conf=0.75)
A(API + "/admin/notification/channel-types", "POST", akey="admin_toggle_notification_type", name="Enable/disable a notification type",
  business="admin_toggle_notification_type", crud="Update", subject="admin",
  obj=OBJ("state", "ntype", "NotificationType", "Notification channel type", "NotificationType", "target", "request", "channel_type", "NotificationChannelType(notification_type)", state_field="enabled"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("NotificationChannelType", ENT("ntype", "NotificationType", "target"))), "Caller names the type.")],
  gen=[eff(FACT("State", ENT("ntype", "NotificationType", "target"), "enabled", "updated"), "state_transition", "Type enabled/disabled.")],
  io_in={"channel_type": "req_know", "enabled": "attr_state"}, io_out={"channel_type": "observed", "enabled": "observed"}, conf=0.75)
A(API + "/admin/notification/channel-types/{channel_type}", "DELETE", akey="admin_delete_notification_type", name="Delete a notification type",
  business="admin_delete_notification_type", crud="Delete", subject="admin",
  obj=OBJ("entity", "ntype", "NotificationType", "Notification channel type", "NotificationType", "target", "request", "channel_type", "NotificationChannelType(notification_type)"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("NotificationChannelType", ENT("ntype", "NotificationType", "target"))), "Caller names the type.")],
  kill=[eff(FACT("Exists", ENT("ntype", "NotificationType", "target")), "action_semantics", "Enabled-type row removed.")],
  io_in={"channel_type": "req_know"}, conf=0.75)
A(API + "/user/notification/available-types", "GET", akey="user_list_available_notification_types", name="List available notification types",
  business="list_available_notification_types", crud="Read", subject="user",
  obj=OBJ("collection", "ntype_list", "NotificationType", "Available notification types", "NotificationType", "target", "response", "channel_type", "NotificationChannelType(notification_type)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", AD, REF("NotificationChannelType", ENT("ntype", "NotificationType", "target"))), "io_reference", "Type keys returned.")],
  io_out={"channel_type": "know"}, conf=0.75)
A(API + "/user/notification/channels", "GET", akey="user_list_own_notification_channels", name="List own notification channels",
  business="list_own_notification_channels", crud="Read", subject="user",
  obj=OBJ("collection", "nchan_list", "NotificationChannel", "Own notification channels", "NotificationChannel", "target", "response", "notif_channel_id", "NotificationChannelID(notification_channel)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", AD, REF("NotificationChannelID", ENT("nchan", "NotificationChannel", "target"))), "io_reference", "Channel ids returned.")],
  io_out={"notif_channel_id": "know", "uid": "observed", "channel_type": "observed", "notif_name": "observed", "notif_config": "observed"}, conf=0.75)
A(API + "/user/notification/channels", "POST", akey="user_create_notification_channel", name="Create a notification channel",
  business="create_notification_channel", crud="Create", subject="user",
  obj=OBJ("entity", "nchan", "NotificationChannel", "Notification channel", "NotificationChannel", "created", "response", "notif_channel_id", "NotificationChannelID(notification_channel)"),
  req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("nchan", "NotificationChannel", "created")), "action_semantics", "A notification channel is created."),
       eff(FACT("Know", AD, REF("NotificationChannelID", ENT("nchan", "NotificationChannel", "created"))), "io_reference", "New channel id returned.")],
  io_in={"channel_type": "attr", "notif_name": "attr", "notif_config": "attr", "trigger_on_groups": "attr_ref_group"},
  io_out={"notif_channel_id": "know", "uid": "observed", "channel_type": "observed", "notif_name": "observed", "notif_config": "observed"}, conf=0.75)
A(API + "/user/notification/channels/{id}", "PUT", akey="user_update_notification_channel", name="Update a notification channel",
  business="update_notification_channel", crud="Update", subject="user",
  obj=OBJ("entity", "nchan", "NotificationChannel", "Notification channel", "NotificationChannel", "target", "request", "notif_channel_id", "NotificationChannelID(notification_channel)", state_field="config"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("NotificationChannelID", ENT("nchan", "NotificationChannel", "target"))), "Caller names the channel id.")],
  gen=[eff(FACT("State", ENT("nchan", "NotificationChannel", "target"), "config", "updated"), "state_transition", "Channel config updated.")],
  io_in={"notif_channel_id": "req_know", "channel_type": "attr_state", "notif_name": "attr_state", "notif_config": "attr_state", "trigger_on_groups": "attr_ref_group"},
  io_out={"notif_channel_id": "observed", "uid": "observed", "channel_type": "observed", "notif_name": "observed", "notif_config": "observed"}, conf=0.75)
A(API + "/user/notification/channels/{id}", "DELETE", akey="user_delete_notification_channel", name="Delete a notification channel",
  business="delete_notification_channel", crud="Delete", subject="user",
  obj=OBJ("entity", "nchan", "NotificationChannel", "Notification channel", "NotificationChannel", "target", "request", "notif_channel_id", "NotificationChannelID(notification_channel)"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("NotificationChannelID", ENT("nchan", "NotificationChannel", "target"))), "Caller names the channel id.")],
  kill=[eff(FACT("Exists", ENT("nchan", "NotificationChannel", "target")), "action_semantics", "Channel deleted.")],
  io_in={"notif_channel_id": "req_know"}, conf=0.75)
A(API + "/user/notification/channels/{id}/test", "POST", akey="user_test_notification_channel", name="Test a notification channel",
  business="test_notification_channel", crud="Update", subject="user",
  obj=OBJ("entity", "nchan", "NotificationChannel", "Notification channel", "NotificationChannel", "target", "request", "notif_channel_id", "NotificationChannelID(notification_channel)", state_field="last_test"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("NotificationChannelID", ENT("nchan", "NotificationChannel", "target"))), "Caller names the channel id.")],
  gen=[eff(FACT("State", ENT("nchan", "NotificationChannel", "target"), "last_test", "sent"), "state_transition", "A test notification is dispatched.")],
  io_in={"notif_channel_id": "req_know"}, conf=0.7)

# ---- admin/user --------------------------------------------------------------
def admin_user_obj(role="target", source="request", field="uid"):
    return OBJ("entity", "user", "User", "User account", "User", role, source, field, "UserID(user)")
A(API + "/admin/user", "POST", akey="admin_create_user_account", name="Create a user", business="admin_create_user", crud="Create",
  subject="admin", obj=admin_user_obj("created", "response", "uid"), req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("user", "User", "created")), "action_semantics", "A new user account is created."),
       eff(FACT("Know", AD, REF("UserID", ENT("user", "User", "created"))), "io_reference", "New uid returned.")],
  io_in={"email": "attr", "password": "attr", "name": "attr", "is_admin": "attr_state", "webhook_url": "attr"},
  io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed", "online_devices": "observed",
          "device_token": "observed", "status": "observed", "webhook_url": "observed"})
A(API + "/admin/user", "GET", akey="admin_list_users", name="List users (admin)", business="admin_list_users", crud="Read",
  subject="admin", obj=OBJ("collection", "user_list", "User", "User directory (admin)", "User", "target", "response", "uid", "UserID(user)"),
  req_facts=[authed()], gen=[eff(FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Uids returned.")],
  io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed", "online_devices": "observed",
          "device_token": "observed", "status": "observed", "webhook_url": "observed"})
A(API + "/admin/user/{uid}", "GET", akey="admin_read_user", name="Read a user (admin)", business="admin_read_user", crud="Read",
  subject="admin", obj=admin_user_obj(), req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the uid."),
             req("existence", FACT("Exists", ENT("user", "User", "target")), "Unknown uid returns 404.")],
  gen=[eff(FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Returns the uid.")],
  io_in={"uid": "req_know"},
  io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed", "online_devices": "observed",
          "device_token": "observed", "status": "observed", "webhook_url": "observed"})
A(API + "/admin/user/{uid}", "DELETE", akey="admin_delete_user_account", name="Delete a user (admin)", business="admin_delete_user", crud="Delete",
  subject="admin", obj=admin_user_obj(),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the uid."),
             req("existence", FACT("Exists", ENT("user", "User", "target")), "Unknown uid returns 404.")],
  kill=[eff(FACT("Exists", ENT("user", "User", "target")), "action_semantics", "User row deleted (not self or uid 1).")],
  io_in={"uid": "req_know"})
A(API + "/admin/user/{uid}", "PUT", akey="admin_update_user_account", name="Update a user (admin)", business="admin_update_user", crud="Update",
  subject="admin", obj=OBJ("entity", "user", "User", "User account", "User", "target", "request", "uid", "UserID(user)", state_field="status"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the uid."),
             req("existence", FACT("Exists", ENT("user", "User", "target")), "Unknown uid returns 404.")],
  kill=[eff(FACT("State", ENT("user", "User", "target"), "status", "previous"), "state_transition", "Previous profile/privilege/status replaced.")],
  gen=[eff(FACT("State", ENT("user", "User", "target"), "status", "updated"), "state_transition", "Profile / is_admin / status / password updated (freeze kicks sessions).")],
  io_in={"uid": "req_know", "email": "attr_state", "password": "attr_state", "name": "attr_state", "is_admin": "attr_state", "status": "attr_state", "webhook_url": "attr_state"},
  io_out={"uid": "observed", "email": "observed", "name": "observed", "is_admin": "observed", "status": "observed",
          "online_devices": "observed", "device_token": "observed", "webhook_url": "observed"})
A(API + "/admin/user/{uid}/avatar", "POST", akey="admin_upload_user_avatar", name="Upload a user avatar (admin)",
  business="admin_upload_user_avatar", crud="Update", subject="admin",
  obj=OBJ("entity", "user", "User", "User avatar", "User", "target", "request", "uid", "UserID(user)", state_field="avatar"),
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the uid.")],
  gen=[eff(FACT("State", ENT("user", "User", "target"), "avatar", "updated"), "state_transition", "Avatar replaced.")],
  io_in={"uid": "req_know", "avatar": "attr_state"})
A(API + "/admin/user/bot-api-key/{uid}", "POST", akey="admin_create_bot_api_key", name="Create a bot API key", business="create_bot_api_key", crud="Create",
  subject="admin", obj=OBJ("entity", "bot_key", "BotKey", "Bot API key", "BotKey", "created", "response", "", "BotAPIKey(bot_key)"),
  participants=[ENT("user", "User", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the owning uid.")],
  gen=[eff(FACT("Exists", ENT("bot_key", "BotKey", "created")), "action_semantics", "A bot API key is created for the user."),
       eff(FACT("Know", AD, REF("BotAPIKey", ENT("bot_key", "BotKey", "created"))), "io_reference", "Full key returned once.")],
  io_in={"uid": "attr_ref_user", "bot_key_name": "attr"}, io_out={"api_key": "know"})
A(API + "/admin/user/bot-api-key/{uid}", "GET", akey="admin_list_bot_api_keys", name="List bot API keys", business="list_bot_api_keys", crud="Read",
  subject="admin", obj=OBJ("collection", "bot_key_list", "BotKey", "Bot API keys", "BotKey", "target", "response", "bot_key_id", "BotKeyID(bot_key)"),
  participants=[ENT("user", "User", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the owning uid.")],
  gen=[eff(FACT("Know", AD, REF("BotKeyID", ENT("bot_key", "BotKey", "target"))), "io_reference", "Key ids returned."),
       eff(FACT("Know", AD, REF("BotAPIKey", ENT("bot_key", "BotKey", "target"))), "io_reference", "Full key secrets returned.")],
  io_in={"uid": "attr_ref_user"}, io_out={"bot_key_id": "know", "api_key": "know", "bot_key_name": "observed"})
A(API + "/admin/user/bot-api-key/{uid}/{kid}", "DELETE", akey="admin_delete_bot_api_key", name="Delete a bot API key", business="delete_bot_api_key", crud="Delete",
  subject="admin", obj=OBJ("entity", "bot_key", "BotKey", "Bot API key", "BotKey", "target", "request", "kid", "BotKeyID(bot_key)"),
  participants=[ENT("user", "User", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("BotKeyID", ENT("bot_key", "BotKey", "target"))), "Caller names the key id."),
             req("knowledge", FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "Caller names the owning uid.")],
  kill=[eff(FACT("Exists", ENT("bot_key", "BotKey", "target")), "action_semantics", "Bot key deleted.")],
  io_in={"kid": "req_know", "uid": "req_know_user"})

# ---- admin bot-chat viewer ---------------------------------------------------
A(API + "/admin/bot_chat/bots", "GET", akey="admin_list_bots", name="List bot accounts", business="admin_list_bots", crud="Read",
  subject="admin", obj=OBJ("collection", "user_list", "User", "Bot accounts", "User", "target", "response", "uid", "UserID(user)"),
  req_facts=[authed()], gen=[eff(FACT("Know", AD, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Bot uids returned.")],
  io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"}, conf=0.75)
A(API + "/admin/bot_chat/{bot_uid}/conversations", "GET", akey="admin_list_bot_conversations", name="List a bot's conversations",
  business="admin_list_bot_conversations", crud="Read", subject="admin",
  obj=OBJ("collection", "conv_list", "Conversation", "Bot conversations", "Conversation", "target", "response", "conv_last_mid", "MessageID(message)"),
  participants=[ENT("bot", "User", "target"), ENT("peer", "User", "target"), ENT("message", "Message", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("bot", "User", "target"))), "Caller names the bot uid.")],
  gen=[eff(FACT("Know", AD, REF("UserID", ENT("peer", "User", "target"))), "io_reference", "Conversation peer uids returned."),
       eff(FACT("Know", AD, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Last message ids returned.")],
  io_in={"bot_uid": "attr_ref_user"},
  io_out={"target_uid": "know", "conv_last_mid": "know", "target_gid": "observed"}, conf=0.7)
A(API + "/admin/bot_chat/{bot_uid}/user/{uid}/history", "GET", akey="admin_read_bot_dm_history", name="Read a bot's DM history",
  business="admin_read_bot_dm_history", crud="Read", subject="admin",
  obj=OBJ("collection", "message_list", "Message", "Bot DM history", "Message", "target", "response", "mid", "MessageID(message)"),
  participants=[ENT("bot", "User", "target"), ENT("peer", "User", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("bot", "User", "target"))), "Caller names the bot uid."),
             req("knowledge", FACT("Know", AD, REF("UserID", ENT("peer", "User", "target"))), "Caller names the peer uid.")],
  gen=[eff(FACT("Know", AD, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Message ids returned.")],
  io_in={"bot_uid": "attr_ref_user", "uid": "req_know_peer"},
  io_out={"mid": "know", "from_uid": "observed", "content": "observed", "target_uid": "observed", "target_gid": "observed", "ref_mid": "observed"}, conf=0.7)
A(API + "/admin/bot_chat/{bot_uid}/group/{gid}/history", "GET", akey="admin_read_bot_group_history", name="Read a bot's group history",
  business="admin_read_bot_group_history", crud="Read", subject="admin",
  obj=OBJ("collection", "message_list", "Message", "Bot group history", "Message", "target", "response", "mid", "MessageID(message)"),
  participants=[ENT("bot", "User", "target"), ENT("group", "Group", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", AD, REF("UserID", ENT("bot", "User", "target"))), "Caller names the bot uid."),
             req("knowledge", FACT("Know", AD, REF("GroupID", ENT("group", "Group", "target"))), "Caller names the group id.")],
  gen=[eff(FACT("Know", AD, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Message ids returned.")],
  io_in={"bot_uid": "attr_ref_user", "gid": "req_know_group"},
  io_out={"mid": "know", "from_uid": "observed", "content": "observed", "target_uid": "observed", "target_gid": "observed", "ref_mid": "observed"}, conf=0.7)

# =============================================================================
#  BOT (API-key subject)
# =============================================================================
BOTU = SUBJ()
A(API + "/bot", "GET", akey="bot_list_related_groups", name="Bot lists related groups", business="bot_list_related_groups", crud="Read",
  subject="bot", obj=OBJ("collection", "group_list", "Group", "Bot's related groups", "Group", "target", "response", "gid", "GroupID(group)"),
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required.")],
  gen=[eff(FACT("Know", BOTU, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "Group ids returned."),
       eff(FACT("Know", BOTU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Pinned message ids returned.")],
  io_out={"gid": "know", "pinned_mid": "know", "owner": "observed", "group_name": "observed", "description": "observed",
          "members": "observed", "is_public": "observed", "pinned_content": "observed"}, conf=0.8)
A(API + "/bot/send_to_user/{uid}", "POST", akey="bot_send_direct_message_message", name="Bot sends a DM", business="bot_send_direct_message", crud="Create",
  subject="bot", obj=OBJ("entity", "message", "Message", "Bot DM", "Message", "created", "response", "", "MessageID(message)"),
  participants=[PRIN("recipient", "User", "recipient", "PEER")],
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required."),
             req("knowledge", FACT("Know", BOTU, REF("UserID", PRIN("recipient", "User", "recipient", "PEER"))), "Bot names the recipient uid.")],
  gen=[eff(FACT("Exists", ENT("message", "Message", "created")), "action_semantics", "A DM is stored and broadcast."),
       eff(FACT("Know", BOTU, REF("MessageID", ENT("message", "Message", "created"))), "io_reference", "New mid returned.")],
  io_in={"uid": "req_know_recipient", "content": "attr"}, io_out={"mid": "know"}, conf=0.8)
A(API + "/bot/send_to_group/{gid}", "POST", akey="bot_send_group_message_message", name="Bot sends a group message", business="bot_send_group_message", crud="Create",
  subject="bot", obj=OBJ("entity", "message", "Message", "Bot group message", "Message", "created", "response", "", "MessageID(message)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required."),
             req("knowledge", FACT("Know", BOTU, REF("GroupID", ENT("group", "Group", "target"))), "Bot names the group id.")],
  gen=[eff(FACT("Exists", ENT("message", "Message", "created")), "action_semantics", "A group message is stored."),
       eff(FACT("Know", BOTU, REF("MessageID", ENT("message", "Message", "created"))), "io_reference", "New mid returned.")],
  io_in={"gid": "req_know_group", "content": "attr"}, io_out={"mid": "know"}, conf=0.8)
A(API + "/bot/user/{uid}", "GET", akey="bot_read_user", name="Bot reads a user", business="bot_read_user", crud="Read",
  subject="bot", obj=OBJ("entity", "user", "User", "User account", "User", "target", "query", "uid", "UserID(user)"),
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required."),
             req("knowledge", FACT("Know", BOTU, REF("UserID", ENT("user", "User", "target"))), "Bot supplies the uid (read from the query string).")],
  gen=[eff(FACT("Know", BOTU, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Returns the uid.")],
  io_in={"uid": "req_know"}, io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"}, conf=0.75)
A(API + "/bot/group/{gid}", "GET", akey="bot_read_group", name="Bot reads a group", business="bot_read_group", crud="Read",
  subject="bot", obj=OBJ("entity", "group", "Group", "Group", "Group", "target", "query", "gid", "GroupID(group)"),
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required."),
             req("knowledge", FACT("Know", BOTU, REF("GroupID", ENT("group", "Group", "target"))), "Bot supplies the gid (read from the query string).")],
  gen=[eff(FACT("Know", BOTU, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "Returns the gid."),
       eff(FACT("Know", BOTU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Returns pinned mids.")],
  io_in={"gid": "req_know"},
  io_out={"gid": "know", "pinned_mid": "know", "owner": "observed", "group_name": "observed", "description": "observed",
          "members": "observed", "is_public": "observed", "pinned_content": "observed"}, conf=0.75)
A(API + "/bot/file/prepare", "POST", akey="bot_prepare_file_upload", name="Bot prepares a file upload", business="bot_prepare_file_upload", crud="Create",
  subject="bot", obj=OBJ("entity", "upload", "Upload", "Pending upload", "Upload", "created", "response", "", "UploadID(upload)"),
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required.")],
  gen=[eff(FACT("Exists", ENT("upload", "Upload", "created")), "action_semantics", "A temp upload is created."),
       eff(FACT("Know", BOTU, REF("UploadID", ENT("upload", "Upload", "created"))), "io_reference", "Upload UUID returned.")],
  io_in={"filename": "attr"}, io_out={"file_id": "know"}, conf=0.75)
A(API + "/bot/file/upload", "POST", akey="bot_upload_file_chunk", name="Bot uploads a file chunk", business="bot_upload_file_chunk", crud="Update",
  subject="bot", obj=OBJ("entity", "upload", "Upload", "Pending upload", "Upload", "target", "request", "file_id", "UploadID(upload)", state_field="bytes"),
  req_facts=[req("authentication", FACT("Authenticated", BOTU, "APIToken"), "Valid bot API key required."),
             req("knowledge", FACT("Know", BOTU, REF("UploadID", ENT("upload", "Upload", "target"))), "Bot supplies the upload id.")],
  gen=[eff(FACT("State", ENT("upload", "Upload", "target"), "bytes", "appended"), "state_transition", "Chunk appended; last chunk finalises a file."),
       eff(FACT("Exists", ENT("file", "File", "created")), "action_semantics", "The last chunk materialises a stored file."),
       eff(FACT("Know", BOTU, REF("FilePath", ENT("file", "File", "created"))), "io_reference", "Final chunk returns the file path.")],
  participants=[ENT("file", "File", "created")],
  io_in={"file_id": "req_know", "chunk_data": "attr_state"}, io_out={"path": "know", "hash": "observed"}, conf=0.75)

# ---- passkey (frontend, feature-gated) --------------------------------------
PK = SUBJ()
A(API + "/token/passkey/register/start", "POST", akey="user_start_passkey_registration", name="Start passkey registration",
  business="start_passkey_registration", crud="Create", subject="user",
  obj=OBJ("entity", "pk_challenge", "PasskeyChallenge", "Passkey registration challenge", "PasskeyChallenge", "created", "response", "challenge_id", "PasskeyChallengeID(passkey_challenge)"),
  req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("pk_challenge", "PasskeyChallenge", "created")), "action_semantics", "A registration challenge is created."),
       eff(FACT("Know", PK, REF("PasskeyChallengeID", ENT("pk_challenge", "PasskeyChallenge", "created"))), "io_reference", "Challenge id returned.")],
  io_in={"passkey_name": "attr"}, io_out={"challenge_id": "know"}, conf=0.6)
A(API + "/token/passkey/register/finish", "POST", akey="user_finish_passkey_registration", name="Finish passkey registration",
  business="finish_passkey_registration", crud="Create", subject="user",
  obj=OBJ("entity", "passkey", "Passkey", "Registered passkey", "Passkey", "created", "request", "challenge_id", "PasskeyChallengeID(passkey_challenge)"),
  req_facts=[authed(), req("knowledge", FACT("Know", PK, REF("PasskeyChallengeID", ENT("challenge", "PasskeyChallenge", "target"))), "Caller presents the challenge id.")],
  gen=[eff(FACT("Exists", ENT("passkey", "Passkey", "created")), "action_semantics", "A passkey credential is registered.")],
  io_in={"challenge_id": "req_know_challenge", "webauthn": "attr_cred", "passkey_name": "attr"}, conf=0.6)
A(API + "/token/passkey/auth/start", "POST", akey="anonymous_start_passkey_login", name="Start passkey login", business="start_passkey_login", crud="Create",
  subject="anon", obj=OBJ("entity", "pk_challenge", "PasskeyChallenge", "Passkey login challenge", "PasskeyChallenge", "created", "response", "challenge_id", "PasskeyChallengeID(passkey_challenge)"),
  gen=[eff(FACT("Exists", ENT("pk_challenge", "PasskeyChallenge", "created")), "action_semantics", "A login challenge is created."),
       eff(FACT("Know", PK, REF("PasskeyChallengeID", ENT("pk_challenge", "PasskeyChallenge", "created"))), "io_reference", "Challenge id returned.")],
  io_out={"challenge_id": "know"}, conf=0.6)
A(API + "/token/passkey/auth/finish", "POST", akey="anonymous_finish_passkey_login", name="Finish passkey login", business="finish_passkey_login", crud="Create",
  subject="anon", obj=OBJ("entity", "session", "Session", "User session", "Session", "created", "response", "token", "AccessToken(session)"),
  req_facts=[req("knowledge", FACT("Know", PK, REF("PasskeyChallengeID", ENT("challenge", "PasskeyChallenge", "target"))), "Caller presents the challenge id.")],
  gen=[eff(FACT("Exists", ENT("session", "Session", "created")), "action_semantics", "A session is issued on successful assertion."),
       eff(FACT("Authenticated", PK, "Session"), "auth_transition", "Caller becomes authenticated."),
       eff(FACT("Know", PK, REF("AccessToken", ENT("session", "Session", "created"))), "io_reference", "Access token returned."),
       eff(FACT("Know", PK, REF("RefreshToken", ENT("session", "Session", "created"))), "io_reference", "Refresh token returned (consumed by /api/token/renew).")],
  io_in={"challenge_id": "req_know_challenge", "webauthn": "attr_cred"},
  io_out={"token": "know", "refresh_token": "know", "uid": "observed", "email": "observed", "name": "observed", "is_admin": "observed", "server_id": "observed"},
  conf=0.6)
A(API + "/token/passkey/list", "GET", akey="user_list_own_passkeys", name="List own passkeys", business="list_own_passkeys", crud="Read",
  subject="user", obj=OBJ("collection", "passkey_list", "Passkey", "Own passkeys", "Passkey", "target", "response", "credential_id", "PasskeyCredentialID(passkey)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", PK, REF("PasskeyCredentialID", ENT("passkey", "Passkey", "target"))), "io_reference", "Credential ids returned.")],
  io_out={"credential_id": "know", "passkey_name": "observed"}, conf=0.6)
A(API + "/token/passkey/{credential_id}", "DELETE", akey="user_delete_own_passkey", name="Delete a passkey", business="delete_own_passkey", crud="Delete",
  subject="user", obj=OBJ("entity", "passkey", "Passkey", "Registered passkey", "Passkey", "target", "request", "credential_id", "PasskeyCredentialID(passkey)"),
  req_facts=[authed(), req("knowledge", FACT("Know", PK, REF("PasskeyCredentialID", ENT("passkey", "Passkey", "target"))), "Caller names the credential id.")],
  kill=[eff(FACT("Exists", ENT("passkey", "Passkey", "target")), "action_semantics", "Passkey credential removed.")],
  io_in={"credential_id": "req_know"}, conf=0.6)
