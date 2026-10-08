"""Operations referenced by the deployed web frontend (vocechat-web 0.9.122) that are absent from the
server source tree (Cargo 0.3.3) but served by the deployed server (reports 0.5.36).
Contracts come from the frontend service definitions + TS types; HAR evidence is attached at build time.
Server-side authorisation for these is not visible in source; identity_statuses are filled ONLY from HAR."""
from common import *
from ops_server import OPS

def FO(path, method, fe, *, sem, req=(), req_format="none", resp=(), resp_format="empty", value=None,
       ctypes=("application/json",), body_example=None, sk=None, notes=None, reach=True, conds=None, kind="api",
       trigger="fetch", auth="unknown", vis="black_box", vis_reason=None):
    OPS.append(dict(key=API + path, method=method, src=None, auth=auth, sem=sem, req=list(req), req_format=req_format,
                    resp=list(resp), resp_format=resp_format, value=value,
                    ctypes=list(ctypes) if resp_format != "empty" else [], idst=None, fe=list(fe),
                    body_example=body_example or {}, sk=sk or {}, notes=notes, params=None, vis=vis,
                    vis_reason=vis_reason or "Referenced by the shipped web bundle (frontend service) and therefore visible in JS/network traffic.",
                    reach=reach, conds=conds, kind=kind, trigger=trigger, origin="frontend", extra_evidence=[]))

GATE_PASSKEY = ["LoginConfig.passkey=true (deployment /admin/login/config shows passkey: false)"]

# ---------------------------------------------------------------- passkey (auth.ts)
FO("/token/passkey/register/start", "POST", [("auth.ts", "passkeyRegisterStart")], sem="start_passkey_registration",
   req_format="json", req=[TOKEN_H, B("passkey_name", path="name", desc="Label for the new passkey.")],
   resp_format="json", resp=[R("challenge_id", "challenge_id", "string", True, "Challenge id."), R("options", "options.publicKey", "object", False, "WebAuthn creation options.")],
   body_example={"name": "laptop"}, reach=False, conds=GATE_PASSKEY + ["Authenticated session"])
FO("/token/passkey/register/finish", "POST", [("auth.ts", "passkeyRegisterFinish")], sem="finish_passkey_registration",
   req_format="json", req=[TOKEN_H, B("challenge_id", desc="From register/start."), B("webauthn", "object", True, True, "Attestation credential.", path="credential"),
                           B("passkey_name", path="name", desc="Label.")],
   resp_format="json", resp=[R("bool_result", "success", "boolean", False, "Success flag."), R("message", "message", "string", False, "Message.")],
   reach=False, conds=GATE_PASSKEY)
FO("/token/passkey/auth/start", "POST", [("auth.ts", "passkeyLoginStart")], sem="start_passkey_login",
   req_format="json", req=[],
   resp_format="json", resp=[R("challenge_id", "challenge_id", "string", True, "Challenge id."), R("options", "options.publicKey", "object", False, "WebAuthn request options.")],
   reach=False, conds=GATE_PASSKEY)
FO("/token/passkey/auth/finish", "POST", [("auth.ts", "passkeyLoginFinish")], sem="finish_passkey_login",
   req_format="json", req=[B("challenge_id", desc="From auth/start."), B("webauthn", "object", True, True, "Assertion.", path="authentication")],
   resp_format="json", resp=[R("server_id", "server_id", "string", True, "Server id."), R("token", "token", "string", True, "Access token."),
                             R("refresh_token", "refresh_token", "string", True, "Refresh token."), R("expired_in", "expired_in", "integer", False, "Lifetime.")] + userinfo("user"),
   reach=False, conds=GATE_PASSKEY)
FO("/token/passkey/list", "GET", [("auth.ts", "getUserPasskeys")], sem="list_own_passkeys", req=[TOKEN_H],
   resp_format="json", resp=[R("passkey_id", "[].id", "integer", False, "Row id."), R("credential_id", "[].credential_id", "string", True, "Credential id."),
                             R("passkey_name", "[].name", "string", True, "Label.")],
   sk={"passkey_id": "bool_result"}, reach=False, conds=GATE_PASSKEY)
FO("/token/passkey/{credential_id}", "DELETE", [("auth.ts", "deletePasskey")], sem="delete_own_passkey",
   req=[TOKEN_H, P("credential_id", "string", "Credential id (URL-encoded).")], reach=False, conds=GATE_PASSKEY)

# ---------------------------------------------------------------- contacts / search / pin (user.ts)
FO("/user/contacts", "GET", [("user.ts", "getContacts")], sem="list_contacts", req=[TOKEN_H],
   resp_format="json", resp=[R("target_uid", "[].target_uid", "integer", True, "Contact uid."),
                             R("contact_status", "[].contact_info.status", "string", True, "added|blocked."),
                             R("email", "[].target_info.email", "string", True, "Contact e-mail."),
                             R("name", "[].target_info.name", "string", True, "Contact name.")])
FO("/user/search", "POST", [("user.ts", "searchUser")], sem="search_user",
   req_format="json", req=[TOKEN_H, B("search_type", flow=False, desc="id|email|name."), B("keyword", desc="Search term.")],
   resp_format="json", resp=userinfo(""), body_example={"search_type": "email", "keyword": "bob@gt.test"},
   conds=["Authenticated session", "SystemCommon.search_user_enable=true (deployment: true)"])
FO("/user/pin_chat", "POST", [("user.ts", "pinChat")], sem="pin_chat",
   req_format="json", req=[TOKEN_H, B("target_uid", "integer", False, True, "Pinned DM peer.", path="target.uid"),
                           B("target_gid", "integer", False, True, "Pinned group.", path="target.gid")],
   body_example={"target": {"gid": 1}})
FO("/user/unpin_chat", "POST", [("user.ts", "unpinChat")], sem="unpin_chat",
   req_format="json", req=[TOKEN_H, B("target_uid", "integer", False, True, "DM peer.", path="target.uid"),
                           B("target_gid", "integer", False, True, "Group.", path="target.gid")],
   body_example={"target": {"gid": 1}})
FO("/user/contact_remark", "PUT", [("user.ts", "updateRemark")], sem="update_contact_remark",
   req_format="json", req=[TOKEN_H, B("contact_uid", "integer", True, True, "Contact uid."), B("remark", desc="Remark text.")],
   sk={"contact_uid": "target_uid"}, body_example={"contact_uid": 3, "remark": "colleague"})
FO("/user/update_contact_status", "POST", [("user.ts", "updateContactStatus")], sem="update_contact_status",
   req_format="json", req=[TOKEN_H, B("target_uid", "integer", True, True, "Contact uid."), B("contact_action", path="action", desc="add|remove|block|unblock.")],
   body_example={"target_uid": 3, "action": "block"})
FO("/user/join_private", "POST", [("channel.ts", "joinPrivateChannel")], sem="join_private_group_by_invite",
   req_format="json", req=[TOKEN_H, B("magic_token", desc="Private group invite token.")],
   resp_format="json", resp=group(""), body_example={"magic_token": "<hex>"})

# ---------------------------------------------------------------- notifications (notification.ts)
NCH_IN = [B("channel_type", desc="Provider type."), B("notif_name", path="name", desc="Label."), B("enabled", "boolean", True, False, "Enabled."),
          B("notif_config", "object", True, True, "Provider config (webhook URL / bot token).", path="config"),
          B("trigger_on_all_messages", "boolean", True, False, "Trigger flag."), B("trigger_on_mentions", "boolean", True, False, "Trigger flag."),
          B("trigger_on_groups", "integer", True, True, "Gids that trigger.", path="trigger_on_groups[]"),
          B("skip_when_online", "boolean", True, False, "Skip flag.")]
NCH_OUT = [R("notif_channel_id", "id", "integer", True, "Channel id."), R("uid", "user_id", "integer", True, "Owner uid."),
           R("channel_type", "channel_type", "string", True, "Provider."), R("notif_name", "name", "string", True, "Label."),
           R("notif_config", "config", "object", True, "Provider config.")]
NSK = {"notif_name": "passkey_name", "trigger_on_groups": "gid"}
NSK = {"notif_name": "config_value", "trigger_on_groups": "gid"}
FO("/admin/notification/channel-types", "GET", [("notification.ts", "getEnabledChannelTypes")], sem="admin_list_notification_types",
   req=[TOKEN_H], resp_format="json", resp=[R("channel_type", "[].channel_type", "string", True, "Provider."), R("enabled", "[].enabled", "boolean", True, "Enabled.")])
FO("/admin/notification/channel-types", "POST", [("notification.ts", "toggleChannelType")], sem="admin_toggle_notification_type",
   req_format="json", req=[TOKEN_H, B("channel_type", desc="Provider."), B("enabled", "boolean", True, True, "Enable flag.")],
   resp_format="json", resp=[R("channel_type", "channel_type", "string", True, "Provider."), R("enabled", "enabled", "boolean", True, "Enabled.")],
   body_example={"channel_type": "discord", "enabled": True})
FO("/admin/notification/channel-types/{channel_type}", "DELETE", [("notification.ts", "deleteChannelType")], sem="admin_delete_notification_type",
   req=[TOKEN_H, P("channel_type", "string", "Provider type.")], resp_format="raw", value=("bool_result", "string", False, "Text result."), ctypes=("text/plain",))
FO("/user/notification/available-types", "GET", [("notification.ts", "getAvailableChannelTypes")], sem="list_available_notification_types",
   req=[TOKEN_H], resp_format="json", resp=[R("channel_type", "[].id", "string", True, "Provider type.")])
FO("/user/notification/channels", "GET", [("notification.ts", "getUserChannels")], sem="list_own_notification_channels",
   req=[TOKEN_H], resp_format="json", resp=[R(r["name"], "[]." + r["path"], r["type"], r["flow"], r["description"]) for r in NCH_OUT], sk=NSK)
FO("/user/notification/channels", "POST", [("notification.ts", "createUserChannel")], sem="create_notification_channel",
   req_format="json", req=[TOKEN_H] + NCH_IN, resp_format="json", resp=NCH_OUT, sk=NSK,
   body_example={"channel_type": "discord", "name": "n", "enabled": True, "config": {"webhook_url": "https://discord.com/api/webhooks/.."},
                 "trigger_on_all_messages": True, "trigger_on_mentions": True, "trigger_on_groups": [], "skip_when_online": False},
   notes="Provider config contains outbound webhook URLs -> server-side requests to user-chosen URLs (see channelSchemas.ts).")
FO("/user/notification/channels/{id}", "PUT", [("notification.ts", "updateUserChannel")], sem="update_notification_channel",
   req_format="json", req=[TOKEN_H, P("notif_channel_id", desc="Channel id.")] + NCH_IN, resp_format="json", resp=NCH_OUT, sk=NSK)
FO("/user/notification/channels/{id}", "DELETE", [("notification.ts", "deleteUserChannel")], sem="delete_notification_channel",
   req=[TOKEN_H, P("notif_channel_id", desc="Channel id.")], resp_format="raw", value=("bool_result", "string", False, "Text result."), ctypes=("text/plain",))
FO("/user/notification/channels/{id}/test", "POST", [("notification.ts", "testUserChannel")], sem="test_notification_channel",
   req=[TOKEN_H, P("notif_channel_id", desc="Channel id.")], resp_format="raw", value=("bool_result", "string", False, "Text result."), ctypes=("text/plain",))

# ---------------------------------------------------------------- group extras (channel.ts / server.ts)
FO("/group/{gid}/clear", "DELETE", [("channel.ts", "clearChannelMessage")], sem="clear_group_messages", req=[TOKEN_H, P("gid", desc="Group id.")])
FO("/group/create_invite_private_magic_link", "GET", [("channel.ts", "createPrivateInviteLink")], sem="create_private_group_invite_link",
   req=[TOKEN_H, Q("gid", "integer", True, True, "Private group id."), Q("expired_in", "integer", False, False, "Seconds."), Q("max_times", "integer", False, False, "Uses.")],
   resp_format="raw", value=("magic_link", "string", True, "Invite URL."), ctypes=("text/plain",))
FO("/group/{gid}/announcement", "GET", [("server.ts", "getGroupAnnouncement")], sem="read_group_announcement",
   req=[TOKEN_H, P("gid", desc="Group id.")],
   resp_format="json", resp=[R("gid", "announcement.gid", "integer", True, "Group id."), R("announcement", "announcement.content", "string", True, "Text."),
                             R("created_by", "announcement.created_by", "integer", True, "Author uid.")])
FO("/group/{gid}/announcement", "POST", [("server.ts", "createOrUpdateGroupAnnouncement")], sem="upsert_group_announcement",
   req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("announcement", path="content", desc="Announcement text.")],
   resp_format="json", resp=[R("gid", "gid", "integer", True, "Group id."), R("announcement", "content", "string", True, "Text."), R("created_by", "created_by", "integer", True, "Author.")],
   body_example={"content": "hello"})
FO("/group/{gid}/announcement", "DELETE", [("server.ts", "deleteGroupAnnouncement")], sem="delete_group_announcement", req=[TOKEN_H, P("gid", desc="Group id.")])

# ---------------------------------------------------------------- message bulk delete
FO("/message/bulk/{mids}", "DELETE", [("message.ts", "deleteMessages")], sem="bulk_delete_messages",
   req=[TOKEN_H, P("mids", "string", "Comma-separated message ids.")],
   resp_format="scalar", value=("count_result", "integer", False, "Number of messages deleted."))

# ---------------------------------------------------------------- admin system extras (server.ts)
COMMON = ["show_user_online_status", "webclient_auto_update", "contact_verification_enable", "chat_layout_mode", "max_file_expiry_mode",
          "only_admin_can_create_group", "ext_setting", "msg_smtp_notify_enable", "msg_smtp_notify_delay_seconds", "dm_enable",
          "add_friend_enable", "search_user_enable"]
FO("/admin/system/common", "GET", [("server.ts", "getSystemCommon")], sem="read_system_settings", req=[TOKEN_H],
   resp_format="json", resp=[R(f, f, "string" if f in ("chat_layout_mode", "max_file_expiry_mode", "ext_setting") else "boolean", True, f"System setting {f}.") for f in COMMON],
   sk={f: "common_setting" for f in COMMON})
FO("/admin/system/common", "PUT", [("server.ts", "updateSystemCommon")], sem="update_system_settings",
   req_format="json", req=[TOKEN_H] + [B(f, "string" if f in ("chat_layout_mode", "max_file_expiry_mode", "ext_setting") else "boolean", False, True, f"Setting {f}.") for f in COMMON],
   sk={f: "common_setting" for f in COMMON}, body_example={"ext_setting": "{\"admin_only_can_invite\":true}"})
FO("/admin/system/organization", "PUT", [("server.ts", "updateServer")], sem="update_organization",
   req_format="json", req=[TOKEN_H, B("org_name", path="name", required=False, desc="Name."), B("org_description", path="description", required=False, desc="Description.")],
   body_example={"name": "GT-Org-2", "description": "x"})
FO("/admin/system/files", "GET", [("server.ts", "getFiles")], sem="admin_list_files",
   req=[TOKEN_H, Q("uid", "integer", False, True, "Uploader filter."), Q("gid", "integer", False, True, "Group filter."),
        Q("file_type", required=False, flow=False, desc="Doc|PDF|Image|Audio|Video."), Q("creation_time_type", required=False, flow=False, desc="Age filter."),
        Q("page", "integer", False, False, "Page."), Q("page_size", "integer", False, False, "Size.")],
   sk={"page": "page_no"},
   resp_format="json", resp=[R("file_list_mid", "[].mid", "integer", True, "Carrying message id."), R("from_uid", "[].from_uid", "integer", True, "Uploader."),
                             R("gid", "[].gid", "integer", True, "Group."), R("content", "[].content", "string", True, "File path content.")])
FO("/admin/system/message/clear", "DELETE", [("server.ts", "clearAllMessages")], sem="admin_clear_all_messages", req=[TOKEN_H])
FO("/resource/file/delete", "DELETE", [("server.ts", "clearAllFiles")], sem="admin_delete_all_files", req=[TOKEN_H])
FO("/resource/widget-extra.css", "GET", [("server.ts", "getWidgetExtCSS")], sem="read_widget_css", kind="api",
   resp_format="raw", value=("css", "string", True, "Widget CSS."), ctypes=("text/css",))
FO("/resource/widget-extra.css", "PUT", [("server.ts", "updateWidgetExtCSS")], sem="update_widget_css",
   req_format="json", req=[TOKEN_H, B("css", path="data", desc="CSS text.")], resp_format="scalar", value=("bool_result", "boolean", False, "Result."),
   body_example={"data": ".x{}"})

# ---------------------------------------------------------------- integrations (server.ts)
FO("/admin/google_auth/public_config", "GET", [("server.ts", "getGoogleAuthPublicConfig")], sem="read_google_auth_public_config",
   resp_format="json", resp=[R("client_id", "client_id", "string", True, "Client id.")], sk={"client_id": "config_value"})
FO("/admin/github_auth/public_config", "GET", [("server.ts", "getGithubAuthPublicConfig")], sem="read_github_auth_public_config",
   resp_format="json", resp=[R("client_id", "client_id", "string", True, "Client id.")], sk={"client_id": "config_value"})
VS = ["enabled", "password", "url", "license", "state"]
FO("/admin/vocespace/config", "GET", [("server.ts", "getVocespaceConfig")], sem="read_vocespace_config", req=[TOKEN_H],
   resp_format="json", resp=[R(f, f, "boolean" if f == "enabled" else "string", True, f"VoceSpace {f}.") for f in VS],
   sk={"enabled": "enabled", "password": "config_secret", "url": "vocespace", "license": "config_secret", "state": "vocespace"})
FO("/admin/vocespace/config", "POST", [("server.ts", "updateVocespaceConfig")], sem="update_vocespace_config",
   req_format="json", req=[TOKEN_H] + [B(f, "boolean" if f == "enabled" else "string", f != "state", True, f"VoceSpace {f}.") for f in VS],
   sk={"enabled": "enabled", "password": "config_secret", "url": "vocespace", "license": "config_secret", "state": "vocespace"},
   body_example={"enabled": False, "password": "", "url": "172.17.0.2:7880", "license": ""})
FO("/admin/vocespace/health/{url}", "GET", [("server.ts", "healthCheckVocespace")], sem="check_vocespace_health",
   req=[TOKEN_H, P("url", "string", "URL-encoded VoceSpace URL probed server-side.")],
   resp_format="scalar", value=("bool_result", "boolean", False, "Healthy flag."),
   notes="Server probes a caller-supplied URL (SSRF-style primitive) per frontend contract.")
FO("/admin/agora/enabled", "GET", [("server.ts", "getAgoraStatus")], sem="read_agora_enabled", req=[TOKEN_H],
   resp_format="scalar", value=("enabled", "boolean", True, "Agora enabled."))
FO("/admin/agora/token", "POST", [("server.ts", "generateAgoraToken")], sem="create_call_token",
   req_format="json", req=[TOKEN_H, B("rtc_target_uid", "integer", False, True, "DM peer.", path="uid"), B("rtc_target_gid", "integer", False, True, "Group.", path="gid")],
   resp_format="json", resp=[R("agora_token", "agora_token", "string", True, "RTC token."), R("uid", "uid", "integer", True, "Caller uid."),
                             R("channel_name", "channel_name", "string", True, "Channel."), R("app_id", "app_id", "string", True, "App id.")],
   reach=False, conds=["Agora enabled (deployment false)"], body_example={"gid": 1})
FO("/admin/agora/channel/{page_no}/{page_size}", "GET", [("server.ts", "getAgoraChannels")], sem="list_voice_channels",
   req=[TOKEN_H, P("page_no", desc="Page."), P("page_size", desc="Size.")],
   resp_format="json", resp=[R("agora_channels", "data.channels[].channel_name", "string", True, "Channel names.")],
   reach=False, conds=["Agora enabled (deployment false)"])
# NOTE: the web client calls GET /admin/agora/channel/user/{channel_name}/false; its canonical spec route
# is /admin/agora/channel/user/{channel_name}/{hosts_only} and is defined in ops_binary.py (the deployed
# binary exposes it; the frontend simply hard-codes hosts_only=false).

# ---------------------------------------------------------------- cloudflared (server.ts + direct fetch)
FO("/admin/cloudflared/status", "GET", [("server.ts", "getCloudflaredStatus")], sem="read_tunnel_status", req=[TOKEN_H],
   resp_format="json", resp=[R("tunnel", "status", "string", True, "Status."), R("tunnel_url", "url", "string", True, "Public tunnel URL.")],
   sk={"tunnel_url": "tunnel"})
FO("/admin/cloudflared/stop", "POST", [("server.ts", "stopCloudflared")], sem="stop_tunnel", req=[TOKEN_H],
   resp_format="raw", value=("tunnel", "string", True, "Text result."), ctypes=("text/plain",))
FO("/admin/cloudflared/auto_info", "GET", [("server.ts", "getAutoTunnelInfo")], sem="read_auto_tunnel_info",
   resp_format="json", resp=[R("tunnel", "tunnel_status.status", "string", True, "Status."), R("tunnel_url", "tunnel_status.url", "string", True, "URL.")],
   sk={"tunnel_url": "tunnel"})
FO("/admin/cloudflared/start", "POST", [("routes/setting/Cloudflared/index.tsx", "api/admin/cloudflared/start")], sem="start_tunnel",
   req=[TOKEN_H], resp_format="raw", value=("tunnel", "string", True, "Streamed progress events incl. tunnel URL."), ctypes=("text/event-stream",))
FO("/admin/cloudflared/auto_stream", "GET", [("routes/onboarding/steps/welcome-page.tsx", "api/admin/cloudflared/auto_stream")], sem="stream_auto_tunnel",
   resp_format="raw", value=("tunnel", "string", True, "Streamed tunnel progress."), ctypes=("text/event-stream",))

# ---------------------------------------------------------------- custom pages (server.ts + BlankPlaceholder)
FO("/page/apikey", "GET", [("server.ts", "getPageApiKey")], sem="read_page_api_key", req=[TOKEN_H],
   resp_format="json", resp=[R("page_api_key", "key", "string", True, "Page API key.")])
FO("/page/apikey", "POST", [("server.ts", "generatePageApiKey")], sem="rotate_page_api_key", req=[TOKEN_H],
   resp_format="json", resp=[R("page_api_key", "key", "string", True, "New page API key.")])
FO("/page/{page}", "GET", [("server.ts", "getPageHtml"), ("components/BlankPlaceholder.tsx", "api/page/after_signin")], sem="read_custom_page",
   req=[P("page", "string", "landing|after_signin."), Q("t", "string", False, False, "Cache buster.")],
   resp_format="raw", value=("html", "string", True, "Admin-supplied HTML rendered in an iframe."), ctypes=("text/html",), trigger="other")
FO("/page/{page}", "PUT", [("server.ts", "uploadPageHtml")], sem="update_custom_page",
   req_format="raw", req=[TOKEN_H, P("page", "string", "Slot."), F("html", "body", "string", True, True, "HTML (text/plain).", path="")])
FO("/page/{page}", "DELETE", [("server.ts", "resetPageHtml")], sem="reset_custom_page", req=[TOKEN_H, P("page", "string", "Slot.")])

# ---------------------------------------------------------------- admin bot chat viewer (adminBotChat.ts)
FO("/admin/bot_chat/bots", "GET", [("adminBotChat.ts", "listBots")], sem="admin_list_bots", req=[TOKEN_H], resp_format="json", resp=userinfo("[]"))
FO("/admin/bot_chat/{bot_uid}/conversations", "GET", [("adminBotChat.ts", "listBotConversations")], sem="admin_list_bot_conversations",
   req=[TOKEN_H, P("bot_uid", desc="Bot uid."), Q("before", "integer", False, True, "Cursor."), Q("limit", "integer", False, False, "Size.")],
   resp_format="json", resp=[R("target_uid", "conversations[].target.uid", "integer", True, "DM peer."), R("target_gid", "conversations[].target.gid", "integer", True, "Group."),
                             R("conv_last_mid", "conversations[].last_mid", "integer", True, "Last mid.")])
FO("/admin/bot_chat/{bot_uid}/user/{uid}/history", "GET", [("adminBotChat.ts", "getAdminBotDmHistory")], sem="admin_read_bot_dm_history",
   req=[TOKEN_H, P("bot_uid", desc="Bot uid."), P("uid", desc="Peer uid."), Q("before", "integer", False, True, "Cursor."), Q("limit", "integer", False, False, "Size.")],
   resp_format="json", resp=chatmsg("[]"))
FO("/admin/bot_chat/{bot_uid}/group/{gid}/history", "GET", [("adminBotChat.ts", "getAdminBotGroupHistory")], sem="admin_read_bot_group_history",
   req=[TOKEN_H, P("bot_uid", desc="Bot uid."), P("gid", desc="Group."), Q("before", "integer", False, True, "Cursor."), Q("limit", "integer", False, False, "Size.")],
   resp_format="json", resp=chatmsg("[]"))
