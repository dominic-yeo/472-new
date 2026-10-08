"""L1 ops for the 26 operations present in the deployed 0.5.36 binary's /api/spec but absent from the
0.3.3 source tree and the frontend services. Contracts resolved from the live GET /api/spec (OpenAPI).
Server-side authorisation is taken from the spec's declared security (x-api-key for /bot/*, none declared
for the rest) and the handler family; it cannot be confirmed against source."""
from common import *
from ops_server import OPS

API = BASE + "/api"

def SPECST(ok=(200,)):
    s = sorted(set(ok))
    return {"anonymous": s, "user": s, "admin": s}

def BO(path, method, *, sem, auth, req=(), req_format="none", resp=(), resp_format="empty", value=None,
       ctypes=("application/json",), body_example=None, sk=None, notes=None, idst=None, reach=True, conds=None,
       trigger="fetch", summary=""):
    OPS.append(dict(key=API + path, method=method, src=None, auth=auth, sem=sem, req=list(req), req_format=req_format,
                    resp=list(resp), resp_format=resp_format, value=value,
                    ctypes=list(ctypes) if resp_format != "empty" else [], idst=idst, fe=[], body_example=body_example or {},
                    sk=sk or {}, notes=notes, params=None, vis="white_box",
                    vis_reason="Present only in the deployed 0.5.36 binary's OpenAPI spec (GET /api/spec); not in the 0.3.3 source tree and not called by vocechat-web 0.9.122. Identifiable black-box only via the server's own spec endpoint.",
                    reach=reach, conds=conds, kind="api", trigger=trigger, origin="binary", extra_evidence=[],
                    spec_summary=summary))

CHATMSG = [R("mid", "[].mid", "integer", True, "Message id."), R("from_uid", "[].from_uid", "integer", True, "Sender uid."),
           R("created_at", "[].created_at", "integer", False, "Timestamp."),
           R("target_uid", "[].target.uid", "integer", True, "DM peer uid."), R("target_gid", "[].target.gid", "integer", True, "Group id."),
           R("content", "[].detail.content", "string", True, "Message content."), R("content_type", "[].detail.content_type", "string", False, "MIME.")]

# ---------------- bot command subsystem (x-api-key) ----------------
BO("/bot/command", "GET", sem="bot_list_commands", auth="bot", summary="Get commands",
   req=[BOTKEY_H], resp_format="json", resp=[R("command_id", "[].id", "integer", True, "Command id."),
        R("command", "[].command", "string", True, "Command trigger."), R("command_desc", "[].description", "string", True, "Command description.")],
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/command", "POST", sem="bot_add_command", auth="bot", summary="Add command", req_format="json",
   req=[BOTKEY_H, B("command", desc="Slash-command trigger text."), B("command_desc", path="description", required=False, desc="Description.")],
   resp_format="json", resp=[R("command_id", "id", "integer", True, "New command id.")],
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]}, body_example={"command": "/weather", "description": "Weather bot"})
BO("/bot/command/{id}", "PUT", sem="bot_update_command", auth="bot", summary="Update command", req_format="json",
   req=[BOTKEY_H, P("command_id", type="integer", desc="Command id (path {id})."), B("command", desc="Trigger."), B("command_desc", path="description", required=False, desc="Description.")],
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]}, body_example={"command": "/w", "description": "d"})
BO("/bot/command/{id}", "DELETE", sem="bot_delete_command", auth="bot", summary="Delete command",
   req=[BOTKEY_H, P("command_id", type="integer", desc="Command id (path {id}).")],
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/delete/{mid}", "DELETE", sem="bot_delete_message", auth="bot", summary="Delete message",
   req=[BOTKEY_H, P("mid", desc="Message id to delete.")], resp_format="scalar", value=("mid", "integer", True, "Deleted message id."),
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/edit/{mid}", "PUT", sem="bot_edit_message", auth="bot", summary="Edit message", req_format="raw",
   req=[BOTKEY_H, P("mid", desc="Message id."), PROPS_H, F("content", "body", "string", True, True, "Replacement content (content-type selects text/markdown/file/audio/archive).", path="")],
   resp_format="scalar", value=("mid", "integer", True, "Edit-reaction record id."),
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/reply/{mid}", "POST", sem="bot_reply_message", auth="bot", summary="Reply message", req_format="raw",
   req=[BOTKEY_H, P("mid", desc="Message being replied to."), PROPS_H, F("content", "body", "string", True, True, "Reply content.", path="")],
   resp_format="scalar", value=("mid", "integer", True, "New reply message id."),
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/user/{uid}/messages", "GET", sem="bot_read_dm_history", auth="bot", summary="Get recent DM messages",
   req=[BOTKEY_H, P("uid", desc="DM peer uid."), Q("context", "integer", False, False, "Context filter.")],
   resp_format="json", resp=CHATMSG, idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/group/{gid}/messages", "GET", sem="bot_read_group_history", auth="bot", summary="Get recent group messages",
   req=[BOTKEY_H, P("gid", desc="Group id."), Q("context", "integer", False, False, "Context filter."), Q("user_id", "integer", False, True, "Filter by sender uid.")],
   resp_format="json", resp=CHATMSG, idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/secret", "GET", sem="bot_read_secret", auth="bot", summary="Get secret",
   req=[BOTKEY_H], resp_format="scalar", value=("bot_secret", "string", True, "The bot's webhook-verification secret."),
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]})
BO("/bot/secret", "PUT", sem="bot_set_secret", auth="bot", summary="Set secret", req_format="json",
   req=[BOTKEY_H, B("bot_secret", path="secret", desc="New webhook secret.")],
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]}, body_example={"secret": "<redacted>"})
BO("/bot/send_mail", "POST", sem="bot_send_mail", auth="bot", summary="Send email (bot)", req_format="json",
   req=[BOTKEY_H, B("mail_to", path="to", desc="Recipient address."), B("mail_subject", path="subject", desc="Subject."), B("mail_content", path="content", desc="Body.")],
   idst={"anonymous": [400], "user": [400], "admin": [400], "bot": [200]}, reach=False,
   conds=["Bot API key", "SMTP configured (deployment disabled)"], body_example={"to": "a@b", "subject": "s", "content": "c"})

# ---------------- user (session) ----------------
BO("/user/{uid}/command", "GET", sem="read_user_commands", auth="token", summary="Get commands",
   req=[TOKEN_H, P("uid", desc="Bot user id.")], resp_format="json",
   resp=[R("command_id", "[].id", "integer", True, "Command id."), R("command", "[].command", "string", True, "Trigger."),
         R("command_desc", "[].description", "string", True, "Description.")], idst={"anonymous": [401], "user": [200], "admin": [200]})
BO("/user/avo", "GET", sem="read_own_avatar_params", auth="token", summary="Get the current user's Avo parameters",
   req=[TOKEN_H], resp_format="json", resp=[R("avo_params", "avo_params", "object", True, "Generative avatar parameters.")],
   idst={"anonymous": [401], "user": [200], "admin": [200]})
BO("/user/avo", "PUT", sem="update_own_avatar_params", auth="token", summary="Update the current user's Avo parameters",
   req_format="json", req=[TOKEN_H, B("avo_name", path="name", required=False, desc="Seed name."), B("avo_variant", "integer", False, True, "Variant.", path="variant"),
        B("avo_hue", "integer", False, True, "Hue.", path="hue"), B("avo_style", required=False, desc="Style.", path="style"), B("avo_energy", "number", False, True, "Energy.", path="energy")],
   resp_format="json", resp=[R("avo_params", "avo_params", "object", True, "Updated avatar parameters.")],
   idst={"anonymous": [401], "user": [200], "admin": [200]}, body_example={"name": "n", "hue": 214, "variant": 2, "style": "ring", "energy": 0.3})
BO("/user/contacts/search", "POST", sem="search_contacts", auth="token", summary="Search user in contacts", req_format="json",
   req=[TOKEN_H, B("search_type", flow=False, desc="id|email."), B("keyword", desc="Search term.")],
   resp_format="json", resp=[R("uid", "uid", "integer", True, "Matched uid."), R("email", "email", "string", True, "E-mail."), R("name", "name", "string", True, "Name."), R("is_admin", "is_admin", "boolean", True, "Admin flag.")],
   sk={"search_type": "search_type", "keyword": "keyword"}, idst={"anonymous": [401], "user": [200], "admin": [200]}, body_example={"search_type": "email", "keyword": "bob@gt.test"})
BO("/user/send_mail", "POST", sem="send_mail_to_user", auth="token", summary="Send mail to another user", req_format="json",
   req=[TOKEN_H, B("to_uid", "integer", True, True, "Recipient uid."), B("mail_subject", path="subject", desc="Subject."), B("mail_content", path="content", desc="Body.")],
   idst={"anonymous": [401], "user": [200], "admin": [200]}, reach=False, conds=["SMTP configured (deployment disabled)"],
   body_example={"to_uid": 3, "subject": "s", "content": "c"})
BO("/user/update_conv", "POST", sem="update_conversation_comment", auth="token", summary="Update conversation", req_format="json",
   req=[TOKEN_H, B("conv_target_uid", "integer", False, True, "DM peer uid.", path="target.uid"), B("conv_target_gid", "integer", False, True, "Group id.", path="target.gid"),
        B("conv_comment", path="comment", required=False, desc="Conversation comment/note.")],
   sk={"conv_target_uid": "target_uid", "conv_target_gid": "target_gid", "conv_comment": "conv_comment"},
   idst={"anonymous": [401], "user": [200], "admin": [200]}, body_example={"target": {"uid": 3}, "comment": "note"})
BO("/user/events_ws", "GET", sem="subscribe_user_events_ws", auth="token_q", summary="Subscribe events via WebSocket",
   req=[Q("api-key", desc="Access token presented as a query param for the WebSocket upgrade (same as /user/events)."),
        Q("after_mid", "integer", False, True, "Resume cursor."), Q("limit", "string", False, False, "Batch size."), Q("users_version", "integer", False, True, "Users version cursor.")],
   resp_format="raw", value=("events", "string", True, "WebSocket upgrade carrying the same event stream as /user/events."),
   resp=[R("events_uid", "data.users[].uid", "integer", True, "User ids in the stream."),
         R("events_gid", "data.groups[].gid", "integer", True, "Group ids in the stream."),
         R("events_mid", "data.mid", "integer", True, "Message ids in the stream.")],
   ctypes=("application/octet-stream",), idst={"anonymous": [400, 401], "user": [101], "admin": [101]}, trigger="other",
   notes="WebSocket variant of /user/events (HTTP 101 upgrade); api-key carried as a query param, same as the SSE variant.")
BO("/voice/avo/events_ws", "GET", sem="subscribe_voice_events_ws", auth="token_q", summary="Subscribe voice/Avo events via WebSocket",
   req=[Q("api-key", required=False, desc="Access token presented as a query param for the WebSocket upgrade."),
        Q("room_type", desc="Room type (group|dm)."), Q("room_id", "integer", True, True, "Room id.")],
   resp_format="raw", value=("events", "string", True, "WebSocket upgrade for voice/Avo room events."),
   ctypes=("application/octet-stream",), idst={"anonymous": [400, 401], "user": [101], "admin": [101]}, trigger="other", reach=False,
   conds=["Voice/Avo room active"], notes="WebSocket voice/Avo room stream under /api/voice (HTTP 101). room_type/room_id select the room.")

# ---------------- token ----------------
BO("/token/parse_tokens", "POST", sem="parse_tokens", auth="none", summary="Parse token and refresh token", req_format="json",
   req=[B("token", desc="Access token to decode."), B("refresh_token", desc="Refresh token to decode.")],
   resp_format="json", resp=[R("parse_result", "", "object", False, "Decoded claims / validity of the supplied tokens.")],
   idst=SPECST((200, 400)), body_example={"token": "<access-jwt>", "refresh_token": "<refresh-jwt>"},
   notes="Unauthenticated token-introspection endpoint.")

# ---------------- admin ----------------
BO("/admin/system/update_webclient", "GET", sem="update_webclient", auth="admin", summary="Update webclient",
   req=[TOKEN_H], resp_format="empty", idst={"anonymous": [401], "user": [403], "admin": [200]},
   notes="Admin-triggered self-update of the bundled web client.")
BO("/admin/vocespace/enabled", "GET", sem="read_vocespace_enabled", auth="user", summary="VoceSpace enabled",
   req=[TOKEN_H], resp_format="scalar", value=("enabled", "boolean", True, "VoceSpace enabled flag."),
   idst={"anonymous": [401], "user": [200], "admin": [200]})
BO("/admin/agora/channel_event_callback", "POST", sem="ingest_agora_channel_event", auth="none", summary="Agora channel event callback",
   req_format="json", req=[B("agora_event", "object", True, True, "Agora RTC channel event payload (notice_id, event_type, sid, payload).", path="")],
   idst=SPECST((200,)), trigger="other",
   notes="Inbound webhook invoked by Agora's RTC service; unauthenticated public callback that ingests channel events.",
   body_example={"notice_id": "..", "event_type": 1, "sid": ".."})
BO("/admin/agora/channel/user/{channel_name}/{hosts_only}", "GET", sem="list_voice_channel_users", auth="user", summary="Get channel's users",
   req=[TOKEN_H, P("channel_name", "string", "Agora channel name."), P("hosts_only", "boolean", "Only hosts.")],
   resp_format="json", resp=[R("agora_users", "data.users[]", "integer", True, "Uids in the channel."), R("bool_result", "success", "boolean", False, "Success flag.")],
   idst={"anonymous": [401], "user": [200], "admin": [200]}, reach=False, conds=["Agora enabled (deployment disabled)"],
   notes="Canonical spec route; the web client calls it with hosts_only hard-coded to false (server.ts getAgoraUsersByChannel).")
BO("/admin/agora/channel/user/property/{uid}/{channel_name}", "GET", sem="read_voice_channel_user_property", auth="user", summary="Get user's property",
   req=[TOKEN_H, P("uid", desc="User id."), P("channel_name", "string", "Agora channel name.")],
   resp_format="json", resp=[R("agora_user_property", "data", "object", False, "Per-user property in the channel."), R("bool_result", "success", "boolean", False, "Success flag.")],
   idst={"anonymous": [401], "user": [200], "admin": [200]}, reach=False, conds=["Agora enabled (deployment disabled)"])
