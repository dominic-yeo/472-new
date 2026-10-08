"""Operations enumerated from the server source tree (vocechat-server-rust, Cargo version 0.3.3)."""
from common import *

OPS = []

def NONE(ok=(200,), err=()):
    s = sorted(set(ok) | set(err))
    return {"anonymous": s, "user": s, "admin": s}

def TOK(ok=(200,), err=(), uerr=None, aerr=None):
    return {"anonymous": [401], "user": sorted(set(ok) | set(err if uerr is None else uerr)),
            "admin": sorted(set(ok) | set(err if aerr is None else aerr))}

def ADM(ok=(200,), err=()):
    return {"anonymous": [401], "user": [403], "admin": sorted(set(ok) | set(err))}

def BOT(ok=(200,), err=()):
    return {"anonymous": [400], "user": [400], "admin": [400], "bot": sorted(set(ok) | set(err) | {401})}

def O(path, method, src, *, auth, sem, req=(), req_format="none", resp=(), resp_format="empty", value=None,
      ctypes=("application/json",), idst=None, fe=(), body_example=None, sk=None, notes=None, params=None,
      vis="black_box", vis_reason=None, reach=True, conds=None, kind="api", trigger="fetch", origin="server",
      extra_evidence=()):
    OPS.append(dict(key=API + path, method=method, src=src, auth=auth, sem=sem, req=list(req),
                    req_format=req_format, resp=list(resp), resp_format=resp_format, value=value,
                    ctypes=list(ctypes) if resp_format not in ("empty",) else [], idst=idst, fe=list(fe),
                    body_example=body_example or {}, sk=sk or {}, notes=notes, params=params, vis=vis,
                    vis_reason=vis_reason, reach=reach, conds=conds, kind=kind, trigger=trigger, origin=origin,
                    extra_evidence=list(extra_evidence)))

# =====================================================================  /token
O("/token/openid/authorize", "POST", ("token.rs", "openid_authorize"), auth="none", sem="start_oidc_authorization",
  req_format="json", req=[B("issuer", desc="OIDC issuer domain; must match an enabled LoginConfig.oidc entry."),
                          B("redirect_uri", desc="Client redirect URI registered dynamically.")],
  resp_format="json", resp=[R("auth_url", "url", "string", True, "Provider authorisation URL with PKCE challenge.")],
  idst=NONE((200,), (400, 403, 503)), fe=[("auth.ts", "getOpenid")],
  body_example={"issuer": "accounts.example.com", "redirect_uri": "http://localhost:3009/#/oauth/oidc"},
  reach=False, conds=["LoginConfig.oidc must contain an enabled issuer (deployment: oidc=[] per /admin/login/config) -> 403 otherwise"],
  notes="Feature-gated: deployment login config has oidc: [] so the handler returns 403 (token.rs:418-424).")
O("/token/metamask/nonce", "GET", ("token.rs", "metamask_nonce"), auth="none", sem="create_metamask_nonce",
  req=[Q("public_address", desc="Wallet address (lower-cased server side).")],
  resp_format="scalar", value=("nonce", "string", True, "Fresh nonce upserted into metamask_nonce table."),
  idst=NONE((200,), (400,)), fe=[("auth.ts", "getMetamaskNonce")],
  notes="Not gated by LoginConfig.metamask: any caller can upsert a nonce row for an arbitrary address (token.rs:526-545).")
O("/token/create_third_party_key", "POST", ("token.rs", "create_third_party_key"), auth="secret", sem="create_third_party_login_key",
  req_format="json", req=[H("X-SECRET", flow=True, desc="Server third-party secret (from GET /admin/system/third_party_secret)."),
                          B("userid", desc="External user id to embed."), B("username", desc="External username to embed.")],
  resp_format="scalar", value=("third_party_key", "string", True, "Hex HMAC-signed key valid for 120 s."),
  idst={"anonymous": [400, 403], "user": [400, 403], "admin": [400, 403], "secret_holder": [200]},
  body_example={"userid": "ext-1", "username": "ext-user"}, vis="white_box",
  vis_reason="Not referenced by the web frontend (no service/fetch call); identifiable from server source or the OpenAPI spec only.",
  conds=["Knowledge of the server third_party_secret (admin can read it via GET /admin/system/third_party_secret)"],
  notes="Missing X-SECRET header -> 400 (poem required header); wrong secret -> 403 (token.rs:556).")
O("/token/login_guest", "GET", ("token.rs", "login_guest"), auth="none", sem="login_as_guest",
  resp_format="json", resp=[R("server_id", "server_id", "string", True, "Server id."),
                            R("token", "token", "string", True, "Access token."),
                            R("refresh_token", "refresh_token", "string", True, "Refresh token."),
                            R("expired_in", "expired_in", "integer", False, "Access token lifetime (s).")]
                           + userinfo("user"),
  idst=NONE((200,), (403,)), fe=[("auth.ts", "guestLogin")],
  conds=["LoginConfig.guest=true (deployment /admin/login/config shows guest: true)"],
  notes="Creates a new guest user row on every call (token.rs:587-594).")
O("/token/login", "POST", ("token.rs", "login"), auth="none", sem="login",
  req_format="json",
  req=[B("type", path="credential.type", flow=False, desc="Credential discriminator password|magiclink|google|github|oidc|metamask|thirdparty (selects which of the conditional fields below apply)."),
       B("email", path="credential.email", required=False, desc="Account e-mail. Required ONLY when credential.type=password.", sel=["password"]),
       B("password", path="credential.password", required=False, desc="Account password. Required ONLY when credential.type=password.", sel=["password"]),
       B("magic_token", path="credential.magic_token", required=False, desc="Login/invite magic token. Required for type=magiclink; optional for oauth types.", sel=["magiclink", "google", "github", "oidc", "metamask"]),
       B("extra_name", path="credential.extra_name", required=False, flow=False, desc="Name for auto-registration via magic link (type=magiclink).", sel=["magiclink"]),
       B("id_token", path="credential.id_token", required=False, desc="Google ID token. Required ONLY when credential.type=google.", sel=["google"]),
       B("code", path="credential.code", required=False, desc="OAuth code. Required ONLY when credential.type=github|oidc.", sel=["github", "oidc"]),
       B("state", path="credential.state", required=False, desc="OIDC state. Required ONLY when credential.type=oidc.", sel=["oidc"]),
       B("public_address", path="credential.public_address", required=False, desc="Wallet address. Required ONLY when credential.type=metamask.", sel=["metamask"]),
       B("nonce", path="credential.nonce", required=False, desc="Nonce from /token/metamask/nonce. Required ONLY when credential.type=metamask.", sel=["metamask"]),
       B("signature", path="credential.signature", required=False, desc="Wallet signature. Required ONLY when credential.type=metamask.", sel=["metamask"]),
       B("key", path="credential.key", required=False, desc="Third-party key from /token/create_third_party_key. Required ONLY when credential.type=thirdparty.", sel=["thirdparty"]),
       B("device", required=False, desc="Client device id (default 'unknown')."),
       B("device_token", required=False, desc="Optional FCM token.")],
  resp_format="json", resp=[R("server_id", "server_id", "string", True, "Server id."),
                            R("token", "token", "string", True, "Access token."),
                            R("refresh_token", "refresh_token", "string", True, "Refresh token."),
                            R("expired_in", "expired_in", "integer", False, "Access token lifetime (s).")]
                           + userinfo("user"),
  idst=NONE((200,), (400, 401, 403, 404, 409, 410, 423, 451)), fe=[("auth.ts", "login")],
  body_example={"credential": {"type": "password", "email": "test@test.com", "password": "<redacted>"}, "device": "web:<id>", "device_token": ""},
  notes="Single endpoint multiplexes 7 credential types via credential.type; only password/magiclink(and thirdparty if enabled) are enabled in the deployment (login config: password=true, magic_link=true, google/github/metamask/third_party=false, oidc=[]). Status codes from LoginApiResponse (token.rs:264-287) plus 451 license check (license.rs:105).")
O("/token/bind", "POST", ("token.rs", "bind"), auth="token_ng", sem="bind_external_credential",
  req_format="json",
  req=[TOKEN_H, B("type", path="credential.type", flow=False, desc="google|github|oidc|metamask"),
       B("id_token", path="credential.id_token", desc="Google id token.", sel=["google"]),
       B("code", path="credential.code", desc="OAuth code.", sel=["github", "oidc"]),
       B("state", path="credential.state", desc="OIDC state.", sel=["oidc"]),
       B("public_address", path="credential.public_address", desc="Wallet address.", sel=["metamask"]),
       B("nonce", path="credential.nonce", desc="Wallet nonce.", sel=["metamask"]),
       B("signature", path="credential.signature", desc="Wallet signature.", sel=["metamask"])],
  idst=TOK((200,), (401, 403, 409)), reach=False, vis="white_box",
  vis_reason="No frontend service calls /token/bind in vocechat-web 0.9.122; known from server source/OpenAPI only.",
  conds=["Non-guest session", "google/github/metamask/oidc enabled in LoginConfig (all disabled in deployment -> 403)"],
  body_example={"credential": {"type": "metamask", "public_address": "0x..", "nonce": "..", "signature": ".."}})
O("/token/credentials", "GET", ("token.rs", "credentials"), auth="token", sem="read_own_credentials",
  req=[TOKEN_H], resp_format="json",
  resp=[R("password", "password", "boolean", True, "Whether a password is set."),
        R("google", "google", "string", True, "Bound Google e-mail."),
        R("metamask", "metamask", "string", True, "Bound wallet address."),
        R("oidc", "oidc[]", "string", True, "Bound OIDC issuers.")],
  sk={"password": "credential_flags", "google": "credential_flags", "metamask": "credential_flags", "oidc": "credential_flags"},
  idst=TOK((200,)), fe=[("auth.ts", "getCredentials")])
O("/token/renew", "POST", ("token.rs", "renew"), auth="none", sem="renew_session_token",
  req_format="json", req=[B("token", desc="Current (possibly expired) access token."), B("refresh_token", desc="Refresh token stored for (uid, device).")],
  resp_format="json", resp=[R("token", "token", "string", True, "New access token."), R("refresh_token", "refresh_token", "string", True, "Rotated refresh token."),
                            R("expired_in", "expired_in", "integer", False, "Lifetime (s).")],
  idst=NONE((200,), (401,)), fe=[("auth.ts", "renew"), ("base.query.ts", None)],
  body_example={"token": "<access-jwt>", "refresh_token": "<refresh-jwt>"},
  notes="No session header required; validity proven by the token pair (token.rs:1211-1278).")
O("/token/logout", "GET", ("token.rs", "logout"), auth="token", sem="logout",
  req=[TOKEN_H], idst=TOK((200,)), fe=[("auth.ts", "logout")],
  notes="Deletes refresh_token+device rows for (uid, device) and kicks SSE; the stateless access token remains valid until expiry (token.rs:1281-1322).")
O("/token/device_token", "PUT", ("token.rs", "update_device_token"), auth="token_ng", sem="update_device_push_token",
  req_format="json", req=[TOKEN_H, B("device_token", required=False, desc="FCM token for the current device (nullable).")],
  idst=TOK((200,), (403, 404)), fe=[("auth.ts", "updateDeviceToken")], body_example={"device_token": "fcm-token"})

# =====================================================================  /user
O("/user/check_magic_token", "POST", ("user.rs", "check_magic_token"), auth="none", sem="validate_magic_token",
  req_format="json", req=[B("magic_token", desc="Magic token to validate.")],
  resp_format="scalar", value=("bool_result", "boolean", False, "true if the token parses and signature verifies."),
  idst=NONE((200,)), fe=[("auth.ts", "checkMagicTokenValid")], body_example={"magic_token": "<hex>"})
O("/user/register", "POST", ("user.rs", "register"), auth="none", sem="register_user_account",
  req_format="json",
  req=[B("magic_token", required=False, desc="Invitation token (required when who_can_sign_up=InvitationOnly); may embed gid/email/password."),
       B("email", required=False, desc="E-mail."), B("password", required=False, desc="Password."),
       B("name", required=False, desc="Display name (max 32)."),
       B("gender", "integer", False, False, "Gender."), B("language", required=False, flow=False, desc="Language."),
       B("device", required=False, desc="Device id (frontend sends 'browser')."), B("device_token", required=False, desc="FCM token.")],
  resp_format="json", resp=[R("server_id", "server_id", "string", True, "Server id."),
                            R("token", "token", "string", True, "Access token."),
                            R("refresh_token", "refresh_token", "string", True, "Refresh token."),
                            R("expired_in", "expired_in", "integer", False, "Lifetime.")] + userinfo("user"),
  idst=NONE((200,), (403, 409, 412, 413)), fe=[("auth.ts", "register")],
  body_example={"name": "test", "email": "test@test.com", "password": "<redacted>", "gender": 0, "device": "browser"},
  notes="who_can_sign_up=EveryOne in deployment, so anonymous self-registration succeeds (runtime auth.har#10). Registering with a group invite token adds the new uid to that private group (user.rs:430-459).")
O("/user/check_email", "GET", ("user.rs", "check_email"), auth="none", sem="check_email_available",
  req=[Q("email", desc="E-mail to test.")],
  resp_format="scalar", value=("bool_result", "boolean", False, "true when NOT already used (cache.check_email_conflict)."),
  idst=NONE((200,), (400,)), fe=[("auth.ts", "checkEmail")],
  notes="Unauthenticated account-enumeration oracle (user.rs:464-468).")
O("/user/send_reg_magic_link", "POST", ("user.rs", "send_reg_magic_link"), auth="none", sem="send_registration_magic_link",
  req_format="json", req=[B("magic_token", desc="Invitation token (verified only when SMTP enabled)."), B("email", desc="E-mail."), B("password", desc="Password to embed.")],
  resp_format="json", resp=[R("new_magic_token", "new_magic_token", "string", True, "Confirmed registration token (empty when mail sent)."),
                            R("mail_is_sent", "mail_is_sent", "boolean", False, "Whether an e-mail was dispatched.")],
  idst=NONE((200,), (400, 403, 409)), fe=[("auth.ts", "sendRegMagicLink")],
  body_example={"magic_token": "<hex>", "email": "x@y.z", "password": "<redacted>"},
  notes="With SMTP disabled (deployment) the server signs and returns a confirmed register token embedding the supplied email/password without validating the input magic_token (user.rs:526-541, 600-604).")
O("/user/send_login_magic_link", "POST", ("user.rs", "send_login_magic_link"), auth="none", sem="send_login_magic_link",
  req=[Q("email", desc="Account e-mail to mail a login link to.")],
  resp_format="raw", value=("bool_result", "string", False, "Fixed confirmation text."), ctypes=("text/plain",),
  idst=NONE((200,), (400, 406, 451, 500, 503)), fe=[("auth.ts", "sendLoginMagicLink")], reach=False,
  conds=["LoginConfig.magic_link=true", "SMTP configured (deployment SMTP disabled -> mail cannot be delivered)"],
  notes="Requires working SMTP to be useful; deployment /admin/smtp/enabled=false.")
O("/user/me", "GET", ("user.rs", "me"), auth="token", sem="read_own_profile", req=[TOKEN_H],
  resp_format="json", resp=userinfo(""), idst=TOK((200,)), vis="black_box",
  vis_reason="Not called by vocechat-web 0.9.122 but trivially guessable REST path next to /user/{uid}; documented in OpenAPI.")
O("/user/{uid}", "GET", ("user.rs", "get_user"), auth="none", sem="read_user_profile",
  req=[P("uid", desc="Target user id.")], resp_format="json", resp=userinfo(""),
  idst=NONE((200,), (404,)), vis_reason="Guessable from /user listing; no auth extractor in handler.",
  notes="No Token parameter: unauthenticated profile (incl. e-mail) lookup by uid (user.rs:656-664).")
O("/user/change_password", "POST", ("user.rs", "change_password"), auth="token_ng", sem="change_own_password",
  req_format="json", req=[TOKEN_H, B("old_password", desc="Current password."), B("new_password", desc="New password.")],
  idst=TOK((200,), (401, 403)), fe=[("auth.ts", "updatePassword")], body_example={"old_password": "<redacted>", "new_password": "<redacted>"})
O("/user", "PUT", ("user.rs", "update_user"), auth="token_ng", sem="update_own_profile",
  req_format="json", req=[TOKEN_H, B("name", required=False, desc="New display name."), B("gender", "integer", False, False, "Gender."),
                          B("language", required=False, flow=False, desc="Language.")],
  resp_format="json", resp=userinfo(""), idst=TOK((200,), (400, 401, 403, 409)), fe=[("user.ts", "updateInfo")],
  body_example={"name": "new-name"})
O("/user/avatar", "POST", ("user.rs", "upload_avatar"), auth="token_ng", sem="upload_own_avatar",
  req_format="raw", req=[TOKEN_H, F("avatar", "body", "binary", True, True, "PNG bytes (Content-Type image/png).", path="")],
  idst=TOK((200,), (401, 403, 413, 415)), fe=[("user.ts", "updateAvatar")])
O("/user", "GET", ("user.rs", "get_all_users"), auth="none", sem="list_users",
  resp_format="json", resp=userinfo("[]"), idst=NONE((200,)), fe=[("user.ts", "getUsers")],
  notes="Source handler has no Token -> anonymous listing of all non-guest users with e-mails (user.rs:891-904).")
O("/user/{uid}/send", "POST", ("user.rs", "send"), auth="token_ng", sem="send_direct_message",
  req_format="raw", req=[TOKEN_H, P("uid", desc="Recipient user id."), PROPS_H,
                         F("content", "body", "string", True, True, "Body: text/plain | text/markdown | vocechat/file JSON {path} | vocechat/archive path (Content-Type selects).", path="")],
  resp_format="scalar", value=("mid", "integer", True, "New message id."),
  idst=TOK((200,), (400, 401, 403, 404)), fe=[("user.ts", "sendMsg")])
O("/user/{uid}/history", "GET", ("user.rs", "get_history_messages"), auth="token", sem="read_direct_message_history",
  req=[TOKEN_H, P("uid", desc="DM peer id."), Q("before", "integer", False, True, "Cursor mid."), Q("limit", "integer", False, False, "Page size (default 300).")],
  resp_format="json", resp=chatmsg("[]"), idst=TOK((200,)), fe=[("message.ts", "loadMoreMessages")])
O("/user/events", "GET", ("user.rs", "events"), auth="token_q", sem="subscribe_user_events",
  req=[Q("api-key", desc="Access token (EventSource cannot set headers)."), Q("after_mid", "integer", False, True, "Resume after mid."),
       Q("users_version", "integer", False, True, "Users log version cursor."), Q("limit", "string", False, False, "Sent by client; not read by source handler.")],
  resp_format="raw", value=("events", "string", True, "SSE stream (users_snapshot, users_state, related_groups, user_settings, chat, kick, heartbeat, ...)."),
  resp=[R("events_uid", "data.users[].uid", "integer", True, "User ids delivered in users_snapshot/users_state/users_log events."),
        R("events_gid", "data.groups[].gid", "integer", True, "Group ids delivered in related_groups/joined_group events."),
        R("events_mid", "data.mid", "integer", True, "Message ids delivered in chat events."),
        R("events_email", "data.users[].email", "string", False, "User e-mails exposed in users_snapshot (disclosure, but not an object reference).")],
  ctypes=("text/event-stream",), idst={"anonymous": [400, 401], "user": [200, 403], "admin": [200, 403]},
  fe=[("hooks/useStreaming/index.ts", "new EventSource")], trigger="other",
  notes="403 when the token's device has no device row (create_user_event_receiver user.rs:1694-1726). Stream carries uid/gid/mid references (and every non-guest user's e-mail in users_snapshot) that enable follow-on actions.")
O("/user/devices", "GET", ("user.rs", "get_devices"), auth="token", sem="list_own_devices", req=[TOKEN_H],
  resp_format="json", resp=[R("device", "[]", "string", True, "Device ids of current user.")], idst=TOK((200,)),
  vis_reason="Not called by web frontend; guessable sibling of DELETE /user/devices/{device}; in OpenAPI.")
O("/user/devices/{device}", "DELETE", ("user.rs", "delete_device"), auth="token_ng", sem="delete_own_device",
  req=[TOKEN_H, P("device", "string", "Device id to sign out.")], idst=TOK((200,), (401, 403)),
  vis_reason="Not called by web frontend; REST path documented in OpenAPI.")
O("/user/mute", "POST", ("user.rs", "mute"), auth="token", sem="update_mute_settings",
  req_format="json", req=[TOKEN_H, B("add_users_uid", "integer", False, True, "Users to mute.", path="add_users[].uid"),
                          B("add_users_expired_in", "integer", False, True, "Mute seconds.", path="add_users[].expired_in"),
                          B("add_groups_gid", "integer", False, True, "Groups to mute.", path="add_groups[].gid"),
                          B("add_groups_expired_in", "integer", False, True, "Mute seconds.", path="add_groups[].expired_in"),
                          B("remove_users", "integer", False, True, "Uids to unmute.", path="remove_users[]"),
                          B("remove_groups", "integer", False, True, "Gids to unmute.", path="remove_groups[]")],
  sk={"add_users_uid": "uid", "remove_users": "uid", "add_groups_gid": "gid", "remove_groups": "gid",
      "add_users_expired_in": "mute_expired_in", "add_groups_expired_in": "mute_expired_in"},
  idst=TOK((200,), (400, 401)), fe=[("user.ts", "updateMuteSetting")], body_example={"add_groups": [{"gid": 1}]})
O("/user/burn-after-reading", "POST", ("user.rs", "update_burn_after_reading"), auth="token", sem="update_burn_after_reading",
  req_format="json", req=[TOKEN_H, B("users_uid", "integer", False, True, "Peer uid.", path="users[].uid"),
                          B("users_expires_in", "integer", False, True, "Seconds; 0 removes.", path="users[].expires_in"),
                          B("groups_gid", "integer", False, True, "Group id.", path="groups[].gid"),
                          B("groups_expires_in", "integer", False, True, "Seconds; 0 removes.", path="groups[].expires_in")],
  sk={"users_uid": "uid", "groups_gid": "gid", "users_expires_in": "expires_in", "groups_expires_in": "expires_in"},
  idst=TOK((200,), (400, 401)), fe=[("user.ts", "updateAutoDeleteMsg")], body_example={"groups": [{"gid": 1, "expires_in": 3600}]})
O("/user/read-index", "POST", ("user.rs", "update_read_index"), auth="token", sem="update_read_index",
  req_format="json", req=[TOKEN_H, B("users_uid", "integer", False, True, "Peer uid.", path="users[].uid"),
                          B("users_mid", "integer", False, True, "Last read mid.", path="users[].mid"),
                          B("groups_gid", "integer", False, True, "Group id.", path="groups[].gid"),
                          B("groups_mid", "integer", False, True, "Last read mid.", path="groups[].mid")],
  sk={"users_uid": "uid", "groups_gid": "gid", "users_mid": "mid", "groups_mid": "mid"},
  idst=TOK((200,), (400, 401)), fe=[("message.ts", "readMessage")], body_example={"groups": [{"gid": 1, "mid": 27}]})
O("/user/delete", "DELETE", ("user.rs", "delete_current_user"), auth="token", sem="delete_own_account",
  req=[TOKEN_H], idst=TOK((200,), (404,)), fe=[("auth.ts", "deleteCurrentAccount")])
O("/user/update_fcm_token", "PUT", ("user.rs", "update_fcm_token"), auth="token", sem="register_device_fcm_token",
  req_format="raw", req=[TOKEN_H, Q("device", desc="Device id to upsert."), F("fcm_token", "body", "string", True, True, "FCM token (text/plain).", path="")],
  idst=TOK((200,), (401,)), vis_reason="Mobile-client endpoint; not used by the web frontend; documented in OpenAPI.",
  notes="Upserts an arbitrary device row for the caller (user.rs:1475-1516); a fresh device row also satisfies the SSE device check.")

# =====================================================================  /group
O("/group", "POST", ("group.rs", "create"), auth="token_ng", sem="create_group",
  req_format="json", req=[TOKEN_H, B("group_name", path="name", desc="Group name."), B("description", required=False, desc="Description."),
                          B("members", "integer", False, True, "Initial member uids (private only).", path="members[]"),
                          B("is_public", "boolean", False, True, "Public group (admin only).")],
  resp_format="json", resp=[R("gid", "gid", "integer", True, "New group id."), R("created_at", "created_at", "integer", False, "Timestamp.")],
  idst=TOK((200,), (400, 401, 403)), fe=[("channel.ts", "createChannel")],
  body_example={"name": "test", "description": "", "is_public": True})
O("/group/{gid}/avatar", "POST", ("group.rs", "upload_avatar"), auth="token", sem="upload_group_avatar",
  req_format="raw", req=[TOKEN_H, P("gid", desc="Group id."), F("group_avatar", "body", "binary", True, True, "PNG bytes.", path="")],
  idst=TOK((200,), (401, 403, 413, 415)), fe=[("channel.ts", "updateIcon")],
  notes="Unknown gid returns 401 (not 404) (group.rs:256-259).")
O("/group/{gid}", "DELETE", ("group.rs", "delete"), auth="token", sem="delete_group",
  req=[TOKEN_H, P("gid", desc="Group id.")], idst=TOK((200,), (403, 404)), fe=[("channel.ts", "removeChannel")])
O("/group/{gid}", "PUT", ("group.rs", "update"), auth="token", sem="update_group",
  req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("group_name", required=False, path="name", desc="New name."),
                          B("description", required=False, desc="New description."), B("owner", "integer", False, True, "Transfer ownership to member uid.")],
  idst=TOK((200,), (400, 403, 404)), fe=[("channel.ts", "updateChannel")], body_example={"name": "renamed"},
  notes="Deployed build also accepts show_email/add_friend/only_owner_can_send_msg/dm_to_member/ext_setting (frontend ChannelDTO; runtime localhost.har#25 body {only_owner_can_send_msg:true}); not present in this source tree.")
O("/group/{gid}/change_type", "POST", ("group.rs", "change_type"), auth="token", sem="change_group_visibility",
  req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("is_public", "boolean", True, True, "Target visibility."),
                          B("members", "integer", False, True, "Members when making private.", path="members[]")],
  idst=TOK((200,), (403, 404)), fe=[("channel.ts", "changeChannelType")], body_example={"is_public": True})
O("/group/{gid}/leave", "GET", ("group.rs", "leave"), auth="token", sem="leave_group",
  req=[TOKEN_H, P("gid", desc="Group id.")], idst=TOK((200,), (403, 404)), fe=[("channel.ts", "leaveChannel")])
O("/group/{gid}", "GET", ("group.rs", "get"), auth="none", sem="read_group", req=[P("gid", desc="Group id.")],
  resp_format="json", resp=group(""), idst=NONE((200,), (404,)), fe=[("channel.ts", "getChannel")],
  notes="No Token extractor in source: anonymous read of any group incl. private member lists and pinned content (group.rs:682-692).")
O("/group", "GET", ("group.rs", "get_related_groups"), auth="token", sem="list_related_groups",
  req=[TOKEN_H, Q("public_only", "boolean", False, False, "Only public groups.")],
  resp_format="json", resp=group("[]"), idst=TOK((200,)), fe=[("channel.ts", "getChannels")])
O("/group/{gid}/members/add", "POST", ("group.rs", "add_members"), auth="token", sem="add_group_members",
  req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("members", "integer", True, True, "Uids to add (JSON array root).", path="[]")],
  idst=TOK((200,), (400, 403, 404)), fe=[("channel.ts", "addMembers")], body_example=[3],
  notes="Any existing member (not only the owner) may add members to a private group (group.rs:731-737).")
O("/group/{gid}/members/remove", "POST", ("group.rs", "remove_members"), auth="token", sem="remove_group_members",
  req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("members", "integer", True, True, "Uids to remove (JSON array root).", path="[]")],
  idst=TOK((200,), (403, 404)), fe=[("channel.ts", "removeMembers")], body_example=[6])
O("/group/{gid}/send", "POST", ("group.rs", "send"), auth="token_ng", sem="send_group_message",
  req_format="raw", req=[TOKEN_H, P("gid", desc="Group id."), PROPS_H,
                         F("content", "body", "string", True, True, "Message body (text/plain|text/markdown|vocechat/file JSON|vocechat/archive).", path="")],
  resp_format="scalar", value=("mid", "integer", True, "New message id."),
  idst=TOK((200,), (400, 401, 403, 404)), fe=[("channel.ts", "sendChannelMsg")])
O("/group/create_reg_magic_link", "GET", ("group.rs", "create_reg_magic_link"), auth="token", sem="create_invite_link",
  req=[TOKEN_H, Q("gid", "integer", False, True, "Group to auto-join (optional)."), Q("expired_in", "integer", False, False, "Seconds."),
       Q("max_times", "integer", False, False, "Max uses.")],
  resp_format="raw", value=("magic_link", "string", True, "{frontend}/?magic_token=..#/register"), ctypes=("text/plain",),
  idst=TOK((200,), (403, 404)), fe=[("channel.ts", "createInviteLink")],
  notes="Any authenticated user can mint invite links (no admin check in source; deployment ext_setting admin_only_can_invite may restrict newer build).")
O("/group/{gid}/history", "GET", ("group.rs", "get_history_messages"), auth="token", sem="read_group_message_history",
  req=[TOKEN_H, P("gid", desc="Group id."), Q("before", "integer", False, True, "Cursor mid."), Q("limit", "integer", False, False, "Page size.")],
  resp_format="json", resp=chatmsg("[]"), idst=TOK((200,), (403, 404)), fe=[("message.ts", "loadMoreMessages")])
O("/group/{gid}/agora_token", "GET", ("group.rs", "generate_agora_token"), auth="token", sem="create_group_call_token",
  req=[TOKEN_H, P("gid", desc="Group id.")],
  resp_format="json", resp=[R("agora_token", "agora_token", "string", True, "RTC token."), R("app_id", "app_id", "string", True, "Agora app id."),
                            R("uid", "uid", "integer", True, "Caller uid."), R("channel_name", "channel_name", "string", True, "vocechat:group:{gid}"),
                            R("expired_in", "expired_in", "integer", False, "Lifetime.")],
  idst=TOK((200,), (403, 404, 503)), reach=False, conds=["Agora configured (deployment /admin/agora/enabled=false -> 503)", "Caller is member of the group"],
  vis_reason="Web frontend 0.9.122 uses POST /admin/agora/token instead; known from source/OpenAPI.", vis="white_box")
O("/group/{gid}/pin", "POST", ("group.rs", "pin_message"), auth="token", sem="pin_group_message",
  req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("mid", "integer", True, True, "Message to pin.")],
  idst=TOK((200,), (403, 404, 409)), fe=[("message.ts", "pinMessage")], body_example={"mid": 27},
  notes="Does not check that mid belongs to gid (group.rs:1012-1017).")
O("/group/{gid}/unpin", "POST", ("group.rs", "unpin_message"), auth="token", sem="unpin_group_message",
  req_format="json", req=[TOKEN_H, P("gid", desc="Group id."), B("mid", "integer", True, True, "Message to unpin.")],
  idst=TOK((200,), (403, 404)), fe=[("message.ts", "unpinMessage")], body_example={"mid": 27})

# =====================================================================  /message
O("/message/{mid}/edit", "PUT", ("message_api.rs", "edit"), auth="token_ng", sem="edit_message",
  req_format="raw", req=[TOKEN_H, P("mid", desc="Message id."), PROPS_H, F("content", "body", "string", True, True, "Replacement content.", path="")],
  resp_format="scalar", value=("mid", "integer", True, "Id of the appended edit-reaction record."),
  idst=TOK((200,), (403, 404)), fe=[("message.ts", "editMessage")],
  notes="Implemented as an appended Reaction{Edit} message, not an in-place update (message_api.rs:45-63).")
O("/message/{mid}/like", "PUT", ("message_api.rs", "like"), auth="token_ng", sem="react_to_message",
  req_format="json", req=[TOKEN_H, P("mid", desc="Message id."), B("action", desc="Emoji from allow-list.")],
  resp_format="scalar", value=("mid", "integer", True, "Id of the reaction record."),
  idst=TOK((200,), (400, 403, 404)), fe=[("message.ts", "reactMessage")], body_example={"action": "👍"},
  notes="can_reaction(Like) returns true for any user; no membership check on target conversation (message.rs:170-174).")
O("/message/{mid}", "DELETE", ("message_api.rs", "delete"), auth="token_ng", sem="delete_message",
  req=[TOKEN_H, P("mid", desc="Message id.")], resp_format="scalar", value=("mid", "integer", True, "Id of the delete-reaction record."),
  idst=TOK((200,), (403, 404)), fe=[("message.ts", "deleteMessage")])
O("/message/{mid}/reply", "POST", ("message_api.rs", "reply"), auth="token_ng", sem="reply_to_message",
  req_format="raw", req=[TOKEN_H, P("mid", desc="Message being replied to."), PROPS_H, F("content", "body", "string", True, True, "Reply content.", path="")],
  resp_format="scalar", value=("mid", "integer", True, "New reply message id."),
  idst=TOK((200,), (403, 404)), fe=[("message.ts", "replyMessage")])

# =====================================================================  /resource
O("/resource/organization/logo", "GET", ("resource.rs", "get_organization_logo"), auth="none", sem="read_organization_logo",
  req=[Q("t", "string", False, False, "Cache buster.")], resp_format="raw", value=("logo", "binary", False, "PNG logo."),
  ctypes=("image/png",), idst=NONE((200, 304)), fe=[("routes/login/index.tsx", "resource/organization/logo")], trigger="other")
O("/resource/avatar", "GET", ("resource.rs", "get_avatar"), auth="none", sem="read_user_avatar",
  req=[Q("uid", "integer", True, True, "User id."), Q("t", "string", False, False, "Cache buster.")],
  resp_format="raw", value=("avatar", "binary", False, "PNG avatar."), ctypes=("image/png",), idst=NONE((200, 304), (404,)),
  fe=[("app/slices/users.ts", "resource/avatar")], trigger="other")
O("/resource/group_avatar", "GET", ("resource.rs", "get_group_avatar"), auth="none", sem="read_group_avatar",
  req=[Q("gid", "integer", True, True, "Group id."), Q("t", "string", False, False, "Cache buster.")],
  resp_format="raw", value=("group_avatar", "binary", False, "PNG avatar."), ctypes=("image/png", "text/plain"), idst=NONE((200, 304), (404,)),
  fe=[("app/slices/channels.ts", "resource/group_avatar")], trigger="other")
O("/resource/file/prepare", "POST", ("resource.rs", "upload_file_prepare"), auth="token", sem="prepare_file_upload",
  req_format="json", req=[TOKEN_H, B("content_type", required=False, flow=False, desc="MIME type."), B("filename", required=False, desc="Original name.")],
  resp_format="scalar", value=("file_id", "string", True, "Upload UUID."),
  idst=TOK((200,)), fe=[("message.ts", "prepareUploadFile")], body_example={"content_type": "image/png", "filename": "a.png"})
O("/resource/file/upload", "POST", ("resource.rs", "upload_file"), auth="token", sem="upload_file_chunk",
  req_format="form", req=[TOKEN_H, B("file_id", desc="UUID from /file/prepare."), B("chunk_data", "binary", True, True, "Chunk bytes."),
                          B("chunk_is_last", "boolean", False, False, "Finalise flag.")],
  resp_format="json", resp=[R("path", "path", "string", True, "Stored file path (only on last chunk; else null)."),
                            R("size", "size", "integer", False, "Size."), R("hash", "hash", "string", True, "SHA-256."),
                            R("image_properties", "image_properties", "object", False, "Width/height for images.")],
  idst=TOK((200,), (400,)), fe=[("message.ts", "uploadFile")],
  notes="file_id is joined into a filesystem path without validation (resource.rs:206-211); any session can append to any pending upload id.")
O("/resource/file", "GET", ("resource.rs", "download_file"), auth="none", sem="download_file",
  req=[Q("file_path", desc="Stored path yyyy/m/d/uuid."), Q("thumbnail", "boolean", False, False, "Thumbnail variant."),
       Q("download", "boolean", False, False, "Content-Disposition attachment.")],
  resp_format="raw", value=("file_bytes", "binary", True, "File bytes with stored content-type."), ctypes=("application/octet-stream",),
  idst=NONE((200,), (400, 404)), fe=[("hooks/useUploadFile.ts", "resource/file?file_path")], trigger="other",
  notes="No auth: anyone with the path can download (resource.rs:341-381). Frontend also issues HEAD (message.ts preCheckFileFromUrl).")
O("/resource/archive", "POST", ("resource.rs", "create_archive"), auth="token", sem="create_message_archive",
  req_format="json", req=[TOKEN_H, B("mid_list", "integer", True, True, "Messages to archive.", path="mid_list[]")],
  resp_format="scalar", value=("archive_path", "string", True, "Archive path yyyy/m/d/uuid."),
  idst=TOK((200,), (400, 403, 404)), fe=[("message.ts", "createArchive")], body_example={"mid_list": [27, 28]})
O("/resource/archive", "GET", ("resource.rs", "get_archive_index"), auth="none", sem="read_message_archive",
  req=[Q("file_path", desc="Archive path.")], sk={"file_path": "archive_path"},
  resp_format="json", resp=archive(""), idst=NONE((200,), (400, 404)), fe=[("message.ts", "getArchiveMessage")],
  notes="No auth on archive read (resource.rs:414-430).")
O("/resource/archive/attachment", "GET", ("resource.rs", "get_archive_attachment"), auth="none", sem="download_archive_attachment",
  req=[Q("file_path", desc="Archive path."), Q("attachment_id", "integer", True, True, "Attachment index."), Q("download", "boolean", False, False, "Disposition.")],
  sk={"file_path": "archive_path"}, resp_format="raw", value=("attachment_bytes", "binary", True, "Attachment bytes."),
  ctypes=("application/octet-stream",), idst=NONE((200,), (400, 404)), fe=[("utils.tsx", "resource/archive/attachment")], trigger="other")
O("/resource/open_graphic_parse", "GET", ("resource.rs", "open_graphic_parse"), auth="none", sem="fetch_url_preview",
  req=[Q("url", desc="Arbitrary URL fetched server-side.")],
  resp_format="json", resp=[R("og_title", "title", "string", False, "Page title."), R("og_url", "url", "string", False, "Canonical URL."),
                            R("og_images", "images[].url", "string", False, "Image URLs."), R("og_description", "description", "string", False, "Description.")],
  idst=NONE((200,), (400,)), fe=[("message.ts", "getOGInfo")],
  notes="Unauthenticated server-side fetch of attacker-chosen URL (SSRF primitive) (resource.rs:467-487).")

# =====================================================================  /favorite
O("/favorite", "POST", ("favorite.rs", "create"), auth="token_ng", sem="create_favorite_archive",
  req_format="json", req=[TOKEN_H, B("mid_list", "integer", True, True, "Messages to favourite.", path="mid_list[]")],
  resp_format="json", resp=[R("favorite_id", "id", "string", True, "Favorite UUID."), R("created_at", "created_at", "integer", False, "Timestamp.")],
  idst=TOK((200,), (400, 403, 404, 429)), fe=[("message.ts", "favoriteMessage")], body_example={"mid_list": [27]})
O("/favorite", "GET", ("favorite.rs", "list"), auth="token", sem="list_favorites", req=[TOKEN_H],
  resp_format="json", resp=[R("favorite_id", "[].id", "string", True, "Favorite UUID."), R("created_at", "[].created_at", "integer", False, "Timestamp.")],
  idst=TOK((200,)), fe=[("message.ts", "getFavorites")])
O("/favorite/{id}", "DELETE", ("favorite.rs", "delete"), auth="token_ng", sem="delete_favorite",
  req=[TOKEN_H, P("id", "string", "Favorite UUID.")], idst=TOK((200,), (403, 404)), fe=[("message.ts", "removeFavorite")])
O("/favorite/{id}", "GET", ("favorite.rs", "get_index"), auth="token", sem="read_favorite",
  req=[TOKEN_H, P("id", "string", "Favorite UUID.")], resp_format="json", resp=archive(""),
  idst=TOK((200,), (400, 404)), fe=[("message.ts", "getFavoriteDetails")])
O("/favorite/attachment/{uid}/{id}/{attachment_id}", "GET", ("favorite.rs", "get_archive_attachment"), auth="none",
  sem="download_favorite_attachment",
  req=[P("uid", desc="Owner uid of the favorite."), P("id", "string", "Favorite UUID."), P("attachment_id", desc="Attachment index."),
       Q("download", "boolean", False, False, "Disposition.")],
  resp_format="raw", value=("attachment_bytes", "binary", True, "Attachment bytes."), ctypes=("application/octet-stream",),
  idst=NONE((200,), (400, 404)), fe=[("utils.tsx", "favorite/attachment")], trigger="other",
  notes="No auth and owner uid supplied by caller (favorite.rs:149-177).")

# =====================================================================  /license
O("/license/check", "POST", ("license.rs", "check"), auth="none", sem="check_license",
  req_format="json", req=[B("license", desc="Base58 license blob.")],
  resp_format="json", resp=[R("license_domains", "domains[]", "string", True, "Domains."), R("user_limit", "user_limit", "integer", True, "User cap."),
                            R("sign", "sign", "boolean", True, "Signature valid."), R("base58", "base58", "string", True, "Echo.")],
  idst=NONE((200,), (400,)), fe=[("server.ts", "checkLicense")], body_example={"license": "<base58>"})
O("/license", "PUT", ("license.rs", "put"), auth="token", sem="save_license",
  req_format="json", req=[TOKEN_H, B("license", desc="Base58 license blob.")],
  resp_format="scalar", value=("bool_result", "boolean", False, "Always true; update only applied if caller is admin or no license file exists."),
  idst=TOK((200,), (400,)), fe=[("server.ts", "upsertLicense")], body_example={"license": "<base58>"},
  notes="Non-admin succeeds (200 true) without effect when a license exists; with no license file any user can install one (license.rs:68-85).")
O("/license", "GET", ("license.rs", "get"), auth="none", sem="read_license",
  resp_format="json", resp=[R("license_domains", "domains[]", "string", True, "Domains."), R("user_limit", "user_limit", "integer", True, "User cap."),
                            R("sign", "sign", "boolean", True, "Signature valid."), R("base58", "base58", "string", True, "License blob.")],
  idst=NONE((200,), (400,)), fe=[("server.ts", "getLicense")])

# =====================================================================  /admin/system
O("/admin/system/version", "GET", ("admin_system.rs", "version"), auth="none", sem="read_server_version",
  resp_format="raw", value=("version", "string", True, "Cargo package version (deployment: 0.5.36)."), ctypes=("text/plain",),
  idst=NONE((200,)), fe=[("server.ts", "getServerVersion")])
O("/admin/system/create_admin", "POST", ("admin_system.rs", "create_admin_user"), auth="none", sem="bootstrap_admin_account",
  req_format="json", req=[B("email", desc="Admin e-mail."), B("name", desc="Admin name."), B("password", desc="Admin password."), B("gender", "integer", True, False, "Gender.")],
  resp_format="json", resp=userinfo(""), idst=NONE((200, 403)), fe=[("server.ts", "createAdmin")], reach=False,
  conds=["Only succeeds while no user exists (initialized=false); deployment is initialized -> 403"],
  body_example={"email": "admin@x", "name": "admin", "password": "<redacted>", "gender": 0})
O("/admin/system/initialized", "GET", ("admin_system.rs", "initialized"), auth="none", sem="read_server_initialized",
  resp_format="scalar", value=("initialized", "boolean", True, "Whether any user exists."), idst=NONE((200,)), fe=[("auth.ts", "getInitialized")])
O("/admin/system/metrics", "GET", ("admin_system.rs", "get_metrics"), auth="admin", sem="read_server_metrics",
  req=[TOKEN_H], resp_format="json", resp=[R("user_count", "user_count", "integer", False, "Users."), R("group_count", "group_count", "integer", False, "Groups."),
                                           R("online_user_count", "online_user_count", "integer", False, "Online."), R("version", "version", "string", True, "Version.")],
  idst=ADM((200,)), vis_reason="Not called by web frontend 0.9.122; guessable sibling path; in OpenAPI.")
O("/admin/system/organization", "GET", ("admin_system.rs", "get_organization"), auth="none", sem="read_organization",
  resp_format="json", resp=[R("org_name", "name", "string", True, "Organization name."), R("org_description", "description", "string", True, "Description."),
                            R("server_id", "server_id", "string", True, "Server UUID (deployed build only).")],
  idst=NONE((200,)), fe=[("server.ts", "getServer")])
O("/admin/system/organization", "POST", ("admin_system.rs", "set_organization"), auth="admin", sem="update_organization",
  req_format="json", req=[TOKEN_H, B("org_name", path="name", desc="Organization name."), B("org_description", path="description", required=False, desc="Description.")],
  idst=ADM((200,)), fe=[("server.ts", "updateServer")], body_example={"name": "GT-Org", "description": "x"},
  notes="Frontend uses PUT on servers > 0.3.8 (server.ts updateServer); POST is the source-declared method.")
O("/admin/system/organization/logo", "POST", ("admin_system.rs", "upload_organization_logo"), auth="admin", sem="upload_organization_logo",
  req_format="raw", req=[TOKEN_H, F("logo", "body", "binary", True, True, "PNG bytes.", path="")],
  idst=ADM((200,), (415, 500)), fe=[("server.ts", "updateLogo")])
O("/admin/system/send_mail", "POST", ("admin_system.rs", "send_mail"), auth="admin", sem="send_test_mail",
  req_format="json", req=[TOKEN_H, B("mail_to", path="to", desc="Recipient."), B("mail_subject", path="subject", desc="Subject."), B("mail_content", path="content", desc="Body.")],
  idst=ADM((200,), (503,)), fe=[("server.ts", "sendTestEmail")], reach=False, conds=["SMTP configured (deployment disabled -> 503)"],
  body_example={"to": "a@b", "subject": "s", "content": "c"})
O("/admin/system/third_party_secret", "GET", ("admin_system.rs", "third_party_secret"), auth="admin", sem="read_third_party_secret",
  req=[TOKEN_H], resp_format="raw", value=("third_party_secret", "string", True, "Server third-party secret."), ctypes=("text/plain",),
  idst=ADM((200,)), fe=[("server.ts", "getThirdPartySecret")])
O("/admin/system/third_party_secret", "POST", ("admin_system.rs", "update_third_party_secret"), auth="admin", sem="rotate_third_party_secret",
  req=[TOKEN_H], resp_format="raw", value=("third_party_secret", "string", True, "New secret."), ctypes=("text/plain",),
  idst=ADM((200,)), fe=[("server.ts", "updateThirdPartySecret")])
O("/admin/system/frontend_url", "GET", ("admin_system.rs", "get_frontend_url"), auth="admin", sem="read_frontend_url",
  req=[TOKEN_H], resp_format="raw", value=("frontend_url", "string", True, "Configured frontend URL (may be empty)."), ctypes=("text/plain",),
  idst=ADM((200,)), fe=[("server.ts", "getFrontendUrl")])
O("/admin/system/update_frontend_url", "POST", ("admin_system.rs", "update_frontend_url"), auth="admin", sem="update_frontend_url",
  req_format="raw", req=[TOKEN_H, F("frontend_url", "body", "string", True, True, "http(s)://host[:port] (text/plain).", path="")],
  idst=ADM((200,), (400,)), fe=[("server.ts", "updateFrontendUrl")],
  notes="Value is embedded in every invite/login magic link; admin can redirect links (admin_system.rs:293-322).")

# =====================================================================  /admin/{agora,fcm,smtp,login,google_auth,github_auth}
AG_FIELDS = [("url", "config_value"), ("project_id", "config_value"), ("app_id", "app_id"), ("app_certificate", "config_secret"),
             ("rtm_key", "config_secret"), ("rtm_secret", "config_secret")]
O("/admin/agora/config", "POST", ("admin_agora.rs", "set_config"), auth="admin", sem="update_agora_config",
  req_format="json", req=[TOKEN_H, B("enabled", "boolean", True, True, "Enable flag.")] + [B(f, required=(f != "url"), desc=f"Agora {f}.") for f, _ in AG_FIELDS],
  sk=dict(AG_FIELDS), idst=ADM((200,)), fe=[("server.ts", "updateAgoraConfig")], body_example={"enabled": False, "app_id": "x"})
O("/admin/agora/config", "GET", ("admin_agora.rs", "get_config"), auth="token", sem="read_agora_config",
  req=[TOKEN_H], resp_format="json", resp=[R("enabled", "enabled", "boolean", True, "Enabled.")] + [R(f, f, "string", True, f"Agora {f}.") for f, _ in AG_FIELDS],
  sk=dict(AG_FIELDS), idst=TOK((200,)), fe=[("server.ts", "getAgoraConfig")],
  notes="Admin check commented out in source (admin_agora.rs:106-108): any session reads app_certificate/rtm_secret.")
O("/admin/agora/usages", "GET", ("admin_agora.rs", "usage"), auth="admin", sem="read_agora_usage",
  req=[TOKEN_H, Q("from_date", flow=False, desc="YYYY-MM-DD."), Q("to_date", flow=False, desc="YYYY-MM-DD.")],
  resp_format="json", resp=[R("usages", "usages[]", "object", False, "Usage items.")],
  idst=ADM((200,), (400, 503)), reach=False, vis="white_box", vis_reason="Not referenced by web frontend 0.9.122; source/OpenAPI only.",
  conds=["Agora configured (disabled in deployment -> 503)"])
FCM_FIELDS = [("use_official", "config_value"), ("token_url", "config_value"), ("project_id", "config_value"), ("private_key", "config_secret"), ("client_email", "config_value")]
O("/admin/fcm/config", "POST", ("admin_fcm.rs", "set_config"), auth="admin", sem="update_fcm_config",
  req_format="json", req=[TOKEN_H, B("enabled", "boolean", True, True, "Enabled.")] + [B(f, "boolean" if f == "use_official" else "string", f != "token_url", True, f"FCM {f}.") for f, _ in FCM_FIELDS],
  sk=dict(FCM_FIELDS), idst=ADM((200,)), fe=[("server.ts", "updateFirebaseConfig")], body_example={"enabled": True, "use_official": True})
O("/admin/fcm/config", "GET", ("admin_fcm.rs", "get_config"), auth="admin", sem="read_fcm_config",
  req=[TOKEN_H], resp_format="json", resp=[R("enabled", "enabled", "boolean", True, "Enabled.")] + [R(f, f, "string", True, f"FCM {f}.") for f, _ in FCM_FIELDS],
  sk=dict(FCM_FIELDS), idst=ADM((200,)), fe=[("server.ts", "getFirebaseConfig")])
SMTP_FIELDS = [("host", "config_value"), ("port", "config_value"), ("from", "config_value"), ("username", "config_value"), ("password", "config_secret")]
O("/admin/smtp/config", "POST", ("admin_smtp.rs", "set_config"), auth="admin", sem="update_smtp_config",
  req_format="json", req=[TOKEN_H, B("enabled", "boolean", True, True, "Enabled.")] + [B(f, "integer" if f == "port" else "string", f != "port", True, f"SMTP {f}.") for f, _ in SMTP_FIELDS],
  sk=dict(SMTP_FIELDS), idst=ADM((200,)), fe=[("server.ts", "updateSMTPConfig")], body_example={"enabled": False, "host": "", "from": "", "username": "", "password": "<redacted>"})
O("/admin/smtp/config", "GET", ("admin_smtp.rs", "get_config"), auth="admin", sem="read_smtp_config",
  req=[TOKEN_H], resp_format="json", resp=[R("enabled", "enabled", "boolean", True, "Enabled.")] + [R(f, f, "string", True, f"SMTP {f}.") for f, _ in SMTP_FIELDS],
  sk=dict(SMTP_FIELDS), idst=ADM((200,)), fe=[("server.ts", "getSMTPConfig")])
O("/admin/smtp/enabled", "GET", ("admin_smtp.rs", "is_enabled"), auth="none", sem="read_smtp_enabled",
  resp_format="scalar", value=("enabled", "boolean", True, "SMTP enabled."), idst=NONE((200,)), fe=[("server.ts", "getSMTPStatus")])
LOGIN_FIELDS = ["who_can_sign_up", "guest", "password", "magic_link", "google", "github", "metamask", "third_party"]
O("/admin/login/config", "POST", ("admin_login.rs", "set_config"), auth="admin", sem="update_login_policy",
  req_format="json", req=[TOKEN_H] + [B(f, "string" if f == "who_can_sign_up" else "boolean", True, True, f"Login policy {f}.") for f in LOGIN_FIELDS]
                         + [B("oidc", "array", True, True, "OIDC issuers [{enable,favicon,domain}].", path="oidc[]")],
  sk={f: "login_config" for f in LOGIN_FIELDS + ["oidc"]}, idst=ADM((200,)), fe=[("server.ts", "updateLoginConfig")],
  body_example={"who_can_sign_up": "EveryOne", "guest": True, "password": True, "magic_link": True, "google": False, "github": False, "oidc": [], "metamask": False, "third_party": False})
O("/admin/login/config", "GET", ("admin_login.rs", "get_config"), auth="none", sem="read_login_policy",
  resp_format="json", resp=[R(f, f, "string" if f == "who_can_sign_up" else "boolean", True, f"Login policy {f}.") for f in LOGIN_FIELDS] + [R("oidc", "oidc[]", "object", True, "OIDC issuers.")],
  sk={f: "login_config" for f in LOGIN_FIELDS + ["oidc"]}, idst=NONE((200,)), fe=[("server.ts", "getLoginConfig")])
O("/admin/google_auth/config", "POST", ("admin_google_auth.rs", "set_config"), auth="admin", sem="update_google_auth_config",
  req_format="json", req=[TOKEN_H, B("client_id", desc="Google OAuth client id.")], sk={"client_id": "config_value"},
  idst=ADM((200,)), fe=[("server.ts", "updateGoogleAuthConfig")], body_example={"client_id": "x.apps.googleusercontent.com"})
O("/admin/google_auth/config", "GET", ("admin_google_auth.rs", "get_config"), auth="none", sem="read_google_auth_config",
  resp_format="json", resp=[R("client_id", "client_id", "string", True, "Client id.")], sk={"client_id": "config_value"},
  idst=NONE((200,)), fe=[("server.ts", "getGoogleAuthConfig")],
  notes="Source: unauthenticated. Frontend whiteList401 tolerates 401 here, suggesting the deployed build added auth (unverified; not in HAR).")
O("/admin/github_auth/config", "POST", ("admin_github_auth.rs", "set_config"), auth="admin", sem="update_github_auth_config",
  req_format="json", req=[TOKEN_H, B("client_id", desc="GitHub OAuth client id."), B("client_secret", desc="GitHub client secret.")],
  sk={"client_id": "config_value", "client_secret": "config_secret"}, idst=ADM((200,)), fe=[("server.ts", "updateGithubAuthConfig")],
  body_example={"client_id": "x", "client_secret": "<redacted>"})
O("/admin/github_auth/config", "GET", ("admin_github_auth.rs", "get_config"), auth="none", sem="read_github_auth_config",
  resp_format="json", resp=[R("client_id", "client_id", "string", True, "Client id."), R("client_secret", "client_secret", "string", True, "Client secret.")],
  sk={"client_id": "config_value", "client_secret": "config_secret"}, idst=NONE((200,)), fe=[("server.ts", "getGithubAuthConfig")],
  notes="Source: unauthenticated and returns client_secret (admin_github_auth.rs:59-63). Frontend whiteList401 suggests deployed build may require auth (unverified).")

# =====================================================================  /admin/user
O("/admin/user", "POST", ("admin_user.rs", "create"), auth="admin", sem="admin_create_user",
  req_format="json", req=[TOKEN_H, B("email", desc="E-mail."), B("password", desc="Password."), B("name", desc="Name (<=32)."),
                          B("gender", "integer", True, False, "Gender."), B("is_admin", "boolean", True, True, "Grant admin."),
                          B("language", required=False, flow=False, desc="Language."), B("webhook_url", required=False, desc="Bot webhook (server GETs it)."),
                          B("is_bot", "boolean", False, False, "Bot flag.")],
  resp_format="json", resp=admin_user(""), idst=ADM((200,), (406, 409)), fe=[("user.ts", "createUser")],
  body_example={"email": "u@x", "password": "<redacted>", "name": "u", "gender": 0, "is_admin": False},
  notes="webhook_url is fetched server-side before save (admin_user.rs:161-170).")
O("/admin/user/{uid}", "GET", ("admin_user.rs", "get"), auth="admin", sem="admin_read_user", req=[TOKEN_H, P("uid", desc="User id.")],
  resp_format="json", resp=admin_user(""), idst=ADM((200,), (404,)), fe=[("user.ts", "getUserByAdmin")])
O("/admin/user", "GET", ("admin_user.rs", "get_all"), auth="admin", sem="admin_list_users", req=[TOKEN_H],
  resp_format="json", resp=admin_user("[]"), idst=ADM((200,)),
  vis_reason="Not called by web frontend 0.9.122; sibling of /admin/user/{uid}; in OpenAPI.")
O("/admin/user/{uid}", "DELETE", ("admin_user.rs", "delete"), auth="admin", sem="admin_delete_user", req=[TOKEN_H, P("uid", desc="User id (not self, not uid 1).")],
  idst=ADM((200,), (403, 404)), fe=[("user.ts", "deleteUser")])
O("/admin/user/{uid}", "PUT", ("admin_user.rs", "update"), auth="admin", sem="admin_update_user",
  req_format="json", req=[TOKEN_H, P("uid", desc="User id."), B("email", required=False, desc="E-mail."), B("password", required=False, desc="Reset password."),
                          B("name", required=False, desc="Name."), B("gender", "integer", False, False, "Gender."), B("is_admin", "boolean", False, True, "Admin flag."),
                          B("language", required=False, flow=False, desc="Language."), B("status", required=False, desc="normal|frozen."),
                          B("webhook_url", required=False, desc="Webhook.")],
  resp_format="json", resp=admin_user(""), idst=ADM((200,), (400, 404, 406, 409)), fe=[("user.ts", "updateUser")],
  body_example={"status": "frozen"}, notes="Selector-like optional fields: is_admin (privilege), status (freeze), password (reset), profile fields.")
O("/admin/user/{uid}/avatar", "POST", ("admin_user.rs", "upload_avatar"), auth="admin", sem="admin_upload_user_avatar",
  req_format="raw", req=[TOKEN_H, P("uid", desc="User id."), F("avatar", "body", "binary", True, True, "PNG bytes.", path="")],
  idst=ADM((200,), (401, 413, 415)), fe=[("user.ts", "updateAvatarByAdmin")])
O("/admin/user/bot-api-key/{uid}", "POST", ("admin_user.rs", "create_bot_api_key"), auth="admin", sem="create_bot_api_key",
  req_format="json", req=[TOKEN_H, P("uid", desc="Bot user id."), B("bot_key_name", path="name", desc="Key label.")],
  resp_format="scalar", value=("api_key", "string", True, "New bot API key."), idst=ADM((200,), (401, 409)),
  fe=[("user.ts", "createBotAPIKey")], body_example={"name": "k1"}, notes="Works for any uid, not only is_bot users (admin_user.rs:508-562).")
O("/admin/user/bot-api-key/{uid}/{kid}", "DELETE", ("admin_user.rs", "delete_bot_api_key"), auth="admin", sem="delete_bot_api_key",
  req=[TOKEN_H, P("uid", desc="Bot user id."), P("kid", desc="Key id.")], idst=ADM((200,), (401, 404)), fe=[("user.ts", "deleteBotAPIKey")])
O("/admin/user/bot-api-key/{uid}", "GET", ("admin_user.rs", "list_bot_api_key"), auth="admin", sem="list_bot_api_keys",
  req=[TOKEN_H, P("uid", desc="Bot user id.")],
  resp_format="json", resp=[R("bot_key_id", "[].id", "integer", True, "Key id."), R("bot_key_name", "[].name", "string", True, "Label."),
                            R("api_key", "[].key", "string", True, "Full key secret."), R("created_at", "[].created_at", "integer", False, "Created."),
                            R("last_used", "[].last_used", "integer", False, "Last used.")],
  idst=ADM((200,), (401,)), fe=[("user.ts", "getBotAPIKeys")])

# =====================================================================  /bot  (API-key authenticated)
O("/bot", "GET", ("bot.rs", "get_related_groups"), auth="bot", sem="bot_list_related_groups",
  req=[BOTKEY_H, Q("public_only", "boolean", False, False, "Only public.")], resp_format="json", resp=group("[]"),
  idst=BOT((200,)), fe=[("server.ts", "getBotRelatedChannels")])
O("/bot/send_to_user/{uid}", "POST", ("bot.rs", "send_to_user"), auth="bot", sem="bot_send_direct_message",
  req_format="raw", req=[BOTKEY_H, P("uid", desc="Recipient."), PROPS_H, F("content", "body", "string", True, True, "Message body.", path="")],
  resp_format="scalar", value=("mid", "integer", True, "Message id."), idst=BOT((200,), (404,)), fe=[("server.ts", "sendMessageByBot")])
O("/bot/send_to_group/{gid}", "POST", ("bot.rs", "send_to_group"), auth="bot", sem="bot_send_group_message",
  req_format="raw", req=[BOTKEY_H, P("gid", desc="Group."), PROPS_H, F("content", "body", "string", True, True, "Message body.", path="")],
  resp_format="scalar", value=("mid", "integer", True, "Message id."), idst=BOT((200,), (403, 404)), fe=[("server.ts", "sendMessageByBot")])
O("/bot/user/{uid}", "GET", ("bot.rs", "user_info"), auth="bot", sem="bot_read_user",
  req=[BOTKEY_H, P("uid_path", "integer", "Path segment (ignored by handler).", flow=False), Q("uid", "integer", True, True, "User id actually used (Query<i64>).")],
  resp_format="json", resp=userinfo(""), idst=BOT((200,), (400, 404)), vis="white_box",
  vis_reason="Not referenced by web frontend; source/OpenAPI only.",
  notes="Handler binds uid from the QUERY string although the route declares :uid (bot.rs:115-131).")
O("/bot/group/{gid}", "GET", ("bot.rs", "group_info"), auth="bot", sem="bot_read_group",
  req=[BOTKEY_H, P("gid_path", "integer", "Path segment (ignored).", flow=False), Q("gid", "integer", True, True, "Group id actually used.")],
  resp_format="json", resp=group(""), idst=BOT((200,), (400, 404)), vis="white_box", vis_reason="Not referenced by web frontend; source/OpenAPI only.",
  notes="Returns any group incl. private ones regardless of bot membership (bot.rs:134-150).")
O("/bot/file/prepare", "POST", ("bot.rs", "upload_file_prepare"), auth="bot", sem="bot_prepare_file_upload",
  req_format="json", req=[BOTKEY_H, B("content_type", required=False, flow=False, desc="MIME."), B("filename", required=False, desc="Name.")],
  resp_format="scalar", value=("file_id", "string", True, "Upload UUID."), idst=BOT((200,)), vis="white_box",
  vis_reason="Not referenced by web frontend; source/OpenAPI only.", body_example={"filename": "a.txt"})
O("/bot/file/upload", "POST", ("bot.rs", "upload_file"), auth="bot", sem="bot_upload_file_chunk",
  req_format="form", req=[BOTKEY_H, B("file_id", desc="Upload UUID."), B("chunk_data", "binary", True, True, "Bytes."), B("chunk_is_last", "boolean", False, False, "Final.")],
  resp_format="json", resp=[R("path", "path", "string", True, "Stored path."), R("size", "size", "integer", False, "Size."), R("hash", "hash", "string", True, "SHA-256.")],
  idst=BOT((200,), (400,)), vis="white_box", vis_reason="Not referenced by web frontend; source/OpenAPI only.")

# =====================================================================  non-OpenAPI routes registered in server.rs
O("/doc", "GET", None, auth="none", sem="", kind="page", resp_format="raw", value=("html_page", "string", False, "Swagger UI."), ctypes=("text/html",),
  idst=NONE((200,)), vis_reason="Standard documentation path; linked from Settings > API Document (routes/setting/APIDocument.tsx uses /api/swagger).")
O("/doc2", "GET", None, auth="none", sem="", kind="page", resp_format="raw", value=("html_page", "string", False, "RapiDoc UI."), ctypes=("text/html",), idst=NONE((200,)))
O("/swagger", "GET", None, auth="none", sem="", kind="page", resp_format="raw", value=("html_page", "string", False, "Swagger UI."), ctypes=("text/html",),
  idst=NONE((200,)), fe=[("routes/setting/APIDocument.tsx", "api/swagger")], trigger="link")
O("/doc3", "GET", None, auth="none", sem="", kind="page", resp_format="raw", value=("html_page", "string", False, "ReDoc UI."), ctypes=("text/html",), idst=NONE((200,)))
O("/spec", "GET", None, auth="none", sem="read_openapi_spec", resp_format="raw", value=("html_page", "string", False, "OpenAPI JSON."),
  ctypes=("application/json",), idst=NONE((200,)), vis_reason="Well-known spec path under /api; served by poem spec_endpoint (server.rs).")
