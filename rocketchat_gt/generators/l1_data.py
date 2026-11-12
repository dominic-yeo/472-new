# -*- coding: utf-8 -*-
"""Rocket.Chat (OSS) L1 attack surface as data.

Authoritative source: apps/meteor/server/api/v1/*.ts (fluent API.v1.get/post/put/delete
and legacy .addRoute), mounted at /api/v1 (apps/meteor/server/api/ApiClass.ts apiPath).
ORIGIN = http://localhost:3000 (default).

Auth model (ApiClass.ts): REST auth = 'X-Auth-Token' + 'X-User-Id' headers obtained from
POST /api/v1/login, OR 'Authorization: Bearer <personal-access-token>'. Each route declares
authRequired; admin routes additionally check permissions (hasPermission). 2FA via 'X-2fa-code'.

Scope: the security-critical OSS core (auth, users, channels, groups, chat, rooms, settings,
permissions, roles, integrations, misc) is modeled; omnichannel/livechat (~150), EE/apps,
and secondary groups are enumerated/excluded (see build_l1.EXCLUDED). Nodes with io_variants
are L2 candidates. Statuses/identity_statuses left for runtime confirmation.
"""
import common as c
from common import key as K, rf, of, variant, resp_json, resp_empty, dec

V1 = "/api/v1"
SRC = "apps/meteor/server/api/v1"


def ev(ref, supports="route + authRequired"):
    return c.ev("source", ref, supports)


API_NODES = []
_SPECS, _ORDER = {}, []


def _dedup(ds):
    out, seen = [], set()
    for d in ds:
        s = (d["raw_field"], d["resource"])
        if s not in seen:
            seen.add(s); out.append(d)
    return out


def api(name, methods, variants, op, sin=None, sout=None, vis_reason="", reach=None, evref="", notes=None):
    k = K(V1 + "/" + name)
    if k not in _SPECS:
        _ORDER.append(k)
        _SPECS[k] = {"methods": [], "variants": [], "sin": [], "sout": [], "op": op,
                     "vis_reason": vis_reason, "reach": [], "ev": [], "notes": []}
    s = _SPECS[k]
    for m in methods:
        if m not in s["methods"]:
            s["methods"].append(m)
    s["variants"] += variants
    s["sin"] += (sin or [])
    s["sout"] += (sout or [])
    if op and len(op) > len(s["op"]):
        s["op"] = op
    if vis_reason and not s["vis_reason"]:
        s["vis_reason"] = vis_reason
    for r in (reach or []):
        if r not in s["reach"]:
            s["reach"].append(r)
    if evref:
        s["ev"].append(evref)
    if notes:
        s["notes"].append(notes)


def api0(name, methods, op, reach=None, evref="", notes=None):
    api(name, methods, [], op, reach=reach, evref=evref, notes=notes)


def _finalize():
    for k in _ORDER:
        s = _SPECS[k]
        API_NODES.append(c.node(
            k, "api", s["methods"], variants=s["variants"], operation_semantic=s["op"],
            sem_in_decisions=_dedup(s["sin"]), sem_out_decisions=_dedup(s["sout"]),
            visibility="black_box", vis_reason=s["vis_reason"], reachable=True, reach_conds=s["reach"],
            evidence=[ev(SRC + "/" + e) for e in dict.fromkeys(s["ev"])],
            notes="; ".join(dict.fromkeys(s["notes"])) or None))


def d_user():
    return dec("user", "Username(user)", "identifier", reference_capable=True, reason="Target username.")


def d_userId():
    return dec("userId", "UserID(user)", "identifier", reference_capable=True, reason="Target user id.")


def d_rid():
    return dec("roomId", "RoomID(room)", "identifier", reference_capable=True, reason="Target room id.")


# ===========================================================================
# AUTH
# ===========================================================================
api("login", ["POST"],
    [variant("POST", [rf("user", "body", required=True, description="username or email"),
                      rf("password", "body", required=True, description="password")],
             resp_json([of("authToken", description="auth token"), of("userId", description="user id")]),
             body_format="json", reason="Meteor login; returns X-Auth-Token + userId (authRequired:false)",
             evidence="ApiClass.ts:994 login")],
    "login_user",
    sin=[dec("user", "Username(user)", "identifier", reference_capable=True, reason="Login identifier."),
         dec("password", "Password(user)", "credential", reason="Account password.")],
    sout=[dec("authToken", "AuthToken(session)", "credential", reason="Session auth token (X-Auth-Token)."),
          dec("userId", "UserID(user)", "identifier", reference_capable=True, reason="Authenticated user id.")],
    vis_reason="Public login.", reach=["Public. Brute-force / credential-stuffing surface (+ X-2fa-code)."],
    evref="ApiClass.ts", notes="authRequired:false; primary auth. 2FA via X-2fa-code header.")

api("logout", ["POST"],
    [variant("POST", [], resp_empty(), reason="invalidate the auth token", evidence="ApiClass.ts:1102 logout")],
    "logout_user", vis_reason="Logout.", reach=["Authenticated."], evref="ApiClass.ts")

api("me", ["GET"],
    [variant("GET", [], resp_json([of("user", description="the caller's own user")]),
             reason="returns the authenticated user", evidence="misc.ts me")],
    "read_me",
    sout=[dec("user", "UserID(user)", "identifier", reference_capable=True, reason="Caller's own account.")],
    vis_reason="Self.", reach=["Authenticated."], evref="misc.ts")

api("users.register", ["POST"],
    [variant("POST", [rf("username", "body", required=True), rf("email", "body", required=True),
                      rf("pass", "body", required=True, description="password"),
                      rf("name", "body", required=True)],
             resp_json([of("user")]), body_format="json",
             reason="public self-registration (if Accounts_RegistrationForm allows)",
             evidence="users.ts users.register")],
    "register_user",
    sin=[dec("username", "Username(user)", "identifier", reference_capable=True, reason="Chosen username."),
         dec("email", "UserEmail(user)", "identifier", reference_capable=True, reason="Email."),
         dec("pass", "Password(user)", "credential", reason="New password.")],
    sout=[dec("user", "UserID(user)", "identifier", reference_capable=True, reason="Created user.")],
    vis_reason="Public self-registration.",
    reach=["Public IF registration enabled (Accounts_RegistrationForm='Public'). Config-dependent."],
    evref="users.ts", notes="Unauthenticated account creation when registration is open.")

api("users.generatePersonalAccessToken", ["POST"],
    [variant("POST", [rf("tokenName", "body", required=True, description="token label")],
             resp_json([of("token", description="personal access token")]), body_format="json",
             reason="mints a long-lived personal access token for the caller",
             evidence="personal-access-tokens api")],
    "generate_pat",
    sout=[dec("token", "PersonalAccessToken(user)", "credential",
              reason="Long-lived API credential (bypasses session/2FA for API calls).")],
    vis_reason="PAT mint.", reach=["Authenticated; permission 'create-personal-access-tokens'."],
    evref="../../imports/personal-access-tokens", notes="Persistent credential; high-value if stolen.")

api("users.2fa.sendEmailCode", ["POST"], [], "send_2fa_email")  # placeholder covered below by api0


# ===========================================================================
# USERS (admin / self)
# ===========================================================================
api("users.create", ["POST"],
    [variant("POST", [rf("username", "body", required=True), rf("email", "body", required=True),
                      rf("password", "body", required=True), rf("name", "body", required=True),
                      rf("roles", "body", description="roles to assign")],
             resp_json([of("user")]), body_format="json",
             reason="admin creates a user (permission create-user)", evidence="users.ts users.create")],
    "create_user",
    sin=[dec("username", "Username(user)", "identifier", reference_capable=True, reason="New username."),
         dec("password", "Password(user)", "credential", reason="Initial password.")],
    sout=[dec("user", "UserID(user)", "identifier", reference_capable=True, reason="Created user.")],
    vis_reason="Admin create user.", reach=["Admin permission 'create-user'. Assigning 'admin' role = escalation."],
    evref="users.ts", notes="roles[] in the body -> privilege assignment surface.")

api("users.update", ["POST"],
    [variant("POST", [rf("userId", "body", required=True), rf("data", "body", description="fields incl roles/password")],
             resp_json([of("user")]), body_format="json",
             reason="admin edits a user (permission edit-other-user-info)", evidence="users.ts users.update")],
    "update_user", sin=[d_userId()],
    vis_reason="Admin edit user.",
    reach=["Admin permission. Can set another user's password/roles -> account takeover + escalation."],
    evref="users.ts", notes="Can change another user's password and roles.")

api("users.delete", ["POST"],
    [variant("POST", [rf("userId", "body", required=True)], resp_empty(), body_format="json",
             reason="admin deletes a user", evidence="users.ts users.delete")],
    "delete_user", sin=[d_userId()],
    vis_reason="Admin delete user.", reach=["Admin permission 'delete-user'."], evref="users.ts")

api("users.setActiveStatus", ["POST"],
    [variant("POST", [rf("userId", "body", required=True), rf("activeStatus", "body", required=True)],
             resp_json([of("user")]), body_format="json",
             reason="activate/deactivate a user", evidence="users.ts users.setActiveStatus")],
    "set_user_active", sin=[d_userId()],
    vis_reason="Admin (de)activate user.", reach=["Admin permission 'edit-other-user-active-status'."],
    evref="users.ts")

api("users.info", ["GET"],
    [variant("GET", [rf("userId", "query", description="user id"), rf("username", "query", description="username")],
             resp_json([of("user")]), reason="read a user's info", evidence="users.ts users.info")],
    "read_user", sin=[d_userId(), d_user()],
    sout=[dec("user", "UserID(user)", "identifier", reference_capable=True, reason="Looked-up user.")],
    vis_reason="User info.", reach=["Authenticated; fuller fields need 'view-full-other-user-info'."],
    evref="users.ts", notes="Enumeration surface for usernames/emails.")

api("users.resetAvatar", ["POST"],
    [variant("POST", [rf("userId", "body", description="target user")], resp_empty(), body_format="json",
             reason="reset a user's avatar", evidence="users.ts users.resetAvatar")],
    "reset_avatar", sin=[d_userId()],
    vis_reason="Reset avatar.", reach=["Self, or admin 'edit-other-user-avatar'."], evref="users.ts")

api("users.list", ["GET"],
    [variant("GET", [rf("query", "query", description="filter")], resp_json([of("users")]),
             reason="admin lists users", evidence="users.ts users.list (addRoute)")],
    "list_users",
    sout=[dec("users", "UserID(user)", "identifier", reference_capable=True, reason="All users.")],
    vis_reason="Admin user list.", reach=["Admin permission 'view-d-room'/'view-user-administration'."],
    evref="users.ts", notes="Bulk user/email enumeration for admins.")

# deferred user endpoints
for n, ms in [("users.setAvatar", ["POST"]), ("users.getAvatar", ["GET"]), ("users.deleteOwnAccount", ["POST"]),
              ("users.getPreferences", ["GET"]), ("users.setPreferences", ["POST"]),
              ("users.presence", ["GET"]), ("users.autocomplete", ["GET"]), ("users.verifyEmail", ["POST"]),
              ("users.sendConfirmationEmail", ["POST"]), ("users.removePersonalAccessToken", ["POST"]),
              ("users.getPersonalAccessTokens", ["GET"]), ("users.forgotPassword", ["POST"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Varies; see handler."], evref="users.ts")


# ===========================================================================
# CHANNELS (public channels)
# ===========================================================================
api("channels.create", ["POST"],
    [variant("POST", [rf("name", "body", required=True, description="channel name"),
                      rf("members", "body", description="initial members")],
             resp_json([of("channel")]), body_format="json",
             reason="create a public channel (permission create-c)", evidence="channels.ts channels.create")],
    "create_channel",
    sout=[dec("channel", "RoomID(room)", "identifier", reference_capable=True, reason="Created channel.")],
    vis_reason="Create channel.", reach=["Authenticated; permission 'create-c'."], evref="channels.ts")

api("channels.delete", ["POST"],
    [variant("POST", [rf("roomId", "body", description="room id"), rf("roomName", "body", description="name")],
             resp_empty(), body_format="json", reason="delete a channel", evidence="channels.ts channels.delete")],
    "delete_channel", sin=[d_rid()],
    vis_reason="Delete channel.", reach=["Room owner or 'delete-c'."], evref="channels.ts")

api("channels.info", ["GET"],
    [variant("GET", [rf("roomId", "query"), rf("roomName", "query")], resp_json([of("channel")]),
             reason="read channel info", evidence="channels.ts channels.info")],
    "read_channel", sin=[d_rid()],
    vis_reason="Channel info.", reach=["Authenticated; member or public."], evref="channels.ts")

api("channels.list", ["GET"],
    [variant("GET", [], resp_json([of("channels")]), reason="list channels (admin view-c-room)",
             evidence="channels.ts channels.list")],
    "list_channels",
    sout=[dec("channels", "RoomID(room)", "identifier", reference_capable=True, reason="All channels.")],
    vis_reason="Channel list.", reach=["Admin permission 'view-c-room'."], evref="channels.ts")

api("channels.invite", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("userId", "body", required=True)],
             resp_json([of("channel")]), body_format="json", reason="add a user to a channel",
             evidence="channels.ts channels.invite")],
    "invite_channel", sin=[d_rid(), d_userId()],
    vis_reason="Invite to channel.", reach=["Member with add-user permission."], evref="channels.ts")

api("channels.kick", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("userId", "body", required=True)],
             resp_json([of("channel")]), body_format="json", reason="remove a user from a channel",
             evidence="channels.ts channels.kick")],
    "kick_channel", sin=[d_rid(), d_userId()],
    vis_reason="Kick from channel.", reach=["Owner/moderator ('remove-user')."], evref="channels.ts")

api("channels.addOwner", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("userId", "body", required=True)],
             resp_empty(), body_format="json", reason="grant channel ownership (privilege)",
             evidence="channels.ts channels.addOwner")],
    "add_channel_owner", sin=[d_rid(), d_userId()],
    vis_reason="Grant channel owner.", reach=["Owner ('set-owner'). Room-level privilege escalation."],
    evref="channels.ts")

api("channels.setType", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("type", "body", required=True, description="c|p")],
             resp_json([of("channel")]), body_format="json", reason="convert channel public<->private",
             evidence="channels.ts channels.setType")],
    "set_channel_type", sin=[d_rid()],
    vis_reason="Channel public/private.", reach=["Owner. Visibility-boundary change."], evref="channels.ts")

api("channels.members", ["GET"],
    [variant("GET", [rf("roomId", "query")], resp_json([of("members")]), reason="list channel members",
             evidence="channels.ts channels.members")],
    "list_channel_members", sin=[d_rid()],
    sout=[dec("members", "UserID(user)", "identifier", reference_capable=True, reason="Channel members.")],
    vis_reason="Channel members.", reach=["Member."], evref="channels.ts")

for n, ms in [("channels.archive", ["POST"]), ("channels.unarchive", ["POST"]), ("channels.rename", ["POST"]),
              ("channels.setReadOnly", ["POST"]), ("channels.setDefault", ["POST"]),
              ("channels.setAnnouncement", ["POST"]), ("channels.setDescription", ["POST"]),
              ("channels.setTopic", ["POST"]), ("channels.setJoinCode", ["POST"]),
              ("channels.addModerator", ["POST"]), ("channels.removeModerator", ["POST"]),
              ("channels.removeOwner", ["POST"]), ("channels.addLeader", ["POST"]),
              ("channels.history", ["GET"]), ("channels.messages", ["GET"]), ("channels.files", ["GET"]),
              ("channels.online", ["GET"]), ("channels.counters", ["GET"]), ("channels.join", ["POST"]),
              ("channels.leave", ["POST"]), ("channels.open", ["POST"]), ("channels.close", ["POST"]),
              ("channels.convertToTeam", ["POST"]), ("channels.getIntegrations", ["GET"]),
              ("channels.anonymousread", ["GET"]), ("channels.roles", ["GET"]), ("channels.moderators", ["GET"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Authenticated; per-handler permission."], evref="channels.ts")


# ===========================================================================
# GROUPS (private) + IM
# ===========================================================================
api("groups.create", ["POST"],
    [variant("POST", [rf("name", "body", required=True), rf("members", "body")],
             resp_json([of("group")]), body_format="json", reason="create a private group",
             evidence="groups.ts groups.create")],
    "create_group",
    sout=[dec("group", "RoomID(room)", "identifier", reference_capable=True, reason="Created group.")],
    vis_reason="Create private group.", reach=["Authenticated; 'create-p'."], evref="groups.ts")

api("groups.list", ["GET"],
    [variant("GET", [], resp_json([of("groups")]), reason="list the caller's private groups",
             evidence="groups.ts groups.list")],
    "list_groups",
    sout=[dec("groups", "RoomID(room)", "identifier", reference_capable=True, reason="Caller's groups.")],
    vis_reason="Group list.", reach=["Authenticated (own groups)."], evref="groups.ts")

for n, ms in [("groups.delete", ["POST"]), ("groups.invite", ["POST"]), ("groups.kick", ["POST"]),
              ("groups.addOwner", ["POST"]), ("groups.removeOwner", ["POST"]), ("groups.info", ["GET"]),
              ("groups.members", ["GET"]), ("groups.messages", ["GET"]), ("groups.history", ["GET"]),
              ("groups.setType", ["POST"]), ("groups.setEncrypted", ["POST"]), ("groups.listAll", ["GET"]),
              ("groups.convertToTeam", ["POST"]), ("groups.rename", ["POST"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Authenticated; per-handler permission."], evref="groups.ts")

for n, ms in [("im.create", ["POST"]), ("im.list", ["GET"]), ("im.history", ["GET"]), ("im.messages", ["GET"]),
              ("im.delete", ["POST"]), ("im.members", ["GET"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Authenticated."], evref="im.ts")


# ===========================================================================
# CHAT (messages)
# ===========================================================================
api("chat.postMessage", ["POST"],
    [variant("POST", [rf("roomId", "body", description="target room"), rf("channel", "body"),
                      rf("text", "body", description="message text"), rf("attachments", "body")],
             resp_json([of("message")]), body_format="json", reason="post a message to a room",
             evidence="chat.ts chat.postMessage")],
    "post_message", sin=[d_rid()],
    sout=[dec("message", "MessageID(message)", "identifier", reference_capable=True, reason="Created message.")],
    vis_reason="Post message.", reach=["Authenticated member of the room."], evref="chat.ts",
    notes="attachments[] -> stored HTML/markdown (XSS/content-injection surface).")

api("chat.sendMessage", ["POST"],
    [variant("POST", [rf("message", "body", required=True, description="{rid,msg,...}")],
             resp_json([of("message")]), body_format="json", reason="send a message (rich)",
             evidence="chat.ts chat.sendMessage")],
    "send_message",
    sout=[dec("message", "MessageID(message)", "identifier", reference_capable=True, reason="Created message.")],
    vis_reason="Send message.", reach=["Authenticated member."], evref="chat.ts")

api("chat.update", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("msgId", "body", required=True),
                      rf("text", "body", required=True)],
             resp_json([of("message")]), body_format="json", reason="edit a message",
             evidence="chat.ts chat.update")],
    "update_message", sin=[d_rid(), dec("msgId", "MessageID(message)", "identifier",
        reference_capable=True, reason="Target message.")],
    vis_reason="Edit message.", reach=["Author, or 'edit-message' permission."], evref="chat.ts")

api("chat.delete", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("msgId", "body", required=True)],
             resp_empty(), body_format="json", reason="delete a message", evidence="chat.ts chat.delete")],
    "delete_message", sin=[d_rid(), dec("msgId", "MessageID(message)", "identifier",
        reference_capable=True, reason="Target message.")],
    vis_reason="Delete message.", reach=["Author, or 'force-delete-message'."], evref="chat.ts")

api("chat.react", ["POST"],
    [variant("POST", [rf("messageId", "body", required=True), rf("emoji", "body", required=True)],
             resp_empty(), body_format="json", reason="react to a message", evidence="chat.ts chat.react")],
    "react_message",
    sin=[dec("messageId", "MessageID(message)", "identifier", reference_capable=True, reason="Target message.")],
    vis_reason="React.", reach=["Authenticated member."], evref="chat.ts")

api("chat.getMessage", ["GET"],
    [variant("GET", [rf("msgId", "query", required=True)], resp_json([of("message")]),
             reason="read a single message", evidence="chat.ts chat.getMessage")],
    "read_message",
    sin=[dec("msgId", "MessageID(message)", "identifier", reference_capable=True, reason="Message id.")],
    vis_reason="Read message.", reach=["Authenticated; room access checked."], evref="chat.ts",
    notes="IDOR surface: confirm room-membership enforcement on arbitrary msgId.")

for n, ms in [("chat.pinMessage", ["POST"]), ("chat.unPinMessage", ["POST"]), ("chat.starMessage", ["POST"]),
              ("chat.reportMessage", ["POST"]), ("chat.search", ["GET"]), ("chat.getPinnedMessages", ["GET"]),
              ("chat.getStarredMessages", ["GET"]), ("chat.getThreadsList", ["GET"]),
              ("chat.getMentionedMessages", ["GET"]), ("chat.getURLPreview", ["GET"]),
              ("chat.getDeletedMessages", ["GET"]), ("chat.followMessage", ["POST"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Authenticated."], evref="chat.ts")


# ===========================================================================
# ROOMS
# ===========================================================================
api("rooms.media/:rid", ["POST"],
    [variant("POST", [rf("rid", "path", required=True, description="room id"),
                      rf("file", "body", required=True, description="uploaded file (multipart)")],
             resp_json([of("file")]), body_format="plain", reason="upload a file to a room",
             evidence="rooms.ts rooms.media (addRoute)")],
    "upload_file", sin=[dec("rid", "RoomID(room)", "identifier", reference_capable=True, reason="Target room.")],
    vis_reason="File upload to room.", reach=["Authenticated member; file-type/size validation surface."],
    evref="rooms.ts", notes="Upload surface (content-type sniffing, storage).")

api("rooms.adminRooms", ["GET"],
    [variant("GET", [rf("filter", "query")], resp_json([of("rooms")]),
             reason="admin lists ALL rooms (incl private)", evidence="rooms.ts rooms.adminRooms")],
    "admin_list_rooms",
    sout=[dec("rooms", "RoomID(room)", "identifier", reference_capable=True, reason="All rooms.")],
    vis_reason="Admin room list.", reach=["Admin permission 'view-room-administration'."], evref="rooms.ts",
    notes="Lists private rooms' metadata to admins.")

api("rooms.saveRoomSettings", ["POST"],
    [variant("POST", [rf("rid", "body", required=True), rf("settings", "body", description="room settings")],
             resp_empty(), body_format="json", reason="admin/owner changes room settings",
             evidence="rooms.ts rooms.saveRoomSettings")],
    "save_room_settings",
    sin=[dec("rid", "RoomID(room)", "identifier", reference_capable=True, reason="Target room.")],
    vis_reason="Save room settings.", reach=["Owner or 'edit-room'."], evref="rooms.ts")

api("rooms.cleanHistory", ["POST"],
    [variant("POST", [rf("roomId", "body", required=True), rf("latest", "body"), rf("oldest", "body")],
             resp_empty(), body_format="json", reason="bulk-delete messages in a time range",
             evidence="rooms.ts rooms.cleanHistory")],
    "clean_history", sin=[d_rid()],
    vis_reason="Bulk delete messages.", reach=["Permission 'clean-channel-history'. Destructive."],
    evref="rooms.ts")

api("rooms.export", ["POST"],
    [variant("POST", [rf("rid", "body", required=True), rf("type", "body", description="email|file")],
             resp_empty(), body_format="json", reason="export a room's messages",
             evidence="rooms.ts rooms.export")],
    "export_room", sin=[dec("rid", "RoomID(room)", "identifier", reference_capable=True, reason="Room to export.")],
    vis_reason="Export room.", reach=["Permission 'mail-messages'/room access. Data exfiltration."],
    evref="rooms.ts")

for n, ms in [("rooms.get", ["GET"]), ("rooms.info", ["GET"]), ("rooms.createDiscussion", ["POST"]),
              ("rooms.favorite", ["POST"]), ("rooms.cleanHistory", ["POST"]), ("rooms.muteUser", ["POST"]),
              ("rooms.unmuteUser", ["POST"]), ("rooms.changeArchivationState", ["POST"]),
              ("rooms.nameExists", ["GET"]), ("rooms.autocomplete.channelAndPrivate", ["GET"])]:
    api0(n, ms, n.replace(".", "_").replace("/", "_"), reach=["Authenticated."], evref="rooms.ts")


# ===========================================================================
# SETTINGS (admin config)
# ===========================================================================
api("settings.public", ["GET"],
    [variant("GET", [], resp_json([of("settings")]), reason="public settings (NO auth)",
             evidence="settings.ts settings.public")],
    "public_settings", vis_reason="Public settings.",
    reach=["Public (authRequired:false). Workspace fingerprinting surface."], evref="settings.ts")

api("settings", ["GET"],
    [variant("GET", [], resp_json([of("settings")]), reason="admin lists all settings",
             evidence="settings.ts settings")],
    "list_settings",
    sout=[dec("settings", "SettingKey(setting)", "identifier", reference_capable=True, reason="All settings.")],
    vis_reason="Admin settings list.", reach=["Admin permission 'view-privileged-setting'."], evref="settings.ts")

api("settings/:_id", ["GET", "POST"],
    [variant("GET", [rf("_id", "path", required=True, description="setting id")], resp_json([of("setting")]),
             reason="read a setting", evidence="settings.ts settings/:_id GET"),
     variant("POST", [rf("_id", "path", required=True), rf("value", "body", required=True)],
             resp_empty(), body_format="json", reason="CHANGE a setting (config takeover surface)",
             evidence="settings.ts settings/:_id POST")],
    "manage_setting",
    sin=[dec("_id", "SettingKey(setting)", "identifier", reference_capable=True, reason="Setting key.")],
    vis_reason="Read/change a setting.",
    reach=["Admin 'edit-privileged-setting'. Changing settings (e.g. URL/OAuth/file-upload) = workspace takeover."],
    evref="settings.ts", notes="Setting writes can reconfigure auth, uploads, integrations -> high impact.")

api0("settings.oauth", ["GET"], "settings_oauth", reach=["Authenticated."], evref="settings.ts")
api0("service.configurations", ["GET"], "service_configurations", reach=["Public."], evref="settings.ts")


# ===========================================================================
# PERMISSIONS / ROLES (authorization surface)
# ===========================================================================
api("permissions.listAll", ["GET"],
    [variant("GET", [], resp_json([of("permissions")]), reason="list role->permission mappings",
             evidence="permissions.ts permissions.listAll")],
    "list_permissions",
    sout=[dec("permissions", "PermissionID(permission)", "identifier", reference_capable=True,
              reason="Permission mappings.")],
    vis_reason="List permissions.", reach=["Authenticated."], evref="permissions.ts")

api("permissions.update", ["POST"],
    [variant("POST", [rf("permissions", "body", required=True, description="[{_id, roles[]}]")],
             resp_json([of("permissions")]), body_format="json",
             reason="reassign which roles hold which permissions (authorization rewrite)",
             evidence="permissions.ts permissions.update")],
    "update_permissions",
    vis_reason="Rewrite permissions.", reach=["Admin 'access-permissions'. Direct privilege-model control."],
    evref="permissions.ts", notes="Granting a permission to a low role = global privilege escalation.")

api("roles.addUserToRole", ["POST"],
    [variant("POST", [rf("roleName", "body", required=True, description="e.g. admin"),
                      rf("username", "body", required=True)],
             resp_json([of("role")]), body_format="json",
             reason="assign a role (e.g. admin) to a user", evidence="roles.ts roles.addUserToRole")],
    "add_user_to_role",
    sin=[dec("username", "Username(user)", "identifier", reference_capable=True, reason="User to elevate.")],
    vis_reason="Assign role.", reach=["Admin 'access-permissions'. Assigning 'admin' = full escalation."],
    evref="roles.ts", notes="Primary privilege-escalation primitive.")

api("roles.list", ["GET"],
    [variant("GET", [], resp_json([of("roles")]), reason="list roles", evidence="roles.ts roles.list")],
    "list_roles",
    sout=[dec("roles", "RoleID(role)", "identifier", reference_capable=True, reason="Roles.")],
    vis_reason="List roles.", reach=["Authenticated."], evref="roles.ts")

for n, ms in [("roles.create", ["POST"]), ("roles.delete", ["POST"]), ("roles.removeUserFromRole", ["POST"]),
              ("roles.getUsersInRole", ["GET"]), ("permissions.addRole", ["POST"]),
              ("permissions.removeRole", ["POST"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Admin 'access-permissions'."], evref="permissions.ts")


# ===========================================================================
# INTEGRATIONS (webhooks run server-side scripts)
# ===========================================================================
api("integrations.create", ["POST"],
    [variant("POST", [rf("type", "body", required=True, description="webhook-incoming|webhook-outgoing"),
                      rf("name", "body", required=True), rf("script", "body", description="server-side JS"),
                      rf("urls", "body", description="outgoing target urls")],
             resp_json([of("integration")]), body_format="json",
             reason="create an integration; outgoing webhooks can run a server-side script",
             evidence="integrations.ts integrations.create")],
    "create_integration",
    sout=[dec("integration", "IntegrationID(integration)", "identifier", reference_capable=True,
              reason="Created integration.")],
    vis_reason="Create integration/webhook.",
    reach=["Admin 'manage-incoming-integrations'/'manage-outgoing-integrations'."],
    evref="integrations.ts",
    notes="Outgoing-webhook 'script' runs in a server VM; 'urls' = SSRF. High-impact (code/SSRF).")

api("integrations.list", ["GET"],
    [variant("GET", [], resp_json([of("integrations")]), reason="list integrations",
             evidence="integrations.ts integrations.list")],
    "list_integrations",
    sout=[dec("integrations", "IntegrationID(integration)", "identifier", reference_capable=True,
              reason="Integrations (may expose webhook tokens/scripts).")],
    vis_reason="List integrations.", reach=["Admin 'manage-*-integrations'."], evref="integrations.ts")

for n, ms in [("integrations.remove", ["POST"]), ("integrations.get", ["GET"]), ("integrations.update", ["PUT"]),
              ("integrations.history", ["GET"]), ("integrations.replayOutgoing", ["POST"])]:
    api0(n, ms, n.replace(".", "_"), reach=["Admin 'manage-*-integrations'."], evref="integrations.ts")


# ===========================================================================
# MISC (DDP bridge, stats, directory)
# ===========================================================================
api("method.call/:method", ["POST"],
    [variant("POST", [rf("method", "path", required=True, description="server method name"),
                      rf("params", "body", description="method args")],
             resp_json([of("message")]), body_format="json",
             reason="REST bridge to ANY Meteor server method (huge indirect surface)",
             evidence="misc.ts method.call")],
    "call_method",
    vis_reason="DDP method bridge.",
    reach=["Authenticated. Proxies hundreds of server methods -> broad indirect attack surface."],
    evref="misc.ts", notes="Single node standing in for the whole Meteor-method surface; per-method authz varies.")

api("statistics", ["GET"],
    [variant("GET", [], resp_json([of("statistics")]), reason="admin reads workspace statistics",
             evidence="stats.ts statistics")],
    "read_statistics",
    vis_reason="Workspace statistics.", reach=["Admin 'view-statistics'."], evref="stats.ts")

for n, ms in [("directory", ["GET"]), ("spotlight", ["GET"]), ("pw.getPolicy", ["GET"]),
              ("method.callAnon/:method", ["POST"]), ("instances.get", ["GET"]), ("shield.svg", ["GET"]),
              ("assets.setAsset", ["POST"]), ("oauth-apps.create", ["POST"]), ("oauth-apps.list", ["GET"]),
              ("moderation.reportUser", ["POST"]), ("import.uploadImportFile", ["POST"]),
              ("statistics.telemetry", ["POST"])]:
    api0(n, ms, n.replace(".", "_").replace("/", "_"), reach=["Varies."], evref="misc.ts")


_finalize()


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded against rocket.chat:latest (==8.9 image;
# source is 9.1.0-develop, auth model stable). runtime/probe.ps1 -> probe_results/matrix.json.
# Identity labels: anonymous | user (regular workspace user) | admin.
# KEY RUNTIME FACTS: (1) permission denials surface as HTTP 400 (errorType
# 'error-not-authorized'), NOT 403. (2) users.list + settings returned 200 to a
# REGULAR user (broadly granted / self-filtered) -- see annotation rc-008.
# ===========================================================================
_RUNTIME = {
    "/api/v1/settings.public":      {"s": [200], "id": {"anonymous": [200]}},
    "/api/v1/login":                {"s": [200, 401], "id": {"anonymous": [200, 401]}},
    "/api/v1/me":                   {"s": [200, 401], "id": {"anonymous": [401], "user": [200]}},
    "/api/v1/channels.list":        {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/v1/users.list":           {"s": [200, 401], "id": {"anonymous": [401], "user": [200], "admin": [200]}},
    "/api/v1/settings":             {"s": [200], "id": {"user": [200], "admin": [200]}},
    "/api/v1/rooms.adminRooms":     {"s": [200, 400], "id": {"user": [400], "admin": [200]}},  # 400 = denied
    "/api/v1/statistics":           {"s": [200, 400], "id": {"user": [400], "admin": [200]}},
    "/api/v1/permissions.listAll":  {"s": [200], "id": {"admin": [200]}},
    "/api/v1/integrations.list":    {"s": [200], "id": {"admin": [200]}},
    "/api/v1/channels.create":      {"s": [200], "id": {"user": [200], "admin": [200]}},
    "/api/v1/roles.addUserToRole":  {"s": [400], "id": {"user": [400]}},  # self-elevate denied
    "/api/v1/users.create":         {"s": [200], "id": {"admin": [200]}},
    "/api/v1/users.register":       {"s": [200], "id": {"anonymous": [200]}},  # open registration enabled
}


def _apply_runtime():
    base = len(c.ORIGIN)
    for n in API_NODES:
        r = _RUNTIME.get(n["key"][base:])
        if r:
            n["statuses"] = r["s"]
            n["identity_statuses"] = r["id"]
            n["route_confirmed"] = True


_apply_runtime()


# ===========================================================================
# PAGE / CLIENT nodes
# ===========================================================================
PAGE_NODES = []


def page(key, methods, op="", kind="page", reach=None, evref="", notes=None):
    PAGE_NODES.append(c.node(K(key), kind, methods, variants=[], operation_semantic=op, params=[],
                             visibility="black_box", reachable=True, reach_conds=reach or [],
                             evidence=[ev(evref, "client")] if evref else [], notes=notes))


page("/", ["GET"], "web_client", kind="static", evref="apps/meteor/client", notes="React SPA shell.")
page("/admin", ["GET"], "admin_spa", kind="page", evref="apps/meteor/client", notes="Admin area (API-driven).")
page("/sockjs", ["GET"], "ddp_websocket", kind="page", evref="Meteor DDP",
     notes="DDP/websocket transport -- a separate real-time surface, out of scope for the REST GT.")


EDGES = [
    {"src": K("/"), "dst": K(V1 + "/login"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/"), "dst": K(V1 + "/me"), "methods": ["GET"], "triggers": ["xhr"]},
]
