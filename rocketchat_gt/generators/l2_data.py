# -*- coding: utf-8 -*-
"""Rocket.Chat (OSS) L2 action cores over the six Pengent predicates.

io_accounting fact strings use common.fact_key so they match Req/Eff. Auth plane
(l2lib.SUBJECTS): REST auth = X-Auth-Token + X-User-Id (or Bearer PAT). Admin routes add a
hasPermission check modeled as Can(...) requirements with the permission named in reach_conds;
room-scoped authz uses subjects RoomMember/RoomOwner. Evidence -> apps/meteor/server/api/v1.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind

V1 = "/api/v1"
ACTOR = subj()


def kf(f):
    return fact_key(f)


def src(ref, supports="route + handler"):
    return c.ev("source", "apps/meteor/server/api/v1/" + ref, supports)


def ent(k, t, role="target"):
    return entity(k, t, role)


def know(rt, e):
    return f_know(ACTOR, reference(rt, e))


def msel(m):
    return dict(sel_field="method", sel_values=[m])


_auth = f_auth(ACTOR, "AuthToken")


# ---- generic read/mutate helpers -----------------------------------------
def read(akey, name, business, path, subject, out_ref, out_type, out_role, perm=None, inref=None):
    o = know(out_ref, ent(out_type.lower(), out_type, out_role))
    reqs = [req("authentication", _auth, "Authenticated (X-Auth-Token).")]
    io_in = []
    if inref:
        rk, rt, rtype = inref
        kr = know(rt, ent(rk, rtype, "target"))
        reqs.append(req("knowledge", kr, "References the target by id."))
        io_in = [io("input", rk + " / " + rt + "(" + rtype.lower() + ")", "req", [kf(kr)])]
    if perm:
        reqs.append(req("authorization", f_can(ACTOR, "Read", ent(out_type.lower(), out_type, "scope")),
                        "Permission '" + perm + "'."))
    action(
        akey, name, "Read", business, subject,
        obj("entity", out_type.lower(), out_type, "response", "", out_ref, role=out_role),
        requirements=reqs, gen=[eff(o, "io_reference", "Returns " + out_type.lower() + ".")], kill=[],
        io_accounting=io_in + [io("output", out_type.lower() + " / " + out_ref, "gen", [kf(o)])],
        bindings=[bind(K(V1 + "/" + path), ["GET"], **(msel("GET") if "settings/:_id" in path else {}))],
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=[("Admin permission '" + perm + "'.") if perm else "Authenticated."],
        evidence=[src(business + ".ts")], confidence=0.8, reasoning=name + ".",
        description=name + ".")


def admin_mutate(akey, name, crud, business, path, subject, perm, obj_type, obj_ref, inref=None,
                 gen_new=False, kill_obj=False, note=None, method="POST"):
    tgt = ent(obj_type.lower(), obj_type, "target")
    reqs = [req("authentication", _auth, "Authenticated."),
            req("authorization", f_can(ACTOR, crud, tgt), "Permission '" + perm + "'.")]
    io_in = []
    if inref:
        rk, rt, rtype = inref
        kr = know(rt, ent(rk, rtype, "target"))
        reqs.append(req("knowledge", kr, "Targets an existing " + rtype.lower() + "."))
        io_in = [io("input", rk + " / " + rt + "(" + rtype.lower() + ")", "req", [kf(kr)])]
    gen, kill = [], []
    if gen_new:
        o = know(obj_ref, ent(obj_type.lower(), obj_type, "created"))
        gen = [eff(f_exists(ent(obj_type.lower(), obj_type, "created")), "action_semantics",
                   "A " + obj_type.lower() + " is created."),
               eff(o, "io_reference", "Returns the new " + obj_type.lower() + ".")]
        io_in += [io("output", obj_type.lower() + " / " + obj_ref, "gen", [kf(o)])]
    elif kill_obj:
        kill = [eff(f_exists(tgt), "action_semantics", "The " + obj_type.lower() + " is removed.")]
    else:
        gen = [eff(f_state(tgt, "fields", "updated"), "action_semantics", "State is updated.")]
    action(
        akey, name, crud, business, subject,
        obj("entity" if (gen_new or kill_obj) else "state", obj_type.lower(), obj_type,
            "request", "", obj_ref, role="created" if gen_new else "target",
            state_field="" if (gen_new or kill_obj) else "fields"),
        requirements=reqs, gen=gen, kill=kill, io_accounting=io_in,
        bindings=[bind(K(V1 + "/" + path), [method], **(msel(method) if path == "settings/:_id" else {}))],
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=["Admin permission '" + perm + "'."],
        evidence=[src(business + ".ts")], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


# ===========================================================================
# AUTH
# ===========================================================================
_pw = know("Password", ent("user", "User", "self"))
_tok = know("AuthToken", ent("session", "Session", "created"))
action(
    "login", "Log in", "Create", "login_user", "Anonymous",
    obj("state", "session", "Session", "response", "", "AuthToken(session)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", _pw, "Caller supplies username/email + password.")],
    gen=[eff(f_auth(ACTOR, "AuthToken"), "auth_transition", "Caller becomes authenticated."),
         eff(_tok, "io_reference", "Returns the X-Auth-Token + userId.")],
    kill=[],
    io_accounting=[io("input", "user / Username(user)", "object_attribute", [], "Login identifier."),
                   io("input", "password / Password(user)", "req", [kf(_pw)]),
                   io("output", "authToken / AuthToken(session)", "gen", [kf(_tok)])],
    bindings=[bind(K(V1 + "/login"), ["POST"])],
    vis="black_box", vis_reason="Public login.", reachable=True,
    reach_conds=["Public (authRequired:false). Brute-force / credential-stuffing; X-2fa-code for 2FA."],
    evidence=[src("../ApiClass.ts", "login")],
    confidence=0.9, reasoning="login returns an auth token + userId.",
    description="A visitor authenticates and receives an auth token.")

action(
    "logout", "Log out", "Delete", "logout_user", "User",
    obj("state", "session", "Session", "subject", "", "AuthToken(session)", role="self",
        state_field="authenticated"),
    requirements=[req("authentication", _auth, "Authenticated.")],
    gen=[], kill=[eff(f_auth(ACTOR, "AuthToken"), "auth_transition", "The auth token is invalidated.")],
    io_accounting=[], bindings=[bind(K(V1 + "/logout"), ["POST"])],
    vis="black_box", vis_reason="Logout.", reachable=True, reach_conds=["Authenticated."],
    evidence=[src("../ApiClass.ts", "logout")],
    confidence=0.9, reasoning="logout invalidates the token.",
    description="A user logs out.")

_me = know("UserID", ent("user", "User", "self"))
action(
    "read_me", "Read own account", "Read", "read_me", "User",
    obj("entity", "user", "User", "subject", "", "UserID(user)", role="self"),
    requirements=[req("authentication", _auth, "Authenticated.")],
    gen=[eff(_me, "io_reference", "Returns the caller's own account.")], kill=[],
    io_accounting=[io("output", "user / UserID(user)", "gen", [kf(_me)])],
    bindings=[bind(K(V1 + "/me"), ["GET"])],
    vis="black_box", vis_reason="Self.", reachable=True, reach_conds=["Authenticated."],
    evidence=[src("misc.ts", "me")],
    confidence=0.9, reasoning="me returns the authenticated user.",
    description="A user reads their own account.")

_newuser = know("UserID", ent("user", "User", "created"))
action(
    "register_user", "Self-register", "Create", "register_user", "Anonymous",
    obj("entity", "user", "User", "response", "", "UserID(user)", role="created"),
    requirements=[req("knowledge", _pw, "Caller supplies username/email/password.")],
    gen=[eff(f_exists(ent("user", "User", "created")), "action_semantics", "A user account is created."),
         eff(_newuser, "io_reference", "Returns the created user.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "object_attribute", [], "Chosen username."),
                   io("input", "email / UserEmail(user)", "object_attribute", [], "Email."),
                   io("input", "pass / Password(user)", "req", [kf(_pw)]),
                   io("output", "user / UserID(user)", "gen", [kf(_newuser)])],
    bindings=[bind(K(V1 + "/users.register"), ["POST"])],
    vis="black_box", vis_reason="Public self-registration.", reachable=True,
    reach_conds=["Public IF Accounts_RegistrationForm='Public' (config-dependent)."],
    evidence=[src("users.ts", "register")],
    confidence=0.85, reasoning="users.register creates an account when registration is open.",
    description="A visitor self-registers an account.")

_pat = know("PersonalAccessToken", ent("user", "User", "self"))
action(
    "generate_pat", "Generate personal access token", "Create", "generate_pat", "User",
    obj("entity", "token", "Token", "response", "", "PersonalAccessToken(user)", role="created"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Create", ent("token", "Token", "new")),
                      "Permission 'create-personal-access-tokens'.")],
    gen=[eff(_pat, "io_reference", "Mints a long-lived personal access token.")], kill=[],
    io_accounting=[io("input", "tokenName / -", "object_attribute", [], "Token label."),
                   io("output", "token / PersonalAccessToken(user)", "gen", [kf(_pat)])],
    bindings=[bind(K(V1 + "/users.generatePersonalAccessToken"), ["POST"])],
    vis="black_box", vis_reason="PAT mint.", reachable=True,
    reach_conds=["Permission 'create-personal-access-tokens'."],
    evidence=[src("users.ts", "generatePersonalAccessToken")],
    confidence=0.8, reasoning="Mints a persistent API credential.",
    description="A user mints a personal access token.")


# ===========================================================================
# USERS
# ===========================================================================
admin_mutate("create_user", "Create user", "Create", "create_user", "users.create",
             "Administrator", "create-user", "User", "UserID(user)", gen_new=True,
             note="roles[] in the body assigns privileges at creation -> escalation if 'admin'.")
admin_mutate("update_user", "Update user", "Update", "update_user", "users.update",
             "Administrator", "edit-other-user-info", "User", "UserID(user)",
             inref=("userId", "UserID", "User"),
             note="Can set another user's password/roles -> takeover + escalation.")
admin_mutate("delete_user", "Delete user", "Delete", "delete_user", "users.delete",
             "Administrator", "delete-user", "User", "UserID(user)",
             inref=("userId", "UserID", "User"), kill_obj=True)
admin_mutate("set_user_active", "Set user active status", "Update", "set_user_active",
             "users.setActiveStatus", "Administrator", "edit-other-user-active-status", "User",
             "UserID(user)", inref=("userId", "UserID", "User"))
read("read_user", "Read user info", "read_user", "users.info", "User",
     "UserID", "User", "target", inref=("userId", "UserID", "User"))
admin_mutate("reset_avatar", "Reset avatar", "Update", "reset_avatar", "users.resetAvatar",
             "User", "edit-other-user-avatar", "User", "UserID(user)",
             inref=("userId", "UserID", "User"))
read("list_users", "List users", "list_users", "users.list", "Administrator",
     "UserID", "User", "collection", perm="view-user-administration")


# ===========================================================================
# CHANNELS / GROUPS
# ===========================================================================
admin_mutate("create_channel", "Create channel", "Create", "create_channel", "channels.create",
             "User", "create-c", "Room", "RoomID(room)", gen_new=True)
admin_mutate("delete_channel", "Delete channel", "Delete", "delete_channel", "channels.delete",
             "RoomOwner", "delete-c", "Room", "RoomID(room)", inref=("roomId", "RoomID", "Room"),
             kill_obj=True)
read("read_channel", "Read channel info", "read_channel", "channels.info", "RoomMember",
     "RoomID", "Room", "target", inref=("roomId", "RoomID", "Room"))
read("list_channels", "List channels", "list_channels", "channels.list", "Administrator",
     "RoomID", "Room", "collection", perm="view-c-room")
admin_mutate("invite_channel", "Invite to channel", "Update", "invite_channel", "channels.invite",
             "RoomMember", "add-user-to-joined-room", "Room", "RoomID(room)",
             inref=("roomId", "RoomID", "Room"))
admin_mutate("kick_channel", "Kick from channel", "Update", "kick_channel", "channels.kick",
             "RoomOwner", "remove-user", "Room", "RoomID(room)", inref=("roomId", "RoomID", "Room"))
admin_mutate("add_channel_owner", "Grant channel owner", "Update", "add_channel_owner",
             "channels.addOwner", "RoomOwner", "set-owner", "Room", "RoomID(room)",
             inref=("roomId", "RoomID", "Room"), note="Room-level privilege escalation.")
admin_mutate("set_channel_type", "Set channel type", "Update", "set_channel_type", "channels.setType",
             "RoomOwner", "edit-room", "Room", "RoomID(room)", inref=("roomId", "RoomID", "Room"),
             note="public<->private visibility boundary change.")
read("list_channel_members", "List channel members", "list_channel_members", "channels.members",
     "RoomMember", "UserID", "User", "collection", inref=("roomId", "RoomID", "Room"))
admin_mutate("create_group", "Create private group", "Create", "create_group", "groups.create",
             "User", "create-p", "Room", "RoomID(room)", gen_new=True)
read("list_groups", "List groups", "list_groups", "groups.list", "User",
     "RoomID", "Room", "collection")


# ===========================================================================
# CHAT
# ===========================================================================
def chat_create(akey, name, path, business):
    o = know("MessageID", ent("message", "Message", "created"))
    action(
        akey, name, "Create", business, "RoomMember",
        obj("entity", "message", "Message", "response", "", "MessageID(message)", role="created"),
        requirements=[req("authentication", _auth, "Authenticated."),
                      req("knowledge", know("RoomID", ent("room", "Room", "target")),
                          "Targets a room the caller can post to."),
                      req("authorization", f_can(ACTOR, "Create", ent("message", "Message", "new")),
                          "Member of the room (post permission).")],
        gen=[eff(f_exists(ent("message", "Message", "created")), "action_semantics", "A message is stored."),
             eff(o, "io_reference", "Returns the message.")],
        kill=[],
        io_accounting=[io("input", "roomId / RoomID(room)", "req",
                          [kf(know("RoomID", ent("room", "Room", "target")))]),
                       io("input", "text / -", "object_attribute", [], "Message body (content-injection surface)."),
                       io("output", "message / MessageID(message)", "gen", [kf(o)])],
        bindings=[bind(K(V1 + "/" + path), ["POST"])],
        vis="black_box", vis_reason=name + ".", reachable=True, reach_conds=["Authenticated member of the room."],
        evidence=[src("chat.ts")], confidence=0.85, reasoning=name + ".", description=name + ".")


chat_create("post_message", "Post message", "chat.postMessage", "post_message")
chat_create("send_message", "Send message", "chat.sendMessage", "send_message")

admin_mutate("update_message", "Edit message", "Update", "update_message", "chat.update",
             "RoomMember", "edit-message", "Message", "MessageID(message)",
             inref=("msgId", "MessageID", "Message"))
admin_mutate("delete_message", "Delete message", "Delete", "delete_message", "chat.delete",
             "RoomMember", "delete-message", "Message", "MessageID(message)",
             inref=("msgId", "MessageID", "Message"), kill_obj=True)
admin_mutate("react_message", "React to message", "Update", "react_message", "chat.react",
             "RoomMember", "post-readonly", "Message", "MessageID(message)",
             inref=("messageId", "MessageID", "Message"))
read("read_message", "Read message", "read_message", "chat.getMessage", "RoomMember",
     "MessageID", "Message", "target", inref=("msgId", "MessageID", "Message"))


# ===========================================================================
# ROOMS
# ===========================================================================
admin_mutate("upload_file", "Upload file to room", "Create", "upload_file", "rooms.media/:rid",
             "RoomMember", "post-message-with-files", "File", "FileID(file)",
             inref=("rid", "RoomID", "Room"), gen_new=True,
             note="File upload (type/size validation, storage).")
read("admin_list_rooms", "Admin list all rooms", "admin_list_rooms", "rooms.adminRooms",
     "Administrator", "RoomID", "Room", "collection", perm="view-room-administration")
admin_mutate("save_room_settings", "Save room settings", "Update", "save_room_settings",
             "rooms.saveRoomSettings", "RoomOwner", "edit-room", "Room", "RoomID(room)",
             inref=("rid", "RoomID", "Room"))
admin_mutate("clean_history", "Clean room history", "Delete", "clean_history", "rooms.cleanHistory",
             "Administrator", "clean-channel-history", "Message", "MessageID(message)",
             inref=("roomId", "RoomID", "Room"), kill_obj=True, note="Bulk destructive message deletion.")
_exp = know("RoomExport", ent("room", "Room", "self"))
action(
    "export_room", "Export room", "Read", "export_room", "RoomMember",
    obj("entity", "room", "Room", "request", "rid", "RoomID(room)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", know("RoomID", ent("room", "Room", "target")), "Target room."),
                  req("authorization", f_can(ACTOR, "Read", ent("room", "Room", "target")),
                      "Permission 'mail-messages' or room access.")],
    gen=[eff(_exp, "io_reference", "Exports the room's messages (exfiltration).")], kill=[],
    io_accounting=[io("input", "rid / RoomID(room)", "req", [kf(know("RoomID", ent("room", "Room", "target")))]),
                   io("output", "export / RoomExport(room)", "gen", [kf(_exp)])],
    bindings=[bind(K(V1 + "/rooms.export"), ["POST"])],
    vis="black_box", vis_reason="Export room.", reachable=True, reach_conds=["Permission 'mail-messages'."],
    evidence=[src("rooms.ts")], confidence=0.8, reasoning="rooms.export dumps room messages.",
    description="A user exports a room's message history.")


# ===========================================================================
# SETTINGS / PERMISSIONS / ROLES
# ===========================================================================
_pubset = know("SettingKey", ent("setting", "Setting", "public"))
action(
    "public_settings", "Read public settings", "Read", "public_settings", "Anonymous",
    obj("entity", "setting", "Setting", "response", "", "SettingKey(setting)", role="public"),
    requirements=[],
    gen=[eff(_pubset, "io_reference", "Returns public settings (fingerprinting).")], kill=[],
    io_accounting=[io("output", "settings / SettingKey(setting)", "gen", [kf(_pubset)])],
    bindings=[bind(K(V1 + "/settings.public"), ["GET"])],
    vis="black_box", vis_reason="Public settings.", reachable=True,
    reach_conds=["Public (authRequired:false)."],
    evidence=[src("settings.ts", "public")],
    confidence=0.9, reasoning="settings.public needs no auth.",
    description="Anyone reads public workspace settings.")

read("list_settings", "List settings", "list_settings", "settings", "Administrator",
     "SettingKey", "Setting", "collection", perm="view-privileged-setting")
read("read_setting", "Read a setting", "read_setting", "settings/:_id", "Administrator",
     "SettingKey", "Setting", "target", perm="view-privileged-setting", inref=("_id", "SettingKey", "Setting"))
admin_mutate("change_setting", "Change a setting", "Update", "manage_setting", "settings/:_id",
             "Administrator", "edit-privileged-setting", "Setting", "SettingKey(setting)",
             inref=("_id", "SettingKey", "Setting"),
             note="Setting writes reconfigure auth/uploads/integrations -> workspace takeover.")

read("list_permissions", "List permissions", "list_permissions", "permissions.listAll", "User",
     "PermissionID", "Permission", "collection")
admin_mutate("update_permissions", "Rewrite permissions", "Update", "update_permissions",
             "permissions.update", "Administrator", "access-permissions", "Permission",
             "PermissionID(permission)", note="Granting a permission to a low role = global escalation.")
_role = know("RoleID", ent("role", "Role", "target"))
action(
    "add_user_to_role", "Assign role to user", "Update", "add_user_to_role", "Administrator",
    obj("state", "role", "Role", "request", "", "RoleID(role)", role="target", state_field="members"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", know("Username", ent("user", "User", "target")), "User to elevate."),
                  req("authorization", f_can(ACTOR, "Update", ent("role", "Role", "target")),
                      "Permission 'access-permissions'.")],
    gen=[eff(f_state(ent("role", "Role", "target"), "members", "added"), "action_semantics",
             "The user is granted the role.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "req",
                      [kf(know("Username", ent("user", "User", "target")))]),
                   io("input", "roleName / -", "object_attribute", [], "Role (e.g. admin).")],
    bindings=[bind(K(V1 + "/roles.addUserToRole"), ["POST"])],
    vis="black_box", vis_reason="Assign role.", reachable=True,
    reach_conds=["Permission 'access-permissions'. Assigning 'admin' = full escalation."],
    evidence=[src("roles.ts")], confidence=0.8, reasoning="roles.addUserToRole grants a role.",
    description="An admin assigns a role (e.g. admin) to a user.")
read("list_roles", "List roles", "list_roles", "roles.list", "User",
     "RoleID", "Role", "collection")


# ===========================================================================
# INTEGRATIONS / MISC
# ===========================================================================
admin_mutate("create_integration", "Create integration/webhook", "Create", "create_integration",
             "integrations.create", "Administrator", "manage-outgoing-integrations", "Integration",
             "IntegrationID(integration)", gen_new=True,
             note="Outgoing-webhook 'script' runs in a server VM; 'urls' = SSRF. Code/SSRF-adjacent.")
read("list_integrations", "List integrations", "list_integrations", "integrations.list",
     "Administrator", "IntegrationID", "Integration", "collection", perm="manage-outgoing-integrations")

action(
    "call_method", "Call server method (DDP bridge)", "Update", "call_method", "User",
    obj("entity", "method", "Method", "request", "method", "", role="invoked"),
    requirements=[req("authentication", _auth, "Authenticated.")],
    gen=[], kill=[],
    io_accounting=[io("input", "method / -", "object_attribute", [], "Server method name."),
                   io("input", "params / -", "object_attribute", [], "Method arguments.")],
    bindings=[bind(K(V1 + "/method.call/:method"), ["POST"])],
    vis="black_box", vis_reason="DDP method bridge.", reachable=True,
    reach_conds=["Authenticated. Proxies ANY Meteor server method -> broad indirect surface; per-method authz varies."],
    evidence=[src("misc.ts", "method.call")],
    confidence=0.7, reasoning="method.call invokes a server method over REST.",
    description="A user invokes an arbitrary server method via the REST bridge.")

read("read_statistics", "Read statistics", "read_statistics", "statistics", "Administrator",
     "StatID", "Statistic", "collection", perm="view-statistics")
