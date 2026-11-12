# -*- coding: utf-8 -*-
"""Directus L2 action cores over the six Pengent predicates.

io_accounting fact strings use common.fact_key so they match Req/Eff. Auth: a token
(Bearer | ?access_token= | cookie) -> accountability -> role -> policies -> permissions.
A policy with admin_access=true BYPASSES checks (subject 'Admin'). No token => public role
(subject 'Anonymous'). Permission grants are modeled as Can(...) with the collection/action
named in reach_conds. Evidence -> directus/api/src/controllers.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind

ACTOR = subj()


def kf(f):
    return fact_key(f)


def src(ref, supports="route + controller"):
    return c.ev("source", "directus/api/src/controllers/" + ref, supports)


def ent(k, t, role="target"):
    return entity(k, t, role)


def know(rt, e):
    return f_know(ACTOR, reference(rt, e))


_tok_auth = f_auth(ACTOR, "AccessToken")

AUTHS = {"token": (_tok_auth, "Authenticated (token resolves to a policy)."),
         "none": (None, None)}


def _mbind(path, methods):
    return [bind(K(path), methods, sel_field="method", sel_values=methods)]


def read(akey, name, business, path, methods, subject, out_ref, out_type, out_role,
         auth="token", perm=None, inref=None, reach=None, note=None, evref=None):
    o = know(out_ref, ent(out_type.lower(), out_type, out_role))
    reqs = []
    a, areason = AUTHS[auth]
    if a:
        reqs.append(req("authentication", a, areason))
    io_in = []
    if inref:
        rk, rt, rtype = inref
        kr = know(rt, ent(rk, rtype, "target"))
        reqs.append(req("knowledge", kr, "References the target by id."))
        io_in = [io("input", rk + " / " + rt + "(" + rtype.lower() + ")", "req", [kf(kr)])]
    if perm:
        reqs.append(req("authorization", f_can(ACTOR, "Read", ent(out_type.lower(), out_type, "scope")),
                        "Policy grants '" + perm + "'."))
    action(
        akey, name, "Read", business, subject,
        obj("entity", out_type.lower(), out_type, "response", "", out_ref, role=out_role),
        requirements=reqs, gen=[eff(o, "io_reference", "Returns " + out_type.lower() + ".")], kill=[],
        io_accounting=io_in + [io("output", out_type.lower() + " / " + out_ref, "gen", [kf(o)])],
        bindings=_mbind(path, methods),
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=reach or ["Authenticated + policy permission."],
        evidence=[src(evref or business)], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


def mutate(akey, name, crud, business, path, methods, subject, obj_type, obj_ref,
           auth="token", perm=None, inref=None, gen_new=False, kill_obj=False,
           note=None, reach=None, evref=None, state_field="fields"):
    tgt = ent(obj_type.lower(), obj_type, "target")
    reqs = []
    a, areason = AUTHS[auth]
    if a:
        reqs.append(req("authentication", a, areason))
    if perm:
        reqs.append(req("authorization", f_can(ACTOR, crud, tgt), "Policy grants '" + perm + "'."))
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
        gen = [eff(f_state(tgt, state_field, "updated"), "action_semantics", "State is updated.")]
    action(
        akey, name, crud, business, subject,
        obj("entity" if (gen_new or kill_obj) else "state", obj_type.lower(), obj_type,
            "request", "", obj_ref, role="created" if gen_new else "target",
            state_field="" if (gen_new or kill_obj) else state_field),
        requirements=reqs, gen=gen, kill=kill, io_accounting=io_in,
        bindings=_mbind(path, methods),
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=reach or ["Authenticated + policy permission."],
        evidence=[src(evref or business)], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


# ===========================================================================
# AUTH
# ===========================================================================
_pw = know("Password", ent("user", "User", "self"))
_tok = know("AccessToken", ent("session", "Session", "created"))
action(
    "user_login", "Log in", "Create", "user_login", "Anonymous",
    obj("state", "session", "Session", "response", "", "AccessToken(session)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", _pw, "Caller supplies email + password.")],
    gen=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "Caller becomes authenticated."),
         eff(_tok, "io_reference", "Returns access + refresh tokens.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Login email."),
                   io("input", "password / Password(user)", "req", [kf(_pw)]),
                   io("output", "access_token / AccessToken(session)", "gen", [kf(_tok)])],
    bindings=_mbind("/auth/login", ["POST"]),
    vis="black_box", vis_reason="Public login.", reachable=True,
    reach_conds=["Public. Brute-force / credential-stuffing; 'otp' for 2FA."],
    evidence=[src("auth.ts", "login")],
    confidence=0.9, reasoning="login returns access+refresh tokens.",
    description="A visitor authenticates and receives access+refresh tokens.")

_rtok = know("RefreshToken", ent("session", "Session", "held"))
action(
    "refresh_token", "Refresh token", "Create", "refresh_token", "Anonymous",
    obj("state", "session", "Session", "request", "", "AccessToken(session)", role="created",
        state_field="access_token"),
    requirements=[req("knowledge", _rtok, "Caller presents a refresh token (body or cookie).")],
    gen=[eff(_tok, "io_reference", "Returns a fresh access token (+ rotated refresh).")], kill=[],
    io_accounting=[io("input", "refresh_token / RefreshToken(session)", "req", [kf(_rtok)]),
                   io("output", "access_token / AccessToken(session)", "gen", [kf(_tok)])],
    bindings=_mbind("/auth/refresh", ["POST"]),
    vis="black_box", vis_reason="Token refresh.", reachable=True,
    reach_conds=["Public; consumes a refresh token (replay / rotation surface)."],
    evidence=[src("auth.ts", "refresh")],
    confidence=0.85, reasoning="refresh mints a new access token.",
    description="A holder of a refresh token obtains a new access token.")

action(
    "password_request", "Request password reset", "Create", "password_request", "Anonymous",
    obj("state", "user", "User", "request", "", "UserEmail(user)", role="target", state_field="reset_requested"),
    requirements=[],
    gen=[eff(f_state(ent("user", "User", "target"), "reset_requested", "true"), "state_transition",
             "A reset email is sent if the address matches.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [],
                      "Target email (enumeration oracle)."),
                   io("input", "reset_url / -", "object_attribute", [], "Reset link base (allow-listed).")],
    bindings=_mbind("/auth/password/request", ["POST"]),
    vis="black_box", vis_reason="Password reset request.", reachable=True,
    reach_conds=["Public. Email enumeration; reset_url validated against PASSWORD_RESET_URL_ALLOW_LIST."],
    evidence=[src("auth.ts", "password/request")],
    confidence=0.75, reasoning="password/request is a public reset trigger.",
    description="A visitor requests a password-reset email.")

_rst = know("ResetToken", ent("user", "User", "target"))
action(
    "password_reset", "Reset password", "Update", "password_reset", "Anonymous",
    obj("state", "user", "User", "request", "", "UserID(user)", role="target", state_field="password"),
    requirements=[req("knowledge", _rst, "Caller holds a valid reset token."),
                  req("knowledge", _pw, "Caller supplies a new password.")],
    gen=[eff(f_state(ent("user", "User", "target"), "password", "reset"), "state_transition",
             "The user password is reset.")],
    kill=[],
    io_accounting=[io("input", "token / ResetToken(user)", "req", [kf(_rst)]),
                   io("input", "password / Password(user)", "req", [kf(_pw)])],
    bindings=_mbind("/auth/password/reset", ["POST"]),
    vis="black_box", vis_reason="Password reset.", reachable=True,
    reach_conds=["Public IF a valid reset token is held -> account takeover."],
    evidence=[src("auth.ts", "password/reset")],
    confidence=0.8, reasoning="password/reset with a token takes over an account.",
    description="An actor with a reset token sets a new password.")

action(
    "logout", "Log out", "Delete", "logout", "User",
    obj("state", "session", "Session", "subject", "", "RefreshToken(session)", role="self",
        state_field="authenticated"),
    requirements=[req("knowledge", _rtok, "Caller presents the refresh token/session to invalidate.")],
    gen=[], kill=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "The session is invalidated.")],
    io_accounting=[io("input", "refresh_token / RefreshToken(session)", "req", [kf(_rtok)])],
    bindings=_mbind("/auth/logout", ["POST"]),
    vis="black_box", vis_reason="Logout.", reachable=True, reach_conds=["Holder of a refresh token/session."],
    evidence=[src("auth.ts", "logout")],
    confidence=0.9, reasoning="logout invalidates the session.",
    description="A user logs out, invalidating their refresh token.")

read("list_auth_providers", "List auth providers", "list_auth_providers", "/auth", ["GET"],
     "Anonymous", "AuthProvider(provider)", "Provider", "collection", auth="none",
     reach=["Public. Fingerprints configured SSO providers."], evref="auth.ts")


# ===========================================================================
# SERVER / BOOTSTRAP
# ===========================================================================
_newadmin = know("UserID", ent("admin", "AdminUser", "created"))
action(
    "server_setup", "Bootstrap first admin", "Create", "server_setup", "Anonymous",
    obj("entity", "admin", "AdminUser", "response", "", "UserID(admin)", role="created"),
    requirements=[req("knowledge", _pw, "Caller supplies the first admin's email + password.")],
    gen=[eff(f_exists(ent("admin", "AdminUser", "created")), "action_semantics",
             "The first admin account is created."),
         eff(_newadmin, "io_reference", "Returns success.")],
    kill=[],
    io_accounting=[io("input", "admin.email / UserEmail(user)", "object_attribute", [], "Admin email."),
                   io("input", "admin.password / Password(user)", "req", [kf(_pw)]),
                   io("output", "data / UserID(admin)", "gen", [kf(_newadmin)])],
    bindings=_mbind("/server/setup", ["POST"]),
    vis="black_box", vis_reason="Bootstrap admin.", reachable=True,
    reach_conds=["Public but ONLY while setup is not completed (no admin) -> first-boot takeover window."],
    evidence=[src("server.ts", "setup")],
    confidence=0.85, reasoning="server/setup seizes admin on an un-provisioned instance.",
    description="An actor creates the first admin on an un-initialized instance.")

read("server_specs_oas", "Read OpenAPI spec", "server_specs_oas", "/server/specs/oas", ["GET"],
     "User", "OpenApiSpec(server)", "Spec", "self", auth="token",
     reach=["OPENAPI_ENABLED; accountability-scoped. Discloses visible collections/fields (recon)."],
     evref="server.ts")
read("server_info", "Read server info", "server_info", "/server/info", ["GET"],
     "Anonymous", "ServerInfo(server)", "Info", "self", auth="none",
     reach=["Public (limited) / authenticated (more). Version + project fingerprinting."], evref="server.ts")


# ===========================================================================
# ITEMS (dynamic per-collection CRUD) -- cover all four verbs on one node
# ===========================================================================
_items = know("ItemID", ent("item", "Item", "collection"))
action(
    "item_read", "Read collection items", "Read", "item_read", "Anonymous",
    obj("entity", "item", "Item", "response", "collection", "ItemID(item)", role="collection"),
    requirements=[req("knowledge", know("CollectionName", ent("collection", "Collection", "target")),
                      "Targets a collection by name."),
                  req("authorization", f_can(ACTOR, "Read", ent("item", "Item", "scope")),
                      "Policy grants read on <collection> (public role if no token).")],
    gen=[eff(_items, "io_reference", "Returns permission-filtered items.")], kill=[],
    io_accounting=[io("input", "collection / CollectionName(collection)", "req",
                      [kf(know("CollectionName", ent("collection", "Collection", "target")))]),
                   io("input", "fields / -", "object_attribute", [], "Field selection / relation traversal."),
                   io("output", "data / ItemID(item)", "gen", [kf(_items)])],
    bindings=[bind(K("/items/:collection"), ["GET", "SEARCH"], sel_field="method", sel_values=["GET", "SEARCH"])],
    vis="black_box", vis_reason="Dynamic collection read.", reachable=True,
    reach_conds=["Policy read grant on the collection (public role if unauthenticated). 'fields'/'deep' "
                 "traverse relations and over-expose related data."],
    evidence=[src("items.ts", "readHandler")],
    confidence=0.85, reasoning="the generic read is the primary data surface.",
    description="A caller reads a collection's items, permission-filtered.")

_newitem = know("ItemID", ent("item", "Item", "created"))
action(
    "item_create", "Create collection item", "Create", "item_create", "User",
    obj("entity", "item", "Item", "response", "collection", "ItemID(item)", role="created"),
    requirements=[req("authentication", _tok_auth, "Authenticated."),
                  req("knowledge", know("CollectionName", ent("collection", "Collection", "target")),
                      "Targets a collection."),
                  req("authorization", f_can(ACTOR, "Create", ent("item", "Item", "new")),
                      "Policy grants create on <collection>.")],
    gen=[eff(f_exists(ent("item", "Item", "created")), "action_semantics", "An item is created."),
         eff(_newitem, "io_reference", "Returns the created item.")],
    kill=[],
    io_accounting=[io("input", "collection / CollectionName(collection)", "req",
                      [kf(know("CollectionName", ent("collection", "Collection", "target")))]),
                   io("input", "data / -", "object_attribute", [], "Item fields (field-permission scoped)."),
                   io("output", "data / ItemID(item)", "gen", [kf(_newitem)])],
    bindings=[bind(K("/items/:collection"), ["POST"], sel_field="method", sel_values=["POST"])],
    vis="black_box", vis_reason="Dynamic collection create.", reachable=True,
    reach_conds=["Policy create grant on the collection."],
    evidence=[src("items.ts", "POST")],
    confidence=0.85, reasoning="create writes an item; fields are field-permission scoped.",
    description="A caller creates an item in a collection.")

mutate("item_update_batch", "Update items (batch/query)", "Update", "item_update_batch",
       "/items/:collection", ["PATCH"], "User", "Item", "ItemID(item)", perm="<collection>.update",
       inref=("collection", "CollectionName", "Collection"), state_field="fields",
       reach=["Policy update grant. Batch update by keys/query = high blast radius."],
       evref="items.ts", note="updateByQuery mutates every matching row.")
mutate("item_delete_batch", "Delete items (batch/query)", "Delete", "item_delete_batch",
       "/items/:collection", ["DELETE"], "User", "Item", "ItemID(item)", perm="<collection>.delete",
       inref=("collection", "CollectionName", "Collection"), kill_obj=True,
       reach=["Policy delete grant. deleteByQuery is destructive at scale."], evref="items.ts")

read("item_read_one", "Read one item", "item_read_one", "/items/:collection/:pk", ["GET"],
     "Anonymous", "ItemID(item)", "Item", "target", auth="none", perm="<collection>.read",
     inref=("pk", "ItemID", "Item"),
     reach=["Policy read grant. A permission without a row filter exposes any item by pk (IDOR surface)."],
     evref="items.ts", note="Row-level access = permission filter; missing filter -> IDOR.")
mutate("item_update_one", "Update one item", "Update", "item_update_one", "/items/:collection/:pk", ["PATCH"],
       "User", "Item", "ItemID(item)", perm="<collection>.update", inref=("pk", "ItemID", "Item"),
       reach=["Policy update grant; row filter governs whether others' items are editable (IDOR surface)."],
       evref="items.ts")
mutate("item_delete_one", "Delete one item", "Delete", "item_delete_one", "/items/:collection/:pk", ["DELETE"],
       "User", "Item", "ItemID(item)", perm="<collection>.delete", inref=("pk", "ItemID", "Item"),
       kill_obj=True, reach=["Policy delete grant."], evref="items.ts")


# ===========================================================================
# USERS
# ===========================================================================
read("list_users", "List users", "list_users", "/users", ["GET", "SEARCH"], "User",
     "UserID(user)", "User", "collection", perm="directus_users.read",
     reach=["directus_users read grant. PII exposure if over-granted."], evref="users.ts")
mutate("create_user", "Create user", "Create", "create_user", "/users", ["POST"], "User",
       "User", "UserID(user)", perm="directus_users.create", gen_new=True,
       reach=["directus_users create grant. 'role' assigns privileges -> escalation if an admin role."],
       evref="users.ts", note="Role assignment at creation = escalation lever.")
read("read_user", "Read one user", "read_user", "/users/:pk", ["GET"], "User",
     "UserID(user)", "User", "target", perm="directus_users.read", inref=("pk", "UserID", "User"),
     reach=["directus_users read grant."], evref="users.ts")
mutate("update_user", "Update one user", "Update", "update_user", "/users/:pk", ["PATCH"], "User",
       "User", "UserID(user)", perm="directus_users.update", inref=("pk", "UserID", "User"),
       state_field="role", reach=["directus_users update grant. PATCH role/password on another user "
                                  "(absent a row filter) = takeover / escalation."],
       evref="users.ts", note="Account-takeover + privilege-escalation primitive.")
mutate("delete_user", "Delete one user", "Delete", "delete_user", "/users/:pk", ["DELETE"], "User",
       "User", "UserID(user)", perm="directus_users.delete", inref=("pk", "UserID", "User"), kill_obj=True,
       reach=["directus_users delete grant."], evref="users.ts")
read("read_me", "Read own account", "read_me", "/users/me", ["GET"], "User",
     "UserID(user)", "User", "self", auth="token", reach=["Authenticated (or share)."], evref="users.ts")
mutate("update_me", "Update own account", "Update", "update_me", "/users/me", ["PATCH"], "User",
       "User", "UserID(user)", auth="token", state_field="profile",
       reach=["Authenticated. Editable-field allow-list governs self-escalation."],
       evref="users.ts", note="Must not expose role/policies for self-edit.")
mutate("invite_user", "Invite user", "Create", "invite_user", "/users/invite", ["POST"], "User",
       "User", "UserID(user)", perm="directus_users.create", gen_new=True,
       reach=["directus_users create grant. Invites into an arbitrary 'role' (escalation if admin)."],
       evref="users.ts")
action(
    "accept_invite", "Accept user invite", "Update", "accept_invite", "Anonymous",
    obj("state", "user", "User", "request", "", "UserID(user)", role="target", state_field="password"),
    requirements=[req("knowledge", know("InviteToken", ent("invite", "Invite", "held")),
                      "Caller holds an invite token."),
                  req("knowledge", _pw, "Caller sets a password.")],
    gen=[eff(f_state(ent("user", "User", "target"), "password", "set"), "state_transition",
             "The invited account is activated.")],
    kill=[],
    io_accounting=[io("input", "token / InviteToken(invite)", "req",
                      [kf(know("InviteToken", ent("invite", "Invite", "held")))]),
                   io("input", "password / Password(user)", "req", [kf(_pw)])],
    bindings=_mbind("/users/invite/accept", ["POST"]),
    vis="black_box", vis_reason="Invite acceptance.", reachable=True,
    reach_conds=["Public IF a valid invite token is held."],
    evidence=[src("users.ts", "invite/accept")],
    confidence=0.8, reasoning="invite/accept activates an account from a token.",
    description="An invited actor sets a password and activates the account.")
_reguser = know("UserID", ent("user", "User", "created"))
action(
    "register_user", "Self-register", "Create", "register_user", "Anonymous",
    obj("entity", "user", "User", "response", "", "UserID(user)", role="created"),
    requirements=[req("knowledge", _pw, "Caller supplies email + password.")],
    gen=[eff(f_exists(ent("user", "User", "created")), "action_semantics", "A user is registered."),
         eff(_reguser, "io_reference", "Returns success (pending verification).")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Email."),
                   io("input", "password / Password(user)", "req", [kf(_pw)]),
                   io("output", "data / UserID(user)", "gen", [kf(_reguser)])],
    bindings=_mbind("/users/register", ["POST"]),
    vis="black_box", vis_reason="Public self-registration.", reachable=True,
    reach_conds=["Public IF registration is enabled (settings). Rate-limited. Lands in the default role."],
    evidence=[src("users.ts", "register")],
    confidence=0.8, reasoning="register opens self-service accounts when enabled.",
    description="A visitor self-registers an account.")
mutate("disable_user_tfa", "Disable a user's 2FA (admin)", "Update", "disable_user_tfa",
       "/users/:pk/tfa/disable", ["POST"], "Admin", "User", "UserID(user)", auth="token",
       perm="admin", inref=("pk", "UserID", "User"), state_field="tfa",
       reach=["accountability.admin. Disables a victim's 2FA (account-weakening)."], evref="users.ts")


# ===========================================================================
# RBAC
# ===========================================================================
read("list_roles", "List roles", "list_roles", "/roles", ["GET", "SEARCH"], "User",
     "RoleID(role)", "Role", "collection", perm="directus_roles.read", reach=["directus_roles read grant."],
     evref="roles.ts")
mutate("create_role", "Create role", "Create", "create_role", "/roles", ["POST"], "User",
       "Role", "RoleID(role)", perm="directus_roles.create", gen_new=True,
       reach=["directus_roles create grant."], evref="roles.ts")
mutate("update_role", "Update role (attach policies)", "Update", "update_role", "/roles/:pk", ["PATCH"],
       "User", "Role", "RoleID(role)", perm="directus_roles.update", inref=("pk", "RoleID", "Role"),
       state_field="policies", reach=["directus_roles update grant. Attaching an admin-access policy = escalation."],
       evref="roles.ts", note="Role<->policy link is an escalation lever.")
mutate("create_policy", "Create policy (admin_access)", "Create", "create_policy", "/policies", ["POST"],
       "User", "Policy", "PolicyID(policy)", perm="directus_policies.create", gen_new=True,
       reach=["directus_policies create grant. admin_access=true policy = full superuser."],
       evref="policies.ts", note="TOP escalation: a policy carries the admin_access bypass flag.")
read("list_policies", "List policies", "list_policies", "/policies", ["GET", "SEARCH"], "User",
     "PolicyID(policy)", "Policy", "collection", perm="directus_policies.read",
     reach=["directus_policies read grant."], evref="policies.ts")
mutate("update_policy", "Update policy flags", "Update", "update_policy", "/policies/:pk", ["PATCH"],
       "User", "Policy", "PolicyID(policy)", perm="directus_policies.update", inref=("pk", "PolicyID", "Policy"),
       state_field="admin_access", reach=["directus_policies update grant. Flipping admin_access=true = escalation."],
       evref="policies.ts")
mutate("create_permission", "Create permission rule", "Create", "create_permission", "/permissions", ["POST"],
       "User", "Permission", "PermissionID(permission)", perm="directus_permissions.create", gen_new=True,
       reach=["directus_permissions create grant. A broad/unfiltered rule opens data to the policy's holders."],
       evref="permissions.ts", note="Permission rows are the content-API grants.")
read("list_permissions", "List permission rules", "list_permissions", "/permissions", ["GET", "SEARCH"],
     "User", "PermissionID(permission)", "Permission", "collection", perm="directus_permissions.read",
     reach=["directus_permissions read grant."], evref="permissions.ts")
mutate("update_permission", "Edit permission rule", "Update", "update_permission", "/permissions/:pk", ["PATCH"],
       "User", "Permission", "PermissionID(permission)", perm="directus_permissions.update",
       inref=("pk", "PermissionID", "Permission"), reach=["directus_permissions update grant."],
       evref="permissions.ts")
read("permissions_me", "Read own permissions", "permissions_me", "/permissions/me", ["GET"], "User",
     "PermissionID(permission)", "Permission", "self", auth="token",
     reach=["Authenticated; discloses the caller's effective grants."], evref="permissions.ts")
mutate("assign_policy", "Assign policy to user/role", "Create", "assign_policy", "/access", ["POST"],
       "User", "Access", "AccessID(access)", perm="directus_access.create", gen_new=True,
       reach=["directus_access create grant. Attaching an admin-access policy to a user = escalation."],
       evref="access.ts", note="directus_access junction = direct escalation lever.")


# ===========================================================================
# FILES / ASSETS
# ===========================================================================
_file = know("FileID", ent("file", "File", "created"))
action(
    "upload_file", "Upload file", "Create", "upload_file", "User",
    obj("entity", "file", "File", "response", "", "FileID(file)", role="created"),
    requirements=[req("authentication", _tok_auth, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Create", ent("file", "File", "new")),
                      "Policy grants directus_files.create.")],
    gen=[eff(f_exists(ent("file", "File", "created")), "action_semantics", "A file is stored."),
         eff(_file, "io_reference", "Returns the file record.")],
    kill=[],
    io_accounting=[io("input", "file / -", "object_attribute", [], "Multipart upload."),
                   io("output", "data / FileID(file)", "gen", [kf(_file)])],
    bindings=[bind(K("/files"), ["POST"], sel_field="method", sel_values=["POST"])],
    vis="black_box", vis_reason="File upload.", reachable=True,
    reach_conds=["directus_files create grant. Stored-file + content-type surface."],
    evidence=[src("files.ts", "POST")],
    confidence=0.8, reasoning="upload stores a file.",
    description="A user uploads a file.")
read("list_files", "List files", "list_files", "/files", ["GET", "SEARCH"], "User",
     "FileID(file)", "File", "collection", perm="directus_files.read",
     reach=["directus_files read grant."], evref="files.ts")
action(
    "import_file_url", "Import file from URL (SSRF)", "Create", "import_file_url", "User",
    obj("entity", "file", "File", "response", "", "FileID(file)", role="created"),
    requirements=[req("authentication", _tok_auth, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Create", ent("file", "File", "new")),
                      "Policy grants directus_files.create.")],
    gen=[eff(f_exists(ent("file", "File", "created")), "action_semantics", "Remote content is fetched + stored."),
         eff(_file, "io_reference", "Returns the stored file.")],
    kill=[],
    io_accounting=[io("input", "url / RemoteURL(url)", "object_attribute", [],
                      "Attacker-chosen URL the server GETs (SSRF)."),
                   io("output", "data / FileID(file)", "gen", [kf(_file)])],
    bindings=_mbind("/files/import", ["POST"]),
    vis="black_box", vis_reason="Import-from-URL (SSRF).", reachable=True,
    reach_conds=["directus_files create grant. Server-side fetch of an arbitrary 'url' = SSRF."],
    evidence=[src("files.ts", "import")],
    confidence=0.8, reasoning="files/import makes the server fetch an attacker URL.",
    description="A user makes the server fetch and store a remote URL (SSRF).")
mutate("update_file", "Update/replace file", "Update", "update_file", "/files/:pk", ["PATCH"], "User",
       "File", "FileID(file)", perm="directus_files.update", inref=("pk", "FileID", "File"),
       reach=["directus_files update grant."], evref="files.ts")
read("download_asset", "Download/transform asset", "download_asset", "/assets/:pk/:filename?", ["GET"],
     "Anonymous", "FileID(file)", "File", "target", auth="none", perm="file.read",
     inref=("pk", "FileID", "File"),
     reach=["Read access to the file (public if allowed). Arbitrary transform params = CPU/memory DoS."],
     evref="assets.ts", note="Image-transform params are a resource-exhaustion surface.")
mutate("create_folder", "Create folder", "Create", "create_folder", "/folders", ["POST"], "User",
       "Folder", "FolderID(folder)", perm="directus_folders.create", gen_new=True,
       reach=["directus_folders create grant."], evref="folders.ts")


# ===========================================================================
# FLOWS / OPERATIONS (automation)
# ===========================================================================
action(
    "trigger_flow", "Trigger flow", "Update", "trigger_flow", "Anonymous",
    obj("entity", "flow", "Flow", "request", "pk", "FlowID(flow)", role="invoked"),
    requirements=[req("knowledge", know("FlowID", ent("flow", "Flow", "target")),
                      "References a flow by id.")],
    gen=[eff(f_state(ent("flow", "Flow", "target"), "execution", "run"), "action_semantics",
             "The flow's operation chain executes server-side.")],
    kill=[],
    io_accounting=[io("input", "pk / FlowID(flow)", "req",
                      [kf(know("FlowID", ent("flow", "Flow", "target")))]),
                   io("input", "body / -", "object_attribute", [], "Payload passed into the flow.")],
    bindings=_mbind("/flows/trigger/:pk", ["GET", "POST"]),
    vis="black_box", vis_reason="Flow execution.", reachable=True,
    reach_conds=["Per the flow's trigger config: a 'webhook' flow can be PUBLIC. Runs operations "
                 "(request=SSRF, exec=sandboxed JS, item mutations) with the flow's accountability."],
    evidence=[src("flows.ts", "webhookFlowHandler")],
    confidence=0.8, reasoning="triggering a webhook flow runs its server-side chain.",
    description="An actor triggers a flow, executing its operation chain server-side.")
mutate("create_flow", "Create flow", "Create", "create_flow", "/flows", ["POST"], "User",
       "Flow", "FlowID(flow)", perm="directus_flows.create", gen_new=True,
       reach=["directus_flows create grant. A flow with request/exec operations = SSRF/code by configuration."],
       evref="flows.ts", note="Flow authoring = server-side automation authoring.")
mutate("create_operation", "Create flow operation", "Create", "create_operation", "/operations", ["POST"],
       "User", "Operation", "OperationID(operation)", perm="directus_operations.create", gen_new=True,
       reach=["directus_operations create grant. 'exec' = sandboxed JS; 'request' = SSRF."],
       evref="operations.ts", note="Operation building blocks: exec (code) + request (SSRF).")


# ===========================================================================
# SCHEMA / DATA MODEL
# ===========================================================================
read("schema_snapshot", "Export schema snapshot", "schema_snapshot", "/schema/snapshot", ["GET"],
     "Admin", "SchemaSnapshot(schema)", "Schema", "self", auth="token", perm="admin",
     reach=["admin only (checkIsAdmin). Full data-model disclosure."], evref="schema.ts")
mutate("schema_apply", "Apply schema changes", "Update", "schema_apply", "/schema/apply", ["POST"],
       "Admin", "Schema", "SchemaSnapshot(schema)", auth="token", perm="admin", state_field="model",
       reach=["admin only. Create/alter/drop collections+fields -> destructive + surface-widening."],
       evref="schema.ts", note="Whole-schema write; highest-impact data-model primitive.")
mutate("create_collection", "Create collection", "Create", "create_collection", "/collections", ["POST"],
       "Admin", "Collection", "CollectionName(collection)", auth="token", perm="directus_collections.create",
       gen_new=True, reach=["admin / directus_collections. Creates a DB table."], evref="collections.ts")
mutate("create_field", "Add field to collection", "Create", "create_field", "/fields/:collection", ["POST"],
       "Admin", "Field", "FieldName(field)", auth="token", perm="directus_fields.create",
       inref=("collection", "CollectionName", "Collection"), gen_new=True,
       reach=["admin / directus_fields. Alters DB columns."], evref="fields.ts")


# ===========================================================================
# UTILS
# ===========================================================================
_exp = know("ExportFile", ent("export", "Export", "created"))
action(
    "export_data", "Export collection data", "Read", "export_data", "User",
    obj("entity", "export", "Export", "response", "collection", "ExportFile(export)", role="created"),
    requirements=[req("authentication", _tok_auth, "Authenticated."),
                  req("knowledge", know("CollectionName", ent("collection", "Collection", "target")),
                      "Targets a collection."),
                  req("authorization", f_can(ACTOR, "Read", ent("collection", "Collection", "scope")),
                      "Policy grants read on the collection.")],
    gen=[eff(_exp, "io_reference", "Exports query results to a file (exfiltration).")], kill=[],
    io_accounting=[io("input", "collection / CollectionName(collection)", "req",
                      [kf(know("CollectionName", ent("collection", "Collection", "target")))]),
                   io("output", "file / ExportFile(export)", "gen", [kf(_exp)])],
    bindings=_mbind("/utils/export/:collection", ["POST"]),
    vis="black_box", vis_reason="Data export (exfil).", reachable=True,
    reach_conds=["Read permission on the collection. Bulk exfiltration to a file."],
    evidence=[src("utils.ts", "export")],
    confidence=0.8, reasoning="utils/export dumps readable data to a file.",
    description="A user exports a collection's readable data to a file.")
mutate("import_data", "Import file into collection", "Create", "import_data", "/utils/import/:collection",
       ["POST"], "User", "Item", "ItemID(item)", perm="<collection>.create",
       inref=("collection", "CollectionName", "Collection"), gen_new=True,
       reach=["Create permission on the collection. Bulk write from an uploaded file."], evref="utils.ts")
mutate("import_batch", "Batch import", "Update", "import_batch", "/utils/import", ["POST"], "User",
       "Item", "ItemID(item)", auth="token", state_field="items",
       reach=["Create/update permission; 'dangerouslyAllowDelete' flag enables deletions."],
       evref="utils.ts", note="dangerouslyAllowDelete makes this destructive.")
mutate("clear_cache", "Clear cache", "Delete", "clear_cache", "/utils/cache/clear", ["POST"], "Admin",
       "Cache", "Cache(cache)", auth="token", perm="admin", kill_obj=True,
       reach=["Permission-gated (admin for system cache). Availability/consistency impact."], evref="utils.ts")


# ===========================================================================
# EXTENSIONS
# ===========================================================================
mutate("install_extension", "Install extension (code)", "Create", "install_extension",
       "/extensions/registry/install", ["POST"], "Admin", "Extension", "ExtensionID(extension)",
       auth="token", perm="admin", gen_new=True,
       reach=["admin. Installs + loads third-party extension code -> code-execution-adjacent / supply-chain."],
       evref="extensions.ts", note="Loading an extension executes untrusted code.")
mutate("manage_extension", "Enable/disable/remove extension", "Update", "manage_extension",
       "/extensions/:pk", ["PATCH", "DELETE"], "Admin", "Extension", "ExtensionID(extension)",
       auth="token", perm="admin", inref=("pk", "ExtensionID", "Extension"), state_field="enabled",
       reach=["admin. Toggling/removing extensions changes loaded server code."], evref="extensions.ts")
read("list_extensions", "List extensions", "list_extensions", "/extensions", ["GET"], "User",
     "ExtensionID(extension)", "Extension", "collection", auth="token",
     reach=["Authenticated (app). Reveals installed extensions."], evref="extensions.ts")


# ===========================================================================
# SHARES (public access)
# ===========================================================================
_stok = know("AccessToken", ent("session", "Session", "created"))
action(
    "share_auth", "Authenticate to a share", "Create", "share_auth", "Anonymous",
    obj("state", "session", "Session", "response", "", "AccessToken(session)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", know("ShareID", ent("share", "Share", "target")),
                      "Caller knows a share id (+ password if set).")],
    gen=[eff(f_auth(ACTOR, "ShareToken"), "auth_transition", "Caller gets item-scoped accountability."),
         eff(_stok, "io_reference", "Returns an access token scoped to the shared item.")],
    kill=[],
    io_accounting=[io("input", "share / ShareID(share)", "req",
                      [kf(know("ShareID", ent("share", "Share", "target")))]),
                   io("input", "password / SharePassword(share)", "object_attribute", [],
                      "Share password (if set)."),
                   io("output", "access_token / AccessToken(session)", "gen", [kf(_stok)])],
    bindings=_mbind("/shares/auth", ["POST"]),
    vis="black_box", vis_reason="Public share login.", reachable=True,
    reach_conds=["Public. Share id (+ password if set) -> item-scoped token. Guessable id / weak password "
                 "= unauthenticated data access."],
    evidence=[src("shares.ts", "auth")],
    confidence=0.85, reasoning="shares/auth issues an item-scoped token with no login.",
    description="A visitor authenticates to a share and receives an item-scoped token.")
read("share_info", "Read share info", "share_info", "/shares/info/:pk", ["GET"], "Anonymous",
     "ShareID(share)", "Share", "target", auth="none", inref=("pk", "ShareID", "Share"),
     reach=["Public (no auth). Confirms a share exists + whether a password is set (oracle)."],
     evref="shares.ts", note="Share existence/password oracle.")
mutate("create_share", "Create a share", "Create", "create_share", "/shares", ["POST"], "User",
       "Share", "ShareID(share)", perm="<collection>.share", gen_new=True,
       reach=["directus_shares + 'share' permission. Exposes an item to unauthenticated link holders."],
       evref="shares.ts", note="Deliberate public-exposure primitive.")


# ===========================================================================
# SETTINGS
# ===========================================================================
read("read_settings", "Read project settings", "read_settings", "/settings", ["GET"], "User",
     "Settings(instance)", "Settings", "self", auth="token",
     reach=["App users (some fields drive the login screen)."], evref="settings.ts")
mutate("update_settings", "Update project settings", "Update", "update_settings", "/settings", ["PATCH"],
       "Admin", "Settings", "Settings(instance)", auth="token", perm="directus_settings.update",
       state_field="config", reach=["directus_settings update (admin). Reconfigure storage/CORS/auth/"
                                    "registration/default role -> workspace-takeover-adjacent."],
       evref="settings.ts", note="Controls registration, default roles, storage and CORS.")


# ===========================================================================
# CONTENT VERSIONS / COLLAB
# ===========================================================================
mutate("promote_version", "Promote content version", "Update", "promote_version", "/versions/:pk/promote",
       ["POST"], "User", "Item", "VersionID(version)", perm="<collection>.update",
       inref=("pk", "VersionID", "Version"), state_field="main",
       reach=["Update permission on the versioned collection. Promotes draft content to live."],
       evref="versions.ts", note="Draft->live publish path.")
mutate("create_version", "Create content version", "Create", "create_version", "/versions", ["POST"], "User",
       "Version", "VersionID(version)", perm="directus_versions.create", gen_new=True,
       reach=["directus_versions + collection permission."], evref="versions.ts")
mutate("create_comment", "Comment on an item", "Create", "create_comment", "/comments", ["POST"], "User",
       "Comment", "CommentID(comment)", perm="directus_comments.create", gen_new=True,
       reach=["directus_comments create grant. Stored content (studio-XSS surface)."], evref="comments.ts")
mutate("send_notification", "Send notification", "Create", "send_notification", "/notifications", ["POST"],
       "User", "Notification", "NotificationID(notification)", perm="directus_notifications.create",
       gen_new=True, reach=["directus_notifications create grant. Can message arbitrary users (in-app phishing)."],
       evref="notifications.ts")


# ===========================================================================
# GRAPHQL
# ===========================================================================
_gql = know("ItemID", ent("item", "Item", "collection"))
action(
    "graphql_query", "GraphQL query/mutation", "Read", "graphql_query", "Anonymous",
    obj("entity", "item", "Item", "response", "", "ItemID(item)", role="collection"),
    requirements=[req("authorization", f_can(ACTOR, "Read", ent("item", "Item", "scope")),
                      "Same policy permission model as REST (public role if no token).")],
    gen=[eff(_gql, "io_reference", "Returns query results (permission-filtered).")], kill=[],
    io_accounting=[io("input", "query / -", "object_attribute", [], "GraphQL query (depth/complexity = DoS)."),
                   io("output", "data / ItemID(item)", "gen", [kf(_gql)])],
    bindings=_mbind("/graphql", ["POST", "GET"]),
    vis="black_box", vis_reason="GraphQL (items).", reachable=True,
    reach_conds=["Same accountability/permission model as REST, re-exposed as GraphQL. Introspection + "
                 "query depth = recon/DoS surface."],
    evidence=[src("graphql.ts", "items")],
    confidence=0.8, reasoning="GraphQL mirrors the REST permission model.",
    description="A caller queries/mutates via GraphQL under the same permission model.")
