# -*- coding: utf-8 -*-
"""Ghost (OSS) L2 action cores over the six Pengent predicates.

io_accounting fact strings use common.fact_key so they match Req/Eff. Evidence refs
point at ghost/core/server. Three auth planes (see l2lib.SUBJECTS):
  ContentClient (Content API key) | Member (magic-link session) | Staff/Admin/Owner
  (AdminSession cookie or Admin API key). Bootstrap auth actions use Anonymous.
Role authorization (authorizeAdminApi) is modeled as Can(...) requirements; the exact
role boundary per endpoint is confidence-flagged pending runtime.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind

ADMIN = "/ghost/api/admin"
CONTENT = "/ghost/api/content"
MEMBERS = "/members/api"
ACTOR = subj()


def kf(f):
    return fact_key(f)


def src(ref, supports="route + handler"):
    return c.ev("source", "ghost/core/server/" + ref, supports)


def ent(k, t, role="target"):
    return entity(k, t, role)


def know(rt, e):
    return f_know(ACTOR, reference(rt, e))


_aA = f_auth(ACTOR, "AdminSession")
_aM = f_auth(ACTOR, "MemberSession")
_ckey = know("ContentAPIKey", ent("client", "Client", "self"))


def msel(method):
    return dict(sel_field="method", sel_values=[method])


# ===========================================================================
# CONTENT API (Content API key) -- public reads
# ===========================================================================
def content_read(akey, path, resource, rtype):
    o = know(rtype, ent(resource, resource.capitalize(), "result"))
    action(
        akey, "Content: " + resource, "Read", "content_" + resource, "ContentClient",
        obj("entity", resource, resource.capitalize(), "response", "", rtype, role="result"),
        requirements=[req("knowledge", _ckey, "A Content API key authorizes the read.")],
        gen=[eff(o, "io_reference", "Returns published " + resource + ".")], kill=[],
        io_accounting=[io("input", "key / ContentAPIKey(client)", "req", [kf(_ckey)]),
                       io("output", resource + " / " + rtype, "gen", [kf(o)])],
        bindings=[bind(K(CONTENT + path), ["GET"])],
        vis="black_box", vis_reason="Public Content API.", reachable=True,
        reach_conds=["Valid Content API key; resource published."],
        evidence=[src("web/api/endpoints/content/routes.js", "authenticatePublic + browse")],
        confidence=0.85, reasoning="Content API returns published " + resource + ".",
        description="A Content API client lists published " + resource + ".")


content_read("content_posts", "/posts", "posts", "PostID(post)")
content_read("content_pages", "/pages", "pages", "PageID(page)")
content_read("content_authors", "/authors", "authors", "AuthorID(author)")
content_read("content_tags", "/tags", "tags", "TagID(tag)")
content_read("content_settings", "/settings", "settings", "SettingKey(setting)")
content_read("content_tiers", "/tiers", "tiers", "TierID(tier)")


# ===========================================================================
# ADMIN API -- auth bootstrap
# ===========================================================================
_pw = know("Password", ent("user", "User", "self"))
_sess = know("AdminSession", ent("session", "Session", "created"))
action(
    "admin_login", "Admin log in", "Create", "admin_session", "Anonymous",
    obj("state", "session", "Session", "response", "", "AdminSession(session)",
        role="created", state_field="authenticated"),
    requirements=[req("knowledge", _pw, "Caller supplies email + password.")],
    gen=[eff(f_auth(ACTOR, "AdminSession"), "auth_transition", "Caller becomes an authenticated staff user."),
         eff(_sess, "io_reference", "Sets the admin session cookie.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Login identifier."),
                   io("input", "password / Password(user)", "req", [kf(_pw)]),
                   io("output", "token / AdminSession(session)", "gen", [kf(_sess)])],
    bindings=[bind(K(ADMIN + "/session"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Admin login.", reachable=True,
    reach_conds=["Valid staff credentials; brute-force / rate-limit surface."],
    evidence=[src("api/endpoints/admin/session", "verify + set cookie")],
    confidence=0.9, reasoning="session.add authenticates and sets a cookie.",
    description="A visitor logs into the admin with email+password.")

action(
    "admin_logout", "Admin log out", "Delete", "admin_session", "Staff",
    obj("state", "session", "Session", "subject", "", "AdminSession(session)",
        role="self", state_field="authenticated"),
    requirements=[req("authentication", _aA, "An admin session identifies the caller.")],
    gen=[], kill=[eff(f_auth(ACTOR, "AdminSession"), "auth_transition", "The session is destroyed.")],
    io_accounting=[],
    bindings=[bind(K(ADMIN + "/session"), ["DELETE"], **msel("DELETE"))],
    vis="black_box", vis_reason="Admin logout.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/session", "destroy session")],
    confidence=0.9, reasoning="session.delete ends the session.",
    description="A staff user logs out.")

_owner = know("UserID", ent("user", "User", "created"))
action(
    "admin_setup", "Initial owner setup", "Create", "admin_setup", "Anonymous",
    obj("entity", "user", "User", "response", "", "UserID(user)", role="created"),
    requirements=[req("knowledge", _pw, "Caller supplies the owner email + password.")],
    gen=[eff(f_exists(ent("user", "User", "created")), "action_semantics", "The owner user is created."),
         eff(f_auth(ACTOR, "AdminSession"), "auth_transition", "Caller is logged in as owner."),
         eff(_owner, "io_reference", "Returns the created owner.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Owner email."),
                   io("input", "password / Password(user)", "req", [kf(_pw)]),
                   io("output", "user / UserID(user)", "gen", [kf(_owner)])],
    bindings=[bind(K(ADMIN + "/authentication/setup"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Owner bootstrap.", reachable=True,
    reach_conds=["ONLY on a fresh install (before setup completes) -- else 403. Setup-race surface."],
    evidence=[src("api/endpoints/admin/authentication", "create owner")],
    confidence=0.85, reasoning="authentication.setup creates the owner unauthenticated.",
    description="On a fresh install, a visitor creates the owner account.")

action(
    "admin_check_setup", "Check setup status", "Read", "admin_setup", "Anonymous",
    obj("entity", "site", "Site", "implicit", "", "", role="site"),
    requirements=[], gen=[], kill=[],
    io_accounting=[io("output", "status / -", "observed_only", [], "Whether the blog is set up.")],
    bindings=[bind(K(ADMIN + "/authentication/setup"), ["GET"], **msel("GET"))],
    vis="black_box", vis_reason="Setup status.", reachable=True, reach_conds=["Public."],
    evidence=[src("api/endpoints/admin/authentication", "isSetup")],
    confidence=0.9, reasoning="isSetup reports setup state.",
    description="A visitor checks whether the blog has been set up.")

_rt = know("ResetToken", ent("user", "User", "target"))
action(
    "admin_request_reset", "Request password reset", "Create", "admin_password_reset", "Anonymous",
    obj("entity", "user", "User", "request", "", "UserEmail(user)", role="target"),
    requirements=[req("knowledge", know("UserEmail", ent("user", "User", "target")),
                      "Caller supplies an email to reset.")],
    gen=[], kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "req",
                      [kf(know("UserEmail", ent("user", "User", "target")))])],
    bindings=[bind(K(ADMIN + "/authentication/password_reset"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Reset request.", reachable=True,
    reach_conds=["Public -- user-enumeration + email-bomb surface."],
    evidence=[src("api/endpoints/admin/authentication", "generateResetToken")],
    confidence=0.85, reasoning="generateResetToken emails a reset link.",
    description="A visitor requests a password-reset email for an address.")

action(
    "admin_perform_reset", "Reset password via token", "Update", "admin_password_reset", "Anonymous",
    obj("state", "user", "User", "request", "", "Password(user)", role="target", state_field="password"),
    requirements=[req("knowledge", _rt, "A valid emailed reset token authorizes the change.")],
    gen=[eff(f_state(ent("user", "User", "target"), "password", "reset"), "action_semantics",
             "The user's password is replaced.")],
    kill=[],
    io_accounting=[io("input", "token / ResetToken(user)", "req", [kf(_rt)]),
                   io("input", "password / Password(user)", "object_attribute", [], "New password.")],
    bindings=[bind(K(ADMIN + "/authentication/password_reset"), ["PUT"], **msel("PUT"))],
    vis="black_box", vis_reason="Reset perform.", reachable=True,
    reach_conds=["Valid emailed reset token (token = the real gate)."],
    evidence=[src("api/endpoints/admin/authentication", "resetPassword")],
    confidence=0.85, reasoning="resetPassword sets a new password from a token.",
    description="A visitor sets a new password using an emailed reset token.")

_it = know("InviteToken", ent("invite", "Invite", "target"))
action(
    "admin_accept_invite", "Accept staff invite", "Create", "admin_invitation", "Anonymous",
    obj("state", "user", "User", "response", "", "AdminSession(session)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", _it, "A valid emailed invite token authorizes account creation.")],
    gen=[eff(f_exists(ent("user", "User", "created")), "action_semantics", "A staff user is created."),
         eff(f_auth(ACTOR, "AdminSession"), "auth_transition", "The new staff user is logged in.")],
    kill=[],
    io_accounting=[io("input", "token / InviteToken(invite)", "req", [kf(_it)]),
                   io("input", "password / Password(user)", "object_attribute", [], "Chosen password."),
                   io("input", "email / UserEmail(user)", "object_attribute", [], "Invited email.")],
    bindings=[bind(K(ADMIN + "/authentication/invitation"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Invite accept.", reachable=True,
    reach_conds=["Valid invite token."],
    evidence=[src("api/endpoints/admin/authentication", "acceptInvitation")],
    confidence=0.8, reasoning="acceptInvitation provisions a staff user from a token.",
    description="An invited person accepts a staff invite and sets a password.")

action(
    "admin_check_invite", "Check invite", "Read", "admin_invitation", "Anonymous",
    obj("entity", "invite", "Invite", "request", "", "UserEmail(user)", role="target"),
    requirements=[], gen=[], kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Email probed."),
                   io("output", "invitation / -", "observed_only", [], "Whether an invite exists.")],
    bindings=[bind(K(ADMIN + "/authentication/invitation"), ["GET"], **msel("GET"))],
    vis="black_box", vis_reason="Invite check.", reachable=True, reach_conds=["Public."],
    evidence=[src("api/endpoints/admin/authentication", "isInvitation")],
    confidence=0.8, reasoning="isInvitation checks an invite for an email.",
    description="A visitor checks whether an email has a pending invite.")

action(
    "admin_verify_2fa", "Verify 2FA code", "Update", "admin_session_verify", "Anonymous",
    obj("state", "session", "Session", "request", "", "OTPCode(session)", role="target",
        state_field="verified"),
    requirements=[req("knowledge", know("OTPCode", ent("session", "Session", "target")),
                      "Caller supplies the emailed 2FA code.")],
    gen=[eff(f_auth(ACTOR, "AdminSession"), "auth_transition", "The session becomes fully verified.")],
    kill=[],
    io_accounting=[io("input", "token / OTPCode(session)", "req",
                      [kf(know("OTPCode", ent("session", "Session", "target")))])],
    bindings=[bind(K(ADMIN + "/session/verify"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="2FA verify.", reachable=True, reach_conds=["Mid-login; valid code."],
    evidence=[src("api/endpoints/admin/session", "verify 2FA")],
    confidence=0.75, reasoning="session/verify completes 2FA.",
    description="A staff user submits their emailed 2FA code.")

_idt = know("IdentityToken", ent("session", "Session", "self"))
action(
    "admin_read_identity", "Read SSO identity token", "Read", "admin_read_identities", "Staff",
    obj("entity", "session", "Session", "subject", "", "IdentityToken(session)", role="self"),
    requirements=[req("authentication", _aA, "Authenticated admin.")],
    gen=[eff(_idt, "io_reference", "Mints an SSO identity token for the caller.")], kill=[],
    io_accounting=[io("output", "identities / IdentityToken(session)", "gen", [kf(_idt)])],
    bindings=[bind(K(ADMIN + "/identities"), ["GET"])],
    vis="black_box", vis_reason="SSO token.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/identities", "mint token")],
    confidence=0.8, reasoning="identities.read mints an SSO token.",
    description="A staff user obtains an SSO identity token.")

action(
    "admin_public_site", "Read site info", "Read", "admin_public_site", "Anonymous",
    obj("entity", "site", "Site", "implicit", "", "", role="site"),
    requirements=[], gen=[], kill=[],
    io_accounting=[io("output", "site / -", "observed_only", [], "Public site metadata.")],
    bindings=[bind(K(ADMIN + "/site"), ["GET"])],
    vis="black_box", vis_reason="Public site (publicAdminApi).", reachable=True, reach_conds=["Public."],
    evidence=[src("api/endpoints/admin/site", "publicAdminApi")],
    confidence=0.9, reasoning="site.read is public.",
    description="Anyone reads public site info from the admin API.")


# ===========================================================================
# ADMIN API -- resource CRUD helpers
# ===========================================================================
def admin_browse(akey, path, resource, rtype, role="Staff", key_override=None):
    o = know(rtype, ent(resource, resource.capitalize(), "listed"))
    action(
        akey, "List " + resource, "Read", "admin_" + resource, role,
        obj("entity", resource, resource.capitalize(), "response", "", rtype, role="collection"),
        requirements=[req("authentication", _aA, "Authenticated admin.")],
        gen=[eff(o, "io_reference", "Returns " + resource + ".")], kill=[],
        io_accounting=[io("output", resource + " / " + rtype, "gen", [kf(o)])],
        bindings=[bind(K(ADMIN + (key_override or path)), ["GET"], **msel("GET"))],
        vis="black_box", vis_reason="Admin list " + resource + ".", reachable=True,
        reach_conds=["Authenticated admin."],
        evidence=[src("api/endpoints/admin", resource + ".browse")],
        confidence=0.85, reasoning="browse lists " + resource + ".",
        description="A staff user lists " + resource + ".")


def admin_create(akey, path, resource, rtype, singular, role="Staff", note=None):
    o = know(rtype, ent(singular, singular.capitalize(), "created"))
    action(
        akey, "Create " + singular, "Create", "admin_" + resource, role,
        obj("entity", singular, singular.capitalize(), "response", "", rtype, role="created"),
        requirements=[req("authentication", _aA, "Authenticated admin."),
                      req("authorization", f_can(ACTOR, "Create", ent(singular, singular.capitalize(), "new")),
                          "Role permits creating a " + singular + ".")],
        gen=[eff(f_exists(ent(singular, singular.capitalize(), "created")), "action_semantics",
                 "A " + singular + " is created."),
             eff(o, "io_reference", "Returns the new " + singular + ".")],
        kill=[],
        io_accounting=[io("output", resource + " / " + rtype, "gen", [kf(o)])],
        bindings=[bind(K(ADMIN + path), ["POST"], **msel("POST"))],
        vis="black_box", vis_reason="Create " + singular + ".", reachable=True,
        reach_conds=["Authenticated admin with create permission."],
        evidence=[src("api/endpoints/admin", resource + ".add")],
        confidence=0.8, reasoning="add creates a " + singular + ".",
        description="A staff user creates a " + singular + ".", notes=note)


def admin_edit(akey, path, singular, rtype, role="Staff"):
    kr = know(rtype, ent(singular, singular.capitalize(), "target"))
    action(
        akey, "Edit " + singular, "Update", "admin_" + singular + "_edit", role,
        obj("state", singular, singular.capitalize(), "request", "id", rtype, role="target",
            state_field="fields"),
        requirements=[req("authentication", _aA, "Authenticated admin."),
                      req("knowledge", kr, "Targets an existing " + singular + " by id."),
                      req("authorization", f_can(ACTOR, "Update", ent(singular, singular.capitalize(), "target")),
                          "Role permits editing the " + singular + ".")],
        gen=[eff(f_state(ent(singular, singular.capitalize(), "target"), "fields", "updated"),
                 "action_semantics", "Fields are updated.")],
        kill=[],
        io_accounting=[io("input", "id / " + rtype, "req", [kf(kr)])],
        bindings=[bind(K(ADMIN + path), ["PUT"], **msel("PUT"))],
        vis="black_box", vis_reason="Edit " + singular + ".", reachable=True,
        reach_conds=["Authenticated admin; resource exists; role permits."],
        evidence=[src("api/endpoints/admin", singular + ".edit")],
        confidence=0.8, reasoning="edit mutates a " + singular + ".",
        description="A staff user edits a " + singular + ".")


def admin_delete(akey, path, singular, rtype, role="Staff"):
    kr = know(rtype, ent(singular, singular.capitalize(), "target"))
    action(
        akey, "Delete " + singular, "Delete", "admin_" + singular + "_delete", role,
        obj("entity", singular, singular.capitalize(), "request", "id", rtype, role="target"),
        requirements=[req("authentication", _aA, "Authenticated admin."),
                      req("knowledge", kr, "Targets an existing " + singular + "."),
                      req("authorization", f_can(ACTOR, "Delete", ent(singular, singular.capitalize(), "target")),
                          "Role permits deleting the " + singular + ".")],
        gen=[], kill=[eff(f_exists(ent(singular, singular.capitalize(), "target")), "action_semantics",
                          "The " + singular + " is removed.")],
        io_accounting=[io("input", "id / " + rtype, "req", [kf(kr)])],
        bindings=[bind(K(ADMIN + path), ["DELETE"], **msel("DELETE"))],
        vis="black_box", vis_reason="Delete " + singular + ".", reachable=True,
        reach_conds=["Authenticated admin; resource exists; role permits."],
        evidence=[src("api/endpoints/admin", singular + ".destroy")],
        confidence=0.8, reasoning="destroy removes a " + singular + ".",
        description="A staff user deletes a " + singular + ".")


# posts
admin_browse("admin_list_posts", "/posts", "posts", "PostID(post)")
admin_create("admin_create_post", "/posts", "posts", "PostID(post)", "post")
admin_edit("admin_edit_post", "/posts/:id", "post", "PostID(post)")
admin_delete("admin_delete_post", "/posts/:id", "post", "PostID(post)")
# tags
admin_browse("admin_list_tags", "/tags", "tags", "TagID(tag)")
admin_create("admin_create_tag", "/tags", "tags", "TagID(tag)", "tag")
admin_edit("admin_edit_tag", "/tags/:id", "tag", "TagID(tag)")
# members
admin_browse("admin_list_members", "/members", "members", "MemberID(member)", role="Administrator")
admin_create("admin_create_member", "/members", "members", "MemberID(member)", "member", role="Administrator")
admin_edit("admin_edit_member", "/members/:id", "member", "MemberID(member)", role="Administrator")
admin_delete("admin_delete_member", "/members/:id", "member", "MemberID(member)", role="Administrator")
# integrations (create mints an Admin API key)
admin_browse("admin_list_integrations", "/integrations", "integrations", "IntegrationID(integration)",
             role="Administrator")
admin_create("admin_create_integration", "/integrations", "integrations", "IntegrationID(integration)",
             "integration", role="Administrator",
             note="Creating an integration mints a new Admin API key -> persistent credential.")
admin_delete("admin_delete_integration", "/integrations/:id", "integration", "IntegrationID(integration)",
             role="Administrator")
# pages / users / roles
admin_browse("admin_list_pages", "/pages", "pages", "PageID(page)")
admin_browse("admin_list_users", "/users", "users", "UserID(user)")
admin_browse("admin_list_roles", "/roles", "roles", "RoleID(role)", key_override="/roles")

action(
    "admin_edit_user", "Edit staff user", "Update", "admin_user_item", "Administrator",
    obj("state", "user", "User", "request", "id", "UserID(user)", role="target", state_field="fields"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("knowledge", know("UserID", ent("user", "User", "target")), "Targets a staff user."),
                  req("authorization", f_can(ACTOR, "Update", ent("user", "User", "target")),
                      "Role permits editing that user (role boundary).")],
    gen=[eff(f_state(ent("user", "User", "target"), "fields", "updated"), "action_semantics",
             "Staff user fields updated.")],
    kill=[],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(know("UserID", ent("user", "User", "target")))])],
    bindings=[bind(K(ADMIN + "/users/:id"), ["PUT"], **msel("PUT"))],
    vis="black_box", vis_reason="Edit user.", reachable=True,
    reach_conds=["Editing a higher-role user must be blocked by authorizeAdminApi -- privilege boundary."],
    evidence=[src("api/endpoints/admin/users", "edit")],
    confidence=0.8, reasoning="users.edit mutates a staff user.",
    description="An admin edits a staff user (role-bounded).")

action(
    "admin_delete_user", "Delete staff user", "Delete", "admin_user_item", "Administrator",
    obj("entity", "user", "User", "request", "id", "UserID(user)", role="target"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("knowledge", know("UserID", ent("user", "User", "target")), "Targets a staff user."),
                  req("authorization", f_can(ACTOR, "Delete", ent("user", "User", "target")),
                      "Role permits deleting that user.")],
    gen=[], kill=[eff(f_exists(ent("user", "User", "target")), "action_semantics", "Staff user removed.")],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(know("UserID", ent("user", "User", "target")))])],
    bindings=[bind(K(ADMIN + "/users/:id"), ["DELETE"], **msel("DELETE"))],
    vis="black_box", vis_reason="Delete user.", reachable=True, reach_conds=["Administrator; role boundary."],
    evidence=[src("api/endpoints/admin/users", "destroy")],
    confidence=0.8, reasoning="users.destroy removes a staff user.",
    description="An admin deletes a staff user.")

action(
    "admin_change_password", "Change password", "Update", "admin_change_password", "Staff",
    obj("state", "user", "User", "subject", "", "Password(user)", role="self", state_field="password"),
    requirements=[req("authentication", _aA, "Authenticated admin.")],
    gen=[eff(f_state(ent("user", "User", "self"), "password", "changed"), "action_semantics",
             "Password is changed.")],
    kill=[],
    io_accounting=[io("input", "password / Password(user)", "object_attribute", [], "New password.")],
    bindings=[bind(K(ADMIN + "/users/password"), ["PUT"])],
    vis="black_box", vis_reason="Change password.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/users", "changePassword")],
    confidence=0.85, reasoning="changePassword updates the caller's password.",
    description="A staff user changes a password.")

action(
    "admin_transfer_ownership", "Transfer ownership", "Update", "admin_transfer_ownership", "Owner",
    obj("state", "user", "User", "request", "id", "UserID(user)", role="target", state_field="role"),
    requirements=[req("authentication", _aA, "Authenticated as OWNER."),
                  req("knowledge", know("UserID", ent("user", "User", "target")), "New owner user id."),
                  req("authorization", f_can(ACTOR, "Update", ent("site", "Site", "self")),
                      "Owner-only capability.")],
    gen=[eff(f_state(ent("user", "User", "target"), "role", "Owner"), "action_semantics",
             "Ownership is transferred.")],
    kill=[],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(know("UserID", ent("user", "User", "target")))])],
    bindings=[bind(K(ADMIN + "/users/owner"), ["PUT"])],
    vis="black_box", vis_reason="Transfer ownership.", reachable=True,
    reach_conds=["OWNER only -- site-takeover primitive."],
    evidence=[src("api/endpoints/admin/users", "transferOwnership")],
    confidence=0.85, reasoning="transferOwnership reassigns the owner.",
    description="The owner transfers site ownership to another user.")

_signin = know("MemberMagicLink", ent("member", "Member", "target"))
action(
    "admin_member_signin_url", "Mint member sign-in URL", "Read", "admin_member_signin_url", "Administrator",
    obj("entity", "member", "Member", "request", "id", "MemberID(member)", role="target"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("knowledge", know("MemberID", ent("member", "Member", "target")), "Target member.")],
    gen=[eff(_signin, "io_reference", "Returns a one-click sign-in URL for the member (impersonation).")],
    kill=[],
    io_accounting=[io("input", "id / MemberID(member)", "req",
                      [kf(know("MemberID", ent("member", "Member", "target")))]),
                   io("output", "signin_url / MemberMagicLink(member)", "gen", [kf(_signin)])],
    bindings=[bind(K(ADMIN + "/members/:id/signin_urls"), ["GET"])],
    vis="black_box", vis_reason="Member impersonation URL.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/members", "signin_urls")],
    confidence=0.8, reasoning="memberSigninUrls.read mints an impersonation URL.",
    description="An admin mints a one-click sign-in URL impersonating a member.")

# settings
_set = know("SettingKey", ent("setting", "Setting", "listed"))
action(
    "admin_read_settings", "Read settings", "Read", "admin_settings", "Staff",
    obj("entity", "setting", "Setting", "response", "", "SettingKey(setting)", role="collection"),
    requirements=[req("authentication", _aA, "Authenticated admin.")],
    gen=[eff(_set, "io_reference", "Returns settings.")], kill=[],
    io_accounting=[io("output", "settings / SettingKey(setting)", "gen", [kf(_set)])],
    bindings=[bind(K(ADMIN + "/settings"), ["GET"], **msel("GET"))],
    vis="black_box", vis_reason="Read settings.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/settings", "browse")],
    confidence=0.85, reasoning="settings.browse returns settings.",
    description="A staff user reads settings.")

action(
    "admin_edit_settings", "Edit settings", "Update", "admin_settings", "Administrator",
    obj("state", "setting", "Setting", "request", "", "SettingKey(setting)", role="collection",
        state_field="value"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Update", ent("setting", "Setting", "target")),
                      "Editing settings may require Administrator.")],
    gen=[eff(f_state(ent("setting", "Setting", "target"), "value", "updated"), "action_semantics",
             "Settings are updated.")],
    kill=[],
    io_accounting=[io("input", "settings / SettingKey(setting)", "object_attribute", [], "Settings array.")],
    bindings=[bind(K(ADMIN + "/settings"), ["PUT"], **msel("PUT"))],
    vis="black_box", vis_reason="Edit settings.", reachable=True, reach_conds=["Administrator."],
    evidence=[src("api/endpoints/admin/settings", "edit")],
    confidence=0.8, reasoning="settings.edit mutates settings.",
    description="An admin edits site settings.")


# ===========================================================================
# ADMIN API -- dangerous (DB, themes, uploads, webhooks, invites)
# ===========================================================================
_exp = know("ContentExport", ent("site", "Site", "self"))
action(
    "admin_export_content", "Export all content", "Read", "admin_db", "Administrator",
    obj("entity", "site", "Site", "subject", "", "ContentExport(site)", role="self"),
    requirements=[req("authentication", _aA, "Authenticated admin.")],
    gen=[eff(_exp, "io_reference", "Dumps ALL content as JSON (exfiltration).")], kill=[],
    io_accounting=[io("output", "db / ContentExport(site)", "gen", [kf(_exp)])],
    bindings=[bind(K(ADMIN + "/db"), ["GET"], **msel("GET"))],
    vis="black_box", vis_reason="Full export.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/db", "exportContent")],
    confidence=0.85, reasoning="db.exportContent dumps all content.",
    description="An admin exports the entire site content.")

action(
    "admin_import_content", "Import content", "Create", "admin_db", "Administrator",
    obj("entity", "site", "Site", "subject", "", "", role="self"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Create", ent("site", "Site", "self")),
                      "Import permission.")],
    gen=[eff(f_exists(ent("import", "Import", "created")), "action_semantics",
             "Content is bulk-imported (mass-assignment surface).")],
    kill=[],
    io_accounting=[io("input", "importfile / -", "object_attribute", [], "Uploaded JSON/zip.")],
    bindings=[bind(K(ADMIN + "/db"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Import.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/db", "importContent")],
    confidence=0.8, reasoning="db.importContent bulk-imports content.",
    description="An admin imports content from a file.")

action(
    "admin_delete_all_content", "Delete all content", "Delete", "admin_db", "Administrator",
    obj("entity", "site", "Site", "subject", "", "", role="self"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Delete", ent("site", "Site", "self")),
                      "Destructive wipe permission.")],
    gen=[], kill=[eff(f_exists(ent("content", "Content", "all")), "action_semantics",
                      "All posts/pages/tags are deleted.")],
    io_accounting=[],
    bindings=[bind(K(ADMIN + "/db"), ["DELETE"], **msel("DELETE"))],
    vis="black_box", vis_reason="Wipe content.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/db", "deleteAllContent")],
    confidence=0.85, reasoning="db.deleteAllContent wipes content.",
    description="An admin deletes all site content.")

action(
    "admin_upload_theme", "Upload theme ZIP", "Create", "admin_theme_upload", "Administrator",
    obj("entity", "theme", "Theme", "response", "", "ThemeName(theme)", role="created"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Create", ent("theme", "Theme", "new")),
                      "Theme upload permission.")],
    gen=[eff(f_exists(ent("theme", "Theme", "created")), "action_semantics",
             "A theme ZIP is unpacked into content/themes.")],
    kill=[],
    io_accounting=[io("input", "file / -", "object_attribute", [], "Uploaded .zip (template files).")],
    bindings=[bind(K(ADMIN + "/themes/upload"), ["POST"])],
    vis="black_box", vis_reason="Theme upload.", reachable=True,
    reach_conds=["Authenticated admin. Code-adjacent: theme templates/helpers run server-side."],
    evidence=[src("api/endpoints/admin/themes", "upload")],
    confidence=0.8, reasoning="themes.upload unpacks a ZIP of templates.",
    description="An admin uploads a theme ZIP.")

action(
    "admin_install_theme", "Install theme from source", "Create", "admin_theme_install", "Administrator",
    obj("entity", "theme", "Theme", "request", "source", "ThemeName(theme)", role="created"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Create", ent("theme", "Theme", "new")),
                      "Theme install permission.")],
    gen=[eff(f_exists(ent("theme", "Theme", "created")), "action_semantics",
             "The server fetches + installs a theme from a remote source.")],
    kill=[],
    io_accounting=[io("input", "source / -", "object_attribute", [], "Remote source ref (server fetches it).")],
    bindings=[bind(K(ADMIN + "/themes/install"), ["POST"])],
    vis="black_box", vis_reason="Theme install.", reachable=True,
    reach_conds=["Authenticated admin. Server-side fetch -> SSRF-adjacent."],
    evidence=[src("api/endpoints/admin/themes", "install")],
    confidence=0.75, reasoning="themes.install fetches a remote source.",
    description="An admin installs a theme from a remote source.")

action(
    "admin_activate_theme", "Activate theme", "Update", "admin_theme_activate", "Administrator",
    obj("state", "theme", "Theme", "request", "name", "ThemeName(theme)", role="target", state_field="active"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("knowledge", know("ThemeName", ent("theme", "Theme", "target")), "Theme to activate.")],
    gen=[eff(f_state(ent("theme", "Theme", "target"), "active", "true"), "action_semantics",
             "The theme becomes active.")],
    kill=[],
    io_accounting=[io("input", "name / ThemeName(theme)", "req",
                      [kf(know("ThemeName", ent("theme", "Theme", "target")))])],
    bindings=[bind(K(ADMIN + "/themes/:name/activate"), ["PUT"])],
    vis="black_box", vis_reason="Activate theme.", reachable=True, reach_conds=["Authenticated admin."],
    evidence=[src("api/endpoints/admin/themes", "activate")],
    confidence=0.8, reasoning="themes.activate switches the active theme.",
    description="An admin activates a theme.")

_img = know("ImageURL", ent("image", "Image", "created"))
action(
    "admin_upload_image", "Upload image", "Create", "admin_image_upload", "Staff",
    obj("entity", "image", "Image", "response", "", "ImageURL(image)", role="created"),
    requirements=[req("authentication", _aA, "Authenticated admin.")],
    gen=[eff(_img, "io_reference", "Stores the image and returns its URL.")], kill=[],
    io_accounting=[io("input", "file / -", "object_attribute", [], "Uploaded image."),
                   io("output", "images / ImageURL(image)", "gen", [kf(_img)])],
    bindings=[bind(K(ADMIN + "/images/upload"), ["POST"])],
    vis="black_box", vis_reason="Image upload.", reachable=True,
    reach_conds=["Authenticated admin. File type/size validation surface."],
    evidence=[src("api/endpoints/admin/images", "upload")],
    confidence=0.8, reasoning="images.upload stores a file.",
    description="A staff user uploads an image.")

_wh = know("WebhookID", ent("webhook", "Webhook", "created"))
action(
    "admin_create_webhook", "Create webhook", "Create", "admin_webhook_add", "Integration",
    obj("entity", "webhook", "Webhook", "response", "", "WebhookID(webhook)", role="created"),
    requirements=[req("authentication", _aA, "Authenticated admin or integration."),
                  req("authorization", f_can(ACTOR, "Create", ent("webhook", "Webhook", "new")),
                      "Webhook create permission.")],
    gen=[eff(f_exists(ent("webhook", "Webhook", "created")), "action_semantics", "A webhook is registered."),
         eff(_wh, "io_reference", "Returns the webhook id.")],
    kill=[],
    io_accounting=[io("input", "target_url / -", "object_attribute", [], "Attacker-controlled callback URL."),
                   io("output", "webhooks / WebhookID(webhook)", "gen", [kf(_wh)])],
    bindings=[bind(K(ADMIN + "/webhooks"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Create webhook.", reachable=True,
    reach_conds=["Authenticated admin/integration. target_url -> SSRF-adjacent."],
    evidence=[src("api/endpoints/admin/webhooks", "add")],
    confidence=0.8, reasoning="webhooks.add registers a callback URL.",
    description="An admin/integration registers a webhook.")

action(
    "admin_create_invite", "Invite staff", "Create", "admin_invites", "Administrator",
    obj("entity", "invite", "Invite", "response", "", "InviteID(invite)", role="created"),
    requirements=[req("authentication", _aA, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Create", ent("invite", "Invite", "new")),
                      "Inviting a given role requires >= that role.")],
    gen=[eff(f_exists(ent("invite", "Invite", "created")), "action_semantics",
             "A staff invite is created and emailed.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Invitee email."),
                   io("input", "role_id / -", "object_attribute", [], "Role to grant (privilege boundary).")],
    bindings=[bind(K(ADMIN + "/invites"), ["POST"], **msel("POST"))],
    vis="black_box", vis_reason="Staff invite.", reachable=True,
    reach_conds=["Administrator. Inviting a higher role must be blocked -- escalation surface."],
    evidence=[src("api/endpoints/admin/invites", "add")],
    confidence=0.8, reasoning="invites.add creates+emails a staff invite.",
    description="An admin invites a new staff user with a role.")

admin_browse("admin_list_invites", "/invites", "invites", "InviteID(invite)", role="Administrator")
admin_browse("admin_list_webhooks_get", "/webhooks", "webhooks", "WebhookID(webhook)",
             role="Integration", key_override="/webhooks")


# ===========================================================================
# MEMBERS API (magic-link session)
# ===========================================================================
action(
    "member_send_magic_link", "Request magic link", "Create", "member_send_magic_link", "Anonymous",
    obj("entity", "member", "Member", "request", "", "MemberEmail(member)", role="target"),
    requirements=[req("knowledge", know("MemberEmail", ent("member", "Member", "target")),
                      "Caller supplies an email.")],
    gen=[], kill=[],
    io_accounting=[io("input", "email / MemberEmail(member)", "req",
                      [kf(know("MemberEmail", ent("member", "Member", "target")))])],
    bindings=[bind(K(MEMBERS + "/send-magic-link"), ["POST"])],
    vis="black_box", vis_reason="Passwordless signin request.", reachable=True,
    reach_conds=["Members enabled. Enumeration + email-bomb surface."],
    evidence=[src("web/members/app.js", "send-magic-link")],
    confidence=0.85, reasoning="Emails a passwordless sign-in link.",
    description="A visitor requests a members magic-link email.")

action(
    "member_verify_otc", "Verify one-time code", "Create", "member_verify_otc", "Anonymous",
    obj("state", "session", "Session", "response", "", "MemberSession(member)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", know("OTPCode", ent("member", "Member", "target")),
                      "Caller supplies the emailed OTC.")],
    gen=[eff(f_auth(ACTOR, "MemberSession"), "auth_transition", "The member becomes authenticated.")],
    kill=[],
    io_accounting=[io("input", "otc / OTPCode(member)", "req",
                      [kf(know("OTPCode", ent("member", "Member", "target")))])],
    bindings=[bind(K(MEMBERS + "/verify-otc"), ["POST"])],
    vis="black_box", vis_reason="OTC verify.", reachable=True, reach_conds=["Valid OTC."],
    evidence=[src("web/members/app.js", "verify-otc")],
    confidence=0.8, reasoning="verify-otc establishes a member session.",
    description="A visitor verifies a one-time code to log in as a member.")

_mtok = know("MemberIdentityToken", ent("member", "Member", "self"))
action(
    "member_identity", "Member identity token", "Read", "member_session", "Member",
    obj("entity", "member", "Member", "subject", "", "MemberIdentityToken(member)", role="self"),
    requirements=[req("authentication", _aM, "Member session.")],
    gen=[eff(_mtok, "io_reference", "Returns a member identity JWT.")], kill=[],
    io_accounting=[io("output", "token / MemberIdentityToken(member)", "gen", [kf(_mtok)])],
    bindings=[bind(K(MEMBERS + "/session"), ["GET"], **msel("GET"))],
    vis="black_box", vis_reason="Member identity.", reachable=True, reach_conds=["Member session."],
    evidence=[src("web/members/app.js", "getIdentityToken")],
    confidence=0.8, reasoning="session GET mints a member identity token.",
    description="A member fetches their identity token.")

action(
    "member_logout", "Member log out", "Delete", "member_session", "Member",
    obj("state", "session", "Session", "subject", "", "MemberSession(member)", role="self",
        state_field="authenticated"),
    requirements=[req("authentication", _aM, "Member session.")],
    gen=[], kill=[eff(f_auth(ACTOR, "MemberSession"), "auth_transition", "The member session ends.")],
    io_accounting=[],
    bindings=[bind(K(MEMBERS + "/session"), ["DELETE"], **msel("DELETE"))],
    vis="black_box", vis_reason="Member logout.", reachable=True, reach_conds=["Any."],
    evidence=[src("web/members/app.js", "deleteSession")],
    confidence=0.85, reasoning="session DELETE logs the member out.",
    description="A member logs out.")

_self = know("MemberID", ent("member", "Member", "self"))
action(
    "member_read_self", "Read own account", "Read", "member_read_self", "Member",
    obj("entity", "member", "Member", "subject", "", "MemberID(member)", role="self"),
    requirements=[req("authentication", _aM, "Member session.")],
    gen=[eff(_self, "io_reference", "Returns the member's own account.")], kill=[],
    io_accounting=[io("output", "member / MemberID(member)", "gen", [kf(_self)])],
    bindings=[bind(K(MEMBERS + "/member"), ["GET"])],
    vis="black_box", vis_reason="Member self.", reachable=True, reach_conds=["Member session."],
    evidence=[src("web/members/account", "read self")],
    confidence=0.85, reasoning="account read returns the member's own record.",
    description="A member reads their own account.")

action(
    "member_stripe_checkout", "Create Stripe checkout", "Create", "member_stripe_checkout", "Member",
    obj("entity", "checkout", "Checkout", "response", "", "", role="created"),
    requirements=[req("authentication", _aM, "Member session (or anonymous signup checkout).")],
    gen=[], kill=[],
    io_accounting=[io("input", "tierId / -", "object_attribute", [], "Tier to subscribe to."),
                   io("output", "url / -", "observed_only", [], "Stripe checkout URL.")],
    bindings=[bind(K(MEMBERS + "/create-stripe-checkout-session"), ["POST"])],
    vis="black_box", vis_reason="Stripe checkout.", reachable=True, reach_conds=["Members + Stripe configured."],
    evidence=[src("web/members/app.js", "create-stripe-checkout-session")],
    confidence=0.75, reasoning="Creates a Stripe checkout session.",
    description="A member starts a Stripe subscription checkout.")

action(
    "member_public_site", "Member site info", "Read", "member_public_site", "Anonymous",
    obj("entity", "site", "Site", "implicit", "", "", role="site"),
    requirements=[], gen=[], kill=[],
    io_accounting=[io("output", "site / -", "observed_only", [], "Public site info.")],
    bindings=[bind(K(MEMBERS + "/site"), ["GET"])],
    vis="black_box", vis_reason="Public site.", reachable=True, reach_conds=["Public."],
    evidence=[src("web/members/app.js", "site.read")],
    confidence=0.9, reasoning="members /api/site is public.",
    description="Anyone reads public site info via the members API.")
