# -*- coding: utf-8 -*-
"""Ghost (OSS) L1 attack surface as data.

Authoritative sources:
  ghost/core/server/web/api/endpoints/content/routes.js  (Content API, key auth)
  ghost/core/server/web/api/endpoints/admin/routes.js     (Admin API, session/key auth)
  ghost/core/server/web/api/endpoints/admin/middleware.js (authAdminApi chain)
  ghost/core/server/web/members/app.js                    (Members API, magic-link session)
Mounts: /ghost/api/content, /ghost/api/admin (web/api/app.js), /members/api (web/parent/frontend.js).
ORIGIN = http://localhost:2368 (default Ghost port / official image).

Auth planes:
  - Content API  : Content API key (?key= or Authorization) -> subject ContentClient.
  - Admin API    : AdminSession cookie OR Admin API key JWT, then role authorization
                   (authAdminApi chain) -> subjects Staff/Administrator/Owner/Integration.
                   Bootstrap routes (session, authentication/*, invitation) are UN-authenticated.
  - Members API  : member session from magic-link / OTC -> subject Member (some Anonymous).

Nodes with non-empty io_variants are L2 coverage candidates; the Admin API long tail is
enumerated without io_variants (surface-complete, L2-deferred). Statuses/identity_statuses
left for runtime confirmation.
"""
import common as c
from common import key as K, rf, of, variant, resp_json, resp_empty, dec

ADMIN = "/ghost/api/admin"
CONTENT = "/ghost/api/content"
MEMBERS = "/members/api"


def ev(ref, supports="route + middleware"):
    return c.ev("source", "ghost/core/server/web/" + ref, supports)


API_NODES = []
_SPECS, _ORDER = {}, []


def _dedup(decs):
    out, seen = [], set()
    for d in decs:
        s = (d["raw_field"], d["resource"])
        if s not in seen:
            seen.add(s); out.append(d)
    return out


def api(key, methods, variants, op, sin=None, sout=None, vis_reason="", reach=None, evref="", notes=None):
    k = K(key)
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


def api0(key, methods, op, reach=None, evref="", notes=None):
    api(key, methods, [], op, reach=reach, evref=evref, notes=notes)


def _finalize():
    for k in _ORDER:
        s = _SPECS[k]
        API_NODES.append(c.node(
            k, "api", s["methods"], variants=s["variants"], operation_semantic=s["op"],
            sem_in_decisions=_dedup(s["sin"]), sem_out_decisions=_dedup(s["sout"]),
            visibility="black_box", vis_reason=s["vis_reason"], reachable=True, reach_conds=s["reach"],
            evidence=[ev(e) for e in dict.fromkeys(s["ev"])],
            notes="; ".join(dict.fromkeys(s["notes"])) or None))


# shared decs
def d_email():
    return dec("email", "UserEmail(user)", "identifier", reference_capable=True, reason="Account email.")


def d_pw():
    return dec("password", "Password(user)", "credential", reason="Account password.")


def d_key():
    return dec("key", "ContentAPIKey(client)", "credential", reason="Content API key authorizes the read.")


# ===========================================================================
# CONTENT API (Content API key) -- public read / enumeration surface
# ===========================================================================
def content_read(path, resource, rtype, evref):
    api(CONTENT + path, ["GET"],
        [variant("GET", [rf("key", "query", required=True, description="Content API key")],
                 resp_json([of(resource, description=resource + " records")]),
                 reason="authenticatePublic then browse/read", evidence=evref)],
        "content_" + resource, sin=[d_key()],
        sout=[dec(resource, rtype, "identifier", reference_capable=True,
                  reason="Published " + resource + ".")],
        vis_reason="Public Content API read.", reach=["Valid Content API key; resource is published."],
        evref="api/endpoints/content/routes.js")


content_read("/posts", "posts", "PostID(post)", "content browse posts")
content_read("/pages", "pages", "PageID(page)", "content browse pages")
content_read("/authors", "authors", "AuthorID(author)", "content browse authors")
content_read("/tags", "tags", "TagID(tag)", "content browse tags")
content_read("/settings", "settings", "SettingKey(setting)", "content public settings")
content_read("/tiers", "tiers", "TierID(tier)", "content tiers")
# deferred content reads
for p, o in [("/posts/:id", "read_post"), ("/posts/slug/:slug", "read_post_slug"),
             ("/pages/:id", "read_page"), ("/authors/:id", "read_author"), ("/tags/:id", "read_tag"),
             ("/newsletters", "browse_newsletters"), ("/offers/:id", "read_offer"),
             ("/recommendations", "browse_recommendations"),
             ("/search-index/posts", "search_posts"), ("/search-index/authors", "search_authors"),
             ("/search-index/tags", "search_tags")]:
    api0(CONTENT + p, ["GET"], "content_" + o, reach=["Content API key."],
         evref="api/endpoints/content/routes.js")


# ===========================================================================
# ADMIN API -- auth bootstrap (UN-authenticated or session-establishing)
# ===========================================================================
api(ADMIN + "/session", ["POST", "DELETE"],
    [variant("POST", [rf("email", "body", required=True), rf("password", "body", required=True)],
             resp_empty(), body_format="json",
             reason="session.add: verify credentials, set admin session cookie",
             evidence="session.add"),
     variant("DELETE", [], resp_empty(), reason="session.delete: destroy admin session",
             evidence="session.delete")],
    "admin_session",
    sin=[d_email(), d_pw()],
    sout=[dec("token", "AdminSession(session)", "credential", reason="Admin session cookie.")],
    vis_reason="Admin login/logout.", reach=["Public (login); authenticated (logout)."],
    evref="api/endpoints/admin/routes.js:session", notes="Primary admin auth surface; brute-force target.")

api(ADMIN + "/authentication/setup", ["POST", "GET"],
    [variant("POST", [rf("email", "body", required=True), rf("password", "body", required=True)],
             resp_json([of("user")]), body_format="json",
             reason="authentication.setup: create the OWNER on a fresh install (UNAUTHENTICATED)",
             evidence="authentication.setup"),
     variant("GET", [], resp_json([of("status", flow=False)]),
             reason="isSetup: whether the blog has been set up", evidence="authentication.isSetup")],
    "admin_setup", sin=[d_email(), d_pw()],
    sout=[dec("user", "UserID(user)", "identifier", reference_capable=True, reason="Created owner user.")],
    vis_reason="Initial owner setup.",
    reach=["POST reachable ONLY before setup completes (fresh install) -- else 403."],
    evref="api/endpoints/admin/routes.js:setup",
    notes="Unauthenticated owner-creation; a setup-race / re-setup attack surface.")

api(ADMIN + "/authentication/password_reset", ["POST", "PUT"],
    [variant("POST", [rf("email", "body", required=True)], resp_empty(), body_format="json",
             reason="generateResetToken: emails a reset link (UNAUTHENTICATED)",
             evidence="authentication.generateResetToken"),
     variant("PUT", [rf("token", "body", required=True), rf("password", "body", required=True)],
             resp_empty(), body_format="json",
             reason="resetPassword: set a new password via emailed token",
             evidence="authentication.resetPassword")],
    "admin_password_reset", sin=[d_email(), d_pw(),
        dec("token", "ResetToken(user)", "credential", reason="Emailed password-reset token.")],
    vis_reason="Password reset.", reach=["Public; PUT needs a valid emailed token."],
    evref="api/endpoints/admin/routes.js:password_reset",
    notes="Unauthenticated reset-request = user-enumeration + email-bomb surface.")

api(ADMIN + "/authentication/invitation", ["POST", "GET"],
    [variant("POST", [rf("token", "body", required=True), rf("password", "body", required=True)],
             resp_empty(), body_format="json",
             reason="acceptInvitation: staff accepts an invite and sets a password (UNAUTH)",
             evidence="authentication.acceptInvitation"),
     variant("GET", [rf("email", "query", required=True)], resp_json([of("invitation", flow=False)]),
             reason="isInvitation: check an invite exists for an email", evidence="authentication.isInvitation")],
    "admin_invitation",
    sin=[dec("token", "InviteToken(invite)", "credential", reason="Emailed staff-invite token."),
         d_pw(), d_email()],
    vis_reason="Invitation accept/check.", reach=["Public; needs a valid invite token/email."],
    evref="api/endpoints/admin/routes.js:invitation")

api(ADMIN + "/session/verify", ["POST", "PUT"],
    [variant("POST", [rf("token", "body", required=True, description="2FA code")], resp_empty(),
             body_format="json", reason="sendAuthCode / verifyAuthCode (2FA)", evidence="session.verify")],
    "admin_session_verify",
    sin=[dec("token", "OTPCode(session)", "credential", reason="Emailed 2FA code.")],
    vis_reason="Admin 2FA.", reach=["Mid-login (staff 2FA enabled)."],
    evref="api/endpoints/admin/routes.js:session_verify")

api(ADMIN + "/identities", ["GET"],
    [variant("GET", [], resp_json([of("identities", description="SSO identity token")]),
             reason="identities.read: mints an SSO identity token for the staff user",
             evidence="identities.read")],
    "admin_read_identities",
    sout=[dec("identities", "IdentityToken(session)", "credential",
              reason="SSO identity token for the authenticated staff user.")],
    vis_reason="SSO identity token.", reach=["Authenticated admin."],
    evref="api/endpoints/admin/routes.js:identities")

api(ADMIN + "/site", ["GET"],
    [variant("GET", [], resp_json([of("site", description="public site info")]),
             reason="site.read via publicAdminApi (NO auth)", evidence="site.read")],
    "admin_public_site",
    vis_reason="Public site info (publicAdminApi).", reach=["Public (publicAdminApi, no token)."],
    evref="api/endpoints/admin/routes.js:site")


# ===========================================================================
# ADMIN API -- core resources (authAdminApi: session or Admin API key + role)
# ===========================================================================
def _pid():
    return rf("id", "path", required=True, description="resource id")


def admin_browse(path, resource, rtype, op, evref, role="Staff"):
    api(ADMIN + path, ["GET"],
        [variant("GET", [], resp_json([of(resource)]),
                 reason="authAdminApi then browse", evidence=evref)],
        op, sout=[dec(resource, rtype, "identifier", reference_capable=True, reason="Listed " + resource + ".")],
        vis_reason="Admin browse " + resource + ".", reach=["Authenticated admin (role " + role + ")."],
        evref="api/endpoints/admin/routes.js")


def admin_crud(base, resource, rtype, singular, evbase, add_body=None):
    """Models POST base, GET base/:id, PUT base/:id, DELETE base/:id as 2 nodes."""
    rk = rtype  # e.g. PostID(post)
    _res = dec(singular, rk, "identifier", reference_capable=True, reason=singular + " id.")
    # collection node: GET browse + POST add
    api(ADMIN + base, ["GET", "POST"],
        [variant("GET", [], resp_json([of(resource)]), reason="browse", evidence=evbase + ".browse"),
         variant("POST", add_body or [rf("payload", "body", required=True, description=singular + " body")],
                 resp_json([of(singular)]), body_format="json", reason="add", evidence=evbase + ".add")],
        "admin_" + resource,
        sout=[dec(resource, rk, "identifier", reference_capable=True, reason="Listed/created " + singular + ".")],
        vis_reason="Admin " + resource + " browse/create.", reach=["Authenticated admin."],
        evref="api/endpoints/admin/routes.js")
    # item node: GET read + PUT edit + DELETE destroy
    api(ADMIN + base + "/:id", ["GET", "PUT", "DELETE"],
        [variant("GET", [_pid()], resp_json([of(singular)]), reason="read", evidence=evbase + ".read"),
         variant("PUT", [_pid()], resp_json([of(singular)]), body_format="json", reason="edit",
                 evidence=evbase + ".edit"),
         variant("DELETE", [_pid()], resp_empty(), reason="destroy", evidence=evbase + ".destroy")],
        "admin_" + singular + "_item", sin=[_res],
        vis_reason="Admin " + singular + " read/edit/delete.",
        reach=["Authenticated admin; resource exists."], evref="api/endpoints/admin/routes.js")


admin_crud("/posts", "posts", "PostID(post)", "post", "posts")
admin_crud("/tags", "tags", "TagID(tag)", "tag", "tags")
admin_crud("/members", "members", "MemberID(member)", "member", "members")
admin_crud("/integrations", "integrations", "IntegrationID(integration)", "integration", "integrations",
           add_body=[rf("name", "body", required=True, description="integration name")])

# pages: browse+add only (item ops deferred)
admin_browse("/pages", "pages", "PageID(page)", "admin_pages", "pages.browse")
api0(ADMIN + "/pages", ["POST", "DELETE"], "admin_pages_write", evref="api/endpoints/admin/routes.js")
api0(ADMIN + "/pages/:id", ["GET", "PUT", "DELETE"], "admin_page_item", evref="api/endpoints/admin/routes.js")

# ## Users (no create via API; special actions)
api(ADMIN + "/users", ["GET"],
    [variant("GET", [], resp_json([of("users")]), reason="users.browse", evidence="users.browse")],
    "admin_users", sout=[dec("users", "UserID(user)", "identifier", reference_capable=True,
                             reason="Staff users.")],
    vis_reason="Admin user list.", reach=["Authenticated admin."], evref="api/endpoints/admin/routes.js")
api(ADMIN + "/users/:id", ["GET", "PUT", "DELETE"],
    [variant("GET", [_pid()], resp_json([of("user")]), reason="users.read", evidence="users.read"),
     variant("PUT", [_pid()], resp_json([of("user")]), body_format="json", reason="users.edit",
             evidence="users.edit"),
     variant("DELETE", [_pid()], resp_empty(), reason="users.destroy", evidence="users.destroy")],
    "admin_user_item",
    sin=[dec("id", "UserID(user)", "identifier", reference_capable=True, reason="Target staff user.")],
    vis_reason="Admin user read/edit/delete.",
    reach=["Authenticated admin; editing another user requires sufficient role."],
    evref="api/endpoints/admin/routes.js",
    notes="Cross-user edit/delete is role-gated by authorizeAdminApi -- a privilege-boundary surface.")
api(ADMIN + "/users/password", ["PUT"],
    [variant("PUT", [rf("password", "body", required=True, description="new password")], resp_empty(),
             body_format="json", reason="users.changePassword", evidence="users.changePassword")],
    "admin_change_password", sin=[d_pw()],
    vis_reason="Change password.", reach=["Authenticated admin."], evref="api/endpoints/admin/routes.js")
api(ADMIN + "/users/owner", ["PUT"],
    [variant("PUT", [rf("id", "body", required=True, description="new owner user id")], resp_empty(),
             body_format="json", reason="users.transferOwnership", evidence="users.transferOwnership")],
    "admin_transfer_ownership",
    sin=[dec("id", "UserID(user)", "identifier", reference_capable=True, reason="New owner.")],
    vis_reason="Transfer ownership.", reach=["Owner ONLY (highest-privilege action)."],
    evref="api/endpoints/admin/routes.js", notes="Owner-only; site takeover primitive if abused.")
api0(ADMIN + "/users/:id/token", ["GET", "PUT"], "admin_staff_token", evref="api/endpoints/admin/routes.js")
api(ADMIN + "/members/:id/signin_urls", ["GET"],
    [variant("GET", [_pid()], resp_json([of("signin_url", description="one-click member sign-in URL")]),
             reason="memberSigninUrls.read: mints a magic sign-in URL for a member",
             evidence="memberSigninUrls.read")],
    "admin_member_signin_url",
    sin=[dec("id", "MemberID(member)", "identifier", reference_capable=True, reason="Target member.")],
    sout=[dec("signin_url", "MemberMagicLink(member)", "credential",
              reason="Impersonation URL: logs anyone in AS the member.")],
    vis_reason="Member impersonation URL.", reach=["Authenticated admin."],
    evref="api/endpoints/admin/routes.js", notes="Member-impersonation surface.")

# ## Settings + Roles
api(ADMIN + "/settings", ["GET", "PUT"],
    [variant("GET", [], resp_json([of("settings")]), reason="settings.browse", evidence="settings.browse"),
     variant("PUT", [rf("settings", "body", required=True, description="settings array")],
             resp_json([of("settings")]), body_format="json", reason="settings.edit", evidence="settings.edit")],
    "admin_settings",
    sout=[dec("settings", "SettingKey(setting)", "identifier", reference_capable=True, reason="Settings.")],
    vis_reason="Settings browse/edit.", reach=["Authenticated admin (edit may need Administrator)."],
    evref="api/endpoints/admin/routes.js")
api(ADMIN + "/roles", ["GET"],
    [variant("GET", [], resp_json([of("roles")]), reason="roles.browse", evidence="roles.browse")],
    "admin_roles", vis_reason="Roles list.", reach=["Authenticated admin."],
    evref="api/endpoints/admin/routes.js")


# ===========================================================================
# ADMIN API -- high-value / dangerous (DB, themes, uploads, webhooks, invites)
# ===========================================================================
api(ADMIN + "/db", ["GET", "POST", "DELETE"],
    [variant("GET", [], resp_json([of("db", description="full content export")]),
             reason="db.exportContent: dumps ALL content as JSON", evidence="db.exportContent"),
     variant("POST", [rf("importfile", "body", required=True, description="import JSON/zip (multipart)")],
             resp_empty(), body_format="plain", reason="db.importContent", evidence="db.importContent"),
     variant("DELETE", [], resp_empty(), reason="db.deleteAllContent: wipes all content",
             evidence="db.deleteAllContent")],
    "admin_db",
    sout=[dec("db", "ContentExport(site)", "summary", reason="Full-content export (data exfiltration).")],
    vis_reason="Content export/import/delete.", reach=["Authenticated admin (Owner/Admin)."],
    evref="api/endpoints/admin/routes.js:db",
    notes="GET=full exfiltration; DELETE=destructive wipe; POST=import (mass-assignment surface).")

api(ADMIN + "/themes/upload", ["POST"],
    [variant("POST", [rf("file", "body", required=True, description="theme .zip (multipart)")],
             resp_json([of("themes")]), body_format="plain",
             reason="themes.upload: accepts a theme ZIP", evidence="themes.upload")],
    "admin_theme_upload",
    vis_reason="Theme ZIP upload.", reach=["Authenticated admin."],
    evref="api/endpoints/admin/routes.js:themes",
    notes="Arbitrary ZIP -> theme files (template/helpers): code-adjacent upload surface.")
api(ADMIN + "/themes/install", ["POST"],
    [variant("POST", [rf("source", "query", required=True, description="e.g. github repo ref")],
             resp_json([of("themes")]), reason="themes.install: fetch+install from a source (SSRF-adjacent)",
             evidence="themes.install")],
    "admin_theme_install", vis_reason="Install theme from source.", reach=["Authenticated admin."],
    evref="api/endpoints/admin/routes.js:themes", notes="Server fetches a remote source -> SSRF-adjacent.")
api(ADMIN + "/themes/:name/activate", ["PUT"],
    [variant("PUT", [rf("name", "path", required=True, description="theme name")], resp_json([of("themes")]),
             reason="themes.activate", evidence="themes.activate")],
    "admin_theme_activate",
    sin=[dec("name", "ThemeName(theme)", "identifier", reference_capable=True, reason="Theme to activate.")],
    vis_reason="Activate theme.", reach=["Authenticated admin."], evref="api/endpoints/admin/routes.js:themes")
api0(ADMIN + "/themes/", ["GET"], "admin_themes_browse", evref="api/endpoints/admin/routes.js")
api0(ADMIN + "/themes/:name/download", ["GET"], "admin_theme_download", evref="api/endpoints/admin/routes.js")
api0(ADMIN + "/themes/:name", ["DELETE"], "admin_theme_destroy", evref="api/endpoints/admin/routes.js")

api(ADMIN + "/images/upload", ["POST"],
    [variant("POST", [rf("file", "body", required=True, description="image file (multipart)")],
             resp_json([of("images", description="uploaded image URL")]), body_format="plain",
             reason="images.upload", evidence="images.upload")],
    "admin_image_upload",
    sout=[dec("images", "ImageURL(image)", "locator", reason="Stored image URL.")],
    vis_reason="Image upload.", reach=["Authenticated admin."],
    evref="api/endpoints/admin/routes.js:images", notes="File upload (type/size validation surface).")
api0(ADMIN + "/media/upload", ["POST"], "admin_media_upload", evref="api/endpoints/admin/routes.js")
api0(ADMIN + "/files/upload", ["POST"], "admin_file_upload", evref="api/endpoints/admin/routes.js")

api(ADMIN + "/webhooks", ["POST"],
    [variant("POST", [rf("target_url", "body", required=True, description="webhook target URL")],
             resp_json([of("webhooks")]), body_format="json", reason="webhooks.add", evidence="webhooks.add")],
    "admin_webhook_add",
    sout=[dec("webhooks", "WebhookID(webhook)", "identifier", reference_capable=True, reason="Created webhook.")],
    vis_reason="Create webhook.", reach=["Authenticated admin / integration."],
    evref="api/endpoints/admin/routes.js:webhooks", notes="Attacker-controlled target_url -> SSRF-adjacent.")
api0(ADMIN + "/webhooks/:id", ["PUT", "DELETE"], "admin_webhook_item", evref="api/endpoints/admin/routes.js")

api(ADMIN + "/invites", ["GET", "POST"],
    [variant("GET", [], resp_json([of("invites")]), reason="invites.browse", evidence="invites.browse"),
     variant("POST", [rf("email", "body", required=True), rf("role_id", "body", required=True)],
             resp_json([of("invites")]), body_format="json",
             reason="invites.add: invite a staff user with a role", evidence="invites.add")],
    "admin_invites", sin=[d_email()],
    sout=[dec("invites", "InviteID(invite)", "identifier", reference_capable=True, reason="Invites.")],
    vis_reason="Staff invites.", reach=["Authenticated admin (Administrator to invite)."],
    evref="api/endpoints/admin/routes.js:invites",
    notes="Inviting a high role is a privilege-escalation surface if role checks are weak.")
api0(ADMIN + "/invites/:id", ["GET", "DELETE"], "admin_invite_item", evref="api/endpoints/admin/routes.js")

# ## Admin API long tail (surface-complete, L2-deferred)
_TAIL = [
    ("/config", ["GET"]), ("/config/featurebase", ["GET"]), ("/mentions", ["GET"]),
    ("/comments", ["GET", "POST"]), ("/comments/:id", ["GET", "PUT"]),
    ("/labels", ["GET", "POST"]), ("/labels/:id", ["GET", "PUT", "DELETE"]),
    ("/offers", ["GET", "POST"]), ("/offers/:id", ["GET", "PUT"]),
    ("/snippets", ["GET", "POST"]), ("/snippets/:id", ["GET", "PUT", "DELETE"]),
    ("/newsletters", ["GET", "POST"]), ("/newsletters/:id", ["GET", "PUT"]),
    ("/recommendations", ["GET", "POST"]), ("/recommendations/:id", ["GET", "PUT", "DELETE"]),
    ("/emails/:id", ["GET"]), ("/email_previews/posts/:id", ["GET", "POST"]),
    ("/webhooks-deferred", ["GET"]), ("/oembed", ["GET"]), ("/slack/test", ["POST"]),
    ("/redirects/download", ["GET"]), ("/redirects/upload", ["POST"]),
    ("/exports/download", ["GET"]), ("/exports", ["POST"]),
    ("/db/backup", ["POST"]), ("/db/media/inline", ["POST"]),
    ("/schedules/:resource/:id", ["PUT"]), ("/notifications", ["GET", "POST"]),
    ("/custom_theme_settings", ["GET", "PUT"]), ("/actions", ["GET"]),
    ("/tiers", ["GET", "POST"]), ("/tiers/:id", ["GET", "PUT"]),
    ("/members/upload", ["GET"]), ("/members/stripe_connect", ["GET"]),
]
for p, ms in _TAIL:
    pp = p.replace("-deferred", "")
    api0(ADMIN + pp, ms, "admin_tail" + p.replace("/", "_").replace(":", ""),
         reach=["Authenticated admin."], evref="api/endpoints/admin/routes.js")


# ===========================================================================
# MEMBERS API (/members/api) -- magic-link session
# ===========================================================================
api(MEMBERS + "/send-magic-link", ["POST"],
    [variant("POST", [rf("email", "body", required=True, description="member email")], resp_empty(),
             body_format="json", reason="emails a passwordless sign-in link", evidence="send-magic-link")],
    "member_send_magic_link", sin=[dec("email", "MemberEmail(member)", "identifier",
        reference_capable=True, reason="Member email (signup/signin).")],
    vis_reason="Passwordless signin request.",
    reach=["Public (members enabled). Enumeration + email-bomb surface."],
    evref="members/app.js:send-magic-link")
api(MEMBERS + "/verify-otc", ["POST"],
    [variant("POST", [rf("otc", "body", required=True, description="one-time code")], resp_empty(),
             body_format="json", reason="verify one-time code -> member session", evidence="verify-otc")],
    "member_verify_otc",
    sin=[dec("otc", "OTPCode(member)", "credential", reason="Emailed one-time code.")],
    vis_reason="OTC verify.", reach=["Public; needs a valid OTC."], evref="members/app.js:verify-otc")
api(MEMBERS + "/session", ["GET", "DELETE"],
    [variant("GET", [], resp_json([of("token", description="member identity token (JWT)")]),
             reason="getIdentityToken", evidence="members/app.js:session"),
     variant("DELETE", [], resp_empty(), reason="deleteSession (logout)", evidence="members/app.js:session")],
    "member_session",
    sout=[dec("token", "MemberIdentityToken(member)", "credential", reason="Member identity JWT.")],
    vis_reason="Member identity token / logout.", reach=["Member session (GET); any (DELETE)."],
    evref="members/app.js:session")
api(MEMBERS + "/member", ["GET"],
    [variant("GET", [], resp_json([of("member", description="the member's own account")]),
             reason="account read (self)", evidence="members/account")],
    "member_read_self",
    sout=[dec("member", "MemberID(member)", "identifier", reference_capable=True, reason="Own account.")],
    vis_reason="Member self account.", reach=["Member session."], evref="members/app.js:/api/member")
api(MEMBERS + "/create-stripe-checkout-session", ["POST"],
    [variant("POST", [rf("tierId", "body", description="tier to subscribe to")], resp_json([of("url")]),
             body_format="json", reason="create Stripe checkout session", evidence="create-stripe-checkout-session")],
    "member_stripe_checkout",
    vis_reason="Stripe checkout.", reach=["Members + Stripe configured."],
    evref="members/app.js:create-stripe-checkout-session")
api(MEMBERS + "/site", ["GET"],
    [variant("GET", [], resp_json([of("site")]), reason="public site info", evidence="members/app.js:site")],
    "member_public_site", vis_reason="Public site info.", reach=["Public."],
    evref="members/app.js:/api/site")
# deferred members endpoints
for p, ms, o in [("/member/newsletters", ["GET", "PUT"], "member_newsletters"),
                 ("/member/email", ["POST"], "member_update_email"),
                 ("/entitlements", ["GET"], "member_entitlements"),
                 ("/integrity-token", ["GET"], "member_integrity_token"),
                 ("/create-stripe-update-session", ["POST"], "member_stripe_update"),
                 ("/create-stripe-billing-portal-session", ["POST"], "member_stripe_portal"),
                 ("/subscriptions/:id", ["PUT"], "member_update_subscription"),
                 ("/comments", ["GET", "POST"], "member_comments"),
                 ("/feedback", ["POST"], "member_feedback"),
                 ("/gifts/:token/redeem", ["GET", "POST"], "member_redeem_gift"),
                 ("/recommendations/:id/clicked", ["POST"], "member_rec_clicked")]:
    api0(MEMBERS + p, ms, o, reach=["Members API."], evref="members/app.js")


_finalize()


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded against official ghost:6-alpine (dev/SQLite,
# security__staffDeviceVerification=false). runtime/probe.ps1 -> probe_results/matrix.json.
# Identity labels: anonymous | staff (admin session cookie) | contentclient (Content API key).
# NOTE: with staffDeviceVerification=TRUE (default/production) the admin SESSION plane is
# blocked without SMTP (email 2FA) -> staff rows require that flag off or SMTP configured
# (see annotation ghost-008).
# ===========================================================================
_RUNTIME = {
    "/ghost/api/admin/site":                        {"s": [200], "id": {"anonymous": [200]}},
    "/ghost/api/admin/authentication/setup":        {"s": [200, 201, 403],
        "id": {"anonymous": [200, 201, 403]}},   # GET isSetup 200; POST fresh 201; POST after setup 403
    "/ghost/api/admin/session":                     {"s": [201], "id": {"anonymous": [201]}},  # login
    "/ghost/api/admin/authentication/password_reset": {"s": [404, 500],
        "id": {"anonymous": [404, 500]}},        # known email 500(mail), unknown 404 -> enumeration oracle
    "/ghost/api/admin/posts":                       {"s": [200, 201, 403],
        "id": {"anonymous": [403], "staff": [200, 201]}},
    "/ghost/api/admin/users":                       {"s": [200, 403], "id": {"anonymous": [403], "staff": [200]}},
    "/ghost/api/admin/members":                     {"s": [200, 403], "id": {"anonymous": [403], "staff": [200]}},
    "/ghost/api/admin/settings":                    {"s": [200, 403], "id": {"anonymous": [403], "staff": [200]}},
    "/ghost/api/admin/integrations":                {"s": [200, 403], "id": {"anonymous": [403], "staff": [200]}},
    "/ghost/api/content/posts":                     {"s": [200, 403],
        "id": {"anonymous": [403], "contentclient": [200]}},
    "/ghost/api/content/settings":                  {"s": [200, 403],
        "id": {"anonymous": [403], "contentclient": [200]}},
    "/members/api/site":                            {"s": [200], "id": {"anonymous": [200]}},
    "/members/api/member":                          {"s": [204], "id": {"anonymous": [204]}},
    "/members/api/send-magic-link":                 {"s": [400], "id": {"anonymous": [400]}},
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
# PAGE / FRONTEND nodes (surface-complete, not candidates)
# ===========================================================================
PAGE_NODES = []


def page(key, methods, op="", kind="page", reach=None, evref="", notes=None):
    PAGE_NODES.append(c.node(K(key), kind, methods, variants=[], operation_semantic=op, params=[],
                             visibility="black_box", reachable=True, reach_conds=reach or [],
                             evidence=[ev(evref, "frontend")] if evref else [], notes=notes))


page("/ghost/", ["GET"], "admin_spa", kind="static", evref="web/admin", notes="Ember Admin SPA shell.")
page("/", ["GET"], "frontend_home", kind="page", evref="web/site", notes="Theme-rendered home.")
page("/:slug/", ["GET"], "frontend_post", kind="page", evref="web/site")
page("/rss/", ["GET"], "frontend_rss", kind="page", evref="web/site")
page("/sitemap.xml", ["GET"], "frontend_sitemap", kind="static", evref="web/site")
page("/.well-known/", ["GET"], "well_known", kind="static", evref="web/well-known.js")


EDGES = [
    {"src": K("/ghost/"), "dst": K(ADMIN + "/session"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/ghost/"), "dst": K(ADMIN + "/posts"), "methods": ["GET"], "triggers": ["xhr"]},
    {"src": K("/"), "dst": K(MEMBERS + "/send-magic-link"), "methods": ["POST"], "triggers": ["xhr"]},
]
