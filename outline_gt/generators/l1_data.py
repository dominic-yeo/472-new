# -*- coding: utf-8 -*-
"""Outline L1 attack surface as data.

Authoritative source (this repo, getoutline/outline @ 1.12.0):
  - Mounts:      server/services/web.ts  (mount("/api", api), ("/auth", auth),
                 ("/oauth", oauth), ("/mcp", mcp); the root app serves /share/*)
  - API:         server/routes/api/*/*.ts  -- POST-RPC, e.g. "documents.create"
                 (each @koa/router mounted at /api via router.use("/", ...))
  - Auth:        server/middlewares/authentication.ts  (token: Authorization Bearer |
                 body "token" | ?token= query | accessToken cookie)
  - AuthZ:       server/policies/*.ts  -- cancan authorize(user, action, model);
                 roles admin|member|viewer|guest; team-scoped multi-tenant.

ORIGIN = http://localhost:3000 (Outline default URL/PORT).

Auth model: a token (API key | OAuth access token | app session JWT) resolves to a
USER -> TEAM + ROLE. Most /api/* endpoints require auth(); a few are public
(auth.config, installation.create bootstrap) or optional-auth (shares.info,
urls.unfurl). Public document reading is via a SHARE (/share/:shareId). Nodes with
io_variants are L2 candidates; statuses left for runtime (runtime/ has a compose +
probe).
"""
import common as c
from common import key as K, rf, of, variant, resp_json, resp_empty, resp_redirect, dec


def evs(ref, supports="route + handler"):
    return c.ev("source", "outline/server/routes/" + ref, supports)


API_NODES = []
_SPECS, _ORDER = {}, []


def _dedup(ds):
    out, seen = [], set()
    for d in ds:
        s = (d["raw_field"], d["resource"])
        if s not in seen:
            seen.add(s); out.append(d)
    return out


def api(path, methods, variants, op, sin=None, sout=None, vis_reason="", reach=None, evref="", notes=None):
    """Merge-by-path registry (Outline routes are mostly one POST each, but this
    keeps the shared shape and lets GET siblings merge if needed)."""
    k = K(path)
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


def api0(path, methods, op, reach=None, evref="", notes=None):
    api(path, methods, [], op, reach=reach, evref=evref, notes=notes)


def _finalize():
    for k in _ORDER:
        s = _SPECS[k]
        API_NODES.append(c.node(
            k, "api", s["methods"], variants=s["variants"], operation_semantic=s["op"],
            sem_in_decisions=_dedup(s["sin"]), sem_out_decisions=_dedup(s["sout"]),
            visibility="black_box", vis_reason=s["vis_reason"], reachable=True, reach_conds=s["reach"],
            evidence=[evs(e) for e in dict.fromkeys(s["ev"])],
            notes="; ".join(dict.fromkeys(s["notes"])) or None))


# ---- semantic decision shorthands --------------------------------------
def d_doc():
    return dec("documentId", "DocumentID(document)", "identifier", reference_capable=True,
               reason="Target document id (or urlId).")


def d_coll():
    return dec("collectionId", "CollectionID(collection)", "identifier", reference_capable=True,
               reason="Target collection id.")


def d_share():
    return dec("shareId", "ShareID(share)", "identifier", reference_capable=True,
               reason="Public share id (urlId).")


def d_user():
    return dec("userId", "UserID(user)", "identifier", reference_capable=True, reason="Target user id.")


def d_team():
    return dec("teamId", "TeamID(team)", "identifier", reference_capable=True, reason="Team (workspace) id.")


def d_group():
    return dec("groupId", "GroupID(group)", "identifier", reference_capable=True, reason="Target group id.")


def d_email():
    return dec("email", "UserEmail(user)", "identifier", reference_capable=True, reason="User email.")


def d_token():
    return dec("token", "AccessToken(session)", "credential", reason="API key / OAuth / session token.")


def d_id(resource, reason):
    return dec("id", resource, "identifier", reference_capable=True, reason=reason)


# small response shapes
def r_data(*names):
    return resp_json([of(n) for n in names])


POST = ["POST"]


# ===========================================================================
# AUTH / SESSION  (server/routes/api/auth, server/routes/auth, server/routes/oauth)
# ===========================================================================
api("/api/auth.config", POST,
    [variant("POST", [], r_data("name", "hostname", "providers", "passwordLogin"),
             body_format="json", reason="public auth config: providers + team branding for the login screen",
             evidence="api/auth/auth.ts auth.config (PUBLIC, no auth)")],
    "auth_config", vis_reason="Public: unauthenticated config/branding + enabled SSO providers.",
    reach=["PUBLIC (no auth). Leaks team name/subdomain existence + enabled providers (enumeration oracle)."],
    evref="api/auth/auth.ts", notes="Only public /api endpoint besides installation.create.")

api("/api/auth.info", POST,
    [variant("POST", [rf("token", "body", description="optional explicit token")],
             r_data("user", "team", "groups", "availableTeams"), body_format="json",
             reason="returns the authenticated user + team + memberships",
             evidence="api/auth/auth.ts auth.info")],
    "auth_info", sout=[d_token()],
    vis_reason="Authenticated: who am I.", reach=["Authenticated (any role)."],
    evref="api/auth/auth.ts")

api("/api/auth.delete", POST,
    [variant("POST", [], resp_empty(), body_format="json",
             reason="sign out: revokes the session / transfers cookie clearing",
             evidence="api/auth/auth.ts auth.delete")],
    "logout", vis_reason="Authenticated logout.", reach=["Authenticated. Clears session."],
    evref="api/auth/auth.ts")

api("/api/installation.create", POST,
    [variant("POST", [rf("teamName", "body", required=True), rf("userName", "body", required=True),
                      rf("userEmail", "body", required=True)],
             r_data("team", "user", "accessToken"), body_format="json",
             reason="first-boot bootstrap: creates the first team + admin when none exist",
             evidence="api/installation/installation.ts installation.create (no auth; blocked once a team exists)")],
    "installation_create", sin=[d_email()], sout=[d_token()],
    vis_reason="Public bootstrap (self-hosted): first-run team+admin creation.",
    reach=["PUBLIC but single-shot: refuses once any team exists. First-boot takeover window."],
    evref="api/installation/installation.ts", notes="Self-hosted only (not isCloudHosted).")

api("/api/installation.info", POST,
    [variant("POST", [], r_data("version", "latestVersion", "versionsBehind"), body_format="json",
             reason="server version info", evidence="api/installation/installation.ts installation.info")],
    "installation_info", vis_reason="Authenticated server version.", reach=["Authenticated."],
    evref="api/installation/installation.ts")

# --- SSO sign-in (generic across providers) + email magic link + oauth2 server ---
api("/auth/email", POST,
    [variant("POST", [rf("email", "body", required=True), rf("client", "body", description="web|desktop")],
             r_data("redirect", "success"), body_format="json",
             reason="password-less sign-in: emails a magic-link token to a known address",
             evidence="plugins/email/server/auth/email.ts")],
    "signin_email", sin=[d_email()],
    vis_reason="Public: request an email sign-in link.",
    reach=["PUBLIC. User-enumeration via response/timing; email-link delivery; rate-limited."],
    evref="../../plugins/email/server/auth/email.ts", notes="Default when no SSO provider is configured.")

api("/auth/:provider", ["GET"],
    [variant("GET", [rf("provider", "path", required=True, description="google|azure|oidc|discord|slack|..."),
                     rf("client", "query")],
             resp_redirect("302 to the IdP authorize URL"),
             reason="start an SSO/OAuth sign-in flow (passport); sets state cookie",
             evidence="plugins/*/server/auth/*.ts router.get(config.id, startOAuthFlow)")],
    "signin_sso_start", vis_reason="Public: begin SSO.",
    reach=["PUBLIC. State/CSRF via cookie; 'client' chooses web/desktop redirect target."],
    evref="../../plugins/google/server/auth/google.ts",
    notes="One pair per enabled provider (google/azure/oidc/discord/slack/github/gitlab/gitea/linear/notion/figma).")

api("/auth/:provider.callback", ["GET"],
    [variant("GET", [rf("provider", "path", required=True), rf("code", "query"), rf("state", "query")],
             resp_redirect("302 to the app (sets accessToken cookie) or an error"),
             reason="SSO callback: exchanges code, provisions/links the user, mints a session",
             evidence="plugins/*/server/auth/*.ts router.get(config.id+'.callback', passportMiddleware)")],
    "signin_sso_callback", sin=[d_email()],
    vis_reason="Public SSO callback.",
    reach=["PUBLIC. Account-linking by verified email; redirect/state handling is the open-redirect surface."],
    evref="../../plugins/google/server/auth/google.ts")

api("/auth/redirect", ["GET"],
    [variant("GET", [rf("state", "query")], resp_redirect(),
             reason="post-login redirect to the resolved team subdomain",
             evidence="server/routes/auth/index.ts /redirect")],
    "auth_redirect", vis_reason="Post-login redirect.",
    reach=["Transfer cookie -> team subdomain. Redirect-target validation surface."],
    evref="auth/index.ts")

api("/oauth/authorize", ["GET", "POST"],
    [variant("GET", [rf("client_id", "query", required=True), rf("redirect_uri", "query", required=True),
                     rf("response_type", "query"), rf("scope", "query"), rf("state", "query"),
                     rf("code_challenge", "query")],
             resp_redirect("302 to redirect_uri with an authorization code"),
             reason="OAuth2 authorization endpoint (Outline is an OAuth provider)",
             evidence="server/routes/oauth/index.ts /authorize")],
    "oauth_authorize", sout=[d_token()],
    vis_reason="OAuth2 authorize (consent).",
    reach=["Authenticated user grants a client; redirect_uri + scope + PKCE are the surface."],
    evref="oauth/index.ts", notes="Outline ships an OAuth2 server + dynamic client registration.")

api("/oauth/token", POST,
    [variant("POST", [rf("grant_type", "body", required=True), rf("code", "body"),
                      rf("client_id", "body"), rf("client_secret", "body"),
                      rf("redirect_uri", "body"), rf("code_verifier", "body"),
                      rf("refresh_token", "body")],
             r_data("access_token", "refresh_token", "expires_in", "token_type"), body_format="json",
             reason="OAuth2 token endpoint: exchange code / refresh for an access token",
             evidence="server/routes/oauth/index.ts /token")],
    "oauth_token", sout=[d_token()],
    vis_reason="OAuth2 token exchange.",
    reach=["Client credentials + code/PKCE. Mints scoped OAuth access tokens."],
    evref="oauth/index.ts")

api("/oauth/revoke", POST,
    [variant("POST", [rf("token", "body", required=True), rf("client_id", "body"),
                      rf("client_secret", "body")],
             resp_empty(), body_format="json", reason="revoke an OAuth token",
             evidence="server/routes/oauth/index.ts /revoke")],
    "oauth_revoke", sin=[d_token()], vis_reason="OAuth2 revoke.",
    reach=["Client revokes its token."], evref="oauth/index.ts")

api0("/oauth/register", POST, "oauth_register_client",
     reach=["Dynamic client registration (RFC 7591); gated by config."], evref="oauth/index.ts")
api0("/oauth/register/:clientId", ["GET"], "oauth_registration_read",
     reach=["Read a dynamically-registered client (registration access token)."], evref="oauth/index.ts")
api0("/mcp", ["GET", "POST"], "mcp_server",
     reach=["AI MCP transport; OAuth access-token gated."], evref="mcp/index.ts")


# ===========================================================================
# USERS  (api/users)
# ===========================================================================
U = "api/users/users.ts"
api("/api/users.list", POST,
    [variant("POST", [rf("query", "body"), rf("filter", "body", description="all|invited|suspended|active|admins"),
                      rf("role", "body"), rf("limit", "body", "number"), rf("offset", "body", "number")],
             r_data("users"), body_format="json", reason="list team members (directory)",
             evidence=U)],
    "users_list", vis_reason="List team members.", reach=["Authenticated member; team-scoped."], evref=U)

api("/api/users.info", POST,
    [variant("POST", [rf("id", "body", description="omit = self")],
             r_data("user"), body_format="json", reason="fetch a user profile", evidence=U)],
    "users_info", sin=[d_id("UserID(user)", "Target user id (self if omitted).")],
    vis_reason="Read a user.", reach=["Authenticated; any member can read a teammate (id = IDOR surface)."], evref=U)

api("/api/users.invite", POST,
    [variant("POST", [rf("invites", "body", required=True, description="[{email,name,role}]")],
             r_data("sent", "users"), body_format="json", reason="invite users by email (provisions accounts)",
             evidence=U)],
    "users_invite", sin=[d_email()], vis_reason="Invite users.",
    reach=["authorize(user,'inviteUser',team): member+ may invite; role field escalation surface."], evref=U)

api("/api/users.update", POST,
    [variant("POST", [rf("id", "body"), rf("name", "body"), rf("avatarUrl", "body"),
                      rf("language", "body"), rf("preferences", "body")],
             r_data("user"), body_format="json", reason="update a user profile", evidence=U)],
    "users_update", sin=[d_id("UserID(user)", "User being updated (self or, for admins, another).")],
    vis_reason="Update a user.", reach=["authorize(user,'update',target): self, or admin on others."], evref=U)

api("/api/users.updateEmail", POST,
    [variant("POST", [rf("id", "body"), rf("email", "body", required=True)],
             r_data("success"), body_format="json", reason="change a user's email (verification flow)",
             evidence=U)],
    "users_update_email", sin=[d_email()], vis_reason="Change email.",
    reach=["Self (verification) / admin. Account-takeover-adjacent."], evref=U)

api("/api/users.update_role", POST,
    [variant("POST", [rf("id", "body", required=True), rf("role", "body", required=True,
                                                          description="admin|member|viewer|guest")],
             r_data("user"), body_format="json", reason="set a user's role (privilege change)",
             evidence=U)],
    "users_update_role", sin=[d_id("UserID(user)", "User whose role changes.")],
    vis_reason="Change a user's role (ESCALATION).",
    reach=["authorize(actor,'update'/'demote'/'promote',target): ADMIN. Promote to admin = full team control."],
    evref=U, notes="Primary privilege-escalation lever (also promote/demote).")

api("/api/users.promote", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("user"), body_format="json",
             reason="promote a user to admin", evidence=U)],
    "users_promote", sin=[d_id("UserID(user)", "User promoted to admin.")],
    vis_reason="Promote to admin (ESCALATION).", reach=["authorize(actor,'promote',user): ADMIN only."], evref=U)

api("/api/users.demote", POST,
    [variant("POST", [rf("id", "body", required=True), rf("to", "body", description="member|viewer")],
             r_data("user"), body_format="json", reason="demote an admin", evidence=U)],
    "users_demote", sin=[d_id("UserID(user)", "User demoted.")],
    vis_reason="Demote admin.", reach=["ADMIN only; cannot demote the last admin."], evref=U)

api("/api/users.suspend", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("user"), body_format="json",
             reason="suspend a user (revokes access)", evidence=U)],
    "users_suspend", sin=[d_id("UserID(user)", "User suspended.")],
    vis_reason="Suspend user.", reach=["ADMIN only. DoS-of-account lever."], evref=U)

api("/api/users.activate", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("user"), body_format="json",
             reason="reactivate a suspended user", evidence=U)],
    "users_activate", sin=[d_id("UserID(user)", "User reactivated.")],
    vis_reason="Activate user.", reach=["ADMIN only."], evref=U)

api("/api/users.delete", POST,
    [variant("POST", [rf("id", "body"), rf("code", "body", description="confirmation code for self-delete")],
             r_data("success"), body_format="json", reason="delete a user account", evidence=U)],
    "users_delete", sin=[d_id("UserID(user)", "User deleted (self with code, or admin).")],
    vis_reason="Delete user.", reach=["Self (with emailed code) or ADMIN on others."], evref=U)

api0("/api/users.requestDelete", POST, "users_request_delete",
     reach=["Self: emails a delete-confirmation code."], evref=U)
api0("/api/users.resendInvite", POST, "users_resend_invite", reach=["Admin re-sends an invite."], evref=U)
api0("/api/users.notificationsSubscribe", POST, "users_notif_subscribe", reach=["Self."], evref=U)
api0("/api/users.notificationsUnsubscribe", POST, "users_notif_unsubscribe", reach=["Self / token."], evref=U)


# ===========================================================================
# API KEYS + OAUTH CLIENTS + OAUTH AUTHENTICATIONS
# ===========================================================================
AK = "api/apiKeys/apiKeys.ts"
api("/api/apiKeys.create", POST,
    [variant("POST", [rf("name", "body", required=True), rf("scope", "body", description="['read'|'write'|'create']"),
                      rf("expiresAt", "body")],
             r_data("apiKey", "token"), body_format="json",
             reason="mint a personal API key (long-lived bearer token)", evidence=AK)],
    "apikeys_create", sout=[d_token()], vis_reason="Create API key (credential issuance).",
    reach=["authorize(user,'createApiKey',team). Scoped read/write/create; long-lived bearer -> key sprawl."],
    evref=AK, notes="Keys are bearer tokens accepted on header/body/query transports.")

api("/api/apiKeys.list", POST,
    [variant("POST", [rf("limit", "body", "number"), rf("offset", "body", "number")],
             r_data("apiKeys"), body_format="json", reason="list the caller's API keys", evidence=AK)],
    "apikeys_list", vis_reason="List own API keys.", reach=["Authenticated; own keys."], evref=AK)

api("/api/apiKeys.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="revoke an API key", evidence=AK)],
    "apikeys_delete", sin=[d_id("ApiKeyID(apiKey)", "API key revoked.")],
    vis_reason="Revoke API key.", reach=["Owner / admin."], evref=AK)

OC = "api/oauthClients/oauthClients.ts"
api("/api/oauthClients.create", POST,
    [variant("POST", [rf("name", "body", required=True), rf("redirectUris", "body", required=True),
                      rf("published", "body", "boolean", description="list in the app directory")],
             r_data("oauthClient", "clientId", "clientSecret"), body_format="json",
             reason="register an OAuth client application", evidence=OC)],
    "oauthclients_create", sout=[d_token()], vis_reason="Create OAuth client.",
    reach=["authorize(user,'createOAuthClient',team). redirectUris + 'published' are the phishing/consent surface."],
    evref=OC)

api("/api/oauthClients.rotate_secret", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("oauthClient", "clientSecret"),
             body_format="json", reason="rotate an OAuth client secret", evidence=OC)],
    "oauthclients_rotate_secret", sin=[d_id("OAuthClientID(oauthClient)", "Client whose secret rotates.")],
    sout=[d_token()], vis_reason="Rotate client secret.", reach=["Owner / admin."], evref=OC)

api("/api/oauthClients.info", POST,
    [variant("POST", [rf("clientId", "body", description="public lookup by client_id")],
             r_data("oauthClient"), body_format="json", reason="fetch OAuth client metadata", evidence=OC)],
    "oauthclients_info", vis_reason="Read OAuth client.",
    reach=["Published clients are readable for the consent screen (metadata oracle)."], evref=OC)

api("/api/oauthClients.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("name", "body"), rf("redirectUris", "body")],
             r_data("oauthClient"), body_format="json", reason="update an OAuth client", evidence=OC)],
    "oauthclients_update", sin=[d_id("OAuthClientID(oauthClient)", "Client updated.")],
    vis_reason="Update OAuth client.", reach=["Owner / admin. redirectUris change = hijack surface."], evref=OC)

api("/api/oauthClients.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete an OAuth client", evidence=OC)],
    "oauthclients_delete", sin=[d_id("OAuthClientID(oauthClient)", "Client deleted.")],
    vis_reason="Delete OAuth client.", reach=["Owner / admin."], evref=OC)

api0("/api/oauthClients.list", POST, "oauthclients_list", reach=["Team admin lists clients."], evref=OC)
api("/api/oauthAuthentications.list", POST,
    [variant("POST", [], r_data("oauthAuthentications"), body_format="json",
             reason="list apps the user has authorized", evidence="api/oauthAuthentications/oauthAuthentications.ts")],
    "oauthauth_list", vis_reason="List authorized apps.", reach=["Authenticated; own grants."],
    evref="api/oauthAuthentications/oauthAuthentications.ts")
api("/api/oauthAuthentications.delete", POST,
    [variant("POST", [rf("oauthClientId", "body", required=True)], r_data("success"), body_format="json",
             reason="revoke an app's access (deletes grant + tokens)",
             evidence="api/oauthAuthentications/oauthAuthentications.ts")],
    "oauthauth_delete", vis_reason="Revoke app access.", reach=["Authenticated; own grant."],
    evref="api/oauthAuthentications/oauthAuthentications.ts")


# ===========================================================================
# COLLECTIONS  (api/collections) -- permission boundary for documents
# ===========================================================================
CO = "api/collections/collections.ts"
api("/api/collections.create", POST,
    [variant("POST", [rf("name", "body", required=True), rf("permission", "body",
             description="read|read_write|null (private)"), rf("sharing", "body", "boolean"),
                      rf("private", "body", "boolean")],
             r_data("collection"), body_format="json", reason="create a collection", evidence=CO)],
    "collections_create", vis_reason="Create collection.",
    reach=["authorize(user,'createCollection',team). 'permission' sets the team-wide default access."], evref=CO)

api("/api/collections.info", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("collection"), body_format="json",
             reason="read a collection", evidence=CO)],
    "collections_info", sin=[d_coll()], vis_reason="Read collection.",
    reach=["authorize(user,'read',collection): membership or team default permission."], evref=CO)

api("/api/collections.list", POST,
    [variant("POST", [rf("limit", "body", "number"), rf("offset", "body", "number")],
             r_data("collections"), body_format="json", reason="list collections the user can see", evidence=CO)],
    "collections_list", vis_reason="List collections.", reach=["Authenticated; filtered by access."], evref=CO)

api("/api/collections.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("name", "body"), rf("permission", "body"),
                      rf("sharing", "body", "boolean")],
             r_data("collection"), body_format="json", reason="update a collection (incl. default permission)",
             evidence=CO)],
    "collections_update", sin=[d_coll()], vis_reason="Update collection.",
    reach=["authorize(user,'update',collection): ADMIN of the collection. 'permission' widens team access."], evref=CO)

api("/api/collections.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete a collection and its documents", evidence=CO)],
    "collections_delete", sin=[d_coll()], vis_reason="Delete collection.",
    reach=["authorize(user,'delete',collection): collection admin. Destructive (cascades to documents)."], evref=CO)

api("/api/collections.add_user", POST,
    [variant("POST", [rf("id", "body", required=True), rf("userId", "body", required=True),
                      rf("permission", "body", description="read|read_write|admin")],
             r_data("users", "memberships"), body_format="json",
             reason="grant a user membership on a collection", evidence=CO)],
    "collections_add_user", sin=[d_coll(), d_user()], vis_reason="Grant collection access.",
    reach=["authorize(user,'update',collection). 'admin' permission = escalation within the collection."], evref=CO)

api("/api/collections.add_group", POST,
    [variant("POST", [rf("id", "body", required=True), rf("groupId", "body", required=True),
                      rf("permission", "body")],
             r_data("collectionGroupMemberships"), body_format="json",
             reason="grant a group access to a collection", evidence=CO)],
    "collections_add_group", sin=[d_coll(), d_group()], vis_reason="Grant collection access to a group.",
    reach=["authorize(user,'update',collection)."], evref=CO)

api("/api/collections.documents", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("documents"), body_format="json",
             reason="document structure (tree) of a collection", evidence=CO)],
    "collections_documents", sin=[d_coll()], vis_reason="Collection document tree.",
    reach=["authorize(user,'read',collection)."], evref=CO)

api("/api/collections.export", POST,
    [variant("POST", [rf("id", "body", required=True), rf("format", "body", description="outline-markdown|json|html")],
             r_data("fileOperation"), body_format="json",
             reason="queue an export of a collection (async file operation)", evidence=CO)],
    "collections_export", sin=[d_coll()], vis_reason="Export collection.",
    reach=["authorize(user,'read',collection) + 'export'. Produces a downloadable archive."], evref=CO)

api("/api/collections.export_all", POST,
    [variant("POST", [rf("format", "body")], r_data("fileOperation"), body_format="json",
             reason="queue an export of the whole workspace", evidence=CO)],
    "collections_export_all", vis_reason="Export entire workspace.",
    reach=["authorize(user,'export',team): ADMIN. Bulk data exfiltration primitive."], evref=CO)

api0("/api/collections.remove_user", POST, "collections_remove_user", reach=["Collection admin."], evref=CO)
api0("/api/collections.remove_group", POST, "collections_remove_group", reach=["Collection admin."], evref=CO)
api0("/api/collections.memberships", POST, "collections_memberships", reach=["Read membership list."], evref=CO)
api0("/api/collections.group_memberships", POST, "collections_group_memberships", reach=["Read group memberships."],
     evref=CO)
api0("/api/collections.move", POST, "collections_move", reach=["Reorder/move in the sidebar; collection admin."],
     evref=CO)
api0("/api/collections.duplicate", POST, "collections_duplicate", reach=["Copy a collection; createCollection."],
     evref=CO)
api0("/api/collections.archive", POST, "collections_archive", reach=["Collection admin."], evref=CO)
api0("/api/collections.restore", POST, "collections_restore", reach=["Collection admin."], evref=CO)
api0("/api/collections.import", POST, "collections_import", reach=["Admin: import an uploaded archive."], evref=CO)


# ===========================================================================
# DOCUMENTS  (api/documents) -- the core content surface
# ===========================================================================
DO = "api/documents/documents.ts"
api("/api/documents.create", POST,
    [variant("POST", [rf("title", "body"), rf("text", "body"), rf("collectionId", "body"),
                      rf("parentDocumentId", "body"), rf("templateId", "body"),
                      rf("publish", "body", "boolean"), rf("template", "body", "boolean")],
             r_data("document"), body_format="json", reason="create a document (optionally publish)", evidence=DO)],
    "documents_create", sin=[d_coll()], vis_reason="Create document.",
    reach=["authorize(user,'createDocument',collection) / 'update' on parent."], evref=DO)

api("/api/documents.info", POST,
    [variant("POST", [rf("id", "body", description="document id, urlId, or share-scoped"),
                      rf("shareId", "body", description="read via a public share"),
                      rf("apiVersion", "body", "number")],
             r_data("document"), body_format="json",
             reason="read a document -- by id (authed) OR by shareId (public)", evidence=DO)],
    "documents_info", sin=[d_doc(), d_share()], vis_reason="Read a document (authed OR via share).",
    reach=["authorize(user,'read',document) via collection/membership; OR an active public share (no auth)."],
    evref=DO, notes="Dual path: the shareId branch is the unauthenticated public-read surface.")

api("/api/documents.list", POST,
    [variant("POST", [rf("collectionId", "body"), rf("userId", "body"), rf("parentDocumentId", "body"),
                      rf("backlinkDocumentId", "body"), rf("template", "body", "boolean"),
                      rf("sort", "body"), rf("limit", "body", "number")],
             r_data("documents"), body_format="json", reason="list documents (filtered by access)", evidence=DO)],
    "documents_list", sin=[d_coll()], vis_reason="List documents.", reach=["Authenticated; access-filtered."],
    evref=DO)

api("/api/documents.search", POST,
    [variant("POST", [rf("query", "body"), rf("collectionId", "body"), rf("userId", "body"),
                      rf("shareId", "body", description="search within a public share tree"),
                      rf("dateFilter", "body"), rf("limit", "body", "number")],
             r_data("documents", "totalCount"), body_format="json",
             reason="full-text search across accessible documents (or a share)", evidence=DO)],
    "documents_search", sin=[d_share()], vis_reason="Search documents.",
    reach=["Authenticated full-text (access-filtered); shareId branch searches a public share."], evref=DO)

api("/api/documents.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("title", "body"), rf("text", "body"),
                      rf("publish", "body", "boolean"), rf("append", "body", "boolean"),
                      rf("done", "body", "boolean")],
             r_data("document"), body_format="json", reason="edit a document's content/metadata", evidence=DO)],
    "documents_update", sin=[d_doc()], vis_reason="Edit document.",
    reach=["authorize(user,'update',document): read_write membership / collection permission."], evref=DO)

api("/api/documents.delete", POST,
    [variant("POST", [rf("id", "body", required=True), rf("permanent", "body", "boolean")],
             r_data("success"), body_format="json", reason="trash (or permanently delete) a document", evidence=DO)],
    "documents_delete", sin=[d_doc()], vis_reason="Delete document.",
    reach=["authorize(user,'delete'/'permanentDelete',document)."], evref=DO)

api("/api/documents.move", POST,
    [variant("POST", [rf("id", "body", required=True), rf("collectionId", "body"),
                      rf("parentDocumentId", "body"), rf("index", "body", "number")],
             r_data("documents", "collections"), body_format="json",
             reason="move a document to another collection/parent", evidence=DO)],
    "documents_move", sin=[d_doc(), d_coll()], vis_reason="Move document.",
    reach=["authorize(user,'move',document) + 'update' on the destination collection."], evref=DO)

api("/api/documents.import", POST,
    [variant("POST", [rf("file", "multipart", description="uploaded .md/.docx/.html"),
                      rf("collectionId", "body"), rf("parentDocumentId", "body"), rf("publish", "body", "boolean")],
             r_data("document"), body_format="none", content_types=["multipart/form-data"],
             reason="import an uploaded file as a document (parser surface)", evidence=DO)],
    "documents_import", sin=[d_coll()], vis_reason="Import file as document.",
    reach=["createDocument on the collection. Untrusted file parsing (docx/html/markdown)."], evref=DO)

api("/api/documents.export", POST,
    [variant("POST", [rf("id", "body", required=True)], c.resp_scalar("markdown", "string",
             "the document rendered as markdown/html"), body_format="json",
             reason="export one document's content", evidence=DO)],
    "documents_export", sin=[d_doc()], vis_reason="Export a document.",
    reach=["authorize(user,'read',document)."], evref=DO)

api("/api/documents.add_user", POST,
    [variant("POST", [rf("id", "body", required=True), rf("userId", "body", required=True),
                      rf("permission", "body", description="read|read_write|admin")],
             r_data("users", "memberships"), body_format="json",
             reason="grant a user direct access to a document", evidence=DO)],
    "documents_add_user", sin=[d_doc(), d_user()], vis_reason="Share a document with a user.",
    reach=["authorize(user,'manageUsers'/'update',document). Direct per-document membership."], evref=DO)

api("/api/documents.add_group", POST,
    [variant("POST", [rf("id", "body", required=True), rf("groupId", "body", required=True),
                      rf("permission", "body")],
             r_data("documentGroupMemberships"), body_format="json",
             reason="grant a group access to a document", evidence=DO)],
    "documents_add_group", sin=[d_doc(), d_group()], vis_reason="Share a document with a group.",
    reach=["authorize(user,'manageUsers'/'update',document)."], evref=DO)

api("/api/documents.users", POST,
    [variant("POST", [rf("id", "body", required=True), rf("query", "body")],
             r_data("users"), body_format="json", reason="list users with access to a document", evidence=DO)],
    "documents_users", sin=[d_doc()], vis_reason="List document users.",
    reach=["authorize(user,'read',document)."], evref=DO)

api("/api/documents.templatize", POST,
    [variant("POST", [rf("id", "body", required=True), rf("collectionId", "body")],
             r_data("document"), body_format="json", reason="turn a document into a template", evidence=DO)],
    "documents_templatize", sin=[d_doc()], vis_reason="Templatize a document.",
    reach=["authorize(user,'update',document)."], evref=DO)

api("/api/documents.unpublish", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("document"), body_format="json",
             reason="unpublish a document back to draft", evidence=DO)],
    "documents_unpublish", sin=[d_doc()], vis_reason="Unpublish document.",
    reach=["authorize(user,'unpublish',document)."], evref=DO)

api("/api/documents.empty_trash", POST,
    [variant("POST", [], r_data("success"), body_format="json",
             reason="permanently delete all trashed documents", evidence=DO)],
    "documents_empty_trash", vis_reason="Empty trash (bulk destructive).",
    reach=["authorize over owned/permitted trashed docs."], evref=DO)

# document read/list long-tail (enumerated; same policy model)
for _n, _op in [("archived", "list_archived"), ("deleted", "list_deleted"), ("drafts", "list_drafts"),
                ("viewed", "list_viewed"), ("search_titles", "search_titles"), ("documents", "list_mine"),
                ("insights", "document_insights")]:
    api0(f"/api/documents.{_n}", POST, f"documents_{_op}",
         reach=["Authenticated; access-filtered."], evref=DO)
for _n, _op in [("archive", "archive"), ("restore", "restore"), ("duplicate", "duplicate"),
                ("remove_user", "remove_user"), ("remove_group", "remove_group"),
                ("memberships", "memberships"), ("group_memberships", "group_memberships")]:
    api0(f"/api/documents.{_n}", POST, f"documents_{_op}",
         reach=["authorize on the document."], evref=DO)


# ===========================================================================
# SHARES  (api/shares) -- public link sharing
# ===========================================================================
SH = "api/shares/shares.ts"
api("/api/shares.create", POST,
    [variant("POST", [rf("documentId", "body", required=True),
                      rf("published", "body", "boolean", description="publish to the whole internet"),
                      rf("includeChildDocuments", "body", "boolean"),
                      rf("urlId", "body", description="custom share slug")],
             r_data("share"), body_format="json",
             reason="create a public share link for a document", evidence=SH)],
    "shares_create", sin=[d_doc()], sout=[d_share()], vis_reason="Create public share (exposure).",
    reach=["authorize(user,'share',document) + collection.sharing. 'published' = unauthenticated internet read."],
    evref=SH, notes="Core public-exposure primitive; 'includeChildDocuments' widens scope to the subtree.")

api("/api/shares.info", POST,
    [variant("POST", [rf("id", "body", description="share id"), rf("documentId", "body")],
             r_data("share", "shares"), body_format="json",
             reason="fetch share metadata -- OPTIONAL auth (public branch)", evidence=SH)],
    "shares_info", sin=[d_share(), d_doc()], vis_reason="Read share info (optional auth).",
    reach=["auth optional: a published share is readable unauthenticated (existence/metadata oracle)."],
    evref=SH, notes="auth({optional:true}): the public-share read surface.")

api("/api/shares.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("published", "body", "boolean"),
                      rf("urlId", "body")],
             r_data("share"), body_format="json", reason="toggle publish / change slug", evidence=SH)],
    "shares_update", sin=[d_share()], vis_reason="Update share.",
    reach=["authorize(user,'update',share). Flipping 'published' widens/narrows exposure."], evref=SH)

api("/api/shares.revoke", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="revoke a share link", evidence=SH)],
    "shares_revoke", sin=[d_share()], vis_reason="Revoke share.",
    reach=["authorize(user,'revoke',share)."], evref=SH)

api("/api/shares.list", POST,
    [variant("POST", [rf("limit", "body", "number")], r_data("shares"), body_format="json",
             reason="list the caller's shares", evidence=SH)],
    "shares_list", vis_reason="List shares.", reach=["Authenticated; own/team shares."], evref=SH)

api0("/api/shares.sitemap", ["GET", "POST"], "shares_sitemap",
     reach=["Public sitemap for a published share domain."], evref=SH)
api0("/api/shares.subscribe", POST, "shares_subscribe", reach=["Subscribe to a shared doc's updates."], evref=SH)
api0("/api/shares.unsubscribe", POST, "shares_unsubscribe", reach=["Unsubscribe."], evref=SH)
api0("/api/shares.confirmSubscription", ["GET", "POST"], "shares_confirm_subscription",
     reach=["Confirm an email subscription via token."], evref=SH)


# ===========================================================================
# COMMENTS  (api/comments)
# ===========================================================================
CM = "api/comments/comments.ts"
api("/api/comments.create", POST,
    [variant("POST", [rf("documentId", "body", required=True), rf("data", "body", required=True),
                      rf("parentCommentId", "body")],
             r_data("comment"), body_format="json", reason="comment on a document", evidence=CM)],
    "comments_create", sin=[d_doc()], vis_reason="Create comment.",
    reach=["authorize(user,'comment',document)."], evref=CM)

api("/api/comments.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("data", "body", required=True)],
             r_data("comment"), body_format="json", reason="edit a comment", evidence=CM)],
    "comments_update", sin=[d_id("CommentID(comment)", "Comment edited.")],
    vis_reason="Edit comment.", reach=["authorize(user,'update',comment): author / doc admin."], evref=CM)

api("/api/comments.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete a comment", evidence=CM)],
    "comments_delete", sin=[d_id("CommentID(comment)", "Comment deleted.")],
    vis_reason="Delete comment.", reach=["authorize(user,'delete',comment)."], evref=CM)

api("/api/comments.info", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("comment"), body_format="json",
             reason="read a comment", evidence=CM)],
    "comments_info", sin=[d_id("CommentID(comment)", "Comment read.")],
    vis_reason="Read comment.", reach=["authorize(user,'read',comment)."], evref=CM)

api("/api/comments.list", POST,
    [variant("POST", [rf("documentId", "body"), rf("collectionId", "body"), rf("parentCommentId", "body")],
             r_data("comments"), body_format="json", reason="list comments on a document", evidence=CM)],
    "comments_list", sin=[d_doc()], vis_reason="List comments.", reach=["authorize read on the document."], evref=CM)

api0("/api/comments.resolve", POST, "comments_resolve", reach=["Resolve a comment thread."], evref=CM)
api0("/api/comments.unresolve", POST, "comments_unresolve", reach=["Unresolve."], evref=CM)
api0("/api/comments.add_reaction", POST, "comments_add_reaction", reach=["React to a comment."], evref=CM)
api0("/api/comments.remove_reaction", POST, "comments_remove_reaction", reach=["Remove a reaction."], evref=CM)


# ===========================================================================
# GROUPS + MEMBERSHIPS
# ===========================================================================
GR = "api/groups/groups.ts"
api("/api/groups.create", POST,
    [variant("POST", [rf("name", "body", required=True)], r_data("group"), body_format="json",
             reason="create a group", evidence=GR)],
    "groups_create", vis_reason="Create group.", reach=["authorize(user,'createGroup',team): ADMIN."], evref=GR)

api("/api/groups.add_user", POST,
    [variant("POST", [rf("id", "body", required=True), rf("userId", "body", required=True)],
             r_data("groups", "groupMemberships", "users"), body_format="json",
             reason="add a user to a group (inherits group's collection access)", evidence=GR)],
    "groups_add_user", sin=[d_group(), d_user()], vis_reason="Add user to group (indirect access grant).",
    reach=["authorize(user,'update',group): ADMIN. Group membership inherits all the group's grants."], evref=GR)

api("/api/groups.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("name", "body")],
             r_data("group"), body_format="json", reason="rename a group", evidence=GR)],
    "groups_update", sin=[d_group()], vis_reason="Update group.", reach=["ADMIN."], evref=GR)

api("/api/groups.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete a group", evidence=GR)],
    "groups_delete", sin=[d_group()], vis_reason="Delete group.", reach=["ADMIN."], evref=GR)

api0("/api/groups.info", POST, "groups_info", reach=["Read a group."], evref=GR)
api0("/api/groups.list", POST, "groups_list", reach=["List groups."], evref=GR)
api0("/api/groups.remove_user", POST, "groups_remove_user", reach=["ADMIN removes a member."], evref=GR)
api0("/api/groups.update_user", POST, "groups_update_user", reach=["ADMIN."], evref=GR)
api0("/api/groups.memberships", POST, "groups_memberships", reach=["Read group memberships."], evref=GR)
api0("/api/groups.deleteAll", POST, "groups_delete_all", reach=["ADMIN bulk delete."], evref=GR)
api0("/api/groupMemberships.list", POST, "group_memberships_list", reach=["List memberships."],
     evref="api/groupMemberships/groupMemberships.ts")
api0("/api/userMemberships.list", POST, "user_memberships_list", reach=["Own doc memberships."],
     evref="api/userMemberships/userMemberships.ts")
api0("/api/userMemberships.update", POST, "user_memberships_update", reach=["Reorder own memberships."],
     evref="api/userMemberships/userMemberships.ts")


# ===========================================================================
# ATTACHMENTS + FILE OPERATIONS + IMPORTS  (upload + SSRF)
# ===========================================================================
AT = "api/attachments/attachments.ts"
api("/api/attachments.create", POST,
    [variant("POST", [rf("name", "body", required=True), rf("contentType", "body", required=True),
                      rf("size", "body", "number", required=True), rf("documentId", "body"),
                      rf("preset", "body", description="avatar|documentAttachment|import|workspaceImport")],
             r_data("uploadUrl", "form", "attachment"), body_format="json",
             reason="pre-sign an upload (returns an S3/local PUT URL + form fields)", evidence=AT)],
    "attachments_create", sin=[d_doc()], vis_reason="Create (pre-sign) an upload.",
    reach=["Authenticated; preset governs ACL/size. uploadUrl is the storage write grant."], evref=AT)

api("/api/attachments.createFromUrl", POST,
    [variant("POST", [rf("url", "body", required=True, description="remote URL the SERVER fetches"),
                      rf("documentId", "body"), rf("preset", "body")],
             r_data("attachment", "url"), body_format="json",
             reason="server-side fetch of an attacker-supplied URL -> stored (SSRF)", evidence=AT)],
    "attachments_create_from_url",
    sin=[dec("url", "RemoteURL(fetch)", "attribute", reason="Server-fetched remote URL (SSRF sink).")],
    vis_reason="Server fetches a remote URL (SSRF).",
    reach=["Authenticated. Classic SSRF: server GETs 'url' (cloud metadata / internal services)."],
    evref=AT, notes="SSRF sink #1.")

api("/api/attachments.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete an attachment", evidence=AT)],
    "attachments_delete", sin=[d_id("AttachmentID(attachment)", "Attachment deleted.")],
    vis_reason="Delete attachment.", reach=["authorize(user,'delete',attachment)."], evref=AT)

api0("/api/attachments.list", POST, "attachments_list", reach=["List a document's attachments."], evref=AT)

FO = "api/fileOperations/fileOperations.ts"
api("/api/fileOperations.info", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("fileOperation"), body_format="json",
             reason="poll an export/import job + get its download URL", evidence=FO)],
    "fileops_info", sin=[d_id("FileOperationID(fileOperation)", "Export/import job.")],
    vis_reason="Read a file operation.",
    reach=["authorize(user,'read',fileOperation): owner/admin. Download URL is the export payload."], evref=FO)

api("/api/fileOperations.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete an export/import job + its stored file", evidence=FO)],
    "fileops_delete", sin=[d_id("FileOperationID(fileOperation)", "Job deleted.")],
    vis_reason="Delete file operation.", reach=["Owner / admin."], evref=FO)

api0("/api/fileOperations.list", POST, "fileops_list", reach=["List export/import jobs."], evref=FO)

IM = "api/imports/imports.ts"
api("/api/imports.create", POST,
    [variant("POST", [rf("integrationId", "body"), rf("type", "body", required=True,
             description="notion|confluence|..."), rf("input", "body", description="source refs/urls")],
             r_data("import"), body_format="json",
             reason="start an external import (server pulls from a 3rd-party source)", evidence=IM)],
    "imports_create", vis_reason="Start an external import.",
    reach=["authorize(user,'createImport',team): ADMIN. Server-side fetch from an external provider (SSRF-adjacent)."],
    evref=IM, notes="SSRF sink #2 (provider import).")

api0("/api/imports.info", POST, "imports_info", reach=["Read an import job."], evref=IM)
api0("/api/imports.list", POST, "imports_list", reach=["List imports."], evref=IM)
api0("/api/imports.cancel", POST, "imports_cancel", reach=["Cancel an import."], evref=IM)
api0("/api/imports.delete", POST, "imports_delete", reach=["Delete an import."], evref=IM)


# ===========================================================================
# URLS (unfurl / embed -- SSRF)
# ===========================================================================
UR = "api/urls/urls.ts"
api("/api/urls.unfurl", POST,
    [variant("POST", [rf("url", "body", description="URL to unfurl (server fetches)"),
                      rf("documentId", "body")],
             r_data("type", "title", "description", "thumbnailUrl"), body_format="json",
             reason="server fetches a URL to build a link preview -- OPTIONAL auth (SSRF)", evidence=UR)],
    "urls_unfurl", sin=[dec("url", "RemoteURL(fetch)", "attribute", reason="Server-fetched preview URL (SSRF sink).")],
    vis_reason="Server-side URL preview (SSRF).",
    reach=["auth optional. Server GETs 'url' with workspace credentials -> SSRF + credentialed fetch."],
    evref=UR, notes="SSRF sink #3; comment in source: 'External resources are unfurled with workspace credentials'.")

api("/api/urls.checkEmbed", POST,
    [variant("POST", [rf("url", "body", required=True)], r_data("embed"), body_format="json",
             reason="check whether a URL matches an embed integration", evidence=UR)],
    "urls_check_embed", sin=[dec("url", "RemoteURL(fetch)", "attribute", reason="URL tested against embed matchers.")],
    vis_reason="Embed matcher check.", reach=["Authenticated."], evref=UR)

api0("/api/urls.validateCustomDomain", POST, "urls_validate_custom_domain",
     reach=["Admin: validate a custom share domain (DNS/cert surface)."], evref=UR)


# ===========================================================================
# TEAMS + AUTH PROVIDERS + INTEGRATIONS
# ===========================================================================
TE = "api/teams/teams.ts"
api("/api/team.update", POST,
    [variant("POST", [rf("name", "body"), rf("subdomain", "body"), rf("sharing", "body", "boolean"),
                      rf("defaultUserRole", "body", description="member|viewer"),
                      rf("guestSignin", "body", "boolean"), rf("documentEmbeds", "body", "boolean"),
                      rf("memberCollectionCreate", "body", "boolean"),
                      rf("inviteRequired", "body", "boolean"), rf("allowedDomains", "body")],
             r_data("team"), body_format="json", reason="update workspace settings (security-relevant toggles)",
             evidence=TE)],
    "team_update", vis_reason="Update workspace settings (ADMIN).",
    reach=["authorize(user,'update',team): ADMIN. defaultUserRole/sharing/guestSignin/allowedDomains are "
           "the exposure toggles."], evref=TE, notes="Also exposed as teams.update (alias).")

api("/api/teams.create", POST,
    [variant("POST", [rf("name", "body", required=True)], r_data("team", "user"), body_format="json",
             reason="create an additional workspace (multi-team installs)", evidence=TE)],
    "teams_create", vis_reason="Create a workspace.",
    reach=["Gated by installation config (canCreateTeam)."], evref=TE)

api("/api/teams.delete", POST,
    [variant("POST", [rf("id", "body"), rf("code", "body", description="confirmation code")],
             r_data("success"), body_format="json", reason="delete a workspace", evidence=TE)],
    "teams_delete", sin=[d_team()], vis_reason="Delete workspace (destructive).",
    reach=["authorize(user,'delete',team): ADMIN + emailed confirmation code."], evref=TE)

api0("/api/teams.update", POST, "teams_update_alias", reach=["Alias of team.update (ADMIN)."], evref=TE)
api0("/api/teams.requestDelete", POST, "teams_request_delete", reach=["ADMIN: emails a delete code."], evref=TE)

AP = "api/authenticationProviders/authenticationProviders.ts"
api("/api/authenticationProviders.update", POST,
    [variant("POST", [rf("id", "body", required=True), rf("isEnabled", "body", "boolean", required=True),
                      rf("settings", "body", description="group-sync settings")],
             r_data("authenticationProvider"), body_format="json",
             reason="enable/disable an SSO provider for the workspace", evidence=AP)],
    "authproviders_update", vis_reason="Toggle an SSO provider (ADMIN).",
    reach=["authorize(user,'update',team): ADMIN. Disabling the only provider can lock the workspace out."],
    evref=AP)

api0("/api/authenticationProviders.list", POST, "authproviders_list", reach=["ADMIN lists providers."], evref=AP)
api0("/api/authenticationProviders.info", POST, "authproviders_info", reach=["ADMIN reads a provider."], evref=AP)
api0("/api/authenticationProviders.delete", POST, "authproviders_delete", reach=["ADMIN removes a provider."],
     evref=AP)
api0("/api/authenticationProviders.startGroupSync", POST, "authproviders_group_sync",
     reach=["ADMIN triggers IdP group sync."], evref=AP)

IN = "api/integrations/integrations.ts"
api("/api/integrations.create", POST,
    [variant("POST", [rf("type", "body", required=True, description="webhook|embed|post|command|..."),
                      rf("service", "body"), rf("settings", "body", description="incl. webhook url"),
                      rf("events", "body")],
             r_data("integration"), body_format="json",
             reason="create an integration (e.g. an outbound webhook subscription)", evidence=IN)],
    "integrations_create", vis_reason="Create integration/webhook.",
    reach=["authorize(user,'createIntegration',team): ADMIN. Outbound webhook URL = data-exfil / SSRF-ish sink."],
    evref=IN, notes="Webhook subscriptions deliver event payloads to an admin-chosen URL.")

api("/api/integrations.delete", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("success"), body_format="json",
             reason="delete an integration", evidence=IN)],
    "integrations_delete", sin=[d_id("IntegrationID(integration)", "Integration deleted.")],
    vis_reason="Delete integration.", reach=["ADMIN."], evref=IN)

api0("/api/integrations.list", POST, "integrations_list", reach=["List integrations."], evref=IN)
api0("/api/integrations.info", POST, "integrations_info", reach=["Read an integration."], evref=IN)
api0("/api/integrations.update", POST, "integrations_update", reach=["ADMIN updates an integration."], evref=IN)


# ===========================================================================
# REVISIONS / PINS / STARS / SUBSCRIPTIONS / NOTIFICATIONS / VIEWS / misc
# ===========================================================================
RV = "api/revisions/revisions.ts"
api("/api/revisions.list", POST,
    [variant("POST", [rf("documentId", "body", required=True), rf("limit", "body", "number")],
             r_data("revisions"), body_format="json", reason="document edit history", evidence=RV)],
    "revisions_list", sin=[d_doc()], vis_reason="List revisions.", reach=["authorize read on the document."],
    evref=RV)
api("/api/revisions.info", POST,
    [variant("POST", [rf("id", "body", required=True)], r_data("revision"), body_format="json",
             reason="read a specific revision", evidence=RV)],
    "revisions_info", sin=[d_id("RevisionID(revision)", "Revision read.")],
    vis_reason="Read revision.", reach=["authorize read on the parent document."], evref=RV)
api0("/api/revisions.update", POST, "revisions_update", reach=["Rename a revision."], evref=RV)
api0("/api/revisions.delete", POST, "revisions_delete", reach=["Delete a revision (doc admin)."], evref=RV)
api0("/api/revisions.export", POST, "revisions_export", reach=["Export a revision."], evref=RV)

PI = "api/pins/pins.ts"
api("/api/pins.create", POST,
    [variant("POST", [rf("documentId", "body", required=True), rf("collectionId", "body")],
             r_data("pin"), body_format="json", reason="pin a document to a collection/home", evidence=PI)],
    "pins_create", sin=[d_doc()], vis_reason="Pin a document.",
    reach=["authorize(user,'update',collection) or team for home pins."], evref=PI)
api0("/api/pins.info", POST, "pins_info", reach=["Read a pin."], evref=PI)
api0("/api/pins.list", POST, "pins_list", reach=["List pins."], evref=PI)
api0("/api/pins.update", POST, "pins_update", reach=["Reorder pins."], evref=PI)
api0("/api/pins.delete", POST, "pins_delete", reach=["Remove a pin."], evref=PI)

ST = "api/stars/stars.ts"
api("/api/stars.create", POST,
    [variant("POST", [rf("documentId", "body"), rf("collectionId", "body")],
             r_data("star"), body_format="json", reason="star a document/collection (personal)", evidence=ST)],
    "stars_create", sin=[d_doc()], vis_reason="Star a document.", reach=["Authenticated; personal."], evref=ST)
api0("/api/stars.list", POST, "stars_list", reach=["List own stars."], evref=ST)
api0("/api/stars.update", POST, "stars_update", reach=["Reorder stars."], evref=ST)
api0("/api/stars.delete", POST, "stars_delete", reach=["Unstar."], evref=ST)

SU = "api/subscriptions/subscriptions.ts"
api("/api/subscriptions.create", POST,
    [variant("POST", [rf("documentId", "body"), rf("collectionId", "body"),
                      rf("event", "body", description="documents.update")],
             r_data("subscription"), body_format="json", reason="subscribe to document/collection changes",
             evidence=SU)],
    "subscriptions_create", sin=[d_doc()], vis_reason="Subscribe to updates.",
    reach=["authorize read on the target."], evref=SU)
api0("/api/subscriptions.info", POST, "subscriptions_info", reach=["Read a subscription."], evref=SU)
api0("/api/subscriptions.list", POST, "subscriptions_list", reach=["List subscriptions."], evref=SU)
api0("/api/subscriptions.delete", POST, "subscriptions_delete", reach=["Unsubscribe."], evref=SU)

NO = "api/notifications/notifications.ts"
api0("/api/notifications.list", POST, "notifications_list", reach=["Own notifications."], evref=NO)
api0("/api/notifications.update", POST, "notifications_update", reach=["Mark read/archived."], evref=NO)
api0("/api/notifications.update_all", POST, "notifications_update_all", reach=["Mark all read."], evref=NO)
api0("/api/notifications.unsubscribe", ["GET", "POST"], "notifications_unsubscribe",
     reach=["Unsubscribe via emailed token (optional auth)."], evref=NO)
api("/api/notifications.pixel", ["GET"],
    [variant("GET", [rf("token", "query"), rf("id", "query")], c.resp_binary("pixel", "1x1 tracking gif"),
             reason="email open-tracking pixel", evidence=NO)],
    "notifications_pixel", vis_reason="Email tracking pixel (public).",
    reach=["PUBLIC image endpoint keyed by token; open-tracking + token-in-URL."], evref=NO)

VI = "api/views/views.ts"
api0("/api/views.create", POST, "views_create", reach=["Record a document view."], evref=VI)
api0("/api/views.list", POST, "views_list", reach=["List viewers of a document."], evref=VI)

# emojis / reactions / templates / searches / suggestions / events / relationships / accessRequests
EM = "api/emojis/emojis.ts"
api0("/api/emojis.create", POST, "emojis_create", reach=["Custom emoji (upload)."], evref=EM)
api0("/api/emojis.list", POST, "emojis_list", reach=["List custom emoji."], evref=EM)
api0("/api/emojis.info", POST, "emojis_info", reach=["Read a custom emoji."], evref=EM)
api0("/api/emojis.update", POST, "emojis_update", reach=["Rename custom emoji."], evref=EM)
api0("/api/emojis.delete", POST, "emojis_delete", reach=["Delete custom emoji."], evref=EM)
api0("/api/emojis.redirect", ["GET"], "emojis_redirect", reach=["Redirect to emoji image bytes."], evref=EM)

api0("/api/reactions.list", POST, "reactions_list", reach=["List reactions."], evref="api/reactions/reactions.ts")

TM = "api/templates/templates.ts"
api("/api/templates.create", POST,
    [variant("POST", [rf("title", "body"), rf("text", "body"), rf("collectionId", "body"),
                      rf("data", "body")],
             r_data("template"), body_format="json", reason="create a reusable template", evidence=TM)],
    "templates_create", vis_reason="Create template.", reach=["createDocument/template permission."], evref=TM)
api0("/api/templates.info", POST, "templates_info", reach=["Read a template."], evref=TM)
api0("/api/templates.list", POST, "templates_list", reach=["List templates."], evref=TM)
api0("/api/templates.update", POST, "templates_update", reach=["Edit a template."], evref=TM)
api0("/api/templates.delete", POST, "templates_delete", reach=["Delete a template."], evref=TM)
api0("/api/templates.duplicate", POST, "templates_duplicate", reach=["Copy a template."], evref=TM)
api0("/api/templates.restore", POST, "templates_restore", reach=["Restore a template version."], evref=TM)

api0("/api/searches.list", POST, "searches_list", reach=["Own search history."], evref="api/searches/searches.ts")
api0("/api/searches.update", POST, "searches_update", reach=["Edit a saved search."], evref="api/searches/searches.ts")
api0("/api/searches.delete", POST, "searches_delete", reach=["Delete search history."],
     evref="api/searches/searches.ts")
api0("/api/suggestions.mention", POST, "suggestions_mention",
     reach=["Autocomplete users/documents for @mentions (directory oracle)."],
     evref="api/suggestions/suggestions.ts")
api0("/api/events.list", POST, "events_list",
     reach=["Audit log / activity stream; admin for team-wide events."], evref="api/events/events.ts")
api0("/api/relationships.list", POST, "relationships_list", reach=["Document backlinks."],
     evref="api/relationships/relationships.ts")
api0("/api/relationships.info", POST, "relationships_info", reach=["Read a relationship."],
     evref="api/relationships/relationships.ts")

AR = "api/accessRequests/accessRequests.ts"
api("/api/accessRequests.create", POST,
    [variant("POST", [rf("documentId", "body"), rf("collectionId", "body")],
             r_data("accessRequest"), body_format="json",
             reason="request access to a document/collection you can't see", evidence=AR)],
    "access_requests_create", sin=[d_doc()], vis_reason="Request access.",
    reach=["Authenticated member; notifies the resource managers."], evref=AR)
api0("/api/accessRequests.info", POST, "access_requests_info", reach=["Read a request."], evref=AR)
api0("/api/accessRequests.approve", POST, "access_requests_approve", reach=["Manager approves (grants access)."],
     evref=AR)
api0("/api/accessRequests.dismiss", POST, "access_requests_dismiss", reach=["Manager dismisses."], evref=AR)

# batch / cron / developer (internal / dev-only)
api0("/api/batch", POST, "batch",
     reach=["Batched multi-request envelope; each sub-request re-authorized."], evref="api/batch/batch.ts")
api0("/api/cron", ["GET", "POST"], "cron",
     reach=["Internal scheduler trigger; gated by a cron secret (token)."], evref="api/cron/cron.ts")
api0("/api/developer.create_test_users", POST, "developer_create_test_users",
     reach=["DEV-ONLY (isDevelopment). Seeds test users."], evref="api/developer/developer.ts")
api0("/api/developer.create_test_notifications", POST, "developer_create_test_notifications",
     reach=["DEV-ONLY."], evref="api/developer/developer.ts")


# ===========================================================================
_finalize()


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded against outlinewiki/outline:1.12.0 (official image,
# Postgres+Redis+Mailpit, http://localhost:3001). Identity labels: anonymous (no token) |
# admin (first user = team admin, magic-link session) | apikey (personal API key).
# Populated from runtime/probe_results/ (runtime/probe.ps1). 25 nodes confirmed.
# Findings: denial = HTTP 401 for missing/invalid auth; auth.config is the only pre-auth
# /api read; a published share serves documents.info?shareId + shares.info UNAUTH while the
# same document by id stays 401; an API key is accepted via header | body | ?token= (URL).
# ===========================================================================
_RUNTIME = {
    # public / pre-auth
    "/api/auth.config":        {"s": [200], "id": {"anonymous": [200]}},
    "/auth/email":             {"s": [200], "id": {"anonymous": [200]}},
    "/auth/:provider.callback": {"s": [200], "id": {"anonymous": [200]}},  # via /auth/email.callback two-step
    # authenticated reads: anon 401, admin 200 (denial convention = 401 for missing auth)
    "/api/auth.info":          {"s": [200, 401], "id": {"anonymous": [401], "admin": [200], "apikey": [200]}},
    "/api/installation.info":  {"s": [200, 401], "id": {"anonymous": [401]}},
    "/api/users.list":         {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/collections.list":   {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/documents.list":     {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/shares.list":        {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/apiKeys.list":       {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/integrations.list":  {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/api/groups.list":        {"s": [200], "id": {"admin": [200]}},
    "/api/oauthClients.list":  {"s": [200], "id": {"admin": [200]}},
    "/api/events.list":        {"s": [200], "id": {"admin": [200]}},
    # admin writes (confirmed 200 as team admin)
    "/api/collections.create": {"s": [200], "id": {"admin": [200]}},
    "/api/documents.create":   {"s": [200], "id": {"admin": [200]}},
    "/api/shares.create":      {"s": [200], "id": {"admin": [200]}},
    "/api/apiKeys.create":     {"s": [200], "id": {"admin": [200]}},
    # published-share exposure: anon 200 via shareId, 401 by id (end-to-end confirmed)
    "/api/documents.info":     {"s": [200, 401], "id": {"anonymous": [200, 401], "admin": [200]}},
    "/api/shares.info":        {"s": [200], "id": {"anonymous": [200], "admin": [200]}},
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
# PAGE / CLIENT nodes  (public share pages + SPA)
# ===========================================================================
PAGE_NODES = []


def page(key, methods, op="", kind="page", reach=None, evref="", notes=None):
    PAGE_NODES.append(c.node(K(key), kind, methods, variants=[], operation_semantic=op, params=[],
                             visibility="black_box", reachable=True, reach_conds=reach or [],
                             evidence=[c.ev("source", evref, "client")] if evref else [], notes=notes))


page("/share/:shareId", ["GET"], "public_share_page", kind="page",
     reach=["PUBLIC page for a published share; renders the shared document tree without auth."],
     evref="server/routes/index.ts /share/:shareId",
     notes="Unauthenticated read surface; also /share/:shareId/doc/:documentSlug and /s/:shareId.")
page("/", ["GET"], "app_spa", kind="page",
     reach=["SPA shell / marketing; redirects to the team subdomain or login."],
     evref="server/routes/app.ts renderApp")


EDGES = [
    {"src": K("/"), "dst": K("/api/auth.config"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/"), "dst": K("/api/auth.info"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/"), "dst": K("/api/documents.list"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/share/:shareId"), "dst": K("/api/documents.info"), "methods": ["POST"], "triggers": ["xhr"]},
]
