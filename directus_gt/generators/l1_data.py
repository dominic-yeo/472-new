# -*- coding: utf-8 -*-
"""Directus L1 attack surface as data.

Authoritative source (this repo, directus/ api @ 41.0.1):
  - Mounts:      api/src/app.ts  (app.use('/items', ...), '/users', '/auth', ... at ROOT)
  - Controllers: api/src/controllers/*.ts  (one express Router per resource)
  - Auth:        api/src/middleware/{extract-token,authenticate}.ts
  - AuthZ:       accountability -> role -> policies -> permissions; admin_access BYPASSES checks.

ORIGIN = http://localhost:8055 (Directus default).

Auth model: a token (Authorization: Bearer | ?access_token= query | session cookie) resolves to an
accountability. Permissions are policy-based (roles hold policies; policies hold permissions + flags:
admin_access, app_access, enforce_tfa, ip_access). No token => the public role. Share tokens
(POST /shares/auth) grant item-scoped accountability. Nodes with io_variants are L2 candidates;
statuses left for runtime (runtime/ has an official-image compose + probe).
"""
import common as c
from common import key as K, rf, of, variant, resp_json, resp_empty, dec


def evs(ref, supports="route + controller"):
    return c.ev("source", "directus/api/src/controllers/" + ref, supports)


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
    """Merge-by-path registry: multiple methods on one path dispatch to one L1 node."""
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


def d_collection():
    return dec("collection", "CollectionName(collection)", "identifier", reference_capable=True,
               reason="Target collection name.")


def d_pk():
    return dec("pk", "ItemID(item)", "identifier", reference_capable=True, reason="Item primary key.")


def d_email():
    return dec("email", "UserEmail(user)", "identifier", reference_capable=True, reason="User email.")


def d_password():
    return dec("password", "Password(user)", "credential", reason="Account password.")


def d_token():
    return dec("access_token", "AccessToken(session)", "credential", reason="Session access token.")


# ===========================================================================
# AUTH  (controllers/auth.ts -> /auth)
# ===========================================================================
AUTH = "auth.ts"

api("/auth/login", ["POST"],
    [variant("POST", [rf("email", "body", required=True), rf("password", "body", required=True),
                      rf("otp", "body", description="2FA code if enabled"),
                      rf("mode", "body", description="json|cookie|session")],
             resp_json([of("access_token", description="access JWT"),
                        of("refresh_token", description="refresh token"), of("expires")]),
             body_format="json", reason="local login; returns access+refresh tokens",
             evidence="auth.ts createLocalAuthRouter")],
    "user_login",
    sin=[d_email(), d_password()],
    sout=[d_token(), dec("refresh_token", "RefreshToken(session)", "credential",
                         reason="Refresh token (long-lived).")],
    vis_reason="Public login.",
    reach=["Public. Brute-force / credential-stuffing (default-auth rate limiting applies). 2FA via 'otp'."],
    evref=AUTH, notes="Default local provider at /auth/login; SSO providers at /auth/login/:provider.")

api("/auth/refresh", ["POST"],
    [variant("POST", [rf("refresh_token", "body", description="refresh token (or cookie)"),
                      rf("mode", "body")],
             resp_json([of("access_token"), of("refresh_token"), of("expires")]), body_format="json",
             reason="exchange a refresh token for a new access token", evidence="auth.ts /refresh")],
    "refresh_token",
    sout=[d_token()],
    vis_reason="Token refresh.",
    reach=["Public; consumes a refresh token (replay / rotation surface)."],
    evref=AUTH)

api("/auth/password/request", ["POST"],
    [variant("POST", [rf("email", "body", required=True),
                      rf("reset_url", "body", description="reset link base (allowlisted)")],
             resp_empty(), body_format="json", reason="request a password-reset email",
             evidence="auth.ts /password/request")],
    "password_request",
    sin=[d_email()],
    vis_reason="Password reset request.",
    reach=["Public. Email-enumeration oracle; 'reset_url' is validated against PASSWORD_RESET_URL_ALLOW_LIST."],
    evref=AUTH, notes="reset_url open-redirect/token-leak surface if allow-list is mis-set.")

api("/auth/password/reset", ["POST"],
    [variant("POST", [rf("token", "body", required=True, description="reset JWT"),
                      rf("password", "body", required=True)],
             resp_empty(), body_format="json", reason="complete a password reset",
             evidence="auth.ts /password/reset")],
    "password_reset",
    sin=[dec("token", "ResetToken(user)", "credential", reason="Password-reset token."), d_password()],
    vis_reason="Password reset.",
    reach=["Public IF a valid reset token is held -> account takeover."],
    evref=AUTH)

api("/auth/logout", ["POST"],
    [variant("POST", [rf("refresh_token", "body"), rf("mode", "body")], resp_empty(), body_format="json",
             reason="invalidate the refresh token/session", evidence="auth.ts /logout")],
    "logout", vis_reason="Logout.", reach=["Holder of a refresh token/session."], evref=AUTH)

api("/auth", ["GET"],
    [variant("GET", [], resp_json([of("data", description="configured auth providers")]),
             reason="list configured SSO providers + default-disabled flag", evidence="auth.ts GET /")],
    "list_auth_providers",
    vis_reason="Auth provider list.",
    reach=["Public. Fingerprints configured identity providers."], evref=AUTH)

api0("/auth/login/:provider", ["POST", "GET"], "sso_login",
     reach=["Public SSO (oauth2/openid/ldap/saml) login + callback; provider-dependent."], evref=AUTH,
     notes="Per-provider router: /login, /callback. Open-redirect + account-linking surface.")


# ===========================================================================
# SERVER  (controllers/server.ts -> /server)
# ===========================================================================
SRV = "server.ts"

api("/server/setup", ["POST"],
    [variant("POST", [rf("admin", "body", required=True, description="{email,password,...}"),
                      rf("license_key", "body")],
             resp_empty(), body_format="json",
             reason="create the FIRST admin if setup is not completed (bootstrap)",
             evidence="server.ts /setup")],
    "server_setup",
    sin=[d_email(), d_password()],
    vis_reason="Bootstrap admin creation.",
    reach=["Public but only succeeds while setup is NOT completed (no admin) -> first-boot takeover window."],
    evref=SRV, notes="Directus bootstrap: seizes an admin on an un-provisioned instance.")

api("/server/specs/oas", ["GET"],
    [variant("GET", [], resp_json([of("data", description="OpenAPI 3 spec of the live API+schema")]),
             reason="generate the OpenAPI spec for this instance", evidence="server.ts /specs/oas")],
    "server_specs_oas",
    vis_reason="OpenAPI disclosure.",
    reach=["Accountability-scoped (OPENAPI_ENABLED); reveals collections/fields the caller can see (recon)."],
    evref=SRV)

api("/server/info", ["GET"],
    [variant("GET", [], resp_json([of("data", description="project + server info")]),
             reason="server/project info", evidence="server.ts /info")],
    "server_info",
    vis_reason="Server info.",
    reach=["Public (limited fields) / authenticated (more). Version + config fingerprinting."], evref=SRV)

for _p, _m, _o in [("/server/health", ["GET"], "server_health"),
                   ("/server/specs/graphql/:scope", ["GET"], "server_specs_graphql"),
                   ("/server/ping", ["GET"], "server_ping")]:
    api0(_p, _m, _o, reach=["Public / authenticated (feature-flagged)."], evref=SRV)


# ===========================================================================
# ITEMS -- the dynamic per-collection CRUD core  (controllers/items.ts -> /items)
# ===========================================================================
IT = "items.ts"

api("/items/:collection", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("GET", [rf("collection", "path", required=True), rf("filter", "query"),
                     rf("fields", "query", description="field selection incl relation traversal"),
                     rf("deep", "query"), rf("sort", "query"), rf("limit", "query")],
             resp_json([of("data", description="items"), of("meta")]),
             reason="read a collection (permission-filtered)", evidence="items.ts readHandler"),
     variant("POST", [rf("collection", "path", required=True), rf("data", "body", description="item fields")],
             resp_json([of("data")]), body_format="json",
             reason="create item(s) (create permission)", evidence="items.ts POST"),
     variant("PATCH", [rf("collection", "path", required=True),
                       rf("keys", "body", description="bulk keys"), rf("data", "body")],
             resp_json([of("data")]), body_format="json",
             reason="update item(s) by keys/query (update permission)", evidence="items.ts PATCH"),
     variant("DELETE", [rf("collection", "path", required=True), rf("keys", "body")],
             resp_empty(), body_format="json", reason="delete item(s) (delete permission)",
             evidence="items.ts DELETE")],
    "item_collection",
    sin=[d_collection()],
    sout=[dec("data", "ItemID(item)", "identifier", reference_capable=True, reason="Items.")],
    vis_reason="Dynamic collection CRUD.",
    reach=["Caller's policy permission for <collection>.{create,read,update,delete}. Public role if no token. "
           "'fields'/'deep' traverse relations and can over-expose related data; filters are a powerful "
           "query surface. System collections (directus_*) are 403 here (use the dedicated controllers)."],
    evref=IT,
    notes="Primary data surface. Permission-filtered per policy; over-permissive Public read + deep field "
          "traversal = data exposure; batch update/delete by query are high-blast-radius.")

api("/items/:collection/:pk", ["GET", "PATCH", "DELETE"],
    [variant("GET", [rf("collection", "path", required=True), rf("pk", "path", required=True),
                     rf("fields", "query")],
             resp_json([of("data")]), reason="read one item (read permission)", evidence="items.ts GET /:pk"),
     variant("PATCH", [rf("collection", "path", required=True), rf("pk", "path", required=True),
                       rf("data", "body")],
             resp_json([of("data")]), body_format="json", reason="update one item (update permission)",
             evidence="items.ts PATCH /:pk"),
     variant("DELETE", [rf("collection", "path", required=True), rf("pk", "path", required=True)],
             resp_empty(), reason="delete one item (delete permission)", evidence="items.ts DELETE /:pk")],
    "item_one",
    sin=[d_collection(), d_pk()],
    vis_reason="Per-item CRUD.",
    reach=["Policy permission for the collection+action. Item-level access is enforced by permission filters; "
           "a permission without a row filter exposes every item by pk (IDOR surface to validate per policy)."],
    evref=IT, notes="Row-level authorization depends on each permission's filter -- a missing filter = IDOR.")


# ===========================================================================
# USERS  (controllers/users.ts -> /users)
# ===========================================================================
US = "users.ts"

api("/users", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("GET", [rf("fields", "query"), rf("filter", "query")],
             resp_json([of("data", description="user records"), of("meta")]),
             reason="list users (directus_users read permission)", evidence="users.ts readHandler"),
     variant("POST", [rf("email", "body"), rf("password", "body"),
                      rf("role", "body", description="assigned role id")],
             resp_json([of("data")]), body_format="json",
             reason="create user(s) (create permission on directus_users)", evidence="users.ts POST"),
     variant("PATCH", [rf("keys", "body"), rf("data", "body", description="fields incl role/password")],
             resp_json([of("data")]), body_format="json", reason="bulk-update users", evidence="users.ts PATCH"),
     variant("DELETE", [rf("keys", "body")], resp_empty(), body_format="json", reason="bulk-delete users",
             evidence="users.ts DELETE")],
    "users",
    sin=[d_email(), dec("role", "RoleID(role)", "identifier", reference_capable=True, reason="Assigned role.")],
    sout=[dec("data", "UserID(user)", "identifier", reference_capable=True, reason="User records.")],
    vis_reason="User directory + management.",
    reach=["Policy permission for directus_users.{read,create,update,delete}. 'role' in create/update assigns "
           "privileges -> escalation if an admin-access role is set. PII exposure if read is over-granted."],
    evref=US, notes="Role assignment here is the escalation primitive; password can be set on update.")

api("/users/:pk", ["GET", "PATCH", "DELETE"],
    [variant("GET", [rf("pk", "path", required=True)], resp_json([of("data")]),
             reason="read one user", evidence="users.ts GET /:pk"),
     variant("PATCH", [rf("pk", "path", required=True), rf("data", "body", description="incl role/password")],
             resp_json([of("data")]), body_format="json", reason="update one user", evidence="users.ts PATCH /:pk"),
     variant("DELETE", [rf("pk", "path", required=True)], resp_empty(), reason="delete one user",
             evidence="users.ts DELETE /:pk")],
    "user_one",
    sin=[dec("pk", "UserID(user)", "identifier", reference_capable=True, reason="Target user.")],
    vis_reason="Per-user management.",
    reach=["directus_users.{read,update,delete} permission. PATCH role/password on another user (if no row "
           "filter) = account takeover / privilege escalation."],
    evref=US)

api("/users/me", ["GET", "PATCH"],
    [variant("GET", [], resp_json([of("data", description="own account")]),
             reason="the caller's own account", evidence="users.ts GET /me"),
     variant("PATCH", [rf("data", "body", description="own editable fields")], resp_json([of("data")]),
             body_format="json", reason="update own profile", evidence="users.ts PATCH /me")],
    "users_me",
    vis_reason="Self profile.",
    reach=["Authenticated user (or share). PATCH /me field allow-list governs self-escalation risk."],
    evref=US, notes="Self-update must not allow editing role/policies -- verify the editable-field set.")

api("/users/invite", ["POST"],
    [variant("POST", [rf("email", "body", required=True), rf("role", "body", required=True),
                      rf("invite_url", "body")],
             resp_empty(), body_format="json", reason="invite a user into a role", evidence="users.ts /invite")],
    "user_invite",
    sin=[d_email(), dec("role", "RoleID(role)", "identifier", reference_capable=True, reason="Invite role.")],
    vis_reason="User invite.",
    reach=["directus_users create permission. Invites into an arbitrary 'role' (escalation if admin role)."],
    evref=US, notes="invite_url is allow-listed (USER_INVITE_URL_ALLOW_LIST).")

api("/users/invite/accept", ["POST"],
    [variant("POST", [rf("token", "body", required=True), rf("password", "body", required=True)],
             resp_empty(), body_format="json", reason="accept an invite + set password",
             evidence="users.ts /invite/accept")],
    "user_invite_accept",
    sin=[dec("token", "InviteToken(invite)", "credential", reason="Invite token."), d_password()],
    vis_reason="Invite acceptance.",
    reach=["Public IF a valid invite token is held."], evref=US)

api("/users/register", ["POST"],
    [variant("POST", [rf("email", "body", required=True), rf("password", "body", required=True),
                      rf("verification_url", "body"), rf("first_name", "body")],
             resp_empty(), body_format="json", reason="public self-registration (if enabled)",
             evidence="users.ts /register")],
    "user_register",
    sin=[d_email(), d_password()],
    vis_reason="Public self-registration.",
    reach=["Public IF AUTH_* registration is enabled (settings). Rate-limited (rate-limiter-registration). "
           "New user lands in the configured default registration role."],
    evref=US, notes="Open registration + a powerful default role = self-service privilege.")

api("/users/:pk/tfa/disable", ["POST"],
    [variant("POST", [rf("pk", "path", required=True)], resp_empty(), body_format="json",
             reason="admin disables another user's 2FA", evidence="users.ts /:pk/tfa/disable")],
    "user_tfa_disable_admin",
    sin=[dec("pk", "UserID(user)", "identifier", reference_capable=True, reason="Target user.")],
    vis_reason="Admin TFA reset.",
    reach=["accountability.admin required -> disables a victim's 2FA (weakens their account)."],
    evref=US)

for _p, _m, _o in [("/users/me/track/page", ["PATCH"], "users_track_page"),
                   ("/users/me/tfa/generate", ["POST"], "users_tfa_generate"),
                   ("/users/me/tfa/enable", ["POST"], "users_tfa_enable"),
                   ("/users/me/tfa/disable", ["POST"], "users_tfa_disable"),
                   ("/users/register/verify-email", ["GET"], "users_verify_email")]:
    api0(_p, _m, _o, reach=["Authenticated self / public verify."], evref=US)


# ===========================================================================
# RBAC: ROLES / POLICIES / PERMISSIONS / ACCESS
# ===========================================================================
RL, PO, PM, AC = "roles.ts", "policies.ts", "permissions.ts", "access.ts"

api("/roles", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("GET", [], resp_json([of("data", description="roles")]), reason="list roles",
             evidence="roles.ts readHandler"),
     variant("POST", [rf("name", "body", required=True), rf("policies", "body")], resp_json([of("data")]),
             body_format="json", reason="create a role", evidence="roles.ts POST")],
    "roles",
    sout=[dec("data", "RoleID(role)", "identifier", reference_capable=True, reason="Roles.")],
    vis_reason="RBAC roles.",
    reach=["directus_roles permission (admin-managed). Roles group policies."], evref=RL)

api("/roles/:pk", ["GET", "PATCH", "DELETE"],
    [variant("PATCH", [rf("pk", "path", required=True), rf("policies", "body", description="attached policies")],
             resp_json([of("data")]), body_format="json",
             reason="update a role incl its policies", evidence="roles.ts PATCH /:pk")],
    "role_one",
    sin=[dec("pk", "RoleID(role)", "identifier", reference_capable=True, reason="Target role.")],
    vis_reason="Role management.",
    reach=["directus_roles update permission. Attaching an admin-access policy to a role = escalation."],
    evref=RL, notes="Role<->policy linkage is a privilege-escalation lever.")

api("/policies", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("name", "body", required=True),
                      rf("admin_access", "body", description="superuser bypass flag"),
                      rf("app_access", "body"), rf("ip_access", "body"),
                      rf("enforce_tfa", "body")],
             resp_json([of("data")]), body_format="json",
             reason="create a policy (carries admin_access/app_access flags)", evidence="policies.ts POST")],
    "policies",
    sout=[dec("data", "PolicyID(policy)", "identifier", reference_capable=True, reason="Policies.")],
    vis_reason="Access policies.",
    reach=["directus_policies permission. A policy with admin_access=true is full superuser -> creating/attaching "
           "one is the top escalation primitive."],
    evref=PO, notes="admin_access=true bypasses ALL permission checks.")

api("/policies/:pk", ["GET", "PATCH", "DELETE"],
    [variant("PATCH", [rf("pk", "path", required=True), rf("admin_access", "body")],
             resp_json([of("data")]), body_format="json", reason="update a policy's flags/permissions",
             evidence="policies.ts PATCH /:pk")],
    "policy_one",
    sin=[dec("pk", "PolicyID(policy)", "identifier", reference_capable=True, reason="Target policy.")],
    vis_reason="Policy management.",
    reach=["directus_policies update. Flipping admin_access=true on a policy the attacker holds = escalation."],
    evref=PO)

api("/permissions", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("GET", [], resp_json([of("data", description="permission rows")]),
             reason="list permission rules", evidence="permissions.ts readHandler"),
     variant("POST", [rf("policy", "body", required=True), rf("collection", "body", required=True),
                      rf("action", "body", description="create|read|update|delete|share"),
                      rf("permissions", "body", description="filter rule"),
                      rf("fields", "body")],
             resp_json([of("data")]), body_format="json",
             reason="create a permission rule for a policy", evidence="permissions.ts POST")],
    "permissions",
    sin=[d_collection(), dec("policy", "PolicyID(policy)", "identifier", reference_capable=True,
                             reason="Owning policy.")],
    vis_reason="Permission rules.",
    reach=["directus_permissions permission. Adding a broad rule (e.g. read * on directus_users with no filter) "
           "to a low policy opens data to that role."],
    evref=PM, notes="Permission rows define the content-API grants; mis-set filters -> exposure.")

api("/permissions/:pk", ["GET", "PATCH", "DELETE"],
    [variant("PATCH", [rf("pk", "path", required=True), rf("permissions", "body")], resp_json([of("data")]),
             body_format="json", reason="edit a permission rule", evidence="permissions.ts PATCH /:pk")],
    "permission_one",
    sin=[dec("pk", "PermissionID(permission)", "identifier", reference_capable=True, reason="Target rule.")],
    vis_reason="Permission rule edit.",
    reach=["directus_permissions update."], evref=PM)

api("/permissions/me", ["GET"],
    [variant("GET", [], resp_json([of("data", description="the caller's effective permissions")]),
             reason="the caller's own permissions", evidence="permissions.ts GET /me")],
    "permissions_me",
    vis_reason="Own permissions.",
    reach=["Authenticated; discloses the caller's effective grants (useful recon for the caller)."],
    evref=PM)

api("/access", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("user", "body"), rf("role", "body"), rf("policy", "body", required=True)],
             resp_json([of("data")]), body_format="json",
             reason="link a policy to a user or role (directus_access)", evidence="access.ts POST")],
    "access",
    sin=[dec("policy", "PolicyID(policy)", "identifier", reference_capable=True, reason="Linked policy.")],
    vis_reason="Policy assignment.",
    reach=["directus_access permission. Attaching an admin-access policy directly to a user = escalation."],
    evref=AC, notes="directus_access is the user/role <-> policy junction; a direct escalation lever.")

for _p, _m, _o in [("/access/:pk", ["GET", "PATCH", "DELETE"], "access_one"),
                   ("/policies/me/globals", ["GET"], "policies_me_globals"),
                   ("/permissions/me/:collection/:pk?", ["GET"], "permissions_me_collection")]:
    api0(_p, _m, _o, reach=["Authenticated / RBAC-managed."], evref=PM)


# ===========================================================================
# FILES / ASSETS / FOLDERS
# ===========================================================================
FI, AS, FO = "files.ts", "assets.ts", "folders.ts"

api("/files", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("file", "body", required=True, description="multipart upload")],
             resp_json([of("data", description="file record")]), body_format="multipart",
             reason="upload a file (create permission on directus_files)", evidence="files.ts POST /"),
     variant("GET", [], resp_json([of("data"), of("meta")]), reason="list files",
             evidence="files.ts readHandler")],
    "files",
    sout=[dec("data", "FileID(file)", "identifier", reference_capable=True, reason="Stored files.")],
    vis_reason="File library.",
    reach=["directus_files permission. Upload = stored-file + content-type surface; list exposes metadata."],
    evref=FI)

api("/files/import", ["POST"],
    [variant("POST", [rf("url", "body", required=True, description="remote URL the server fetches"),
                      rf("data", "body", description="file metadata")],
             resp_json([of("data")]), body_format="json",
             reason="import a file from a remote URL (server-side fetch)", evidence="files.ts POST /import")],
    "file_import",
    sin=[dec("url", "RemoteURL(url)", "locator", reference_capable=True, reason="Server-fetched URL.")],
    vis_reason="Import-from-URL (SSRF).",
    reach=["directus_files create permission. Server GETs an attacker-chosen 'url' = SSRF "
           "(cloud metadata / internal services)."],
    evref=FI, notes="Classic Directus SSRF vector.")

api("/files/:pk", ["GET", "PATCH", "DELETE"],
    [variant("PATCH", [rf("pk", "path", required=True), rf("data", "body")], resp_json([of("data")]),
             body_format="json", reason="update file metadata / replace", evidence="files.ts PATCH /:pk"),
     variant("DELETE", [rf("pk", "path", required=True)], resp_empty(), reason="delete a file",
             evidence="files.ts DELETE /:pk")],
    "file_one",
    sin=[dec("pk", "FileID(file)", "identifier", reference_capable=True, reason="Target file.")],
    vis_reason="File CRUD.",
    reach=["directus_files {read,update,delete} permission."], evref=FI)

api("/assets/:pk/:filename?", ["GET"],
    [variant("GET", [rf("pk", "path", required=True, description="file id"),
                     rf("key", "query", description="named transform preset"),
                     rf("width", "query"), rf("height", "query"), rf("transforms", "query")],
             c.resp_binary("asset", "the (optionally transformed) file bytes"),
             reason="download/stream a file with on-the-fly image transforms", evidence="assets.ts GET /:pk")],
    "asset_download",
    sin=[dec("pk", "FileID(file)", "identifier", reference_capable=True, reason="File to serve.")],
    vis_reason="Asset download + transform.",
    reach=["Read permission on the file (public if the file's folder/permission allows). Arbitrary 'transforms' "
           "params are a CPU/memory DoS surface (ASSETS_TRANSFORM_* limits)."],
    evref=AS, notes="Image-transform params = resource-exhaustion surface; also the public file-serving path.")

api("/folders", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("name", "body", required=True), rf("parent", "body")], resp_json([of("data")]),
             body_format="json", reason="create a folder", evidence="folders.ts POST")],
    "folders",
    vis_reason="File folders.",
    reach=["directus_folders permission."], evref=FO)

for _p, _m, _o in [("/assets/folder/:pk", ["POST"], "asset_folder_action"),
                   ("/assets/files/", ["POST"], "asset_files_action"),
                   ("/folders/:pk", ["GET", "PATCH", "DELETE"], "folder_one")]:
    api0(_p, _m, _o, reach=["Authenticated + directus_files/folders permission."], evref=AS)


# ===========================================================================
# FLOWS / OPERATIONS  (automation engine)
# ===========================================================================
FL, OP = "flows.ts", "operations.ts"

api("/flows/trigger/:pk", ["GET", "POST"],
    [variant("POST", [rf("pk", "path", required=True, description="flow id"),
                      rf("body", "body", description="passed to the flow payload")],
             resp_json([of("data", description="flow result")]), body_format="json",
             reason="trigger a webhook/manual flow (runs its operations)", evidence="flows.ts webhookFlowHandler"),
     variant("GET", [rf("pk", "path", required=True)], resp_json([of("data")]),
             reason="trigger a GET-method flow", evidence="flows.ts webhookFlowHandler")],
    "flow_trigger",
    sin=[dec("pk", "FlowID(flow)", "identifier", reference_capable=True, reason="Target flow.")],
    vis_reason="Flow execution (automation).",
    reach=["Reachability per the flow's trigger config: a 'webhook' flow can be PUBLIC (no auth). A triggered "
           "flow runs its operation chain (request/webhook-url = SSRF, run-script = sandboxed JS, "
           "item mutations) with the flow's configured accountability."],
    evref=FL, notes="The automation attack surface: public webhook flows execute server-side operation chains.")

api("/flows", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("name", "body", required=True), rf("trigger", "body", description="webhook|manual|..."),
                      rf("operations", "body", description="operation chain")],
             resp_json([of("data")]), body_format="json",
             reason="create a flow + its operation chain", evidence="flows.ts POST")],
    "flows",
    sout=[dec("data", "FlowID(flow)", "identifier", reference_capable=True, reason="Flows.")],
    vis_reason="Flow definitions.",
    reach=["directus_flows permission (admin-managed). Defining a flow with a run-script/request operation = "
           "server-side code/SSRF by configuration."],
    evref=FL, notes="Creating flows is effectively server-side automation authoring.")

api("/operations", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("type", "body", required=True, description="exec|request|..."),
                      rf("options", "body", description="e.g. script body / target url")],
             resp_json([of("data")]), body_format="json",
             reason="create a flow operation (code/SSRF by type)", evidence="operations.ts POST")],
    "operations",
    vis_reason="Flow operations.",
    reach=["directus_operations permission. 'exec' runs sandboxed JS; 'request' fetches a URL (SSRF)."],
    evref=OP, notes="operation 'exec' = sandboxed code; 'request' = SSRF -- the flow building blocks.")


# ===========================================================================
# SCHEMA / DATA MODEL  (schema.ts, collections.ts, fields.ts, relations.ts)
# ===========================================================================
SC, CO, FD, RE = "schema.ts", "collections.ts", "fields.ts", "relations.ts"

api("/schema/snapshot", ["GET"],
    [variant("GET", [rf("includeCollections", "query"), rf("excludeCollections", "query")],
             resp_json([of("data", description="full schema snapshot")]),
             reason="export the full data-model snapshot (admin only)", evidence="schema.ts GET /snapshot")],
    "schema_snapshot",
    vis_reason="Schema export.",
    reach=["admin only (checkIsAdmin). Full data-model disclosure."], evref=SC)

api("/schema/apply", ["POST"],
    [variant("POST", [rf("diff", "body", required=True, description="snapshot diff to apply")],
             resp_empty(), body_format="json",
             reason="apply schema changes: create/alter/drop collections+fields (admin only)",
             evidence="schema.ts POST /apply")],
    "schema_apply",
    vis_reason="Schema mutation.",
    reach=["admin only. Full control of the data model (create/drop tables, change fields) -> destructive + "
           "can introduce fields/relations that widen the surface."],
    evref=SC, notes="Whole-schema write; highest-impact data-model primitive.")

api("/collections", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("collection", "body", required=True), rf("schema", "body"), rf("fields", "body")],
             resp_json([of("data")]), body_format="json",
             reason="create a collection (table) (admin/collections permission)", evidence="collections.ts POST")],
    "collections",
    sin=[d_collection()],
    vis_reason="Collection (table) management.",
    reach=["directus_collections permission (admin). Creating/dropping collections changes the DB schema."],
    evref=CO)

api("/fields/:collection", ["GET", "POST", "PATCH"],
    [variant("POST", [rf("collection", "path", required=True), rf("field", "body", required=True),
                      rf("type", "body"), rf("schema", "body")],
             resp_json([of("data")]), body_format="json",
             reason="add a field to a collection (admin)", evidence="fields.ts POST /:collection")],
    "fields_collection",
    sin=[d_collection()],
    vis_reason="Field management.",
    reach=["directus_fields permission (admin). Field changes alter the DB columns."], evref=FD)

for _p, _m, _o in [("/schema/diff", ["POST"], "schema_diff"),
                   ("/collections/:collection", ["GET", "PATCH", "DELETE"], "collection_one"),
                   ("/fields", ["GET"], "fields_all"),
                   ("/fields/:collection/:field", ["GET", "PATCH", "DELETE"], "field_one"),
                   ("/relations", ["GET", "POST", "PATCH"], "relations"),
                   ("/relations/:collection", ["GET"], "relations_collection"),
                   ("/relations/:collection/:field", ["GET", "PATCH", "DELETE"], "relation_one")]:
    api0(_p, _m, _o, reach=["admin / data-model permission."], evref=SC)


# ===========================================================================
# UTILS  (controllers/utils.ts -> /utils)
# ===========================================================================
UT = "utils.ts"

api("/utils/export/:collection", ["POST"],
    [variant("POST", [rf("collection", "path", required=True),
                      rf("query", "body", required=True, description="filter/fields to export"),
                      rf("format", "body", required=True, description="csv|json|xml|yaml")],
             resp_empty(), body_format="json",
             reason="export query results to a file (background, saved as a directus_file)",
             evidence="utils.ts POST /export/:collection")],
    "utils_export",
    sin=[d_collection()],
    vis_reason="Data export (exfil).",
    reach=["Read permission on the collection. Bulk exfiltration of readable data to a file."],
    evref=UT, notes="Permission-scoped, but a convenient bulk-exfil channel.")

api("/utils/import/:collection", ["POST"],
    [variant("POST", [rf("collection", "path", required=True), rf("file", "body", description="uploaded file")],
             resp_empty(), body_format="multipart",
             reason="import a file's rows into a collection", evidence="utils.ts POST /import/:collection")],
    "utils_import",
    sin=[d_collection()],
    vis_reason="Bulk data import.",
    reach=["Create permission on the collection. Bulk write from an uploaded file."],
    evref=UT)

api("/utils/cache/clear", ["POST"],
    [variant("POST", [rf("system", "query", description="also clear system cache")], resp_empty(),
             reason="clear the cache", evidence="utils.ts POST /cache/clear")],
    "utils_cache_clear",
    vis_reason="Cache clear.",
    reach=["Permission-gated (admin for system cache). Availability/consistency impact."], evref=UT)

api("/utils/import", ["POST"],
    [variant("POST", [rf("mode", "query", description="add|merge"),
                      rf("dangerouslyAllowDelete", "query"), rf("body", "body", description="batch items")],
             resp_json([of("data")]), body_format="json",
             reason="batch import across collections (optional destructive delete)",
             evidence="utils.ts POST /import")],
    "utils_import_batch",
    vis_reason="Batch import.",
    reach=["Create/update permission; 'dangerouslyAllowDelete' flag enables deletions."],
    evref=UT, notes="dangerouslyAllowDelete makes this destructive.")

for _p, _m, _o in [("/utils/random/string", ["GET"], "utils_random"),
                   ("/utils/sort/:collection", ["POST"], "utils_sort"),
                   ("/utils/revert/:revision", ["POST"], "utils_revert"),
                   ("/utils/translations/generate", ["POST"], "utils_translations_generate"),
                   ("/utils/resolve-redirect", ["POST"], "utils_resolve_redirect")]:
    api0(_p, _m, _o, reach=["Authenticated / permission-gated (translations/generate is admin)."], evref=UT)


# ===========================================================================
# EXTENSIONS  (controllers/extensions.ts -> /extensions)
# ===========================================================================
EX = "extensions.ts"

api("/extensions/registry/install", ["POST"],
    [variant("POST", [rf("extension", "body", required=True, description="registry extension id"),
                      rf("version", "body")],
             resp_empty(), body_format="json",
             reason="install a 3rd-party extension from the registry (runs its code)",
             evidence="extensions.ts POST /registry/install")],
    "extension_install",
    vis_reason="Extension install (code).",
    reach=["admin. Installs and loads third-party extension code into the server -> code-execution-adjacent."],
    evref=EX, notes="Installing an extension loads untrusted code; marketplace/supply-chain surface.")

api("/extensions/:pk", ["PATCH", "DELETE"],
    [variant("PATCH", [rf("pk", "path", required=True), rf("enabled", "body", description="enable/disable")],
             resp_json([of("data")]), body_format="json",
             reason="enable/disable an installed extension", evidence="extensions.ts PATCH /:pk"),
     variant("DELETE", [rf("pk", "path", required=True)], resp_empty(), reason="remove an extension",
             evidence="extensions.ts DELETE /:pk")],
    "extension_manage",
    vis_reason="Extension enable/remove.",
    reach=["admin. Toggling/removing extensions changes loaded server code."], evref=EX)

api("/extensions", ["GET"],
    [variant("GET", [], resp_json([of("data", description="installed extensions")]),
             reason="list installed extensions", evidence="extensions.ts GET /")],
    "extensions_list",
    vis_reason="Extension inventory.",
    reach=["Authenticated (app). Reveals installed extensions (recon)."], evref=EX)

for _p, _m, _o in [("/extensions/registry", ["GET"], "extensions_registry_browse"),
                   ("/extensions/registry/account/:pk", ["GET"], "extensions_registry_account"),
                   ("/extensions/registry/extension/:pk", ["GET"], "extensions_registry_extension"),
                   ("/extensions/registry/reinstall", ["POST"], "extensions_reinstall"),
                   ("/extensions/registry/uninstall/:pk", ["DELETE"], "extensions_uninstall"),
                   ("/extensions/sources/:chunk", ["GET"], "extensions_sources")]:
    api0(_p, _m, _o, reach=["admin (registry ops) / app (sources)."], evref=EX)


# ===========================================================================
# SHARES  (controllers/shares.ts -> /shares)  -- public share access
# ===========================================================================
SH = "shares.ts"

api("/shares/auth", ["POST"],
    [variant("POST", [rf("share", "body", required=True, description="share id"),
                      rf("password", "body", description="if the share is password-protected"),
                      rf("mode", "body")],
             resp_json([of("access_token"), of("refresh_token"), of("expires")]), body_format="json",
             reason="authenticate to a share -> item-scoped tokens (no login)", evidence="shares.ts POST /auth")],
    "share_auth",
    sin=[dec("share", "ShareID(share)", "identifier", reference_capable=True, reason="Share id."),
         dec("password", "SharePassword(share)", "credential", reason="Share password (optional).")],
    sout=[d_token()],
    vis_reason="Public share login.",
    reach=["Public. Anyone with a share id (+ password if set) gets an access token scoped to the shared item. "
           "Share id guessability + weak/absent password = unauthenticated data access."],
    evref=SH, notes="Public auth surface; brute-force on share password / id enumeration.")

api("/shares/info/:pk", ["GET"],
    [variant("GET", [rf("pk", "path", required=True)],
             resp_json([of("data", description="share metadata incl. max_uses/times_used/dates")]),
             reason="public share metadata (no accountability)", evidence="shares.ts GET /info/:pk")],
    "share_info",
    sin=[dec("pk", "ShareID(share)", "identifier", reference_capable=True, reason="Share id.")],
    vis_reason="Public share info.",
    reach=["Public (no auth). Returns share metadata; confirms a share id exists + whether it is password-set."],
    evref=SH, notes="Oracle for share existence + password requirement.")

api("/shares", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("collection", "body", required=True), rf("item", "body", required=True),
                      rf("password", "body"), rf("max_uses", "body")],
             resp_json([of("data")]), body_format="json",
             reason="create a share for an item", evidence="shares.ts POST /")],
    "shares",
    sout=[dec("data", "ShareID(share)", "identifier", reference_capable=True, reason="Shares.")],
    vis_reason="Share management.",
    reach=["directus_shares + 'share' permission on the item's collection. Creating a share exposes an item "
           "to unauthenticated holders of the link."],
    evref=SH, notes="Share create = deliberate public-exposure primitive.")

for _p, _m, _o in [("/shares/invite", ["POST"], "share_invite"),
                   ("/shares/:pk", ["GET", "PATCH", "DELETE"], "share_one")]:
    api0(_p, _m, _o, reach=["directus_shares permission."], evref=SH)


# ===========================================================================
# SETTINGS  (controllers/settings.ts -> /settings)  -- project-wide config
# ===========================================================================
ST = "settings.ts"

api("/settings", ["GET", "PATCH", "POST"],
    [variant("GET", [], resp_json([of("data", description="project settings")]),
             reason="read project settings", evidence="settings.ts GET /"),
     variant("PATCH", [rf("data", "body", description="settings incl auth/storage/cors/public flags")],
             resp_json([of("data")]), body_format="json",
             reason="update project settings (admin)", evidence="settings.ts PATCH /")],
    "settings",
    vis_reason="Project settings.",
    reach=["Read: app users (some public-ish fields drive the login screen). Update: directus_settings permission "
           "(admin) -> reconfigure storage/CORS/auth/public registration/default role = workspace takeover-adjacent."],
    evref=ST, notes="Settings writes control registration, default roles, storage and CORS.")


# ===========================================================================
# CONTENT VERSIONS / COLLAB  (versions, comments, notifications, presets, revisions, activity)
# ===========================================================================
VE = "versions.ts"

api("/versions/:pk/promote", ["POST"],
    [variant("POST", [rf("pk", "path", required=True), rf("mainHash", "body")], resp_json([of("data")]),
             body_format="json", reason="promote a content version to the main item", evidence="versions.ts promote")],
    "version_promote",
    sin=[dec("pk", "VersionID(version)", "identifier", reference_capable=True, reason="Target version.")],
    vis_reason="Promote content version.",
    reach=["Update permission on the versioned collection. Promotes draft content to live."],
    evref=VE, notes="Draft->live publish path for content versioning.")

api("/versions", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("collection", "body", required=True), rf("item", "body", required=True),
                      rf("key", "body")],
             resp_json([of("data")]), body_format="json",
             reason="create a content version (draft)", evidence="versions.ts POST")],
    "versions",
    sin=[d_collection()],
    vis_reason="Content versions.",
    reach=["directus_versions + collection permission."], evref=VE)

api("/comments", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("collection", "body", required=True), rf("item", "body", required=True),
                      rf("comment", "body", required=True)],
             resp_json([of("data")]), body_format="json", reason="comment on an item", evidence="comments.ts POST")],
    "comments",
    sin=[d_collection()],
    vis_reason="Item comments.",
    reach=["directus_comments permission. Stored content (XSS-in-studio surface)."], evref="comments.ts")

api("/notifications", ["GET", "POST", "SEARCH", "PATCH", "DELETE"],
    [variant("POST", [rf("recipient", "body", required=True), rf("subject", "body"), rf("message", "body")],
             resp_json([of("data")]), body_format="json",
             reason="send a notification to a user", evidence="notifications.ts POST")],
    "notifications",
    vis_reason="Notifications.",
    reach=["directus_notifications permission. Can message arbitrary users (phishing-in-app surface)."],
    evref="notifications.ts")

for _p, _m, _o in [("/versions/:pk", ["GET", "PATCH", "DELETE"], "version_one"),
                   ("/versions/:pk/save", ["POST"], "version_save"),
                   ("/versions/:pk/compare", ["GET"], "version_compare"),
                   ("/comments/:pk", ["GET", "PATCH", "DELETE"], "comment_one"),
                   ("/notifications/:pk", ["GET", "PATCH", "DELETE"], "notification_one"),
                   ("/presets", ["GET", "POST", "PATCH", "DELETE"], "presets"),
                   ("/presets/:pk", ["GET", "PATCH", "DELETE"], "preset_one"),
                   ("/revisions", ["GET", "SEARCH"], "revisions"),
                   ("/revisions/:pk", ["GET"], "revision_one"),
                   ("/activity", ["GET", "SEARCH"], "activity"),
                   ("/activity/:pk", ["GET"], "activity_one")]:
    api0(_p, _m, _o, reach=["Authenticated + relevant directus_* permission."], evref="collab")


# ===========================================================================
# GRAPHQL  (controllers/graphql.ts -> /graphql, /graphql/system)
# ===========================================================================
api("/graphql", ["POST", "GET"],
    [variant("POST", [rf("query", "body", required=True, description="GraphQL query/mutation"),
                      rf("variables", "body")],
             resp_json([of("data"), of("errors")]), body_format="json",
             reason="GraphQL endpoint over the item/content schema (same permission model)",
             evidence="graphql.ts")],
    "graphql_items",
    vis_reason="GraphQL (items).",
    reach=["Same accountability/permission model as REST, re-exposed as GraphQL. Query depth/complexity = DoS "
           "surface; introspection (GRAPHQL_INTROSPECTION) discloses the schema."],
    evref="graphql.ts", notes="GraphQL mirrors the REST permission model; one POST, broad reach.")

api0("/graphql/system", ["POST", "GET"], "graphql_system",
     reach=["GraphQL over the system (directus_*) collections; same permission model."], evref="graphql.ts")


# ===========================================================================
# DASHBOARDS / PANELS / TRANSLATIONS / METRICS / MCP (enumerated)
# ===========================================================================
for _p, _m, _o, _e in [("/dashboards", ["GET", "POST", "PATCH", "DELETE"], "dashboards", "dashboards.ts"),
                       ("/dashboards/:pk", ["GET", "PATCH", "DELETE"], "dashboard_one", "dashboards.ts"),
                       ("/panels", ["GET", "POST", "PATCH", "DELETE"], "panels", "panels.ts"),
                       ("/panels/:pk", ["GET", "PATCH", "DELETE"], "panel_one", "panels.ts"),
                       ("/translations", ["GET", "POST", "PATCH", "DELETE"], "translations", "translations.ts"),
                       ("/translations/:pk", ["GET", "PATCH", "DELETE"], "translation_one", "translations.ts"),
                       ("/metrics", ["GET"], "metrics", "metrics.ts")]:
    api0(_p, _m, _o, reach=["Authenticated + directus_* permission (metrics is config-gated)."], evref=_e)


_finalize()


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded against directus/directus (official image).
# Identity labels: anonymous (public role, no token) | user (app user token) |
# admin (admin_access policy). Populated by runtime/probe.ps1 after a probe.
# ===========================================================================
_RUNTIME = {
    # public surface
    "/server/health":   {"s": [200], "id": {"anonymous": [200]}},
    "/server/info":     {"s": [200], "id": {"anonymous": [200]}},
    "/auth":            {"s": [200], "id": {"anonymous": [200]}},
    "/server/setup":    {"s": [403], "id": {"anonymous": [403]}},   # bootstrap window closed (admin exists)
    "/users/register":  {"s": [403], "id": {"anonymous": [403]}},   # registration DISABLED by default
    "/auth/login":      {"s": [200, 401], "id": {"anonymous": [200, 401]}},
    # system reads: default-deny for anon (403), admin 200
    "/users/me":        {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/users":           {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/roles":           {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/policies":        {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/permissions":     {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/settings":        {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/files":           {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/collections":     {"s": [200, 403], "id": {"anonymous": [403], "admin": [200]}},
    "/flows":           {"s": [200], "id": {"admin": [200]}},
    "/extensions":      {"s": [200], "id": {"admin": [200]}},
    "/schema/snapshot": {"s": [200], "id": {"admin": [200]}},   # admin-only (checkIsAdmin)
    "/server/specs/oas": {"s": [200], "id": {"admin": [200]}},
    # dynamic items: anon 403 by DEFAULT, 200 once the public policy is granted read (confirmed both)
    "/items/:collection":     {"s": [200, 403], "id": {"anonymous": [403, 200], "admin": [200]}},
    "/items/:collection/:pk": {"s": [200, 403], "id": {"anonymous": [200, 403], "admin": [200]}},
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
                             evidence=[c.ev("source", evref, "client")] if evref else [], notes=notes))


page("/admin", ["GET"], "data_studio", kind="page", evref="app/ (Data Studio SPA)",
     notes="Vue Data Studio SPA; drives the REST/GraphQL API.")
page("/", ["GET"], "root", kind="page", evref="api/src/app.ts",
     notes="Root (redirects to /admin or returns server info).")


EDGES = [
    {"src": K("/admin"), "dst": K("/auth/login"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/admin"), "dst": K("/users/me"), "methods": ["GET"], "triggers": ["xhr"]},
    {"src": K("/admin"), "dst": K("/items/:collection"), "methods": ["GET"], "triggers": ["xhr"]},
]
