# -*- coding: utf-8 -*-
"""Open WebUI HTTP API L1 inventory -- data table.

Module: Authentication + Account (router backend/open_webui/routers/auths.py,
mounted at /api/v1/auths; the sessions sub-router at /api/v1/auths/sessions is a
separate follow-on module). Source-first from the FastAPI handlers + Pydantic
request/response models (models/auths.py, models/users.py). Auth model: JWT
session-cookie `token` OR `sk-` API key -> get_current_user; get_verified_user
requires role in {user, admin}; get_admin_user requires role == admin.

No runtime capture here (no Docker/network); samples=[], black_box_reachable
derived from source gating. See environment.yaml web_gt:.

Builds: API_NODES (kind=api, io_variants -> L2 candidates), PAGE_NODES, EDGES.
"""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, resp_scalar, dec, dec_for, ev

SRC = "backend/open_webui/routers/auths.py"
MSRC = "backend/open_webui/models/auths.py"

# identity -> derived status codes.
ST_PUBLIC   = {"anonymous": [200, 400, 403]}             # signin/signup/ldap/oauth-exchange
ST_USER     = {"anonymous": [401], "pending": [200], "user": [200], "admin": [200]}   # get_current_user
ST_VERIFIED = {"anonymous": [401], "pending": [401], "user": [200], "admin": [200]}   # get_verified_user
ST_ADMIN    = {"anonymous": [401], "pending": [401], "user": [401], "admin": [200]}   # get_admin_user

# Shared semantic decisions
D_EMAIL   = dec_for("email")
D_PASSWD  = dec_for("password")
D_NAME    = dec_for("name")
D_ROLE    = dec_for("role")
D_IMG     = dec_for("profile_image_url")
D_TOKEN   = dec_for("token")
D_APIKEY  = dec_for("api_key")
D_ID      = dec_for("id")
D_PERMS   = dec("permissions", "Permissions(authz)", "content", mergeable=True,
                reason="Effective permission map returned with the session.")
D_CONFIG  = dec("config", "AdminConfig(system)", "content", mergeable=True,
                reason="Instance auth/admin configuration blob (includes secret config such as "
                       "ldap app password / OAuth client secrets -- recorded as location, not value).")
D_LDAPCFG = dec("ldap_config", "LdapServerConfig(system)", "content", mergeable=True,
                reason="LDAP bind/server configuration (app_dn_password is a stored secret -- location only).")
D_OAUTHCFG = dec("oauth_config", "OAuthConfig(system)", "content", mergeable=True,
                 reason="OAuth provider configuration (client_secret is a stored secret -- location only).")

API_NODES = []

# ---- Session identity ------------------------------------------------------
API_NODES.append(node(
    K("/api/v1/auths/"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("token", "string", True, "Freshly re-issued JWT session token."),
        of("token_type", "string", False, "Bearer."),
        of("expires_at", "integer", False, "Token expiry (epoch)."),
        of("permissions", "object", True, "Effective permission map for the caller."),
        of("id", "string", True, "User id."), of("email", "string", True, "User email."),
        of("name", "string", True, "Display name."), of("role", "string", True, "user|admin|pending."),
        of("profile_image_url", "string", True, "Profile image URL.")]),
        reason="Returns the caller's session user info and re-issues a token.",
        evidence=f"{SRC}:185")],
    operation_semantic="get_session_user", statuses=[200, 401], identity_statuses=ST_USER,
    sem_out_decisions=[D_TOKEN, D_PERMS, D_ID, D_EMAIL, D_NAME, D_ROLE, D_IMG],
    route_confirmed=True, vis_reason="Any authenticated caller reads their own session.",
    evidence=[ev("source", f"{SRC}:185", "GET / [get_current_user] -> SessionUserInfoResponse; re-issues token")],
    notes="Re-issues a session token on every call; discloses caller role + effective permissions."))

# ---- Account self-service --------------------------------------------------
API_NODES.append(node(
    K("/api/v1/auths/update/profile"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"profile_image_url": "/user.png", "name": "Alice", "bio": None},
        request_fields=[rf("profile_image_url", "body", "string", required=True, flow=True,
                           description="New profile image URL (validate_image_url guards scheme)."),
                        rf("name", "body", "string", required=True, flow=True, description="New display name."),
                        rf("bio", "body", "string", required=False, flow=True, description="Bio text."),
                        rf("gender", "body", "string", required=False, flow=False, description="Gender."),
                        rf("date_of_birth", "body", "string", required=False, flow=False, description="DOB.")],
        response=resp_json([of("profile_image_url", "string", True, "Updated image URL."),
                            of("name", "string", True, "Updated name.")]),
        reason="Updates the caller's own profile fields.", evidence=f"{SRC}:253")],
    operation_semantic="update_profile", statuses=[200, 401], identity_statuses=ST_VERIFIED,
    sem_in_decisions=[D_IMG, D_NAME, dec("bio", "Bio(identity)", "content", reason="Free-text bio.")],
    sem_out_decisions=[D_IMG, D_NAME],
    route_confirmed=True, vis_reason="Verified caller edits own profile.",
    evidence=[ev("source", f"{SRC}:253", "POST /update/profile [get_verified_user] -> UserProfileImageResponse")],
    notes="profile_image_url passes validate_image_url; bio/name are stored-reflected (self-stored XSS surface)."))

API_NODES.append(node(
    K("/api/v1/auths/update/timezone"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"timezone": "Asia/Singapore"},
        request_fields=[rf("timezone", "body", "string", required=True, flow=True, description="IANA timezone.")],
        response=resp_json([of("timezone", "string", True, "Stored timezone.")]),
        reason="Stores the caller's preferred timezone.", evidence=f"{SRC}:288")],
    operation_semantic="update_timezone", statuses=[200, 401], identity_statuses=ST_USER,
    sem_in_decisions=[dec("timezone", "Timezone(preference)", "attribute", reason="User timezone preference.")],
    sem_out_decisions=[dec("timezone", "Timezone(preference)", "attribute", reason="Stored timezone.")],
    route_confirmed=True, vis_reason="Authenticated caller sets own preference.",
    evidence=[ev("source", f"{SRC}:288", "POST /update/timezone [get_current_user]")],
    notes="Low-sensitivity preference write."))

API_NODES.append(node(
    K("/api/v1/auths/update/password"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"password": "old", "new_password": "new"},
        request_fields=[rf("password", "body", "string", required=True, flow=True, description="Current password."),
                        rf("new_password", "body", "string", required=True, flow=True, description="New password.")],
        response=resp_scalar("result", "boolean", "True on success.", value_flow=True),
        reason="Rotates the caller's own password after verifying the current one.", evidence=f"{SRC}:316")],
    operation_semantic="update_password", statuses=[200, 400, 401], identity_statuses=ST_USER,
    sem_in_decisions=[D_PASSWD, dec("new_password", "Password(credential)", "credential", mergeable=True,
                                    reason="Replacement credential.")],
    route_confirmed=True, vis_reason="Authenticated caller rotates own credential.",
    evidence=[ev("source", f"{SRC}:316", "POST /update/password [get_current_user] verify_password -> bool")],
    notes="Credential write; requires the current password. Secrets are inputs only, never echoed."))

# ---- Login / registration (anonymous auth boundary) ------------------------
API_NODES.append(node(
    K("/api/v1/auths/ldap"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"user": "alice", "password": "***"},
        request_fields=[rf("user", "body", "string", required=True, flow=True, description="LDAP username."),
                        rf("password", "body", "string", required=True, flow=True, description="LDAP password.")],
        response=resp_json([of("token", "string", True, "Session token on success."),
                            of("email", "string", True, "Resolved email."), of("role", "string", True, "Role.")]),
        reason="Binds to the configured LDAP server and establishes a session.", evidence=f"{SRC}:409")],
    operation_semantic="ldap_auth", statuses=[200, 400, 403], identity_statuses=ST_PUBLIC,
    sem_in_decisions=[dec("user", "LdapUsername(identity)", "identifier", reference_capable=True,
                          reason="LDAP login name."), D_PASSWD],
    sem_out_decisions=[D_TOKEN, D_EMAIL, D_ROLE],
    route_confirmed=True, vis_reason="Public login endpoint (only live when LDAP enabled).",
    reach_conds=["ldap.server enabled in admin config"],
    evidence=[ev("source", f"{SRC}:409", "POST /ldap -> SigninResult; escape_filter_chars on bind")],
    notes="LDAP bind boundary; filter chars escaped. Live only when LDAP is enabled."))

API_NODES.append(node(
    K("/api/v1/auths/signin"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"email": "a@b.co", "password": "***"},
        request_fields=[rf("email", "body", "string", required=True, flow=True, description="Account email."),
                        rf("password", "body", "string", required=True, flow=True, description="Account password.")],
        response=resp_json([of("token", "string", True, "JWT session token (also set as cookie)."),
                            of("token_type", "string", False, "Bearer."),
                            of("email", "string", True, "Account email."), of("name", "string", True, "Name."),
                            of("role", "string", True, "Role."),
                            of("profile_image_url", "string", True, "Image.")]),
        reason="Password / trusted-header / no-auth signin; issues a session cookie.", evidence=f"{SRC}:660")],
    operation_semantic="signin", statuses=[200, 400, 403, 429], identity_statuses=ST_PUBLIC,
    sem_in_decisions=[D_EMAIL, D_PASSWD], sem_out_decisions=[D_TOKEN, D_EMAIL, D_NAME, D_ROLE, D_IMG],
    route_confirmed=True, vis_reason="Public login endpoint.",
    reach_conds=["ENABLE_PASSWORD_AUTH true for password mode"],
    evidence=[ev("source", f"{SRC}:660", "POST /signin -> create_signin_response(set_cookie=True)"),
              ev("source", f"{SRC}:676", "WEBUI_AUTH_TRUSTED_EMAIL/ROLE_HEADER: proxy header establishes identity+role")],
    notes="Auth boundary. Rate-limited (5*3/180s). Alternate modes: trusted-header "
          "(proxy header sets identity AND role -> impersonation if header spoofable) and "
          "WEBUI_AUTH=false (admin@localhost/admin bootstrap)."))

API_NODES.append(node(
    K("/api/v1/auths/signup"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"name": "Alice", "email": "a@b.co", "password": "***", "profile_image_url": "/user.png"},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="Display name."),
                        rf("email", "body", "string", required=True, flow=True, description="Email."),
                        rf("password", "body", "string", required=True, flow=True, description="Password."),
                        rf("profile_image_url", "body", "string", required=False, flow=True,
                           description="Avatar URL (validate_image_url).")],
        response=resp_json([of("token", "string", True, "Session token (first user becomes admin)."),
                            of("email", "string", True, "Email."), of("role", "string", True, "Assigned role."),
                            of("name", "string", True, "Name.")]),
        reason="Registers a new account; first user becomes admin, others get default role.", evidence=f"{SRC}:849")],
    operation_semantic="signup", statuses=[200, 400, 403], identity_statuses=ST_PUBLIC,
    sem_in_decisions=[D_NAME, D_EMAIL, D_PASSWD, D_IMG], sem_out_decisions=[D_TOKEN, D_EMAIL, D_ROLE, D_NAME],
    route_confirmed=True, vis_reason="Public registration endpoint.",
    reach_conds=["ui.enable_signup true (or first-ever user bootstrap)"],
    evidence=[ev("source", f"{SRC}:849", "POST /signup -> signup_handler; first user -> admin")],
    notes="Registration boundary; gated by ui.enable_signup except the initial-admin bootstrap."))

API_NODES.append(node(
    K("/api/v1/auths/signout"), "api", ["POST"],
    variants=[variant("POST", response=resp_json([of("status", "boolean", False, "Signed out."),
                                                  of("redirect_url", "string", False, "Optional redirect.")]),
        reason="Invalidates the token and clears session/oauth cookies.", evidence=f"{SRC}:905")],
    operation_semantic="signout", statuses=[200], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Any caller may end their session.",
    evidence=[ev("source", f"{SRC}:905", "POST /signout -> invalidate_token + delete_cookie")],
    notes="Clears token/oauth cookies; may 302 to WEBUI_AUTH_SIGNOUT_REDIRECT_URL."))

# ---- OAuth sessions + token exchange ---------------------------------------
API_NODES.append(node(
    K("/api/v1/auths/oauth/sessions/{provider}"), "api", ["DELETE"],
    params=[{"name": "provider", "in": "path", "type": "string", "required": True, "flow": True,
             "description": "OAuth provider id (path:path)."}],
    variants=[variant("DELETE", response=resp_scalar("result", "boolean", "True if removed.", value_flow=True),
        reason="Deletes the caller's stored OAuth session for a provider.", evidence=f"{SRC}:1019")],
    operation_semantic="delete_oauth_session", statuses=[200, 401], identity_statuses=ST_VERIFIED,
    sem_in_decisions=[dec("provider", "OAuthProvider(auth)", "identifier", reference_capable=True,
                          reason="Which provider session to drop.")],
    route_confirmed=True, vis_reason="Verified caller manages own OAuth links.",
    evidence=[ev("source", f"{SRC}:1019", "DELETE /oauth/sessions/{provider:path} [get_verified_user]")],
    notes="Scoped to the caller's own OAuth sessions."))

API_NODES.append(node(
    K("/api/v1/auths/oauth/{provider}/token/exchange"), "api", ["POST"],
    params=[{"name": "provider", "in": "path", "type": "string", "required": True, "flow": True,
             "description": "OAuth provider id."}],
    variants=[variant("POST", body_format="json", body_example={"token": "<external-idp-token>"},
        request_fields=[rf("token", "body", "string", required=True, flow=True,
                           description="External IdP access/ID token to exchange.")],
        response=resp_json([of("token", "string", True, "Open WebUI session token."),
                            of("email", "string", True, "Resolved email."), of("role", "string", True, "Role.")]),
        reason="Exchanges a trusted external IdP token for an Open WebUI session.", evidence=f"{SRC}:1605")],
    operation_semantic="oauth_token_exchange", statuses=[200, 400, 401, 403, 429], identity_statuses=ST_PUBLIC,
    sem_in_decisions=[dec("provider", "OAuthProvider(auth)", "identifier", reference_capable=True,
                          reason="Provider to validate the token against."),
                      dec("token", "ExternalIdpToken(credential)", "credential", mergeable=True,
                          reason="Bearer token minted by the external IdP.")],
    sem_out_decisions=[D_TOKEN, D_EMAIL, D_ROLE],
    route_confirmed=True, vis_reason="Public token-exchange endpoint when enabled.",
    reach_conds=["ENABLE_OAUTH_TOKEN_EXCHANGE true", "client_id in OAUTH_TOKEN_EXCHANGE_TRUSTED_CLIENT_IDS"],
    evidence=[ev("source", f"{SRC}:1605", "POST /oauth/{provider}/token/exchange -> SigninResult; trusted client ids + rate limit")],
    notes="Federated auth boundary: mints a local session from an external token. Best-effort rate limit "
          "(no caller identity pre-validation); trusts configured client ids."))

# ---- Admin: user provisioning ----------------------------------------------
API_NODES.append(node(
    K("/api/v1/auths/add"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"name": "Bob", "email": "b@c.co", "password": "***", "role": "user"},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="Name."),
                        rf("email", "body", "string", required=True, flow=True, description="Email."),
                        rf("password", "body", "string", required=True, flow=True, description="Initial password."),
                        rf("profile_image_url", "body", "string", required=False, flow=True, description="Avatar."),
                        rf("role", "body", "string", required=False, flow=True, description="Role (default pending).")],
        response=resp_json([of("id", "string", True, "New user id."), of("email", "string", True, "Email."),
                            of("name", "string", True, "Name."), of("role", "string", True, "Assigned role."),
                            of("token", "string", True, "Session token for the created user.")]),
        reason="Admin directly provisions an account with a chosen role.", evidence=f"{SRC}:1051")],
    operation_semantic="admin_add_user", statuses=[200, 400, 401], identity_statuses=ST_ADMIN,
    sem_in_decisions=[D_NAME, D_EMAIL, D_PASSWD, D_IMG, D_ROLE],
    sem_out_decisions=[D_ID, D_EMAIL, D_NAME, D_ROLE, D_TOKEN],
    route_confirmed=True, vis_reason="Admin-only provisioning.",
    evidence=[ev("source", f"{SRC}:1051", "POST /add [get_admin_user] -> AddUserResponse (returns a token)")],
    notes="Admin sets role at creation (privilege assignment); response carries a session token for the new user."))

API_NODES.append(node(
    K("/api/v1/auths/admin/details"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("name", "string", True, "Admin display name."),
                                                 of("email", "string", True, "Admin contact email.")]),
        reason="Returns the admin contact details (if ui show-admin-details enabled).", evidence=f"{SRC}:1124")],
    operation_semantic="get_admin_details", statuses=[200, 401], identity_statuses=ST_USER,
    sem_out_decisions=[D_NAME, D_EMAIL],
    route_confirmed=True, vis_reason="Any authenticated caller can read admin contact.",
    evidence=[ev("source", f"{SRC}:1124", "GET /admin/details [get_current_user]")],
    notes="Discloses the admin's name/email to any authenticated user when SHOW_ADMIN_DETAILS is on."))

# ---- Admin: auth configuration (GET+POST pairs) ----------------------------
API_NODES.append(node(
    K("/api/v1/auths/admin/config"), "api", ["GET", "POST"],
    variants=[variant("GET", response=resp_json([of("config", "object", True, "Current admin/auth config.")]),
                      reason="Reads the instance auth/admin configuration.", evidence=f"{SRC}:1155"),
              variant("POST", body_format="json", body_example={"ENABLE_SIGNUP": True, "DEFAULT_USER_ROLE": "pending"},
                      request_fields=[rf("config", "body", "object", required=True, flow=True,
                                         description="Admin config key/values (AdminConfig).")],
                      response=resp_json([of("config", "object", True, "Applied config.")]),
                      reason="Writes auth/admin configuration (signup, default role, api-key policy, JWT expiry...).",
                      evidence=f"{SRC}:1228")],
    operation_semantic="admin_auth_config", statuses=[200, 401], identity_statuses=ST_ADMIN,
    sem_in_decisions=[D_CONFIG], sem_out_decisions=[D_CONFIG],
    route_confirmed=True, vis_reason="Admin-only configuration surface.",
    evidence=[ev("source", f"{SRC}:1155", "GET /admin/config [get_admin_user]"),
              ev("source", f"{SRC}:1228", "POST /admin/config [get_admin_user] AdminConfig")],
    notes="Controls signup/default-role/api-key policy/JWT expiry; changing these reshapes the auth boundary."))

API_NODES.append(node(
    K("/api/v1/auths/admin/config/ldap/server"), "api", ["GET", "POST"],
    variants=[variant("GET", response=resp_json([of("ldap_config", "object", True, "LDAP server config "
                                                    "(app_dn_password returned/stored as secret).")]),
                      reason="Reads LDAP server/bind config.", evidence=f"{SRC}:1297"),
              variant("POST", body_format="json",
                      body_example={"host": "ldap.local", "port": 389, "app_dn": "cn=svc", "use_tls": True},
                      request_fields=[rf("ldap_config", "body", "object", required=True, flow=True,
                                         description="LdapServerConfig (host/port/app_dn/app_dn_password/tls...).")],
                      response=resp_json([of("ldap_config", "object", True, "Applied LDAP config.")]),
                      reason="Writes LDAP server/bind config incl. the bind password.", evidence=f"{SRC}:1303")],
    operation_semantic="admin_ldap_server_config", statuses=[200, 401], identity_statuses=ST_ADMIN,
    sem_in_decisions=[D_LDAPCFG], sem_out_decisions=[D_LDAPCFG],
    route_confirmed=True, vis_reason="Admin-only LDAP configuration.",
    evidence=[ev("source", f"{SRC}:1297", "GET /admin/config/ldap/server [get_admin_user]"),
              ev("source", f"{SRC}:1303", "POST /admin/config/ldap/server [get_admin_user] LdapServerConfig")],
    notes="Carries the LDAP bind secret (app_dn_password) -- a stored credential location; GT records location, not value."))

API_NODES.append(node(
    K("/api/v1/auths/admin/config/ldap"), "api", ["GET", "POST"],
    variants=[variant("GET", response=resp_json([of("ENABLE_LDAP", "boolean", True, "Whether LDAP auth is on.")]),
                      reason="Reads the LDAP enable flag.", evidence=f"{SRC}:1328"),
              variant("POST", body_format="json", body_example={"enable_ldap": True},
                      request_fields=[rf("enable_ldap", "body", "boolean", required=True, flow=True,
                                         description="Toggle LDAP auth.")],
                      response=resp_json([of("ENABLE_LDAP", "boolean", True, "New state.")]),
                      reason="Toggles the LDAP auth method.", evidence=f"{SRC}:1338")],
    operation_semantic="admin_ldap_toggle", statuses=[200, 401], identity_statuses=ST_ADMIN,
    sem_in_decisions=[dec("enable_ldap", "LdapEnabled(authz)", "state", reason="Enable/disable LDAP auth method.")],
    sem_out_decisions=[dec("ENABLE_LDAP", "LdapEnabled(authz)", "state", reason="LDAP auth method state.")],
    route_confirmed=True, vis_reason="Admin-only auth-method toggle.",
    evidence=[ev("source", f"{SRC}:1328", "GET /admin/config/ldap [get_admin_user]"),
              ev("source", f"{SRC}:1338", "POST /admin/config/ldap [get_admin_user]")],
    notes="Enables/disables an entire authentication path."))

API_NODES.append(node(
    K("/api/v1/auths/admin/config/oauth"), "api", ["GET", "POST"],
    variants=[variant("GET", response=resp_json([of("oauth_config", "object", True,
                                                    "OAuth providers config (client_secret stored as secret).")]),
                      reason="Reads OAuth provider configuration.", evidence=f"{SRC}:1483"),
              variant("POST", body_format="json",
                      body_example={"google": {"client_id": "...", "client_secret": "..."}},
                      request_fields=[rf("oauth_config", "body", "object", required=True, flow=True,
                                         description="OAuthConfigForm (per-provider client_id/client_secret/scopes).")],
                      response=resp_json([of("oauth_config", "object", True, "Applied OAuth config.")]),
                      reason="Writes OAuth provider configuration incl. client secrets.", evidence=f"{SRC}:1489")],
    operation_semantic="admin_oauth_config", statuses=[200, 401], identity_statuses=ST_ADMIN,
    sem_in_decisions=[D_OAUTHCFG], sem_out_decisions=[D_OAUTHCFG],
    route_confirmed=True, vis_reason="Admin-only OAuth configuration.",
    evidence=[ev("source", f"{SRC}:1483", "GET /admin/config/oauth [get_admin_user] -> OAuthConfigResponse"),
              ev("source", f"{SRC}:1489", "POST /admin/config/oauth [get_admin_user] OAuthConfigForm")],
    notes="Carries OAuth client secrets (stored-credential location); controls federated auth providers."))

# ---- API keys (GET+POST+DELETE on one path) --------------------------------
API_NODES.append(node(
    K("/api/v1/auths/api_key"), "api", ["GET", "POST", "DELETE"],
    variants=[variant("GET", response=resp_json([of("api_key", "string", True, "The caller's current API key.")]),
                      reason="Returns the caller's existing API key.", evidence=f"{SRC}:1553"),
              variant("POST", response=resp_json([of("api_key", "string", True, "Newly minted sk- API key.")]),
                      reason="Generates (and stores) a new personal API key.", evidence=f"{SRC}:1510"),
              variant("DELETE", response=resp_scalar("result", "boolean", "True if revoked.", value_flow=True),
                      reason="Revokes the caller's API key.", evidence=f"{SRC}:1535")],
    operation_semantic="manage_api_key", statuses=[200, 401, 403], identity_statuses=ST_USER,
    sem_out_decisions=[D_APIKEY],
    route_confirmed=True, vis_reason="Authenticated caller manages own API key.",
    reach_conds=["auth.enable_api_keys true", "features.api_keys permission (admins exempt)"],
    evidence=[ev("source", f"{SRC}:1510", "POST /api_key [_check_api_key_permission]"),
              ev("source", f"{SRC}:1535", "DELETE /api_key"), ev("source", f"{SRC}:1553", "GET /api_key")],
    notes="Mints/reads/revokes a long-lived `sk-` credential; gated by enable_api_keys + features.api_keys permission."))

PAGE_NODES = []
EDGES = []
