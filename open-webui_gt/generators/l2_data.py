# -*- coding: utf-8 -*-
"""Open WebUI HTTP API L2 action cores.

Module: Authentication + Account (/api/v1/auths). One business action per
<Subject, Operation, Object, Req, Eff>. Subjects follow the get_current_user /
get_verified_user / get_admin_user tiers. Facts use only the six Pengent
predicates; io_accounting strings via fact_key. 23 actions over 17 L1 nodes
(GET/POST/DELETE sharing a path -> one node, several actions keyed by method).
"""
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists, f_state,
                    f_can, req, eff, io, fact_key, ev)
from l2lib import action, obj, bind

AU = "/api/v1/auths"
ACTOR = subj()
AUTH = f_auth(ACTOR, "Session")                       # get_current_user
INSTANCE = entity("instance", "Instance", "authority")
CAN_VERIFIED = f_can(ACTOR, "Use", INSTANCE)          # role in {user, admin} (not pending)
CAN_ADMIN = f_can(ACTOR, "Administer", INSTANCE)      # role == admin


def kf(fact):
    return fact_key(fact)


# Shared entities
SELF = entity("self", "User", "target")
NEW_USER = entity("new_user", "User", "target")
SESSION = entity("session", "Session", "target")
ADMIN_CFG = entity("admin_config", "AdminConfig", "target")
LDAP_CFG = entity("ldap_config", "LdapServerConfig", "target")
OAUTH_CFG = entity("oauth_config", "OAuthConfig", "target")
OAUTH_SESS = entity("oauth_session", "OAuthSession", "target")
APIKEY = entity("api_key", "ApiKey", "target")
ADMIN_PROFILE = entity("admin", "AdminProfile", "target")

# Shared facts
KNOW_SESSION = f_know(ACTOR, reference("SessionToken", SESSION))
KNOW_PERMS = f_know(ACTOR, reference("Permissions", SELF))
AUTHD = f_auth(ACTOR, "Session")                      # as an effect (auth_transition)

REQ_AUTH = req("authentication", AUTH, "get_current_user resolves the JWT token / API key.")
REQ_VERIFIED = req("authorization", CAN_VERIFIED, "get_verified_user requires a non-pending role.")
REQ_ADMIN = req("authorization", CAN_ADMIN, "get_admin_user requires role == admin.")


# ============================= Session identity =============================
action(
    "owui_get_session_user", "Read own session", "Read", "get_session_user", "User",
    obj("entity", "self", "User", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(KNOW_SESSION, "io_reference", "Response returns a freshly re-issued session token."),
         eff(KNOW_PERMS, "io_reference", "Response returns the caller's effective permission map.")],
    kill=[],
    io_accounting=[io("output", "token / SessionToken(credential)", "gen", [kf(KNOW_SESSION)]),
                   io("output", "permissions / Permissions(authz)", "gen", [kf(KNOW_PERMS)]),
                   io("output", "role / UserRole(authz)", "observed_only", [], "Caller's own role, echoed.")],
    bindings=[bind(K(AU + "/"), ["GET"])],
    vis="black_box", vis_reason="Any authenticated caller reads their own session.", reachable=True,
    reach_conds=["Valid session token or API key"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:185",
                 "GET / [get_current_user] -> SessionUserInfoResponse; re-issues token")],
    confidence=0.95, reasoning="Self-scoped read that also rotates the session token.",
    description="An authenticated user reads their own session info and receives a refreshed token.",
    notes="Discloses caller role + effective permissions; re-issues a token on every call.")

# ============================= Account self-service =========================
_st_name = f_state(SELF, "name", "updated")
_st_img = f_state(SELF, "profile_image_url", "updated")
action(
    "owui_update_profile", "Update own profile", "Update", "update_profile", "VerifiedUser",
    obj("entity", "self", "User", "request", "name", "DisplayName(identity)", role="target"),
    requirements=[REQ_AUTH, REQ_VERIFIED],
    gen=[eff(_st_name, "state_transition", "Display name is replaced."),
         eff(_st_img, "state_transition", "Profile image URL is replaced.")],
    kill=[],
    io_accounting=[io("input", "name / DisplayName(identity)", "object_attribute", [], "New display name."),
                   io("input", "profile_image_url / ProfileImage(identity)", "object_attribute", [],
                      "New avatar URL (validate_image_url)."),
                   io("input", "bio / Bio(identity)", "object_attribute", [], "Free-text bio."),
                   io("output", "name / DisplayName(identity)", "gen", [kf(_st_name)]),
                   io("output", "profile_image_url / ProfileImage(identity)", "gen", [kf(_st_img)])],
    bindings=[bind(K(AU + "/update/profile"), ["POST"])],
    vis="black_box", vis_reason="Verified caller edits own profile.", reachable=True,
    reach_conds=["Non-pending role"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:253",
                 "POST /update/profile [get_verified_user] -> UserProfileImageResponse")],
    confidence=0.95, reasoning="Self profile write; name/bio are stored and reflected.",
    description="A verified user updates their own display name, avatar and bio.",
    notes="name/bio are stored-reflected (self stored-XSS surface); image URL passes validate_image_url.")

_st_tz = f_state(SELF, "timezone", "updated")
action(
    "owui_update_timezone", "Update own timezone", "Update", "update_timezone", "User",
    obj("entity", "self", "User", "request", "timezone", "Timezone(preference)", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(_st_tz, "state_transition", "Stored timezone preference is replaced.")],
    kill=[],
    io_accounting=[io("input", "timezone / Timezone(preference)", "object_attribute", [], "IANA timezone."),
                   io("output", "timezone / Timezone(preference)", "gen", [kf(_st_tz)])],
    bindings=[bind(K(AU + "/update/timezone"), ["POST"])],
    vis="black_box", vis_reason="Authenticated caller sets own preference.", reachable=True, reach_conds=[],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:288", "POST /update/timezone [get_current_user]")],
    confidence=0.9, reasoning="Low-sensitivity preference write.",
    description="An authenticated user stores their preferred timezone.", notes=None)

_know_cur_pw = f_know(ACTOR, reference("Password", SELF))
_st_pw = f_state(SELF, "password", "rotated")
action(
    "owui_update_password", "Rotate own password", "Update", "update_password", "User",
    obj("entity", "self", "User", "request", "new_password", "Password(credential)", role="target"),
    requirements=[REQ_AUTH,
                  req("knowledge", _know_cur_pw, "verify_password checks the supplied current password.")],
    gen=[eff(_st_pw, "state_transition", "The stored password hash is replaced.")],
    kill=[],
    io_accounting=[io("input", "password / Password(credential)", "req", [kf(_know_cur_pw)]),
                   io("input", "new_password / Password(credential)", "object_attribute", [], "Replacement credential."),
                   io("output", "result / Result(status)", "observed_only", [], "Boolean success flag.")],
    bindings=[bind(K(AU + "/update/password"), ["POST"])],
    vis="black_box", vis_reason="Authenticated caller rotates own credential.", reachable=True,
    reach_conds=["Knows current password"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:316",
                 "POST /update/password [get_current_user] verify_password -> bool")],
    confidence=0.95, reasoning="Credential rotation gated by current-password check.",
    description="An authenticated user changes their own password after proving the current one.",
    notes="Secrets are inputs only, never echoed.")

# ============================= Login / registration ========================
_know_ldap = f_know(ACTOR, reference("LdapCredential", entity("ldap_account", "LdapAccount", "target")))
_know_sess_new = f_know(ACTOR, reference("SessionToken", SESSION))
action(
    "owui_ldap_signin", "Sign in via LDAP", "Create", "ldap_auth", "Anonymous",
    obj("state", "session", "Session", "implicit", "", "", role="target"),
    requirements=[req("knowledge", _know_ldap, "Caller must present valid LDAP bind credentials.")],
    gen=[eff(AUTHD, "auth_transition", "A session is established on successful LDAP bind."),
         eff(_know_sess_new, "io_reference", "Response returns the session token.")],
    kill=[],
    io_accounting=[io("input", "user / LdapUsername(identity)", "object_attribute", [], "LDAP login name."),
                   io("input", "password / Password(credential)", "object_attribute", [], "LDAP password."),
                   io("output", "token / SessionToken(credential)", "gen", [kf(_know_sess_new)])],
    bindings=[bind(K(AU + "/ldap"), ["POST"])],
    vis="black_box", vis_reason="Public login endpoint (LDAP mode).", reachable=True,
    reach_conds=["LDAP enabled in admin config"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:409",
                 "POST /ldap -> SigninResult; escape_filter_chars on bind")],
    confidence=0.9, reasoning="Authentication boundary; LDAP filter chars escaped.",
    description="An anonymous caller authenticates against the configured LDAP directory and obtains a session.",
    notes="Live only when LDAP is enabled.")

action(
    "owui_password_signin", "Sign in with password", "Create", "signin", "Anonymous",
    obj("state", "session", "Session", "implicit", "", "", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("Password", SELF)),
                      "Caller must present matching email + password.")],
    gen=[eff(AUTHD, "auth_transition", "A session cookie/token is issued on valid credentials."),
         eff(_know_sess_new, "io_reference", "Response returns the session token.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(identity)", "object_attribute", [], "Account email."),
                   io("input", "password / Password(credential)", "object_attribute", [], "Account password."),
                   io("output", "token / SessionToken(credential)", "gen", [kf(_know_sess_new)])],
    bindings=[bind(K(AU + "/signin"), ["POST"])],
    vis="black_box", vis_reason="Public login endpoint.", reachable=True,
    reach_conds=["ENABLE_PASSWORD_AUTH for password mode"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:660", "POST /signin -> create_signin_response"),
              ev("source", "backend/open_webui/routers/auths.py:676",
                 "WEBUI_AUTH_TRUSTED_EMAIL/ROLE_HEADER: proxy header establishes identity + role")],
    confidence=0.95, reasoning="Primary authentication boundary; rate-limited.",
    description="An anonymous caller authenticates with email/password and receives a session cookie.",
    notes="Rate-limited (5*3/180s). Alternate modes: trusted-header (a proxy header sets BOTH identity and "
          "role -> impersonation if the header is spoofable) and WEBUI_AUTH=false (admin@localhost/admin bootstrap).")

action(
    "owui_self_register", "Register account", "Create", "signup", "Anonymous",
    obj("entity", "new_user", "User", "request", "email", "UserEmail(identity)", role="target"),
    requirements=[],
    gen=[eff(f_exists(NEW_USER), "action_semantics", "A new user account is created (first user -> admin)."),
         eff(AUTHD, "auth_transition", "The new account is signed in."),
         eff(_know_sess_new, "io_reference", "Response returns the session token.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(identity)", "object_attribute", [], "New account email."),
                   io("input", "password / Password(credential)", "object_attribute", [], "Initial password."),
                   io("input", "name / DisplayName(identity)", "object_attribute", [], "Display name."),
                   io("output", "token / SessionToken(credential)", "gen", [kf(_know_sess_new)])],
    bindings=[bind(K(AU + "/signup"), ["POST"])],
    vis="black_box", vis_reason="Public registration endpoint.", reachable=True,
    reach_conds=["ui.enable_signup (or first-ever-user bootstrap)"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:849", "POST /signup -> signup_handler; first user -> admin")],
    confidence=0.95, reasoning="Registration boundary; privilege of first user is elevated.",
    description="An anonymous caller self-registers; the first account created becomes the instance admin.",
    notes="Gated by ui.enable_signup except for the initial-admin bootstrap.")

action(
    "owui_signout", "Sign out", "Delete", "signout", "User",
    obj("state", "session", "Session", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[],
    kill=[eff(f_auth(ACTOR, "Session"), "auth_transition", "The session token is invalidated and cookies cleared.")],
    io_accounting=[],
    bindings=[bind(K(AU + "/signout"), ["POST"])],
    vis="black_box", vis_reason="Any caller may end their own session.", reachable=True, reach_conds=[],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:905",
                 "POST /signout -> invalidate_token + delete_cookie")],
    confidence=0.95, reasoning="Session teardown.",
    description="An authenticated user ends their session; token invalidated and cookies cleared.",
    notes="May 302-redirect to WEBUI_AUTH_SIGNOUT_REDIRECT_URL.")

# ============================= OAuth sessions + exchange ====================
_know_provider = f_know(ACTOR, reference("OAuthProvider", OAUTH_SESS))
action(
    "owui_delete_oauth_session", "Drop own OAuth session", "Delete", "delete_oauth_session", "VerifiedUser",
    obj("entity", "oauth_session", "OAuthSession", "path", "provider", "OAuthProvider(auth)", role="target"),
    requirements=[REQ_AUTH, REQ_VERIFIED,
                  req("knowledge", _know_provider, "Caller names the provider whose session to drop.")],
    gen=[],
    kill=[eff(f_exists(OAUTH_SESS), "state_transition", "The stored OAuth session for that provider is removed.")],
    io_accounting=[io("input", "provider / OAuthProvider(auth)", "req", [kf(_know_provider)])],
    bindings=[bind(K(AU + "/oauth/sessions/{provider}"), ["DELETE"])],
    vis="black_box", vis_reason="Verified caller manages own OAuth links.", reachable=True, reach_conds=[],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1019",
                 "DELETE /oauth/sessions/{provider:path} [get_verified_user]")],
    confidence=0.9, reasoning="Self-scoped OAuth session deletion.",
    description="A verified user removes their stored OAuth session for a given provider.", notes=None)

_know_sess_exch = f_know(ACTOR, reference("SessionToken", SESSION))
action(
    "owui_oauth_token_exchange", "Exchange IdP token for session", "Create", "oauth_token_exchange", "Anonymous",
    obj("state", "session", "Session", "request", "token", "ExternalIdpToken(credential)", role="target"),
    requirements=[req("knowledge",
                      f_know(ACTOR, reference("ExternalIdpToken", entity("idp", "IdentityProvider", "target"))),
                      "Caller must present a token minted by a trusted external IdP.")],
    gen=[eff(AUTHD, "auth_transition", "A local session is minted from the validated external token."),
         eff(_know_sess_exch, "io_reference", "Response returns the Open WebUI session token.")],
    kill=[],
    io_accounting=[io("input", "token / ExternalIdpToken(credential)", "object_attribute", [],
                      "External IdP token, validated against the provider."),
                   io("input", "provider / OAuthProvider(auth)", "object_attribute", [], "Provider to validate against."),
                   io("output", "token / SessionToken(credential)", "gen", [kf(_know_sess_exch)])],
    bindings=[bind(K(AU + "/oauth/{provider}/token/exchange"), ["POST"])],
    vis="black_box", vis_reason="Public token-exchange endpoint when enabled.", reachable=True,
    reach_conds=["ENABLE_OAUTH_TOKEN_EXCHANGE", "client_id in OAUTH_TOKEN_EXCHANGE_TRUSTED_CLIENT_IDS"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1605",
                 "POST /oauth/{provider}/token/exchange -> SigninResult; trusted client ids + rate limit")],
    confidence=0.85, reasoning="Federated auth boundary minting a local session from an external credential.",
    description="An anonymous caller exchanges a trusted external IdP token for an Open WebUI session.",
    notes="Best-effort rate limit (no caller identity before the provider answers); trusts configured client ids.")

# ============================= Admin: user provisioning =====================
_know_new_tok = f_know(ACTOR, reference("SessionToken", NEW_USER))
_st_new_role = f_state(NEW_USER, "role", "assigned")
action(
    "owui_admin_add_user", "Provision user (admin)", "Create", "admin_add_user", "Admin",
    obj("entity", "new_user", "User", "request", "email", "UserEmail(identity)", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(f_exists(NEW_USER), "action_semantics", "A new account is created directly by the admin."),
         eff(_st_new_role, "state_transition", "The admin assigns the account's role at creation."),
         eff(_know_new_tok, "io_reference", "Response returns a session token for the created user.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(identity)", "object_attribute", [], "New account email."),
                   io("input", "password / Password(credential)", "object_attribute", [], "Initial password."),
                   io("input", "role / UserRole(authz)", "object_attribute", [], "Role assigned at creation."),
                   io("output", "token / SessionToken(credential)", "gen", [kf(_know_new_tok)]),
                   io("output", "id / UserId(identity)", "observed_only", [], "New user id echoed.")],
    bindings=[bind(K(AU + "/add"), ["POST"])],
    vis="black_box", vis_reason="Admin-only provisioning.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1051",
                 "POST /add [get_admin_user] -> AddUserResponse (returns a token)")],
    confidence=0.95, reasoning="Admin creates accounts and sets privilege directly.",
    description="An admin provisions a new account with a chosen role; the response carries a session token.",
    notes="Direct privilege assignment; the returned token can bootstrap the new account's session.")

_know_admin = f_know(ACTOR, reference("AdminContact", ADMIN_PROFILE))
action(
    "owui_read_admin_details", "Read admin contact", "Read", "get_admin_details", "User",
    obj("entity", "admin", "AdminProfile", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(_know_admin, "io_reference", "Response returns the admin's name and contact email.")],
    kill=[],
    io_accounting=[io("output", "name / DisplayName(identity)", "gen", [kf(_know_admin)]),
                   io("output", "email / UserEmail(identity)", "gen", [kf(_know_admin)])],
    bindings=[bind(K(AU + "/admin/details"), ["GET"])],
    vis="black_box", vis_reason="Any authenticated caller can read admin contact.", reachable=True,
    reach_conds=["SHOW_ADMIN_DETAILS enabled"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1124", "GET /admin/details [get_current_user]")],
    confidence=0.9, reasoning="Admin contact disclosed to any authenticated user when enabled.",
    description="An authenticated user reads the configured admin's name and email.",
    notes="Information disclosure when SHOW_ADMIN_DETAILS is on.")

# ============================= Admin: auth configuration ====================
_know_admin_cfg = f_know(ACTOR, reference("AdminConfig", ADMIN_CFG))
_st_admin_cfg = f_state(ADMIN_CFG, "config", "updated")
action(
    "owui_read_admin_config", "Read auth/admin config", "Read", "read_admin_config", "Admin",
    obj("entity", "admin_config", "AdminConfig", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_know_admin_cfg, "io_reference", "Response returns the current auth/admin configuration.")],
    kill=[],
    io_accounting=[io("output", "config / AdminConfig(system)", "gen", [kf(_know_admin_cfg)])],
    bindings=[bind(K(AU + "/admin/config"), ["GET"])],
    vis="black_box", vis_reason="Admin-only configuration read.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1155", "GET /admin/config [get_admin_user]")],
    confidence=0.95, reasoning="Reads signup/role/api-key/JWT policy.",
    description="An admin reads the instance auth/admin configuration.",
    notes="Includes secret-config presence; GT records config location, not secret values.")

action(
    "owui_update_admin_config", "Update auth/admin config", "Update", "update_admin_config", "Admin",
    obj("entity", "admin_config", "AdminConfig", "request", "config", "AdminConfig(system)", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_st_admin_cfg, "state_transition", "Auth/admin policy values are replaced.")],
    kill=[],
    io_accounting=[io("input", "config / AdminConfig(system)", "object_attribute", [], "Admin config key/values."),
                   io("output", "config / AdminConfig(system)", "gen", [kf(_st_admin_cfg)])],
    bindings=[bind(K(AU + "/admin/config"), ["POST"])],
    vis="black_box", vis_reason="Admin-only configuration write.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1228", "POST /admin/config [get_admin_user] AdminConfig")],
    confidence=0.95, reasoning="Reshapes the auth boundary (signup/default-role/api-key policy/JWT expiry).",
    description="An admin writes auth/admin configuration (signup, default role, API-key policy, JWT expiry, ...).",
    notes="High-impact: changing these alters who can register and how sessions/keys are governed.")

_know_ldap_cfg = f_know(ACTOR, reference("LdapServerConfig", LDAP_CFG))
_st_ldap_cfg = f_state(LDAP_CFG, "config", "updated")
action(
    "owui_read_ldap_server_config", "Read LDAP server config", "Read", "read_ldap_server_config", "Admin",
    obj("entity", "ldap_config", "LdapServerConfig", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_know_ldap_cfg, "io_reference", "Response returns the LDAP server/bind configuration.")],
    kill=[],
    io_accounting=[io("output", "ldap_config / LdapServerConfig(system)", "gen", [kf(_know_ldap_cfg)])],
    bindings=[bind(K(AU + "/admin/config/ldap/server"), ["GET"])],
    vis="black_box", vis_reason="Admin-only LDAP config read.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1297", "GET /admin/config/ldap/server [get_admin_user]")],
    confidence=0.95, reasoning="Reads LDAP bind config incl. the stored bind-password location.",
    description="An admin reads the LDAP server/bind configuration.",
    notes="Carries the LDAP bind-secret location (app_dn_password); GT records location, not value.")

action(
    "owui_update_ldap_server_config", "Update LDAP server config", "Update", "update_ldap_server_config", "Admin",
    obj("entity", "ldap_config", "LdapServerConfig", "request", "ldap_config", "LdapServerConfig(system)", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_st_ldap_cfg, "state_transition", "LDAP server/bind settings are replaced.")],
    kill=[],
    io_accounting=[io("input", "ldap_config / LdapServerConfig(system)", "object_attribute", [],
                      "Host/port/app_dn/app_dn_password/tls."),
                   io("output", "ldap_config / LdapServerConfig(system)", "gen", [kf(_st_ldap_cfg)])],
    bindings=[bind(K(AU + "/admin/config/ldap/server"), ["POST"])],
    vis="black_box", vis_reason="Admin-only LDAP config write.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1303",
                 "POST /admin/config/ldap/server [get_admin_user] LdapServerConfig")],
    confidence=0.95, reasoning="Writes the LDAP bind endpoint + credential.",
    description="An admin writes the LDAP server/bind configuration, including the bind password.",
    notes="Sets a stored credential (app_dn_password) and the directory endpoint used for auth.")

_know_ldap_on = f_know(ACTOR, reference("LdapEnabled", LDAP_CFG))
_st_ldap_on = f_state(INSTANCE, "ldap_enabled", "toggled")
action(
    "owui_read_ldap_toggle", "Read LDAP enabled flag", "Read", "read_ldap_toggle", "Admin",
    obj("entity", "ldap_config", "LdapServerConfig", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_know_ldap_on, "io_reference", "Response returns whether LDAP auth is enabled.")],
    kill=[],
    io_accounting=[io("output", "ENABLE_LDAP / LdapEnabled(authz)", "gen", [kf(_know_ldap_on)])],
    bindings=[bind(K(AU + "/admin/config/ldap"), ["GET"])],
    vis="black_box", vis_reason="Admin-only read.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1328", "GET /admin/config/ldap [get_admin_user]")],
    confidence=0.9, reasoning="Reads the LDAP auth-method flag.",
    description="An admin reads whether the LDAP authentication method is enabled.", notes=None)

action(
    "owui_set_ldap_toggle", "Toggle LDAP auth method", "Update", "set_ldap_toggle", "Admin",
    obj("state", "instance", "Instance", "request", "enable_ldap", "LdapEnabled(authz)", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_st_ldap_on, "state_transition", "The LDAP authentication path is enabled or disabled.")],
    kill=[],
    io_accounting=[io("input", "enable_ldap / LdapEnabled(authz)", "object_attribute", [], "Toggle LDAP auth."),
                   io("output", "ENABLE_LDAP / LdapEnabled(authz)", "gen", [kf(_st_ldap_on)])],
    bindings=[bind(K(AU + "/admin/config/ldap"), ["POST"])],
    vis="black_box", vis_reason="Admin-only auth-method toggle.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1338", "POST /admin/config/ldap [get_admin_user]")],
    confidence=0.9, reasoning="Enables/disables an entire authentication path.",
    description="An admin enables or disables the LDAP authentication method.", notes=None)

_know_oauth_cfg = f_know(ACTOR, reference("OAuthConfig", OAUTH_CFG))
_st_oauth_cfg = f_state(OAUTH_CFG, "config", "updated")
action(
    "owui_read_oauth_config", "Read OAuth config", "Read", "read_oauth_config", "Admin",
    obj("entity", "oauth_config", "OAuthConfig", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_know_oauth_cfg, "io_reference", "Response returns the OAuth provider configuration.")],
    kill=[],
    io_accounting=[io("output", "oauth_config / OAuthConfig(system)", "gen", [kf(_know_oauth_cfg)])],
    bindings=[bind(K(AU + "/admin/config/oauth"), ["GET"])],
    vis="black_box", vis_reason="Admin-only read.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1483",
                 "GET /admin/config/oauth [get_admin_user] -> OAuthConfigResponse")],
    confidence=0.95, reasoning="Reads federated-auth provider config incl. secret locations.",
    description="An admin reads the OAuth provider configuration.",
    notes="Carries OAuth client-secret locations; GT records location, not value.")

action(
    "owui_update_oauth_config", "Update OAuth config", "Update", "update_oauth_config", "Admin",
    obj("entity", "oauth_config", "OAuthConfig", "request", "oauth_config", "OAuthConfig(system)", role="target"),
    requirements=[REQ_AUTH, REQ_ADMIN],
    gen=[eff(_st_oauth_cfg, "state_transition", "OAuth provider settings (incl. client secrets) are replaced.")],
    kill=[],
    io_accounting=[io("input", "oauth_config / OAuthConfig(system)", "object_attribute", [],
                      "Per-provider client_id/client_secret/scopes."),
                   io("output", "oauth_config / OAuthConfig(system)", "gen", [kf(_st_oauth_cfg)])],
    bindings=[bind(K(AU + "/admin/config/oauth"), ["POST"])],
    vis="black_box", vis_reason="Admin-only write.", reachable=True, reach_conds=["role == admin"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1489",
                 "POST /admin/config/oauth [get_admin_user] OAuthConfigForm")],
    confidence=0.95, reasoning="Controls federated identity providers + their secrets.",
    description="An admin writes the OAuth provider configuration, including client secrets.",
    notes="Controls which external IdPs can mint sessions on this instance.")

# ============================= API keys =====================================
_know_apikey = f_know(ACTOR, reference("ApiKey", APIKEY))
action(
    "owui_read_api_key", "Read own API key", "Read", "read_api_key", "User",
    obj("entity", "api_key", "ApiKey", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(_know_apikey, "io_reference", "Response returns the caller's current API key.")],
    kill=[],
    io_accounting=[io("output", "api_key / ApiKey(credential)", "gen", [kf(_know_apikey)])],
    bindings=[bind(K(AU + "/api_key"), ["GET"])],
    vis="black_box", vis_reason="Authenticated caller reads own key.", reachable=True,
    reach_conds=["auth.enable_api_keys", "features.api_keys permission (admins exempt)"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1553", "GET /api_key [get_current_user]")],
    confidence=0.9, reasoning="Returns a long-lived credential in clear to its owner.",
    description="An authenticated user reads their current `sk-` API key.",
    notes="The key is returned in clear; it is a long-lived bearer credential.")

action(
    "owui_create_api_key", "Mint own API key", "Create", "generate_api_key", "User",
    obj("entity", "api_key", "ApiKey", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(f_exists(APIKEY), "action_semantics", "A new personal API key is created and stored."),
         eff(_know_apikey, "io_reference", "Response returns the newly minted key.")],
    kill=[],
    io_accounting=[io("output", "api_key / ApiKey(credential)", "gen", [kf(_know_apikey)])],
    bindings=[bind(K(AU + "/api_key"), ["POST"])],
    vis="black_box", vis_reason="Authenticated caller mints own key.", reachable=True,
    reach_conds=["auth.enable_api_keys", "features.api_keys permission (admins exempt)"],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1510", "POST /api_key [_check_api_key_permission]")],
    confidence=0.9, reasoning="Issues a long-lived bearer credential.",
    description="An authenticated user mints a new personal API key.",
    notes="Gated by enable_api_keys + the features.api_keys permission.")

action(
    "owui_revoke_api_key", "Revoke own API key", "Delete", "delete_api_key", "User",
    obj("entity", "api_key", "ApiKey", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[],
    kill=[eff(f_exists(APIKEY), "state_transition", "The caller's API key is revoked.")],
    io_accounting=[io("output", "result / Result(status)", "observed_only", [], "Boolean success flag.")],
    bindings=[bind(K(AU + "/api_key"), ["DELETE"])],
    vis="black_box", vis_reason="Authenticated caller revokes own key.", reachable=True, reach_conds=[],
    evidence=[ev("source", "backend/open_webui/routers/auths.py:1535", "DELETE /api_key [get_current_user]")],
    confidence=0.9, reasoning="Credential teardown.",
    description="An authenticated user revokes their personal API key.", notes=None)
