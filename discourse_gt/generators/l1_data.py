# -*- coding: utf-8 -*-
"""Discourse HTTP API L1 inventory -- data table.

Module: Session + Authentication (app/controllers/session_controller.rb,
routes under /session + /login helpers in config/routes.rb). Source-first from
the controller actions: request params from params.require/permit, responses
from render json:. Auth model: session cookie `_t` + CSRF token, or
api_key/api_username. No runtime capture here (no Docker/network); samples=[],
black_box_reachable derived from source gating + before_action filters.
See environment.yaml web_gt:.

Builds: API_NODES (kind=api, io_variants -> L2 candidates), PAGE_NODES, EDGES.
"""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, resp_scalar, resp_raw, dec, dec_for, ev

SRC = "app/controllers/session_controller.rb"

# identity -> derived status codes.
ST_PUBLIC = {"anonymous": [200, 400, 403]}            # login/signup/reset endpoints
ST_PUBLIC_RL = {"anonymous": [200, 400, 403, 429]}    # rate-limited login endpoints
ST_USER = {"anonymous": [403, 404], "user": [200]}    # requires current_user

# shared decisions
D_LOGIN = dec_for("login")
D_PASSWD = dec_for("password")
D_EMAIL = dec_for("email")
D_TOKEN = dec_for("token")
D_2FA = dec_for("second_factor_token")
D_CSRF = dec_for("csrf")

API_NODES = []

# ---- CSRF / honeypot bootstrap --------------------------------------------
API_NODES.append(node(
    K("/session/csrf"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("csrf", "string", True, "Per-session CSRF (form authenticity) token.")]),
        reason="Returns form_authenticity_token for the session; required header for subsequent mutations.",
        evidence=f"{SRC}:50")],
    operation_semantic="get_csrf_token", statuses=[200], identity_statuses={"anonymous": [200], "user": [200]},
    sem_out_decisions=[D_CSRF],
    route_confirmed=True, vis_reason="Unauthenticated bootstrap endpoint for the SPA.",
    evidence=[ev("source", f"{SRC}:50", "GET /session/csrf -> {csrf: form_authenticity_token}")],
    notes="Hands out the CSRF token the Ember app attaches to mutating requests."))

API_NODES.append(node(
    K("/session/hp"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("value", "string", False, "Honeypot field value."),
        of("challenge", "string", False, "Signup challenge token.")]),
        reason="Returns honeypot/challenge values consumed by the signup form (anti-bot).",
        evidence=f"{SRC}:838")],
    operation_semantic="get_honeypot_value", statuses=[200], identity_statuses={"anonymous": [200]},
    route_confirmed=True, vis_reason="Unauthenticated signup-form bootstrap.",
    evidence=[ev("source", f"{SRC}:838", "GET /session/hp -> {value, challenge}")],
    notes="Anti-automation tokens; not business data (flow=false)."))

# ---- Primary password login + logout --------------------------------------
API_NODES.append(node(
    K("/session"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"login": "alice", "password": "***", "second_factor_token": "123456",
                      "second_factor_method": 1},
        request_fields=[rf("login", "body", "string", required=True, flow=True,
                           description="Username or email (find_by_username_or_email)."),
                        rf("password", "body", "string", required=True, flow=True,
                           description="Account password (confirm_password?)."),
                        rf("second_factor_token", "body", "string", required=False, flow=True,
                           description="TOTP/backup 2FA token when 2FA is enabled."),
                        rf("second_factor_method", "body", "integer", required=False, flow=False,
                           description="2FA method selector (TOTP/backup/security key).")],
        response=resp_json([of("user", "object", True, "Serialized logged-in user (session cookie set)."),
                            of("error", "string", False, "Error/reason on failure (invalid/expired/not_approved).")]),
        reason="Password login: verifies credentials, enforces approval/activation + 2FA, establishes session.",
        evidence=f"{SRC}:362")],
    operation_semantic="password_login", statuses=[200, 400, 403, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_LOGIN, D_PASSWD, D_2FA],
    sem_out_decisions=[dec("user", "UserProfile(identity)", "content", mergeable=True,
                           reason="Authenticated user's serialized profile returned on success.")],
    route_confirmed=True, vis_reason="Primary unauthenticated login boundary.",
    reach_conds=["Local login enabled (check_local_login_allowed)", "Not SSO-only"],
    evidence=[ev("source", f"{SRC}:362", "POST /session require(:login,:password); confirm_password?; login(user)"),
              ev("source", f"{SRC}:13", "rate_limit_login before_action")],
    notes="Auth boundary. Rate-limited per-IP and per-account; enforces approval, activation, password "
          "expiry and second factor. Generic invalid_credentials (no user enumeration on the password check)."))

API_NODES.append(node(
    K("/session/{id}"), "api", ["DELETE"],
    params=[{"name": "id", "in": "path", "type": "string", "required": True, "flow": True,
             "description": "Username of the session to end (id: RouteFormat.username)."}],
    variants=[variant("DELETE", body_format="json",
        body_example={"return_url": "/", "push_subscription": {"endpoint": "https://...", "keys": {}}},
        request_fields=[rf("return_url", "body", "string", required=False, flow=False,
                           description="Post-logout redirect target (validated)."),
                        rf("push_subscription", "body", "object", required=False, flow=False,
                           description="Web-push subscription to detach (endpoint + p256dh/auth keys).")],
        response=resp_json([of("redirect_url", "string", False, "Where to send the client after logout.")]),
        reason="Ends the current session (log out) and optionally detaches a push subscription.",
        evidence=f"{SRC}:785")],
    operation_semantic="logout", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Requires an active session.",
    evidence=[ev("source", f"{SRC}:785", "DELETE /session/:id -> reset_session + redirect_url"),
              ev("source", f"{SRC}:821", "permit push_subscription(endpoint, keys[p256dh,auth])")],
    notes="Session teardown; return_url is validated to prevent open-redirect."))

API_NODES.append(node(
    K("/session/current"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("current_user", "object", True, "Serialized current user (CurrentUserSerializer).")]),
        reason="Returns the signed-in user; 404 body when anonymous.", evidence=f"{SRC}:777")],
    operation_semantic="get_current_user", statuses=[200, 404], identity_statuses=ST_USER,
    sem_out_decisions=[dec("current_user", "UserProfile(identity)", "content", mergeable=True,
                           reason="Caller's own session identity + preferences.")],
    route_confirmed=True, vis_reason="Reflects the caller's own session.",
    evidence=[ev("source", f"{SRC}:777", "GET /session/current -> CurrentUserSerializer or 404")],
    notes="Self identity endpoint used by the SPA bootstrap."))

API_NODES.append(node(
    K("/session/scopes"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("scopes", "array", True, "Granted API scopes for the current API-key session.")]),
        reason="Lists the scopes of the API key authenticating the request; 404 if not API-scoped.",
        evidence=f"{SRC}:849")],
    operation_semantic="get_api_scopes", statuses=[200, 404], identity_statuses=ST_USER,
    sem_out_decisions=[dec("scopes", "ApiScopes(authz)", "collection", mergeable=True,
                           reason="Authorization scopes attached to the API key.")],
    route_confirmed=True, vis_reason="Reflects the caller's API-key scopes.",
    evidence=[ev("source", f"{SRC}:849", "GET /session/scopes -> scopes or 404")],
    notes="Only meaningful for API-key authenticated requests."))

# ---- Password reset flow ---------------------------------------------------
API_NODES.append(node(
    K("/session/forgot_password"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"login": "alice"},
        request_fields=[rf("login", "body", "string", required=True, flow=True,
                           description="Username or email to send a reset link to.")],
        response=resp_json([of("user_found", "boolean", False,
                               "Present only when hide_email_address_taken is off; omitted otherwise.")]),
        reason="Initiates a password reset; response is deliberately generic to avoid account enumeration.",
        evidence=f"{SRC}:713")],
    operation_semantic="forgot_password", statuses=[200, 429], identity_statuses=ST_PUBLIC,
    sem_in_decisions=[D_LOGIN],
    route_confirmed=True, vis_reason="Unauthenticated reset-request endpoint.",
    reach_conds=["Local logins allowed"],
    evidence=[ev("source", f"{SRC}:713", "POST /session/forgot_password require(:login); rate limited")],
    notes="Enumeration-resistant: does not confirm whether an account exists (unless setting disabled)."))

API_NODES.append(node(
    K("/session/password-reset-code/verify"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"token": "<reset-token>", "password": "***", "second_factor_token": "123456"},
        request_fields=[rf("token", "body", "string", required=True, flow=True,
                           description="Password-reset code from the email link."),
                        rf("password", "body", "string", required=False, flow=True,
                           description="New password to set when redeeming."),
                        rf("second_factor_token", "body", "string", required=False, flow=True,
                           description="2FA token if enabled.")],
        response=resp_json([of("success", "string", False, "Status, or errors on failure.")]),
        reason="Redeems a password-reset code, optionally setting a new password + enforcing 2FA.",
        evidence=f"{SRC}:754")],
    operation_semantic="redeem_password_reset_code", statuses=[200, 400], identity_statuses=ST_PUBLIC,
    sem_in_decisions=[D_TOKEN, D_PASSWD, D_2FA],
    route_confirmed=True, vis_reason="Unauthenticated reset-redemption endpoint (token-gated).",
    evidence=[ev("source", f"{SRC}:754", "POST /session/password-reset-code/verify")],
    notes="Token-scoped credential reset; 2FA still enforced on redemption."))

# ---- Email (magic-link) login ---------------------------------------------
API_NODES.append(node(
    K("/session/email-login/{token}"), "api", ["GET", "POST"],
    params=[{"name": "token", "in": "path", "type": "string", "required": True, "flow": True,
             "description": "Email-login token from the magic link."}],
    variants=[variant("GET", response=resp_json([
                          of("can_login", "boolean", False, "Whether the token is valid/usable."),
                          of("second_factor_required", "boolean", False, "Whether 2FA is needed."),
                          of("error", "string", False, "Error when the token is invalid/expired.")]),
                      reason="Returns login-eligibility + 2FA requirement for an email-login token.",
                      evidence=f"{SRC}:456"),
              variant("POST", body_format="json",
                      body_example={"second_factor_token": "123456", "timezone": "Asia/Singapore"},
                      request_fields=[rf("second_factor_token", "body", "string", required=False, flow=True,
                                         description="2FA token when required."),
                                      rf("timezone", "body", "string", required=False, flow=False,
                                         description="Client timezone stored on first login.")],
                      response=resp_json([of("error", "string", False, "Invalid-token error, or success.")]),
                      reason="Consumes the email-login token, enforces 2FA, and establishes a session.",
                      evidence=f"{SRC}:493")],
    operation_semantic="email_login", statuses=[200, 400, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_2FA], sem_out_decisions=[dec("session", "AuthSession(auth)", "state", mergeable=True,
                                                     reason="Session established on token redemption.")],
    route_confirmed=True, vis_reason="Unauthenticated magic-link login (token-gated).",
    reach_conds=["enable_local_logins_via_email"],
    evidence=[ev("source", f"{SRC}:456", "GET /session/email-login/:token -> info"),
              ev("source", f"{SRC}:493", "POST /session/email-login/:token -> login"),
              ev("source", f"{SRC}:13", "rate_limit_login on email_login")],
    notes="Passwordless login boundary; token is the sole credential. Rate-limited; 2FA still enforced."))

# ---- Login code (one-time code) -------------------------------------------
API_NODES.append(node(
    K("/session/login-code"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"login": "alice@example.com"},
        request_fields=[rf("login", "body", "string", required=True, flow=True,
                           description="Email/username to send a one-time login code to."),
                        rf("invite_key", "body", "string", required=False, flow=False,
                           description="Invite key when the code is requested via an invite.")],
        response=resp_empty(),
        reason="Requests a one-time login code (sent out-of-band); honeypot + rate limited.",
        evidence=f"{SRC}:525")],
    operation_semantic="create_login_code", statuses=[200, 400, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_LOGIN],
    route_confirmed=True, vis_reason="Unauthenticated code-request endpoint.",
    reach_conds=["ensure_login_code_allowed"],
    evidence=[ev("source", f"{SRC}:525", "POST /session/login-code; honeypot + rate_limit_login_code_request")],
    notes="Enumeration-resistant (always success_json on honeypot); IP registration limit enforced."))

API_NODES.append(node(
    K("/session/login-code/verify"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"login": "alice@example.com", "login_code": "123456"},
        request_fields=[rf("login", "body", "string", required=True, flow=True, description="Email/username."),
                        rf("login_code", "body", "string", required=True, flow=True,
                           description="One-time login code to verify."),
                        rf("signup_token", "body", "string", required=False, flow=False,
                           description="Signup token when verifying during registration.")],
        response=resp_json([of("error", "string", False, "invalid_login_code or success.")]),
        reason="Verifies a one-time login code and signs the user in (or completes signup).",
        evidence=f"{SRC}:548")],
    operation_semantic="verify_login_code", statuses=[200, 400, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_LOGIN, dec("login_code", "LoginCode(credential)", "credential", mergeable=True,
                                   reason="One-time code acting as the login credential.")],
    sem_out_decisions=[dec("session", "AuthSession(auth)", "state", mergeable=True,
                           reason="Session established on code verification.")],
    route_confirmed=True, vis_reason="Unauthenticated code-verification login boundary.",
    reach_conds=["ensure_login_code_allowed"],
    evidence=[ev("source", f"{SRC}:548", "POST /session/login-code/verify; rate_limit_login_code_verify")],
    notes="Passwordless login boundary; rate-limited on verification attempts."))

# ---- One-time password (cross-login OTP) ----------------------------------
API_NODES.append(node(
    K("/session/otp/{token}"), "api", ["GET", "POST"],
    params=[{"name": "token", "in": "path", "type": "string", "required": True, "flow": True,
             "description": "OTP token (hex) from redis otp_<token>."}],
    variants=[variant("GET", response=resp_raw("HTML confirmation page (no_ember layout)."),
                      reason="Shows the OTP confirmation page for a one-time cross-login token.",
                      evidence=f"{SRC}:562"),
              variant("POST", response=resp_empty(),
                      reason="Consumes the OTP token and logs the resolved user in.",
                      evidence=f"{SRC}:562")],
    operation_semantic="one_time_password", statuses=[200, 404], identity_statuses={"anonymous": [200, 404]},
    content_types=["text/html", "application/json"],
    route_confirmed=True, vis_reason="Token-gated one-time cross-login (e.g. from another device).",
    evidence=[ev("source", f"{SRC}:562", "GET/POST /session/otp/:token; Discourse.redis otp_<token>")],
    notes="Single-use OTP resolved from redis; token deleted on use."))

# ---- Interactive 2FA challenge (second_factor_auth) -----------------------
API_NODES.append(node(
    K("/session/2fa"), "api", ["GET", "POST"],
    params=[{"name": "nonce", "in": "query", "type": "string", "required": True, "flow": True,
             "description": "Server-issued 2FA challenge nonce."}],
    variants=[variant("GET", response=resp_json([
                          of("totp_enabled", "boolean", False, "Whether TOTP is available."),
                          of("security_keys_enabled", "boolean", False, "Whether security keys are available."),
                          of("description", "string", False, "What the 2FA step is authorizing.")]),
                      reason="Shows the 2FA challenge for a protected action gated by a nonce.",
                      evidence=f"{SRC}:583"),
              variant("POST", body_format="json",
                      body_example={"nonce": "<nonce>", "second_factor_method": 1, "second_factor_token": "123456"},
                      request_fields=[rf("nonce", "body", "string", required=True, flow=True,
                                         description="Challenge nonce being satisfied."),
                                      rf("second_factor_token", "body", "string", required=False, flow=True,
                                         description="TOTP/backup token or security-key assertion."),
                                      rf("second_factor_method", "body", "integer", required=False, flow=False,
                                         description="2FA method selector.")],
                      response=resp_json([of("ok", "boolean", False, "Whether 2FA succeeded."),
                                          of("callback_method", "string", False, "How to resume the gated action."),
                                          of("redirect_url", "string", False, "Where to continue after success.")]),
                      reason="Performs the 2FA step for a nonce-gated sensitive action and resumes it.",
                      evidence=f"{SRC}:640")],
    operation_semantic="second_factor_auth", statuses=[200, 400], identity_statuses=ST_USER,
    sem_in_decisions=[D_2FA],
    route_confirmed=True, vis_reason="Reauthentication gate for sensitive actions.",
    evidence=[ev("source", f"{SRC}:583", "GET /session/2fa require(:nonce)"),
              ev("source", f"{SRC}:640", "POST /session/2fa require(:nonce); authenticate")],
    notes="Generic step-up 2FA gate; the nonce ties the challenge to a specific pending action."))

# ---- Passkeys (WebAuthn) ---------------------------------------------------
API_NODES.append(node(
    K("/session/passkey/challenge"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("challenge", "string", True, "WebAuthn passkey challenge to sign.")]),
        reason="Stages a WebAuthn challenge for passkey authentication.", evidence=f"{SRC}:419")],
    operation_semantic="passkey_challenge", statuses=[200], identity_statuses={"anonymous": [200], "user": [200]},
    sem_out_decisions=[dec("challenge", "WebauthnChallenge(credential)", "opaque", mergeable=True,
                           reason="Server nonce the authenticator signs.")],
    route_confirmed=True, vis_reason="Unauthenticated passkey-login bootstrap.",
    evidence=[ev("source", f"{SRC}:419", "GET /session/passkey/challenge -> stage_challenge")],
    notes="WebAuthn challenge issuance; staged in the server session."))

API_NODES.append(node(
    K("/session/passkey/auth"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"publicKeyCredential": {"id": "...", "response": {}}},
        request_fields=[rf("publicKeyCredential", "body", "object", required=True, flow=True,
                           description="WebAuthn assertion (credential id + signed response).")],
        response=resp_json([of("user", "object", True, "Logged-in user on valid assertion."),
                            of("error", "string", False, "Failure/ not-approved payload.")]),
        reason="Verifies a WebAuthn passkey assertion and establishes a session.",
        evidence=f"{SRC}:423")],
    operation_semantic="passkey_login", statuses=[200, 400, 401], identity_statuses={"anonymous": [200, 401]},
    sem_in_decisions=[dec("publicKeyCredential", "WebauthnAssertion(credential)", "credential", mergeable=True,
                          reason="Signed authenticator assertion acting as the login credential.")],
    sem_out_decisions=[dec("user", "UserProfile(identity)", "content", mergeable=True,
                           reason="Authenticated user returned on success.")],
    route_confirmed=True, vis_reason="Unauthenticated passkey-login boundary.",
    evidence=[ev("source", f"{SRC}:423", "POST /session/passkey/auth require(:publicKeyCredential)")],
    notes="Passwordless login boundary; approval/activation checks still apply."))

# ---- DiscourseConnect (SSO) -----------------------------------------------
API_NODES.append(node(
    K("/session/sso"), "api", ["GET"],
    params=[{"name": "return_path", "in": "query", "type": "string", "required": False, "flow": False,
             "description": "Where to return after SSO (validated)."}],
    variants=[variant("GET", response=resp_raw("302 redirect to the configured SSO provider."),
        reason="Begins DiscourseConnect SSO: redirects the browser to the external provider.",
        evidence=f"{SRC}:54")],
    operation_semantic="sso_begin", statuses=[302, 400], identity_statuses={"anonymous": [302, 400]},
    content_types=["text/html"],
    route_confirmed=True, vis_reason="Unauthenticated SSO entry (when SSO enabled).",
    reach_conds=["enable_discourse_connect"],
    evidence=[ev("source", f"{SRC}:54", "GET /session/sso -> redirect to sso_url")],
    notes="SSO handoff; return_path validated to prevent open-redirect."))

API_NODES.append(node(
    K("/session/sso_login"), "api", ["GET"],
    params=[{"name": "sso", "in": "query", "type": "string", "required": True, "flow": True,
             "description": "Signed SSO payload from the provider (base64)."},
            {"name": "sig", "in": "query", "type": "string", "required": True, "flow": True,
             "description": "HMAC signature over the sso payload."}],
    variants=[variant("GET", response=resp_raw("302 redirect after establishing the SSO session, or error page."),
        reason="DiscourseConnect callback: verifies the signed payload, provisions/logs in the user.",
        evidence=f"{SRC}:197")],
    operation_semantic="sso_login", statuses=[200, 302, 403, 422], identity_statuses={"anonymous": [302, 403, 422]},
    content_types=["text/html"],
    sem_in_decisions=[dec("sso", "SsoPayload(auth)", "content", mergeable=True,
                          reason="Provider-signed identity assertion (email/external_id/groups...)."),
                      dec("sig", "SsoSignature(credential)", "credential", mergeable=True,
                          reason="HMAC proving the payload came from the trusted provider.")],
    route_confirmed=True, vis_reason="Unauthenticated SSO callback (signature-gated).",
    reach_conds=["enable_discourse_connect", "valid HMAC over the shared secret"],
    evidence=[ev("source", f"{SRC}:197", "GET /session/sso_login require(:sso,:sig)")],
    notes="FEDERATED AUTH BOUNDARY: a valid signature mints/updates a local account (incl. role/group sync). "
          "Security hinges on the shared-secret HMAC and nonce validation."))

API_NODES.append(node(
    K("/session/sso_provider"), "api", ["GET"],
    params=[{"name": "sso", "in": "query", "type": "string", "required": True, "flow": True,
             "description": "Signed SSO request from a consuming site."},
            {"name": "sig", "in": "query", "type": "string", "required": True, "flow": True,
             "description": "HMAC signature over the sso request."}],
    variants=[variant("GET", response=resp_json([
        of("redirect_url", "string", True, "Signed return URL carrying this site's identity assertion.")]),
        reason="Discourse-as-SSO-provider: signs this site's user identity back to a consuming site.",
        evidence=f"{SRC}:73")],
    operation_semantic="sso_provider", statuses=[200, 400, 422], identity_statuses=ST_USER,
    content_types=["text/html", "application/json"],
    sem_in_decisions=[dec("sso", "SsoProviderRequest(auth)", "content", mergeable=True,
                          reason="Consuming site's signed SSO request (nonce + return_sso_url)."),
                      dec("sig", "SsoSignature(credential)", "credential", mergeable=True,
                          reason="HMAC proving the request came from a registered consumer.")],
    sem_out_decisions=[dec("redirect_url", "SsoAssertion(auth)", "locator", reference_capable=True,
                           reason="Signed assertion of this site's user identity, as a return URL.")],
    route_confirmed=True, vis_reason="Requires a local session to assert identity to the consumer.",
    reach_conds=["enable_discourse_connect_provider", "requesting site registered with a secret"],
    evidence=[ev("source", f"{SRC}:73", "GET /session/sso_provider sign user identity -> redirect_url")],
    notes="Discourse acts as IdP: emits a signed identity assertion for a downstream consumer."))

# ===========================================================================
# Additional modules (one file per controller group; each exports NODES).
# ===========================================================================
import importlib

_MODULES = [
    "l1_users", "l1_account", "l1_topics", "l1_posts", "l1_categories",
    "l1_tags", "l1_groups", "l1_invites", "l1_notifications", "l1_uploads",
    "l1_bookmarks_drafts", "l1_misc", "l1_reviewables", "l1_admin_core",
    "l1_admin_users", "l1_admin_content",
]
for _m in _MODULES:
    try:
        _mod = importlib.import_module(_m)
    except ModuleNotFoundError:
        continue
    API_NODES += list(getattr(_mod, "NODES", []))

PAGE_NODES = []
EDGES = []
