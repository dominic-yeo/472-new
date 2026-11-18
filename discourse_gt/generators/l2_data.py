# -*- coding: utf-8 -*-
"""Discourse HTTP API L2 action cores.

Module: Session + Authentication (SessionController). One business action per
<Subject, Operation, Object, Req, Eff>. Subjects follow Guardian tiers
(Anonymous / User / Staff / Admin). Facts use only the six Pengent predicates;
io_accounting strings via fact_key. 21 actions over 18 L1 nodes (GET/POST on a
shared path -> one node, several actions keyed by method).
"""
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists, f_state,
                    f_can, req, eff, io, fact_key, ev)
from l2lib import action, obj, bind

S = "/session"
ACTOR = subj()
AUTH = f_auth(ACTOR, "Session")
SELF = entity("self", "User", "target")
SESSION = entity("session", "Session", "target")
AUTHD = f_auth(ACTOR, "Session")           # as an effect (auth_transition)

REQ_AUTH = req("authentication", AUTH, "current_user must be present (signed-in session or API key).")


def kf(fact):
    return fact_key(fact)


# ============================= Bootstrap tokens =============================
_know_csrf = f_know(ACTOR, reference("CsrfToken", SESSION))
action(
    "disc_get_csrf", "Get CSRF token", "Read", "get_csrf_token", "Anonymous",
    obj("entity", "session", "Session", "implicit", "", "", role="target"),
    requirements=[],
    gen=[eff(_know_csrf, "io_reference", "Response returns the session CSRF token.")],
    kill=[],
    io_accounting=[io("output", "csrf / CsrfToken(credential)", "gen", [kf(_know_csrf)])],
    bindings=[bind(K(S + "/csrf"), ["GET"])],
    vis="black_box", vis_reason="Unauthenticated SPA bootstrap.", reachable=True, reach_conds=[],
    evidence=[ev("source", "app/controllers/session_controller.rb:50", "GET /session/csrf -> {csrf}")],
    confidence=0.95, reasoning="Hands out the CSRF token for later mutations.",
    description="Any caller fetches the per-session CSRF token used to authorize mutations.", notes=None)

_know_hp = f_know(ACTOR, reference("Honeypot", SESSION))
action(
    "disc_get_honeypot", "Get signup honeypot", "Read", "get_honeypot_value", "Anonymous",
    obj("entity", "session", "Session", "implicit", "", "", role="target"),
    requirements=[],
    gen=[eff(_know_hp, "io_reference", "Response returns the signup honeypot/challenge values.")],
    kill=[],
    io_accounting=[io("output", "challenge / Honeypot(antibot)", "observed_only", [], "Anti-bot token, not business data.")],
    bindings=[bind(K(S + "/hp"), ["GET"])],
    vis="black_box", vis_reason="Unauthenticated signup bootstrap.", reachable=True, reach_conds=[],
    evidence=[ev("source", "app/controllers/session_controller.rb:838", "GET /session/hp -> {value, challenge}")],
    confidence=0.9, reasoning="Anti-automation values for the signup form.",
    description="Any caller fetches the honeypot + challenge values the signup form must echo back.", notes=None)

# ============================= Password login + logout =====================
_know_user = f_know(ACTOR, reference("UserProfile", SELF))
action(
    "disc_password_login", "Log in with password", "Create", "password_login", "Anonymous",
    obj("state", "session", "Session", "request", "login", "LoginName(identity)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("Password", SELF)),
                      "Caller must present login + matching password (confirm_password?).")],
    gen=[eff(AUTHD, "auth_transition", "A session is established on valid credentials + 2FA."),
         eff(_know_user, "io_reference", "Response returns the serialized logged-in user.")],
    kill=[],
    io_accounting=[io("input", "login / LoginName(identity)", "object_attribute", [], "Username or email."),
                   io("input", "password / Password(credential)", "object_attribute", [], "Account password."),
                   io("input", "second_factor_token / SecondFactorToken(credential)", "object_attribute", [],
                      "2FA token when enabled."),
                   io("output", "user / UserProfile(identity)", "gen", [kf(_know_user)])],
    bindings=[bind(K(S), ["POST"])],
    vis="black_box", vis_reason="Primary unauthenticated login boundary.", reachable=True,
    reach_conds=["Local login enabled", "Not SSO-only"],
    evidence=[ev("source", "app/controllers/session_controller.rb:362", "POST /session confirm_password?; login(user)"),
              ev("source", "app/controllers/session_controller.rb:13", "rate_limit_login")],
    confidence=0.95, reasoning="Credential + 2FA auth boundary; rate-limited.",
    description="An anonymous caller authenticates with username/email + password (and 2FA) to open a session.",
    notes="Rate-limited per IP and per account; enforces approval/activation/password-expiry/2FA. "
          "Generic invalid_credentials avoids user enumeration on the password check.")

action(
    "disc_logout", "Log out", "Delete", "logout", "User",
    obj("state", "session", "Session", "path", "id", "Username(identity)", role="target"),
    requirements=[REQ_AUTH],
    gen=[],
    kill=[eff(f_auth(ACTOR, "Session"), "auth_transition", "The current session is reset (logged out).")],
    io_accounting=[],
    bindings=[bind(K(S + "/{id}"), ["DELETE"])],
    vis="black_box", vis_reason="Requires an active session.", reachable=True, reach_conds=[],
    evidence=[ev("source", "app/controllers/session_controller.rb:785", "DELETE /session/:id -> reset_session")],
    confidence=0.95, reasoning="Session teardown.",
    description="A signed-in user ends their session; return_url is validated against open-redirect.",
    notes="Optionally detaches a web-push subscription.")

action(
    "disc_current_user", "Read own session identity", "Read", "get_current_user", "User",
    obj("entity", "self", "User", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(_know_user, "io_reference", "Response returns the caller's own serialized user.")],
    kill=[],
    io_accounting=[io("output", "current_user / UserProfile(identity)", "gen", [kf(_know_user)])],
    bindings=[bind(K(S + "/current"), ["GET"])],
    vis="black_box", vis_reason="Reflects the caller's own session.", reachable=True, reach_conds=[],
    evidence=[ev("source", "app/controllers/session_controller.rb:777", "GET /session/current -> CurrentUserSerializer")],
    confidence=0.95, reasoning="Self identity read.",
    description="A signed-in user reads their own identity/preferences; 404 when anonymous.", notes=None)

_know_scopes = f_know(ACTOR, reference("ApiScopes", SELF))
action(
    "disc_api_scopes", "Read API-key scopes", "Read", "get_api_scopes", "User",
    obj("entity", "self", "User", "implicit", "", "", role="target"),
    requirements=[REQ_AUTH],
    gen=[eff(_know_scopes, "io_reference", "Response returns the authenticating API key's scopes.")],
    kill=[],
    io_accounting=[io("output", "scopes / ApiScopes(authz)", "gen", [kf(_know_scopes)])],
    bindings=[bind(K(S + "/scopes"), ["GET"])],
    vis="black_box", vis_reason="Reflects the caller's API-key scopes.", reachable=True,
    reach_conds=["Request authenticated by an API key"],
    evidence=[ev("source", "app/controllers/session_controller.rb:849", "GET /session/scopes -> scopes or 404")],
    confidence=0.85, reasoning="Discloses the authorization scope of the API key.",
    description="An API-key caller reads the scopes granted to their key.", notes=None)

# ============================= Password reset ==============================
action(
    "disc_forgot_password", "Request password reset", "Create", "forgot_password", "Anonymous",
    obj("entity", "self", "User", "request", "login", "LoginName(identity)", role="target"),
    requirements=[],
    gen=[eff(f_state(SELF, "password_reset", "requested"), "action_semantics",
             "A reset email is sent if the account exists (response is generic).")],
    kill=[],
    io_accounting=[io("input", "login / LoginName(identity)", "object_attribute", [], "Username or email.")],
    bindings=[bind(K(S + "/forgot_password"), ["POST"])],
    vis="black_box", vis_reason="Unauthenticated reset-request endpoint.", reachable=True,
    reach_conds=["Local logins allowed"],
    evidence=[ev("source", "app/controllers/session_controller.rb:713", "POST /session/forgot_password require(:login)")],
    confidence=0.9, reasoning="Reset initiation; enumeration-resistant.",
    description="An anonymous caller requests a password-reset link for an account.",
    notes="Deliberately does not reveal whether the account exists (unless hide_email_address_taken is off).")

_st_pw = f_state(SELF, "password", "reset")
action(
    "disc_redeem_reset", "Redeem password reset", "Update", "redeem_password_reset_code", "Anonymous",
    obj("entity", "self", "User", "request", "token", "AuthToken(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("AuthToken", SELF)),
                      "Caller must present the reset token from the email link.")],
    gen=[eff(_st_pw, "state_transition", "The account password is replaced; session may be established."),
         eff(AUTHD, "auth_transition", "A session is opened on successful redemption.")],
    kill=[],
    io_accounting=[io("input", "token / AuthToken(credential)", "req", [kf(f_know(ACTOR, reference("AuthToken", SELF)))]),
                   io("input", "password / Password(credential)", "object_attribute", [], "New password."),
                   io("input", "second_factor_token / SecondFactorToken(credential)", "object_attribute", [],
                      "2FA token if enabled.")],
    bindings=[bind(K(S + "/password-reset-code/verify"), ["POST"])],
    vis="black_box", vis_reason="Token-gated credential reset.", reachable=True, reach_conds=["Valid reset token"],
    evidence=[ev("source", "app/controllers/session_controller.rb:754", "POST /session/password-reset-code/verify")],
    confidence=0.9, reasoning="Token-scoped credential rotation; 2FA still enforced.",
    description="An anonymous caller redeems a password-reset token to set a new password.", notes=None)

# ============================= Email (magic-link) login ====================
_know_elinfo = f_know(ACTOR, reference("EmailLoginInfo", SELF))
action(
    "disc_email_login_info", "Check email-login token", "Read", "email_login_info", "Anonymous",
    obj("entity", "self", "User", "path", "token", "AuthToken(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("AuthToken", SELF)),
                      "Caller presents the email-login token to check eligibility.")],
    gen=[eff(_know_elinfo, "io_reference", "Response reports token validity + whether 2FA is required.")],
    kill=[],
    io_accounting=[io("input", "token / AuthToken(credential)", "req", [kf(f_know(ACTOR, reference("AuthToken", SELF)))]),
                   io("output", "second_factor_required / EmailLoginInfo(auth)", "gen", [kf(_know_elinfo)])],
    bindings=[bind(K(S + "/email-login/{token}"), ["GET"])],
    vis="black_box", vis_reason="Token-gated pre-login check.", reachable=True,
    reach_conds=["enable_local_logins_via_email"],
    evidence=[ev("source", "app/controllers/session_controller.rb:456", "GET /session/email-login/:token -> info")],
    confidence=0.9, reasoning="Reports eligibility for a magic-link token.",
    description="An anonymous caller checks whether an email-login token is usable and needs 2FA.", notes=None)

action(
    "disc_email_login", "Log in via email token", "Create", "email_login", "Anonymous",
    obj("state", "session", "Session", "path", "token", "AuthToken(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("AuthToken", SELF)),
                      "The email-login token is the sole credential.")],
    gen=[eff(AUTHD, "auth_transition", "A session is established on valid token + 2FA."),
         eff(f_know(ACTOR, reference("UserProfile", SELF)), "io_reference", "The user is signed in.")],
    kill=[],
    io_accounting=[io("input", "token / AuthToken(credential)", "req", [kf(f_know(ACTOR, reference("AuthToken", SELF)))]),
                   io("input", "second_factor_token / SecondFactorToken(credential)", "object_attribute", [],
                      "2FA token when required.")],
    bindings=[bind(K(S + "/email-login/{token}"), ["POST"])],
    vis="black_box", vis_reason="Passwordless login boundary.", reachable=True,
    reach_conds=["enable_local_logins_via_email"],
    evidence=[ev("source", "app/controllers/session_controller.rb:493", "POST /session/email-login/:token -> login"),
              ev("source", "app/controllers/session_controller.rb:13", "rate_limit_login")],
    confidence=0.9, reasoning="Token-only auth boundary; rate-limited; 2FA enforced.",
    description="An anonymous caller redeems a magic-link token to sign in.", notes=None)

# ============================= Login code (OTP by email) ===================
action(
    "disc_create_login_code", "Request login code", "Create", "create_login_code", "Anonymous",
    obj("entity", "self", "User", "request", "login", "LoginName(identity)", role="target"),
    requirements=[],
    gen=[eff(f_state(SELF, "login_code", "requested"), "action_semantics",
             "A one-time login code is sent out-of-band (generic response).")],
    kill=[],
    io_accounting=[io("input", "login / LoginName(identity)", "object_attribute", [], "Email/username.")],
    bindings=[bind(K(S + "/login-code"), ["POST"])],
    vis="black_box", vis_reason="Unauthenticated code-request endpoint.", reachable=True,
    reach_conds=["ensure_login_code_allowed"],
    evidence=[ev("source", "app/controllers/session_controller.rb:525", "POST /session/login-code; honeypot + rate limit")],
    confidence=0.85, reasoning="Enumeration-resistant code request.",
    description="An anonymous caller requests a one-time login code by email.", notes=None)

action(
    "disc_verify_login_code", "Verify login code", "Create", "verify_login_code", "Anonymous",
    obj("state", "session", "Session", "request", "login_code", "LoginCode(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("LoginCode", SELF)),
                      "Caller presents the one-time login code.")],
    gen=[eff(AUTHD, "auth_transition", "A session is established on a valid code."),
         eff(f_know(ACTOR, reference("UserProfile", SELF)), "io_reference", "The user is signed in.")],
    kill=[],
    io_accounting=[io("input", "login_code / LoginCode(credential)", "req", [kf(f_know(ACTOR, reference("LoginCode", SELF)))]),
                   io("input", "login / LoginName(identity)", "object_attribute", [], "Email/username.")],
    bindings=[bind(K(S + "/login-code/verify"), ["POST"])],
    vis="black_box", vis_reason="Passwordless code-verification login boundary.", reachable=True,
    reach_conds=["ensure_login_code_allowed"],
    evidence=[ev("source", "app/controllers/session_controller.rb:548", "POST /session/login-code/verify; rate limit")],
    confidence=0.85, reasoning="Code-only auth boundary; rate-limited.",
    description="An anonymous caller verifies a one-time login code to sign in (or complete signup).", notes=None)

# ============================= One-time password (cross-login) =============
_know_otp = f_know(ACTOR, reference("OtpPage", SESSION))
action(
    "disc_otp_show", "Show OTP confirmation", "Read", "one_time_password_show", "Anonymous",
    obj("entity", "session", "Session", "path", "token", "AuthToken(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("AuthToken", SESSION)),
                      "Caller presents the OTP token (redis otp_<token>).")],
    gen=[eff(_know_otp, "io_reference", "Response is the OTP confirmation page.")],
    kill=[],
    io_accounting=[io("input", "token / AuthToken(credential)", "req", [kf(f_know(ACTOR, reference("AuthToken", SESSION)))])],
    bindings=[bind(K(S + "/otp/{token}"), ["GET"])],
    vis="black_box", vis_reason="Token-gated cross-login confirmation.", reachable=True, reach_conds=["Valid OTP token"],
    evidence=[ev("source", "app/controllers/session_controller.rb:562", "GET /session/otp/:token -> page")],
    confidence=0.85, reasoning="Shows the OTP confirmation UI.",
    description="An anonymous caller opens the one-time-password confirmation page for a token.", notes=None)

action(
    "disc_otp_redeem", "Redeem OTP", "Create", "one_time_password_redeem", "Anonymous",
    obj("state", "session", "Session", "path", "token", "AuthToken(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("AuthToken", SESSION)),
                      "Caller presents the single-use OTP token.")],
    gen=[eff(AUTHD, "auth_transition", "The resolved user is logged in; the token is consumed.")],
    kill=[],
    io_accounting=[io("input", "token / AuthToken(credential)", "req", [kf(f_know(ACTOR, reference("AuthToken", SESSION)))])],
    bindings=[bind(K(S + "/otp/{token}"), ["POST"])],
    vis="black_box", vis_reason="Single-use cross-login redemption.", reachable=True, reach_conds=["Valid OTP token"],
    evidence=[ev("source", "app/controllers/session_controller.rb:562", "POST /session/otp/:token; redis del")],
    confidence=0.85, reasoning="Single-use OTP login; token deleted on use.",
    description="An anonymous caller redeems a one-time-password token to sign in on this device.", notes=None)

# ============================= Step-up 2FA =================================
_know_2fa = f_know(ACTOR, reference("SecondFactorChallenge", SELF))
action(
    "disc_2fa_show", "Show 2FA challenge", "Read", "second_factor_auth_show", "User",
    obj("entity", "self", "User", "request", "nonce", "SecondFactorNonce(auth)", role="target"),
    requirements=[REQ_AUTH, req("knowledge", f_know(ACTOR, reference("SecondFactorNonce", SELF)),
                                "Caller presents the challenge nonce.")],
    gen=[eff(_know_2fa, "io_reference", "Response describes the available 2FA methods for the nonce.")],
    kill=[],
    io_accounting=[io("output", "description / SecondFactorChallenge(auth)", "gen", [kf(_know_2fa)])],
    bindings=[bind(K(S + "/2fa"), ["GET"])],
    vis="black_box", vis_reason="Step-up reauthentication gate.", reachable=True, reach_conds=["Valid nonce"],
    evidence=[ev("source", "app/controllers/session_controller.rb:583", "GET /session/2fa require(:nonce)")],
    confidence=0.9, reasoning="Describes the 2FA step for a pending sensitive action.",
    description="A signed-in user views the 2FA challenge required to continue a sensitive action.", notes=None)

action(
    "disc_2fa_perform", "Perform 2FA step", "Update", "second_factor_auth_perform", "User",
    obj("state", "self", "User", "request", "nonce", "SecondFactorNonce(auth)", role="target"),
    requirements=[REQ_AUTH, req("knowledge", f_know(ACTOR, reference("SecondFactorNonce", SELF)),
                                "Caller presents the nonce being satisfied.")],
    gen=[eff(f_state(SELF, "second_factor", "satisfied"), "state_transition",
             "The 2FA step is marked satisfied; the gated action may resume.")],
    kill=[],
    io_accounting=[io("input", "second_factor_token / SecondFactorToken(credential)", "object_attribute", [],
                      "TOTP/backup token or security-key assertion.")],
    bindings=[bind(K(S + "/2fa"), ["POST"])],
    vis="black_box", vis_reason="Step-up reauthentication gate.", reachable=True, reach_conds=["Valid nonce"],
    evidence=[ev("source", "app/controllers/session_controller.rb:640", "POST /session/2fa authenticate")],
    confidence=0.9, reasoning="Satisfies the 2FA gate tied to a nonce.",
    description="A signed-in user completes the 2FA step for a nonce-gated sensitive action.", notes=None)

# ============================= Passkeys (WebAuthn) =========================
_know_pk = f_know(ACTOR, reference("WebauthnChallenge", SESSION))
action(
    "disc_passkey_challenge", "Get passkey challenge", "Read", "passkey_challenge", "Anonymous",
    obj("entity", "session", "Session", "implicit", "", "", role="target"),
    requirements=[],
    gen=[eff(_know_pk, "io_reference", "Response returns a WebAuthn challenge to sign.")],
    kill=[],
    io_accounting=[io("output", "challenge / WebauthnChallenge(credential)", "gen", [kf(_know_pk)])],
    bindings=[bind(K(S + "/passkey/challenge"), ["GET"])],
    vis="black_box", vis_reason="Unauthenticated passkey bootstrap.", reachable=True, reach_conds=[],
    evidence=[ev("source", "app/controllers/session_controller.rb:419", "GET /session/passkey/challenge")],
    confidence=0.9, reasoning="Issues a WebAuthn challenge.",
    description="Any caller fetches a WebAuthn challenge for passkey login.", notes=None)

action(
    "disc_passkey_login", "Log in with passkey", "Create", "passkey_login", "Anonymous",
    obj("state", "session", "Session", "request", "publicKeyCredential", "WebauthnAssertion(credential)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("WebauthnAssertion", SELF)),
                      "Caller presents a signed WebAuthn assertion.")],
    gen=[eff(AUTHD, "auth_transition", "A session is established on a valid assertion."),
         eff(f_know(ACTOR, reference("UserProfile", SELF)), "io_reference", "The user is signed in.")],
    kill=[],
    io_accounting=[io("input", "publicKeyCredential / WebauthnAssertion(credential)", "req",
                      [kf(f_know(ACTOR, reference("WebauthnAssertion", SELF)))])],
    bindings=[bind(K(S + "/passkey/auth"), ["POST"])],
    vis="black_box", vis_reason="Passwordless passkey login boundary.", reachable=True, reach_conds=[],
    evidence=[ev("source", "app/controllers/session_controller.rb:423", "POST /session/passkey/auth require(:publicKeyCredential)")],
    confidence=0.9, reasoning="WebAuthn assertion auth boundary.",
    description="An anonymous caller authenticates with a passkey (WebAuthn assertion).", notes=None)

# ============================= DiscourseConnect (SSO) ======================
action(
    "disc_sso_begin", "Begin SSO login", "Read", "sso_begin", "Anonymous",
    obj("entity", "session", "Session", "implicit", "", "", role="target"),
    requirements=[],
    gen=[eff(f_know(ACTOR, reference("SsoRedirect", SESSION)), "io_reference",
             "Response is a redirect to the external SSO provider.")],
    kill=[],
    io_accounting=[io("output", "redirect / SsoRedirect(auth)", "gen", [kf(f_know(ACTOR, reference("SsoRedirect", SESSION)))])],
    bindings=[bind(K(S + "/sso"), ["GET"])],
    vis="black_box", vis_reason="Unauthenticated SSO entry.", reachable=True, reach_conds=["enable_discourse_connect"],
    evidence=[ev("source", "app/controllers/session_controller.rb:54", "GET /session/sso -> redirect")],
    confidence=0.9, reasoning="SSO handoff; return_path validated.",
    description="An anonymous caller is redirected to the configured DiscourseConnect provider.", notes=None)

action(
    "disc_sso_login", "Complete SSO login", "Create", "sso_login", "Anonymous",
    obj("state", "session", "Session", "request", "sso", "SsoPayload(auth)", role="target"),
    requirements=[req("knowledge", f_know(ACTOR, reference("SsoSignature", SELF)),
                      "Caller presents a provider-signed payload with a valid HMAC.")],
    gen=[eff(f_exists(SELF), "action_semantics", "The user is provisioned just-in-time if new."),
         eff(AUTHD, "auth_transition", "A local session is established from the signed identity."),
         eff(f_state(SELF, "groups", "synced"), "state_transition", "Groups/role may be synced from the payload.")],
    kill=[],
    io_accounting=[io("input", "sso / SsoPayload(auth)", "object_attribute", [], "Signed identity assertion."),
                   io("input", "sig / SsoSignature(credential)", "req",
                      [kf(f_know(ACTOR, reference("SsoSignature", SELF)))])],
    bindings=[bind(K(S + "/sso_login"), ["GET"])],
    vis="black_box", vis_reason="Federated-auth callback (signature-gated).", reachable=True,
    reach_conds=["enable_discourse_connect", "valid HMAC over the shared secret"],
    evidence=[ev("source", "app/controllers/session_controller.rb:197", "GET /session/sso_login require(:sso,:sig)")],
    confidence=0.9, reasoning="Signed payload mints/updates a local account (incl. group/role sync).",
    description="A valid provider-signed SSO payload provisions/logs in a local user and may sync groups.",
    notes="FEDERATED AUTH BOUNDARY: trust rests on the shared-secret HMAC + nonce validation.")

_know_assert = f_know(ACTOR, reference("SsoAssertion", SELF))
action(
    "disc_sso_provider", "Assert identity as SSO provider", "Read", "sso_provider", "User",
    obj("entity", "self", "User", "request", "sso", "SsoProviderRequest(auth)", role="target"),
    requirements=[REQ_AUTH, req("knowledge", f_know(ACTOR, reference("SsoSignature", SELF)),
                                "Consuming site presents a signed SSO request (registered secret).")],
    gen=[eff(_know_assert, "io_reference", "Response is a signed assertion of this user's identity.")],
    kill=[],
    io_accounting=[io("input", "sig / SsoSignature(credential)", "req", [kf(f_know(ACTOR, reference("SsoSignature", SELF)))]),
                   io("output", "redirect_url / SsoAssertion(auth)", "gen", [kf(_know_assert)])],
    bindings=[bind(K(S + "/sso_provider"), ["GET"])],
    vis="black_box", vis_reason="Requires a local session to assert identity downstream.", reachable=True,
    reach_conds=["enable_discourse_connect_provider", "requesting site registered with a secret"],
    evidence=[ev("source", "app/controllers/session_controller.rb:73", "GET /session/sso_provider -> signed redirect_url")],
    confidence=0.9, reasoning="Discourse acts as IdP, emitting a signed identity assertion.",
    description="A signed-in user's identity is asserted (signed) back to a registered consuming site.",
    notes="Discourse-as-IdP: discloses this user's identity to the downstream consumer per its request.")

# ===========================================================================
# Additional modules (importing registers their actions via l2lib side-effect).
# ===========================================================================
import importlib as _il

for _m in ["l2_users", "l2_account", "l2_topics", "l2_posts", "l2_categories",
           "l2_tags", "l2_groups", "l2_invites", "l2_notifications", "l2_uploads",
           "l2_bookmarks_drafts", "l2_misc", "l2_reviewables", "l2_admin_core",
           "l2_admin_users", "l2_admin_content"]:
    try:
        _il.import_module(_m)
    except ModuleNotFoundError:
        continue
