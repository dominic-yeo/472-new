# -*- coding: utf-8 -*-
"""Keycloak L1 attack surface as data.

Authoritative source (this repo, keycloak/keycloak main @ 999.0.0-SNAPSHOT == the
26.x line; JAX-RS @Path resources):
  - Realm routing:  services/.../services/resources/RealmsResource.java
  - OIDC protocol:  services/.../protocol/oidc/OIDCLoginProtocolService.java + endpoints/*
  - Login actions:  services/.../services/resources/LoginActionsService.java
  - Broker:         services/.../services/resources/IdentityBrokerService.java
  - Client reg:     services/.../services/clientregistration/*
  - Account REST:   services/.../services/resources/account/AccountRestService.java
  - Admin REST:     services/.../services/resources/admin/*  (/admin/realms/{realm}/...)

ORIGIN = http://localhost:8080 (Keycloak default HTTP).

Auth model: CLIENTS authenticate to the token endpoint (secret | assertion | mTLS); USERS via
browser flows or the password grant. Bearer ACCESS TOKENS (JWT) carry realm/client roles, scopes,
audience. Admin REST authZ = the realm-management client roles in the token (manage-users,
view-clients, manage-realm, impersonation, ...) or a master-realm admin. {realm} is a path template
(modeled once). Nodes with io_variants are L2 candidates; statuses left for runtime (runtime/ has a
compose + probe).
"""
import common as c
from common import (key as K, rf, of, variant, resp_json, resp_empty, resp_scalar,
                    resp_html, resp_redirect, dec)


def evs(ref, supports="JAX-RS resource + handler"):
    return c.ev("source", "keycloak/services/src/main/java/org/keycloak/" + ref, supports)


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
def d_realm():
    return dec("realm", "RealmName(realm)", "identifier", reference_capable=True, reason="Target realm.")


def d_client():
    return dec("client_id", "ClientID(client)", "identifier", reference_capable=True, reason="OAuth client.")


def d_cuuid():
    return dec("id", "ClientUUID(client)", "identifier", reference_capable=True, reason="Client internal id.")


def d_user():
    return dec("user_id", "UserID(user)", "identifier", reference_capable=True, reason="Target user id.")


def d_username():
    return dec("username", "Username(user)", "identifier", reference_capable=True, reason="Login name.")


def d_password():
    return dec("password", "Password(user)", "credential", reason="User password.")


def d_secret():
    return dec("client_secret", "ClientSecret(client)", "credential", reason="Client secret.")


def d_code():
    return dec("code", "AuthCode(session)", "credential", reason="Authorization code.")


def d_token():
    return dec("access_token", "AccessToken(session)", "credential", reason="Access token (JWT bearer).")


def d_refresh():
    return dec("refresh_token", "RefreshToken(session)", "credential", reason="Refresh token.")


def d_redirect():
    return dec("redirect_uri", "RedirectURI(client)", "locator", reference_capable=True,
               reason="Client redirect URI (validated against registered set).")


def r_data(*names, envelope="keycloak", error_path="error_description"):
    return resp_json([of(n) for n in names], envelope=envelope, error_path=error_path)


def r_admin(*names):
    return resp_json([of(n) for n in names], envelope="keycloak-admin", error_path="errorMessage")


GET, POST, PUT, DELETE = ["GET"], ["POST"], ["PUT"], ["DELETE"]


# ===========================================================================
# PUBLIC / DISCOVERY  (RealmsResource, PublicRealmResource, wellknown)
# ===========================================================================
api("/realms/{realm}/.well-known/openid-configuration", GET,
    [variant("GET", [rf("realm", "path", required=True)],
             r_data("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                    "jwks_uri", "end_session_endpoint", "registration_endpoint", "grant_types_supported"),
             reason="OIDC discovery document (public)",
             evidence="wellknown/OIDCWellKnownProvider.java")],
    "oidc_discovery", sin=[d_realm()],
    vis_reason="PUBLIC OIDC discovery.", reach=["PUBLIC. Enumerates every endpoint + supported features for the realm."],
    evref="protocol/oidc/OIDCWellKnownProvider.java",
    notes="Also /.well-known/{alias}: webfinger, oauth-authorization-server, etc.")

api("/realms/{realm}", GET,
    [variant("GET", [rf("realm", "path", required=True)],
             r_data("realm", "public_key", "token-service", "account-service"),
             reason="public realm info + realm RSA public key",
             evidence="services/resources/PublicRealmResource.java")],
    "realm_public_info", sin=[d_realm()],
    vis_reason="PUBLIC realm info.", reach=["PUBLIC. Realm existence oracle + signing public key."],
    evref="services/resources/PublicRealmResource.java")

api("/realms/{realm}/protocol/openid-connect/certs", GET,
    [variant("GET", [rf("realm", "path", required=True)], r_data("keys"),
             reason="JWKS: realm signature/encryption public keys", evidence="OIDCLoginProtocolService.certs")],
    "oidc_jwks", sin=[d_realm()], vis_reason="PUBLIC JWKS.",
    reach=["PUBLIC. Token-verification public keys."], evref="protocol/oidc/OIDCLoginProtocolService.java")

api0("/realms/{realm}/.well-known/{alias}", GET, "wellknown_alias",
     reach=["PUBLIC discovery aliases (oauth-authorization-server, webfinger, ...)."],
     evref="services/resources/RealmsResource.java")
api0("/realms/{realm}/clients/{client_id}/redirect", GET, "client_redirect",
     reach=["PUBLIC convenience redirect to a client's base/redirect URL (open-redirect-adjacent)."],
     evref="services/resources/RealmsResource.java")


# ===========================================================================
# OIDC PROTOCOL  (OIDCLoginProtocolService + endpoints/*)
# ===========================================================================
OIDC = "protocol/oidc/OIDCLoginProtocolService.java"
api("/realms/{realm}/protocol/openid-connect/auth", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("client_id", "query", required=True),
                     rf("redirect_uri", "query", required=True), rf("response_type", "query", required=True),
                     rf("scope", "query"), rf("state", "query"), rf("nonce", "query"),
                     rf("code_challenge", "query"), rf("prompt", "query"), rf("login_hint", "query"),
                     rf("request", "query", description="request object (JWT)"),
                     rf("request_uri", "query", description="request object by reference (SSRF)")],
             resp_html("the login/consent page, then 302 to redirect_uri with a code"),
             reason="OIDC/OAuth2 authorization endpoint -- starts the browser flow",
             evidence="endpoints/AuthorizationEndpoint.java")],
    "oidc_authorize", sin=[d_realm(), d_client(), d_redirect()],
    vis_reason="PUBLIC authorization endpoint.",
    reach=["PUBLIC. redirect_uri validation, 'request_uri' (SSRF / request-object-by-reference), 'prompt=none' "
           "silent auth, and PKCE live here. Mis-set redirect_uri = code/token theft."],
    evref="protocol/oidc/endpoints/AuthorizationEndpoint.java",
    notes="Entry point of code & implicit flows; request_uri fetch is an SSRF vector.")

api("/realms/{realm}/protocol/openid-connect/token", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("grant_type", "body", required=True),
                      rf("code", "body"), rf("redirect_uri", "body"), rf("client_id", "body"),
                      rf("client_secret", "body"), rf("client_assertion", "body"),
                      rf("username", "body"), rf("password", "body"), rf("refresh_token", "body"),
                      rf("code_verifier", "body"), rf("scope", "body"),
                      rf("subject_token", "body", description="token-exchange input token"),
                      rf("requested_token_type", "body"), rf("audience", "body")],
             r_data("access_token", "refresh_token", "id_token", "token_type", "expires_in"),
             body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="token endpoint: all grant types (code, refresh, password, client_credentials, "
                    "token-exchange, device_code, ciba, uma-ticket)",
             evidence="endpoints/TokenEndpoint.java")],
    "oidc_token", sin=[d_realm(), d_client(), d_secret(), d_code(), d_username(), d_password(),
                       d_refresh(), dec("subject_token", "AccessToken(session)", "credential",
                                        reason="Token-exchange subject token.")],
    sout=[d_token(), d_refresh()],
    vis_reason="Token endpoint (all grants).",
    reach=["Client-authenticated (secret/assertion/mTLS) or public client. password grant = credential brute-force; "
           "token-exchange = delegation/escalation; refresh = replay/rotation surface."],
    evref="protocol/oidc/endpoints/TokenEndpoint.java",
    notes="grant_type dispatches to OAuth2GrantType providers; token-exchange + uma-ticket are high-risk grants.")

api("/realms/{realm}/protocol/openid-connect/userinfo", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("access_token", "header")],
             r_data("sub", "email", "preferred_username", "roles"),
             reason="OIDC userinfo (bearer access token)", evidence="endpoints/UserInfoEndpoint.java")],
    "oidc_userinfo", sin=[d_realm()], sout=[dec("sub", "UserID(user)", "identifier", reference_capable=True,
                                                reason="Subject id.")],
    vis_reason="Userinfo (bearer).", reach=["Bearer access token with openid scope."],
    evref="protocol/oidc/endpoints/UserInfoEndpoint.java")

api("/realms/{realm}/protocol/openid-connect/logout", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("id_token_hint", "query"),
                     rf("post_logout_redirect_uri", "query"), rf("client_id", "query")],
             resp_redirect("302 to post_logout_redirect_uri"),
             reason="RP-initiated logout (end session)", evidence="endpoints/LogoutEndpoint.java")],
    "oidc_logout", sin=[d_realm()],
    vis_reason="End-session endpoint.",
    reach=["PUBLIC. post_logout_redirect_uri validation; id_token_hint. Session termination."],
    evref="protocol/oidc/endpoints/LogoutEndpoint.java")

api("/realms/{realm}/protocol/openid-connect/revoke", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("token", "body", required=True),
                      rf("client_id", "body"), rf("client_secret", "body")],
             resp_empty(), body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="OAuth2 token revocation", evidence="endpoints/TokenRevocationEndpoint.java")],
    "oidc_revoke", sin=[d_realm(), dec("token", "AccessToken(session)", "credential", reason="Token to revoke.")],
    vis_reason="Token revocation.", reach=["Client-authenticated. Revokes a token."],
    evref="protocol/oidc/endpoints/TokenRevocationEndpoint.java")

api("/realms/{realm}/protocol/openid-connect/token/introspect", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("token", "body", required=True),
                      rf("client_id", "body"), rf("client_secret", "body")],
             r_data("active", "sub", "scope", "exp", "client_id"),
             body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="RFC 7662 token introspection", evidence="endpoints/TokenIntrospectionEndpoint.java")],
    "oidc_introspect", sin=[d_realm()],
    vis_reason="Token introspection.",
    reach=["Client-authenticated (confidential). Reveals token claims/validity -> an oracle if creds leak."],
    evref="protocol/oidc/endpoints/TokenIntrospectionEndpoint.java")

api("/realms/{realm}/protocol/openid-connect/logout/backchannel-logout", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("logout_token", "body", required=True)],
             resp_empty(), body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="OIDC back-channel logout (signed logout_token)", evidence="endpoints/LogoutEndpoint.java")],
    "oidc_backchannel_logout", sin=[d_realm()],
    vis_reason="Back-channel logout.", reach=["Accepts a signed logout_token; signature-validation surface."],
    evref="protocol/oidc/endpoints/LogoutEndpoint.java")

api("/realms/{realm}/protocol/openid-connect/ext/par/request", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("client_id", "body", required=True),
                      rf("request", "body"), rf("redirect_uri", "body")],
             r_data("request_uri", "expires_in"), body_format="form",
             content_types=["application/x-www-form-urlencoded"],
             reason="Pushed Authorization Requests (PAR)", evidence="protocol/oidc/par/*")],
    "oidc_par", sin=[d_realm(), d_client()], sout=[dec("request_uri", "RequestURI(session)", "locator",
                                                       reference_capable=True, reason="PAR request_uri handle.")],
    vis_reason="PAR endpoint.", reach=["Client-authenticated. Stores an authorization request server-side."],
    evref="protocol/oidc/ext/par", notes="Extension under ext/{extension}.")

api("/realms/{realm}/protocol/openid-connect/ext/oidc/device/auth", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("client_id", "body", required=True),
                      rf("scope", "body")],
             r_data("device_code", "user_code", "verification_uri", "interval"),
             body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="OAuth2 device authorization grant -- device code", evidence="protocol/oidc/endpoints/DeviceEndpoint.java")],
    "oidc_device_auth", sin=[d_realm(), d_client()],
    vis_reason="Device authorization.", reach=["Client-authenticated. Device/user-code flow."],
    evref="protocol/oidc/endpoints/DeviceEndpoint.java")

api0("/realms/{realm}/protocol/openid-connect/registrations", GET, "oidc_registration_form",
     reach=["PUBLIC self-registration FORM (if realm registrationAllowed)."], evref=OIDC)
api0("/realms/{realm}/protocol/openid-connect/forgot-credentials", GET, "oidc_forgot_credentials",
     reach=["PUBLIC forgot-password entry (if resetPasswordAllowed)."], evref=OIDC)
api0("/realms/{realm}/protocol/openid-connect/login-status-iframe.html", GET, "oidc_session_iframe",
     reach=["Session-status iframe (session management)."], evref=OIDC)
api0("/realms/{realm}/protocol/openid-connect/3p-cookies", GET, "oidc_3p_cookies",
     reach=["Third-party cookie check iframe."], evref=OIDC)
api0("/realms/{realm}/protocol/openid-connect/oauth/oob", GET, "oidc_oob",
     reach=["Out-of-band redirect display page."], evref=OIDC)


# ===========================================================================
# LOGIN ACTIONS  (LoginActionsService)  -- browser auth flows
# ===========================================================================
LA = "services/resources/LoginActionsService.java"
api("/realms/{realm}/login-actions/authenticate", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("username", "body"), rf("password", "body"),
                      rf("session_code", "body"), rf("execution", "query"), rf("client_id", "query"),
                      rf("tab_id", "query")],
             resp_html("next auth step / redirect with code / re-rendered login on failure"),
             body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="process an authentication flow step (username/password form post)",
             evidence="LoginActionsService.authenticate")],
    "login_authenticate", sin=[d_realm(), d_username(), d_password()],
    vis_reason="Browser login form post.",
    reach=["PUBLIC. The username/password submission -> brute-force / credential-stuffing (attack-detection applies)."],
    evref=LA)

api("/realms/{realm}/login-actions/registration", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("username", "body"), rf("email", "body"),
                      rf("password", "body"), rf("firstName", "body"), rf("lastName", "body"),
                      rf("execution", "query")],
             resp_html("account created -> continue flow, or form errors"),
             body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="self-service user registration submit", evidence="LoginActionsService.processRegister")],
    "login_register", sin=[d_realm(), d_username(),
                           dec("email", "UserEmail(user)", "identifier", reference_capable=True, reason="Email.")],
    vis_reason="Self-registration.",
    reach=["PUBLIC *iff* realm registrationAllowed. Account provisioning + enumeration; captcha/terms optional."],
    evref=LA)

api("/realms/{realm}/login-actions/reset-credentials", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("username", "body"), rf("execution", "query")],
             resp_html("sends a reset email / next step"), body_format="form",
             content_types=["application/x-www-form-urlencoded"],
             reason="forgot-password: trigger a reset-credentials email", evidence="LoginActionsService.resetCredentials")],
    "login_reset_credentials", sin=[d_realm(), d_username()],
    vis_reason="Password reset.",
    reach=["PUBLIC *iff* resetPasswordAllowed. User-enumeration / reset-email trigger."],
    evref=LA)

api("/realms/{realm}/login-actions/action-token", GET,
    [variant("GET", [rf("realm", "path", required=True), rf("key", "query", required=True,
             description="signed action token (JWT)"), rf("execution", "query")],
             resp_html("consumes a one-time action token (verify email, reset password, exec actions)"),
             reason="handle a signed action token link", evidence="LoginActionsService.executeActionToken")],
    "login_action_token", sin=[d_realm(),
                               dec("key", "ActionToken(session)", "credential", reason="Signed action token.")],
    vis_reason="Action-token handler.",
    reach=["PUBLIC with a valid signed token. Verify-email / reset / execute-actions; token forgery = account takeover."],
    evref=LA, notes="Action tokens are JWTs signed by the realm; replay/scope handling is the surface.")

api0("/realms/{realm}/login-actions/required-action", ["GET", "POST"], "login_required_action",
     reach=["Required-action step (configure TOTP, update password, terms, ...)."], evref=LA)
api0("/realms/{realm}/login-actions/first-broker-login", ["GET", "POST"], "login_first_broker_login",
     reach=["Post-IdP-login account linking/creation flow."], evref=LA)
api0("/realms/{realm}/login-actions/post-broker-login", ["GET", "POST"], "login_post_broker_login",
     reach=["Post-broker-login flow."], evref=LA)
api0("/realms/{realm}/login-actions/consent", ["GET", "POST"], "login_consent",
     reach=["OAuth consent grant/deny."], evref=LA)
api0("/realms/{realm}/login-actions/restart", GET, "login_restart", reach=["Restart the auth flow."], evref=LA)


# ===========================================================================
# IDENTITY BROKER  (IdentityBrokerService)  -- social / SSO login
# ===========================================================================
BR = "services/resources/IdentityBrokerService.java"
api("/realms/{realm}/broker/{provider}/login", GET,
    [variant("GET", [rf("realm", "path", required=True), rf("provider", "path", required=True),
                     rf("session_code", "query")],
             resp_redirect("302 to the external IdP authorize URL"),
             reason="start login via an external identity provider", evidence="IdentityBrokerService.performLogin")],
    "broker_login", sin=[d_realm()],
    vis_reason="Broker login start.", reach=["PUBLIC. Redirects to the configured external IdP."],
    evref=BR)

api("/realms/{realm}/broker/{provider}/endpoint", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("provider", "path", required=True),
                     rf("code", "query"), rf("state", "query"), rf("SAMLResponse", "body")],
             resp_redirect("processes the IdP response, links/creates a user, continues the flow"),
             reason="IdP callback: consume the external assertion/code", evidence="IdentityBrokerService.getEndpoint")],
    "broker_endpoint", sin=[d_realm()],
    vis_reason="Broker callback.",
    reach=["PUBLIC. Consumes attacker-influenced IdP responses (OIDC code / SAMLResponse) -> assertion/signature "
           "validation + account-linking surface."],
    evref=BR, notes="SAMLResponse handling here is the XML-signature / assertion-injection surface.")

api0("/realms/{realm}/broker/{provider}/token", GET, "broker_retrieve_token",
     reach=["Retrieve the stored external IdP token (requires the broker read-token role)."], evref=BR)


# ===========================================================================
# CLIENT REGISTRATION  (clientregistration/*)  -- dynamic client registration
# ===========================================================================
CR = "services/clientregistration/ClientRegistrationService.java"
api("/realms/{realm}/clients-registrations/openid-connect", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("redirect_uris", "body"),
                      rf("client_name", "body"), rf("grant_types", "body")],
             r_data("client_id", "client_secret", "registration_access_token", "registration_client_uri"),
             body_format="json", reason="OIDC Dynamic Client Registration (RFC 7591)",
             evidence="clientregistration/oidc/OIDCClientRegistrationProvider.java")],
    "client_register_oidc", sin=[d_realm()], sout=[d_client(), d_secret()],
    vis_reason="Dynamic client registration.",
    reach=["Gated by an initial-access token OR anonymous *iff* the realm allows it (client-registration-policy). "
           "Open registration = attacker-registered clients / redirect_uris."],
    evref=CR, notes="Anonymous DCR is a classic misconfiguration; policies restrict it.")

api("/realms/{realm}/clients-registrations/openid-connect/{clientId}", ["GET", "PUT", "DELETE"],
    [variant("GET", [rf("realm", "path", required=True), rf("clientId", "path", required=True)],
             r_data("client_id", "redirect_uris"), reason="read/update/delete a registered client",
             evidence="clientregistration/oidc/OIDCClientRegistrationProvider.java")],
    "client_registration_manage", sin=[d_realm(), d_client()],
    vis_reason="Manage a registered client.",
    reach=["Requires the client's registration-access-token (bearer). Rotates on update."],
    evref=CR)

api0("/realms/{realm}/clients-registrations/default", POST, "client_register_default",
     reach=["Keycloak-native client registration (ClientRepresentation)."], evref=CR)
api0("/realms/{realm}/clients-registrations/install/{clientId}", GET, "client_registration_install",
     reach=["Adapter install config for a client."], evref=CR)
api0("/realms/{realm}/clients-managements/register-node", POST, "client_register_node",
     reach=["Legacy cluster-node (un)registration via client credentials."],
     evref="services/resources/ClientsManagementService.java")


# ===========================================================================
# SAML
# ===========================================================================
api("/realms/{realm}/protocol/saml", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("SAMLRequest", "body"),
                      rf("SAMLResponse", "body"), rf("RelayState", "body"), rf("Signature", "body")],
             resp_html("SAML SSO/SLO response (POST binding) or 302 (redirect binding)"),
             body_format="form", content_types=["application/x-www-form-urlencoded"],
             reason="SAML 2.0 SSO/SLO endpoint (IdP)", evidence="protocol/saml/SamlService.java")],
    "saml_endpoint", sin=[d_realm()],
    vis_reason="SAML IdP endpoint.",
    reach=["PUBLIC. Parses attacker-supplied SAMLRequest/Response XML -> XML signature-wrapping / XXE / "
           "assertion-injection surface."],
    evref="protocol/saml/SamlService.java", notes="Primary SAML attack surface.")

api0("/realms/{realm}/protocol/saml/descriptor", GET, "saml_descriptor",
     reach=["PUBLIC SAML IdP metadata (entityID, certs)."], evref="protocol/saml/SamlService.java")
api0("/realms/{realm}/protocol/saml/clients/{client}", ["GET", "POST"], "saml_idp_initiated",
     reach=["IdP-initiated SSO for a SAML client."], evref="protocol/saml/SamlService.java")


# ===========================================================================
# ACCOUNT REST API  (AccountRestService)  -- the user's own account
# ===========================================================================
AC = "services/resources/account/AccountRestService.java"
api("/realms/{realm}/account", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("access_token", "header")],
             r_data("username", "email", "firstName", "lastName", "attributes"),
             reason="read/update the caller's own account profile", evidence="AccountRestService.account")],
    "account_profile", sin=[d_realm()],
    vis_reason="Own account profile.",
    reach=["Bearer token for the 'account' client (the user's own token). Self-service only."],
    evref=AC)

api("/realms/{realm}/account/credentials", GET,
    [variant("GET", [rf("realm", "path", required=True)], r_data("credentials"),
             reason="list the caller's credentials (password, OTP, webauthn)", evidence="AccountCredentialResource")],
    "account_credentials", sin=[d_realm()],
    vis_reason="Own credentials.", reach=["Bearer 'account' token; self."], evref="services/resources/account/AccountCredentialResource.java")

api("/realms/{realm}/account/sessions", ["GET", "DELETE"],
    [variant("GET", [rf("realm", "path", required=True)], r_data("sessions"),
             reason="list / revoke the caller's device sessions", evidence="account/SessionResource.java")],
    "account_sessions", sin=[d_realm()],
    vis_reason="Own sessions.", reach=["Bearer 'account' token; self. DELETE = remote logout of own sessions."],
    evref="services/resources/account/SessionResource.java")

api("/realms/{realm}/account/linked-accounts/{providerAlias}", ["POST", "DELETE"],
    [variant("POST", [rf("realm", "path", required=True), rf("providerAlias", "path", required=True),
                      rf("redirectUri", "query")],
             r_data("accountLinkUri"), reason="link/unlink a social/IdP account to the caller",
             evidence="account/LinkedAccountsResource.java")],
    "account_linked_accounts", sin=[d_realm()],
    vis_reason="Own account linking.",
    reach=["Bearer 'account' token; self. The link redirect + state is an account-takeover-adjacent surface."],
    evref="services/resources/account/LinkedAccountsResource.java")

api0("/realms/{realm}/account/applications", GET, "account_applications",
     reach=["List the apps/clients the user has consented to."], evref=AC)
api0("/realms/{realm}/account/applications/{clientId}/consent", ["GET", "POST", "DELETE"], "account_consent",
     reach=["Manage the user's own consent for a client."], evref=AC)
api0("/realms/{realm}/account/resources", GET, "account_resources",
     reach=["UMA: resources the user shares/owns."], evref=AC)
api0("/realms/{realm}/account/groups", GET, "account_groups", reach=["The user's own group memberships."], evref=AC)
api0("/realms/{realm}/account/organizations", GET, "account_organizations",
     reach=["The user's organizations."], evref=AC)


# ===========================================================================
# AUTHZ / UMA  (authorization/protection)
# ===========================================================================
api("/realms/{realm}/authz/protection/resource_set", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("name", "body", required=True),
                      rf("uris", "body"), rf("scopes", "body")],
             r_data("_id", "name"), body_format="json",
             reason="UMA protection API: register a protected resource (PAT-authenticated)",
             evidence="authorization/protection/resource/ResourceService.java")],
    "uma_resource_set", sin=[d_realm()],
    vis_reason="UMA resource registration.",
    reach=["Requires a PAT (resource server access token). Resource-server self-service."],
    evref="authorization/protection/resource/ResourceService.java")

api0("/realms/{realm}/authz/protection/permission", POST, "uma_permission_ticket",
     reach=["UMA permission-ticket endpoint (resource server, PAT)."],
     evref="authorization/protection/permission")
api0("/realms/{realm}/authz/protection/uma-policy", POST, "uma_policy",
     reach=["UMA policy management (owner)."], evref="authorization/protection/policy")


# ===========================================================================
# ADMIN REST API -- root + realms
# ===========================================================================
AR = "services/resources/admin/AdminRoot.java"
api("/admin/serverinfo", GET,
    [variant("GET", [], r_admin("systemInfo", "memoryInfo", "providers", "themes"),
             reason="server + provider info (admin)", evidence="admin/info/ServerInfoAdminResource.java")],
    "admin_serverinfo", vis_reason="Admin server info.",
    reach=["Any authenticated admin. Reveals version/providers/SPI config (recon)."],
    evref="services/resources/admin/info/ServerInfoAdminResource.java")

api("/admin/realms", ["GET", "POST"],
    [variant("GET", [], r_admin("realms"), reason="list realms the caller can view",
             evidence="admin/RealmsAdminResource.java"),
     variant("POST", [rf("realm", "body", required=True), rf("enabled", "body", "boolean")],
             resp_empty(), body_format="json", reason="create a new realm (master-admin)",
             evidence="admin/RealmsAdminResource.java")],
    "admin_realms", sin=[d_realm()],
    vis_reason="List / create realms.",
    reach=["GET: realms the token can view. POST create-realm: master-realm admin (create-realm role). "
           "A new realm is a new trust domain."],
    evref="services/resources/admin/RealmsAdminResource.java")

api("/admin/realms/{realm}", ["GET", "PUT", "DELETE"],
    [variant("GET", [rf("realm", "path", required=True)],
             r_admin("realm", "registrationAllowed", "bruteForceProtected", "sslRequired", "passwordPolicy"),
             reason="read/update/delete a realm's full config", evidence="admin/RealmAdminResource.java")],
    "admin_realm", sin=[d_realm()],
    vis_reason="Realm config (ADMIN).",
    reach=["realm-management view-realm/manage-realm. PUT changes security-critical toggles (registrationAllowed, "
           "sslRequired, bruteForceProtected, passwordPolicy, tokens)."],
    evref="services/resources/admin/RealmAdminResource.java")

api("/admin/realms/{realm}/testSMTPConnection", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("host", "body"), rf("port", "body"),
                      rf("from", "body"), rf("auth", "body"), rf("user", "body"), rf("password", "body")],
             resp_empty(), body_format="json",
             reason="server connects to an admin-supplied SMTP host (SSRF)", evidence="admin/RealmAdminResource.java")],
    "admin_test_smtp", sin=[d_realm(),
                            dec("host", "RemoteHost(fetch)", "attribute", reason="SMTP host the server connects to (SSRF).")],
    vis_reason="SMTP test (SSRF).",
    reach=["realm-management manage-realm. The server opens a connection to an attacker-chosen host:port (SSRF / "
           "port-scan / credential-capture)."],
    evref="services/resources/admin/RealmAdminResource.java", notes="SSRF sink #1.")

api0("/admin/realms/{realm}/partialImport", POST, "admin_partial_import",
     reach=["manage-realm: bulk-import users/clients/roles (mass provisioning)."],
     evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/partial-export", POST, "admin_partial_export",
     reach=["manage-realm: export realm config (may include secrets depending on flags) -> exfiltration."],
     evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/logout-all", POST, "admin_logout_all",
     reach=["manage-users: revoke all realm sessions (DoS)."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/push-revocation", POST, "admin_push_revocation",
     reach=["manage-realm: push a not-before revocation to clients."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/events", ["GET", "DELETE"], "admin_events",
     reach=["view-events: login event log (contains usernames/IPs)."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/admin-events", ["GET", "DELETE"], "admin_admin_events",
     reach=["view-events: admin audit log."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/events/config", ["GET", "PUT"], "admin_events_config",
     reach=["manage-events: configure event logging."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/client-session-stats", GET, "admin_client_session_stats",
     reach=["view-realm: active session stats."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/keys", GET, "admin_keys",
     reach=["view-realm: active realm keys (kids, certs; private material NOT returned)."],
     evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/client-policies/policies", ["GET", "PUT"], "admin_client_policies",
     reach=["manage-realm: client policy JSON."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/client-policies/profiles", ["GET", "PUT"], "admin_client_profiles",
     reach=["manage-realm: client profile JSON."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/localization", GET, "admin_localization",
     reach=["view-realm: localization texts."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/client-description-converter", POST, "admin_client_desc_converter",
     reach=["manage-clients: convert an OIDC/SAML descriptor into a ClientRepresentation (parser; SSRF if URL)."] ,
     evref="services/resources/admin/RealmAdminResource.java")


# ===========================================================================
# ADMIN -- USERS  (UsersResource / UserResource)
# ===========================================================================
US = "services/resources/admin/UsersResource.java"
UR = "services/resources/admin/UserResource.java"
api("/admin/realms/{realm}/users", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("search", "query"), rf("username", "query"),
                     rf("email", "query"), rf("first", "query", "number"), rf("max", "query", "number")],
             r_admin("users"), reason="search/list users",
             evidence="UsersResource.getUsers"),
     variant("POST", [rf("realm", "path", required=True), rf("username", "body", required=True),
                      rf("email", "body"), rf("enabled", "body", "boolean"), rf("credentials", "body")],
             resp_empty(), body_format="json", reason="create a user", evidence="UsersResource.createUser")],
    "admin_users", sin=[d_realm(), d_username()],
    vis_reason="List / create users (ADMIN).",
    reach=["realm-management view-users (GET) / manage-users (POST). Directory read + account provisioning."],
    evref=US)

api("/admin/realms/{realm}/users/{id}", ["GET", "PUT", "DELETE"],
    [variant("GET", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             r_admin("id", "username", "email", "attributes", "realmRoles"),
             reason="read/update/delete a user", evidence="UserResource")],
    "admin_user", sin=[d_realm(), d_user()],
    vis_reason="Manage a user (ADMIN).",
    reach=["view-users (GET) / manage-users (PUT,DELETE). PUT can set enabled, email-verified, attributes."],
    evref=UR)

api("/admin/realms/{realm}/users/{id}/reset-password", PUT,
    [variant("PUT", [rf("realm", "path", required=True), rf("id", "path", required=True),
                     rf("type", "body"), rf("value", "body", required=True), rf("temporary", "body", "boolean")],
             resp_empty(), body_format="json", reason="set a user's password directly (admin)",
             evidence="UserResource.resetPassword")],
    "admin_user_reset_password", sin=[d_realm(), d_user(), d_password()],
    vis_reason="Set a user's password (ADMIN).",
    reach=["manage-users. Setting any user's password = account takeover of that user."],
    evref=UR, notes="Direct account-takeover primitive.")

api("/admin/realms/{realm}/users/{id}/impersonation", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             r_admin("sameRealm", "redirect"), body_format="json",
             reason="impersonate the user -- returns a session as them", evidence="UserResource.impersonate")],
    "admin_user_impersonate", sin=[d_realm(), d_user()],
    vis_reason="Impersonate a user (ESCALATION).",
    reach=["realm-management impersonation role. Grants a live session AS the target user (lateral/vertical move)."],
    evref=UR, notes="Impersonation = become any user; a key escalation lever.")

api("/admin/realms/{realm}/users/{id}/role-mappings/realm", ["GET", "POST", "DELETE"],
    [variant("POST", [rf("realm", "path", required=True), rf("id", "path", required=True),
                      rf("roles", "body", required=True, description="[{id,name}]")],
             resp_empty(), body_format="json", reason="grant realm roles to a user (ESCALATION)",
             evidence="RoleMapperResource")],
    "admin_user_role_mappings", sin=[d_realm(), d_user()],
    vis_reason="Grant roles to a user (ESCALATION).",
    reach=["manage-users (+ the role must be in the admin's manageable set). Granting 'admin'/realm-management roles "
           "escalates the target (or the attacker if self-targeted)."],
    evref="services/resources/admin/RoleMapperResource.java", notes="Role-grant escalation lever.")

api("/admin/realms/{realm}/users/{id}/execute-actions-email", PUT,
    [variant("PUT", [rf("realm", "path", required=True), rf("id", "path", required=True),
                     rf("actions", "body", description="['UPDATE_PASSWORD',...]"),
                     rf("redirect_uri", "query"), rf("client_id", "query")],
             resp_empty(), body_format="json",
             reason="email the user a signed action link (redirect_uri attacker-influenced)", evidence="UserResource")],
    "admin_user_execute_actions", sin=[d_realm(), d_user(), d_redirect()],
    vis_reason="Send action-email (ADMIN).",
    reach=["manage-users. redirect_uri/client_id here are validated against the client; a weak client = link hijack."],
    evref=UR)

api("/admin/realms/{realm}/users/{id}/logout", POST,
    [variant("POST", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             resp_empty(), body_format="json", reason="log the user out of all sessions", evidence="UserResource.logout")],
    "admin_user_logout", sin=[d_realm(), d_user()],
    vis_reason="Force-logout a user (ADMIN).", reach=["manage-users. Session DoS of the target."], evref=UR)

api("/admin/realms/{realm}/users/{id}/credentials", GET,
    [variant("GET", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             r_admin("credentials"), reason="list a user's credentials (types/ids)", evidence="UserResource.credentials")],
    "admin_user_credentials", sin=[d_realm(), d_user()],
    vis_reason="Read a user's credentials.", reach=["view-users. Credential metadata (not secrets)."], evref=UR)

api0("/admin/realms/{realm}/users/{id}/groups", GET, "admin_user_groups",
     reach=["view-users: a user's groups; PUT groups/{gid} to add (indirect role grant)."], evref=UR)
api0("/admin/realms/{realm}/users/{id}/groups/{groupId}", ["PUT", "DELETE"], "admin_user_group_membership",
     reach=["manage-users: add/remove a user to a group (inherits the group's roles -- escalation)."], evref=UR)
api0("/admin/realms/{realm}/users/{id}/sessions", GET, "admin_user_sessions",
     reach=["view-users: a user's active sessions (IPs)."], evref=UR)
api0("/admin/realms/{realm}/users/{id}/federated-identity/{provider}", ["POST", "DELETE"], "admin_user_federated_identity",
     reach=["manage-users: link/unlink a federated identity (account-takeover-adjacent)."], evref=UR)
api0("/admin/realms/{realm}/users/{id}/consents", ["GET", "DELETE"], "admin_user_consents",
     reach=["view-users / manage-users: the user's client consents."], evref=UR)
api0("/admin/realms/{realm}/users/{id}/disable-credential-types", PUT, "admin_user_disable_credential_types",
     reach=["manage-users: disable credential types (e.g. OTP) for a user."], evref=UR)
api0("/admin/realms/{realm}/users/{id}/send-verify-email", PUT, "admin_user_send_verify_email",
     reach=["manage-users: send a verify-email link."], evref=UR)
api0("/admin/realms/{realm}/users/count", GET, "admin_users_count", reach=["view-users: user count."], evref=US)
api0("/admin/realms/{realm}/users/profile", ["GET", "PUT"], "admin_users_profile",
     reach=["manage-realm: the declarative user-profile config (attribute schema)."], evref=US)


# ===========================================================================
# ADMIN -- CLIENTS  (ClientsResource / ClientResource)
# ===========================================================================
CS = "services/resources/admin/ClientsResource.java"
CL = "services/resources/admin/ClientResource.java"
api("/admin/realms/{realm}/clients", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("clientId", "query"), rf("search", "query")],
             r_admin("clients"), reason="list clients", evidence="ClientsResource.getClients"),
     variant("POST", [rf("realm", "path", required=True), rf("clientId", "body", required=True),
                      rf("redirectUris", "body"), rf("publicClient", "body", "boolean"),
                      rf("serviceAccountsEnabled", "body", "boolean")],
             resp_empty(), body_format="json", reason="create a client", evidence="ClientsResource.createClient")],
    "admin_clients", sin=[d_realm(), d_client()],
    vis_reason="List / create clients (ADMIN).",
    reach=["view-clients (GET) / manage-clients (POST). A new client with serviceAccountsEnabled + roles is an "
           "escalation primitive; redirectUris control token delivery."],
    evref=CS)

api("/admin/realms/{realm}/clients/{id}", ["GET", "PUT", "DELETE"],
    [variant("GET", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             r_admin("clientId", "redirectUris", "publicClient", "secret", "serviceAccountsEnabled"),
             reason="read/update/delete a client", evidence="ClientResource")],
    "admin_client", sin=[d_realm(), d_cuuid()],
    vis_reason="Manage a client (ADMIN).",
    reach=["view-clients (GET) / manage-clients (PUT,DELETE). PUT redirectUris/webOrigins/protocolMappers changes "
           "token audience + delivery."],
    evref=CL)

api("/admin/realms/{realm}/clients/{id}/client-secret", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             r_admin("type", "value"), reason="read / regenerate a client's secret", evidence="ClientResource")],
    "admin_client_secret", sin=[d_realm(), d_cuuid()], sout=[d_secret()],
    vis_reason="Read/rotate client secret (CREDENTIAL).",
    reach=["view-clients reads the secret; manage-clients regenerates. A confidential client's secret = impersonate "
           "that client (client_credentials / token-exchange)."],
    evref=CL, notes="Reading a secret = client impersonation.")

api("/admin/realms/{realm}/clients/{id}/service-account-user", GET,
    [variant("GET", [rf("realm", "path", required=True), rf("id", "path", required=True)],
             r_admin("id", "username", "serviceAccountClientId"),
             reason="the client's service-account user (role holder)", evidence="ClientResource")],
    "admin_client_service_account", sin=[d_realm(), d_cuuid()],
    vis_reason="Client service account.",
    reach=["view-clients. The service-account user is where client_credentials roles live -> escalation target."],
    evref=CL)

api("/admin/realms/{realm}/clients/{id}/certificates/{attr}", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("id", "path", required=True),
                      rf("attr", "path", required=True), rf("file", "multipart")],
             r_admin("certificate", "privateKey"), content_types=["multipart/form-data"],
             reason="upload/generate a client keystore/JWT credential", evidence="ClientAttributeCertificateResource")],
    "admin_client_certificates", sin=[d_realm(), d_cuuid()],
    vis_reason="Client certificate/keystore.",
    reach=["manage-clients. Generate/upload the client's signing key (JWT client auth) -> client impersonation."],
    evref="services/resources/admin/ClientAttributeCertificateResource.java")

api0("/admin/realms/{realm}/clients/{id}/nodes", POST, "admin_client_register_node",
     reach=["manage-clients: register a cluster node."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/installation/providers/{providerId}", GET, "admin_client_installation",
     reach=["view-clients: adapter install config (may contain the secret)."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/user-sessions", GET, "admin_client_user_sessions",
     reach=["view-clients: active sessions for the client."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/push-revocation", POST, "admin_client_push_revocation",
     reach=["manage-clients: push not-before to the client."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/evaluate-scopes", GET, "admin_client_evaluate_scopes",
     reach=["view-clients: preview the token a client would issue."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/management/permissions", ["GET", "PUT"], "admin_client_fgap",
     reach=["manage-clients: fine-grained admin permissions (fgap) toggle for this client."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/protocol-mappers/models", ["GET", "POST"], "admin_client_protocol_mappers",
     reach=["manage-clients: protocol mappers (shape token claims; 'script' mapper = code if scripts enabled)."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/roles", ["GET", "POST"], "admin_client_roles",
     reach=["manage-clients: client role CRUD."], evref=CL)
api0("/admin/realms/{realm}/clients/{id}/authz/resource-server", GET, "admin_client_authz",
     reach=["manage-authorization: this client's authorization-services (resources/policies/permissions)."],
     evref=CL)
api0("/admin/realms/{realm}/clients-initial-access", ["GET", "POST", "DELETE"], "admin_clients_initial_access",
     reach=["manage-clients: mint initial-access tokens for dynamic client registration."],
     evref="services/resources/admin/ClientInitialAccessResource.java")


# ===========================================================================
# ADMIN -- ROLES / GROUPS / IDP / COMPONENTS / AUTH FLOWS / ATTACK-DETECTION
# ===========================================================================
api("/admin/realms/{realm}/roles", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("search", "query")], r_admin("roles"),
             reason="list / create realm roles", evidence="RoleContainerResource")],
    "admin_roles", sin=[d_realm()],
    vis_reason="Realm roles (ADMIN).",
    reach=["view-realm / manage-realm. Roles are the authorization currency; composites can bundle privileges."],
    evref="services/resources/admin/RoleContainerResource.java")

api0("/admin/realms/{realm}/roles/{role-name}/composites", ["GET", "POST", "DELETE"], "admin_role_composites",
     reach=["manage-realm: add child roles to a composite (privilege bundling)."],
     evref="services/resources/admin/RoleContainerResource.java")
api0("/admin/realms/{realm}/roles-by-id/{role-id}", ["GET", "PUT", "DELETE"], "admin_role_by_id",
     reach=["manage-realm: role CRUD by id."], evref="services/resources/admin/RoleByIdResource.java")

api("/admin/realms/{realm}/groups", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("search", "query")], r_admin("groups"),
             reason="list / create groups", evidence="GroupsResource")],
    "admin_groups", sin=[d_realm()],
    vis_reason="Groups (ADMIN).",
    reach=["view-users / manage-users (query-groups). Group role-mappings grant privileges to all members."],
    evref="services/resources/admin/GroupsResource.java")

api0("/admin/realms/{realm}/groups/{id}", ["GET", "PUT", "DELETE"], "admin_group",
     reach=["manage-users: group CRUD."], evref="services/resources/admin/GroupResource.java")
api0("/admin/realms/{realm}/groups/{id}/role-mappings/realm", ["GET", "POST", "DELETE"], "admin_group_role_mappings",
     reach=["manage-users + manageable role: grant roles to a group (all members inherit -> escalation)."],
     evref="services/resources/admin/RoleMapperResource.java")
api0("/admin/realms/{realm}/groups/{id}/members", GET, "admin_group_members",
     reach=["view-users: group members."], evref="services/resources/admin/GroupResource.java")

api("/admin/realms/{realm}/identity-provider/import-config", POST,
    [variant("POST", [rf("realm", "path", required=True),
                      rf("fromUrl", "body", description="IdP metadata URL the server fetches (SSRF)"),
                      rf("providerId", "body")],
             r_admin("config"), body_format="json",
             reason="server fetches an IdP metadata URL to build config (SSRF)",
             evidence="IdentityProvidersResource.importFrom")],
    "admin_idp_import_config", sin=[d_realm(),
                                    dec("fromUrl", "RemoteURL(fetch)", "attribute", reason="Metadata URL fetched server-side (SSRF).")],
    vis_reason="IdP metadata import (SSRF).",
    reach=["manage-identity-providers. The server GETs 'fromUrl' (SAML/OIDC metadata) -> SSRF to internal services."],
    evref="services/resources/admin/IdentityProvidersResource.java", notes="SSRF sink #2.")

api("/admin/realms/{realm}/identity-provider/instances", ["GET", "POST"],
    [variant("POST", [rf("realm", "path", required=True), rf("alias", "body", required=True),
                      rf("providerId", "body"), rf("config", "body")],
             resp_empty(), body_format="json", reason="create an identity provider instance",
             evidence="IdentityProvidersResource")],
    "admin_idp_instances", sin=[d_realm()],
    vis_reason="Create IdP (ADMIN).",
    reach=["manage-identity-providers. A rogue IdP (with config URLs) is an SSRF + trust-injection surface."],
    evref="services/resources/admin/IdentityProvidersResource.java")

api("/admin/realms/{realm}/components", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True), rf("type", "query"), rf("parent", "query")],
             r_admin("components"), reason="list / create components (user federation, key providers, mappers)",
             evidence="ComponentResource")],
    "admin_components", sin=[d_realm()],
    vis_reason="Components (ADMIN).",
    reach=["manage-realm. User-federation (LDAP) components hold bind credentials + a connection URL (SSRF/"
           "credential surface); key-provider components manage signing keys."],
    evref="services/resources/admin/ComponentResource.java", notes="LDAP federation config = SSRF sink #3.")

api0("/admin/realms/{realm}/components/{id}", ["GET", "PUT", "DELETE"], "admin_component",
     reach=["manage-realm: component CRUD (e.g. edit an LDAP provider's connectionUrl)."],
     evref="services/resources/admin/ComponentResource.java")
api0("/admin/realms/{realm}/testLDAPConnection", POST, "admin_test_ldap",
     reach=["manage-realm: server connects to an admin-supplied LDAP URL (SSRF / credential-capture)."] ,
     evref="services/resources/admin/ComponentResource.java")

api("/admin/realms/{realm}/authentication/flows", ["GET", "POST"],
    [variant("GET", [rf("realm", "path", required=True)], r_admin("flows"),
             reason="list / create authentication flows", evidence="AuthenticationManagementResource")],
    "admin_auth_flows", sin=[d_realm()],
    vis_reason="Auth flows (ADMIN).",
    reach=["manage-realm. Reordering/replacing flow executions can WEAKEN authentication (e.g. drop password/OTP)."],
    evref="services/resources/admin/AuthenticationManagementResource.java")

api0("/admin/realms/{realm}/authentication/executions", POST, "admin_auth_execution_add",
     reach=["manage-realm: add an execution to a flow."], evref="services/resources/admin/AuthenticationManagementResource.java")
api0("/admin/realms/{realm}/authentication/executions/{executionId}/config", POST, "admin_auth_execution_config",
     reach=["manage-realm: configure an execution (e.g. a 'script' authenticator = code if scripts enabled)."],
     evref="services/resources/admin/AuthenticationManagementResource.java")
api0("/admin/realms/{realm}/authentication/register-required-action", POST, "admin_register_required_action",
     reach=["manage-realm: register a required action."], evref="services/resources/admin/AuthenticationManagementResource.java")
api0("/admin/realms/{realm}/authentication/required-actions", GET, "admin_required_actions",
     reach=["view-realm: required actions."], evref="services/resources/admin/AuthenticationManagementResource.java")

api("/admin/realms/{realm}/attack-detection/brute-force/users/{userId}", ["GET", "DELETE"],
    [variant("GET", [rf("realm", "path", required=True), rf("userId", "path", required=True)],
             r_admin("numFailures", "disabled", "lastIPFailure"),
             reason="read / clear brute-force status for a user", evidence="AttackDetectionResource")],
    "admin_attack_detection", sin=[d_realm(), d_user()],
    vis_reason="Brute-force status (ADMIN).",
    reach=["view-realm (GET) / manage-users (DELETE clears lockout -> re-enables brute-force attempts)."],
    evref="services/resources/admin/AttackDetectionResource.java")

api0("/admin/realms/{realm}/client-scopes", ["GET", "POST"], "admin_client_scopes",
     reach=["manage-clients: client-scope CRUD (shape default token claims/roles)."],
     evref="services/resources/admin/ClientScopesResource.java")
api0("/admin/realms/{realm}/client-registration-policy/providers", GET, "admin_client_reg_policy",
     reach=["view-realm: client-registration-policy providers (govern anonymous DCR)."],
     evref="services/resources/admin/ClientRegistrationPolicyResource.java")
api0("/admin/realms/{realm}/sessions/{session}", DELETE, "admin_delete_session",
     reach=["manage-users: delete a specific user session."], evref="services/resources/admin/RealmAdminResource.java")
api0("/admin/realms/{realm}/users-management-permissions", ["GET", "PUT"], "admin_users_mgmt_permissions",
     reach=["manage-realm: enable fine-grained admin permissions for users."], evref="services/resources/admin/RealmAdminResource.java")


# ===========================================================================
_finalize()


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded against quay.io/keycloak/keycloak:26.0 (26.0.8,
# start-dev, dev H2, realm 'master'). Identity labels: anonymous (no token) | admin
# (master bootstrap admin, admin-cli password grant). From runtime/probe_results/.
# Findings: public protocol reads 200; admin API denial = HTTP 401 (no/invalid token);
# a bad redirect_uri at authorize = 400 (redirect-URI validation); token with a bad
# client = 401; admin-cli token at userinfo = 403 (lacks openid scope/audience).
# ===========================================================================
_RUNTIME = {
    # public protocol surface
    "/realms/{realm}/.well-known/openid-configuration": {"s": [200], "id": {"anonymous": [200]}},
    "/realms/{realm}/protocol/openid-connect/certs":    {"s": [200], "id": {"anonymous": [200]}},
    "/realms/{realm}":                                   {"s": [200], "id": {"anonymous": [200]}},
    # authorize: 200 w/ a valid redirect_uri, 400 on an unregistered one (redirect validation confirmed)
    "/realms/{realm}/protocol/openid-connect/auth":     {"s": [200, 400], "id": {"anonymous": [200, 400]}},
    # token: bad client -> 401; valid admin-cli password grant -> 200
    "/realms/{realm}/protocol/openid-connect/token":    {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    # userinfo: admin-cli token lacks openid scope -> 403 (a scope/audience boundary, not 401)
    "/realms/{realm}/protocol/openid-connect/userinfo": {"s": [200, 403, 401], "id": {"admin": [403]}},
    # admin API: denial = 401 without a token, 200 with the admin token
    "/admin/serverinfo":                                {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/admin/realms":                                    {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/admin/realms/{realm}":                            {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/admin/realms/{realm}/users":                      {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/admin/realms/{realm}/clients":                    {"s": [200, 401], "id": {"anonymous": [401], "admin": [200]}},
    "/admin/realms/{realm}/roles":                      {"s": [200], "id": {"admin": [200]}},
    "/admin/realms/{realm}/groups":                     {"s": [200], "id": {"admin": [200]}},
    "/admin/realms/{realm}/identity-provider/instances": {"s": [200], "id": {"admin": [200]}},
    "/admin/realms/{realm}/components":                 {"s": [200], "id": {"admin": [200]}},
    "/admin/realms/{realm}/authentication/flows":       {"s": [200], "id": {"admin": [200]}},
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


page("/admin/master/console", ["GET"], "admin_console", kind="page",
     reach=["Admin Console SPA; drives the /admin REST API with the admin's bearer token."],
     evref="services/resources/admin/AdminConsole.java",
     notes="One per realm (/admin/{realm}/console).")
page("/realms/{realm}/account/index.html", ["GET"], "account_console", kind="page",
     reach=["Account Console SPA (HTML); drives the /account REST API (same base path, JSON via Accept)."],
     evref="services/resources/account/AccountConsole.java")
page("/", ["GET"], "welcome", kind="page",
     reach=["Welcome page; on a fresh install it bootstraps the first master admin (if no admin exists)."],
     evref="services/resources/WelcomeResource.java",
     notes="Fresh-install admin bootstrap happens here / via KEYCLOAK_ADMIN env.")


EDGES = [
    {"src": K("/admin/master/console"), "dst": K("/realms/{realm}/protocol/openid-connect/token"),
     "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/admin/master/console"), "dst": K("/admin/realms/{realm}/users"), "methods": ["GET"],
     "triggers": ["xhr"]},
    {"src": K("/realms/{realm}/protocol/openid-connect/auth"),
     "dst": K("/realms/{realm}/login-actions/authenticate"), "methods": ["POST"], "triggers": ["form"]},
    {"src": K("/realms/{realm}/account"), "dst": K("/realms/{realm}/account/credentials"),
     "methods": ["GET"], "triggers": ["xhr"]},
]
