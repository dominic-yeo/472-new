# -*- coding: utf-8 -*-
"""Keycloak L2 action cores over the six Pengent predicates.

io_accounting fact strings use common.fact_key so they match Req/Eff. Auth: CLIENTS
authenticate to the token endpoint (secret/assertion/mTLS); USERS via browser flows or
the password grant; bearer ACCESS TOKENS (JWT) carry realm/client roles. Admin REST authZ
= the realm-management client roles in the token (modeled as Can(...) with the role named
in reach_conds) or a master-realm admin. Evidence -> keycloak services/rest source.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind

ACTOR = subj()


def kf(f):
    return fact_key(f)


def src(ref, supports="JAX-RS resource + handler"):
    return c.ev("source", "keycloak/services/src/main/java/org/keycloak/" + ref, supports)


def ent(k, t, role="target"):
    return entity(k, t, role)


def know(rt, e):
    return f_know(ACTOR, reference(rt, e))


_tok_auth = f_auth(ACTOR, "AccessToken")
_admin_auth = f_auth(ACTOR, "AdminToken")

AUTHS = {"token": (_tok_auth, "Authenticated: bearer access token."),
         "admin": (_admin_auth, "Authenticated: admin bearer token."),
         "none": (None, None)}


def _b(path, method="POST"):
    return [bind(K(path), [method], sel_field="method", sel_values=[method])]


def rd(akey, name, path, out_type, out_ref, subject="RealmAdmin", auth="admin", perm=None,
       inref=None, reach=None, note=None, evref=None, method="GET"):
    """Read: output is Know(actor, ref(out_ref, <out_type>))."""
    o = know(out_ref, ent(out_type.lower(), out_type, "response"))
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
                        "Requires " + perm + "."))
    action(
        akey, name, "Read", akey, subject,
        obj("entity", out_type.lower(), out_type, "response", "", out_ref, role="response"),
        requirements=reqs, gen=[eff(o, "io_reference", "Returns " + out_type.lower() + ".")], kill=[],
        io_accounting=io_in + [io("output", out_type.lower() + " / " + out_ref, "gen", [kf(o)])],
        bindings=_b(path, method),
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=reach or ["Authenticated + role."],
        evidence=[src(evref or akey)], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


def mu(akey, name, crud, path, obj_type, obj_ref, subject="RealmAdmin", auth="admin", perm=None,
       inref=None, mode="update", state_field="config", reach=None, note=None, evref=None, method="POST"):
    tgt = ent(obj_type.lower(), obj_type, "target")
    reqs = []
    a, areason = AUTHS[auth]
    if a:
        reqs.append(req("authentication", a, areason))
    if perm:
        reqs.append(req("authorization", f_can(ACTOR, crud, tgt), "Requires " + perm + "."))
    io_in = []
    if inref:
        rk, rt, rtype = inref
        kr = know(rt, ent(rk, rtype, "target"))
        reqs.append(req("knowledge", kr, "Targets an existing " + rtype.lower() + "."))
        io_in = [io("input", rk + " / " + rt + "(" + rtype.lower() + ")", "req", [kf(kr)])]
    gen, kill = [], []
    if mode == "create":
        o = know(obj_ref, ent(obj_type.lower(), obj_type, "created"))
        gen = [eff(f_exists(ent(obj_type.lower(), obj_type, "created")), "action_semantics",
                   "A " + obj_type.lower() + " is created."),
               eff(o, "io_reference", "Returns the new " + obj_type.lower() + ".")]
        io_in += [io("output", obj_type.lower() + " / " + obj_ref, "gen", [kf(o)])]
        okind, orole, ofield = "entity", "created", ""
    elif mode == "delete":
        kill = [eff(f_exists(tgt), "action_semantics", "The " + obj_type.lower() + " is removed.")]
        okind, orole, ofield = "entity", "target", ""
    else:
        gen = [eff(f_state(tgt, state_field, "updated"), "action_semantics", "State is updated.")]
        okind, orole, ofield = "state", "target", state_field
    action(
        akey, name, crud, akey, subject,
        obj(okind, obj_type.lower(), obj_type, "request", "", obj_ref, role=orole, state_field=ofield),
        requirements=reqs, gen=gen, kill=kill, io_accounting=io_in,
        bindings=_b(path, method),
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=reach or ["Authenticated + role."],
        evidence=[src(evref or akey)], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


# ===========================================================================
# PUBLIC / DISCOVERY
# ===========================================================================
rd("oidc_discovery", "Read OIDC discovery", "/realms/{realm}/.well-known/openid-configuration",
   "Discovery", "Discovery(realm)", subject="Anonymous", auth="none",
   reach=["PUBLIC. Enumerates every endpoint + supported features for the realm."],
   evref="protocol/oidc/OIDCWellKnownProvider.java")
rd("realm_public_info", "Read public realm info", "/realms/{realm}", "RealmInfo", "RealmName(realm)",
   subject="Anonymous", auth="none",
   reach=["PUBLIC. Realm existence oracle + signing public key."],
   evref="services/resources/PublicRealmResource.java")
rd("oidc_jwks", "Read JWKS", "/realms/{realm}/protocol/openid-connect/certs", "JWKS", "JWKS(realm)",
   subject="Anonymous", auth="none", reach=["PUBLIC. Token-verification public keys."],
   evref="protocol/oidc/OIDCLoginProtocolService.java")


# ===========================================================================
# OIDC PROTOCOL
# ===========================================================================
# authorization endpoint -- starts the browser flow, issues a code on success
_redirectKnow = know("RedirectURI", ent("client", "Client", "target"))
_codeOut = know("AuthCode", ent("session", "Session", "created"))
action(
    "oidc_authorize", "Authorization request", "Read", "oidc_authorize", "Anonymous",
    obj("entity", "authpage", "LoginPage", "response", "", "LoginPage(realm)", role="response"),
    requirements=[req("knowledge", know("ClientID", ent("client", "Client", "target")),
                      "References a registered client_id + redirect_uri.")],
    gen=[eff(f_know(ACTOR, reference("LoginPage", ent("authpage", "LoginPage", "response"))),
             "io_reference", "Renders the login/consent page (then a code to redirect_uri).")],
    kill=[],
    io_accounting=[io("input", "client_id / ClientID(client)", "req",
                      [kf(know("ClientID", ent("client", "Client", "target")))]),
                   io("input", "redirect_uri / RedirectURI(client)", "object_attribute", [],
                      "Validated against the client's registered redirect URIs."),
                   io("output", "authpage / LoginPage(realm)", "gen",
                      [kf(f_know(ACTOR, reference("LoginPage", ent("authpage", "LoginPage", "response"))))])],
    bindings=_b("/realms/{realm}/protocol/openid-connect/auth", "GET"),
    vis="black_box", vis_reason="Authorization endpoint.", reachable=True,
    reach_conds=["PUBLIC. redirect_uri validation, request_uri (SSRF), prompt=none, PKCE live here."],
    evidence=[src("protocol/oidc/endpoints/AuthorizationEndpoint.java")],
    confidence=0.85, reasoning="auth endpoint starts code/implicit flow.",
    description="A visitor begins an OAuth2/OIDC authorization request.",
    notes="Mis-set redirect_uri = code/token theft; request_uri fetch = SSRF.")

# token endpoint -- all grant types; mints tokens (auth transition)
_secretKnow = know("ClientSecret", ent("client", "Client", "self"))
_accessOut = know("AccessToken", ent("session", "Session", "created"))
_refreshOut = know("RefreshToken", ent("session", "Session", "created"))
action(
    "oidc_token", "Token request", "Create", "oidc_token", "Client",
    obj("state", "session", "Session", "response", "", "AccessToken(session)", role="created",
        state_field="access_token"),
    requirements=[req("authentication", f_auth(ACTOR, "ClientCredentials"),
                      "Confidential client authenticates (secret/assertion/mTLS); public clients use PKCE."),
                  req("knowledge", _codeOut, "Presents a code / password / refresh / subject_token per grant.")],
    gen=[eff(_accessOut, "io_reference", "Issues an access token (JWT)."),
         eff(_refreshOut, "io_reference", "Issues a refresh token."),
         eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "Bearer becomes authenticated for the audience.")],
    kill=[],
    io_accounting=[io("input", "code / AuthCode(session)", "req", [kf(_codeOut)]),
                   io("input", "client_secret / ClientSecret(client)", "object_attribute", [], "Client auth."),
                   io("output", "access_token / AccessToken(session)", "gen", [kf(_accessOut)]),
                   io("output", "refresh_token / RefreshToken(session)", "gen", [kf(_refreshOut)])],
    bindings=_b("/realms/{realm}/protocol/openid-connect/token"),
    vis="black_box", vis_reason="Token endpoint.", reachable=True,
    reach_conds=["All grants: code / refresh / password (brute-force) / client_credentials / token-exchange "
                 "(delegation-escalation) / device / ciba / uma-ticket."],
    evidence=[src("protocol/oidc/endpoints/TokenEndpoint.java")],
    confidence=0.9, reasoning="token endpoint mints tokens for every grant.",
    description="A client exchanges credentials/code/refresh for access + refresh tokens.",
    notes="token-exchange is the high-risk delegation/escalation grant.")

rd("oidc_userinfo", "Read userinfo", "/realms/{realm}/protocol/openid-connect/userinfo", "UserInfo",
   "UserID(user)", subject="User", auth="token",
   reach=["Bearer access token with openid scope."],
   evref="protocol/oidc/endpoints/UserInfoEndpoint.java", method="GET")

# logout (end session) -- revokes the session
action(
    "oidc_logout", "End session", "Delete", "oidc_logout", "User",
    obj("state", "session", "Session", "request", "", "Session(user)", role="target", state_field="active"),
    requirements=[req("knowledge", know("AccessToken", ent("session", "Session", "self")),
                      "id_token_hint / session cookie identifies the session.")],
    gen=[], kill=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "The user session is terminated.")],
    io_accounting=[],
    bindings=_b("/realms/{realm}/protocol/openid-connect/logout", "GET"),
    vis="black_box", vis_reason="End-session endpoint.", reachable=True,
    reach_conds=["PUBLIC. post_logout_redirect_uri validation; id_token_hint."],
    evidence=[src("protocol/oidc/endpoints/LogoutEndpoint.java")],
    confidence=0.8, reasoning="logout ends the session.",
    description="A user (or RP) terminates the SSO session.")

mu("oidc_revoke", "Revoke token", "Delete", "/realms/{realm}/protocol/openid-connect/revoke",
   "Token", "AccessToken(session)", subject="Client", auth="token", mode="delete",
   inref=("token", "AccessToken", "AccessToken"),
   reach=["Client-authenticated. Revokes a token."],
   evref="protocol/oidc/endpoints/TokenRevocationEndpoint.java")

rd("oidc_introspect", "Introspect token", "/realms/{realm}/protocol/openid-connect/token/introspect",
   "Introspection", "Introspection(token)", subject="Client", auth="token",
   reach=["Client-authenticated (confidential). Reveals token claims/validity (oracle if creds leak)."],
   evref="protocol/oidc/endpoints/TokenIntrospectionEndpoint.java", method="POST")

mu("oidc_backchannel_logout", "Back-channel logout", "Delete",
   "/realms/{realm}/protocol/openid-connect/logout/backchannel-logout", "Session", "Session(user)",
   subject="Client", auth="none", mode="delete",
   inref=("logout_token", "LogoutToken", "LogoutToken"),
   reach=["Accepts a signed logout_token; signature-validation surface."],
   evref="protocol/oidc/endpoints/LogoutEndpoint.java")

mu("oidc_par", "Pushed authorization request", "Create",
   "/realms/{realm}/protocol/openid-connect/ext/par/request", "RequestURI", "RequestURI(session)",
   subject="Client", auth="token", mode="create",
   reach=["Client-authenticated. Stores an authorization request server-side -> request_uri handle."],
   evref="protocol/oidc/ext/par")

mu("oidc_device_auth", "Device authorization", "Create",
   "/realms/{realm}/protocol/openid-connect/ext/oidc/device/auth", "DeviceCode", "DeviceCode(session)",
   subject="Client", auth="none", mode="create", inref=("client_id", "ClientID", "Client"),
   reach=["Client-authenticated. Device/user-code flow."],
   evref="protocol/oidc/endpoints/DeviceEndpoint.java")


# ===========================================================================
# LOGIN ACTIONS
# ===========================================================================
LA = "services/resources/LoginActionsService.java"
# authenticate -- username/password submission (auth transition on success)
_pwKnow = know("Password", ent("user", "User", "self"))
action(
    "login_authenticate", "Submit login", "Create", "login_authenticate", "Anonymous",
    obj("state", "session", "Session", "request", "", "Session(user)", role="created", state_field="authenticated"),
    requirements=[req("knowledge", _pwKnow, "Caller supplies username + password.")],
    gen=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "On success the browser session authenticates.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "object_attribute", [], "Login name."),
                   io("input", "password / Password(user)", "req", [kf(_pwKnow)])],
    bindings=_b("/realms/{realm}/login-actions/authenticate"),
    vis="black_box", vis_reason="Browser login.", reachable=True,
    reach_conds=["PUBLIC. Username/password submission -> brute-force / credential-stuffing (attack-detection)."],
    evidence=[src(LA, "authenticate")],
    confidence=0.85, reasoning="processes the login form.",
    description="A visitor submits credentials in the browser flow.")

# register -- self-service account creation
_emailKnow = know("UserEmail", ent("user", "User", "self"))
action(
    "login_register", "Self-register", "Create", "login_register", "Anonymous",
    obj("entity", "user", "User", "response", "", "UserID(user)", role="created"),
    requirements=[req("knowledge", _emailKnow, "Caller supplies registration fields (username/email/password).")],
    gen=[eff(f_exists(ent("user", "User", "created")), "action_semantics", "A user account is created."),
         eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "The registrant is signed in / continues the flow.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "req", [kf(_emailKnow)])],
    bindings=_b("/realms/{realm}/login-actions/registration"),
    vis="black_box", vis_reason="Self-registration.", reachable=True,
    reach_conds=["PUBLIC *iff* registrationAllowed. Account provisioning + enumeration."],
    evidence=[src(LA, "processRegister")],
    confidence=0.8, reasoning="creates a user when registration is enabled.",
    description="A visitor self-registers a new account.")

mu("login_reset_credentials", "Request password reset", "Update",
   "/realms/{realm}/login-actions/reset-credentials", "User", "Username(user)",
   subject="Anonymous", auth="none", state_field="reset_email",
   inref=("username", "Username", "User"),
   reach=["PUBLIC *iff* resetPasswordAllowed. User-enumeration / reset-email trigger."],
   evref=LA)

action(
    "login_action_token", "Consume action token", "Update", "login_action_token", "Anonymous",
    obj("state", "user", "User", "request", "", "ActionToken(session)", role="target", state_field="verified"),
    requirements=[req("knowledge", know("ActionToken", ent("token", "ActionToken", "self")),
                      "Caller presents a signed action token (from an email link).")],
    gen=[eff(f_state(ent("user", "User", "target"), "verified", "applied"), "action_semantics",
             "The token's action (verify-email / reset / execute-actions) is applied.")],
    kill=[],
    io_accounting=[io("input", "key / ActionToken(session)", "req",
                      [kf(know("ActionToken", ent("token", "ActionToken", "self")))])],
    bindings=_b("/realms/{realm}/login-actions/action-token", "GET"),
    vis="black_box", vis_reason="Action-token handler.", reachable=True,
    reach_conds=["PUBLIC with a valid signed token. Token forgery / replay = account takeover."],
    evidence=[src(LA, "executeActionToken")],
    confidence=0.8, reasoning="consumes a one-time signed action token.",
    description="A visitor follows a signed action-token link (verify email / reset password).")


# ===========================================================================
# IDENTITY BROKER
# ===========================================================================
BR = "services/resources/IdentityBrokerService.java"
rd("broker_login", "Start IdP login", "/realms/{realm}/broker/{provider}/login", "Redirect",
   "Redirect(idp)", subject="Anonymous", auth="none",
   reach=["PUBLIC. Redirects to the configured external IdP."], evref=BR, method="GET")

action(
    "broker_endpoint", "IdP callback", "Create", "broker_endpoint", "Anonymous",
    obj("state", "session", "Session", "response", "", "Session(user)", role="created", state_field="brokered"),
    requirements=[req("knowledge", know("IdPAssertion", ent("assertion", "IdPAssertion", "self")),
                      "Consumes the external IdP's code / SAMLResponse.")],
    gen=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition",
             "A valid, signature-checked assertion links/creates a user and starts a session.")],
    kill=[],
    io_accounting=[io("input", "SAMLResponse / IdPAssertion(assertion)", "req",
                      [kf(know("IdPAssertion", ent("assertion", "IdPAssertion", "self")))])],
    bindings=_b("/realms/{realm}/broker/{provider}/endpoint", "GET"),
    vis="black_box", vis_reason="Broker callback.", reachable=True,
    reach_conds=["PUBLIC. Attacker-influenced IdP responses -> signature/assertion validation + account-linking."],
    evidence=[src(BR, "getEndpoint")],
    confidence=0.8, reasoning="consumes the external assertion.",
    description="The external IdP redirects back; Keycloak validates the assertion and brokers a session.",
    notes="SAMLResponse handling = XML-signature-wrapping / assertion-injection surface.")


# ===========================================================================
# CLIENT REGISTRATION
# ===========================================================================
CR = "services/clientregistration/ClientRegistrationService.java"
action(
    "client_register_oidc", "Dynamic client registration", "Create", "client_register_oidc", "Anonymous",
    obj("entity", "client", "Client", "response", "", "ClientID(client)", role="created"),
    requirements=[req("knowledge", know("InitialAccessToken", ent("iat", "InitialAccessToken", "self")),
                      "An initial-access token, OR anonymous if the realm's client-registration-policy allows it.")],
    gen=[eff(f_exists(ent("client", "Client", "created")), "action_semantics", "A client is registered."),
         eff(know("ClientSecret", ent("client", "Client", "created")), "io_reference",
             "Returns client_id + secret + registration-access-token.")],
    kill=[],
    io_accounting=[io("output", "client_secret / ClientSecret(client)", "gen",
                      [kf(know("ClientSecret", ent("client", "Client", "created")))])],
    bindings=_b("/realms/{realm}/clients-registrations/openid-connect"),
    vis="black_box", vis_reason="Dynamic client registration.", reachable=True,
    reach_conds=["Initial-access token OR anonymous *iff* allowed. Open DCR = attacker-registered clients/redirect_uris."],
    evidence=[src(CR)],
    confidence=0.8, reasoning="RFC 7591 dynamic client registration.",
    description="A caller registers a new OAuth client (anonymously if the realm permits).",
    notes="Anonymous DCR is a classic misconfiguration.")

rd("client_registration_manage", "Read a registered client", "/realms/{realm}/clients-registrations/openid-connect/{clientId}",
   "Client", "ClientID(client)", subject="Client", auth="token",
   inref=("clientId", "ClientID", "Client"),
   reach=["Requires the client's registration-access-token (bearer)."], evref=CR)


# ===========================================================================
# SAML
# ===========================================================================
action(
    "saml_endpoint", "SAML SSO/SLO", "Create", "saml_endpoint", "Anonymous",
    obj("state", "session", "Session", "request", "", "Session(user)", role="created", state_field="saml"),
    requirements=[req("knowledge", know("SAMLMessage", ent("msg", "SAMLMessage", "self")),
                      "Caller submits a SAMLRequest/Response (XML).")],
    gen=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition",
             "A valid signed SAML message drives SSO/SLO.")],
    kill=[],
    io_accounting=[io("input", "SAMLResponse / SAMLMessage(msg)", "req",
                      [kf(know("SAMLMessage", ent("msg", "SAMLMessage", "self")))])],
    bindings=_b("/realms/{realm}/protocol/saml"),
    vis="black_box", vis_reason="SAML IdP endpoint.", reachable=True,
    reach_conds=["PUBLIC. Parses attacker XML -> signature-wrapping / XXE / assertion-injection."],
    evidence=[src("protocol/saml/SamlService.java")],
    confidence=0.8, reasoning="SAML IdP endpoint parses XML messages.",
    description="A visitor submits a SAML message to the IdP endpoint.",
    notes="Primary SAML attack surface.")


# ===========================================================================
# ACCOUNT REST API (self-service)
# ===========================================================================
AC = "services/resources/account/AccountRestService.java"
rd("account_profile", "Read own account", "/realms/{realm}/account", "Account", "UserID(user)",
   subject="User", auth="token", reach=["Bearer 'account' token; self only."], evref=AC)
rd("account_credentials", "List own credentials", "/realms/{realm}/account/credentials", "Credential",
   "CredentialID(credential)", subject="User", auth="token", reach=["Bearer 'account' token; self."],
   evref="services/resources/account/AccountCredentialResource.java")
rd("account_sessions", "List own sessions", "/realms/{realm}/account/sessions", "Session", "SessionID(session)",
   subject="User", auth="token", reach=["Bearer 'account' token; self. DELETE = remote logout."],
   evref="services/resources/account/SessionResource.java")
mu("account_linked_accounts", "Link a social account", "Create",
   "/realms/{realm}/account/linked-accounts/{providerAlias}", "LinkedAccount", "LinkedAccount(user)",
   subject="User", auth="token", mode="create",
   reach=["Bearer 'account' token; self. Link redirect+state = account-takeover-adjacent."],
   evref="services/resources/account/LinkedAccountsResource.java")


# ===========================================================================
# AUTHZ / UMA
# ===========================================================================
mu("uma_resource_set", "Register a protected resource", "Create",
   "/realms/{realm}/authz/protection/resource_set", "UmaResource", "UmaResourceID(resource)",
   subject="Client", auth="token", mode="create",
   reach=["Requires a PAT (resource-server token). Resource-server self-service."],
   evref="authorization/protection/resource/ResourceService.java")


# ===========================================================================
# ADMIN -- root + realms
# ===========================================================================
rd("admin_serverinfo", "Read server info", "/admin/serverinfo", "ServerInfo", "ServerInfo(server)",
   subject="MasterAdmin", auth="admin",
   reach=["Any authenticated admin. Version/providers/SPI (recon)."],
   evref="services/resources/admin/info/ServerInfoAdminResource.java")

rd("admin_realms", "List/create realms", "/admin/realms", "Realm", "RealmName(realm)",
   subject="MasterAdmin", auth="admin", perm="a master-realm admin (realms the token can view)",
   reach=["GET: viewable realms. POST create-realm: master-admin (create-realm role) -> new trust domain."],
   evref="services/resources/admin/RealmsAdminResource.java", method="GET")

rd("admin_realm", "Read realm config", "/admin/realms/{realm}", "Realm", "RealmName(realm)",
   subject="RealmAdmin", auth="admin", inref=("realm", "RealmName", "Realm"),
   perm="realm-management view-realm",
   reach=["view-realm (GET) / manage-realm (PUT security toggles: registrationAllowed, sslRequired, bruteForce...)."],
   evref="services/resources/admin/RealmAdminResource.java")

# SSRF: testSMTPConnection
_smtpHost = io("input", "host / RemoteHost(fetch)", "object_attribute", [], "SMTP host the server connects to (SSRF).")
action(
    "admin_test_smtp", "Test SMTP connection (SSRF)", "Read", "admin_test_smtp", "RealmAdmin",
    obj("entity", "probe", "ConnectionProbe", "response", "", "ConnectionProbe(server)", role="response"),
    requirements=[req("authentication", _admin_auth, "Admin bearer token."),
                  req("authorization", f_can(ACTOR, "Read", ent("realm", "Realm", "scope")),
                      "Requires realm-management manage-realm.")],
    gen=[eff(know("ConnectionProbe", ent("probe", "ConnectionProbe", "response")), "io_reference",
             "Returns connection success/failure.")],
    kill=[],
    io_accounting=[_smtpHost,
                   io("output", "probe / ConnectionProbe(server)", "gen",
                      [kf(know("ConnectionProbe", ent("probe", "ConnectionProbe", "response")))])],
    bindings=_b("/admin/realms/{realm}/testSMTPConnection"),
    vis="black_box", vis_reason="SMTP test (SSRF).", reachable=True,
    reach_conds=["manage-realm. Server opens a connection to an attacker-chosen host:port (SSRF / port-scan / "
                 "credential-capture)."],
    evidence=[src("services/resources/admin/RealmAdminResource.java", "testSMTPConnection")],
    confidence=0.8, reasoning="server connects to an admin-supplied SMTP host.",
    description="An admin makes the server connect to an arbitrary SMTP host (SSRF sink #1).",
    notes="SSRF.")


# ===========================================================================
# ADMIN -- users
# ===========================================================================
US = "services/resources/admin/UsersResource.java"
UR = "services/resources/admin/UserResource.java"
rd("admin_users", "List/create users", "/admin/realms/{realm}/users", "User", "UserID(user)",
   subject="RealmAdmin", auth="admin", perm="realm-management view-users",
   reach=["view-users (GET) / manage-users (POST). Directory read + provisioning."], evref=US)
rd("admin_user", "Read a user", "/admin/realms/{realm}/users/{id}", "User", "UserID(user)",
   subject="RealmAdmin", auth="admin", inref=("id", "UserID", "User"), perm="view-users",
   reach=["view-users (GET) / manage-users (PUT,DELETE)."], evref=UR)
mu("admin_user_reset_password", "Set a user's password", "Update",
   "/admin/realms/{realm}/users/{id}/reset-password", "User", "UserID(user)", subject="RealmAdmin",
   auth="admin", inref=("id", "UserID", "User"), state_field="password", perm="manage-users", method="PUT",
   reach=["manage-users. Setting any user's password = account takeover."], evref=UR,
   note="Direct account-takeover primitive.")

# impersonation -- become the target user
action(
    "admin_user_impersonate", "Impersonate a user", "Create", "admin_user_impersonate", "RealmAdmin",
    obj("state", "session", "Session", "response", "", "Session(user)", role="created", state_field="impersonated"),
    requirements=[req("authentication", _admin_auth, "Admin bearer token."),
                  req("knowledge", know("UserID", ent("user", "User", "target")), "References the target user."),
                  req("authorization", f_can(ACTOR, "Create", ent("user", "User", "scope")),
                      "Requires realm-management 'impersonation' role.")],
    gen=[eff(f_auth(ACTOR, "AccessToken"), "auth_transition", "A live session AS the target user is issued.")],
    kill=[],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(know("UserID", ent("user", "User", "target")))])],
    bindings=_b("/admin/realms/{realm}/users/{id}/impersonation"),
    vis="black_box", vis_reason="Impersonation (ESCALATION).", reachable=True,
    reach_conds=["realm-management 'impersonation' role. Become any user (lateral/vertical move)."],
    evidence=[src(UR, "impersonate")],
    confidence=0.85, reasoning="impersonation returns a session as the target.",
    description="An admin with the impersonation role takes over a user's session.",
    notes="Key escalation lever.")

mu("admin_user_role_mappings", "Grant roles to a user", "Update",
   "/admin/realms/{realm}/users/{id}/role-mappings/realm", "User", "UserID(user)", subject="RealmAdmin",
   auth="admin", inref=("id", "UserID", "User"), state_field="realmRoles", perm="manage-users + a manageable role",
   reach=["manage-users (+ role in the admin's manageable set). Granting admin/realm-management roles escalates."],
   evref="services/resources/admin/RoleMapperResource.java", note="Role-grant escalation lever.")
mu("admin_user_execute_actions", "Send action-email", "Update",
   "/admin/realms/{realm}/users/{id}/execute-actions-email", "User", "UserID(user)", subject="RealmAdmin",
   auth="admin", inref=("id", "UserID", "User"), state_field="required_actions", perm="manage-users", method="PUT",
   reach=["manage-users. redirect_uri/client_id validated against the client; weak client = link hijack."],
   evref=UR)
mu("admin_user_logout", "Force-logout a user", "Delete", "/admin/realms/{realm}/users/{id}/logout",
   "Session", "Session(user)", subject="RealmAdmin", auth="admin", inref=("id", "UserID", "User"),
   mode="delete", perm="manage-users",
   reach=["manage-users. Session DoS of the target."], evref=UR)
rd("admin_user_credentials", "List a user's credentials", "/admin/realms/{realm}/users/{id}/credentials",
   "Credential", "CredentialID(credential)", subject="RealmAdmin", auth="admin", inref=("id", "UserID", "User"),
   perm="view-users", reach=["view-users. Credential metadata (not secrets)."], evref=UR)


# ===========================================================================
# ADMIN -- clients
# ===========================================================================
CS = "services/resources/admin/ClientsResource.java"
CL = "services/resources/admin/ClientResource.java"
rd("admin_clients", "List/create clients", "/admin/realms/{realm}/clients", "Client", "ClientID(client)",
   subject="RealmAdmin", auth="admin", perm="realm-management view-clients",
   reach=["view-clients (GET) / manage-clients (POST). serviceAccountsEnabled + roles = escalation primitive."],
   evref=CS)
rd("admin_client", "Read a client", "/admin/realms/{realm}/clients/{id}", "Client", "ClientUUID(client)",
   subject="RealmAdmin", auth="admin", inref=("id", "ClientUUID", "Client"), perm="view-clients",
   reach=["view-clients (GET) / manage-clients (PUT,DELETE). redirectUris/mappers change token delivery."],
   evref=CL)

# client-secret -- reading it = client impersonation
action(
    "admin_client_secret", "Read/rotate client secret", "Read", "admin_client_secret", "RealmAdmin",
    obj("entity", "secret", "ClientSecret", "response", "", "ClientSecret(client)", role="response"),
    requirements=[req("authentication", _admin_auth, "Admin bearer token."),
                  req("knowledge", know("ClientUUID", ent("client", "Client", "target")), "References the client."),
                  req("authorization", f_can(ACTOR, "Read", ent("client", "Client", "scope")),
                      "Requires realm-management view-clients (rotate needs manage-clients).")],
    gen=[eff(know("ClientSecret", ent("secret", "ClientSecret", "response")), "io_reference",
             "Returns the client secret.")],
    kill=[],
    io_accounting=[io("input", "id / ClientUUID(client)", "req",
                      [kf(know("ClientUUID", ent("client", "Client", "target")))]),
                   io("output", "secret / ClientSecret(client)", "gen",
                      [kf(know("ClientSecret", ent("secret", "ClientSecret", "response")))])],
    bindings=_b("/admin/realms/{realm}/clients/{id}/client-secret", "GET"),
    vis="black_box", vis_reason="Client secret (CREDENTIAL).", reachable=True,
    reach_conds=["view-clients reads the secret -> impersonate that confidential client (client_credentials / "
                 "token-exchange)."],
    evidence=[src(CL, "client-secret")],
    confidence=0.85, reasoning="returns/rotates the client secret.",
    description="An admin reads (or rotates) a client's secret -- i.e. can impersonate the client.",
    notes="Credential disclosure = client impersonation.")

rd("admin_client_service_account", "Read client service account",
   "/admin/realms/{realm}/clients/{id}/service-account-user", "User", "UserID(user)", subject="RealmAdmin",
   auth="admin", inref=("id", "ClientUUID", "Client"), perm="view-clients",
   reach=["view-clients. Service-account user holds client_credentials roles -> escalation target."], evref=CL)
mu("admin_client_certificates", "Upload/generate client keystore", "Update",
   "/admin/realms/{realm}/clients/{id}/certificates/{attr}", "Client", "ClientUUID(client)",
   subject="RealmAdmin", auth="admin", inref=("id", "ClientUUID", "Client"), state_field="keystore",
   perm="manage-clients",
   reach=["manage-clients. Generate/upload the client's signing key (JWT client auth) -> client impersonation."],
   evref="services/resources/admin/ClientAttributeCertificateResource.java")


# ===========================================================================
# ADMIN -- roles / groups / idp / components / auth / attack-detection
# ===========================================================================
rd("admin_roles", "List/create realm roles", "/admin/realms/{realm}/roles", "Role", "RoleName(role)",
   subject="RealmAdmin", auth="admin", perm="view-realm / manage-realm",
   reach=["Roles are the authorization currency; composites bundle privileges."],
   evref="services/resources/admin/RoleContainerResource.java")
rd("admin_groups", "List/create groups", "/admin/realms/{realm}/groups", "Group", "GroupID(group)",
   subject="RealmAdmin", auth="admin", perm="view-users / manage-users",
   reach=["Group role-mappings grant privileges to all members."],
   evref="services/resources/admin/GroupsResource.java")

# SSRF: IdP metadata import
_fromUrl = io("input", "fromUrl / RemoteURL(fetch)", "object_attribute", [], "Metadata URL fetched server-side (SSRF).")
action(
    "admin_idp_import_config", "Import IdP metadata (SSRF)", "Create", "admin_idp_import_config", "RealmAdmin",
    obj("entity", "idpconfig", "IdPConfig", "response", "", "IdPConfig(realm)", role="response"),
    requirements=[req("authentication", _admin_auth, "Admin bearer token."),
                  req("authorization", f_can(ACTOR, "Create", ent("realm", "Realm", "scope")),
                      "Requires manage-identity-providers.")],
    gen=[eff(know("IdPConfig", ent("idpconfig", "IdPConfig", "response")), "io_reference",
             "Returns the parsed IdP config.")],
    kill=[],
    io_accounting=[_fromUrl,
                   io("output", "config / IdPConfig(realm)", "gen",
                      [kf(know("IdPConfig", ent("idpconfig", "IdPConfig", "response")))])],
    bindings=_b("/admin/realms/{realm}/identity-provider/import-config"),
    vis="black_box", vis_reason="IdP metadata import (SSRF).", reachable=True,
    reach_conds=["manage-identity-providers. Server GETs 'fromUrl' -> SSRF to internal services."],
    evidence=[src("services/resources/admin/IdentityProvidersResource.java", "importFrom")],
    confidence=0.8, reasoning="server fetches an IdP metadata URL.",
    description="An admin makes the server fetch an IdP metadata URL (SSRF sink #2).",
    notes="SSRF.")

mu("admin_idp_instances", "Create an identity provider", "Create",
   "/admin/realms/{realm}/identity-provider/instances", "IdP", "IdPAlias(idp)", subject="RealmAdmin",
   auth="admin", mode="create", perm="manage-identity-providers",
   reach=["manage-identity-providers. A rogue IdP (with config URLs) = SSRF + trust injection."],
   evref="services/resources/admin/IdentityProvidersResource.java")
rd("admin_components", "List/create components", "/admin/realms/{realm}/components", "Component",
   "ComponentID(component)", subject="RealmAdmin", auth="admin", perm="realm-management manage-realm",
   reach=["manage-realm. LDAP federation components hold bind creds + a connection URL (SSRF/credential surface)."],
   evref="services/resources/admin/ComponentResource.java")
mu("admin_auth_flows", "Create authentication flow", "Create",
   "/admin/realms/{realm}/authentication/flows", "AuthFlow", "AuthFlowID(flow)", subject="RealmAdmin",
   auth="admin", mode="create", perm="manage-realm",
   reach=["manage-realm. Reordering/replacing executions can WEAKEN authentication (drop password/OTP)."],
   evref="services/resources/admin/AuthenticationManagementResource.java")
rd("admin_attack_detection", "Read brute-force status",
   "/admin/realms/{realm}/attack-detection/brute-force/users/{userId}", "BruteForceStatus",
   "BruteForceStatus(user)", subject="RealmAdmin", auth="admin", inref=("userId", "UserID", "User"),
   perm="view-realm",
   reach=["view-realm (GET) / manage-users (DELETE clears lockout -> re-enables brute-force)."],
   evref="services/resources/admin/AttackDetectionResource.java")
