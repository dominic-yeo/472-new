# -*- coding: utf-8 -*-
"""Outline L2 action cores over the six Pengent predicates.

io_accounting fact strings use common.fact_key so they match Req/Eff. Auth: a token
(API key | OAuth access token | session JWT, via Bearer | body 'token' | ?token= |
cookie) -> a USER with a TEAM + ROLE (admin|member|viewer|guest). Authorization is
cancan authorize(user, action, model) in server/policies; modeled as Can(...) with
the action named in reach_conds. Unauthenticated surfaces: /auth, /oauth, the
bootstrap installation.create, and public SHARE reads (subject ShareGuest/Anonymous).
Evidence -> outline/server/routes & server/policies.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind

ACTOR = subj()


def kf(f):
    return fact_key(f)


def src(ref, supports="route + policy"):
    return c.ev("source", "outline/server/" + ref, supports)


def ent(k, t, role="target"):
    return entity(k, t, role)


def know(rt, e):
    return f_know(ACTOR, reference(rt, e))


_tok_auth = f_auth(ACTOR, "SessionToken")

AUTHS = {"token": (_tok_auth, "Authenticated: a token resolves to a user+role."),
         "none": (None, None)}


def _b(path, method="POST"):
    return [bind(K(path), [method], sel_field="method", sel_values=[method])]


def rd(akey, name, path, out_type, out_ref, subject="User", auth="token", perm=None,
       inref=None, reach=None, note=None, evref=None, method="POST"):
    """Read action: output is Know(actor, ref(out_ref, <out_type>))."""
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
                        "Policy: " + perm + "."))
    action(
        akey, name, "Read", akey, subject,
        obj("entity", out_type.lower(), out_type, "response", "", out_ref, role="response"),
        requirements=reqs, gen=[eff(o, "io_reference", "Returns " + out_type.lower() + ".")], kill=[],
        io_accounting=io_in + [io("output", out_type.lower() + " / " + out_ref, "gen", [kf(o)])],
        bindings=_b(path, method),
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=reach or ["Authenticated + policy read."],
        evidence=[src(evref or akey)], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


def mu(akey, name, crud, path, obj_type, obj_ref, subject="User", auth="token", perm=None,
       inref=None, mode="update", state_field="fields", reach=None, note=None, evref=None):
    """Mutate action. mode in {create, update, delete}."""
    tgt = ent(obj_type.lower(), obj_type, "target")
    reqs = []
    a, areason = AUTHS[auth]
    if a:
        reqs.append(req("authentication", a, areason))
    if perm:
        reqs.append(req("authorization", f_can(ACTOR, crud, tgt), "Policy: " + perm + "."))
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
        bindings=_b(path),
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=reach or ["Authenticated + policy permission."],
        evidence=[src(evref or akey)], confidence=0.8, reasoning=name + ".",
        description=name + ".", notes=note)


# ===========================================================================
# AUTH / SESSION / OAUTH  (explicit -- credential + auth-transition semantics)
# ===========================================================================
rd("auth_config", "Read public auth config", "/api/auth.config", "AuthConfig", "AuthConfig(team)",
   subject="Anonymous", auth="none",
   reach=["PUBLIC. Team existence + enabled SSO providers (enumeration oracle)."],
   evref="routes/api/auth/auth.ts")

rd("auth_info", "Read my session", "/api/auth.info", "User", "UserID(user)",
   reach=["Authenticated: returns the caller's user + team + memberships."],
   evref="routes/api/auth/auth.ts")

# logout
action(
    "logout", "Log out", "Delete", "logout", "User",
    obj("state", "session", "Session", "request", "", "AccessToken(session)", role="target",
        state_field="authenticated"),
    requirements=[req("authentication", _tok_auth, "A live session/token.")],
    gen=[], kill=[eff(f_auth(ACTOR, "SessionToken"), "auth_transition", "Session is revoked.")],
    io_accounting=[],
    bindings=_b("/api/auth.delete"),
    vis="black_box", vis_reason="Logout.", reachable=True,
    reach_conds=["Authenticated; clears the session cookie/token."],
    evidence=[src("routes/api/auth/auth.ts", "logout")],
    confidence=0.85, reasoning="auth.delete revokes the session.",
    description="A user ends their session.")

# bootstrap: first team + admin
_biEmail = know("UserEmail", ent("user", "User", "self"))
_biTok = know("AccessToken", ent("session", "Session", "created"))
action(
    "installation_create", "Bootstrap installation", "Create", "installation_create", "Anonymous",
    obj("entity", "team", "Team", "response", "", "TeamID(team)", role="created"),
    requirements=[req("knowledge", _biEmail, "Caller supplies an admin email/name.")],
    gen=[eff(f_exists(ent("team", "Team", "created")), "action_semantics", "The first team is created."),
         eff(f_auth(ACTOR, "SessionToken"), "auth_transition", "Caller becomes the first admin."),
         eff(_biTok, "io_reference", "Returns an access token.")],
    kill=[],
    io_accounting=[io("input", "userEmail / UserEmail(user)", "req", [kf(_biEmail)]),
                   io("output", "accessToken / AccessToken(session)", "gen", [kf(_biTok)])],
    bindings=_b("/api/installation.create"),
    vis="black_box", vis_reason="First-run bootstrap.", reachable=True,
    reach_conds=["PUBLIC but single-shot: refuses once any team exists. First-boot takeover."],
    evidence=[src("routes/api/installation/installation.ts", "bootstrap")],
    confidence=0.85, reasoning="Creates the first team+admin when none exist.",
    description="On a fresh self-hosted install, a visitor creates the first workspace + admin.")

rd("installation_info", "Read server version", "/api/installation.info", "ServerInfo", "ServerInfo(team)",
   reach=["Authenticated."], evref="routes/api/installation/installation.ts")

# email magic-link sign-in
_siEmail = know("UserEmail", ent("user", "User", "self"))
action(
    "signin_email", "Request email sign-in link", "Create", "signin_email", "Anonymous",
    obj("state", "session", "Session", "request", "", "UserEmail(user)", role="target",
        state_field="signin_link"),
    requirements=[req("knowledge", _siEmail, "Caller supplies an email address.")],
    gen=[eff(f_state(ent("user", "User", "target"), "signin_link", "sent"), "action_semantics",
             "A sign-in link is emailed to the address if it exists.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "req", [kf(_siEmail)])],
    bindings=_b("/auth/email"),
    vis="black_box", vis_reason="Email sign-in.", reachable=True,
    reach_conds=["PUBLIC. User-enumeration via response/timing; rate-limited."],
    evidence=[src("../plugins/email/server/auth/email.ts", "magic link")],
    confidence=0.8, reasoning="email provider mails a sign-in token.",
    description="A visitor requests a password-less sign-in link by email.")

rd("signin_sso_start", "Start SSO sign-in", "/auth/:provider", "Redirect", "Redirect(idp)",
   subject="Anonymous", auth="none", method="GET",
   reach=["PUBLIC. Begins a passport OAuth flow; 'client' picks web/desktop return."],
   evref="../plugins/google/server/auth/google.ts")

# SSO callback mints a session
_ssoEmail = know("UserEmail", ent("user", "User", "self"))
_ssoTok = know("AccessToken", ent("session", "Session", "created"))
action(
    "signin_sso_callback", "Complete SSO sign-in", "Create", "signin_sso_callback", "Anonymous",
    obj("state", "session", "Session", "response", "", "AccessToken(session)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", _ssoEmail, "IdP returns a verified email claim.")],
    gen=[eff(f_auth(ACTOR, "SessionToken"), "auth_transition", "Caller becomes authenticated."),
         eff(_ssoTok, "io_reference", "Sets an accessToken cookie.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Verified IdP email."),
                   io("output", "accessToken / AccessToken(session)", "gen", [kf(_ssoTok)])],
    bindings=_b("/auth/:provider.callback", "GET"),
    vis="black_box", vis_reason="SSO callback.", reachable=True,
    reach_conds=["PUBLIC. Account-linking by verified email; redirect/state is the open-redirect surface."],
    evidence=[src("../plugins/google/server/auth/google.ts", "callback")],
    confidence=0.8, reasoning="callback provisions/links a user and mints a session.",
    description="An IdP redirect completes sign-in and establishes a session.")

rd("auth_redirect", "Post-login redirect", "/auth/redirect", "Redirect", "Redirect(team)",
   subject="Anonymous", auth="none", method="GET",
   reach=["Transfer cookie -> team subdomain; redirect-target validation surface."],
   evref="routes/auth/index.ts")

# OAuth2 authorize (consent)
action(
    "oauth_authorize", "OAuth authorize", "Create", "oauth_authorize", "User",
    obj("entity", "authcode", "OAuthCode", "response", "", "OAuthCode(session)", role="created"),
    requirements=[req("authentication", _tok_auth, "A signed-in user grants consent."),
                  req("knowledge", know("OAuthClientID", ent("oauthclient", "OAuthClient", "target")),
                      "References a registered client_id + redirect_uri.")],
    gen=[eff(f_exists(ent("authcode", "OAuthCode", "created")), "action_semantics",
             "An authorization code is issued to the client.")],
    kill=[],
    io_accounting=[io("input", "client_id / OAuthClientID(oauthclient)", "req",
                      [kf(know("OAuthClientID", ent("oauthclient", "OAuthClient", "target")))])],
    bindings=_b("/oauth/authorize", "GET"),
    vis="black_box", vis_reason="OAuth consent.", reachable=True,
    reach_conds=["Authenticated. redirect_uri + scope + PKCE validation are the surface."],
    evidence=[src("routes/oauth/index.ts", "authorize")],
    confidence=0.8, reasoning="authorize issues a code to the client.",
    description="A signed-in user authorizes an OAuth client and a code is issued.")

# OAuth2 token exchange
_ocCode = know("OAuthCode", ent("authcode", "OAuthCode", "target"))
_ocTok = know("AccessToken", ent("session", "Session", "created"))
action(
    "oauth_token", "OAuth token exchange", "Create", "oauth_token", "Anonymous",
    obj("state", "session", "Session", "response", "", "AccessToken(session)", role="created",
        state_field="access_token"),
    requirements=[req("knowledge", _ocCode, "Client presents an auth code (+ PKCE verifier) or a refresh token.")],
    gen=[eff(_ocTok, "io_reference", "Returns a scoped OAuth access token.")],
    kill=[],
    io_accounting=[io("input", "code / OAuthCode(authcode)", "req", [kf(_ocCode)]),
                   io("output", "access_token / AccessToken(session)", "gen", [kf(_ocTok)])],
    bindings=_b("/oauth/token"),
    vis="black_box", vis_reason="OAuth token.", reachable=True,
    reach_conds=["Client credentials + code/PKCE -> scoped access token."],
    evidence=[src("routes/oauth/index.ts", "token")],
    confidence=0.8, reasoning="token endpoint mints an access token.",
    description="A client exchanges a code/refresh token for a scoped access token.")

mu("oauth_revoke", "Revoke OAuth token", "Delete", "/oauth/revoke", "AccessToken", "AccessToken(session)",
   subject="Anonymous", auth="none", mode="delete",
   inref=("token", "AccessToken", "AccessToken"),
   reach=["Client revokes its own token."], evref="routes/oauth/index.ts")


# ===========================================================================
# USERS
# ===========================================================================
rd("users_list", "List team members", "/api/users.list", "User", "UserID(user)",
   reach=["Authenticated member; team-scoped directory."], evref="routes/api/users/users.ts")
rd("users_info", "Read a user", "/api/users.info", "User", "UserID(user)",
   inref=("userId", "UserID", "User"),
   reach=["Authenticated; any member can read a teammate (IDOR surface on id)."],
   evref="routes/api/users/users.ts")
mu("users_invite", "Invite users", "Create", "/api/users.invite", "User", "UserID(user)",
   mode="create", perm="authorize(user,'inviteUser',team)",
   reach=["Member+; 'role' in the invite is an escalation surface."], evref="routes/api/users/users.ts")
mu("users_update", "Update a user", "Update", "/api/users.update", "User", "UserID(user)",
   inref=("userId", "UserID", "User"), perm="authorize(actor,'update',targetUser)",
   reach=["Self, or admin on others."], evref="routes/api/users/users.ts")
mu("users_update_email", "Change user email", "Update", "/api/users.updateEmail", "User", "UserID(user)",
   inref=("userId", "UserID", "User"), state_field="email",
   perm="authorize(actor,'update',targetUser)",
   reach=["Self (verification) / admin. Account-takeover-adjacent."], evref="routes/api/users/users.ts")
mu("users_update_role", "Change a user role", "Update", "/api/users.update_role", "User", "UserID(user)",
   subject="Admin", inref=("userId", "UserID", "User"), state_field="role",
   perm="authorize(actor,'promote'/'demote'/'update',targetUser)",
   reach=["ADMIN. Promoting to admin = full team control (primary escalation lever)."],
   evref="routes/api/users/users.ts")
mu("users_promote", "Promote to admin", "Update", "/api/users.promote", "User", "UserID(user)",
   subject="Admin", inref=("userId", "UserID", "User"), state_field="role",
   perm="authorize(actor,'promote',targetUser)",
   reach=["ADMIN only."], evref="routes/api/users/users.ts")
mu("users_demote", "Demote admin", "Update", "/api/users.demote", "User", "UserID(user)",
   subject="Admin", inref=("userId", "UserID", "User"), state_field="role",
   perm="authorize(actor,'demote',targetUser)",
   reach=["ADMIN only; cannot demote the last admin."], evref="routes/api/users/users.ts")
mu("users_suspend", "Suspend a user", "Update", "/api/users.suspend", "User", "UserID(user)",
   subject="Admin", inref=("userId", "UserID", "User"), state_field="suspended",
   perm="authorize(actor,'update',targetUser)",
   reach=["ADMIN only. Account-DoS lever."], evref="routes/api/users/users.ts")
mu("users_activate", "Reactivate a user", "Update", "/api/users.activate", "User", "UserID(user)",
   subject="Admin", inref=("userId", "UserID", "User"), state_field="suspended",
   perm="authorize(actor,'update',targetUser)", reach=["ADMIN only."], evref="routes/api/users/users.ts")
mu("users_delete", "Delete a user", "Delete", "/api/users.delete", "User", "UserID(user)",
   inref=("userId", "UserID", "User"), mode="delete",
   perm="authorize(actor,'delete',targetUser)",
   reach=["Self (with emailed code) or ADMIN on others."], evref="routes/api/users/users.ts")


# ===========================================================================
# API KEYS + OAUTH CLIENTS + AUTHENTICATIONS
# ===========================================================================
mu("apikeys_create", "Create API key", "Create", "/api/apiKeys.create", "ApiKey", "ApiKeyID(apiKey)",
   mode="create", perm="authorize(user,'createApiKey',team)",
   reach=["Scoped read/write/create long-lived bearer; accepted on header/body/query -> leak surface."],
   evref="routes/api/apiKeys/apiKeys.ts",
   note="The created token value is returned once; it is a bearer credential.")
rd("apikeys_list", "List API keys", "/api/apiKeys.list", "ApiKey", "ApiKeyID(apiKey)",
   reach=["Authenticated; own keys."], evref="routes/api/apiKeys/apiKeys.ts")
mu("apikeys_delete", "Revoke API key", "Delete", "/api/apiKeys.delete", "ApiKey", "ApiKeyID(apiKey)",
   inref=("id", "ApiKeyID", "ApiKey"), mode="delete", perm="authorize(user,'delete',apiKey)",
   reach=["Owner / admin."], evref="routes/api/apiKeys/apiKeys.ts")

mu("oauthclients_create", "Create OAuth client", "Create", "/api/oauthClients.create", "OAuthClient",
   "OAuthClientID(oauthClient)", mode="create", perm="authorize(user,'createOAuthClient',team)",
   reach=["redirectUris + 'published' are the phishing/consent surface; returns a client secret."],
   evref="routes/api/oauthClients/oauthClients.ts")
mu("oauthclients_rotate_secret", "Rotate client secret", "Update", "/api/oauthClients.rotate_secret",
   "OAuthClient", "OAuthClientID(oauthClient)", inref=("id", "OAuthClientID", "OAuthClient"),
   state_field="secret", perm="authorize(user,'update',oauthClient)",
   reach=["Owner / admin."], evref="routes/api/oauthClients/oauthClients.ts")
rd("oauthclients_info", "Read OAuth client", "/api/oauthClients.info", "OAuthClient",
   "OAuthClientID(oauthClient)", reach=["Published clients are readable for the consent screen (metadata oracle)."],
   evref="routes/api/oauthClients/oauthClients.ts")
mu("oauthclients_update", "Update OAuth client", "Update", "/api/oauthClients.update", "OAuthClient",
   "OAuthClientID(oauthClient)", inref=("id", "OAuthClientID", "OAuthClient"),
   perm="authorize(user,'update',oauthClient)",
   reach=["Owner / admin. redirectUris change = hijack surface."],
   evref="routes/api/oauthClients/oauthClients.ts")
mu("oauthclients_delete", "Delete OAuth client", "Delete", "/api/oauthClients.delete", "OAuthClient",
   "OAuthClientID(oauthClient)", inref=("id", "OAuthClientID", "OAuthClient"), mode="delete",
   perm="authorize(user,'delete',oauthClient)", reach=["Owner / admin."],
   evref="routes/api/oauthClients/oauthClients.ts")
rd("oauthauth_list", "List authorized apps", "/api/oauthAuthentications.list", "OAuthGrant",
   "OAuthGrantID(grant)", reach=["Authenticated; own grants."],
   evref="routes/api/oauthAuthentications/oauthAuthentications.ts")
mu("oauthauth_delete", "Revoke app access", "Delete", "/api/oauthAuthentications.delete", "OAuthGrant",
   "OAuthGrantID(grant)", inref=("oauthClientId", "OAuthClientID", "OAuthClient"), mode="delete",
   reach=["Authenticated; own grant (deletes grant + tokens)."],
   evref="routes/api/oauthAuthentications/oauthAuthentications.ts")


# ===========================================================================
# COLLECTIONS
# ===========================================================================
CO = "routes/api/collections/collections.ts"
mu("collections_create", "Create collection", "Create", "/api/collections.create", "Collection",
   "CollectionID(collection)", mode="create", perm="authorize(user,'createCollection',team)",
   reach=["'permission' sets the team-wide default access on the new collection."], evref=CO)
rd("collections_info", "Read collection", "/api/collections.info", "Collection", "CollectionID(collection)",
   inref=("collectionId", "CollectionID", "Collection"), perm="authorize(user,'read',collection)",
   reach=["Membership or team default permission."], evref=CO)
rd("collections_list", "List collections", "/api/collections.list", "Collection", "CollectionID(collection)",
   reach=["Authenticated; filtered by access."], evref=CO)
mu("collections_update", "Update collection", "Update", "/api/collections.update", "Collection",
   "CollectionID(collection)", inref=("collectionId", "CollectionID", "Collection"),
   perm="authorize(user,'update',collection)",
   reach=["Collection ADMIN. 'permission' widens team access."], evref=CO)
mu("collections_delete", "Delete collection", "Delete", "/api/collections.delete", "Collection",
   "CollectionID(collection)", inref=("collectionId", "CollectionID", "Collection"), mode="delete",
   perm="authorize(user,'delete',collection)",
   reach=["Collection admin. Cascades to documents (destructive)."], evref=CO)
mu("collections_add_user", "Grant collection access", "Update", "/api/collections.add_user", "Collection",
   "CollectionID(collection)", inref=("userId", "UserID", "User"),
   perm="authorize(user,'update',collection)", state_field="memberships",
   reach=["Collection admin. 'admin' permission = escalation within the collection."], evref=CO)
mu("collections_add_group", "Grant collection access to a group", "Update", "/api/collections.add_group",
   "Collection", "CollectionID(collection)", inref=("groupId", "GroupID", "Group"),
   perm="authorize(user,'update',collection)", state_field="group_memberships",
   reach=["Collection admin."], evref=CO)
rd("collections_documents", "Collection document tree", "/api/collections.documents", "Collection",
   "CollectionID(collection)", inref=("collectionId", "CollectionID", "Collection"),
   perm="authorize(user,'read',collection)", reach=["Read access to the collection."], evref=CO)
mu("collections_export", "Export a collection", "Create", "/api/collections.export", "FileOperation",
   "FileOperationID(fileOperation)", inref=("collectionId", "CollectionID", "Collection"), mode="create",
   perm="authorize(user,'export',collection)",
   reach=["Read+export on the collection; produces a downloadable archive."], evref=CO)
mu("collections_export_all", "Export entire workspace", "Create", "/api/collections.export_all",
   "FileOperation", "FileOperationID(fileOperation)", subject="Admin", mode="create",
   perm="authorize(user,'export',team)",
   reach=["ADMIN. Bulk data-exfiltration primitive."], evref=CO)


# ===========================================================================
# DOCUMENTS
# ===========================================================================
DO = "routes/api/documents/documents.ts"
mu("documents_create", "Create document", "Create", "/api/documents.create", "Document",
   "DocumentID(document)", inref=("collectionId", "CollectionID", "Collection"), mode="create",
   perm="authorize(user,'createDocument',collection)",
   reach=["createDocument on the collection / update on the parent."], evref=DO)

# documents.info -- dual path: authed read OR public share read (ShareGuest)
_docRef = know("DocumentID", ent("document", "Document", "target"))
_docOut = know("DocumentID", ent("document", "Document", "response"))
action(
    "documents_info", "Read a document", "Read", "documents_info", "User",
    obj("entity", "document", "Document", "response", "", "DocumentID(document)", role="response"),
    requirements=[req("authentication", _tok_auth, "Authenticated read path."),
                  req("knowledge", _docRef, "References the document by id/urlId."),
                  req("authorization", f_can(ACTOR, "Read", ent("document", "Document", "scope")),
                      "authorize(user,'read',document) via collection/membership.")],
    gen=[eff(_docOut, "io_reference", "Returns the document.")], kill=[],
    io_accounting=[io("input", "id / DocumentID(document)", "req", [kf(_docRef)]),
                   io("output", "document / DocumentID(document)", "gen", [kf(_docOut)])],
    bindings=_b("/api/documents.info"),
    vis="black_box", vis_reason="Authed document read.", reachable=True,
    reach_conds=["authorize(user,'read',document). Dual endpoint: see documents_info_share for the public branch."],
    evidence=[src(DO, "info")], confidence=0.85, reasoning="documents.info by id.",
    description="A member reads a document they are authorized for.",
    notes="The same route also serves shareId reads (documents_info_share).")

_shareRef = know("ShareID", ent("share", "Share", "target"))
action(
    "documents_info_share", "Read a document via a public share", "Read", "documents_info_share", "ShareGuest",
    obj("entity", "document", "Document", "response", "", "DocumentID(document)", role="response"),
    requirements=[req("knowledge", _shareRef, "Caller presents a published shareId (no login).")],
    gen=[eff(_docOut, "io_reference", "Returns the shared document.")], kill=[],
    io_accounting=[io("input", "shareId / ShareID(share)", "req", [kf(_shareRef)]),
                   io("output", "document / DocumentID(document)", "gen", [kf(_docOut)])],
    bindings=_b("/api/documents.info"),
    vis="black_box", vis_reason="Public share read.", reachable=True,
    reach_conds=["UNAUTHENTICATED: a published share grants read to the document (and, if set, its children)."],
    evidence=[src(DO, "info shareId branch"), src(DO, "shares.ts")],
    confidence=0.85, reasoning="documents.info accepts shareId without auth.",
    description="An anonymous visitor reads a document through a published share link.",
    notes="Core public-read surface; shareId guess/leak => content exposure.")

rd("documents_list", "List documents", "/api/documents.list", "Document", "DocumentID(document)",
   reach=["Authenticated; access-filtered."], evref=DO)
rd("documents_search", "Search documents", "/api/documents.search", "Document", "DocumentID(document)",
   reach=["Authenticated full-text (access-filtered); shareId branch searches within a public share."], evref=DO)
mu("documents_update", "Edit a document", "Update", "/api/documents.update", "Document", "DocumentID(document)",
   inref=("documentId", "DocumentID", "Document"), perm="authorize(user,'update',document)",
   reach=["read_write membership / collection permission."], evref=DO)
mu("documents_delete", "Delete a document", "Delete", "/api/documents.delete", "Document", "DocumentID(document)",
   inref=("documentId", "DocumentID", "Document"), mode="delete",
   perm="authorize(user,'delete'/'permanentDelete',document)", reach=["Delete permission on the document."],
   evref=DO)
mu("documents_move", "Move a document", "Update", "/api/documents.move", "Document", "DocumentID(document)",
   inref=("documentId", "DocumentID", "Document"), state_field="collectionId",
   perm="authorize(user,'move',document)",
   reach=["move on the doc + update on the destination collection (cross-collection exposure risk)."], evref=DO)
mu("documents_import", "Import a file as a document", "Create", "/api/documents.import", "Document",
   "DocumentID(document)", inref=("collectionId", "CollectionID", "Collection"), mode="create",
   perm="authorize(user,'createDocument',collection)",
   reach=["Untrusted file parsing (docx/html/markdown) -> stored document."], evref=DO)
rd("documents_export", "Export a document", "/api/documents.export", "Document", "DocumentID(document)",
   inref=("documentId", "DocumentID", "Document"), perm="authorize(user,'read',document)",
   reach=["Read permission on the document."], evref=DO)
mu("documents_add_user", "Share a document with a user", "Update", "/api/documents.add_user", "Document",
   "DocumentID(document)", inref=("documentId", "DocumentID", "Document"), state_field="memberships",
   perm="authorize(user,'manageUsers',document)",
   reach=["Direct per-document membership grant."], evref=DO)
mu("documents_add_group", "Share a document with a group", "Update", "/api/documents.add_group", "Document",
   "DocumentID(document)", inref=("documentId", "DocumentID", "Document"), state_field="group_memberships",
   perm="authorize(user,'manageUsers',document)", reach=["manageUsers on the document."], evref=DO)
rd("documents_users", "List document users", "/api/documents.users", "User", "UserID(user)",
   inref=("documentId", "DocumentID", "Document"), perm="authorize(user,'read',document)",
   reach=["Read permission on the document."], evref=DO)
mu("documents_templatize", "Templatize a document", "Update", "/api/documents.templatize", "Document",
   "DocumentID(document)", inref=("documentId", "DocumentID", "Document"), state_field="template",
   perm="authorize(user,'update',document)", reach=["Update on the document."], evref=DO)
mu("documents_unpublish", "Unpublish a document", "Update", "/api/documents.unpublish", "Document",
   "DocumentID(document)", inref=("documentId", "DocumentID", "Document"), state_field="published",
   perm="authorize(user,'unpublish',document)", reach=["Unpublish permission."], evref=DO)
mu("documents_empty_trash", "Empty trash", "Delete", "/api/documents.empty_trash", "Document",
   "DocumentID(document)", mode="delete", perm="authorize over owned/permitted trashed docs",
   reach=["Permanently deletes the caller's trashed documents (bulk destructive)."], evref=DO)


# ===========================================================================
# SHARES
# ===========================================================================
SH = "routes/api/shares/shares.ts"
mu("shares_create", "Create a public share", "Create", "/api/shares.create", "Share", "ShareID(share)",
   inref=("documentId", "DocumentID", "Document"), mode="create",
   perm="authorize(user,'share',document) + collection.sharing",
   reach=["'published'=internet-readable; 'includeChildDocuments' widens to the subtree. Core exposure primitive."],
   evref=SH)
# shares.info is optional-auth: model the public (ShareGuest) read as primary
_shInfoRef = know("ShareID", ent("share", "Share", "target"))
_shInfoOut = know("ShareID", ent("share", "Share", "response"))
action(
    "shares_info", "Read share info", "Read", "shares_info", "ShareGuest",
    obj("entity", "share", "Share", "response", "", "ShareID(share)", role="response"),
    requirements=[req("knowledge", _shInfoRef, "Caller presents a shareId.")],
    gen=[eff(_shInfoOut, "io_reference", "Returns share metadata (published state, document ref).")], kill=[],
    io_accounting=[io("input", "id / ShareID(share)", "req", [kf(_shInfoRef)]),
                   io("output", "share / ShareID(share)", "gen", [kf(_shInfoOut)])],
    bindings=_b("/api/shares.info"),
    vis="black_box", vis_reason="Share info (optional auth).", reachable=True,
    reach_conds=["auth optional: a published share is readable unauthenticated (existence/metadata oracle)."],
    evidence=[src(SH, "info auth optional")], confidence=0.8, reasoning="shares.info uses auth({optional:true}).",
    description="A visitor reads a published share's metadata without authenticating.")
mu("shares_update", "Update a share", "Update", "/api/shares.update", "Share", "ShareID(share)",
   inref=("id", "ShareID", "Share"), state_field="published", perm="authorize(user,'update',share)",
   reach=["Flipping 'published' widens/narrows exposure."], evref=SH)
mu("shares_revoke", "Revoke a share", "Delete", "/api/shares.revoke", "Share", "ShareID(share)",
   inref=("id", "ShareID", "Share"), mode="delete", perm="authorize(user,'revoke',share)",
   reach=["Revoke the share link."], evref=SH)
rd("shares_list", "List shares", "/api/shares.list", "Share", "ShareID(share)",
   reach=["Authenticated; own/team shares."], evref=SH)


# ===========================================================================
# COMMENTS
# ===========================================================================
CM = "routes/api/comments/comments.ts"
mu("comments_create", "Create a comment", "Create", "/api/comments.create", "Comment", "CommentID(comment)",
   inref=("documentId", "DocumentID", "Document"), mode="create", perm="authorize(user,'comment',document)",
   reach=["Comment permission on the document."], evref=CM)
mu("comments_update", "Edit a comment", "Update", "/api/comments.update", "Comment", "CommentID(comment)",
   inref=("id", "CommentID", "Comment"), perm="authorize(user,'update',comment)",
   reach=["Author / document admin."], evref=CM)
mu("comments_delete", "Delete a comment", "Delete", "/api/comments.delete", "Comment", "CommentID(comment)",
   inref=("id", "CommentID", "Comment"), mode="delete", perm="authorize(user,'delete',comment)",
   reach=["Author / document admin."], evref=CM)
rd("comments_info", "Read a comment", "/api/comments.info", "Comment", "CommentID(comment)",
   inref=("id", "CommentID", "Comment"), perm="authorize(user,'read',comment)",
   reach=["Read access to the parent document."], evref=CM)
rd("comments_list", "List comments", "/api/comments.list", "Comment", "CommentID(comment)",
   inref=("documentId", "DocumentID", "Document"), perm="authorize(user,'read',document)",
   reach=["Read access to the document."], evref=CM)


# ===========================================================================
# GROUPS
# ===========================================================================
GR = "routes/api/groups/groups.ts"
mu("groups_create", "Create a group", "Create", "/api/groups.create", "Group", "GroupID(group)",
   subject="Admin", mode="create", perm="authorize(user,'createGroup',team)", reach=["ADMIN."], evref=GR)
mu("groups_add_user", "Add user to group", "Update", "/api/groups.add_user", "Group", "GroupID(group)",
   subject="Admin", inref=("userId", "UserID", "User"), state_field="members",
   perm="authorize(user,'update',group)",
   reach=["ADMIN. Membership inherits all the group's collection grants (indirect escalation)."], evref=GR)
mu("groups_update", "Update a group", "Update", "/api/groups.update", "Group", "GroupID(group)",
   subject="Admin", inref=("id", "GroupID", "Group"), perm="authorize(user,'update',group)",
   reach=["ADMIN."], evref=GR)
mu("groups_delete", "Delete a group", "Delete", "/api/groups.delete", "Group", "GroupID(group)",
   subject="Admin", inref=("id", "GroupID", "Group"), mode="delete", perm="authorize(user,'delete',group)",
   reach=["ADMIN."], evref=GR)


# ===========================================================================
# ATTACHMENTS + FILE OPS + IMPORTS  (incl. SSRF)
# ===========================================================================
AT = "routes/api/attachments/attachments.ts"
mu("attachments_create", "Pre-sign an upload", "Create", "/api/attachments.create", "Attachment",
   "AttachmentID(attachment)", mode="create", perm="authorize(user,'createAttachment',team)",
   reach=["Returns a storage PUT URL; preset governs ACL/size."], evref=AT)

# SSRF: server fetches an attacker URL
_urlIn = io("input", "url / RemoteURL(fetch)", "object_attribute", [], "Server-fetched URL (SSRF sink).")
_attOut = know("AttachmentID", ent("attachment", "Attachment", "created"))
action(
    "attachments_create_from_url", "Fetch a remote URL into storage (SSRF)", "Create",
    "attachments_create_from_url", "User",
    obj("entity", "attachment", "Attachment", "response", "", "AttachmentID(attachment)", role="created"),
    requirements=[req("authentication", _tok_auth, "Authenticated member.")],
    gen=[eff(f_exists(ent("attachment", "Attachment", "created")), "action_semantics",
             "The fetched bytes are stored as an attachment."),
         eff(_attOut, "io_reference", "Returns the stored attachment.")],
    kill=[],
    io_accounting=[_urlIn, io("output", "attachment / AttachmentID(attachment)", "gen", [kf(_attOut)])],
    bindings=_b("/api/attachments.createFromUrl"),
    vis="black_box", vis_reason="Server-side fetch of an attacker URL.", reachable=True,
    reach_conds=["Authenticated. SSRF: the server GETs 'url' (cloud metadata / internal services)."],
    evidence=[src(AT, "createFromUrl")], confidence=0.8,
    reasoning="createFromUrl fetches a caller-supplied URL server-side.",
    description="A member makes the server fetch an arbitrary URL and store it (SSRF sink #1).",
    notes="SSRF.")

mu("attachments_delete", "Delete an attachment", "Delete", "/api/attachments.delete", "Attachment",
   "AttachmentID(attachment)", inref=("id", "AttachmentID", "Attachment"), mode="delete",
   perm="authorize(user,'delete',attachment)", reach=["Delete permission on the attachment."], evref=AT)

FO = "routes/api/fileOperations/fileOperations.ts"
rd("fileops_info", "Read a file operation", "/api/fileOperations.info", "FileOperation",
   "FileOperationID(fileOperation)", inref=("id", "FileOperationID", "FileOperation"),
   perm="authorize(user,'read',fileOperation)",
   reach=["Owner/admin. The download URL is the export payload."], evref=FO)
mu("fileops_delete", "Delete a file operation", "Delete", "/api/fileOperations.delete", "FileOperation",
   "FileOperationID(fileOperation)", inref=("id", "FileOperationID", "FileOperation"), mode="delete",
   perm="authorize(user,'delete',fileOperation)", reach=["Owner/admin."], evref=FO)

# SSRF #2: external import
_impOut = know("ImportID", ent("import", "Import", "created"))
action(
    "imports_create", "Start an external import (SSRF-adjacent)", "Create", "imports_create", "Admin",
    obj("entity", "import", "Import", "response", "", "ImportID(import)", role="created"),
    requirements=[req("authentication", _tok_auth, "Authenticated admin."),
                  req("authorization", f_can(ACTOR, "Create", ent("import", "Import", "scope")),
                      "authorize(user,'createImport',team): ADMIN.")],
    gen=[eff(f_exists(ent("import", "Import", "created")), "action_semantics",
             "An import job is queued; the server pulls from an external provider."),
         eff(_impOut, "io_reference", "Returns the import job.")],
    kill=[],
    io_accounting=[io("input", "input / RemoteURL(fetch)", "object_attribute", [],
                      "External source refs the server fetches."),
                   io("output", "import / ImportID(import)", "gen", [kf(_impOut)])],
    bindings=_b("/api/imports.create"),
    vis="black_box", vis_reason="Server-side external import.", reachable=True,
    reach_conds=["ADMIN. Server-side fetch from a 3rd-party provider (SSRF-adjacent)."],
    evidence=[src("routes/api/imports/imports.ts", "create")], confidence=0.75,
    reasoning="imports.create pulls from an external source server-side.",
    description="An admin starts an import that fetches from an external provider (SSRF sink #2).")


# ===========================================================================
# URLS  (SSRF #3)
# ===========================================================================
UR = "routes/api/urls/urls.ts"
_unfOut = know("Unfurl", ent("unfurl", "Unfurl", "response"))
action(
    "urls_unfurl", "Server-side URL preview (SSRF)", "Read", "urls_unfurl", "User",
    obj("entity", "unfurl", "Unfurl", "response", "", "Unfurl(fetch)", role="response"),
    requirements=[],  # auth optional
    gen=[eff(_unfOut, "io_reference", "Returns a link preview built from the fetched URL.")], kill=[],
    io_accounting=[io("input", "url / RemoteURL(fetch)", "object_attribute", [],
                      "URL the server fetches with workspace credentials (SSRF)."),
                   io("output", "unfurl / Unfurl(fetch)", "gen", [kf(_unfOut)])],
    bindings=_b("/api/urls.unfurl"),
    vis="black_box", vis_reason="Credentialed server-side fetch.", reachable=True,
    reach_conds=["auth OPTIONAL. The server GETs 'url' with workspace credentials -> SSRF + credentialed fetch."],
    evidence=[src(UR, "unfurl 'External resources are unfurled with workspace credentials'")],
    confidence=0.8, reasoning="urls.unfurl fetches arbitrary URLs server-side.",
    description="A (optionally anonymous) caller makes the server fetch a URL for a link preview (SSRF sink #3).",
    notes="SSRF.")
rd("urls_check_embed", "Check embed match", "/api/urls.checkEmbed", "Embed", "Embed(url)",
   reach=["Authenticated. Tests a URL against embed matchers."], evref=UR)


# ===========================================================================
# TEAMS + PROVIDERS + INTEGRATIONS
# ===========================================================================
TE = "routes/api/teams/teams.ts"
mu("team_update", "Update workspace settings", "Update", "/api/team.update", "Team", "TeamID(team)",
   subject="Admin", state_field="settings", perm="authorize(user,'update',team)",
   reach=["ADMIN. defaultUserRole/sharing/guestSignin/allowedDomains are the exposure toggles."], evref=TE)
mu("teams_create", "Create a workspace", "Create", "/api/teams.create", "Team", "TeamID(team)",
   mode="create", perm="installation canCreateTeam", reach=["Gated by installation config."], evref=TE)
mu("teams_delete", "Delete a workspace", "Delete", "/api/teams.delete", "Team", "TeamID(team)",
   subject="Admin", inref=("id", "TeamID", "Team"), mode="delete", perm="authorize(user,'delete',team)",
   reach=["ADMIN + emailed confirmation code (destructive)."], evref=TE)
mu("authproviders_update", "Toggle an SSO provider", "Update", "/api/authenticationProviders.update",
   "AuthProvider", "AuthProviderID(provider)", subject="Admin",
   inref=("id", "AuthProviderID", "AuthProvider"), state_field="isEnabled",
   perm="authorize(user,'update',team)",
   reach=["ADMIN. Disabling the only provider can lock the workspace out."],
   evref="routes/api/authenticationProviders/authenticationProviders.ts")
mu("integrations_create", "Create an integration/webhook", "Create", "/api/integrations.create",
   "Integration", "IntegrationID(integration)", subject="Admin", mode="create",
   perm="authorize(user,'createIntegration',team)",
   reach=["ADMIN. Outbound webhook URL = data-exfil / SSRF-ish sink."],
   evref="routes/api/integrations/integrations.ts")
mu("integrations_delete", "Delete an integration", "Delete", "/api/integrations.delete", "Integration",
   "IntegrationID(integration)", subject="Admin", inref=("id", "IntegrationID", "Integration"), mode="delete",
   perm="authorize(user,'delete',integration)", reach=["ADMIN."],
   evref="routes/api/integrations/integrations.ts")


# ===========================================================================
# REVISIONS / PINS / STARS / SUBS / NOTIF-PIXEL / TEMPLATES / ACCESS REQ
# ===========================================================================
RV = "routes/api/revisions/revisions.ts"
rd("revisions_list", "List revisions", "/api/revisions.list", "Revision", "RevisionID(revision)",
   inref=("documentId", "DocumentID", "Document"), perm="authorize(user,'read',document)",
   reach=["Read access to the document."], evref=RV)
rd("revisions_info", "Read a revision", "/api/revisions.info", "Revision", "RevisionID(revision)",
   inref=("id", "RevisionID", "Revision"), perm="authorize(user,'read',document)",
   reach=["Read access to the parent document."], evref=RV)
mu("pins_create", "Pin a document", "Create", "/api/pins.create", "Pin", "PinID(pin)",
   inref=("documentId", "DocumentID", "Document"), mode="create",
   perm="authorize(user,'update',collection) / team",
   reach=["Collection update (for collection pins) or team (home pins)."],
   evref="routes/api/pins/pins.ts")
mu("stars_create", "Star a document", "Create", "/api/stars.create", "Star", "StarID(star)",
   inref=("documentId", "DocumentID", "Document"), mode="create",
   reach=["Authenticated; personal."], evref="routes/api/stars/stars.ts")
mu("subscriptions_create", "Subscribe to updates", "Create", "/api/subscriptions.create", "Subscription",
   "SubscriptionID(subscription)", inref=("documentId", "DocumentID", "Document"), mode="create",
   perm="authorize(user,'read',target)", reach=["Read access to the target."],
   evref="routes/api/subscriptions/subscriptions.ts")
rd("notifications_pixel", "Email tracking pixel", "/api/notifications.pixel", "Pixel", "Pixel(token)",
   subject="Anonymous", auth="none", method="GET",
   reach=["PUBLIC image keyed by token; open-tracking + token-in-URL."],
   evref="routes/api/notifications/notifications.ts")
mu("templates_create", "Create a template", "Create", "/api/templates.create", "Template",
   "TemplateID(template)", mode="create", perm="createDocument/template permission",
   reach=["Template/create permission."], evref="routes/api/templates/templates.ts")
mu("access_requests_create", "Request access", "Create", "/api/accessRequests.create", "AccessRequest",
   "AccessRequestID(accessRequest)", inref=("documentId", "DocumentID", "Document"), mode="create",
   reach=["Authenticated member; notifies the resource managers."],
   evref="routes/api/accessRequests/accessRequests.ts")
