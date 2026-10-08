"""Per-operation L2 semantic cores for VoceChat.

Each SPEC entry is keyed by "<l1_key>|<METHOD>" (optionally "|<selector_value>") and carries only the
semantics that cannot be inferred mechanically: the business Object, extra participants/constraints, the
requirement facts beyond the automatic authentication fact, the generated/killed effect facts, and the
disposition of each flow IO field. The engine in build_l2.py fills everything else (subject, bindings,
l1_bindings, gt visibility/reachability/evidence) from the op table and the L1 node.

Helpers below return (requirements, effects_gen, effects_kill, io_input_map, io_output_map).
"""
from l2lib import *

API = "http://localhost:3009/api"
BASE = "http://localhost:3009"

SPEC = {}       # key -> list of action cores (list => selector-split actions)

def A(key, method, *, akey, name, business, crud, obj, desc=None, subject=None,
      participants=None, constraints=None, req_facts=None, gen=None, kill=None,
      io_in=None, io_out=None, selector=None, conf=0.9, reasoning=None, extra_bindings=None,
      reach_conds=None, reach=None):
    SPEC.setdefault(f"{key}|{method}", []).append(dict(
        akey=akey, name=name, business=business, crud=crud, obj=obj, desc=desc, subject=subject,
        participants=participants or [], constraints=constraints or [], req_facts=req_facts or [],
        gen=gen or [], kill=kill or [], io_in=io_in or {}, io_out=io_out or {}, selector=selector,
        conf=conf, reasoning=reasoning, extra_bindings=extra_bindings or [],
        reach_conds=reach_conds, reach=reach))

# ---- object constructors ----------------------------------------------------
def OBJ(kind, id, type, name, entity, role="target", source="request", field="", resource="",
        attribute="", state_field=""):
    return dict(kind=kind, id=id, type=type, name=name, entity=entity, role=role,
                attribute=attribute, state_field=state_field,
                binding=dict(source=source, field=field, resource=resource),
                participants=[], constraints=[])

# convenience object makers
def O_session(role="created", source="response"):
    return OBJ("entity", "session", "Session", "User session", "Session", role, source, "token", "AccessToken(session)")
def O_user_self():
    return OBJ("entity", "actor_user", "User", "Own user account", "User", "target", "subject", "", "UserID(user)")
def O_user_target(source="request", field="uid"):
    return OBJ("entity", "user", "User", "User account", "User", "target", source, field, "UserID(user)")
def O_group(field="gid", source="request", role="target"):
    return OBJ("entity", "group", "Group", "Group (channel)", "Group", role, source, field, "GroupID(group)")
def O_message(field="mid", source="request", role="target"):
    return OBJ("entity", "message", "Message", "Chat message", "Message", role, source, field, "MessageID(message)")

# principals
def P_recipient_user():
    return PRIN("recipient", "User", "recipient", "PEER")

# =============================================================================
#  TOKEN / SESSION
# =============================================================================
U = SUBJ()  # actor:User[SELF]
def authed(ctx="Session", reason="Endpoint requires a valid authenticated session."):
    return req("authentication", FACT("Authenticated", U, ctx), reason)

# login (password) — the credential discriminator splits this endpoint
LOGIN_TYPES = {
    "password": ("login_password", "Log in with e-mail and password", ["email", "password"]),
    "magiclink": ("login_magic_link", "Log in / auto-register with a magic-link token", ["magic_token", "extra_name"]),
    "google": ("login_google", "Log in with a Google ID token", ["id_token", "magic_token"]),
    "github": ("login_github", "Log in with a GitHub OAuth code", ["code", "magic_token"]),
    "oidc": ("login_oidc", "Log in with an OpenID-Connect code", ["code", "state", "magic_token"]),
    "metamask": ("login_metamask", "Log in with a MetaMask wallet signature", ["public_address", "nonce", "signature", "magic_token"]),
    "thirdparty": ("login_third_party", "Log in with a third-party HMAC key", ["key"]),
}
# reachability + a knowledge requirement per credential type (addresses empty Req/reachability for oauth/oidc)
LOGIN_REACH = {
    "password": (["LoginConfig.password=true (enabled by default in the deployment)"], None, None),
    "magiclink": (["LoginConfig.magic_link=true"], "MagicToken", "magic_token"),
    "google": (["Admin enables google via POST /api/admin/login/config",
                "EXTERNAL DEPENDENCY: a valid Google ID token from Google"], "ExternalIdToken", "id_token"),
    "github": (["Admin enables github via POST /api/admin/login/config",
                "EXTERNAL DEPENDENCY: a valid GitHub OAuth code from GitHub"], "OAuthCode", "code"),
    "oidc": (["Admin configures an OIDC issuer via POST /api/admin/login/config",
              "A pending OIDC flow started via POST /api/token/openid/authorize",
              "EXTERNAL DEPENDENCY: a reachable OIDC provider that returns the code"], "OAuthCode", "code"),
    "metamask": (["Admin enables metamask via POST /api/admin/login/config",
                  "A nonce obtained from GET /api/token/metamask/nonce, signed by the caller's own wallet"], "WalletSignature", "signature"),
    "thirdparty": (["LoginConfig.third_party=true",
                    "A key minted via POST /api/token/create_third_party_key (needs the server third_party_secret)"], "ThirdPartyLoginKey", "key"),
}
for t, (ak, nm, flds) in LOGIN_TYPES.items():
    rconds, credref, credfield = LOGIN_REACH[t]
    reqs = []
    io_in = {"device": "attr", "device_token": "attr"}
    if credref:
        reqs.append(req("knowledge", FACT("Know", U, REF(credref, ENT("session", "Session", "created"))),
                        f"The caller must possess a valid {credref} to authenticate via {t}."))
        io_in[credfield] = "req_know_credtok"
        io_in["__cred__"] = [f for f in flds if f != credfield]
    else:
        io_in["__cred__"] = flds
    A(API + "/token/login", "POST", selector=("credential.type", [t]),
      akey="anonymous_" + ak + "_session", name=nm, business="login", crud="Create",
      obj=O_session(), conf=0.85 if t != "password" else 0.95, req_facts=reqs, reach_conds=rconds,
      gen=[eff(FACT("Exists", ENT("session", "Session", "created")), "action_semantics", "A new access/refresh token pair (session) is created on success."),
           eff(FACT("Authenticated", U, "Session"), "auth_transition", "The caller becomes authenticated for the issued session."),
           eff(FACT("Know", U, REF("AccessToken", ENT("session", "Session", "created"))), "io_reference", "Response returns the access token."),
           eff(FACT("Know", U, REF("RefreshToken", ENT("session", "Session", "created"))), "io_reference", "Response returns the refresh token (consumed by POST /api/token/renew).")],
      io_in=io_in,
      io_out={"token": "know", "refresh_token": "know", "server_id": "observed", "uid": "observed",
              "email": "observed", "name": "observed", "is_admin": "observed"},
      reasoning="login.rs multiplexes the credential union on credential.type; this action is the %s branch." % t)

A(API + "/token/login_guest", "GET", akey="anonymous_login_guest_session",
  name="Log in as an anonymous guest", business="login_guest", crud="Create", obj=O_session(), conf=0.9,
  gen=[eff(FACT("Exists", ENT("session", "Session", "created")), "action_semantics", "A guest user and session are created."),
       eff(FACT("Authenticated", U, "Session"), "auth_transition", "Caller becomes an authenticated guest."),
       eff(FACT("Know", U, REF("AccessToken", ENT("session", "Session", "created"))), "io_reference", "Access token returned in the body."),
       eff(FACT("Know", U, REF("RefreshToken", ENT("session", "Session", "created"))), "io_reference", "Refresh token returned (consumed by /api/token/renew).")],
  io_out={"token": "know", "refresh_token": "know", "server_id": "observed", "uid": "observed",
          "email": "observed", "name": "observed", "is_admin": "observed"})

A(API + "/token/renew", "POST", akey="anonymous_renew_session", name="Renew a session token pair",
  business="renew_session_token", crud="Update",
  obj=OBJ("entity", "session", "Session", "User session", "Session", "target", "request", "refresh_token", "RefreshToken(session)",
          state_field="token"),
  req_facts=[req("knowledge", FACT("Know", U, REF("RefreshToken", ENT("session", "Session", "target"))),
                 "The caller must present the current refresh token (and matching access token) for the session.")],
  kill=[eff(FACT("State", ENT("session", "Session", "target"), "refresh_token", "previous"), "state_transition", "The stored refresh token is rotated.")],
  gen=[eff(FACT("State", ENT("session", "Session", "target"), "refresh_token", "rotated"), "state_transition", "A new refresh token replaces the old one."),
       eff(FACT("Know", U, REF("AccessToken", ENT("session", "Session", "target"))), "io_reference", "A fresh access token is returned."),
       eff(FACT("Know", U, REF("RefreshToken", ENT("session", "Session", "target"))), "io_reference", "A rotated refresh token is returned (re-usable by a subsequent renew).")],
  io_in={"refresh_token": "req_know_refresh", "token": "attr"},
  io_out={"token": "know", "refresh_token": "know"},
  reasoning="Session token rotation; no session header, proven by the token pair (token.rs:1211).")

A(API + "/token/logout", "GET", akey="user_logout_session", name="Log out the current device session",
  business="logout", crud="Delete",
  obj=OBJ("entity", "session", "Session", "Current device session", "Session", "target", "subject", "", "AccessToken(session)"),
  req_facts=[authed()],
  kill=[eff(FACT("Exists", ENT("session", "Session", "target")), "action_semantics", "Refresh-token and device rows for (uid,device) are deleted and the SSE stream is kicked.")],
  reasoning="logout deletes the refresh token + device row; the stateless access JWT stays valid until expiry (token.rs:1281-1322).")

A(API + "/token/device_token", "PUT", akey="user_update_device_push_token", name="Update the FCM push token of the current device",
  business="update_device_push_token", crud="Update",
  obj=OBJ("entity", "device", "Device", "Current device", "Device", "target", "subject", "", "DeviceID(device)", state_field="device_token"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("device", "Device", "target"), "device_token", "previous"), "state_transition", "Previous push token cleared.")],
  gen=[eff(FACT("State", ENT("device", "Device", "target"), "device_token", "updated"), "state_transition", "New FCM token stored for the device.")],
  io_in={"device_token": "attr_state"})

A(API + "/token/credentials", "GET", akey="user_read_own_credentials", name="Read linked login credentials",
  business="read_own_credentials", crud="Read", obj=O_user_self(), req_facts=[authed()],
  gen=[], io_out={"password": "observed", "google": "observed", "metamask": "observed", "oidc": "observed"})

A(API + "/token/bind", "POST", akey="user_bind_external_credential", name="Bind an external login credential",
  business="bind_external_credential", crud="Create",
  obj=OBJ("entity", "credential", "AccountCredential", "External login credential", "AccountCredential", "created", "request", "", "LinkedCredential(account_credential)"),
  req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("credential", "AccountCredential", "created")), "action_semantics", "A new credential row (google/github/oidc/metamask) is linked to the account."),
       eff(FACT("Relation", U, ENT("credential", "AccountCredential", "created"), "OwnsCredential"), "relation_transition", "The credential is associated with the caller's account.")],
  io_in={"id_token": "attr", "code": "attr", "state": "attr", "public_address": "attr", "nonce": "attr", "signature": "attr"},
  conf=0.7)

A(API + "/token/openid/authorize", "POST", akey="anonymous_start_oidc_authorization", name="Start an OIDC authorization flow",
  business="start_oidc_authorization", crud="Create",
  obj=OBJ("entity", "oidc_flow", "OIDCFlow", "Pending OIDC authorization", "OIDCFlow", "created", "response", "state", "OAuthState(external_account)"),
  gen=[eff(FACT("Exists", ENT("oidc_flow", "OIDCFlow", "created")), "action_semantics", "A pending OIDC state (PKCE challenge) is created server-side."),
       eff(FACT("Know", U, REF("ExternalURL", ENT("oidc_flow", "OIDCFlow", "created"))), "io_reference", "Provider authorization URL returned.")],
  io_in={"issuer": "attr", "redirect_uri": "attr"}, io_out={"auth_url": "observed"}, conf=0.7)

A(API + "/token/metamask/nonce", "GET", akey="anonymous_create_metamask_nonce", name="Create a MetaMask login nonce",
  business="create_metamask_nonce", crud="Create",
  obj=OBJ("entity", "wallet_nonce", "WalletNonce", "MetaMask login nonce", "WalletNonce", "created", "request", "public_address", "WalletAddress(external_account)"),
  gen=[eff(FACT("Exists", ENT("wallet_nonce", "WalletNonce", "created")), "action_semantics", "A nonce row is upserted for the supplied wallet address."),
       eff(FACT("Know", U, REF("WalletNonce", ENT("wallet_nonce", "WalletNonce", "created"))), "io_reference", "Nonce returned to the caller.")],
  io_in={"public_address": "attr"}, io_out={"nonce": "know"}, conf=0.8)

A(API + "/token/create_third_party_key", "POST", akey="secret_create_third_party_login_key", name="Mint a third-party login key",
  business="create_third_party_login_key", crud="Create", subject="secret",
  obj=OBJ("entity", "tp_key", "ThirdPartyLoginKey", "Third-party login key", "ThirdPartyLoginKey", "created", "response", "", "ThirdPartyLoginKey(session)"),
  req_facts=[req("knowledge", FACT("Know", U, REF("ThirdPartySecret", ENT("server", "Server", "target"))),
                 "Caller must present the server third_party_secret in X-SECRET.")],
  gen=[eff(FACT("Exists", ENT("tp_key", "ThirdPartyLoginKey", "created")), "action_semantics", "A signed, 120s-valid login key is produced."),
       eff(FACT("Know", U, REF("ThirdPartyLoginKey", ENT("tp_key", "ThirdPartyLoginKey", "created"))), "io_reference", "Key returned in the body.")],
  io_in={"X-SECRET": "req_know_secret", "userid": "attr", "username": "attr"}, io_out={"third_party_key": "know"}, conf=0.75,
  extra_bindings=[])

# =============================================================================
#  USER (self-service)
# =============================================================================
A(API + "/user/register", "POST", akey="anonymous_register_user_account", name="Register a new user account",
  business="register_user_account", crud="Create",
  obj=OBJ("entity", "user", "User", "New user account", "User", "created", "response", "uid", "UserID(user)"),
  gen=[eff(FACT("Exists", ENT("user", "User", "created")), "action_semantics", "A new user row is created (who_can_sign_up=EveryOne in deployment)."),
       eff(FACT("Authenticated", U, "Session"), "auth_transition", "Successful register auto-logs-in and returns a session."),
       eff(FACT("Know", U, REF("AccessToken", ENT("session", "Session", "created"))), "io_reference", "Access token returned."),
       eff(FACT("Know", U, REF("RefreshToken", ENT("session", "Session", "created"))), "io_reference", "Refresh token returned (consumed by /api/token/renew).")],
  participants=[ENT("session", "Session", "created")],
  io_in={"email": "attr", "password": "attr", "name": "attr", "magic_token": "attr_cred", "device": "attr", "device_token": "attr"},
  io_out={"token": "know", "refresh_token": "know", "uid": "observed", "email": "observed", "name": "observed", "is_admin": "observed", "server_id": "observed"},
  reasoning="A magic_token embedding a gid also joins the new user to that private group (user.rs:430-459).")

A(API + "/user/check_magic_token", "POST", akey="anonymous_validate_magic_token", name="Validate a magic token",
  business="validate_magic_token", crud="Read",
  obj=OBJ("entity", "magic", "MagicLink", "Magic-link token", "MagicLink", "target", "request", "magic_token", "MagicToken(magic_link)"),
  req_facts=[req("knowledge", FACT("Know", U, REF("MagicToken", ENT("magic", "MagicLink", "target"))), "Caller supplies the token to validate.")],
  io_in={"magic_token": "req_know"}, io_out={})

A(API + "/user/check_email", "GET", akey="anonymous_check_email_available", name="Check whether an e-mail is registered",
  business="check_email_available", crud="Read",
  obj=OBJ("entity", "user", "User", "User account keyed by e-mail", "User", "target", "request", "email", "UserEmail(user)"),
  io_in={"email": "attr"}, io_out={},
  reasoning="Unauthenticated enumeration oracle; e-mail is an attribute probe, not a stable object id (user.rs:464).")

A(API + "/user/send_reg_magic_link", "POST", akey="anonymous_send_registration_magic_link", name="Issue a registration magic link",
  business="send_registration_magic_link", crud="Create",
  obj=OBJ("entity", "magic", "MagicLink", "Registration magic token", "MagicLink", "created", "response", "new_magic_token", "MagicToken(magic_link)"),
  gen=[eff(FACT("Exists", ENT("magic", "MagicLink", "created")), "action_semantics", "A signed registration token is produced (SMTP off: returned directly)."),
       eff(FACT("Know", U, REF("MagicToken", ENT("magic", "MagicLink", "created"))), "io_reference", "Token returned in the body when SMTP disabled.")],
  io_in={"email": "attr", "password": "attr", "magic_token": "attr_cred"}, io_out={"new_magic_token": "know"}, conf=0.8)

A(API + "/user/send_login_magic_link", "POST", akey="anonymous_send_login_magic_link", name="E-mail a login magic link",
  business="send_login_magic_link", crud="Create",
  obj=OBJ("entity", "magic", "MagicLink", "Login magic token", "MagicLink", "created", "request", "email", "UserEmail(user)"),
  gen=[eff(FACT("Exists", ENT("magic", "MagicLink", "created")), "action_semantics", "A single-use login token is generated and mailed.")],
  io_in={"email": "attr"}, conf=0.7)

A(API + "/user/me", "GET", akey="user_read_own_profile", name="Read own profile", business="read_own_profile", crud="Read",
  obj=O_user_self(), req_facts=[authed()],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("actor_user", "User", "target"))), "io_reference", "Returns the caller's own uid.")],
  io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"})

A(API + "/user/{uid}", "GET", akey="anonymous_read_user_profile", name="Read a user profile by id",
  business="read_user_profile", crud="Read", obj=O_user_target(),
  req_facts=[req("knowledge", FACT("Know", U, REF("UserID", ENT("user", "User", "target"))), "Caller must know the target uid."),
             req("existence", FACT("Exists", ENT("user", "User", "target")), "Unknown uid returns 404.")],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Returns the uid.")],
  io_in={"uid": "req_know"}, io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"},
  reasoning="No Token extractor: anonymous profile+e-mail disclosure by uid (user.rs:656-664).")

A(API + "/user/change_password", "POST", akey="user_change_own_password", name="Change own password",
  business="change_own_password", crud="Update",
  obj=OBJ("entity", "actor_user", "User", "Own account password", "User", "target", "subject", "", "UserID(user)", state_field="password"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("actor_user", "User", "target"), "password", "previous"), "state_transition", "Old password invalidated.")],
  gen=[eff(FACT("State", ENT("actor_user", "User", "target"), "password", "updated"), "state_transition", "New password stored.")],
  io_in={"old_password": "attr_cred", "new_password": "attr_state"})

A(API + "/user", "PUT", akey="user_update_own_profile", name="Update own profile", business="update_own_profile", crud="Update",
  obj=OBJ("entity", "actor_user", "User", "Own user profile", "User", "target", "subject", "", "UserID(user)", state_field="name"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("actor_user", "User", "target"), "name", "previous"), "state_transition", "Previous profile value replaced.")],
  gen=[eff(FACT("State", ENT("actor_user", "User", "target"), "name", "updated"), "state_transition", "Profile name/gender/language updated.")],
  io_in={"name": "attr_state"}, io_out={"uid": "observed", "email": "observed", "name": "observed", "is_admin": "observed"})

A(API + "/user/avatar", "POST", akey="user_upload_own_avatar", name="Upload own avatar", business="upload_own_avatar", crud="Update",
  obj=OBJ("entity", "actor_user", "User", "Own avatar", "User", "target", "subject", "", "UserID(user)", state_field="avatar"),
  req_facts=[authed()],
  gen=[eff(FACT("State", ENT("actor_user", "User", "target"), "avatar", "updated"), "state_transition", "Avatar image replaced.")],
  io_in={"avatar": "attr_state"})

A(API + "/user", "GET", akey="anonymous_list_users", name="List all users", business="list_users", crud="Read",
  obj=OBJ("collection", "user_list", "User", "User directory", "User", "target", "response", "uid", "UserID(user)"),
  gen=[eff(FACT("Know", U, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Each element exposes a uid.")],
  io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"},
  reasoning="Source handler has no Token: anonymous directory incl. e-mails (user.rs:891-904).")

A(API + "/user/{uid}/send", "POST", akey="user_send_direct_message_message", name="Send a direct message to a user",
  business="send_direct_message", crud="Create",
  obj=OBJ("entity", "message", "Message", "Direct message", "Message", "created", "response", "", "MessageID(message)"),
  participants=[P_recipient_user()],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", PRIN("recipient", "User", "recipient", "PEER"))), "Caller must know the recipient uid."),
             req("existence", FACT("Exists", ENT("recipient_account", "User", "target")), "Unknown recipient uid returns 404.")],
  gen=[eff(FACT("Exists", ENT("message", "Message", "created")), "action_semantics", "A new DM is stored and broadcast."),
       eff(FACT("Know", U, REF("MessageID", ENT("message", "Message", "created"))), "io_reference", "New mid returned.")],
  io_in={"uid": "req_know_recipient", "content": "attr"}, io_out={"mid": "know"},
  extra_bindings=[("recipient_account", "User", "target")])

A(API + "/user/{uid}/history", "GET", akey="user_read_direct_message_history", name="Read DM history with a user",
  business="read_direct_message_history", crud="Read",
  obj=OBJ("collection", "message_list", "Message", "DM history", "Message", "target", "response", "mid", "MessageID(message)"),
  participants=[P_recipient_user()],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", PRIN("recipient", "User", "recipient", "PEER"))), "Caller supplies the peer uid.")],
  gen=[eff(FACT("Know", U, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "History rows expose message ids.")],
  io_in={"uid": "req_know_recipient", "before": "attr_cursor"},
  io_out={"mid": "know", "from_uid": "observed", "target_uid": "observed", "target_gid": "observed", "content": "observed", "ref_mid": "observed"})

A(API + "/user/events", "GET", akey="user_subscribe_user_events", name="Subscribe to the realtime event stream",
  business="subscribe_user_events", crud="Read",
  obj=OBJ("entity", "event_stream", "EventStream", "Server-sent event stream", "EventStream", "target", "subject", "", "AccessToken(session)"),
  req_facts=[authed("Session", "Token passed as api-key query param."),
             req("state", FACT("State", ENT("device", "Device", "target"), "subscribed", "active"), "The token's device must have a device row (else 403).")],
  participants=[ENT("other_user", "User", "target"), ENT("group", "Group", "target"), ENT("message", "Message", "target")],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("other_user", "User", "target"))), "io_reference", "users_snapshot/users_state expose every non-guest user's uid."),
       eff(FACT("Know", U, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "related_groups/joined_group expose group ids."),
       eff(FACT("Know", U, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "chat events expose message ids.")],
  io_in={"api-key": "attr_cred", "after_mid": "attr_cursor", "users_version": "attr_cursor"},
  io_out={"events_uid": "know", "events_gid": "know", "events_mid": "know", "events_email": "observed", "events": "observed"},
  reasoning="Read-only subscription; the stream leaks reference-capable uid/gid/mid (modelled as Know gens) plus other users' e-mails (observed_only).")

A(API + "/user/devices", "GET", akey="user_list_own_devices", name="List own devices", business="list_own_devices", crud="Read",
  obj=OBJ("collection", "device_list", "Device", "Own devices", "Device", "target", "response", "device", "DeviceID(device)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", U, REF("DeviceID", ENT("device", "Device", "target"))), "io_reference", "Device ids returned.")],
  io_out={"device": "know"})

A(API + "/user/devices/{device}", "DELETE", akey="user_delete_own_device", name="Sign out a device",
  business="delete_own_device", crud="Delete",
  obj=OBJ("entity", "device", "Device", "A device of the caller", "Device", "target", "request", "device", "DeviceID(device)"),
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("DeviceID", ENT("device", "Device", "target"))), "Caller names the device id."),
             req("existence", FACT("Exists", ENT("device", "Device", "target")), "Unknown device returns 401.")],
  kill=[eff(FACT("Exists", ENT("device", "Device", "target")), "action_semantics", "Device row deleted and its stream kicked.")],
  io_in={"device": "req_know"})

def settings_obj(field):
    return OBJ("state", "conv_setting", "ConversationSetting", "Conversation setting", "ConversationSetting", "target",
               "subject", "", "SystemSetting(server)", attribute=field, state_field=field)

A(API + "/user/mute", "POST", akey="user_update_mute_settings", name="Update mute settings",
  business="update_mute_settings", crud="Update", obj=settings_obj("mute"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "mute", "previous"), "state_transition", "Old mute set replaced.")],
  gen=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "mute", "updated"), "state_transition", "Mute list for users/groups updated.")],
  io_in={"add_users_uid": "attr_ref_user", "add_groups_gid": "attr_ref_group", "remove_users": "attr_ref_user",
         "remove_groups": "attr_ref_group", "add_users_expired_in": "attr_state", "add_groups_expired_in": "attr_state"})

A(API + "/user/burn-after-reading", "POST", akey="user_update_burn_after_reading", name="Update burn-after-reading",
  business="update_burn_after_reading", crud="Update", obj=settings_obj("burn_after_reading"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "burn_after_reading", "previous"), "state_transition", "Old expiry replaced.")],
  gen=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "burn_after_reading", "updated"), "state_transition", "Expiry per peer/group updated.")],
  io_in={"users_uid": "attr_ref_user", "groups_gid": "attr_ref_group", "users_expires_in": "attr_state", "groups_expires_in": "attr_state"})

A(API + "/user/read-index", "POST", akey="user_update_read_index", name="Advance read markers",
  business="update_read_index", crud="Update", obj=settings_obj("read_index"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "read_index", "previous"), "state_transition", "Old read marker replaced.")],
  gen=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "read_index", "updated"), "state_transition", "Read marker advanced.")],
  io_in={"users_uid": "attr_ref_user", "groups_gid": "attr_ref_group", "users_mid": "attr_ref_msg", "groups_mid": "attr_ref_msg"})

A(API + "/user/delete", "DELETE", akey="user_delete_own_account", name="Delete own account",
  business="delete_own_account", crud="Delete",
  obj=OBJ("entity", "actor_user", "User", "Own account", "User", "target", "subject", "", "UserID(user)"),
  req_facts=[authed()],
  kill=[eff(FACT("Exists", ENT("actor_user", "User", "target")), "action_semantics", "The caller's user row is deleted.")])

A(API + "/user/update_fcm_token", "PUT", akey="user_register_device_fcm_token", name="Register a device FCM token",
  business="register_device_fcm_token", crud="Update",
  obj=OBJ("entity", "device", "Device", "A device of the caller", "Device", "target", "request", "device", "DeviceID(device)", state_field="device_token"),
  req_facts=[authed()],
  gen=[eff(FACT("State", ENT("device", "Device", "target"), "device_token", "updated"), "state_transition", "Upserts a device row with the FCM token.")],
  io_in={"device": "attr_state", "fcm_token": "attr_state"})

# ---- contacts / search / pin (frontend) -------------------------------------
def O_contact(role="target"):
    return OBJ("relation", "contact", "ContactRelation", "Contact relation", "ContactRelation", role, "request", "target_uid", "UserID(user)")

A(API + "/user/contacts", "GET", akey="user_list_contacts", name="List contacts", business="list_contacts", crud="Read",
  obj=OBJ("collection", "contact_list", "User", "Contacts", "User", "target", "response", "target_uid", "UserID(user)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Contact uids returned.")],
  io_out={"target_uid": "know", "contact_status": "observed", "email": "observed", "name": "observed"})

A(API + "/user/search", "POST", akey="user_search_user", name="Search for a user", business="search_user", crud="Read",
  obj=O_user_target("response", "uid"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Matched uid returned.")],
  io_in={"keyword": "attr"}, io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"})

A(API + "/user/pin_chat", "POST", akey="user_pin_chat", name="Pin a conversation", business="pin_chat", crud="Update",
  obj=settings_obj("pinned_chats"), req_facts=[authed()],
  gen=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "pinned_chats", "updated"), "state_transition", "Conversation pinned.")],
  io_in={"target_uid": "attr_ref_user", "target_gid": "attr_ref_group"})
A(API + "/user/unpin_chat", "POST", akey="user_unpin_chat", name="Unpin a conversation", business="unpin_chat", crud="Update",
  obj=settings_obj("pinned_chats"), req_facts=[authed()],
  kill=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "pinned_chats", "previous"), "state_transition", "Conversation unpinned.")],
  io_in={"target_uid": "attr_ref_user", "target_gid": "attr_ref_group"})

A(API + "/user/contact_remark", "PUT", akey="user_update_contact_remark", name="Set a contact remark",
  business="update_contact_remark", crud="Update", obj=O_contact(),
  participants=[ENT("contact_user", "User", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", ENT("contact_user", "User", "target"))), "Caller names the contact's user id (a UserID, learned from the directory/contacts).")],
  gen=[eff(FACT("State", ENT("contact", "ContactRelation", "target"), "remark", "updated"), "state_transition", "Private remark stored.")],
  io_in={"contact_uid": "req_know_contactp", "remark": "attr_state"}, conf=0.75)

CONTACT_ACTIONS = {
    "add": ("add_contact", "Add a contact", "Added", "gen"),
    "remove": ("remove_contact", "Remove a contact", "Added", "kill"),
    "block": ("block_contact", "Block a user", "Blocked", "gen"),
    "unblock": ("unblock_contact", "Unblock a user", "Blocked", "kill"),
}
for act, (ak, nm, rel, mode) in CONTACT_ACTIONS.items():
    g = [eff(FACT("Relation", U, ENT("contact_user", "User", "target"), rel), "relation_transition", f"{nm} relation created.")] if mode == "gen" else []
    k = [eff(FACT("Relation", U, ENT("contact_user", "User", "target"), rel), "relation_transition", f"{nm} relation removed.")] if mode == "kill" else []
    A(API + "/user/update_contact_status", "POST", selector=("action", [act]),
      akey="user_" + ak, name=nm, business="update_contact_status", crud="Update" if mode == "gen" else "Update",
      obj=OBJ("relation", "contact_rel", "ContactRelation", "Contact relation", "ContactRelation", "target", "request", "target_uid", "UserID(user)"),
      participants=[PRIN("contact_user", "User", "contact", "PEER")],
      req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", PRIN("contact_user", "User", "contact", "PEER"))), "Caller names the target uid.")],
      gen=g, kill=k, io_in={"target_uid": "req_know_contactp", "contact_action": "attr"}, conf=0.75,
      reasoning=f"update_contact_status action={act} branch.")

A(API + "/user/join_private", "POST", akey="user_join_private_group_by_invite", name="Join a private group via invite",
  business="join_private_group_by_invite", crud="Create",
  obj=OBJ("relation", "membership", "GroupMembership", "Group membership", "GroupMembership", "created", "request", "magic_token", "MagicToken(magic_link)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("MagicToken", ENT("invite", "MagicLink", "target"))), "Caller presents a valid invite token.")],
  gen=[eff(FACT("Relation", U, ENT("group", "Group", "target"), "Member"), "relation_transition", "Caller becomes a member of the invited group.")],
  io_in={"magic_token": "req_know_invite"},
  io_out={"gid": "observed", "owner": "observed", "group_name": "observed", "description": "observed", "members": "observed",
          "is_public": "observed", "pinned_mid": "observed", "pinned_content": "observed"},
  conf=0.75, extra_bindings=[("invite", "MagicLink", "target")])
