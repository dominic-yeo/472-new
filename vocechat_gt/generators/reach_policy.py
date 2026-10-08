"""Intended-configuration reachability policy.

The GT represents the application's full intended attack surface. A feature that is merely toggled off by
runtime config in THIS deployment is still reachable once an in-scope admin flips it (a stated precondition),
so such actions are black_box_reachable=true with the enabling step recorded as a positive precondition.
Category-2 actions additionally need an external provider/infrastructure that the benchmark cannot mint;
that dependency is kept as an explicit precondition rather than a false flag.
"""
API = "http://localhost:3009/api"

# (method, l1_key) -> positive preconditions replacing the "disabled -> 403/503" gate.
POLICY = {}
def _p(method, path, preconds):
    POLICY[(method, API + path)] = preconds

PK = ["Admin enables passkey via POST /api/admin/login/config (passkey=true)",
      "A WebAuthn authenticator is available (a virtual authenticator satisfies the black-box interface)"]
for pth in ["/token/passkey/register/start", "/token/passkey/register/finish",
            "/token/passkey/auth/start", "/token/passkey/auth/finish", "/token/passkey/list"]:
    _p("POST" if "list" not in pth else "GET", pth, PK)
_p("GET", "/token/passkey/list", PK)
_p("DELETE", "/token/passkey/{credential_id}", PK)

_p("POST", "/admin/system/create_admin",
   ["Server in its initial, un-initialized state (the documented reset/initial state): no user exists yet"])

IDP = ["Admin configures an OIDC/Google/GitHub provider via POST /api/admin/login/config",
       "EXTERNAL DEPENDENCY: a reachable external identity provider that issues the assertion/code"]
_p("POST", "/token/openid/authorize", IDP)
_p("POST", "/token/bind", ["Non-guest session",
   "Admin enables the provider (google/github/oidc/metamask) via POST /api/admin/login/config",
   "EXTERNAL DEPENDENCY for google/github/oidc: a reachable identity provider (metamask is self-signed client-side)"])

SMTP = ["Admin configures SMTP via POST /api/admin/smtp/config (enabled=true)",
        "EXTERNAL DEPENDENCY: a reachable SMTP server to deliver mail"]
_p("POST", "/user/send_login_magic_link", ["Admin enables magic_link via POST /api/admin/login/config"] + SMTP)
_p("POST", "/admin/system/send_mail", SMTP)
_p("POST", "/user/send_mail", SMTP)
_p("POST", "/bot/send_mail", SMTP)

AGORA_LOCAL = ["Admin configures Agora via POST /api/admin/agora/config (enabled=true); the RTC token is computed locally from the configured certificate"]
_p("GET", "/group/{gid}/agora_token", AGORA_LOCAL + ["Caller is a member of the group"])
_p("POST", "/admin/agora/token", AGORA_LOCAL)

AGORA_BACKEND = ["Admin configures Agora via POST /api/admin/agora/config (enabled=true)",
                 "EXTERNAL DEPENDENCY: a live Agora project/backend (these endpoints call Agora's REST API)"]
_p("GET", "/admin/agora/usages", AGORA_BACKEND)
_p("GET", "/admin/agora/channel/{page_no}/{page_size}", AGORA_BACKEND)
_p("GET", "/admin/agora/channel/user/{channel_name}/{hosts_only}", AGORA_BACKEND)
_p("GET", "/admin/agora/channel/user/property/{uid}/{channel_name}", AGORA_BACKEND)
_p("GET", "/voice/avo/events_ws", ["An active voice/Avo room exists",
   "EXTERNAL DEPENDENCY: Agora/voice backend configured for real calls"])

GATE_HINTS = ("disabled", "-> 403", "-> 503", "deployment", "SMTP configured", "Agora enabled",
              "Agora configured", "passkey: false", "oidc=[]", "initialized -> 403", "Voice/Avo room active")

def apply(op):
    """Mutate op in place: flip reach to True for gated actions and replace the gate with positive preconds."""
    k = (op["method"], op["key"])
    if k not in POLICY:
        return
    op["reach"] = True
    kept = [c for c in (op.get("conds") or []) if not any(h in c for h in GATE_HINTS)]
    op["conds"] = POLICY[k] + kept
    op["_intended_reach"] = True
