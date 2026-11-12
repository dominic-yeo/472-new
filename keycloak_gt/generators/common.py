# -*- coding: utf-8 -*-
"""Shared helpers + semantic vocabulary for the Keycloak Pengent Web GT.

Same generator design as the earlier targets (WriteFreely/Uptrace/Ghost/
Rocket.Chat/Directus/Outline):
 - ORIGIN / key helpers
 - L1 node / io_variant / request-field / response builders that fill every
   Pengent-required field and DERIVE inputs/outputs/semantic_inputs/outputs
 - L2 typed-term + fact builders, and fact_key() -- a byte-for-byte copy of the
   validator's canonical fact key so io_accounting always matches Req/Eff.

Keycloak routing is authored from the monorepo source in this repo
(keycloak/keycloak, services + rest modules; JAX-RS @Path resources):
 - Realm routing:  services/.../services/resources/RealmsResource.java  (@Path "/realms",
                   {realm}/protocol/{protocol}, /login-actions, /account, /broker,
                   /clients-registrations, /.well-known/{provider}, /authz, ...)
 - OIDC protocol:  services/.../protocol/oidc/OIDCLoginProtocolService.java + endpoints/*
                   (auth, token, userinfo, logout, certs, revoke, introspect, ext/*, ...)
 - Admin REST:     services/.../services/resources/admin/*  (@Path /admin/realms/{realm}/...
                   users, clients, roles, groups, identity-provider, authentication, components, ...)
 - Account REST:   services/.../services/resources/account/AccountRestService.java
 - Auth model:     clients authenticate to the token endpoint (secret | assertion | mTLS);
                   users via browser flows or the password grant; bearer access tokens (JWT)
                   carry roles/scopes/audience. Admin API authZ = realm-management client roles
                   (manage-users, view-clients, ...) or a master-realm admin.

Mount points differ per resource (/realms/... vs /admin/...), so L1 keys carry the
FULL path (API_PREFIX empty; each node authored with its prefix). {realm} is the
template segment; the probe uses realm 'master' + a test realm.
"""

ORIGIN = "http://localhost:8080"
API_PREFIX = ""   # full paths authored per node (/realms/..., /admin/..., /.well-known via realm)


def key(path):
    """Normalized L1 key = origin + full normalized path (already prefixed)."""
    return ORIGIN + path


# --------------------------------------------------------------------------
# SEM: optional raw_field -> (resource, value_kind, reference_capable, mergeable)
# Keycloak reuses opaque ids ('id') across resources, so most L1 decisions are
# authored explicitly with dec() to avoid cross-object merge errors.
# --------------------------------------------------------------------------
SEM = {
    "realm":         ("RealmName(realm)",       "identifier", True,  True),
    "client_id":     ("ClientID(client)",       "identifier", True,  True),
    "username":      ("Username(user)",         "identifier", True,  True),
    "password":      ("Password(user)",         "credential", False, True),
    "client_secret": ("ClientSecret(client)",   "credential", False, True),
    "code":          ("AuthCode(session)",      "credential", False, True),
    "token":         ("AccessToken(session)",   "credential", False, True),
    "access_token":  ("AccessToken(session)",   "credential", False, True),
    "refresh_token": ("RefreshToken(session)",  "credential", False, True),
    "redirect_uri":  ("RedirectURI(client)",    "locator",    True,  True),
}


def dec_for(raw_field, override_resource=None, reason=None):
    resource, vk, refcap, mergeable = SEM[raw_field]
    if override_resource:
        resource = override_resource
    return {
        "raw_field": raw_field, "resource": resource, "mergeable": mergeable,
        "value_kind": vk, "reference_capable": refcap,
        "reference_fields": [raw_field] if refcap else [],
        "reason": reason or f"{raw_field} denotes {resource}.",
    }


def dec(raw_field, resource, value_kind, mergeable=True, reference_capable=False,
        reference_fields=None, reason=""):
    return {
        "raw_field": raw_field, "resource": resource, "mergeable": mergeable,
        "value_kind": value_kind, "reference_capable": reference_capable,
        "reference_fields": reference_fields or ([raw_field] if reference_capable else []),
        "reason": reason,
    }


# --------------------------------------------------------------------------
# L1 request-field / response / io_variant builders
# --------------------------------------------------------------------------
def rf(name, location, typ="string", required=False, flow=True, description="", path=""):
    return {"name": name, "location": location, "path": path, "type": typ,
            "required": required, "flow": flow, "description": description}


def resp_json(fields, envelope="keycloak", error_path="error_description"):
    # OIDC/OAuth endpoints: success {access_token,...}; error {error, error_description}.
    # Admin REST: JSON representations or 204; error {error, errorMessage}.
    return {"format": "json", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False, "value_description": None,
            "envelope": envelope, "error_path": error_path, "fields": fields}


def resp_empty():
    return {"format": "empty", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False, "value_description": None,
            "fields": []}


def resp_scalar(value_name, value_type, value_description, value_flow=True):
    return {"format": "scalar", "scalar_type": value_type, "value_name": value_name,
            "value_type": value_type, "value_flow": value_flow,
            "value_description": value_description, "fields": []}


def resp_binary(value_name, value_description):
    return {"format": "binary", "scalar_type": "binary", "value_name": value_name,
            "value_type": "binary", "value_flow": True,
            "value_description": value_description, "fields": []}


def resp_html(value_description="an HTML login/consent/error page"):
    return {"format": "html", "scalar_type": "html", "value_name": "page",
            "value_type": "html", "value_flow": False,
            "value_description": value_description, "fields": []}


def resp_redirect(value_description="302 redirect (Location header)"):
    return {"format": "empty", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False,
            "value_description": value_description, "fields": []}


def of(name, typ="string", flow=True, description="", path=None):
    return {"name": name, "path": path if path is not None else name, "type": typ,
            "flow": flow, "description": description}


def variant(method, request_fields=None, response=None, body_format="none",
            body_example=None, reason="", evidence="", content_types=None):
    request_fields = request_fields or []
    response = response if response is not None else resp_empty()
    inputs = [f["name"] for f in request_fields if f.get("flow")]
    outputs = [f["name"] for f in (response.get("fields") or []) if f.get("flow")]
    if response.get("value_flow") and response.get("value_name"):
        outputs.append(response["value_name"])
    return {
        "method": method,
        "content_types": content_types or (["application/json"]),
        "inputs": inputs, "outputs": outputs, "input": {},
        "request": {"body_format": body_format, "body_example": body_example or {},
                    "fields": request_fields},
        "response": response, "reason": reason, "evidence": evidence,
    }


def _uniq(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def ev(type_, ref, supports):
    return {"type": type_, "ref": ref, "supports": supports}


def node(key_, kind, methods, variants=None, operation_semantic="",
         params=None, sem_in_decisions=None, sem_out_decisions=None,
         statuses=None, content_types=None, identity_statuses=None,
         sources=None, referrers=None, resource_types=None, js_sources=None,
         route_confirmed=False, visibility="black_box", vis_reason="",
         reachable=True, reach_conds=None, evidence=None, samples=None, notes=None):
    variants = variants or []
    sem_in_decisions = sem_in_decisions or []
    sem_out_decisions = sem_out_decisions or []
    inputs = _uniq([n for v in variants for n in v["inputs"]])
    outputs = _uniq([n for v in variants for n in v["outputs"]])
    body_json = any(v["request"]["body_format"] == "json" for v in variants)
    body_form = any(v["request"]["body_format"] == "form" for v in variants)
    input_spec = {"format": "json" if body_json else ("form" if body_form else ("plain" if inputs else "")),
                  "fields": inputs}
    semantic_inputs = _uniq([d["resource"] for d in sem_in_decisions if d["mergeable"]])
    semantic_outputs = _uniq([d["resource"] for d in sem_out_decisions if d["mergeable"]])
    return {
        "key": key_, "kind": kind, "methods": methods,
        "statuses": statuses or [], "params": params or [],
        "content_types": content_types or (["application/json"] if kind == "api" else ["text/html"]),
        "inputs": inputs, "outputs": outputs, "input_spec": input_spec,
        "io_variants": variants, "operation_semantic": operation_semantic,
        "semantic_inputs": semantic_inputs, "semantic_outputs": semantic_outputs,
        "semantic_input_decisions": sem_in_decisions,
        "semantic_output_decisions": sem_out_decisions,
        "samples": samples or [],
        "sources": sources or ["source"], "referrers": referrers or [],
        "resource_types": resource_types or (["fetch", "xhr"] if kind == "api" else ["document"]),
        "js_sources": js_sources or [],
        "identity_statuses": identity_statuses or {},
        "route_confirmed": route_confirmed,
        "runtime_api_prefixes": [ORIGIN] if kind == "api" else [],
        "gt": {
            "visibility": {"minimum": visibility, "reason": vis_reason},
            "black_box_reachable": reachable,
            "reachability_conditions": reach_conds or [],
            "evidence": evidence or [], "notes": notes,
        },
    }


# --------------------------------------------------------------------------
# L2 typed terms + facts
# --------------------------------------------------------------------------
def subj(id="actor", type="User", rel="SELF"):
    return {"kind": "subject", "id": id, "type": type, "relative_role": rel}


def principal(id, type, role, rel):
    return {"kind": "principal", "id": id, "type": type, "role": role, "relative_role": rel}


def entity(id, type, role="target"):
    return {"kind": "entity", "id": id, "type": type, "role": role}


def reference(ref_type, target_entity):
    return {"kind": "reference", "type": ref_type, "target": target_entity}


def f_auth(s=None, context="Session"):
    s = s or subj()
    args = [s]
    if context:
        args.append(context)
    return {"predicate": "Authenticated", "arguments": args}


def f_know(s, ref):
    return {"predicate": "Know", "arguments": [s, ref]}


def f_exists(ent):
    return {"predicate": "Exists", "arguments": [ent]}


def f_state(ent, field, value):
    return {"predicate": "State", "arguments": [ent, field, value]}


def f_relation(t1, t2, name):
    return {"predicate": "Relation", "arguments": [t1, t2, name]}


def f_can(s, crud, ent):
    return {"predicate": "Can", "arguments": [s, crud, ent]}


def req(rtype, fact, reason):
    return {"type": rtype, "fact": fact, "reason": reason}


def eff(fact, basis, reason):
    return {"fact": fact, "basis": basis, "reason": reason}


# fact_key: byte-for-byte identical to validate_gt.py so io_accounting matches.
def fact_key(f):
    def tk(x):
        if not isinstance(x, dict):
            return str(x)
        k = x.get("kind")
        if k == "reference":
            return f"{x.get('type')}({tk(x.get('target'))})"
        base = f"{x.get('id')}:{x.get('type')}"
        if k in {"subject", "principal"}:
            return f"{base}[{x.get('relative_role')}]"
        return f"{base}{{{x.get('role')}}}"
    return f"{f.get('predicate')}({','.join(tk(x) for x in (f.get('arguments') or []))})"


def io(direction, field, disposition, facts=None, ignored_reason=""):
    return {"direction": direction, "field": field, "disposition": disposition,
            "facts": facts or [], "ignored_reason": ignored_reason}
