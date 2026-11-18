# -*- coding: utf-8 -*-
"""Shared helpers + semantic vocabulary for the Discourse Pengent Web GT.

Mirrors the mediacms_gt / anything-llm_gt generator contract so the emitted
YAML is template-conformant (pengent-web-gt-v1) and passes ../../validate_gt.py:
 - ORIGIN / key helpers (Discourse routes are top-level, no version mount)
 - SEM resource vocabulary (raw_field -> resource, value_kind, reference_capable)
 - L1 node / io_variant / request-field / response builders that DERIVE
   inputs/outputs/semantic_inputs/semantic_outputs
 - L2 typed-term + fact builders, and fact_key() -- byte-for-byte identical to
   validate_gt.py so io_accounting strings always match Req/Eff.

App: Discourse 2026.11.0 (Ruby on Rails + Ember). Auth model: session cookie
`_t` + CSRF token (browser), OR an api_key/api_username pair / user-scoped API
key (header). Authorization via Guardian + Admin/Staff route constraints
(AdminConstraint / StaffConstraint). Built module by module from the real
controllers under app/controllers/*.rb and config/routes.rb; request params from
`params.require/permit`, responses from `render json:` + app/serializers/*.rb.
Status tracked in ../environment.yaml web_gt:.
"""

ORIGIN = "http://localhost"


def key(path):
    """Normalized L1 key = origin + full normalized path (Discourse routes are top-level)."""
    return ORIGIN + path


# --------------------------------------------------------------------------
# SEM: raw_field -> (resource, value_kind, reference_capable, mergeable).
# reference_capable only ever True for identifier/locator (validator enforces).
# value_kind in VALUE_KINDS {identifier,locator,credential,content,state,
# attribute,collection,summary,opaque}. Grown per module; l1_data may also use
# dec() for explicit one-off rows.
# --------------------------------------------------------------------------
SEM = {
    # credentials / identity (module: session + auth)
    "login":         ("LoginName(identity)",     "identifier", True,  True),   # username OR email
    "username":      ("Username(identity)",      "identifier", True,  True),
    "email":         ("UserEmail(identity)",     "identifier", True,  True),
    "password":      ("Password(credential)",    "credential", False, True),
    "token":         ("AuthToken(credential)",   "credential", False, True),
    "second_factor_token": ("SecondFactorToken(credential)", "credential", False, True),
    "user_id":       ("UserId(identity)",        "identifier", True,  True),
    "csrf":          ("CsrfToken(credential)",   "credential", False, True),
}


def dec_for(raw_field, override_resource=None, reason=None):
    resource, vk, refcap, mergeable = SEM[raw_field]
    if override_resource:
        resource = override_resource
    return {"raw_field": raw_field, "resource": resource, "mergeable": mergeable,
            "value_kind": vk, "reference_capable": refcap,
            "reference_fields": [raw_field] if refcap else [],
            "reason": reason or f"{raw_field} denotes {resource}."}


def dec(raw_field, resource, value_kind, mergeable=True, reference_capable=False,
        reference_fields=None, reason=""):
    return {"raw_field": raw_field, "resource": resource, "mergeable": mergeable,
            "value_kind": value_kind, "reference_capable": reference_capable,
            "reference_fields": reference_fields or ([raw_field] if reference_capable else []),
            "reason": reason}


# --------------------------------------------------------------------------
# L1 request-field / response / io_variant builders
# --------------------------------------------------------------------------
def rf(name, location, typ="string", required=False, flow=True, description="", path=""):
    return {"name": name, "location": location, "path": path, "type": typ,
            "required": required, "flow": flow, "description": description}


def resp_json(fields):
    return {"format": "json", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False, "value_description": None,
            "fields": fields}


def resp_empty():
    return {"format": "empty", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False, "value_description": None,
            "fields": []}


def resp_scalar(value_name, value_type, value_description, value_flow=True):
    return {"format": "scalar", "scalar_type": value_type, "value_name": value_name,
            "value_type": value_type, "value_flow": value_flow,
            "value_description": value_description, "fields": []}


def resp_raw(value_description):
    return {"format": "raw", "scalar_type": None, "value_name": None,
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
    return {"method": method,
            "content_types": content_types or (["application/json"]),
            "inputs": inputs, "outputs": outputs, "input": {},
            "request": {"body_format": body_format, "body_example": body_example or {},
                        "fields": request_fields},
            "response": response, "reason": reason, "evidence": evidence}


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
    input_spec = {"format": "json" if body_json else ("plain" if (inputs and body_form) else ("plain" if inputs else "")),
                  "fields": inputs}
    semantic_inputs = _uniq([d["resource"] for d in sem_in_decisions if d["mergeable"]])
    semantic_outputs = _uniq([d["resource"] for d in sem_out_decisions if d["mergeable"]])
    return {
        "key": key_, "kind": kind, "methods": methods,
        "statuses": statuses or [],
        "content_types": content_types or (["application/json"] if kind == "api" else ["text/html"]),
        "params": params or [], "inputs": inputs, "outputs": outputs,
        "input_spec": input_spec, "io_variants": variants,
        "operation_semantic": operation_semantic,
        "semantic_inputs": semantic_inputs, "semantic_outputs": semantic_outputs,
        "semantic_input_decisions": sem_in_decisions,
        "semantic_output_decisions": sem_out_decisions,
        "samples": samples or [],
        "sources": sources or ["source"],
        "referrers": referrers or [],
        "resource_types": resource_types or (["fetch", "xhr"] if kind == "api" else ["document"]),
        "js_sources": js_sources or [],
        "identity_statuses": identity_statuses or {},
        "route_confirmed": route_confirmed,
        "runtime_api_prefixes": [ORIGIN] if kind == "api" else [],
        "gt": {"visibility": {"minimum": visibility, "reason": vis_reason},
               "black_box_reachable": reachable,
               "reachability_conditions": reach_conds or [],
               "evidence": evidence or [], "notes": notes},
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


# --------------------------------------------------------------------------
# Compact node/variant helpers shared by the per-module l1_*.py files, so each
# module stays terse. snode() wraps node(); V() wraps variant() with json/empty
# body inference; P1(name) builds a single path param.
# --------------------------------------------------------------------------
def V(method, fields=None, resp=None, reason="", src="", ex=None, cts=None):
    return variant(method, body_format="json" if fields else "none", body_example=ex or {},
                   request_fields=fields or [], response=resp if resp is not None else resp_empty(),
                   reason=reason, evidence=src, content_types=cts)


def P1(name, typ="integer", desc=None):
    return [{"name": name, "in": "path", "type": typ, "required": True, "flow": True,
             "description": desc or f"{name}."}]


def snode(path, methods, sem, idst, variants, vis_reason, src, notes=None,
          params=None, statuses=None, sin=None, sout=None, reach=None):
    return node(key(path), "api", methods, variants=variants, operation_semantic=sem,
                statuses=statuses or [200, 403, 404], identity_statuses=idst,
                params=params or [], sem_in_decisions=sin or [], sem_out_decisions=sout or [],
                route_confirmed=True, vis_reason=vis_reason, reach_conds=reach or [],
                evidence=[ev("source", src, sem)], notes=notes)


# Common Discourse identity-status maps (role -> status codes).
IDST_PUB = {"anonymous": [200, 403, 404], "user": [200]}
IDST_USER = {"anonymous": [403], "user": [200]}
IDST_STAFF = {"anonymous": [403], "user": [403], "staff": [200]}
IDST_ADMIN = {"anonymous": [403], "user": [403], "staff": [403], "admin": [200]}
