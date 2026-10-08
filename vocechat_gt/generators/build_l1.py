"""Build L1 (InteractionGraph) for VoceChat from the source-derived op table + HAR verification."""
import json, re, base64, collections, copy
from urllib.parse import urlsplit, parse_qsl
from common import *
import ops_server, ops_frontend, ops_binary  # noqa: F401 (populate OPS)
import reach_policy
from ops_server import OPS, NONE
for _op in OPS:
    reach_policy.apply(_op)

SCRATCH = os.path.dirname(os.path.abspath(__file__)) + "/"
HAR_ENTRIES = json.load(open(SCRATCH + "har_entries.json", encoding="utf-8"))
MAIN_JS = BASE + "/static/js/main.2d25c1cb.js"
SRV_RS = "vocechat-server-rust-0.5.36/src/server.rs"

# ------------------------------------------------------------------ extra non-OpenAPI / static nodes
def X(path, kind, method="GET", sem="", value=None, ctypes=(), idst=None, src=None, vis_reason=None, notes=None, fe=(), trigger="other", origin="static"):
    OPS.append(dict(key=BASE + path, method=method, src=src, auth="none", sem=sem, req=[], req_format="none", resp=[],
                    resp_format="raw" if value else "empty", value=value, ctypes=list(ctypes), idst=idst or NONE((200,)),
                    fe=list(fe), body_example={}, sk={}, notes=notes, params=None, vis="black_box", vis_reason=vis_reason, reach=True,
                    conds=None, kind=kind, trigger=trigger, origin=origin, extra_evidence=[]))

X("/health", "api", sem="health_check", src=("server.rs", r'\.at\("/health"'), vis_reason="Conventional health-check path; returns empty 200.",
  notes="Liveness probe; no business IO (io_variants intentionally empty).")
X("/metrics", "api", sem="read_runtime_metrics", ctypes=("text/plain",), src=("server.rs", r'\.at\("/metrics"'),
  vis_reason="Conventional Prometheus path; unauthenticated tokio runtime metrics.", notes="Runtime metrics exporter; no business IO.")
X("/", "page", ctypes=("text/html",), src=("server.rs", r"StaticFilesEndpoint::new"), value=("html_page", "string", False, "SPA index.html"),
  notes="Single-page app (react-router HashRouter, vocechat-web/src/routes/index.tsx:58). All client routes live in the URL fragment and "
        "therefore normalise to this one node: #/login, #/register, #/register/set_name/:from?, #/email_login, #/send_magic_link/:email, "
        "#/guest_login, #/invite_private/:channel_id, #/invite_mobile/:magic_token, #/cb/:type/:payload, #/oauth/:token, #/onboarding, "
        "#/chat, #/chat/channel/:channel_id, #/chat/dm/:user_id, #/users, #/users/:user_id, #/favs, #/files, #/setting/:nav?, "
        "#/setting/channel/:cid/:nav?, #/setting/dm/:uid/:nav?, #/admin-bot-chat/:bot_uid/:kind/:target_id.")
X("/widget.html", "page", ctypes=("text/html",), src=None, notes="Embeddable chat widget page (vocechat-web/public/widget.html).",
  vis_reason="Shipped public asset; referenced by widget.js embed snippet.")
X("/widget_demo.html", "page", ctypes=("text/html",), notes="Widget demo page (public/widget_demo.html).")
X("/github/cb/webapp.html", "page", ctypes=("text/html",), notes="GitHub OAuth callback relay page (public/github/cb/webapp.html).")
X("/github/cb/widget.html", "page", ctypes=("text/html",), notes="GitHub OAuth callback relay for widget (public/github/cb/widget.html).")
X("/email.tpl.html", "static", ctypes=("text/html",), notes="E-mail template asset (public/email.tpl.html).")
for p, ct in [("/manifest.json", "application/json"), ("/site.webmanifest", "application/manifest+json"), ("/favicon.ico", "image/x-icon"),
              ("/favicon-16x16.png", "image/png"), ("/favicon-32x32.png", "image/png"), ("/android-chrome-192x192.png", "image/png"),
              ("/android-chrome-512x512.png", "image/png"), ("/apple-touch-icon.png", "image/png"), ("/robots.txt", "text/plain"),
              ("/service-worker.js", "text/javascript"), ("/firebase-messaging-sw.js", "text/javascript"), ("/widget.js", "text/javascript"),
              ("/splash/{device}_splash.png", "image/png"), ("/locales/{lang}/{namespace}.json", "application/json"),
              ("/static/js/{chunk}.js", "text/javascript"), ("/static/css/{chunk}.css", "text/css"), ("/static/media/{asset}", "application/octet-stream")]:
    X(p, "static", ctypes=(ct,), idst=NONE((200, 304), ()) if "{" not in p else NONE((200, 404), ()),
      notes=("Normalised: content-hashed build chunks / language files collapse to one node." if "{" in p else None))

NO_VARIANT = {API + "/spec", BASE + "/health", BASE + "/metrics"}
# ------------------------------------------------------------------ helpers
def tmpl_regex(key):
    pat = re.escape(key)
    pat = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", pat)
    return re.compile("^" + pat + "$")

def har_identity(e):
    tok = e["req_headers"].get("X-API-Key") or e["req_headers"].get("x-api-key")
    if not tok:
        q = dict(parse_qsl(urlsplit(e["url"]).query))
        tok = q.get("api-key")
    if not tok:
        return "anonymous"
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        d = json.loads(base64.urlsafe_b64decode(payload))["d"]
        return "admin" if d.get("is_admin") else ("guest" if d.get("is_guest") else "user")
    except Exception:
        return "bot"

JWT = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
def redact(s, limit=600):
    if s is None:
        return None
    s = JWT.sub("<redacted-jwt>", s)
    s = re.sub(r'("password"\s*:\s*")[^"]*(")', r"\1<redacted>\2", s)
    s = re.sub(r"(magic_token=)[0-9a-f]{20,}", r"\1<redacted>", s)
    s = re.sub(r"(api-key=)[^&]+", r"\1<redacted>", s)
    s = re.sub(r'("base58"\s*:\s*")[^"]{40,}(")', r"\1<license-blob>\2", s)
    return s if len(s) <= limit else s[:limit] + "...<truncated>"

def resolve_src(op):
    s = op["src"]
    if s is None:
        return None
    if s[0] == "server.rs":
        return src_line(SRV_RS, s[1])
    return srv_ref(*s)

def resolve_fe(f):
    fname, ep = f
    if ep is None:
        return src_line("vocechat-web/src/app/services/" + fname, r"token/renew")
    return web_ref(fname, ep)

AUTH_COND = {
    "none": [],
    "token": ["Valid access token in X-API-Key header (obtained from POST /api/token/login or /api/user/register)"],
    "user": ["Valid access token in X-API-Key header (obtained from POST /api/token/login or /api/user/register)"],
    "token_ng": ["Valid access token in X-API-Key header", "Non-guest account (guest_forbidden middleware, middleware.rs:6-23)"],
    "token_q": ["Valid access token passed as api-key query parameter", "Token's device has a device row (created at login)"],
    "admin": ["Valid access token of an administrator (is_admin=true)"],
    "bot": ["Bot API key in x-api-key header (admin creates it via POST /api/admin/user/bot-api-key/{uid})"],
    "secret": ["X-SECRET header equal to the server third_party_secret"],
    "unknown": [],
}

# ------------------------------------------------------------------ attach HAR evidence to ops
by_key = collections.OrderedDict()
for op in OPS:
    by_key.setdefault(op["key"], []).append(op)
regexes = [(tmpl_regex(k), k) for k in by_key]
# literal keys must win over templated ones
regexes.sort(key=lambda t: (t[1].count("{"), -len(t[1])))

har_hits = collections.defaultdict(list)
unmatched = []
for e in HAR_ENTRIES:
    u = urlsplit(e["url"])
    if u.netloc != "localhost:3009":
        continue
    plain = f"{u.scheme}://{u.netloc}{u.path}"
    for rx, k in regexes:
        if rx.match(plain):
            har_hits[(k, e["method"])].append(e)
            break
    else:
        unmatched.append((e["method"], plain))

# HEAD preflight on /resource/file comes from message.ts preCheckFileFromUrl
# ------------------------------------------------------------------ build nodes
def dec_for(name, sk, paths):
    key = sk.get(name, name)
    if key not in SEM:
        raise KeyError(f"no SEM for {name} (key {key})")
    d = decision(name, SEM[key], fields_paths=sorted(set(paths)))
    return d

def body_fmt(f):
    return {"json": "json", "raw": "raw", "form": "form", "none": "none"}[f]

nodes, edges = [], collections.OrderedDict()
op_index = {}
for key, ops in by_key.items():
    kind = ops[0]["kind"]
    methods, variants, all_status, ctypes, params = [], [], set(), [], []
    idst = collections.defaultdict(set)
    in_paths, out_paths = collections.defaultdict(list), collections.defaultdict(list)
    sk_all, samples, evid, notes, conds, rtypes, refs = {}, [], [], [], [], set(), set()
    vis_levels, reach_all, origins = [], [], set()
    for op in ops:
        m = op["method"]
        methods.append(m)
        op_index[(key, m)] = op
        sk_all.update(op["sk"])
        origins.add(op["origin"])
        hits = har_hits.get((key, m), [])
        # statuses
        if op["idst"]:
            for ident, sts in op["idst"].items():
                idst[ident].update(sts)
        for e in hits:
            idst[har_identity(e)].add(e["status"])
        for e in hits:
            rtypes.add(e["rtype"] or "fetch")
            r = e["req_headers"].get("Referer") or e["req_headers"].get("referer")
            if r:
                refs.add(r)
        # params
        for f in op["req"]:
            if f["location"] == "query" and f["name"] not in params:
                params.append(f["name"])
        for e in hits:
            for qn, _ in parse_qsl(urlsplit(e["url"]).query, keep_blank_values=True):
                if qn not in params:
                    params.append(qn)
        # io variant
        req_fields = []
        for f in op["req"]:
            g = {k: v for k, v in f.items() if not k.startswith("_")}
            req_fields.append(g)
            if f["flow"]:
                in_paths[f["name"]].append(f["path"] or f["name"])
        resp_fields = [dict(r) for r in op["resp"]]
        for r in op["resp"]:
            if r["flow"]:
                out_paths[r["name"]].append(r["path"] or r["name"])
        resp = {"format": op["resp_format"], "scalar_type": None, "value_name": None, "value_type": None,
                "value_flow": False, "value_description": None, "fields": resp_fields}
        if op["value"]:
            vn, vt, vf, vd = op["value"]
            resp.update(value_name=vn, value_type=vt, value_flow=vf, value_description=vd)
            if op["resp_format"] == "scalar":
                resp["scalar_type"] = vt
            if vf:
                out_paths[vn].append("$")
        ct_resp = sorted(set(op["ctypes"]) | {(e["resp_mime"] or "").split(";")[0] for e in hits if e["resp_mime"] and e["resp_mime"] != "x-unknown"})
        for c in ct_resp:
            if c not in ctypes:
                ctypes.append(c)
        v_inputs = [f["name"] for f in op["req"] if f["flow"]]
        v_outputs = [r["name"] for r in op["resp"] if r["flow"]] + ([op["value"][0]] if op["value"] and op["value"][2] else [])
        src_ref = resolve_src(op)
        fe_refs = [resolve_fe(f) for f in op["fe"]]
        ev_bits = []
        if src_ref:
            ev_bits.append(f"source {src_ref}")
        if fe_refs:
            ev_bits.append("frontend " + ", ".join(fe_refs))
        if hits:
            ev_bits.append("runtime " + ", ".join(f"{e['har']}#{e['idx']} ({har_identity(e)} -> {e['status']})" for e in hits[:4]))
        compact_input = {f["name"]: f["type"] for f in op["req"] if f["flow"] and f["location"] == "body"}
        if op["kind"] == "api" and op["sem"] and key not in NO_VARIANT:
            reason = {"server": "Request/response contract read from the poem-openapi handler signature and payload structs.",
                      "frontend": "Contract taken from the frontend RTK-Query service and TS types (server handler absent from source tree)"
                                  + ("; confirmed by captured traffic." if hits else "; not exercised in captures."),
                      "static": "Static route.",
                      "binary": "Contract taken from the deployed 0.5.36 binary's OpenAPI spec (GET /api/spec); the 0.3.3 source tree does not contain this handler."}[op["origin"]]
            if op["notes"]:
                reason += " " + op["notes"]
            variants.append({
                "method": m, "content_types": ct_resp, "inputs": v_inputs, "outputs": v_outputs, "input": compact_input,
                "request": {"body_format": body_fmt(op["req_format"]), "body_example": op["body_example"], "fields": req_fields},
                "response": resp, "reason": reason, "evidence": "; ".join(ev_bits) or "source",
            })
        # evidence rows
        if src_ref:
            evid.append({"type": "source", "ref": src_ref, "supports": f"{m} handler: route, parameters, auth checks and response type"})
        if op["origin"] == "binary":
            evid.append({"type": "documentation", "ref": "GET http://localhost:3009/api/spec (OpenAPI, server 0.5.36)", "supports": f"{m} route, parameters and request/response schema"})
        for r in fe_refs:
            evid.append({"type": "source", "ref": r, "supports": f"{m} called by deployed web client; request shape"})
        for e in hits[:3]:
            evid.append({"type": "runtime", "ref": f"vocechat_gt/{e['har']} entry #{e['idx']} ({e['started']})",
                         "supports": f"{m} {redact(e['url'], 160)} as {har_identity(e)} -> {e['status']}"})
        # samples
        seen = collections.Counter()
        for e in hits:
            ident = har_identity(e)
            if seen[ident] >= 1:
                continue
            seen[ident] += 1
            samples.append({"identity": ident, "method": m, "status": e["status"], "url": redact(e["url"], 300),
                            "request_body": redact(e["req_body"], 400), "response_body_sample": redact(e["resp_body"], 500) if e["resp_body"] else None,
                            "source": f"har:{e['har']}#{e['idx']}"})
        if op["notes"]:
            notes.append(f"[{m}] {op['notes']}")
        if op["conds"]:
            conds += [c for c in op["conds"] if c not in conds]
        for c in AUTH_COND[op["auth"]]:
            if c not in conds:
                conds.append(c)
        if op["auth"] == "unknown" and any(f["name"] == "X-API-Key" for f in op["req"]):
            c = "Authenticated session (client sends X-API-Key; server-side authorisation not visible in source)"
            if c not in conds:
                conds.append(c)
        vis_levels.append((op["vis"], op["vis_reason"]))
        reach_all.append(op["reach"])
        # edges
        if op["fe"] and op["kind"] != "page" or (op["fe"] and op["trigger"] == "link"):
            ek = (BASE + "/", key)
            ed = edges.setdefault(ek, {"src": BASE + "/", "dst": key, "methods": [], "triggers": [], "gt": {"evidence": []}})
            if m not in ed["methods"]:
                ed["methods"].append(m)
            trig = op["trigger"]
            if trig not in ed["triggers"]:
                ed["triggers"].append(trig)
            for r in fe_refs[:1]:
                ed["gt"]["evidence"].append({"type": "source", "ref": r, "supports": f"SPA issues {m} {key}"})
            for e in hits[:1]:
                ed["gt"]["evidence"].append({"type": "runtime", "ref": f"vocechat_gt/{e['har']} entry #{e['idx']}",
                                             "supports": f"Referer http://localhost:3009/ -> {m} {key}"})
        elif hits and op["kind"] in ("static", "page") and key != BASE + "/":
            ek = (BASE + "/", key)
            ed = edges.setdefault(ek, {"src": BASE + "/", "dst": key, "methods": [m], "triggers": [], "gt": {"evidence": []}})
            for e in hits:
                t = {"script": "script", "stylesheet": "other", "fetch": "fetch", "image": "other", "media": "other",
                     "manifest": "other", "other": "other", "document": "other"}.get(e["rtype"], "other")
                if t not in ed["triggers"]:
                    ed["triggers"].append(t)
            ed["gt"]["evidence"].append({"type": "runtime", "ref": f"vocechat_gt/{hits[0]['har']} entry #{hits[0]['idx']}",
                                         "supports": f"Loaded by SPA (Referer http://localhost:3009/, resourceType {hits[0]['rtype']})"})
        for e in hits:
            all_status.add(e["status"])
    for ident, sts in idst.items():
        all_status |= sts
    # semantic decisions
    in_dec = [dec_for(n, sk_all, p) for n, p in in_paths.items()]
    out_dec = [dec_for(n, sk_all, p) for n, p in out_paths.items()]
    vmin = "black_box"
    vreason = None
    order = {"black_box": 0, "grey_box": 1, "white_box": 2}
    for v, r in vis_levels:
        if order[v] < order[vmin] or vreason is None:
            pass
    # node visibility = least restrictive among its methods (node identity is visible if any method is)
    vmin = min((v for v, _ in vis_levels), key=lambda v: order[v])
    vreason = next((r for v, r in vis_levels if v == vmin and r), None)
    if vmin == "white_box":
        vmin = "black_box"
        vreason = ("Endpoint existence and request/response contract are discoverable black-box via the "
                   "deployment's unauthenticated OpenAPI spec at GET /api/spec (api_docs_provided=true in the "
                   "black-box profile); source is the evidence the annotator used, not the minimum access to identify it.")
    if vreason is None:
        if any(o["fe"] for o in ops):
            vreason = "Called by the shipped web client; visible in JS bundle and network traffic."
        else:
            vreason = "Registered route reachable by direct request."
    any_hits = any(har_hits.get((key, o["method"])) for o in ops)
    flow_in = list(in_paths.keys())
    flow_out = list(out_paths.keys())
    fmt = ""
    for o in ops:
        if o["req_format"] == "json":
            fmt = "json"; break
        if o["req_format"] in ("raw", "form") and not fmt:
            fmt = "plain"
    sems = {o["method"]: o["sem"] for o in ops if o["sem"]}
    opsem = sems.get("GET") or next(iter(sems.values()), "")
    if len(sems) > 1:
        notes.insert(0, "Per-method semantics: " + ", ".join(f"{k}={v}" for k, v in sems.items()))
    origin_note = {"server": None,
                   "frontend": "Route absent from the server source tree (Cargo 0.3.3) but called by vocechat-web 0.9.122 and served by the deployed 0.5.36 binary"
                               + (" (confirmed in HAR)." if any_hits else " (not exercised in the captures; existence inferred from the shipped frontend)."),
                   "static": None,
                   "binary": "Operation present only in the deployed 0.5.36 binary's OpenAPI spec (GET /api/spec); absent from the 0.3.3 source tree and from vocechat-web 0.9.122. Contract taken from the live spec."}
    for o in origins:
        if origin_note.get(o):
            notes.append(origin_note[o])
    node = {
        "key": key, "kind": kind, "methods": methods, "statuses": sorted(all_status), "content_types": ctypes, "params": params,
        "inputs": flow_in, "outputs": flow_out, "input_spec": {"format": fmt, "fields": flow_in},
        "io_variants": variants, "operation_semantic": opsem,
        "semantic_inputs": sorted({d["resource"] for d in in_dec if d["mergeable"]}),
        "semantic_outputs": sorted({d["resource"] for d in out_dec if d["mergeable"]}),
        "semantic_input_decisions": in_dec, "semantic_output_decisions": out_dec,
        "samples": samples,
        "sources": (["runtime"] if any_hits else []) + (["source"] if any(o["src"] or o["fe"] or o["origin"] == "static" for o in ops) else []) + (["documentation"] if any(o["origin"] == "binary" for o in ops) else []),
        "referrers": sorted(refs) or ([BASE + "/"] if any(o["fe"] for o in ops) else []),
        "resource_types": sorted(rtypes) or sorted({{"fetch": "fetch", "other": "other", "link": "document", "script": "script"}[o["trigger"]] for o in ops if o["fe"]}),
        "js_sources": [MAIN_JS] if any(o["fe"] for o in ops) and kind == "api" else [],
        "identity_statuses": {k: sorted(v) for k, v in idst.items()},
        "route_confirmed": bool(any_hits),
        "runtime_api_prefixes": [API] if key.startswith(API) else [],
        "gt": {
            "visibility": {"minimum": vmin, "reason": vreason},
            "black_box_reachable": all(reach_all),
            "reachability_conditions": conds,
            "evidence": evid or [{"type": "source", "ref": "vocechat-web/public/", "supports": "Shipped static asset"}],
            "notes": " ".join(notes) or None,
        },
    }
    if any(not r for r in reach_all) and not all(not r for r in reach_all):
        node["gt"]["black_box_reachable"] = True
        node["gt"]["notes"] = (node["gt"]["notes"] or "") + " Some methods are feature-gated (see L2 reachability)."
    nodes.append(node)

l1 = {"schema_version": "pengent-web-gt-v1", "environment_id": "vocechat-0.5.36-local", "nodes": nodes,
      "edges": [dict(e) for e in edges.values()], "excluded_items": []}
json.dump({"l1": l1, "op_index": {f"{k}|{m}": v for (k, m), v in op_index.items()},
           "unmatched": unmatched}, open(SCRATCH + "l1_build.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("nodes", len(nodes), "api", sum(n["kind"] == "api" for n in nodes), "candidates", sum(n["kind"] == "api" and bool(n["io_variants"]) for n in nodes),
      "edges", len(edges), "ops", len(OPS))
print("unmatched HAR:", collections.Counter(unmatched).most_common())
