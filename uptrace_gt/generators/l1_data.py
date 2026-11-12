# -*- coding: utf-8 -*-
"""Uptrace (OSS) L1 attack surface as data.

Authoritative sources: pkg/bunapp/router.go (base groups /internal/v1, /api/v1),
pkg/{org,tracing,metrics}/*_handler.go register* funcs (routes + middleware),
pkg/org/auth.go (auth model). ORIGIN = http://localhost:14318 (config listen.http).

Auth model:
  - /internal/v1/*  : m.User (JWT 'token' cookie OR 'Authorization: Bearer <token>')
                      project routes add m.UserAndProject (project_id must exist;
                      OSS is single-tenant -> no per-user project ACL).
  - /api/v1/tracing : m.UserAndProject (same user auth) -- PUBLIC path, USER gate.
  - /api/v1/{vector,prometheus,cloudwatch} + /v1/{traces,logs,metrics} : ProjectDSN
                      (uptrace-dsn header / Bearer / ?dsn=), NOT user auth.

API_NODES with non-empty io_variants are the L2 coverage candidates. Near-duplicate
analytical read variants and binary ingestion mirrors are enumerated without
io_variants (surface-complete, L2-deferred). Statuses/identity_statuses are left for
runtime confirmation (see ../annotation_issues.yaml).
"""
import common as c
from common import key as K, rf, of, variant, resp_json, resp_empty, dec

SRC = "uptrace/pkg"


def ev_src(ref, supports):
    return c.ev("source", ref, supports)


API_NODES = []
_API_SPECS = {}   # path-key -> accumulated spec (bunrouter dispatches one path by method)
_API_ORDER = []


def _dedup(decs):
    out, seen = [], set()
    for d in decs:
        sig = (d["raw_field"], d["resource"])
        if sig not in seen:
            seen.add(sig)
            out.append(d)
    return out


def api(key, methods, variants, op, sin=None, sout=None, params=None,
        vis="black_box", vis_reason="", reach=None, evref="", notes=None):
    k = K(key)
    if k not in _API_SPECS:
        _API_ORDER.append(k)
        _API_SPECS[k] = {"methods": [], "variants": [], "sin": [], "sout": [],
                         "op": op, "vis_reason": vis_reason, "reach": [], "ev": [], "notes": []}
    s = _API_SPECS[k]
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


def api0(key, methods, op, reach=None, evref="", notes=None):
    """Enumerated API node WITHOUT io_variants (surface-complete, L2-deferred)."""
    api(key, methods, [], op, reach=reach, evref=evref, notes=notes)


def _finalize_api():
    for k in _API_ORDER:
        s = _API_SPECS[k]
        API_NODES.append(c.node(
            k, "api", s["methods"], variants=s["variants"], operation_semantic=s["op"],
            sem_in_decisions=_dedup(s["sin"]), sem_out_decisions=_dedup(s["sout"]),
            visibility="black_box", vis_reason=s["vis_reason"], reachable=True,
            reach_conds=s["reach"],
            evidence=[ev_src(e, "route + middleware") for e in dict.fromkeys(s["ev"])],
            notes="; ".join(dict.fromkeys(s["notes"])) or None))


# project_id path param shared by most routes
PID = rf("project_id", "path", required=True, description="project id (must exist)")


def pid_dec():
    return dec("project_id", "ProjectID(project)", "identifier", reference_capable=True,
               reason="Target project; middleware loads it by id.")


# ===========================================================================
# AUTH (public login/logout; current requires user)
# ===========================================================================
api("/internal/v1/users/login", ["POST"],
    [variant("POST",
             [rf("email", "body", required=True, description="user email"),
              rf("password", "body", required=True, description="user password")],
             resp_empty(), body_format="json",
             reason="Login verifies bcrypt password and sets the JWT 'token' cookie",
             evidence="org/user_handler.go:Login")],
    "login_user",
    sin=[dec("email", "UserEmail(user)", "identifier", reference_capable=True,
             reason="Login identifier."),
         dec("password", "Password(user)", "credential", reason="Account password.")],
    sout=[dec("token", "AuthToken(session)", "credential",
              reason="JWT session token set as the 'token' cookie.")],
    vis_reason="Public login endpoint.", reach=["User exists in config/db."],
    evref="org/user_handler.go:Login",
    notes="Token travels in a Set-Cookie (name 'token'), not the JSON body.")

api("/internal/v1/users/logout", ["POST"],
    [variant("POST", [], resp_empty(),
             reason="Clears the 'token' cookie", evidence="org/user_handler.go:Logout")],
    "logout_user",
    vis_reason="Public logout.", reach=["Open."], evref="org/user_handler.go:Logout")

api("/internal/v1/users/current", ["GET"],
    [variant("GET", [], resp_json([of("user", description="current user"),
                                   of("projects", description="projects visible to the user")]),
             reason="Returns the authenticated user and all projects",
             evidence="org/user_handler.go:Current")],
    "read_current_user",
    sout=[dec("user", "UserEmail(user)", "identifier", reference_capable=True,
              reason="The caller's own user record."),
          dec("projects", "ProjectID(project)", "identifier", reference_capable=True,
              mergeable=False, reason="All projects (OSS single-tenant lists every project).")],
    vis_reason="Authenticated self + project list.", reach=["Authenticated (cookie/bearer)."],
    evref="org/user_handler.go:registerUserHandler")


# ===========================================================================
# ORG (project, usage) -- m.User
# ===========================================================================
api("/internal/v1/projects/:project_id", ["GET"],
    [variant("GET", [PID], resp_json([of("project"), of("dsn", description="project DSN (ingest credential)")]),
             reason="Returns the project and its DSN",
             evidence="org/project_handler.go:Show")],
    "read_project",
    sin=[pid_dec()],
    sout=[dec("dsn", "ProjectDSN(project)", "credential",
              reason="Ingest DSN embedding the project token -- credential disclosure surface.")],
    vis_reason="Project detail incl. DSN.",
    reach=["Authenticated; project_id exists (no per-user ACL in OSS)."],
    evref="org/project_handler.go:Show",
    notes="DSN embeds the project token; any logged-in user can read ANY project's DSN (no ACL).")

api("/internal/v1/data-usage", ["GET"],
    [variant("GET", [], resp_json([of("spans", flow=False), of("bytes", flow=False),
                                   of("timeseries", flow=False)]),
             reason="Returns span/byte/timeseries usage for the last month",
             evidence="org/usage_handler.go:Show")],
    "read_data_usage",
    vis_reason="Account usage stats.", reach=["Authenticated."],
    evref="org/usage_handler.go:Show")


# ===========================================================================
# TRACING (reads) -- m.User / m.UserAndProject
# ===========================================================================
_span_q = [rf("query", "query", description="TQL query"),
           rf("time_gte", "query", description="start time"),
           rf("time_lt", "query", description="end time"),
           rf("system", "query", description="span system filter")]

api("/internal/v1/traces/search", ["GET"],
    [variant("GET", [rf("trace_id", "query", required=True, description="trace id to locate")],
             resp_json([of("trace_id"), of("project_id"), of("span_id")]),
             reason="Resolves a trace id to its project/span (cross-project lookup under m.User only)",
             evidence="tracing/trace_handler.go:FindTrace")],
    "search_trace",
    sin=[dec("trace_id", "TraceID(trace)", "identifier", reference_capable=True,
             reason="Trace id being located.")],
    sout=[dec("project_id", "ProjectID(project)", "identifier", reference_capable=True,
              reason="Project owning the trace."),
          dec("span_id", "SpanID(span)", "identifier", reference_capable=True, mergeable=False,
              reason="Root span id.")],
    vis_reason="Trace lookup by id (m.User only, no project gate).",
    reach=["Authenticated. NOTE: not project-scoped -> any user resolves any trace id."],
    evref="tracing/trace_handler.go:registerTraceHandler",
    notes="Gated by m.User only (NOT UserAndProject): a cross-project trace-id oracle.")

api("/internal/v1/tracing/:project_id/systems", ["GET"],
    [variant("GET", [PID] + _span_q, resp_json([of("systems", description="span systems")]),
             reason="Lists span systems for the project", evidence="tracing/system_handler.go:ListSystems")],
    "list_span_systems", sin=[pid_dec()],
    sout=[dec("systems", "SpanSystem(project)", "identifier", reference_capable=True,
              reason="Distinct span systems.")],
    vis_reason="Span systems.", reach=["Authenticated; project exists."],
    evref="tracing/system_handler.go:ListSystems")

api("/internal/v1/tracing/:project_id/spans", ["GET"],
    [variant("GET", [PID] + _span_q, resp_json([of("spans"), of("hasMore", flow=False)]),
             reason="Lists spans matching the filter", evidence="tracing/span_handler.go:ListSpans")],
    "list_spans", sin=[pid_dec()],
    sout=[dec("spans", "SpanID(span)", "identifier", reference_capable=True,
              reason="Span ids in the result page.")],
    vis_reason="Span list.", reach=["Authenticated; project exists."],
    evref="tracing/span_handler.go:ListSpans")

api("/internal/v1/tracing/:project_id/groups", ["GET"],
    [variant("GET", [PID] + _span_q, resp_json([of("groups")]),
             reason="Lists span groups", evidence="tracing/span_handler.go:ListGroups")],
    "list_span_groups", sin=[pid_dec()],
    sout=[dec("groups", "GroupID(group)", "identifier", reference_capable=True,
              reason="Span group ids.")],
    vis_reason="Span groups.", reach=["Authenticated; project exists."],
    evref="tracing/span_handler.go:ListGroups")

api("/internal/v1/tracing/:project_id/groups/:group_id", ["GET"],
    [variant("GET", [PID, rf("group_id", "path", required=True, description="group id")],
             resp_json([of("stats")]),
             reason="Group summary", evidence="tracing/group_handler.go:ShowSummary")],
    "read_span_group",
    sin=[pid_dec(), dec("group_id", "GroupID(group)", "identifier", reference_capable=True,
                        reason="Group being summarized.")],
    vis_reason="Group summary.", reach=["Authenticated; project exists."],
    evref="tracing/group_handler.go:ShowSummary")

api("/internal/v1/tracing/:project_id/traces/:trace_id", ["GET"],
    [variant("GET", [PID, rf("trace_id", "path", required=True, description="trace id")],
             resp_json([of("spans"), of("root")]),
             reason="Shows a full trace", evidence="tracing/trace_handler.go:ShowTrace")],
    "read_trace",
    sin=[pid_dec(), dec("trace_id", "TraceID(trace)", "identifier", reference_capable=True,
                        reason="Trace being shown.")],
    sout=[dec("spans", "SpanID(span)", "identifier", reference_capable=True,
              reason="Spans of the trace.")],
    vis_reason="Trace detail.", reach=["Authenticated; project exists."],
    evref="tracing/trace_handler.go:ShowTrace")

api("/internal/v1/tracing/:project_id/attributes", ["GET"],
    [variant("GET", [PID] + _span_q, resp_json([of("keys", description="attribute keys")]),
             reason="Lists span attribute keys", evidence="tracing/attr_handler.go:AttrKeys")],
    "list_span_attr_keys", sin=[pid_dec()],
    sout=[dec("keys", "AttrKey(attr)", "identifier", reference_capable=True,
              reason="Span attribute keys.")],
    vis_reason="Attribute keys.", reach=["Authenticated; project exists."],
    evref="tracing/attr_handler.go:AttrKeys")

# deferred tracing read variants (surface-complete, L2-deferred)
api0("/internal/v1/tracing/:project_id/attributes/:attr", ["GET"], "list_span_attr_values",
     reach=["Authenticated; project exists."], evref="tracing/attr_handler.go:AttrValues")
api0("/internal/v1/tracing/:project_id/percentiles", ["GET"], "span_percentiles",
     evref="tracing/span_handler.go:Percentiles")
api0("/internal/v1/tracing/:project_id/group-stats", ["GET"], "span_group_stats",
     evref="tracing/span_handler.go:GroupStats")
api0("/internal/v1/tracing/:project_id/timeseries", ["GET"], "span_timeseries",
     evref="tracing/span_handler.go:Timeseries")
api0("/internal/v1/tracing/:project_id/traces/:trace_id/:span_id", ["GET"], "read_span",
     evref="tracing/trace_handler.go:ShowSpan")


# ===========================================================================
# METRICS (reads) -- m.UserAndProject
# ===========================================================================
api("/internal/v1/metrics/:project_id", ["GET"],
    [variant("GET", [PID, rf("query", "query", description="metric name filter")],
             resp_json([of("metrics")]),
             reason="Lists metrics", evidence="metrics/metric_handler.go:List")],
    "list_metrics", sin=[pid_dec()],
    sout=[dec("metrics", "MetricName(metric)", "identifier", reference_capable=True,
              reason="Metric names.")],
    vis_reason="Metric list.", reach=["Authenticated; project exists."],
    evref="metrics/metric_handler.go:List")

api("/internal/v1/metrics/:project_id/table", ["GET"],
    [variant("GET", [PID, rf("query", "query", required=True, description="MQL query")],
             resp_json([of("items")]),
             reason="Runs a metrics table query", evidence="metrics/query_handler.go:Table")],
    "query_metrics_table", sin=[pid_dec()],
    vis_reason="Metrics table query.", reach=["Authenticated; project exists."],
    evref="metrics/query_handler.go:Table")

api("/internal/v1/metrics/:project_id/attributes", ["GET"],
    [variant("GET", [PID] + [rf("metric", "query", description="metric filter")],
             resp_json([of("keys")]),
             reason="Lists metric attribute keys", evidence="metrics/attr_handler.go:AttrKeys")],
    "list_metric_attr_keys", sin=[pid_dec()],
    sout=[dec("keys", "AttrKey(attr)", "identifier", reference_capable=True,
              reason="Metric attribute keys.")],
    vis_reason="Metric attribute keys.", reach=["Authenticated; project exists."],
    evref="metrics/attr_handler.go:AttrKeys")

# deferred metrics read variants
api0("/internal/v1/metrics/:project_id/describe", ["GET"], "describe_metrics",
     evref="metrics/metric_handler.go:Describe")
api0("/internal/v1/metrics/:project_id/stats", ["GET"], "metrics_stats",
     evref="metrics/metric_handler.go:Stats")
api0("/internal/v1/metrics/:project_id/attributes/:attr", ["GET"], "list_metric_attr_values",
     evref="metrics/attr_handler.go:AttrValues")
api0("/internal/v1/metrics/:project_id/timeseries", ["GET"], "query_metrics_timeseries",
     evref="metrics/query_handler.go:Timeseries")
api0("/internal/v1/metrics/:project_id/gauge", ["GET"], "query_metrics_gauge",
     evref="metrics/query_handler.go:Gauge")
api0("/internal/v1/metrics/:project_id/heatmap", ["GET"], "query_metrics_heatmap",
     evref="metrics/query_handler.go:Heatmap")


# ===========================================================================
# DASHBOARDS (CRUD) -- m.UserAndProject (+ m.Dashboard for :dash_id)
# ===========================================================================
DASH = "/internal/v1/metrics/:project_id/dashboards"
DID = rf("dash_id", "path", required=True, description="dashboard id (must belong to project)")


def did_dec():
    return dec("dash_id", "DashID(dashboard)", "identifier", reference_capable=True,
               reason="Target dashboard; m.Dashboard checks it belongs to the project.")


api(DASH, ["POST"],
    [variant("POST", [PID, rf("name", "body", required=True, description="dashboard name")],
             resp_json([of("dashboard")]), body_format="json",
             reason="Creates a dashboard", evidence="metrics/dash_handler.go:Create")],
    "create_dashboard", sin=[pid_dec(),
        dec("name", "DashName(dashboard)", "attribute", mergeable=False, reason="New dashboard name.")],
    sout=[dec("dashboard", "DashID(dashboard)", "identifier", reference_capable=True,
              reason="Created dashboard id.")],
    vis_reason="Dashboard create.", reach=["Authenticated; project exists."],
    evref="metrics/dash_handler.go:Create")

api(DASH, ["GET"],
    [variant("GET", [PID], resp_json([of("dashboards")]),
             reason="Lists dashboards", evidence="metrics/dash_handler.go:List")],
    "list_dashboards", sin=[pid_dec()],
    sout=[dec("dashboards", "DashID(dashboard)", "identifier", reference_capable=True,
              reason="Dashboard ids in the project.")],
    vis_reason="Dashboard list.", reach=["Authenticated; project exists."],
    evref="metrics/dash_handler.go:List")

api(DASH + "/yaml", ["POST"],
    [variant("POST", [PID, rf("yaml", "body", required=True, description="dashboard YAML")],
             resp_json([of("dashboard")]), body_format="plain",
             reason="Creates a dashboard from YAML", evidence="metrics/dash_handler.go:CreateFromYAML")],
    "create_dashboard_yaml", sin=[pid_dec()],
    sout=[dec("dashboard", "DashID(dashboard)", "identifier", reference_capable=True,
              reason="Created dashboard id.")],
    vis_reason="Dashboard create from YAML (template injection surface).",
    reach=["Authenticated; project exists."], evref="metrics/dash_handler.go:CreateFromYAML")

api(DASH + "/:dash_id", ["GET"],
    [variant("GET", [PID, DID], resp_json([of("dashboard"), of("grid")]),
             reason="Shows a dashboard", evidence="metrics/dash_handler.go:Show")],
    "read_dashboard", sin=[pid_dec(), did_dec()],
    vis_reason="Dashboard detail.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/dash_handler.go:Show")

api(DASH + "/:dash_id", ["POST"],
    [variant("POST", [PID, DID], resp_json([of("dashboard")]),
             reason="Clones a dashboard", evidence="metrics/dash_handler.go:Clone")],
    "clone_dashboard", sin=[pid_dec(), did_dec()],
    sout=[dec("dashboard", "DashID(dashboard)", "identifier", reference_capable=True,
              mergeable=False, reason="Cloned dashboard id.")],
    vis_reason="Dashboard clone.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/dash_handler.go:Clone")

api(DASH + "/:dash_id", ["PUT"],
    [variant("PUT", [PID, DID, rf("name", "body", description="new name")],
             resp_json([of("dashboard")]), body_format="json",
             reason="Updates a dashboard", evidence="metrics/dash_handler.go:Update")],
    "update_dashboard", sin=[pid_dec(), did_dec(),
        dec("name", "DashName(dashboard)", "attribute", mergeable=False, reason="Updated name.")],
    vis_reason="Dashboard update.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/dash_handler.go:Update")

api(DASH + "/:dash_id", ["DELETE"],
    [variant("DELETE", [PID, DID], resp_empty(),
             reason="Deletes a dashboard", evidence="metrics/dash_handler.go:Delete")],
    "delete_dashboard", sin=[pid_dec(), did_dec()],
    vis_reason="Dashboard delete.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/dash_handler.go:Delete")

api(DASH + "/:dash_id/pinned", ["PUT"],
    [variant("PUT", [PID, DID], resp_empty(),
             reason="Pins a dashboard", evidence="metrics/dash_handler.go:Pin")],
    "pin_dashboard", sin=[pid_dec(), did_dec()],
    vis_reason="Dashboard pin.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/dash_handler.go:Pin")

# deferred dashboard write variants
api0(DASH + "/:dash_id/yaml", ["GET"], "read_dashboard_yaml", evref="metrics/dash_handler.go:ShowYAML")
api0(DASH + "/:dash_id/yaml", ["PUT"], "update_dashboard_yaml", evref="metrics/dash_handler.go:UpdateYAML")
api0(DASH + "/:dash_id/table", ["PUT"], "update_dashboard_table", evref="metrics/dash_handler.go:UpdateTable")
api0(DASH + "/:dash_id/grid", ["PUT"], "update_dashboard_grid", evref="metrics/dash_handler.go:UpdateGrid")
api0(DASH + "/:dash_id/reset", ["PUT"], "reset_dashboard", evref="metrics/dash_handler.go:Reset")
api0(DASH + "/:dash_id/unpinned", ["PUT"], "unpin_dashboard", evref="metrics/dash_handler.go:Unpin")


# ===========================================================================
# GRID ITEMS + ROWS -- m.UserAndProject + m.Dashboard
# ===========================================================================
GRID = DASH + "/:dash_id/grid"
ROWS = DASH + "/:dash_id/rows"
RID = rf("row_id", "path", required=True, description="grid item/row id")

api(GRID, ["POST"],
    [variant("POST", [PID, DID, rf("type", "body", description="grid item type")],
             resp_json([of("gridItem")]), body_format="json",
             reason="Creates a grid item", evidence="metrics/grid_item_handler.go:Create")],
    "create_grid_item", sin=[pid_dec(), did_dec()],
    sout=[dec("gridItem", "GridItemID(grid_item)", "identifier", reference_capable=True,
              reason="Created grid item id.")],
    vis_reason="Grid item create.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/grid_item_handler.go:Create")

api(GRID + "/:row_id", ["DELETE"],
    [variant("DELETE", [PID, DID, RID], resp_empty(),
             reason="Deletes a grid item", evidence="metrics/grid_item_handler.go:Delete")],
    "delete_grid_item",
    sin=[pid_dec(), did_dec(),
         dec("row_id", "GridItemID(grid_item)", "identifier", reference_capable=True,
             reason="Grid item being deleted.")],
    vis_reason="Grid item delete.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/grid_item_handler.go:Delete")

api(ROWS, ["POST"],
    [variant("POST", [PID, DID, rf("title", "body", description="row title")],
             resp_json([of("gridRow")]), body_format="json",
             reason="Creates a grid row", evidence="metrics/grid_row_handler.go:Create")],
    "create_grid_row", sin=[pid_dec(), did_dec()],
    sout=[dec("gridRow", "GridRowID(grid_row)", "identifier", reference_capable=True,
              reason="Created grid row id.")],
    vis_reason="Grid row create.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/grid_row_handler.go:Create")

api(ROWS + "/:row_id", ["DELETE"],
    [variant("DELETE", [PID, DID,
             rf("row_id", "path", required=True, description="grid row id")], resp_empty(),
             reason="Deletes a grid row", evidence="metrics/grid_row_handler.go:Delete")],
    "delete_grid_row",
    sin=[pid_dec(), did_dec(),
         dec("row_id", "GridRowID(grid_row)", "identifier", reference_capable=True,
             reason="Grid row being deleted.")],
    vis_reason="Grid row delete.", reach=["Authenticated; project exists; dash in project."],
    evref="metrics/grid_row_handler.go:Delete")

# deferred grid write/read variants
api0(GRID + "/layout", ["PUT"], "update_grid_layout", evref="metrics/grid_item_handler.go:UpdateLayout")
api0(GRID + "/:row_id", ["PUT"], "update_grid_item", evref="metrics/grid_item_handler.go:Update")
api0(ROWS + "/:row_id", ["GET"], "read_grid_row", evref="metrics/grid_row_handler.go:Show")
api0(ROWS + "/:row_id", ["PUT"], "update_grid_row", evref="metrics/grid_row_handler.go:Update")
api0(ROWS + "/:row_id/up", ["PUT"], "move_grid_row_up", evref="metrics/grid_row_handler.go:MoveUp")
api0(ROWS + "/:row_id/down", ["PUT"], "move_grid_row_down", evref="metrics/grid_row_handler.go:MoveDown")


# ===========================================================================
# PUBLIC API (/api/v1/tracing) -- m.UserAndProject (USER auth on a public path)
# ===========================================================================
api("/api/v1/tracing/:project_id/spans", ["GET"],
    [variant("GET", [PID] + _span_q, resp_json([of("spans")]),
             reason="Public span query", evidence="tracing/public_handler.go:Spans")],
    "public_list_spans", sin=[pid_dec()],
    sout=[dec("spans", "SpanID(span)", "identifier", reference_capable=True,
              reason="Span rows.")],
    vis_reason="Public API span query.",
    reach=["Authenticated (same m.UserAndProject gate despite /api/v1 path)."],
    evref="tracing/public_handler.go:registerPublicHandler")

api("/api/v1/tracing/:project_id/groups", ["GET"],
    [variant("GET", [PID] + _span_q, resp_json([of("groups")]),
             reason="Public group query", evidence="tracing/public_handler.go:Groups")],
    "public_list_groups", sin=[pid_dec()],
    vis_reason="Public API group query.", reach=["Authenticated."],
    evref="tracing/public_handler.go:registerPublicHandler")


# ===========================================================================
# INGESTION (DSN auth) -- OTLP HTTP mirrors + vector + prometheus + cloudwatch
# ===========================================================================
api("/v1/traces", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="uptrace-dsn / Bearer"),
                      rf("raw_body", "body", required=True, description="OTLP ExportTraceServiceRequest")],
             resp_empty(), body_format="plain",
             reason="OTLP HTTP trace ingestion", evidence="tracing/init.go:initOTLP")],
    "ingest_otlp_traces",
    sin=[dec("dsn", "ProjectDSN(project)", "credential",
             reason="DSN selects + authorizes the destination project.")],
    vis_reason="OTLP trace ingest.", reach=["Valid project DSN."],
    evref="tracing/init.go:initOTLP",
    notes="protobuf/json OTLP body; project resolved from DSN, not user session.")

api("/v1/logs", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="uptrace-dsn / Bearer"),
                      rf("raw_body", "body", required=True, description="OTLP ExportLogsServiceRequest")],
             resp_empty(), body_format="plain",
             reason="OTLP HTTP log ingestion", evidence="tracing/init.go:initOTLP")],
    "ingest_otlp_logs",
    sin=[dec("dsn", "ProjectDSN(project)", "credential", reason="DSN authorizes the project.")],
    vis_reason="OTLP log ingest.", reach=["Valid project DSN."], evref="tracing/init.go:initOTLP")

api("/v1/metrics", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="uptrace-dsn / Bearer"),
                      rf("raw_body", "body", required=True, description="OTLP ExportMetricsServiceRequest")],
             resp_empty(), body_format="plain",
             reason="OTLP HTTP metric ingestion", evidence="metrics/init.go:initOTLP")],
    "ingest_otlp_metrics",
    sin=[dec("dsn", "ProjectDSN(project)", "credential", reason="DSN authorizes the project.")],
    vis_reason="OTLP metric ingest.", reach=["Valid project DSN."], evref="metrics/init.go:initOTLP")

api("/api/v1/vector-logs", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="uptrace-dsn / Bearer / ?dsn="),
                      rf("raw_body", "body", required=True, description="ndjson log events")],
             resp_empty(), body_format="plain",
             reason="Vector log ingestion", evidence="tracing/vector_handler.go:Create")],
    "ingest_vector_logs",
    sin=[dec("dsn", "ProjectDSN(project)", "credential", reason="DSN authorizes the project.")],
    vis_reason="Vector log ingest.", reach=["Valid project DSN."],
    evref="tracing/vector_handler.go:registerVectorHandler")

api("/api/v1/prometheus/write", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="DSN"),
                      rf("raw_body", "body", required=True, description="Prometheus remote-write protobuf")],
             resp_empty(), body_format="plain",
             reason="Prometheus remote-write", evidence="metrics/prom_remote_storage.go:Write")],
    "ingest_prometheus_write",
    sin=[dec("dsn", "ProjectDSN(project)", "credential", reason="DSN authorizes the project.")],
    vis_reason="Prometheus remote write.", reach=["Valid project DSN."],
    evref="metrics/prom_remote_storage.go:registerPrometheusHandler")

api("/api/v1/prometheus/read", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="DSN"),
                      rf("raw_body", "body", required=True, description="Prometheus remote-read protobuf")],
             resp_empty(), body_format="plain",
             reason="Prometheus remote-read", evidence="metrics/prom_remote_storage.go:Read")],
    "query_prometheus_read",
    sin=[dec("dsn", "ProjectDSN(project)", "credential", reason="DSN authorizes the project.")],
    vis_reason="Prometheus remote read.", reach=["Valid project DSN."],
    evref="metrics/prom_remote_storage.go:registerPrometheusHandler")

api("/api/v1/cloudwatch/metrics", ["POST"],
    [variant("POST", [rf("dsn", "header", required=True, description="DSN"),
                      rf("raw_body", "body", required=True, description="Kinesis/CloudWatch metric stream")],
             resp_empty(), body_format="plain",
             reason="CloudWatch (Kinesis) metric ingestion", evidence="metrics/cloudwatch_handler.go:Metrics")],
    "ingest_cloudwatch_metrics",
    sin=[dec("dsn", "ProjectDSN(project)", "credential", reason="DSN authorizes the project.")],
    vis_reason="CloudWatch metric ingest.", reach=["Valid project DSN."],
    evref="metrics/cloudwatch_handler.go:registerKinesisHandler")

# deferred ingestion alias
api0("/api/v1/vector/logs", ["POST"], "ingest_vector_logs_alias",
     reach=["Valid project DSN."], evref="tracing/vector_handler.go:registerVectorHandler")


# Build API_NODES from accumulated per-path specs (merges multi-method routes).
_finalize_api()


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded, VERSION-STABLE auth-transport behaviours only.
# Probed against uptrace/uptrace:2.1.0-rc.1 (example/docker stack) via
# runtime/probe.ps1 -> runtime/probe_results/matrix.json. The image DIVERGES from
# the rc.2 source in auth (Guest user), data exposure (project omits DSN) and dash
# routing (POST 405) -- see annotation_issues uptrace-009 -- so ONLY the endpoints
# whose auth transport is architectural (DSN-gating vs user-gating, anon 401,
# existence 404) are stamped. Identity labels: anonymous | authenticated | dsn.
# ===========================================================================
_RUNTIME = {
    "/v1/traces":  {"s": [200, 401], "id": {"dsn": [200], "anonymous": [401]}},
    "/v1/logs":    {"s": [200, 401], "id": {"dsn": [200], "anonymous": [401]}},
    "/v1/metrics": {"s": [200, 401], "id": {"dsn": [200], "anonymous": [401]}},
    # finding uptrace-004 CONFIRMED: /api/v1/tracing is USER-gated, not DSN-gated.
    "/api/v1/tracing/:project_id/spans":  {"s": [400, 401],
        "id": {"anonymous": [401], "dsn": [401], "authenticated": [400]}},
    # anon gate confirmed; existence gate (404) confirmed via project 999999.
    "/internal/v1/projects/:project_id":  {"s": [200, 401, 404], "id": {"anonymous": [401]}},
    "/internal/v1/traces/search":         {"s": [400, 401],
        "id": {"anonymous": [401], "authenticated": [400]}},
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
# PAGE / DEBUG nodes (surface-complete; not candidates)
# ===========================================================================
PAGE_NODES = []


def page(key, methods, op="", kind="page", reach=None, evref="", notes=None):
    PAGE_NODES.append(c.node(
        K(key), kind, methods, variants=[], operation_semantic=op, params=[],
        visibility="black_box", reachable=True, reach_conds=reach or [],
        evidence=[ev_src(evref, "route")] if evref else [], notes=notes))


page("/debug/pprof/", ["GET"], "pprof_index", kind="page",
     reach=["conf.Debug=true ONLY."], evref="bunapp/router.go:initRouter",
     notes="Mounted only when Debug=true; not present in production config.")
page("/debug/pprof/:name", ["GET"], "pprof_named", kind="page",
     reach=["conf.Debug=true ONLY."], evref="bunapp/router.go:initRouter")
page("/", ["GET"], "spa_shell", kind="static", evref="bunapp (Vue SPA FS)",
     notes="SPA shell + client bundle; JSON APIs above are the real surface.")


# ===========================================================================
# EDGES (SPA -> API triggers; minimal source-confirmed set)
# ===========================================================================
EDGES = [
    {"src": K("/"), "dst": K("/internal/v1/users/login"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/"), "dst": K("/internal/v1/users/current"), "methods": ["GET"], "triggers": ["xhr"]},
]
