# -*- coding: utf-8 -*-
"""Uptrace (OSS) L2 action cores.

One business action per <Subject,Operation,Object,Req,Eff> over the six Pengent
predicates. io_accounting fact strings use common.fact_key so they always match
Req/Eff. Evidence refs point at uptrace/pkg source. Auth model (pkg/org/auth.go):
  - Session  = JWT 'token' cookie or Authorization: Bearer (logged-in user)
  - ProjectDSN = uptrace-dsn header / Bearer / ?dsn= (ingestion clients)
OSS is single-tenant: UserAndProject only checks the project EXISTS, so any
authenticated user can act on any project (no per-user ACL) -- captured in reach_conds.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind

ACTOR = subj()


def kf(fact):
    return fact_key(fact)


def src(ref, supports="route + handler"):
    return c.ev("source", "uptrace/pkg/" + ref, supports)


# ---- shared entities / facts ----------------------------------------------
def proj(role="target"):
    return entity("project", "Project", role)


def dash(role="target"):
    return entity("dashboard", "Dashboard", role)


def know(ref_type, ent):
    return f_know(ACTOR, reference(ref_type, ent))


_auth = f_auth(ACTOR, "Session")          # logged-in user
_dsnauth = f_auth(ACTOR, "ProjectDSN")    # DSN-authenticated ingestor
_kp = know("ProjectID", proj())           # caller references an existing project
_kdsn = know("ProjectDSN", proj())        # caller holds the project DSN

OSS_NO_ACL = "Authenticated; project exists (OSS single-tenant: NO per-user ACL)."


# ===========================================================================
# AUTH / SESSION
# ===========================================================================
_pw = know("Password", entity("user", "User", "self"))
_tok = know("AuthToken", entity("session", "Session", "created"))
action(
    "anon_login", "Log in", "Create", "login_user", "Anonymous",
    obj("state", "session", "Session", "response", "", "AuthToken(session)",
        role="created", state_field="authenticated"),
    requirements=[req("knowledge", _pw, "Caller supplies email+password.")],
    gen=[eff(f_auth(ACTOR, "Session"), "auth_transition", "Caller becomes authenticated."),
         eff(_tok, "io_reference", "Sets the 'token' JWT cookie.")],
    kill=[],
    io_accounting=[io("input", "email / UserEmail(user)", "object_attribute", [], "Login identifier."),
                   io("input", "password / Password(user)", "req", [kf(_pw)]),
                   io("output", "token / AuthToken(session)", "gen", [kf(_tok)], "")],
    bindings=[bind(K("/internal/v1/users/login"), ["POST"])],
    vis="black_box", vis_reason="Public login.", reachable=True,
    reach_conds=["User exists in config/db; password matches (bcrypt)."],
    evidence=[src("org/user_handler.go:Login", "verify + set cookie")],
    confidence=0.9, reasoning="Login verifies bcrypt and sets the token cookie.",
    description="A visitor logs in and receives a JWT session cookie.")

action(
    "user_logout", "Log out", "Delete", "logout_user", "User",
    obj("state", "session", "Session", "subject", "", "AuthToken(session)",
        role="self", state_field="authenticated"),
    requirements=[req("authentication", _auth, "A session identifies the caller.")],
    gen=[], kill=[eff(f_auth(ACTOR, "Session"), "auth_transition", "The token cookie is cleared.")],
    io_accounting=[],
    bindings=[bind(K("/internal/v1/users/logout"), ["POST"])],
    vis="black_box", vis_reason="Logout.", reachable=True, reach_conds=["Any (clears cookie)."],
    evidence=[src("org/user_handler.go:Logout", "clear cookie")],
    confidence=0.85, reasoning="Logout clears the token cookie.",
    description="A user clears their session cookie.")

_u = know("UserEmail", entity("user", "User", "self"))
_pl = know("ProjectID", proj("listed"))
action(
    "user_read_current", "Read current user", "Read", "read_current_user", "User",
    obj("entity", "user", "User", "subject", "", "UserEmail(user)", role="self"),
    requirements=[req("authentication", _auth, "Authenticated (cookie/bearer).")],
    gen=[eff(_u, "io_reference", "Returns the caller's user."),
         eff(_pl, "io_reference", "Returns ALL projects (OSS lists every project).")],
    kill=[],
    io_accounting=[io("output", "user / UserEmail(user)", "gen", [kf(_u)]),
                   io("output", "projects / ProjectID(project)", "gen", [kf(_pl)])],
    bindings=[bind(K("/internal/v1/users/current"), ["GET"])],
    vis="black_box", vis_reason="Self + project list.", reachable=True,
    reach_conds=["Authenticated."],
    evidence=[src("org/user_handler.go:Current", "self + projects")],
    confidence=0.9, reasoning="Current returns the user and all projects.",
    description="A user reads their account and the full project list.")


# ===========================================================================
# ORG (project, usage)
# ===========================================================================
_dsn_out = know("ProjectDSN", proj())
action(
    "user_read_project", "Read project + DSN", "Read", "read_project", "ProjectMember",
    obj("entity", "project", "Project", "request", "project_id", "ProjectID(project)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project by id.")],
    gen=[eff(_dsn_out, "io_reference", "Returns the project DSN (ingest credential).")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("output", "dsn / ProjectDSN(project)", "gen", [kf(_dsn_out)])],
    bindings=[bind(K("/internal/v1/projects/:project_id"), ["GET"])],
    vis="black_box", vis_reason="Project incl. DSN.", reachable=True,
    reach_conds=[OSS_NO_ACL, "DSN DISCLOSURE: any user reads any project's ingest credential."],
    evidence=[src("org/project_handler.go:Show", "project + BuildDSN")],
    confidence=0.9, reasoning="Show returns the project and its DSN.",
    description="A user reads a project and obtains its ingest DSN.")

action(
    "user_read_usage", "Read data usage", "Read", "read_data_usage", "User",
    obj("entity", "usage", "Usage", "implicit", "", "", role="account"),
    requirements=[req("authentication", _auth, "Authenticated.")],
    gen=[], kill=[],
    io_accounting=[io("output", "spans / -", "observed_only", [], "Usage counters (no refs)."),
                   io("output", "bytes / -", "observed_only", [], "Byte counters.")],
    bindings=[bind(K("/internal/v1/data-usage"), ["GET"])],
    vis="black_box", vis_reason="Usage stats.", reachable=True, reach_conds=["Authenticated."],
    evidence=[src("org/usage_handler.go:Show", "usage")],
    confidence=0.8, reasoning="Show returns monthly usage counters.",
    description="A user reads account data-usage statistics.")


# ===========================================================================
# TRACING (reads)
# ===========================================================================
_tid_in = know("TraceID", entity("trace", "Trace", "target"))
_pid_out = know("ProjectID", proj("resolved"))
action(
    "user_search_trace", "Search trace by id", "Read", "search_trace", "User",
    obj("entity", "trace", "Trace", "request", "trace_id", "TraceID(trace)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated (m.User ONLY -- no project gate).")],
    gen=[eff(_pid_out, "io_reference", "Resolves the owning project id for ANY trace id.")],
    kill=[],
    io_accounting=[io("input", "trace_id / TraceID(trace)", "object_attribute", [], "Trace id probed."),
                   io("output", "project_id / ProjectID(project)", "gen", [kf(_pid_out)])],
    bindings=[bind(K("/internal/v1/traces/search"), ["GET"])],
    vis="black_box", vis_reason="Trace-id lookup.", reachable=True,
    reach_conds=["Authenticated. NOT project-scoped -> cross-project trace-id oracle."],
    evidence=[src("tracing/trace_handler.go:FindTrace", "m.User only")],
    confidence=0.85, reasoning="FindTrace resolves a trace id to project/span under m.User.",
    description="A user resolves any trace id to its project (no project scoping).")


def tracing_read(akey, name, business, path, out_ref, out_type, out_role, field):
    _o = know(out_ref, entity(out_type.lower(), out_type, out_role))
    action(
        akey, name, "Read", business, "ProjectMember",
        obj("entity", out_type.lower(), out_type, "request", "project_id", "ProjectID(project)", role="result"),
        requirements=[req("authentication", _auth, "Authenticated."),
                      req("knowledge", _kp, "References an existing project.")],
        gen=[eff(_o, "io_reference", f"Returns {field}.")], kill=[],
        io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                       io("input", "query / -", "object_attribute", [], "TQL/time filter."),
                       io("output", f"{field} / {out_ref}({out_type.lower()})", "gen", [kf(_o)])],
        bindings=[bind(K(path), ["GET"])],
        vis="black_box", vis_reason=name + ".", reachable=True, reach_conds=[OSS_NO_ACL],
        evidence=[src("tracing/*_handler.go", "project-scoped read")],
        confidence=0.85, reasoning=f"{business} returns {field} for the project.",
        description=f"A project member reads {field}.")


tracing_read("user_list_systems", "List span systems", "list_span_systems",
             "/internal/v1/tracing/:project_id/systems", "SpanSystem", "SpanSystem", "result", "systems")
tracing_read("user_list_spans", "List spans", "list_spans",
             "/internal/v1/tracing/:project_id/spans", "SpanID", "Span", "result", "spans")
tracing_read("user_list_groups", "List span groups", "list_span_groups",
             "/internal/v1/tracing/:project_id/groups", "GroupID", "Group", "result", "groups")
tracing_read("user_list_span_attrs", "List span attribute keys", "list_span_attr_keys",
             "/internal/v1/tracing/:project_id/attributes", "AttrKey", "Attr", "result", "keys")

_gid_in = know("GroupID", entity("group", "Group", "target"))
action(
    "user_read_group", "Read span group", "Read", "read_span_group", "ProjectMember",
    obj("entity", "group", "Group", "request", "group_id", "GroupID(group)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project.")],
    gen=[], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "group_id / GroupID(group)", "object_attribute", [], "Group selector."),
                   io("output", "stats / -", "observed_only", [], "Group summary stats.")],
    bindings=[bind(K("/internal/v1/tracing/:project_id/groups/:group_id"), ["GET"])],
    vis="black_box", vis_reason="Group summary.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("tracing/group_handler.go:ShowSummary", "group summary")],
    confidence=0.8, reasoning="ShowSummary returns stats for a group.",
    description="A project member reads a span group summary.")

_spans_out = know("SpanID", entity("span", "Span", "result"))
action(
    "user_read_trace", "Read trace", "Read", "read_trace", "ProjectMember",
    obj("entity", "trace", "Trace", "request", "trace_id", "TraceID(trace)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project.")],
    gen=[eff(_spans_out, "io_reference", "Returns the spans of the trace.")], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "trace_id / TraceID(trace)", "object_attribute", [], "Trace selector."),
                   io("output", "spans / SpanID(span)", "gen", [kf(_spans_out)])],
    bindings=[bind(K("/internal/v1/tracing/:project_id/traces/:trace_id"), ["GET"])],
    vis="black_box", vis_reason="Trace detail.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("tracing/trace_handler.go:ShowTrace", "trace detail")],
    confidence=0.85, reasoning="ShowTrace returns the spans of a trace.",
    description="A project member reads a full trace.")


# ===========================================================================
# METRICS (reads)
# ===========================================================================
tracing_read("user_list_metrics", "List metrics", "list_metrics",
             "/internal/v1/metrics/:project_id", "MetricName", "Metric", "result", "metrics")
tracing_read("user_list_metric_attrs", "List metric attribute keys", "list_metric_attr_keys",
             "/internal/v1/metrics/:project_id/attributes", "AttrKey", "Attr", "result", "keys")
action(
    "user_query_metrics_table", "Query metrics table", "Read", "query_metrics_table", "ProjectMember",
    obj("entity", "metric", "Metric", "request", "project_id", "ProjectID(project)", role="result"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project.")],
    gen=[], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "query / -", "object_attribute", [], "MQL query (expression surface)."),
                   io("output", "items / -", "observed_only", [], "Query result rows.")],
    bindings=[bind(K("/internal/v1/metrics/:project_id/table"), ["GET"])],
    vis="black_box", vis_reason="Metrics query.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/query_handler.go:Table", "MQL table")],
    confidence=0.8, reasoning="Table runs an MQL query over the project's metrics.",
    description="A project member runs a metrics table query.")


# ===========================================================================
# DASHBOARDS (CRUD)
# ===========================================================================
DASH = "/internal/v1/metrics/:project_id/dashboards"
_dash_new = f_exists(dash("created"))
_dash_id_out = know("DashID", dash("created"))
action(
    "user_create_dashboard", "Create dashboard", "Create", "create_dashboard", "ProjectMember",
    obj("entity", "dashboard", "Dashboard", "response", "", "DashID(dashboard)", role="created"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("authorization", f_can(ACTOR, "Create", proj()), "May create dashboards in the project.")],
    gen=[eff(_dash_new, "action_semantics", "A dashboard row is created."),
         eff(_dash_id_out, "io_reference", "Returns the new dashboard id.")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "name / DashName(dashboard)", "object_attribute", [], "New dashboard name."),
                   io("output", "dashboard / DashID(dashboard)", "gen", [kf(_dash_id_out)])],
    bindings=[bind(K(DASH), ["POST"], sel_field="method", sel_values=["POST"])],
    vis="black_box", vis_reason="Dashboard create.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:Create", "create dashboard")],
    confidence=0.85, reasoning="Create inserts a dashboard in the project.",
    description="A project member creates a dashboard.")

_dash_list = know("DashID", dash("listed"))
action(
    "user_list_dashboards", "List dashboards", "Read", "list_dashboards", "ProjectMember",
    obj("entity", "dashboard", "Dashboard", "request", "project_id", "ProjectID(project)", role="collection"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project.")],
    gen=[eff(_dash_list, "io_reference", "Returns dashboard ids.")], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("output", "dashboards / DashID(dashboard)", "gen", [kf(_dash_list)])],
    bindings=[bind(K(DASH), ["GET"], sel_field="method", sel_values=["GET"])],
    vis="black_box", vis_reason="Dashboard list.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:List", "list dashboards")],
    confidence=0.85, reasoning="List returns the project's dashboards.",
    description="A project member lists dashboards.")

_dash_yaml_out = know("DashID", dash("created"))
action(
    "user_create_dashboard_yaml", "Create dashboard from YAML", "Create", "create_dashboard_yaml",
    "ProjectMember",
    obj("entity", "dashboard", "Dashboard", "response", "", "DashID(dashboard)", role="created"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("authorization", f_can(ACTOR, "Create", proj()), "May create dashboards.")],
    gen=[eff(f_exists(dash("created")), "action_semantics", "A dashboard is created from YAML."),
         eff(_dash_yaml_out, "io_reference", "Returns the new dashboard id.")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "yaml / -", "object_attribute", [], "YAML document (template-injection surface)."),
                   io("output", "dashboard / DashID(dashboard)", "gen", [kf(_dash_yaml_out)])],
    bindings=[bind(K(DASH + "/yaml"), ["POST"])],
    vis="black_box", vis_reason="Dashboard create from YAML.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:CreateFromYAML", "yaml -> dashboard")],
    confidence=0.8, reasoning="CreateFromYAML builds a dashboard from a YAML body.",
    description="A project member creates a dashboard from YAML.")

# /dashboards/:dash_id  (GET read / POST clone / PUT update / DELETE delete)
_did = "/internal/v1/metrics/:project_id/dashboards/:dash_id"
_kd = know("DashID", dash())
action(
    "user_read_dashboard", "Read dashboard", "Read", "read_dashboard", "ProjectMember",
    obj("entity", "dashboard", "Dashboard", "request", "dash_id", "DashID(dashboard)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard must belong to the project (m.Dashboard).")],
    gen=[], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("output", "dashboard / -", "observed_only", [], "Dashboard + grid.")],
    bindings=[bind(K(_did), ["GET"], sel_field="method", sel_values=["GET"])],
    vis="black_box", vis_reason="Dashboard detail.", reachable=True,
    reach_conds=[OSS_NO_ACL, "dash.ProjectID == project (m.Dashboard) else 403."],
    evidence=[src("metrics/dash_handler.go:Show", "dashboard detail")],
    confidence=0.85, reasoning="Show returns a dashboard scoped to the project.",
    description="A project member reads a dashboard.")

_clone_out = know("DashID", dash("created"))
action(
    "user_clone_dashboard", "Clone dashboard", "Create", "clone_dashboard", "ProjectMember",
    obj("entity", "dashboard", "Dashboard", "request", "dash_id", "DashID(dashboard)", role="source"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Source dashboard in project."),
                  req("authorization", f_can(ACTOR, "Create", proj()), "May create dashboards.")],
    gen=[eff(f_exists(dash("created")), "action_semantics", "A cloned dashboard row is created."),
         eff(_clone_out, "io_reference", "Returns the clone id.")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("output", "dashboard / DashID(dashboard)", "gen", [kf(_clone_out)])],
    bindings=[bind(K(_did), ["POST"], sel_field="method", sel_values=["POST"])],
    vis="black_box", vis_reason="Dashboard clone.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:Clone", "clone dashboard")],
    confidence=0.8, reasoning="Clone duplicates a dashboard.",
    description="A project member clones a dashboard.")

action(
    "user_update_dashboard", "Update dashboard", "Update", "update_dashboard", "ProjectMember",
    obj("state", "dashboard", "Dashboard", "request", "dash_id", "DashID(dashboard)",
        role="target", state_field="name"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Update", dash()), "May update the dashboard.")],
    gen=[eff(f_state(dash(), "name", "updated"), "action_semantics", "Dashboard fields are updated.")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("input", "name / DashName(dashboard)", "object_attribute", [], "New name.")],
    bindings=[bind(K(_did), ["PUT"], sel_field="method", sel_values=["PUT"])],
    vis="black_box", vis_reason="Dashboard update.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:Update", "update dashboard")],
    confidence=0.85, reasoning="Update mutates dashboard fields.",
    description="A project member updates a dashboard.")

action(
    "user_delete_dashboard", "Delete dashboard", "Delete", "delete_dashboard", "ProjectMember",
    obj("entity", "dashboard", "Dashboard", "request", "dash_id", "DashID(dashboard)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Delete", dash()), "May delete the dashboard.")],
    gen=[], kill=[eff(f_exists(dash()), "action_semantics", "The dashboard row is removed.")],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)])],
    bindings=[bind(K(_did), ["DELETE"], sel_field="method", sel_values=["DELETE"])],
    vis="black_box", vis_reason="Dashboard delete.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:Delete", "delete dashboard")],
    confidence=0.85, reasoning="Delete removes a dashboard.",
    description="A project member deletes a dashboard.")

action(
    "user_pin_dashboard", "Pin dashboard", "Update", "pin_dashboard", "ProjectMember",
    obj("state", "dashboard", "Dashboard", "request", "dash_id", "DashID(dashboard)",
        role="target", state_field="pinned"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Update", dash()), "May update pin state.")],
    gen=[eff(f_state(dash(), "pinned", "true"), "action_semantics", "Dashboard is pinned.")], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)])],
    bindings=[bind(K(_did + "/pinned"), ["PUT"])],
    vis="black_box", vis_reason="Dashboard pin.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/dash_handler.go:Pin", "pin")],
    confidence=0.8, reasoning="Pin sets the dashboard pinned flag.",
    description="A project member pins a dashboard.")


# ===========================================================================
# GRID ITEMS + ROWS
# ===========================================================================
_gi_out = know("GridItemID", entity("grid_item", "GridItem", "created"))
action(
    "user_create_grid_item", "Create grid item", "Create", "create_grid_item", "ProjectMember",
    obj("entity", "grid_item", "GridItem", "response", "", "GridItemID(grid_item)", role="created"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Update", dash()), "May add grid items.")],
    gen=[eff(f_exists(entity("grid_item", "GridItem", "created")), "action_semantics", "A grid item is created."),
         eff(_gi_out, "io_reference", "Returns the grid item id.")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("output", "gridItem / GridItemID(grid_item)", "gen", [kf(_gi_out)])],
    bindings=[bind(K(_did + "/grid"), ["POST"], sel_field="method", sel_values=["POST"])],
    vis="black_box", vis_reason="Grid item create.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/grid_item_handler.go:Create", "create grid item")],
    confidence=0.8, reasoning="Create inserts a grid item on the dashboard.",
    description="A project member adds a grid item to a dashboard.")

_kgi = know("GridItemID", entity("grid_item", "GridItem", "target"))
action(
    "user_delete_grid_item", "Delete grid item", "Delete", "delete_grid_item", "ProjectMember",
    obj("entity", "grid_item", "GridItem", "request", "row_id", "GridItemID(grid_item)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Delete", entity("grid_item", "GridItem", "target")),
                      "May delete the grid item (GridItemMiddleware scopes it).")],
    gen=[], kill=[eff(f_exists(entity("grid_item", "GridItem", "target")), "action_semantics",
                      "The grid item is removed.")],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("input", "row_id / GridItemID(grid_item)", "object_attribute", [], "Grid item id.")],
    bindings=[bind(K(_did + "/grid/:row_id"), ["DELETE"], sel_field="method", sel_values=["DELETE"])],
    vis="black_box", vis_reason="Grid item delete.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/grid_item_handler.go:Delete", "delete grid item")],
    confidence=0.8, reasoning="Delete removes a grid item.",
    description="A project member deletes a grid item.")

_gr_out = know("GridRowID", entity("grid_row", "GridRow", "created"))
action(
    "user_create_grid_row", "Create grid row", "Create", "create_grid_row", "ProjectMember",
    obj("entity", "grid_row", "GridRow", "response", "", "GridRowID(grid_row)", role="created"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Update", dash()), "May add grid rows.")],
    gen=[eff(f_exists(entity("grid_row", "GridRow", "created")), "action_semantics", "A grid row is created."),
         eff(_gr_out, "io_reference", "Returns the grid row id.")],
    kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("output", "gridRow / GridRowID(grid_row)", "gen", [kf(_gr_out)])],
    bindings=[bind(K(_did + "/rows"), ["POST"])],
    vis="black_box", vis_reason="Grid row create.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/grid_row_handler.go:Create", "create grid row")],
    confidence=0.8, reasoning="Create inserts a grid row.",
    description="A project member adds a grid row.")

action(
    "user_delete_grid_row", "Delete grid row", "Delete", "delete_grid_row", "ProjectMember",
    obj("entity", "grid_row", "GridRow", "request", "row_id", "GridRowID(grid_row)", role="target"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project."),
                  req("knowledge", _kd, "Dashboard in project."),
                  req("authorization", f_can(ACTOR, "Delete", entity("grid_row", "GridRow", "target")),
                      "May delete the grid row (GridRowMiddleware scopes it).")],
    gen=[], kill=[eff(f_exists(entity("grid_row", "GridRow", "target")), "action_semantics",
                      "The grid row is removed.")],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("input", "dash_id / DashID(dashboard)", "req", [kf(_kd)]),
                   io("input", "row_id / GridRowID(grid_row)", "object_attribute", [], "Grid row id.")],
    bindings=[bind(K(_did + "/rows/:row_id"), ["DELETE"], sel_field="method", sel_values=["DELETE"])],
    vis="black_box", vis_reason="Grid row delete.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("metrics/grid_row_handler.go:Delete", "delete grid row")],
    confidence=0.8, reasoning="Delete removes a grid row.",
    description="A project member deletes a grid row.")


# ===========================================================================
# PUBLIC API (/api/v1/tracing) -- same user auth
# ===========================================================================
_psp = know("SpanID", entity("span", "Span", "result"))
action(
    "public_list_spans", "Public span query", "Read", "public_list_spans", "ProjectMember",
    obj("entity", "span", "Span", "request", "project_id", "ProjectID(project)", role="result"),
    requirements=[req("authentication", _auth, "Authenticated (m.UserAndProject on /api/v1)."),
                  req("knowledge", _kp, "References an existing project.")],
    gen=[eff(_psp, "io_reference", "Returns span rows.")], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("output", "spans / SpanID(span)", "gen", [kf(_psp)])],
    bindings=[bind(K("/api/v1/tracing/:project_id/spans"), ["GET"])],
    vis="black_box", vis_reason="Public span query.", reachable=True,
    reach_conds=[OSS_NO_ACL, "On /api/v1 path but still USER-gated (not DSN)."],
    evidence=[src("tracing/public_handler.go:Spans", "public spans")],
    confidence=0.85, reasoning="Public Spans is gated by m.UserAndProject.",
    description="A project member queries spans via the public API.")

action(
    "public_list_groups", "Public group query", "Read", "public_list_groups", "ProjectMember",
    obj("entity", "group", "Group", "request", "project_id", "ProjectID(project)", role="result"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _kp, "References an existing project.")],
    gen=[], kill=[],
    io_accounting=[io("input", "project_id / ProjectID(project)", "req", [kf(_kp)]),
                   io("output", "groups / -", "observed_only", [], "Group rows.")],
    bindings=[bind(K("/api/v1/tracing/:project_id/groups"), ["GET"])],
    vis="black_box", vis_reason="Public group query.", reachable=True, reach_conds=[OSS_NO_ACL],
    evidence=[src("tracing/public_handler.go:Groups", "public groups")],
    confidence=0.8, reasoning="Public Groups is gated by m.UserAndProject.",
    description="A project member queries span groups via the public API.")


# ===========================================================================
# INGESTION (DSN auth)
# ===========================================================================
def ingest(akey, name, business, path, kind_label, evref):
    action(
        akey, name, "Create", business, "Ingestor",
        obj("entity", "telemetry", "Telemetry", "request", "dsn", "ProjectDSN(project)", role="ingested"),
        requirements=[req("authentication", _dsnauth, "DSN authenticates the client."),
                      req("knowledge", _kdsn, "Holds the project DSN (bearer credential).")],
        gen=[eff(f_exists(entity("telemetry", "Telemetry", "ingested")), "action_semantics",
                 f"{kind_label} are written to the resolved project.")],
        kill=[],
        io_accounting=[io("input", "dsn / ProjectDSN(project)", "req", [kf(_kdsn)]),
                       io("input", "raw_body / -", "object_attribute", [], f"{kind_label} payload.")],
        bindings=[bind(K(path), ["POST"])],
        vis="black_box", vis_reason=name + ".", reachable=True,
        reach_conds=["Valid project DSN (no user session required)."],
        evidence=[src(evref, "DSN ingest")],
        confidence=0.85, reasoning=f"{business} resolves the project from the DSN and ingests {kind_label}.",
        description=f"A telemetry client sends {kind_label} using a project DSN.")


ingest("ingest_otlp_traces", "Ingest OTLP traces", "ingest_otlp_traces", "/v1/traces",
       "spans", "tracing/init.go:initOTLP")
ingest("ingest_otlp_logs", "Ingest OTLP logs", "ingest_otlp_logs", "/v1/logs",
       "logs", "tracing/init.go:initOTLP")
ingest("ingest_otlp_metrics", "Ingest OTLP metrics", "ingest_otlp_metrics", "/v1/metrics",
       "datapoints", "metrics/init.go:initOTLP")
ingest("ingest_vector_logs", "Ingest Vector logs", "ingest_vector_logs", "/api/v1/vector-logs",
       "ndjson logs", "tracing/vector_handler.go:Create")
ingest("ingest_prometheus_write", "Prometheus remote write", "ingest_prometheus_write",
       "/api/v1/prometheus/write", "timeseries", "metrics/prom_remote_storage.go:Write")
ingest("ingest_cloudwatch_metrics", "Ingest CloudWatch metrics", "ingest_cloudwatch_metrics",
       "/api/v1/cloudwatch/metrics", "cloudwatch datapoints", "metrics/cloudwatch_handler.go:Metrics")

# prometheus read is a query, not ingest
action(
    "query_prometheus_read", "Prometheus remote read", "Read", "query_prometheus_read", "Ingestor",
    obj("entity", "telemetry", "Telemetry", "request", "dsn", "ProjectDSN(project)", role="queried"),
    requirements=[req("authentication", _dsnauth, "DSN authenticates the client."),
                  req("knowledge", _kdsn, "Holds the project DSN.")],
    gen=[], kill=[],
    io_accounting=[io("input", "dsn / ProjectDSN(project)", "req", [kf(_kdsn)]),
                   io("input", "raw_body / -", "object_attribute", [], "Remote-read query."),
                   io("output", "timeseries / -", "observed_only", [], "Matching series.")],
    bindings=[bind(K("/api/v1/prometheus/read"), ["POST"])],
    vis="black_box", vis_reason="Prometheus remote read.", reachable=True,
    reach_conds=["Valid project DSN."],
    evidence=[src("metrics/prom_remote_storage.go:Read", "DSN read")],
    confidence=0.8, reasoning="Read resolves the project from the DSN and returns series.",
    description="A client reads back timeseries via Prometheus remote-read using a DSN.")
