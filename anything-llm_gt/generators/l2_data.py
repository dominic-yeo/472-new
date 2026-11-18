# -*- coding: utf-8 -*-
"""AnythingLLM Developer API (/api/v1) L2 action cores.

Module: System Settings + Authentication. One business action per
<Subject,Operation,Object,Req,Eff>. The /api/v1 surface authenticates with a
single instance-level API key (validApiKey); the key holder is operator-level.
Facts use only the six Pengent predicates; io_accounting strings via fact_key.
"""
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists, f_state,
                    f_relation, req, eff, io, fact_key, ev)
from l2lib import action, obj, bind

ACTOR = subj()
AUTH_API = f_auth(ACTOR, "ApiKey")


def kf(fact):
    return fact_key(fact)


# ---- Authentication --------------------------------------------------------
_know_auth = f_know(ACTOR, reference("AuthStatus", entity("auth", "ApiKeyAuth", "target")))
action(
    "dev_verify_api_key", "Verify API key", "Read", "verify_api_key", "ApiCaller",
    obj("entity", "auth", "ApiKeyAuth", "implicit", "", "", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey verifies the Authorization Bearer key.")],
    gen=[eff(_know_auth, "implicit_context", "Response confirms the API key is valid (authenticated:true).")],
    kill=[],
    io_accounting=[],
    bindings=[bind(K("/api/v1/auth"), ["GET"])],
    vis="black_box", vis_reason="Probe the API key by calling the endpoint.", reachable=True,
    reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/auth/index.js:6", "validApiKey gate + fixed response")],
    confidence=0.98, reasoning="Fixed status endpoint behind validApiKey.",
    description="A developer confirms their API key is accepted.")

# ---- System Settings -------------------------------------------------------
action(
    "dev_dump_settings_to_env", "Flush settings to .env", "Update", "dump_settings_to_env", "Anonymous",
    obj("entity", "system_config", "SystemConfig", "implicit", "", "", role="target"),
    requirements=[],
    gen=[eff(f_state(entity("system_config", "SystemConfig", "target"), "env_file", "flushed"),
             "action_semantics", "In production, flushes in-memory settings to the .env file.")],
    kill=[],
    io_accounting=[],
    bindings=[bind(K("/api/v1/system/env-dump"), ["GET"])],
    vis="black_box", vis_reason="Unauthenticated endpoint; any caller can hit it.", reachable=True,
    reach_conds=["None (intentionally unauthenticated)"],
    evidence=[ev("source", "server/endpoints/api/system/index.js:16", "no auth middleware; dumpENV() in production")],
    confidence=0.9, reasoning="GET with a write side effect, guarded only by NODE_ENV===production.",
    description="Any caller triggers a flush of in-memory configuration to the .env file (production only).",
    notes="Unauthenticated by design (SECURITY.md); no secret values returned, but it persists config state.")

_know_settings = f_know(ACTOR, reference("SystemSettings", entity("system", "System", "target")))
action(
    "dev_read_system_settings", "Read system settings", "Read", "read_system_settings", "ApiCaller",
    obj("entity", "system", "System", "response", "settings", "SystemSettings(system)", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_settings, "io_reference", "Response returns the full settings snapshot.")],
    kill=[],
    io_accounting=[io("output", "settings / SystemSettings(system)", "gen", [kf(_know_settings)])],
    bindings=[bind(K("/api/v1/system"), ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True,
    reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/system/index.js:39", "SystemSettings.currentSettings()")],
    confidence=0.95, reasoning="Read of instance configuration; secrets masked to presence booleans.",
    description="A developer reads the instance's system settings (provider/vector-DB/flags + secret presence).",
    notes="Discloses which provider credentials are configured (as booleans) and non-secret config values.")

_know_vc = f_know(ACTOR, reference("VectorCount", entity("vectordb", "VectorDB", "target")))
action(
    "dev_read_vector_count", "Read vector count", "Read", "read_vector_count", "ApiCaller",
    obj("entity", "vectordb", "VectorDB", "response", "vectorCount", "VectorCount(vectordb)", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_vc, "io_reference", "Response returns the total vector count.")],
    kill=[],
    io_accounting=[io("output", "vectorCount / VectorCount(vectordb)", "gen", [kf(_know_vc)])],
    bindings=[bind(K("/api/v1/system/vector-count"), ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True,
    reach_conds=["Valid instance API key", "Vector DB connected"],
    evidence=[ev("source", "server/endpoints/api/system/index.js:76", "VectorDb.totalVectors()")],
    confidence=0.95, reasoning="Aggregate read of the connected vector DB.",
    description="A developer reads the total number of vectors in the connected vector database.")

action(
    "dev_update_system_settings", "Update system settings", "Update", "update_system_settings", "ApiCaller",
    obj("entity", "system_config", "SystemConfig", "request", "env", "EnvConfig(system)", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_state(entity("system_config", "SystemConfig", "target"), "settings", "updated"),
             "state_transition", "Applies the submitted configuration values.")],
    kill=[eff(f_state(entity("system_config", "SystemConfig", "target"), "settings", "previous"),
              "state_transition", "Previous configuration values replaced.")],
    io_accounting=[io("input", "env / EnvConfig(system)", "object_attribute", [],
                      "New configuration values submitted for update; not a precondition reference."),
                   io("output", "newValues / EnvValues(system)", "observed_only", [],
                      "Echo of the applied values; not a stable object reference.")],
    bindings=[bind(K("/api/v1/system/update-env"), ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True,
    reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/system/index.js:108", "updateENV(body) persists settings")],
    confidence=0.9, reasoning="Writes instance configuration from a caller-supplied key/value map.",
    description="A developer updates instance settings (can switch LLM provider, vector DB, or embedded keys).",
    notes="High-impact reconfiguration via one authenticated call.")

_know_export = f_know(ACTOR, reference("ChatExport", entity("chats", "ChatCollection", "collection")))
action(
    "dev_export_all_chats", "Export all chats", "Read", "export_all_chats", "ApiCaller",
    obj("entity", "chats", "ChatCollection", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_export, "io_reference", "Returns all workspace chats serialized in the requested format.")],
    kill=[],
    io_accounting=[io("input", "type / ExportType(export)", "object_attribute", [],
                      "Export format discriminator; not a precondition."),
                   io("output", "(serialized chats)", "observed_only", [],
                      "Raw exported chat content; format varies, not a stable reference.")],
    bindings=[bind(K("/api/v1/system/export-chats"), ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True,
    reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/system/index.js:157", "exportChatsAsType(type,'workspace')")],
    confidence=0.9, reasoning="Bulk read/serialization of all chats across workspaces.",
    description="A developer exports every workspace chat in a chosen format (jsonl/json/csv/jsonAlpaca).",
    notes="Bulk cross-workspace data exposure surface.")

_know_doc = f_know(ACTOR, reference("DocumentLocation", entity("document", "Document", "target")))
action(
    "dev_remove_documents", "Remove documents", "Delete", "remove_documents", "ApiCaller",
    obj("entity", "document", "Document", "request", "names", "DocumentLocation(document)", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", _know_doc, "Caller supplies the document storage locations.")],
    gen=[],
    kill=[eff(f_exists(entity("document", "Document", "target")), "state_transition",
              "Named documents are permanently removed from storage.")],
    io_accounting=[io("input", "names / DocumentLocation(document)", "req", [kf(_know_doc)])],
    bindings=[bind(K("/api/v1/system/remove-documents"), ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True,
    reach_conds=["Valid instance API key", "Known document storage paths"],
    evidence=[ev("source", "server/endpoints/api/system/index.js:219", "purgeDocument(name) per name")],
    confidence=0.9, reasoning="Permanent deletion keyed by caller-supplied storage path.",
    description="A developer permanently removes documents by their storage location.")


# ============================================================================
# WORKSPACES (core RAG / chat surface)
# ============================================================================
WS_ENT = entity("workspace", "Workspace", "target")
WS_CREATED = entity("workspace", "Workspace", "created")
DOC_ENT = entity("document", "Document", "target")
KNOW_WS = f_know(ACTOR, reference("WorkspaceSlug", WS_ENT))
EXISTS_WS = f_exists(WS_ENT)
KNOW_DOC = f_know(ACTOR, reference("DocumentLocation", DOC_ENT))
_WK = K("/api/v1/workspace")

_know_ws_created = f_know(ACTOR, reference("WorkspaceSlug", WS_CREATED))
action(
    "dev_create_workspace", "Create workspace", "Create", "create_workspace", "ApiCaller",
    obj("entity", "workspace", "Workspace", "response", "slug", "WorkspaceSlug(workspace)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(WS_CREATED), "action_semantics", "A new workspace is created."),
         eff(_know_ws_created, "io_reference", "Response returns the new workspace slug.")],
    kill=[],
    io_accounting=[io("input", "name / WorkspaceName(workspace)", "object_attribute", [], "New workspace name."),
                   io("input", "config / WorkspaceConfig(workspace)", "object_attribute", [], "New workspace settings."),
                   io("output", "workspace.slug / WorkspaceSlug(workspace)", "gen", [kf(_know_ws_created)])],
    bindings=[bind(f"{_WK}/new", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:28", "Workspace.new()")],
    confidence=0.95, reasoning="Creates a workspace from caller settings.",
    description="A developer creates a new workspace.")

action(
    "dev_list_workspaces", "List workspaces", "Read", "list_workspaces", "ApiCaller",
    obj("entity", "workspace", "Workspace", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_WS, "io_reference", "Response returns workspace slugs.")],
    kill=[],
    io_accounting=[io("output", "workspaces[].slug / WorkspaceSlug(workspace)", "gen", [kf(KNOW_WS)])],
    bindings=[bind(K("/api/v1/workspaces"), ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:109", "Workspace._findMany")],
    confidence=0.95, reasoning="Lists all workspaces and their slugs.",
    description="A developer lists all workspaces.")

action(
    "dev_read_workspace", "Read workspace", "Read", "read_workspace", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "slug", "WorkspaceSlug(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug.")],
    gen=[eff(KNOW_WS, "io_reference", "Response returns the workspace config, documents and threads.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("output", "workspace / WorkspaceConfig(workspace)", "observed_only", [], "Config snapshot; not a stable reference beyond the slug.")],
    bindings=[bind(f"{_WK}/{{slug}}", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:163", "Workspace._findMany by slug")],
    confidence=0.95, reasoning="Reads one workspace by slug.",
    description="A developer reads a workspace by its slug.")

action(
    "dev_delete_workspace", "Delete workspace", "Delete", "delete_workspace", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "slug", "WorkspaceSlug(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("existence", EXISTS_WS, "Target workspace must exist.")],
    gen=[],
    kill=[eff(EXISTS_WS, "state_transition", "Workspace and its chats, vectors and documents are removed.")],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)])],
    bindings=[bind(f"{_WK}/{{slug}}", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:228", "cascade delete + delete-namespace")],
    confidence=0.9, reasoning="Deletes a workspace and cascades to its data.",
    description="A developer deletes a workspace by its slug.",
    notes="Guarded by workspaceDeletionProtection middleware.")

action(
    "dev_update_workspace", "Update workspace", "Update", "update_workspace", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "slug", "WorkspaceSlug(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("existence", EXISTS_WS, "Target workspace must exist.")],
    gen=[eff(f_state(WS_ENT, "settings", "updated"), "state_transition", "New settings applied.")],
    kill=[eff(f_state(WS_ENT, "settings", "previous"), "state_transition", "Previous settings replaced.")],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "config / WorkspaceConfig(workspace)", "object_attribute", [], "New settings values."),
                   io("output", "workspace / WorkspaceConfig(workspace)", "observed_only", [], "Echo of updated workspace.")],
    bindings=[bind(f"{_WK}/{{slug}}/update", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:279", "Workspace.update(id, data)")],
    confidence=0.95, reasoning="Updates workspace settings (incl. LLM prompt/params).",
    description="A developer updates a workspace's settings.")

_know_chats = f_know(ACTOR, reference("ChatHistory", entity("chats", "WorkspaceChat", "collection")))
action(
    "dev_read_workspace_chats", "Read workspace chats", "Read", "read_workspace_chats", "ApiCaller",
    obj("entity", "chats", "WorkspaceChat", "request", "slug", "WorkspaceSlug(workspace)", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug.")],
    gen=[eff(_know_chats, "io_reference", "Response returns the workspace chat history.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "apiSessionId / SessionID(session)", "object_attribute", [], "Optional session filter."),
                   io("output", "history / ChatHistory(chats)", "observed_only", [], "Chat content across all users of the workspace.")],
    bindings=[bind(f"{_WK}/{{slug}}/chats", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:360", "WorkspaceChats.forWorkspace")],
    confidence=0.9, reasoning="Reads all chats in the workspace regardless of user.",
    description="A developer reads a workspace's chat history.",
    notes="Returns chats for ALL users of the workspace.")

action(
    "dev_update_workspace_embeddings", "Update workspace documents", "Update", "update_workspace_embeddings", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "slug", "WorkspaceSlug(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("existence", EXISTS_WS, "Target workspace must exist.")],
    gen=[eff(f_relation(WS_ENT, DOC_ENT, "embeds"), "relation_transition", "Added documents are embedded into the workspace.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "adds / DocumentLocation(document)", "object_attribute", [], "Documents to embed."),
                   io("input", "deletes / DocumentLocation(document)", "object_attribute", [], "Documents to remove.")],
    bindings=[bind(f"{_WK}/{{slug}}/update-embeddings", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:457", "Document.addDocuments/removeDocuments")],
    confidence=0.9, reasoning="Adds/removes embedded documents in a workspace.",
    description="A developer adds or removes a workspace's embedded documents.")

action(
    "dev_pin_workspace_document", "Pin workspace document", "Update", "pin_workspace_document", "ApiCaller",
    obj("entity", "document", "Document", "request", "docPath", "DocumentLocation(document)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("knowledge", KNOW_DOC, "Caller supplies the document path."),
                  req("existence", f_exists(DOC_ENT), "Target document must exist in the workspace.")],
    gen=[eff(f_state(DOC_ENT, "pinned", "updated"), "state_transition", "Document pin status updated.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "docPath / DocumentLocation(document)", "req", [kf(KNOW_DOC)]),
                   io("input", "pinStatus", "object_attribute", [], "New pin state.")],
    bindings=[bind(f"{_WK}/{{slug}}/update-pin", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug + document path"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:534", "Document.update(id, {pinned})")],
    confidence=0.9, reasoning="Pins/unpins a document in a workspace.",
    description="A developer pins or unpins a document in a workspace.")

_know_chat_resp = f_know(ACTOR, reference("ChatResponse", entity("chat", "WorkspaceChat", "created")))
action(
    "dev_chat_with_workspace", "Chat with workspace", "Create", "chat_with_workspace", "ApiCaller",
    obj("entity", "chat", "WorkspaceChat", "request", "slug", "WorkspaceSlug(workspace)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug.")],
    gen=[eff(f_exists(entity("chat", "WorkspaceChat", "created")), "action_semantics", "A chat turn is recorded."),
         eff(_know_chat_resp, "io_reference", "Model-authored answer returned to the caller.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "message / ChatMessage(chat)", "object_attribute", [], "Untrusted user prompt to the LLM."),
                   io("input", "mode / ChatMode(chat)", "object_attribute", [], "Chat mode discriminator."),
                   io("input", "sessionId / SessionID(session)", "object_attribute", [], "External session partition id."),
                   io("input", "attachments / ChatAttachment(chat)", "object_attribute", [], "Attached images/documents."),
                   io("output", "textResponse / ChatResponse(chat)", "gen", [kf(_know_chat_resp)]),
                   io("output", "sources", "observed_only", [], "RAG sources; not a stable reference.")],
    bindings=[bind(f"{_WK}/{{slug}}/chat", ["POST"]), bind(f"{_WK}/{{slug}}/stream-chat", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:603", "ApiChatHandler.chatSync/streamChat")],
    confidence=0.9, reasoning="Untrusted prompt drives the LLM; output is model-authored.",
    description="A developer chats with a workspace (sync or streaming).",
    notes="Untrusted prompt -> LLM -> model-authored output (streaming-phase XSS to RCE via LLM response injection).")

_know_search = f_know(ACTOR, reference("SearchResults", entity("search", "VectorSearch", "target")))
action(
    "dev_vector_search_workspace", "Vector search workspace", "Read", "vector_search_workspace", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "slug", "WorkspaceSlug(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug.")],
    gen=[eff(_know_search, "io_reference", "Response returns matching document chunks.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "query / SearchQuery(search)", "object_attribute", [], "Search query."),
                   io("output", "results", "observed_only", [], "Matching chunks; not a stable reference.")],
    bindings=[bind(f"{_WK}/{{slug}}/vector-search", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspace/index.js:899", "vector similarity search")],
    confidence=0.9, reasoning="Similarity search over the workspace namespace.",
    description="A developer runs a vector similarity search in a workspace.")


# ============================================================================
# WORKSPACE THREADS
# ============================================================================
THR_ENT = entity("thread", "WorkspaceThread", "target")
THR_CREATED = entity("thread", "WorkspaceThread", "created")
KNOW_THR = f_know(ACTOR, reference("ThreadSlug", THR_ENT))
EXISTS_THR = f_exists(THR_ENT)
_TB = K("/api/v1/workspace")  # thread routes live under /workspace/{slug}/thread/...

_know_thr_created = f_know(ACTOR, reference("ThreadSlug", THR_CREATED))
action(
    "dev_create_thread", "Create thread", "Create", "create_thread", "ApiCaller",
    obj("entity", "thread", "WorkspaceThread", "response", "slug", "ThreadSlug(thread)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug.")],
    gen=[eff(f_exists(THR_CREATED), "action_semantics", "A new thread is created in the workspace."),
         eff(_know_thr_created, "io_reference", "Response returns the new thread slug.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "name / ThreadName(thread)", "object_attribute", [], "New thread name."),
                   io("output", "thread.slug / ThreadSlug(thread)", "gen", [kf(_know_thr_created)])],
    bindings=[bind(f"{_TB}/{{slug}}/thread/new", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/workspaceThread/index.js:21", "WorkspaceThread.new")],
    confidence=0.95, reasoning="Creates a thread under a workspace.",
    description="A developer creates a new thread in a workspace.")

action(
    "dev_update_thread", "Update thread", "Update", "update_thread", "ApiCaller",
    obj("entity", "thread", "WorkspaceThread", "request", "threadSlug", "ThreadSlug(thread)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("knowledge", KNOW_THR, "Caller supplies the thread slug."),
                  req("existence", EXISTS_THR, "Target thread must exist.")],
    gen=[eff(f_state(THR_ENT, "name", "updated"), "state_transition", "Thread name updated.")],
    kill=[eff(f_state(THR_ENT, "name", "previous"), "state_transition", "Previous name replaced.")],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "threadSlug / ThreadSlug(thread)", "req", [kf(KNOW_THR)]),
                   io("input", "name / ThreadName(thread)", "object_attribute", [], "New thread name.")],
    bindings=[bind(f"{_TB}/{{slug}}/thread/{{threadSlug}}/update", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace + thread slug"],
    evidence=[ev("source", "server/endpoints/api/workspaceThread/index.js:111", "WorkspaceThread.update")],
    confidence=0.9, reasoning="Renames a thread.",
    description="A developer renames a thread.")

action(
    "dev_delete_thread", "Delete thread", "Delete", "delete_thread", "ApiCaller",
    obj("entity", "thread", "WorkspaceThread", "request", "threadSlug", "ThreadSlug(thread)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("knowledge", KNOW_THR, "Caller supplies the thread slug."),
                  req("existence", EXISTS_THR, "Target thread must exist.")],
    gen=[],
    kill=[eff(EXISTS_THR, "state_transition", "Thread and its chats are removed.")],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "threadSlug / ThreadSlug(thread)", "req", [kf(KNOW_THR)])],
    bindings=[bind(f"{_TB}/{{slug}}/thread/{{threadSlug}}", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace + thread slug"],
    evidence=[ev("source", "server/endpoints/api/workspaceThread/index.js:197", "WorkspaceThread.delete")],
    confidence=0.9, reasoning="Deletes a thread.",
    description="A developer deletes a thread.")

_know_thr_chats = f_know(ACTOR, reference("ChatHistory", entity("chats", "WorkspaceThreadChat", "collection")))
action(
    "dev_read_thread_chats", "Read thread chats", "Read", "read_thread_chats", "ApiCaller",
    obj("entity", "chats", "WorkspaceThreadChat", "request", "threadSlug", "ThreadSlug(thread)", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("knowledge", KNOW_THR, "Caller supplies the thread slug.")],
    gen=[eff(_know_thr_chats, "io_reference", "Response returns the thread chat history.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "threadSlug / ThreadSlug(thread)", "req", [kf(KNOW_THR)]),
                   io("output", "history / ChatHistory(chats)", "observed_only", [], "Thread chat content.")],
    bindings=[bind(f"{_TB}/{{slug}}/thread/{{threadSlug}}/chats", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace + thread slug"],
    evidence=[ev("source", "server/endpoints/api/workspaceThread/index.js:246", "WorkspaceChats for thread")],
    confidence=0.9, reasoning="Reads a thread's chat history.",
    description="A developer reads a thread's chat history.")

_know_thr_resp = f_know(ACTOR, reference("ChatResponse", entity("chat", "WorkspaceThreadChat", "created")))
action(
    "dev_chat_in_thread", "Chat in thread", "Create", "chat_in_thread", "ApiCaller",
    obj("entity", "chat", "WorkspaceThreadChat", "request", "threadSlug", "ThreadSlug(thread)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug."),
                  req("knowledge", KNOW_THR, "Caller supplies the thread slug.")],
    gen=[eff(f_exists(entity("chat", "WorkspaceThreadChat", "created")), "action_semantics", "A chat turn is recorded in the thread."),
         eff(_know_thr_resp, "io_reference", "Model-authored answer returned to the caller.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "threadSlug / ThreadSlug(thread)", "req", [kf(KNOW_THR)]),
                   io("input", "message / ChatMessage(chat)", "object_attribute", [], "Untrusted user prompt."),
                   io("input", "mode / ChatMode(chat)", "object_attribute", [], "Chat mode discriminator."),
                   io("input", "attachments / ChatAttachment(chat)", "object_attribute", [], "Attached images/documents."),
                   io("output", "textResponse / ChatResponse(chat)", "gen", [kf(_know_thr_resp)]),
                   io("output", "sources", "observed_only", [], "RAG sources; not a stable reference.")],
    bindings=[bind(f"{_TB}/{{slug}}/thread/{{threadSlug}}/chat", ["POST"]),
              bind(f"{_TB}/{{slug}}/thread/{{threadSlug}}/stream-chat", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace + thread slug"],
    evidence=[ev("source", "server/endpoints/api/workspaceThread/index.js:330", "ApiChatHandler.chatSync/streamChat")],
    confidence=0.9, reasoning="Thread-scoped chat; untrusted prompt drives the LLM.",
    description="A developer chats within a thread (sync or streaming).",
    notes="Untrusted prompt -> LLM -> model-authored output.")


# ============================================================================
# DOCUMENTS (ingestion / storage)
# ============================================================================
FOLDER_ENT = entity("folder", "Folder", "target")
FOLDER_CREATED = entity("folder", "Folder", "created")
KNOW_FOLDER = f_know(ACTOR, reference("FolderName", FOLDER_ENT))
EXISTS_FOLDER = f_exists(FOLDER_ENT)
KNOW_DOCNAME = f_know(ACTOR, reference("DocumentName", DOC_ENT))
KNOW_GENFILE = f_know(ACTOR, reference("GeneratedFileName", entity("file", "GeneratedFile", "target")))
_know_doc_created = f_know(ACTOR, reference("DocumentLocation", entity("document", "Document", "created")))
_D = K("/api/v1/document")

action(
    "dev_upload_document", "Upload document", "Create", "upload_document", "ApiCaller",
    obj("entity", "document", "Document", "response", "documents", "DocumentLocation(document)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(entity("document", "Document", "created")), "action_semantics", "A new document is parsed and stored."),
         eff(_know_doc_created, "io_reference", "Response returns the stored document locations.")],
    kill=[],
    io_accounting=[io("input", "file / DocumentFile(document)", "object_attribute", [], "Uploaded file content."),
                   io("input", "metadata", "object_attribute", [], "Optional document metadata."),
                   io("input", "addToWorkspaces / WorkspaceSlug(workspace)", "object_attribute", [], "Target workspaces to embed into."),
                   io("output", "documents / DocumentLocation(document)", "gen", [kf(_know_doc_created)])],
    bindings=[bind(f"{_D}/upload", ["POST"]), bind(f"{_D}/upload/{{folderName}}", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Collector online"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:52", "multipart upload -> collector")],
    confidence=0.9, reasoning="Parses and stores an uploaded file.",
    description="A developer uploads a file (optionally into a folder) for parsing and embedding.")

action(
    "dev_upload_document_from_link", "Upload document from link", "Create", "upload_document_from_link", "ApiCaller",
    obj("entity", "document", "Document", "response", "documents", "DocumentLocation(document)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(entity("document", "Document", "created")), "action_semantics", "The scraped page is stored as a document."),
         eff(_know_doc_created, "io_reference", "Response returns the stored document locations.")],
    kill=[],
    io_accounting=[io("input", "link / ExternalURL(url)", "object_attribute", [], "Caller-supplied URL the server fetches (SSRF surface)."),
                   io("input", "addToWorkspaces / WorkspaceSlug(workspace)", "object_attribute", [], "Target workspaces."),
                   io("output", "documents / DocumentLocation(document)", "gen", [kf(_know_doc_created)])],
    bindings=[bind(f"{_D}/upload-link", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Collector online"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:338", "collector fetches the URL")],
    confidence=0.9, reasoning="Server fetches a caller-supplied URL to scrape.",
    description="A developer submits a URL for the server to fetch, scrape and embed.",
    notes="SSRF surface: the server-side collector fetches a caller-controlled URL.")

action(
    "dev_upload_raw_text", "Upload raw text", "Create", "upload_raw_text", "ApiCaller",
    obj("entity", "document", "Document", "response", "documents", "DocumentLocation(document)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(entity("document", "Document", "created")), "action_semantics", "A document is created from raw text."),
         eff(_know_doc_created, "io_reference", "Response returns the stored document locations.")],
    kill=[],
    io_accounting=[io("input", "textContent / DocumentText(document)", "object_attribute", [], "Raw document text."),
                   io("input", "metadata / DocumentMetadata(document)", "object_attribute", [], "Document metadata (title required)."),
                   io("output", "documents / DocumentLocation(document)", "gen", [kf(_know_doc_created)])],
    bindings=[bind(f"{_D}/raw-text", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Collector online"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:520", "raw-text -> collector")],
    confidence=0.9, reasoning="Creates a document from caller-supplied text.",
    description="A developer creates a document from raw text and metadata.")

action(
    "dev_list_documents", "List documents", "Read", "list_documents", "ApiCaller",
    obj("entity", "document", "Document", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_DOC, "io_reference", "Response returns stored document locations.")],
    kill=[],
    io_accounting=[io("input", "folder / FolderName(folder)", "object_attribute", [], "Optional folder filter."),
                   io("output", "localFiles / DocumentLocation(document)", "gen", [kf(KNOW_DOC)])],
    bindings=[bind(K("/api/v1/documents"), ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:669", "list local documents")],
    confidence=0.95, reasoning="Lists stored documents.",
    description="A developer lists locally-stored documents.")

action(
    "dev_list_folder_documents", "List folder documents", "Read", "list_folder_documents", "ApiCaller",
    obj("entity", "folder", "Folder", "request", "folderName", "FolderName(folder)", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_FOLDER, "Caller supplies the folder name.")],
    gen=[eff(KNOW_DOC, "io_reference", "Response returns the folder's document locations.")],
    kill=[],
    io_accounting=[io("input", "folderName / FolderName(folder)", "req", [kf(KNOW_FOLDER)]),
                   io("output", "documents / DocumentLocation(document)", "gen", [kf(KNOW_DOC)])],
    bindings=[bind(f"{_D}s/folder/{{folderName}}", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known folder"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:725", "list folder documents")],
    confidence=0.95, reasoning="Lists one folder's documents.",
    description="A developer lists the documents in a folder.")

_know_types = f_know(ACTOR, reference("AcceptedFileTypes", entity("upload_config", "UploadConfig", "target")))
action(
    "dev_read_accepted_file_types", "Read accepted file types", "Read", "read_accepted_file_types", "ApiCaller",
    obj("entity", "upload_config", "UploadConfig", "implicit", "", "", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_types, "io_reference", "Response lists accepted upload types.")],
    kill=[],
    io_accounting=[io("output", "types / AcceptedFileTypes", "gen", [kf(_know_types)])],
    bindings=[bind(f"{_D}/accepted-file-types", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:810", "accepted types")],
    confidence=0.95, reasoning="Reports supported upload types.",
    description="A developer reads which file types can be uploaded.")

_know_schema = f_know(ACTOR, reference("MetadataSchema", entity("metadata_schema", "MetadataSchema", "target")))
action(
    "dev_read_metadata_schema", "Read metadata schema", "Read", "read_metadata_schema", "ApiCaller",
    obj("entity", "metadata_schema", "MetadataSchema", "implicit", "", "", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_schema, "io_reference", "Response returns the raw-text metadata schema.")],
    kill=[],
    io_accounting=[io("output", "schema / MetadataSchema", "gen", [kf(_know_schema)])],
    bindings=[bind(f"{_D}/metadata-schema", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:867", "metadata schema")],
    confidence=0.95, reasoning="Reports the metadata schema.",
    description="A developer reads the accepted metadata schema for raw-text uploads.")

action(
    "dev_read_document", "Read document", "Read", "read_document", "ApiCaller",
    obj("entity", "document", "Document", "request", "docName", "DocumentName(document)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_DOCNAME, "Caller supplies the document name.")],
    gen=[eff(KNOW_DOCNAME, "io_reference", "Response returns the document record.")],
    kill=[],
    io_accounting=[io("input", "docName / DocumentName(document)", "req", [kf(KNOW_DOCNAME)]),
                   io("output", "document", "observed_only", [], "Document record content.")],
    bindings=[bind(f"{_D}/{{docName}}", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known document name"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:919", "get single document")],
    confidence=0.95, reasoning="Reads one document by name.",
    description="A developer reads a single document by its name.")

action(
    "dev_create_folder", "Create folder", "Create", "create_folder", "ApiCaller",
    obj("entity", "folder", "Folder", "request", "name", "FolderName(folder)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(FOLDER_CREATED), "action_semantics", "A new storage folder is created.")],
    kill=[],
    io_accounting=[io("input", "name / FolderName(folder)", "object_attribute", [], "New folder name.")],
    bindings=[bind(f"{_D}/create-folder", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:974", "create folder")],
    confidence=0.95, reasoning="Creates a storage folder.",
    description="A developer creates a documents storage folder.")

action(
    "dev_remove_folder", "Remove folder", "Delete", "remove_folder", "ApiCaller",
    obj("entity", "folder", "Folder", "request", "name", "FolderName(folder)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_FOLDER, "Caller supplies the folder name."),
                  req("existence", EXISTS_FOLDER, "Target folder must exist.")],
    gen=[],
    kill=[eff(EXISTS_FOLDER, "state_transition", "Folder and all its contents are removed.")],
    io_accounting=[io("input", "name / FolderName(folder)", "req", [kf(KNOW_FOLDER)])],
    bindings=[bind(f"{_D}/remove-folder", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known folder"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:1048", "remove folder + contents")],
    confidence=0.9, reasoning="Deletes a folder and its contents.",
    description="A developer removes a folder and all its documents.")

action(
    "dev_move_files", "Move documents", "Update", "move_files", "ApiCaller",
    obj("entity", "document", "Document", "request", "files", "DocumentLocation(document)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_DOC, "Caller supplies the document from/to paths.")],
    gen=[eff(f_state(DOC_ENT, "location", "updated"), "state_transition", "Documents moved to new storage locations.")],
    kill=[eff(f_state(DOC_ENT, "location", "previous"), "state_transition", "Previous locations no longer hold.")],
    io_accounting=[io("input", "files / DocumentLocation(document)", "req", [kf(KNOW_DOC)])],
    bindings=[bind(f"{_D}/move-files", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known document paths"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:1107", "move files (traversal-guarded)")],
    confidence=0.9, reasoning="Moves documents between folders; destinations validated.",
    description="A developer moves documents within storage.")

_know_genfile = f_know(ACTOR, reference("GeneratedFile", entity("file", "GeneratedFile", "target")))
action(
    "dev_download_generated_file", "Download generated file", "Read", "download_generated_file", "ApiCaller",
    obj("entity", "file", "GeneratedFile", "request", "filename", "GeneratedFileName(file)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_GENFILE, "Caller supplies the generated file name.")],
    gen=[eff(_know_genfile, "io_reference", "Response streams the generated file bytes.")],
    kill=[],
    io_accounting=[io("input", "filename / GeneratedFileName(file)", "req", [kf(KNOW_GENFILE)]),
                   io("output", "(file bytes)", "observed_only", [], "Binary file content.")],
    bindings=[bind(f"{_D}/generated-files/{{filename}}", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known generated filename"],
    evidence=[ev("source", "server/endpoints/api/document/index.js:1219", "download generated file")],
    confidence=0.9, reasoning="Downloads an agent-generated file by name; format validated.",
    description="A developer downloads an agent-generated file by its storage filename.",
    notes="Filename is format-validated to reject path traversal.")


# ============================================================================
# OpenAI-compatible API
# ============================================================================
_OAI = K("/api/v1/openai")

action(
    "dev_openai_list_models", "List OpenAI models", "Read", "openai_list_models", "ApiCaller",
    obj("entity", "workspace", "Workspace", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_WS, "io_reference", "Response lists workspace slugs as OpenAI models.")],
    kill=[],
    io_accounting=[io("output", "data[].id / WorkspaceSlug(workspace)", "gen", [kf(KNOW_WS)])],
    bindings=[bind(f"{_OAI}/models", ["GET"])],
    vis="black_box", vis_reason="Documented OpenAI-compatible endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/openai/index.js:19", "workspaces as models")],
    confidence=0.95, reasoning="Lists workspaces as OpenAI models.",
    description="A developer lists workspaces exposed as OpenAI models.")

_know_oai_resp = f_know(ACTOR, reference("ChatResponse", entity("chat", "OpenAIChat", "created")))
action(
    "dev_openai_chat_completion", "OpenAI chat completion", "Create", "openai_chat_completion", "ApiCaller",
    obj("entity", "chat", "OpenAIChat", "request", "model", "WorkspaceSlug(workspace)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug as the model.")],
    gen=[eff(f_exists(entity("chat", "OpenAIChat", "created")), "action_semantics", "A chat turn is recorded."),
         eff(_know_oai_resp, "io_reference", "Model-authored completion returned.")],
    kill=[],
    io_accounting=[io("input", "model / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "messages / ChatMessage(chat)", "object_attribute", [], "Untrusted chat messages."),
                   io("output", "choices / ChatResponse(chat)", "gen", [kf(_know_oai_resp)])],
    bindings=[bind(f"{_OAI}/chat/completions", ["POST"])],
    vis="black_box", vis_reason="Documented OpenAI-compatible endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/openai/index.js:76", "OpenAI-compatible chat")],
    confidence=0.9, reasoning="OpenAI-compatible chat over a workspace; untrusted messages drive the LLM.",
    description="A developer runs an OpenAI-compatible chat completion against a workspace.",
    notes="Untrusted messages -> LLM -> model-authored output.")

_know_image = f_know(ACTOR, reference("GeneratedImage", entity("image", "GeneratedImage", "created")))
action(
    "dev_openai_generate_image", "Generate image", "Create", "openai_generate_image", "ApiCaller",
    obj("entity", "image", "GeneratedImage", "response", "data", "GeneratedImage(image)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(entity("image", "GeneratedImage", "created")), "action_semantics", "An image is generated."),
         eff(_know_image, "io_reference", "Generated image returned as base64.")],
    kill=[],
    io_accounting=[io("input", "prompt / ImagePrompt(image)", "object_attribute", [], "Image prompt."),
                   io("input", "image_references / ImageReference(image)", "object_attribute", [], "Reference images for editing."),
                   io("output", "data / GeneratedImage(image)", "gen", [kf(_know_image)])],
    bindings=[bind(f"{_OAI}/images/generations", ["POST"])],
    vis="black_box", vis_reason="Documented OpenAI-compatible endpoint.", reachable=True, reach_conds=["Valid instance API key", "Image provider configured"],
    evidence=[ev("source", "server/endpoints/api/openai/index.js:195", "image generation/editing")],
    confidence=0.9, reasoning="Generates/edits an image via the configured provider.",
    description="A developer generates or edits an image.")

_know_embed = f_know(ACTOR, reference("Embedding", entity("text", "EmbedResult", "target")))
action(
    "dev_openai_embeddings", "OpenAI embeddings", "Read", "openai_embeddings", "ApiCaller",
    obj("entity", "text", "EmbedResult", "request", "input", "EmbedInput(text)", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_embed, "io_reference", "Response returns embedding vectors for the input.")],
    kill=[],
    io_accounting=[io("input", "input / EmbedInput(text)", "object_attribute", [], "Text(s) to embed."),
                   io("output", "data / Embedding(text)", "gen", [kf(_know_embed)])],
    bindings=[bind(f"{_OAI}/embeddings", ["POST"])],
    vis="black_box", vis_reason="Documented OpenAI-compatible endpoint.", reachable=True, reach_conds=["Valid instance API key", "Embedder configured"],
    evidence=[ev("source", "server/endpoints/api/openai/index.js:290", "Embedder.embedChunks")],
    confidence=0.9, reasoning="Embeds caller-supplied text with the system embedder.",
    description="A developer gets embeddings for arbitrary text.")

action(
    "dev_openai_list_vector_stores", "List vector stores", "Read", "openai_list_vector_stores", "ApiCaller",
    obj("entity", "workspace", "Workspace", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_WS, "io_reference", "Response lists workspace slugs as vector stores.")],
    kill=[],
    io_accounting=[io("output", "data[].id / WorkspaceSlug(workspace)", "gen", [kf(KNOW_WS)])],
    bindings=[bind(f"{_OAI}/vector_stores", ["GET"])],
    vis="black_box", vis_reason="Documented OpenAI-compatible endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/openai/index.js:357", "workspaces as vector stores")],
    confidence=0.95, reasoning="Lists workspaces as vector stores.",
    description="A developer lists workspaces exposed as vector stores.")


# ============================================================================
# USER MANAGEMENT / ADMIN / EMBEDS / MCP SERVERS
# ============================================================================
USER_ENT = entity("user", "User", "target")
USER_CREATED = entity("user", "User", "created")
KNOW_USERID = f_know(ACTOR, reference("UserID", USER_ENT))
KNOW_USERNAME = f_know(ACTOR, reference("Username", USER_ENT))
EXISTS_USER = f_exists(USER_ENT)
INVITE_ENT = entity("invite", "Invite", "target")
KNOW_INVITEID = f_know(ACTOR, reference("InviteID", INVITE_ENT))
EXISTS_INVITE = f_exists(INVITE_ENT)
KNOW_WSID = f_know(ACTOR, reference("WorkspaceID", WS_ENT))
EMBED_ENT = entity("embed", "Embed", "target")
KNOW_EMBED = f_know(ACTOR, reference("EmbedUUID", EMBED_ENT))
EXISTS_EMBED = f_exists(EMBED_ENT)
MCP_ENT = entity("server", "MCPServer", "target")
KNOW_MCP = f_know(ACTOR, reference("MCPServerName", MCP_ENT))
EXISTS_MCP = f_exists(MCP_ENT)
_UU = K("/api/v1/users")
_AD = K("/api/v1/admin")
_EM = K("/api/v1/embed")
_MC = K("/api/v1/mcp-servers")

# ---- User Management ----
action(
    "dev_list_users_simple", "List users", "Read", "list_users", "ApiCaller",
    obj("entity", "user", "User", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_USERNAME, "io_reference", "Response lists usernames.")], kill=[],
    io_accounting=[io("output", "users[].username / Username(user)", "gen", [kf(KNOW_USERNAME)])],
    bindings=[bind(_UU, ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/userManagement/index.js:12", "list users")],
    confidence=0.9, reasoning="Lists all users.", description="A developer lists all users.", notes="Requires multi-user mode.")

_know_token = f_know(ACTOR, reference("AuthToken", entity("token", "AuthToken", "created")))
action(
    "dev_issue_user_auth_token", "Issue user auth token", "Create", "issue_user_auth_token", "ApiCaller",
    obj("entity", "token", "AuthToken", "response", "token", "AuthToken(session)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_USERID, "Caller supplies the target user id.")],
    gen=[eff(f_exists(entity("token", "AuthToken", "created")), "action_semantics", "A temporary login token is issued."),
         eff(_know_token, "io_reference", "Response returns the token.")], kill=[],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(KNOW_USERID)]),
                   io("output", "token / AuthToken(session)", "gen", [kf(_know_token)])],
    bindings=[bind(f"{_UU}/{{id}}/issue-auth-token", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/userManagement/index.js:68", "issue temp auth token")],
    confidence=0.9, reasoning="Issues a login token for an arbitrary user (impersonation).",
    description="A developer issues a temporary login token for a user.",
    notes="Impersonation surface: mints a login token for ANY user id.")

# ---- Admin ----
_know_mum = f_know(ACTOR, reference("MultiUserMode", entity("system", "System", "target")))
action(
    "dev_check_multi_user_mode", "Check multi-user mode", "Read", "check_multi_user_mode", "ApiCaller",
    obj("entity", "system", "System", "implicit", "", "", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_mum, "io_reference", "Response reports multi-user mode status.")], kill=[],
    io_accounting=[],
    bindings=[bind(f"{_AD}/is-multi-user-mode", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:15", "multi-user mode flag")],
    confidence=0.95, reasoning="Reports instance mode.", description="A developer checks if multi-user mode is enabled.")

action(
    "dev_admin_list_users", "Admin list users", "Read", "admin_list_users", "ApiCaller",
    obj("entity", "user", "User", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_USERNAME, "io_reference", "Response lists usernames.")], kill=[],
    io_accounting=[io("output", "users[].username / Username(user)", "gen", [kf(KNOW_USERNAME)])],
    bindings=[bind(f"{_AD}/users", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:41", "admin list users")],
    confidence=0.9, reasoning="Admin user list.", description="An admin lists all users.", notes="Requires multi-user mode.")

action(
    "dev_admin_create_user", "Admin create user", "Create", "admin_create_user", "ApiCaller",
    obj("entity", "user", "User", "request", "username", "Username(user)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(USER_CREATED), "action_semantics", "A new user is created.")], kill=[],
    io_accounting=[io("input", "username / Username(user)", "object_attribute", [], "New username."),
                   io("input", "password / Password(user)", "object_attribute", [], "New password (credential)."),
                   io("input", "role / UserRole(user)", "object_attribute", [], "User role.")],
    bindings=[bind(f"{_AD}/users/new", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:85", "create user")],
    confidence=0.9, reasoning="Creates a user with a role.", description="An admin creates a user.", notes="Requires multi-user mode.")

action(
    "dev_admin_update_user", "Admin update user", "Update", "admin_update_user", "ApiCaller",
    obj("entity", "user", "User", "request", "id", "UserID(user)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_USERID, "Caller supplies the user id."),
                  req("existence", EXISTS_USER, "Target user must exist.")],
    gen=[eff(f_state(USER_ENT, "settings", "updated"), "state_transition", "User settings/role updated.")],
    kill=[eff(f_state(USER_ENT, "settings", "previous"), "state_transition", "Previous settings replaced.")],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(KNOW_USERID)]),
                   io("input", "role / UserRole(user)", "object_attribute", [], "New role/settings.")],
    bindings=[bind(f"{_AD}/users/{{id}}", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:143", "update user")],
    confidence=0.9, reasoning="Updates a user (incl. role escalation surface).", description="An admin updates a user's settings/role.")

action(
    "dev_admin_delete_user", "Admin delete user", "Delete", "admin_delete_user", "ApiCaller",
    obj("entity", "user", "User", "request", "id", "UserID(user)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_USERID, "Caller supplies the user id."),
                  req("existence", EXISTS_USER, "Target user must exist.")],
    gen=[], kill=[eff(EXISTS_USER, "state_transition", "User removed.")],
    io_accounting=[io("input", "id / UserID(user)", "req", [kf(KNOW_USERID)])],
    bindings=[bind(f"{_AD}/users/{{id}}", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:216", "delete user")],
    confidence=0.9, reasoning="Deletes a user.", description="An admin deletes a user.")

_know_invcode = f_know(ACTOR, reference("InviteCode", entity("invite", "Invite", "created")))
action(
    "dev_admin_list_invites", "Admin list invites", "Read", "admin_list_invites", "ApiCaller",
    obj("entity", "invite", "Invite", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_know(ACTOR, reference("InviteCode", INVITE_ENT)), "io_reference", "Response lists invite codes.")], kill=[],
    io_accounting=[io("output", "invites[].code / InviteCode(invite)", "gen", [kf(f_know(ACTOR, reference("InviteCode", INVITE_ENT)))])],
    bindings=[bind(f"{_AD}/invites", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:270", "list invites")],
    confidence=0.9, reasoning="Lists invite codes.", description="An admin lists all invites.")

action(
    "dev_admin_create_invite", "Admin create invite", "Create", "admin_create_invite", "ApiCaller",
    obj("entity", "invite", "Invite", "response", "code", "InviteCode(invite)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(entity("invite", "Invite", "created")), "action_semantics", "A new invite is created."),
         eff(_know_invcode, "io_reference", "Response returns the invite code.")], kill=[],
    io_accounting=[io("input", "workspaceIds", "object_attribute", [], "Workspaces to auto-add the invitee to."),
                   io("output", "invite.code / InviteCode(invite)", "gen", [kf(_know_invcode)])],
    bindings=[bind(f"{_AD}/invite/new", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:316", "create invite")],
    confidence=0.9, reasoning="Mints an invite code.", description="An admin creates an invite code.")

action(
    "dev_admin_delete_invite", "Admin delete invite", "Delete", "admin_delete_invite", "ApiCaller",
    obj("entity", "invite", "Invite", "request", "id", "InviteID(invite)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_INVITEID, "Caller supplies the invite id."),
                  req("existence", EXISTS_INVITE, "Target invite must exist.")],
    gen=[], kill=[eff(EXISTS_INVITE, "state_transition", "Invite deactivated.")],
    io_accounting=[io("input", "id / InviteID(invite)", "req", [kf(KNOW_INVITEID)])],
    bindings=[bind(f"{_AD}/invite/{{id}}", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:375", "deactivate invite")],
    confidence=0.9, reasoning="Deactivates an invite.", description="An admin deactivates an invite.")

action(
    "dev_admin_list_workspace_users", "Admin list workspace users", "Read", "admin_list_workspace_users", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "workspaceId", "WorkspaceID(workspace)", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WSID, "Caller supplies the workspace id.")],
    gen=[eff(KNOW_USERNAME, "io_reference", "Response lists the workspace's users.")], kill=[],
    io_accounting=[io("input", "workspaceId / WorkspaceID(workspace)", "req", [kf(KNOW_WSID)]),
                   io("output", "users[].username / Username(user)", "gen", [kf(KNOW_USERNAME)])],
    bindings=[bind(f"{_AD}/workspaces/{{workspaceId}}/users", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:442", "workspace users")],
    confidence=0.9, reasoning="Lists a workspace's authorized users.", description="An admin lists the users who can access a workspace.")

action(
    "dev_admin_overwrite_workspace_users", "Admin overwrite workspace users", "Update", "admin_overwrite_workspace_users", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "workspaceId", "WorkspaceID(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WSID, "Caller supplies the workspace id.")],
    gen=[eff(f_relation(WS_ENT, USER_ENT, "access"), "relation_transition", "Workspace access list overwritten to the given users.")],
    kill=[],
    io_accounting=[io("input", "workspaceId / WorkspaceID(workspace)", "req", [kf(KNOW_WSID)]),
                   io("input", "userIds / UserID(user)", "object_attribute", [], "Users granted access.")],
    bindings=[bind(f"{_AD}/workspaces/{{workspaceId}}/update-users", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:497", "overwrite workspace perms")],
    confidence=0.9, reasoning="Overwrites workspace access control.", description="An admin overwrites a workspace's access list.")

action(
    "dev_admin_manage_workspace_users", "Admin manage workspace users", "Update", "admin_manage_workspace_users", "ApiCaller",
    obj("entity", "workspace", "Workspace", "request", "slug", "WorkspaceSlug(workspace)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug.")],
    gen=[eff(f_relation(WS_ENT, USER_ENT, "access"), "relation_transition", "Workspace access list set to the given users.")],
    kill=[],
    io_accounting=[io("input", "slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "userIds / UserID(user)", "object_attribute", [], "Users granted access.")],
    bindings=[bind(f"{_AD}/workspaces/{{workspaceSlug}}/manage-users", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:564", "set workspace perms")],
    confidence=0.9, reasoning="Sets workspace access control by slug.", description="An admin sets a workspace's access list.")

_know_syschats = f_know(ACTOR, reference("ChatHistory", entity("chats", "SystemChat", "collection")))
action(
    "dev_admin_read_workspace_chats", "Admin read all chats", "Read", "admin_read_workspace_chats", "ApiCaller",
    obj("entity", "chats", "SystemChat", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(_know_syschats, "io_reference", "Response returns all chats across the instance.")], kill=[],
    io_accounting=[io("output", "chats / ChatHistory(system)", "observed_only", [], "All chats across every workspace and user.")],
    bindings=[bind(f"{_AD}/workspace-chats", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:679", "all system chats")],
    confidence=0.9, reasoning="Reads every chat in the instance.", description="An admin reads all chats across the instance.",
    notes="Instance-wide chat data exposure.")

action(
    "dev_admin_update_preferences", "Admin update preferences", "Update", "admin_update_preferences", "ApiCaller",
    obj("entity", "system_config", "SystemConfig", "request", "preferences", "SystemSettings(system)"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_state(entity("system_config", "SystemConfig", "target"), "preferences", "updated"), "state_transition", "Multi-user preferences applied.")],
    kill=[eff(f_state(entity("system_config", "SystemConfig", "target"), "preferences", "previous"), "state_transition", "Previous preferences replaced.")],
    io_accounting=[io("input", "preferences / SystemSettings(system)", "object_attribute", [], "Preference values.")],
    bindings=[bind(f"{_AD}/preferences", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Multi-user mode"],
    evidence=[ev("source", "server/endpoints/api/admin/index.js:735", "update preferences")],
    confidence=0.9, reasoning="Updates multi-user preferences.", description="An admin updates multi-user preferences.")

# ---- Embeds ----
action(
    "dev_list_embeds", "List embeds", "Read", "list_embeds", "ApiCaller",
    obj("entity", "embed", "Embed", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_EMBED, "io_reference", "Response lists embed uuids.")], kill=[],
    io_accounting=[io("output", "embeds[].uuid / EmbedUUID(embed)", "gen", [kf(KNOW_EMBED)])],
    bindings=[bind(_EM, ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/embed/index.js:10", "list embeds")],
    confidence=0.95, reasoning="Lists embed widgets.", description="A developer lists active embed widgets.")

_know_embed_chats = f_know(ACTOR, reference("ChatHistory", entity("chats", "EmbedChat", "collection")))
action(
    "dev_read_embed_chats", "Read embed chats", "Read", "read_embed_chats", "ApiCaller",
    obj("entity", "embed", "Embed", "request", "embedUuid", "EmbedUUID(embed)", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_EMBED, "Caller supplies the embed uuid.")],
    gen=[eff(_know_embed_chats, "io_reference", "Response returns the embed's chats.")], kill=[],
    io_accounting=[io("input", "embedUuid / EmbedUUID(embed)", "req", [kf(KNOW_EMBED)]),
                   io("output", "chats / ChatHistory(embed)", "observed_only", [], "Embed chat content.")],
    bindings=[bind(f"{_EM}/{{embedUuid}}/chats", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known embed uuid"],
    evidence=[ev("source", "server/endpoints/api/embed/index.js:79", "embed chats")],
    confidence=0.9, reasoning="Reads an embed's chats.", description="A developer reads all chats for an embed.")

_know_sessuuid = f_know(ACTOR, reference("SessionUUID", entity("session", "EmbedSession", "target")))
action(
    "dev_read_embed_session_chats", "Read embed session chats", "Read", "read_embed_session_chats", "ApiCaller",
    obj("entity", "embed", "Embed", "request", "embedUuid", "EmbedUUID(embed)", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_EMBED, "Caller supplies the embed uuid."),
                  req("knowledge", _know_sessuuid, "Caller supplies the session uuid.")],
    gen=[eff(_know_embed_chats, "io_reference", "Response returns the embed session's chats.")], kill=[],
    io_accounting=[io("input", "embedUuid / EmbedUUID(embed)", "req", [kf(KNOW_EMBED)]),
                   io("input", "sessionUuid / SessionUUID(session)", "req", [kf(_know_sessuuid)]),
                   io("output", "chats / ChatHistory(embed)", "observed_only", [], "Embed session chat content.")],
    bindings=[bind(f"{_EM}/{{embedUuid}}/chats/{{sessionUuid}}", ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known embed + session uuid"],
    evidence=[ev("source", "server/endpoints/api/embed/index.js:141", "embed session chats")],
    confidence=0.9, reasoning="Reads one embed session's chats.", description="A developer reads an embed session's chats.")

_know_embed_created = f_know(ACTOR, reference("EmbedUUID", entity("embed", "Embed", "created")))
action(
    "dev_create_embed", "Create embed", "Create", "create_embed", "ApiCaller",
    obj("entity", "embed", "Embed", "response", "uuid", "EmbedUUID(embed)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_WS, "Caller supplies the workspace slug the embed serves.")],
    gen=[eff(f_exists(entity("embed", "Embed", "created")), "action_semantics", "A public embed widget is created."),
         eff(_know_embed_created, "io_reference", "Response returns the embed uuid.")], kill=[],
    io_accounting=[io("input", "workspace_slug / WorkspaceSlug(workspace)", "req", [kf(KNOW_WS)]),
                   io("input", "config / EmbedConfig(embed)", "object_attribute", [], "Embed config (allowlist/prompt-override)."),
                   io("output", "embed.uuid / EmbedUUID(embed)", "gen", [kf(_know_embed_created)])],
    bindings=[bind(f"{_EM}/new", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known workspace slug"],
    evidence=[ev("source", "server/endpoints/api/embed/index.js:201", "create embed")],
    confidence=0.9, reasoning="Creates a public chat widget bound to a workspace.",
    description="A developer creates a public embed chat widget.",
    notes="Public exposure surface: allowlist_domains / allow_prompt_override govern who/what can drive the widget.")

action(
    "dev_update_embed", "Update embed", "Update", "update_embed", "ApiCaller",
    obj("entity", "embed", "Embed", "request", "embedUuid", "EmbedUUID(embed)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_EMBED, "Caller supplies the embed uuid."),
                  req("existence", EXISTS_EMBED, "Target embed must exist.")],
    gen=[eff(f_state(EMBED_ENT, "config", "updated"), "state_transition", "Embed config updated.")],
    kill=[eff(f_state(EMBED_ENT, "config", "previous"), "state_transition", "Previous config replaced.")],
    io_accounting=[io("input", "embedUuid / EmbedUUID(embed)", "req", [kf(KNOW_EMBED)]),
                   io("input", "config / EmbedConfig(embed)", "object_attribute", [], "Updated embed config.")],
    bindings=[bind(f"{_EM}/{{embedUuid}}", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known embed uuid"],
    evidence=[ev("source", "server/endpoints/api/embed/index.js:287", "update embed")],
    confidence=0.9, reasoning="Updates an embed widget's config.", description="A developer updates an embed widget.")

action(
    "dev_delete_embed", "Delete embed", "Delete", "delete_embed", "ApiCaller",
    obj("entity", "embed", "Embed", "request", "embedUuid", "EmbedUUID(embed)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_EMBED, "Caller supplies the embed uuid."),
                  req("existence", EXISTS_EMBED, "Target embed must exist.")],
    gen=[], kill=[eff(EXISTS_EMBED, "state_transition", "Embed removed.")],
    io_accounting=[io("input", "embedUuid / EmbedUUID(embed)", "req", [kf(KNOW_EMBED)])],
    bindings=[bind(f"{_EM}/{{embedUuid}}", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known embed uuid"],
    evidence=[ev("source", "server/endpoints/api/embed/index.js:358", "delete embed")],
    confidence=0.9, reasoning="Deletes an embed widget.", description="A developer deletes an embed widget.")

# ---- MCP Servers ----
action(
    "dev_list_mcp_servers", "List MCP servers", "Read", "list_mcp_servers", "ApiCaller",
    obj("entity", "server", "MCPServer", "implicit", "", "", role="collection"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(KNOW_MCP, "io_reference", "Response lists MCP server names.")], kill=[],
    io_accounting=[io("output", "servers[].name / MCPServerName(server)", "gen", [kf(KNOW_MCP)])],
    bindings=[bind(_MC, ["GET"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:8", "list MCP servers")],
    confidence=0.95, reasoning="Lists MCP servers.", description="A developer lists MCP servers.")

action(
    "dev_add_mcp_server", "Add MCP server", "Create", "add_mcp_server", "ApiCaller",
    obj("entity", "server", "MCPServer", "request", "name", "MCPServerName(server)", role="created"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_exists(entity("server", "MCPServer", "created")), "action_semantics", "A new MCP server is registered and started.")], kill=[],
    io_accounting=[io("input", "name / MCPServerName(server)", "object_attribute", [], "MCP server name."),
                   io("input", "config / MCPConfig(server)", "object_attribute", [], "MCP config (command executed / URL contacted).")],
    bindings=[bind(f"{_MC}/new", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:48", "add + start MCP server")],
    confidence=0.9, reasoning="Registers an MCP server whose config can execute a command.",
    description="A developer adds and starts an MCP server.",
    notes="MCP config can define a local command -> code execution / agent tool surface.")

action(
    "dev_reload_mcp_servers", "Reload MCP servers", "Update", "reload_mcp_servers", "ApiCaller",
    obj("entity", "mcp_runtime", "MCPRuntime", "implicit", "", "", role="target"),
    requirements=[req("authentication", AUTH_API, "validApiKey.")],
    gen=[eff(f_state(entity("mcp_runtime", "MCPRuntime", "target"), "servers", "reloaded"), "state_transition", "All MCP servers restarted.")],
    kill=[],
    io_accounting=[],
    bindings=[bind(f"{_MC}/reload", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:108", "reload MCP servers")],
    confidence=0.9, reasoning="Restarts all MCP servers.", description="A developer reloads all MCP servers.")

action(
    "dev_update_mcp_server", "Update MCP server", "Update", "update_mcp_server", "ApiCaller",
    obj("entity", "server", "MCPServer", "request", "name", "MCPServerName(server)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_MCP, "Caller supplies the MCP server name."),
                  req("existence", EXISTS_MCP, "Target server must exist.")],
    gen=[eff(f_state(MCP_ENT, "config", "updated"), "state_transition", "MCP server config replaced and restarted.")],
    kill=[eff(f_state(MCP_ENT, "config", "previous"), "state_transition", "Previous config replaced.")],
    io_accounting=[io("input", "name / MCPServerName(server)", "req", [kf(KNOW_MCP)]),
                   io("input", "config / MCPConfig(server)", "object_attribute", [], "Replacement config.")],
    bindings=[bind(f"{_MC}/{{name}}/update", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known server name"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:139", "replace MCP server")],
    confidence=0.9, reasoning="Replaces an MCP server definition.", description="A developer replaces an MCP server's config.")

action(
    "dev_toggle_mcp_server", "Toggle MCP server", "Update", "toggle_mcp_server", "ApiCaller",
    obj("entity", "server", "MCPServer", "request", "name", "MCPServerName(server)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_MCP, "Caller supplies the MCP server name."),
                  req("existence", EXISTS_MCP, "Target server must exist.")],
    gen=[eff(f_state(MCP_ENT, "running", "toggled"), "state_transition", "MCP server started/stopped.")],
    kill=[],
    io_accounting=[io("input", "name / MCPServerName(server)", "req", [kf(KNOW_MCP)])],
    bindings=[bind(f"{_MC}/{{name}}/toggle", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known server name"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:209", "toggle MCP server")],
    confidence=0.9, reasoning="Starts/stops an MCP server.", description="A developer starts or stops an MCP server.")

_know_toolname = f_know(ACTOR, reference("ToolName", entity("tool", "MCPTool", "target")))
action(
    "dev_toggle_mcp_tool", "Toggle MCP tool", "Update", "toggle_mcp_tool", "ApiCaller",
    obj("entity", "server", "MCPServer", "request", "name", "MCPServerName(server)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_MCP, "Caller supplies the MCP server name."),
                  req("knowledge", _know_toolname, "Caller supplies the tool name."),
                  req("existence", EXISTS_MCP, "Target server must exist.")],
    gen=[eff(f_state(entity("tool", "MCPTool", "target"), "enabled", "toggled"), "state_transition", "MCP tool enabled/disabled for agents.")],
    kill=[],
    io_accounting=[io("input", "name / MCPServerName(server)", "req", [kf(KNOW_MCP)]),
                   io("input", "toolName / ToolName(tool)", "req", [kf(_know_toolname)]),
                   io("input", "enabled", "object_attribute", [], "Enable flag.")],
    bindings=[bind(f"{_MC}/{{name}}/toggle-tool", ["POST"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known server + tool name"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:252", "toggle MCP tool")],
    confidence=0.9, reasoning="Enables/disables one MCP tool for agents.",
    description="A developer enables or disables a single MCP tool.",
    notes="Controls which MCP tools are exposed to agents (agent tool-surface control).")

action(
    "dev_delete_mcp_server", "Delete MCP server", "Delete", "delete_mcp_server", "ApiCaller",
    obj("entity", "server", "MCPServer", "request", "name", "MCPServerName(server)"),
    requirements=[req("authentication", AUTH_API, "validApiKey."),
                  req("knowledge", KNOW_MCP, "Caller supplies the MCP server name."),
                  req("existence", EXISTS_MCP, "Target server must exist.")],
    gen=[], kill=[eff(EXISTS_MCP, "state_transition", "MCP server stopped and removed.")],
    io_accounting=[io("input", "name / MCPServerName(server)", "req", [kf(KNOW_MCP)])],
    bindings=[bind(f"{_MC}/{{name}}", ["DELETE"])],
    vis="black_box", vis_reason="Documented developer endpoint.", reachable=True, reach_conds=["Valid instance API key", "Known server name"],
    evidence=[ev("source", "server/endpoints/api/mcpServers/index.js:322", "remove MCP server")],
    confidence=0.9, reasoning="Removes an MCP server.", description="A developer stops and removes an MCP server.")
