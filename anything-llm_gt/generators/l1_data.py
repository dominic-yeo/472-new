# -*- coding: utf-8 -*-
"""AnythingLLM Developer API (/api/v1) L1 inventory -- data table.

Module: System Settings + Authentication.
Source-first: enumerated from server/endpoints/api/{auth,system}/index.js (Express
routes mounted under app.use("/api", apiRouter); inline #swagger blocks document the
request/response contracts). validApiKey = instance-level API key (Bearer header).
No runtime capture available in this environment (no Docker/network); samples=[],
black_box_reachable derived from source gating. See environment.yaml.

Builds: API_NODES (kind=api, io_variants -> L2 candidates), PAGE_NODES, EDGES.
"""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, resp_raw, dec, ev

# identity -> observed/derived status codes (API key present+valid vs absent/invalid)
ST_KEYED = {"anonymous": [403], "api_key": [200]}
SRC = "server/endpoints/api"

API_NODES = []

# ---- Authentication --------------------------------------------------------
API_NODES.append(node(
    K("/api/v1/auth"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("authenticated", "boolean", False, "True when the Authorization API key is valid.")]),
        reason="validApiKey middleware verifies the Bearer API key; body is a fixed status flag.",
        evidence=f"{SRC}/auth/index.js:6")],
    operation_semantic="verify_api_key", statuses=[200, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Authentication').",
    evidence=[ev("source", f"{SRC}/auth/index.js:6", "GET /v1/auth [validApiKey] -> {authenticated:true}")],
    notes="API-key probe; the status flag is not business data (flow=false)."))

# ---- System Settings -------------------------------------------------------
API_NODES.append(node(
    K("/api/v1/system/env-dump"), "api", ["GET"],
    variants=[variant("GET", response=resp_empty(),
        reason="Side-effecting GET: flushes in-memory settings to the .env file in production; no IO body.",
        evidence=f"{SRC}/system/index.js:18")],
    operation_semantic="dump_settings_to_env_file", statuses=[200, 500],
    identity_statuses={"anonymous": [200]}, route_confirmed=True,
    vis_reason="Intentionally unauthenticated deploy/shutdown hook (see SECURITY.md).",
    evidence=[ev("source", f"{SRC}/system/index.js:16", "GET /v1/system/env-dump (no auth) -> dumpENV() in production")],
    notes="UNAUTHENTICATED by design: any caller triggers a settings flush to .env (prod only)."))

API_NODES.append(node(
    K("/api/v1/system"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("settings", "object", True, "All defined system settings (secret values masked to presence booleans).")]),
        reason="Returns SystemSettings.currentSettings(); secrets appear as booleans, config values in clear.",
        evidence=f"{SRC}/system/index.js:39")],
    operation_semantic="read_system_settings", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[dec("settings", "SystemSettings(system)", "content", mergeable=True,
                           reason="Full instance configuration snapshot (provider, vector DB, flags; secret presence).")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'System Settings').",
    evidence=[ev("source", f"{SRC}/system/index.js:39", "GET /v1/system [validApiKey] -> {settings}")],
    notes="Exposes instance configuration incl. which provider keys are set (presence booleans)."))

API_NODES.append(node(
    K("/api/v1/system/vector-count"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([
        of("vectorCount", "integer", True, "Total vectors across the connected vector database.")]),
        reason="Returns VectorDb.totalVectors().", evidence=f"{SRC}/system/index.js:76")],
    operation_semantic="read_vector_count", statuses=[200, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'System Settings').",
    evidence=[ev("source", f"{SRC}/system/index.js:76", "GET /v1/system/vector-count [validApiKey] -> {vectorCount}")],
    notes="Aggregate count; not an object reference."))

API_NODES.append(node(
    K("/api/v1/system/update-env"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"VectorDB": "lancedb", "AnotherKey": "updatedValue"},
        request_fields=[rf("env", "body", "object", required=True, flow=True,
                           description="Key/value pairs matching valid settings to apply to instance config.")],
        response=resp_json([of("newValues", "object", True, "The applied new values."),
                            of("error", "string", False, "Error message, or null.")]),
        reason="updateENV(body) validates keys and persists new settings; returns applied values.",
        evidence=f"{SRC}/system/index.js:108")],
    operation_semantic="update_system_settings", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("env", "EnvConfig(system)", "content", mergeable=True,
                          reason="Arbitrary settings map; can switch LLM provider, vector DB, embedded keys.")],
    sem_out_decisions=[dec("newValues", "EnvValues(system)", "content", mergeable=True,
                           reason="Echo of the applied configuration values.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'System Settings').",
    evidence=[ev("source", f"{SRC}/system/index.js:108", "POST /v1/system/update-env [validApiKey] -> updateENV(body)")],
    notes="High-impact: reconfigures the instance (provider/vector-DB/keys) via a single authenticated call."))

API_NODES.append(node(
    K("/api/v1/system/export-chats"), "api", ["GET"],
    variants=[variant("GET",
        request_fields=[rf("type", "query", "string", required=False, flow=True,
                           description="Export format: jsonl|json|csv|jsonAlpaca (default jsonl).")],
        response=resp_raw("All workspace chats serialized in the requested format; Content-Type varies."),
        reason="exportChatsAsType(type,'workspace'); content-type set from the format.",
        evidence=f"{SRC}/system/index.js:157")],
    operation_semantic="export_all_chats", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    params=["type"],
    sem_in_decisions=[dec("type", "ExportType(export)", "attribute", mergeable=False,
                          reason="Format discriminator; not an object reference.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'System Settings').",
    evidence=[ev("source", f"{SRC}/system/index.js:157", "GET /v1/system/export-chats?type= [validApiKey] -> serialized chats")],
    notes="Exports ALL chats across every workspace -- bulk data exposure surface."))

API_NODES.append(node(
    K("/api/v1/system/remove-documents"), "api", ["DELETE"],
    variants=[variant("DELETE", body_format="json",
        body_example={"names": ["custom-documents/file.txt-fc4beeeb-e436-454d-8bb4-e5b8979cb48f.json"]},
        request_fields=[rf("names", "body", "array", required=True, flow=True,
                           description="Array of document storage locations to permanently remove.")],
        response=resp_json([of("success", "boolean", False, "True on success."),
                            of("message", "string", False, "Result message.")]),
        reason="Iterates names and calls purgeDocument(name) for each.",
        evidence=f"{SRC}/system/index.js:219")],
    operation_semantic="remove_documents", statuses=[200, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("names", "DocumentLocation(document)", "identifier", mergeable=True,
                          reference_capable=True, reference_fields=["names"],
                          reason="Document storage paths identifying the documents to delete.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'System Settings').",
    evidence=[ev("source", f"{SRC}/system/index.js:219", "DELETE /v1/system/remove-documents [validApiKey] -> purgeDocument()")],
    notes="Permanent deletion keyed by caller-supplied storage path."))

# ---- Workspaces (core RAG / chat surface) ----------------------------------
WS = "server/endpoints/api/workspace"
_slug_in = dec("slug", "WorkspaceSlug(workspace)", "identifier", mergeable=True,
               reference_capable=True, reference_fields=["slug"],
               reason="Workspace slug path parameter identifies the workspace.")

API_NODES.append(node(
    K("/api/v1/workspace/new"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"name": "My New Workspace", "chatMode": "chat", "topN": 4},
        request_fields=[rf("name", "body", "string", required=False, flow=True, description="Workspace display name."),
                        rf("config", "body", "object", required=False, flow=True,
                           description="Optional settings: similarityThreshold, openAiTemp/History/Prompt, queryRefusalResponse, chatMode, topN.")],
        response=resp_json([of("workspace", "object", True, "Created workspace (contains slug)."),
                            of("message", "string", False, "Result message.")]),
        reason="Workspace.new(name, null, additionalFields).", evidence=f"{WS}/index.js:28")],
    operation_semantic="create_workspace", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("name", "WorkspaceName(workspace)", "attribute", mergeable=True, reason="New workspace name."),
                      dec("config", "WorkspaceConfig(workspace)", "content", mergeable=True, reason="New workspace settings.")],
    sem_out_decisions=[dec("workspace.slug", "WorkspaceSlug(workspace)", "identifier", mergeable=True,
                           reference_capable=True, reference_fields=["slug"], reason="Created workspace slug.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:28", "POST /v1/workspace/new [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspaces"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("workspaces", "array", True, "All workspaces (slug, name, threads).")]),
        reason="Workspace._findMany include threads.", evidence=f"{WS}/index.js:109")],
    operation_semantic="list_workspaces", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[dec("workspaces[].slug", "WorkspaceSlug(workspace)", "identifier", mergeable=True,
                           reference_capable=True, reference_fields=["slug"], reason="Slugs of listed workspaces.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:109", "GET /v1/workspaces [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}"), "api", ["GET", "DELETE"],
    variants=[variant("GET", request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug.")],
        response=resp_json([of("workspace", "array", True, "Workspace with documents + threads.")]),
        reason="Workspace._findMany by slug.", evidence=f"{WS}/index.js:163"),
        variant("DELETE", request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug.")],
        response=resp_empty(),
        reason="Cascade delete: chats, vectors, documents, workspace, vector namespace.", evidence=f"{WS}/index.js:228")],
    operation_semantic="workspace_by_slug", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in],
    sem_out_decisions=[dec("workspace", "WorkspaceConfig(workspace)", "content", mergeable=True, reason="Workspace config snapshot.")],
    route_confirmed=True, vis_reason="Documented developer endpoints (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:163", "GET + DELETE /v1/workspace/:slug [validApiKey]")],
    notes="DELETE is guarded by workspaceDeletionProtection middleware; cascades to chats/vectors/documents."))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/update"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"name": "Updated Name", "openAiTemp": 0.2, "openAiPrompt": "..."},
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("config", "body", "object", required=True, flow=True, description="Settings to update (all optional keys).")],
        response=resp_json([of("workspace", "object", True, "Updated workspace."), of("message", "string", False, "Result message.")]),
        reason="Workspace.update(id, data).", evidence=f"{WS}/index.js:279")],
    operation_semantic="update_workspace", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, dec("config", "WorkspaceConfig(workspace)", "content", mergeable=True, reason="New settings values.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:279", "POST /v1/workspace/:slug/update [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/chats"), "api", ["GET"],
    variants=[variant("GET",
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("apiSessionId", "query", "string", required=False, flow=True, description="Optional session filter."),
                        rf("limit", "query", "integer", required=False, flow=False, description="Max messages (default 100)."),
                        rf("orderBy", "query", "string", required=False, flow=False, description="asc|desc.")],
        response=resp_json([of("history", "array", True, "Chat history (role, content, sources).")]),
        reason="WorkspaceChats.forWorkspace / forWorkspaceByApiSessionId.", evidence=f"{WS}/index.js:360")],
    operation_semantic="read_workspace_chats", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    params=["apiSessionId", "limit", "orderBy"],
    sem_in_decisions=[_slug_in,
                      dec("apiSessionId", "SessionID(session)", "identifier", mergeable=True,
                          reference_capable=True, reference_fields=["apiSessionId"], reason="External chat session id filter.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:360", "GET /v1/workspace/:slug/chats [validApiKey]")],
    notes="Returns ALL chats in the workspace regardless of user."))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/update-embeddings"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"adds": ["custom-documents/my-pdf.pdf-hash.json"], "deletes": ["custom-documents/old.txt-hash.json"]},
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("adds", "body", "array", required=False, flow=True, description="Document storage paths to embed."),
                        rf("deletes", "body", "array", required=False, flow=True, description="Document storage paths to remove.")],
        response=resp_json([of("workspace", "object", True, "Updated workspace.")]),
        reason="Document.removeDocuments / addDocuments.", evidence=f"{WS}/index.js:457")],
    operation_semantic="update_workspace_embeddings", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in,
                      dec("adds", "DocumentLocation(document)", "identifier", mergeable=True,
                          reference_capable=True, reference_fields=["adds"], reason="Documents to embed into the workspace."),
                      dec("deletes", "DocumentLocation(document)", "identifier", mergeable=False,
                          reason="Documents to remove (same resource type as adds).")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:457", "POST /v1/workspace/:slug/update-embeddings [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/update-pin"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"docPath": "custom-documents/my-pdf.pdf-hash.json", "pinStatus": True},
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("docPath", "body", "string", required=True, flow=True, description="Document storage path."),
                        rf("pinStatus", "body", "boolean", required=False, flow=True, description="Pin on/off.")],
        response=resp_json([of("message", "string", False, "Result message.")]),
        reason="Document.update(id, {pinned}).", evidence=f"{WS}/index.js:534")],
    operation_semantic="pin_workspace_document", statuses=[200, 404, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in,
                      dec("docPath", "DocumentLocation(document)", "identifier", mergeable=True,
                          reference_capable=True, reference_fields=["docPath"], reason="Document to pin/unpin.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:534", "POST /v1/workspace/:slug/update-pin [validApiKey]")]))

_chat_body_fields = [rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                     rf("message", "body", "string", required=True, flow=True, description="User prompt."),
                     rf("mode", "body", "string", required=False, flow=True, description="automatic|query|chat."),
                     rf("sessionId", "body", "string", required=False, flow=True, description="External id to partition chats."),
                     rf("attachments", "body", "array", required=False, flow=True, description="Image/document attachments."),
                     rf("reset", "body", "boolean", required=False, flow=False, description="Reset chat.")]
_chat_sem_in = [_slug_in,
                dec("message", "ChatMessage(chat)", "content", mergeable=True, reason="User prompt (untrusted input to the LLM)."),
                dec("mode", "ChatMode(chat)", "attribute", mergeable=False, reason="Chat mode discriminator."),
                dec("sessionId", "SessionID(session)", "identifier", mergeable=True,
                    reference_capable=True, reference_fields=["sessionId"], reason="External chat session id."),
                dec("attachments", "ChatAttachment(chat)", "content", mergeable=False, reason="Attached images/documents.")]

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/chat"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"message": "What is AnythingLLM?", "mode": "chat", "sessionId": "ext-1"},
        request_fields=_chat_body_fields,
        response=resp_json([of("textResponse", "string", True, "LLM answer (model-authored; streaming-phase XSS->RCE surface)."),
                            of("sources", "array", True, "RAG sources used."),
                            of("id", "string", False, "Chat id."), of("error", "string", False, "Error or null.")]),
        reason="ApiChatHandler.chatSync.", evidence=f"{WS}/index.js:603")],
    operation_semantic="chat_with_workspace", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=_chat_sem_in,
    sem_out_decisions=[dec("textResponse", "ChatResponse(chat)", "content", mergeable=True, reason="Model-authored answer.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:603", "POST /v1/workspace/:slug/chat [validApiKey]")],
    notes="Untrusted prompt -> LLM; response is model-authored (CVE class: streaming-phase XSS to RCE via LLM response injection)."))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/stream-chat"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"message": "What is AnythingLLM?", "mode": "chat"},
        request_fields=_chat_body_fields,
        response=resp_raw("text/event-stream of textResponseChunk events (id, textResponse, sources, close, error)."),
        content_types=["text/event-stream"],
        reason="ApiChatHandler.streamChat (SSE).", evidence=f"{WS}/index.js:737")],
    operation_semantic="chat_with_workspace", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=_chat_sem_in,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:737", "POST /v1/workspace/:slug/stream-chat [validApiKey]")],
    notes="Streaming variant of chat_with_workspace; same untrusted-prompt -> model-authored-output surface."))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/vector-search"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"query": "What is the meaning of life?", "topN": 4, "scoreThreshold": 0.75},
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("query", "body", "string", required=True, flow=True, description="Search query."),
                        rf("topN", "body", "integer", required=False, flow=False, description="Max results."),
                        rf("scoreThreshold", "body", "number", required=False, flow=False, description="Min similarity score.")],
        response=resp_json([of("results", "array", True, "Matching chunks from the vector DB.")]),
        reason="Vector similarity search over the workspace namespace.", evidence=f"{WS}/index.js:899")],
    operation_semantic="vector_search_workspace", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, dec("query", "SearchQuery(search)", "content", mergeable=True, reason="Vector search query.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspaces').",
    evidence=[ev("source", f"{WS}/index.js:899", "POST /v1/workspace/:slug/vector-search [validApiKey]")]))

# ---- Workspace Threads -----------------------------------------------------
THR = "server/endpoints/api/workspaceThread"
_tslug_in = dec("threadSlug", "ThreadSlug(thread)", "identifier", mergeable=True,
                reference_capable=True, reference_fields=["threadSlug"],
                reason="Thread slug path parameter identifies the thread.")
_thr_chat_fields = [rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                    rf("threadSlug", "path", "string", required=True, flow=True, description="Thread slug."),
                    rf("message", "body", "string", required=True, flow=True, description="User prompt."),
                    rf("mode", "body", "string", required=False, flow=True, description="automatic|query|chat."),
                    rf("attachments", "body", "array", required=False, flow=True, description="Image/document attachments."),
                    rf("reset", "body", "boolean", required=False, flow=False, description="Reset chat.")]
_thr_chat_sem = [_slug_in, _tslug_in,
                 dec("message", "ChatMessage(chat)", "content", mergeable=True, reason="User prompt (untrusted input to the LLM)."),
                 dec("mode", "ChatMode(chat)", "attribute", mergeable=False, reason="Chat mode discriminator."),
                 dec("attachments", "ChatAttachment(chat)", "content", mergeable=False, reason="Attached images/documents.")]

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/thread/new"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"userId": 1, "name": "Name", "slug": "thread-slug"},
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("userId", "body", "integer", required=False, flow=False, description="Optional owner user id (nulled in single-user)."),
                        rf("name", "body", "string", required=False, flow=True, description="Thread name."),
                        rf("threadSlugDesired", "body", "string", required=False, flow=False, description="Optional desired thread slug.")],
        response=resp_json([of("thread", "object", True, "Created thread (contains slug)."), of("message", "string", False, "Result message.")]),
        reason="WorkspaceThread.new.", evidence=f"{THR}/index.js:21")],
    operation_semantic="create_thread", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, dec("name", "ThreadName(thread)", "attribute", mergeable=True, reason="New thread name.")],
    sem_out_decisions=[dec("thread.slug", "ThreadSlug(thread)", "identifier", mergeable=True,
                           reference_capable=True, reference_fields=["slug"], reason="Created thread slug.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspace Threads').",
    evidence=[ev("source", f"{THR}/index.js:21", "POST /v1/workspace/:slug/thread/new [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/thread/{threadSlug}/update"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"name": "Updated thread name"},
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("threadSlug", "path", "string", required=True, flow=True, description="Thread slug."),
                        rf("name", "body", "string", required=True, flow=True, description="New thread name.")],
        response=resp_json([of("thread", "object", True, "Updated thread."), of("message", "string", False, "Result message.")]),
        reason="WorkspaceThread.update name.", evidence=f"{THR}/index.js:111")],
    operation_semantic="update_thread", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, _tslug_in, dec("name", "ThreadName(thread)", "attribute", mergeable=True, reason="New thread name.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspace Threads').",
    evidence=[ev("source", f"{THR}/index.js:111", "POST /v1/workspace/:slug/thread/:threadSlug/update [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/thread/{threadSlug}"), "api", ["DELETE"],
    variants=[variant("DELETE",
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("threadSlug", "path", "string", required=True, flow=True, description="Thread slug.")],
        response=resp_empty(), reason="WorkspaceThread.delete.", evidence=f"{THR}/index.js:197")],
    operation_semantic="delete_thread", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, _tslug_in],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspace Threads').",
    evidence=[ev("source", f"{THR}/index.js:197", "DELETE /v1/workspace/:slug/thread/:threadSlug [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/thread/{threadSlug}/chats"), "api", ["GET"],
    variants=[variant("GET",
        request_fields=[rf("slug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("threadSlug", "path", "string", required=True, flow=True, description="Thread slug.")],
        response=resp_json([of("history", "array", True, "Thread chat history.")]),
        reason="WorkspaceChats for thread.", evidence=f"{THR}/index.js:246")],
    operation_semantic="read_thread_chats", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, _tslug_in],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspace Threads').",
    evidence=[ev("source", f"{THR}/index.js:246", "GET /v1/workspace/:slug/thread/:threadSlug/chats [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/thread/{threadSlug}/chat"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"message": "What is AnythingLLM?", "mode": "chat"},
        request_fields=_thr_chat_fields,
        response=resp_json([of("textResponse", "string", True, "LLM answer (model-authored)."), of("sources", "array", True, "RAG sources."),
                            of("id", "string", False, "Chat id."), of("error", "string", False, "Error or null.")]),
        reason="ApiChatHandler.chatSync with thread.", evidence=f"{THR}/index.js:330")],
    operation_semantic="chat_in_thread", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=_thr_chat_sem,
    sem_out_decisions=[dec("textResponse", "ChatResponse(chat)", "content", mergeable=True, reason="Model-authored answer.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspace Threads').",
    evidence=[ev("source", f"{THR}/index.js:330", "POST /v1/workspace/:slug/thread/:threadSlug/chat [validApiKey]")],
    notes="Thread-scoped chat; untrusted prompt -> model-authored output."))

API_NODES.append(node(
    K("/api/v1/workspace/{slug}/thread/{threadSlug}/stream-chat"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"message": "What is AnythingLLM?", "mode": "chat"},
        request_fields=_thr_chat_fields,
        response=resp_raw("text/event-stream of textResponseChunk events."), content_types=["text/event-stream"],
        reason="ApiChatHandler.streamChat with thread.", evidence=f"{THR}/index.js:493")],
    operation_semantic="chat_in_thread", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=_thr_chat_sem,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Workspace Threads').",
    evidence=[ev("source", f"{THR}/index.js:493", "POST /v1/workspace/:slug/thread/:threadSlug/stream-chat [validApiKey]")],
    notes="Streaming variant of chat_in_thread."))

# ---- Documents (ingestion / storage) ---------------------------------------
DOC = "server/endpoints/api/document"
_docname_in = dec("docName", "DocumentName(document)", "identifier", mergeable=True,
                  reference_capable=True, reference_fields=["docName"], reason="Document name identifies a stored document.")
_folderpath_in = dec("folderName", "FolderName(folder)", "identifier", mergeable=True,
                     reference_capable=True, reference_fields=["folderName"], reason="Folder name identifies a storage folder.")
_addws = dec("addToWorkspaces", "WorkspaceSlug(workspace)", "identifier", mergeable=True,
             reference_capable=True, reference_fields=["addToWorkspaces"], reason="Comma-separated target workspace slugs.")
_docs_out = dec("documents", "DocumentLocation(document)", "identifier", mergeable=True,
                reference_capable=True, reference_fields=["documents"], reason="Created document storage locations.")

API_NODES.append(node(
    K("/api/v1/document/upload"), "api", ["POST"],
    variants=[variant("POST", body_format="form",
        request_fields=[rf("file", "body", "file", required=True, flow=True, description="File to upload and parse."),
                        rf("metadata", "body", "object", required=False, flow=True, description="Optional document metadata."),
                        rf("addToWorkspaces", "body", "string", required=False, flow=True, description="Workspace slugs to embed into.")],
        response=resp_json([of("success", "boolean", False, "Upload succeeded."), of("error", "string", False, "Error or null."),
                            of("documents", "array", True, "Parsed document records (storage locations).")]),
        reason="Multipart upload parsed by the document collector.", evidence=f"{DOC}/index.js:52")],
    operation_semantic="upload_document", statuses=[200, 403, 422, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("file", "DocumentFile(document)", "content", mergeable=True, reason="Uploaded file content."), _addws],
    sem_out_decisions=[_docs_out],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:52", "POST /v1/document/upload [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/upload/{folderName}"), "api", ["POST"],
    variants=[variant("POST", body_format="form",
        request_fields=[rf("folderName", "path", "string", required=True, flow=True, description="Target folder (created if missing)."),
                        rf("file", "body", "file", required=True, flow=True, description="File to upload and parse."),
                        rf("metadata", "body", "object", required=False, flow=True, description="Optional document metadata."),
                        rf("addToWorkspaces", "body", "string", required=False, flow=True, description="Workspace slugs to embed into.")],
        response=resp_json([of("success", "boolean", False, "Upload succeeded."), of("documents", "array", True, "Parsed documents.")]),
        reason="Multipart upload into a named folder.", evidence=f"{DOC}/index.js:183")],
    operation_semantic="upload_document", statuses=[200, 403, 422, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[_folderpath_in, dec("file", "DocumentFile(document)", "content", mergeable=True, reason="Uploaded file content."), _addws],
    sem_out_decisions=[_docs_out],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:183", "POST /v1/document/upload/:folderName [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/upload-link"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"link": "https://example.com", "addToWorkspaces": "my-workspace"},
        request_fields=[rf("link", "body", "string|array", required=True, flow=True, description="URL(s) for the server to fetch and scrape."),
                        rf("addToWorkspaces", "body", "string", required=False, flow=True, description="Workspace slugs to embed into."),
                        rf("scraperHeaders", "body", "object", required=False, flow=False, description="Optional headers for the scrape request."),
                        rf("metadata", "body", "object", required=False, flow=False, description="Optional metadata.")],
        response=resp_json([of("success", "boolean", False, "Scrape succeeded."), of("documents", "array", True, "Parsed documents.")]),
        reason="Collector fetches the model/caller-supplied URL(s).", evidence=f"{DOC}/index.js:338")],
    operation_semantic="upload_document_from_link", statuses=[200, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("link", "ExternalURL(url)", "locator", mergeable=True, reason="Caller-supplied URL the server fetches (SSRF surface)."), _addws],
    sem_out_decisions=[_docs_out],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:338", "POST /v1/document/upload-link [validApiKey]")],
    notes="SSRF surface: the server fetches a caller-supplied URL to scrape."))

API_NODES.append(node(
    K("/api/v1/document/raw-text"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"textContent": "...", "metadata": {"title": "doc.txt"}},
        request_fields=[rf("textContent", "body", "string", required=True, flow=True, description="Raw document text."),
                        rf("metadata", "body", "object", required=True, flow=True, description="Metadata (title required)."),
                        rf("addToWorkspaces", "body", "string", required=False, flow=True, description="Workspace slugs to embed into.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("documents", "array", True, "Parsed documents.")]),
        reason="Create a document from raw text + metadata.", evidence=f"{DOC}/index.js:520")],
    operation_semantic="upload_raw_text", statuses=[200, 403, 422, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("textContent", "DocumentText(document)", "content", mergeable=True, reason="Raw document text."),
                      dec("metadata", "DocumentMetadata(document)", "content", mergeable=True, reason="Document metadata (title required)."), _addws],
    sem_out_decisions=[_docs_out],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:520", "POST /v1/document/raw-text [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/documents"), "api", ["GET"],
    variants=[variant("GET",
        request_fields=[rf("folder", "query", "string", required=False, flow=True, description="Optional folder to list."),
                        rf("offset", "query", "integer", required=False, flow=False, description="Pagination offset."),
                        rf("limit", "query", "string", required=False, flow=False, description="Page size or 'all'.")],
        response=resp_json([of("localFiles", "object", True, "Document tree / folder contents.")]),
        reason="List locally-stored documents.", evidence=f"{DOC}/index.js:669")],
    operation_semantic="list_documents", statuses=[200, 403], identity_statuses=ST_KEYED, params=["folder", "offset", "limit"],
    sem_in_decisions=[dec("folder", "FolderName(folder)", "identifier", mergeable=True, reference_capable=True,
                          reference_fields=["folder"], reason="Optional folder filter.")],
    sem_out_decisions=[dec("localFiles", "DocumentLocation(document)", "identifier", mergeable=True,
                           reference_capable=True, reference_fields=["localFiles"], reason="Listed document locations.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:669", "GET /v1/documents [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/documents/folder/{folderName}"), "api", ["GET"],
    variants=[variant("GET",
        request_fields=[rf("folderName", "path", "string", required=True, flow=True, description="Folder name."),
                        rf("offset", "query", "integer", required=False, flow=False, description="Pagination offset."),
                        rf("limit", "query", "string", required=False, flow=False, description="Page size.")],
        response=resp_json([of("documents", "array", True, "Documents in the folder.")]),
        reason="List a folder's documents.", evidence=f"{DOC}/index.js:725")],
    operation_semantic="list_folder_documents", statuses=[200, 403, 404], identity_statuses=ST_KEYED,
    sem_in_decisions=[_folderpath_in],
    sem_out_decisions=[dec("documents", "DocumentLocation(document)", "identifier", mergeable=True,
                           reference_capable=True, reference_fields=["documents"], reason="Folder document locations.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:725", "GET /v1/documents/folder/:folderName [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/accepted-file-types"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("types", "object", True, "Accepted file types / MIMEs.")]),
        reason="Return supported upload types.", evidence=f"{DOC}/index.js:810")],
    operation_semantic="read_accepted_file_types", statuses=[200, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:810", "GET /v1/document/accepted-file-types [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/metadata-schema"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("schema", "object", True, "Known metadata schema for raw-text upload.")]),
        reason="Return metadata schema.", evidence=f"{DOC}/index.js:867")],
    operation_semantic="read_metadata_schema", statuses=[200, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:867", "GET /v1/document/metadata-schema [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/{docName}"), "api", ["GET"],
    variants=[variant("GET", request_fields=[rf("docName", "path", "string", required=True, flow=True, description="Document name.")],
        response=resp_json([of("document", "object", True, "The stored document record.")]),
        reason="Fetch a single document by name.", evidence=f"{DOC}/index.js:919")],
    operation_semantic="read_document", statuses=[200, 403, 404], identity_statuses=ST_KEYED,
    sem_in_decisions=[_docname_in],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:919", "GET /v1/document/:docName [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/create-folder"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"name": "my-folder"},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="New folder name.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("message", "string", False, "Result message.")]),
        reason="Create a folder in the documents storage dir.", evidence=f"{DOC}/index.js:974")],
    operation_semantic="create_folder", statuses=[200, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("name", "FolderName(folder)", "identifier", mergeable=True, reference_capable=True,
                          reference_fields=["name"], reason="New folder name.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:974", "POST /v1/document/create-folder [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/remove-folder"), "api", ["DELETE"],
    variants=[variant("DELETE", body_format="json", body_example={"name": "my-folder"},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="Folder to remove (and its contents).")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("message", "string", False, "Result message.")]),
        reason="Remove a folder and all its contents.", evidence=f"{DOC}/index.js:1048")],
    operation_semantic="remove_folder", statuses=[200, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("name", "FolderName(folder)", "identifier", mergeable=True, reference_capable=True,
                          reference_fields=["name"], reason="Folder to remove.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:1048", "DELETE /v1/document/remove-folder [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/document/move-files"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"files": [{"from": "a/x.json", "to": "b/x.json"}]},
        request_fields=[rf("files", "body", "array", required=True, flow=True, description="Array of {from, to} document paths.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("message", "string", False, "Result message.")]),
        reason="Move files; destinations validated by isFolderFilePath (traversal guard).", evidence=f"{DOC}/index.js:1107")],
    operation_semantic="move_files", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("files", "DocumentLocation(document)", "identifier", mergeable=True, reference_capable=True,
                          reference_fields=["files"], reason="Document from/to storage paths.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:1107", "POST /v1/document/move-files [validApiKey]")],
    notes="Destination paths are validated to a top-level folder/file (path-traversal guard)."))

API_NODES.append(node(
    K("/api/v1/document/generated-files/{filename}"), "api", ["GET"],
    variants=[variant("GET", request_fields=[rf("filename", "path", "string", required=True, flow=True, description="Generated file storageFilename.")],
        response=resp_raw("application/octet-stream download of the generated file."), content_types=["application/octet-stream"],
        reason="Download an agent-generated file; filename format-validated.", evidence=f"{DOC}/index.js:1219")],
    operation_semantic="download_generated_file", statuses=[200, 400, 403, 404], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("filename", "GeneratedFileName(file)", "identifier", mergeable=True, reference_capable=True,
                          reference_fields=["filename"], reason="Generated file name (format-validated against traversal).")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Documents').",
    evidence=[ev("source", f"{DOC}/index.js:1219", "GET /v1/document/generated-files/:filename [validApiKey]")],
    notes="Download by caller-supplied filename; format validation rejects traversal ('Invalid filename format')."))

# ---- OpenAI-compatible API --------------------------------------------------
OAI = "server/endpoints/api/openai"
_ws_id_out = dec("data[].id", "WorkspaceSlug(workspace)", "identifier", mergeable=True,
                 reference_capable=True, reference_fields=["id"], reason="Model/store id == workspace slug.")

API_NODES.append(node(
    K("/api/v1/openai/models"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("data", "array", True, "OpenAI-style model list (id == workspace slug).")]),
        reason="Workspaces presented as OpenAI models.", evidence=f"{OAI}/index.js:19")],
    operation_semantic="openai_list_models", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[_ws_id_out],
    route_confirmed=True, vis_reason="Documented OpenAI-compatible endpoint.",
    evidence=[ev("source", f"{OAI}/index.js:19", "GET /v1/openai/models [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/openai/chat/completions"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"model": "my-workspace", "messages": [{"role": "user", "content": "hi"}], "stream": False},
        request_fields=[rf("model", "body", "string", required=True, flow=True, description="Workspace slug used as the model."),
                        rf("messages", "body", "array", required=True, flow=True, description="OpenAI messages (last user message is the prompt)."),
                        rf("stream", "body", "boolean", required=False, flow=False, description="Stream the completion.")],
        response=resp_json([of("choices", "array", True, "OpenAI choices (model-authored content)."),
                            of("id", "string", False, "Completion id.")]),
        reason="OpenAI-compatible chat over a workspace.", evidence=f"{OAI}/index.js:76")],
    operation_semantic="openai_chat_completion", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("model", "WorkspaceSlug(workspace)", "identifier", mergeable=True, reference_capable=True,
                          reference_fields=["model"], reason="Workspace slug used as the model."),
                      dec("messages", "ChatMessage(chat)", "content", mergeable=True, reason="Untrusted chat messages.")],
    sem_out_decisions=[dec("choices", "ChatResponse(chat)", "content", mergeable=True, reason="Model-authored completion.")],
    route_confirmed=True, vis_reason="Documented OpenAI-compatible endpoint.",
    evidence=[ev("source", f"{OAI}/index.js:76", "POST /v1/openai/chat/completions [validApiKey]")],
    notes="OpenAI-compatible chat; untrusted messages -> LLM -> model-authored output. Supports stream."))

API_NODES.append(node(
    K("/api/v1/openai/images/generations"), "api", ["POST"],
    variants=[variant("POST", body_format="form",
        request_fields=[rf("prompt", "body", "string", required=True, flow=True, description="Image prompt."),
                        rf("size", "body", "string", required=False, flow=False, description="Image size."),
                        rf("image_references", "body", "file", required=False, flow=True, description="Reference image(s) for editing.")],
        response=resp_json([of("data", "array", True, "Generated image(s) as base64 PNG.")]),
        reason="Generate/edit an image via the configured provider.", evidence=f"{OAI}/index.js:195")],
    operation_semantic="openai_generate_image", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("prompt", "ImagePrompt(image)", "content", mergeable=True, reason="Image generation prompt."),
                      dec("image_references", "ImageReference(image)", "content", mergeable=False, reason="Reference images for editing.")],
    sem_out_decisions=[dec("data", "GeneratedImage(image)", "content", mergeable=True, reason="Generated image bytes (base64).")],
    route_confirmed=True, vis_reason="Documented OpenAI-compatible endpoint.",
    evidence=[ev("source", f"{OAI}/index.js:195", "POST /v1/openai/images/generations [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/openai/embeddings"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"input": ["some text"]},
        request_fields=[rf("input", "body", "string|array", required=True, flow=True, description="Text(s) to embed."),
                        rf("model", "body", "string", required=False, flow=False, description="Ignored; uses system embedder.")],
        response=resp_json([of("data", "array", True, "Embedding vectors.")]),
        reason="Embed arbitrary text with the system embedder.", evidence=f"{OAI}/index.js:290")],
    operation_semantic="openai_embeddings", statuses=[200, 400, 403, 500], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("input", "EmbedInput(text)", "content", mergeable=True, reason="Text to embed.")],
    sem_out_decisions=[dec("data", "Embedding(text)", "content", mergeable=True, reason="Embedding vectors.")],
    route_confirmed=True, vis_reason="Documented OpenAI-compatible endpoint.",
    evidence=[ev("source", f"{OAI}/index.js:290", "POST /v1/openai/embeddings [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/openai/vector_stores"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("data", "array", True, "Vector stores (== workspace slugs).")]),
        reason="Workspaces presented as vector stores.", evidence=f"{OAI}/index.js:357")],
    operation_semantic="openai_list_vector_stores", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[_ws_id_out],
    route_confirmed=True, vis_reason="Documented OpenAI-compatible endpoint.",
    evidence=[ev("source", f"{OAI}/index.js:357", "GET /v1/openai/vector_stores [validApiKey]")]))

# ---- User Management -------------------------------------------------------
UM = "server/endpoints/api/userManagement"
_uname_out = dec("users[].username", "Username(user)", "identifier", mergeable=True,
                 reference_capable=True, reference_fields=["username"], reason="Listed usernames.")
_uid_in = dec("id", "UserID(user)", "identifier", mergeable=True,
              reference_capable=True, reference_fields=["id"], reason="User id path parameter.")

API_NODES.append(node(
    K("/api/v1/users"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("users", "array", True, "All users (id, username, role).")]),
        reason="List users.", evidence=f"{UM}/index.js:12")],
    operation_semantic="list_users", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[_uname_out], route_confirmed=True,
    vis_reason="Documented developer endpoint (Swagger 'User Management').",
    evidence=[ev("source", f"{UM}/index.js:12", "GET /v1/users [validApiKey]")],
    notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/users/{id}/issue-auth-token"), "api", ["GET"],
    variants=[variant("GET", request_fields=[rf("id", "path", "integer", required=True, flow=True, description="User id.")],
        response=resp_json([of("token", "string", True, "Temporary login token for the user."), of("error", "string", False, "Error or null.")]),
        reason="Issue a temporary auth/login token for a user.", evidence=f"{UM}/index.js:68")],
    operation_semantic="issue_user_auth_token", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_uid_in],
    sem_out_decisions=[dec("token", "AuthToken(session)", "credential", mergeable=True, reference_capable=False,
                           reason="Issued login token for the target user (impersonation surface).")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'User Management').",
    evidence=[ev("source", f"{UM}/index.js:68", "GET /v1/users/:id/issue-auth-token [validApiKey]")],
    notes="Issues a login token for ANY user id -> impersonation. Requires multi-user mode."))

# ---- Admin -----------------------------------------------------------------
ADM = "server/endpoints/api/admin"
API_NODES.append(node(
    K("/api/v1/admin/is-multi-user-mode"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("isMultiUser", "boolean", False, "True if multi-user mode is on.")]),
        reason="Report multi-user mode status.", evidence=f"{ADM}/index.js:15")],
    operation_semantic="check_multi_user_mode", statuses=[200, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:15", "GET /v1/admin/is-multi-user-mode [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/admin/users"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("users", "array", True, "All users.")]),
        reason="Admin list users.", evidence=f"{ADM}/index.js:41")],
    operation_semantic="admin_list_users", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[_uname_out], route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:41", "GET /v1/admin/users [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/users/new"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"username": "sample-sam", "password": "hunter2", "role": "default"},
        request_fields=[rf("username", "body", "string", required=True, flow=True, description="New username."),
                        rf("password", "body", "string", required=True, flow=True, description="New password."),
                        rf("role", "body", "string", required=False, flow=True, description="User role (default|manager|admin).")],
        response=resp_json([of("user", "object", True, "Created user."), of("error", "string", False, "Error or null.")]),
        reason="Create a user.", evidence=f"{ADM}/index.js:85")],
    operation_semantic="admin_create_user", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("username", "Username(user)", "identifier", mergeable=True, reference_capable=True, reference_fields=["username"], reason="New username."),
                      dec("password", "Password(user)", "credential", mergeable=True, reference_capable=False, reason="New password."),
                      dec("role", "UserRole(user)", "attribute", mergeable=True, reason="User role.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:85", "POST /v1/admin/users/new [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/users/{id}"), "api", ["POST", "DELETE"],
    variants=[variant("POST", body_format="json", body_example={"role": "admin", "suspended": 0},
        request_fields=[rf("id", "path", "integer", required=True, flow=True, description="User id."),
                        rf("username", "body", "string", required=False, flow=True, description="New username."),
                        rf("password", "body", "string", required=False, flow=True, description="New password."),
                        rf("role", "body", "string", required=False, flow=True, description="New role."),
                        rf("suspended", "body", "integer", required=False, flow=True, description="Suspend flag.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("error", "string", False, "Error or null.")]),
        reason="Update user settings.", evidence=f"{ADM}/index.js:143"),
        variant("DELETE", request_fields=[rf("id", "path", "integer", required=True, flow=True, description="User id.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("error", "string", False, "Error or null.")]),
        reason="Delete user.", evidence=f"{ADM}/index.js:216")],
    operation_semantic="admin_user_by_id", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_uid_in, dec("role", "UserRole(user)", "attribute", mergeable=True, reason="New role.")],
    route_confirmed=True, vis_reason="Documented developer endpoints (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:143", "POST + DELETE /v1/admin/users/:id [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/invites"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("invites", "array", True, "All invites with status.")]),
        reason="List invites.", evidence=f"{ADM}/index.js:270")],
    operation_semantic="admin_list_invites", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[dec("invites[].code", "InviteCode(invite)", "identifier", mergeable=True, reference_capable=True,
                           reference_fields=["code"], reason="Invite codes.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:270", "GET /v1/admin/invites [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/invite/new"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"workspaceIds": [1, 2]},
        request_fields=[rf("workspaceIds", "body", "array", required=False, flow=True, description="Workspaces to auto-add the invitee to.")],
        response=resp_json([of("invite", "object", True, "Created invite (code)."), of("error", "string", False, "Error or null.")]),
        reason="Create an invite code.", evidence=f"{ADM}/index.js:316")],
    operation_semantic="admin_create_invite", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[dec("invite.code", "InviteCode(invite)", "identifier", mergeable=True, reference_capable=True,
                           reference_fields=["code"], reason="Created invite code.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:316", "POST /v1/admin/invite/new [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/invite/{id}"), "api", ["DELETE"],
    variants=[variant("DELETE", request_fields=[rf("id", "path", "integer", required=True, flow=True, description="Invite id.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("error", "string", False, "Error or null.")]),
        reason="Deactivate invite.", evidence=f"{ADM}/index.js:375")],
    operation_semantic="admin_delete_invite", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("id", "InviteID(invite)", "identifier", mergeable=True, reference_capable=True, reference_fields=["id"], reason="Invite id.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:375", "DELETE /v1/admin/invite/:id [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/workspaces/{workspaceId}/users"), "api", ["GET"],
    variants=[variant("GET", request_fields=[rf("workspaceId", "path", "integer", required=True, flow=True, description="Workspace id.")],
        response=resp_json([of("users", "array", True, "Users with access to the workspace.")]),
        reason="List workspace users.", evidence=f"{ADM}/index.js:442")],
    operation_semantic="admin_list_workspace_users", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("workspaceId", "WorkspaceID(workspace)", "identifier", mergeable=True, reference_capable=True, reference_fields=["workspaceId"], reason="Workspace id.")],
    sem_out_decisions=[_uname_out], route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:442", "GET /v1/admin/workspaces/:workspaceId/users [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/workspaces/{workspaceId}/update-users"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"userIds": [1, 2]},
        request_fields=[rf("workspaceId", "path", "integer", required=True, flow=True, description="Workspace id."),
                        rf("userIds", "body", "array", required=True, flow=True, description="User ids to grant access.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("error", "string", False, "Error or null.")]),
        reason="Overwrite workspace access list.", evidence=f"{ADM}/index.js:497")],
    operation_semantic="admin_overwrite_workspace_users", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("workspaceId", "WorkspaceID(workspace)", "identifier", mergeable=True, reference_capable=True, reference_fields=["workspaceId"], reason="Workspace id."),
                      dec("userIds", "UserID(user)", "identifier", mergeable=True, reference_capable=True, reference_fields=["userIds"], reason="User ids granted access.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:497", "POST /v1/admin/workspaces/:workspaceId/update-users [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/workspaces/{workspaceSlug}/manage-users"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"userIds": [1, 2], "reset": False},
        request_fields=[rf("workspaceSlug", "path", "string", required=True, flow=True, description="Workspace slug."),
                        rf("userIds", "body", "array", required=True, flow=True, description="User ids to grant access."),
                        rf("reset", "body", "boolean", required=False, flow=False, description="Reset access list.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("users", "array", True, "Resulting access list."), of("error", "string", False, "Error or null.")]),
        reason="Set workspace access list.", evidence=f"{ADM}/index.js:564")],
    operation_semantic="admin_manage_workspace_users", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_slug_in, dec("userIds", "UserID(user)", "identifier", mergeable=True, reference_capable=True, reference_fields=["userIds"], reason="User ids granted access.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:564", "POST /v1/admin/workspaces/:workspaceSlug/manage-users [validApiKey]")], notes="Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/workspace-chats"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"offset": 0},
        request_fields=[rf("offset", "body", "integer", required=False, flow=False, description="Pagination offset.")],
        response=resp_json([of("chats", "array", True, "All chats in the system."), of("hasPages", "boolean", False, "More pages flag.")]),
        reason="All chats across the instance.", evidence=f"{ADM}/index.js:679")],
    operation_semantic="admin_read_workspace_chats", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:679", "POST /v1/admin/workspace-chats [validApiKey]")],
    notes="Returns ALL chats across ALL workspaces/users -- instance-wide data exposure. Requires multi-user mode."))

API_NODES.append(node(
    K("/api/v1/admin/preferences"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"limit_user_messages": True},
        request_fields=[rf("preferences", "body", "object", required=True, flow=True, description="Multi-user preference settings.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("error", "string", False, "Error or null.")]),
        reason="Update multi-user preferences.", evidence=f"{ADM}/index.js:735")],
    operation_semantic="admin_update_preferences", statuses=[200, 401, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("preferences", "SystemSettings(system)", "content", mergeable=True, reason="Multi-user preference settings.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Admin').",
    evidence=[ev("source", f"{ADM}/index.js:735", "POST /v1/admin/preferences [validApiKey]")], notes="Requires multi-user mode."))

# ---- Embeds (public chat widgets) ------------------------------------------
EMB = "server/endpoints/api/embed"
_embuuid_in = dec("embedUuid", "EmbedUUID(embed)", "identifier", mergeable=True,
                  reference_capable=True, reference_fields=["embedUuid"], reason="Embed uuid identifies the widget config.")

API_NODES.append(node(
    K("/api/v1/embed"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("embeds", "array", True, "Active embed widgets.")]),
        reason="List embeds.", evidence=f"{EMB}/index.js:10")],
    operation_semantic="list_embeds", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[dec("embeds[].uuid", "EmbedUUID(embed)", "identifier", mergeable=True, reference_capable=True,
                           reference_fields=["uuid"], reason="Embed uuids.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Embed').",
    evidence=[ev("source", f"{EMB}/index.js:10", "GET /v1/embed [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/embed/{embedUuid}/chats"), "api", ["GET"],
    variants=[variant("GET", request_fields=[rf("embedUuid", "path", "string", required=True, flow=True, description="Embed uuid.")],
        response=resp_json([of("chats", "array", True, "All chats for the embed.")]),
        reason="Embed chats.", evidence=f"{EMB}/index.js:79")],
    operation_semantic="read_embed_chats", statuses=[200, 403, 404], identity_statuses=ST_KEYED,
    sem_in_decisions=[_embuuid_in], route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Embed').",
    evidence=[ev("source", f"{EMB}/index.js:79", "GET /v1/embed/:embedUuid/chats [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/embed/{embedUuid}/chats/{sessionUuid}"), "api", ["GET"],
    variants=[variant("GET", request_fields=[rf("embedUuid", "path", "string", required=True, flow=True, description="Embed uuid."),
                                              rf("sessionUuid", "path", "string", required=True, flow=True, description="Session uuid.")],
        response=resp_json([of("chats", "array", True, "Chats for the embed session.")]),
        reason="Embed session chats.", evidence=f"{EMB}/index.js:141")],
    operation_semantic="read_embed_session_chats", statuses=[200, 403, 404], identity_statuses=ST_KEYED,
    sem_in_decisions=[_embuuid_in, dec("sessionUuid", "SessionUUID(session)", "identifier", mergeable=True,
                                       reference_capable=True, reference_fields=["sessionUuid"], reason="Embed chat session uuid.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Embed').",
    evidence=[ev("source", f"{EMB}/index.js:141", "GET /v1/embed/:embedUuid/chats/:sessionUuid [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/embed/new"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"workspace_slug": "workspace-slug-1", "chat_mode": "chat", "allowlist_domains": ["example.com"], "allow_prompt_override": False},
        request_fields=[rf("workspace_slug", "body", "string", required=True, flow=True, description="Workspace the embed chats against."),
                        rf("config", "body", "object", required=False, flow=True, description="Embed config (chat_mode, allowlist_domains, allow_prompt_override, limits...).")],
        response=resp_json([of("embed", "object", True, "Created embed (uuid)."), of("error", "string", False, "Error or null.")]),
        reason="Create an embed widget config.", evidence=f"{EMB}/index.js:201")],
    operation_semantic="create_embed", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("workspace_slug", "WorkspaceSlug(workspace)", "identifier", mergeable=True, reference_capable=True, reference_fields=["workspace_slug"], reason="Target workspace."),
                      dec("config", "EmbedConfig(embed)", "content", mergeable=True, reason="Embed widget configuration.")],
    sem_out_decisions=[dec("embed.uuid", "EmbedUUID(embed)", "identifier", mergeable=True, reference_capable=True, reference_fields=["uuid"], reason="Created embed uuid.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'Embed').",
    evidence=[ev("source", f"{EMB}/index.js:201", "POST /v1/embed/new [validApiKey]")],
    notes="Creates a PUBLIC chat widget (allowlist_domains / allow_prompt_override are the exposure controls)."))

API_NODES.append(node(
    K("/api/v1/embed/{embedUuid}"), "api", ["POST", "DELETE"],
    variants=[variant("POST", body_format="json",
        request_fields=[rf("embedUuid", "path", "string", required=True, flow=True, description="Embed uuid."),
                        rf("config", "body", "object", required=True, flow=True, description="Updated embed config.")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("error", "string", False, "Error or null.")]),
        reason="Update embed config.", evidence=f"{EMB}/index.js:287"),
        variant("DELETE", request_fields=[rf("embedUuid", "path", "string", required=True, flow=True, description="Embed uuid.")],
        response=resp_json([of("success", "boolean", False, "Succeeded.")]),
        reason="Delete embed.", evidence=f"{EMB}/index.js:358")],
    operation_semantic="embed_by_uuid", statuses=[200, 403, 404], identity_statuses=ST_KEYED,
    sem_in_decisions=[_embuuid_in, dec("config", "EmbedConfig(embed)", "content", mergeable=True, reason="Updated embed config.")],
    route_confirmed=True, vis_reason="Documented developer endpoints (Swagger 'Embed').",
    evidence=[ev("source", f"{EMB}/index.js:287", "POST + DELETE /v1/embed/:embedUuid [validApiKey]")]))

# ---- MCP Servers -----------------------------------------------------------
MCP = "server/endpoints/api/mcpServers"
_mcpname_in = dec("name", "MCPServerName(server)", "identifier", mergeable=True,
                  reference_capable=True, reference_fields=["name"], reason="MCP server name identifies the server.")

API_NODES.append(node(
    K("/api/v1/mcp-servers"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("servers", "array", True, "MCP servers with status, config, tools.")]),
        reason="List MCP servers.", evidence=f"{MCP}/index.js:8")],
    operation_semantic="list_mcp_servers", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_out_decisions=[dec("servers[].name", "MCPServerName(server)", "identifier", mergeable=True, reference_capable=True,
                           reference_fields=["name"], reason="MCP server names.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:8", "GET /v1/mcp-servers [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/mcp-servers/new"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"name": "my-mcp", "config": {"command": "npx", "args": ["..."]}},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="MCP server name."),
                        rf("config", "body", "object", required=True, flow=True, description="MCP server config (command/args/env or url).")],
        response=resp_json([of("success", "boolean", False, "Succeeded."), of("server", "object", True, "The new server record.")]),
        reason="Add + start an MCP server.", evidence=f"{MCP}/index.js:48")],
    operation_semantic="add_mcp_server", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[dec("name", "MCPServerName(server)", "identifier", mergeable=True, reference_capable=True, reference_fields=["name"], reason="MCP server name."),
                      dec("config", "MCPConfig(server)", "content", mergeable=True, reason="MCP server config (command executed / URL contacted).")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:48", "POST /v1/mcp-servers/new [validApiKey]")],
    notes="Config can define a command the server executes -> code-execution/tool surface for agents."))

API_NODES.append(node(
    K("/api/v1/mcp-servers/reload"), "api", ["POST"],
    variants=[variant("POST", response=resp_json([of("success", "boolean", False, "Succeeded.")]),
        reason="Restart all MCP servers.", evidence=f"{MCP}/index.js:108")],
    operation_semantic="reload_mcp_servers", statuses=[200, 403], identity_statuses=ST_KEYED,
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:108", "POST /v1/mcp-servers/reload [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/mcp-servers/{name}/update"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"config": {"command": "npx"}},
        request_fields=[rf("name", "path", "string", required=True, flow=True, description="MCP server name."),
                        rf("config", "body", "object", required=True, flow=True, description="Replacement config.")],
        response=resp_json([of("success", "boolean", False, "Succeeded.")]),
        reason="Replace + restart an MCP server.", evidence=f"{MCP}/index.js:139")],
    operation_semantic="update_mcp_server", statuses=[200, 400, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_mcpname_in, dec("config", "MCPConfig(server)", "content", mergeable=True, reason="Replacement MCP config.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:139", "POST /v1/mcp-servers/:name/update [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/mcp-servers/{name}/toggle"), "api", ["POST"],
    variants=[variant("POST", request_fields=[rf("name", "path", "string", required=True, flow=True, description="MCP server name.")],
        response=resp_json([of("success", "boolean", False, "Succeeded.")]),
        reason="Start/stop an MCP server.", evidence=f"{MCP}/index.js:209")],
    operation_semantic="toggle_mcp_server", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_mcpname_in], route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:209", "POST /v1/mcp-servers/:name/toggle [validApiKey]")]))

API_NODES.append(node(
    K("/api/v1/mcp-servers/{name}/toggle-tool"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"toolName": "search", "enabled": True},
        request_fields=[rf("name", "path", "string", required=True, flow=True, description="MCP server name."),
                        rf("toolName", "body", "string", required=True, flow=True, description="Tool to enable/disable."),
                        rf("enabled", "body", "boolean", required=True, flow=True, description="Enable flag.")],
        response=resp_json([of("success", "boolean", False, "Succeeded.")]),
        reason="Enable/disable one MCP tool.", evidence=f"{MCP}/index.js:252")],
    operation_semantic="toggle_mcp_tool", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_mcpname_in, dec("toolName", "ToolName(tool)", "identifier", mergeable=True, reference_capable=True,
                                       reference_fields=["toolName"], reason="MCP tool name.")],
    route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:252", "POST /v1/mcp-servers/:name/toggle-tool [validApiKey]")],
    notes="Disabled tools are not exposed to agents (agent tool-surface control)."))

API_NODES.append(node(
    K("/api/v1/mcp-servers/{name}"), "api", ["DELETE"],
    variants=[variant("DELETE", request_fields=[rf("name", "path", "string", required=True, flow=True, description="MCP server name.")],
        response=resp_json([of("success", "boolean", False, "Succeeded.")]),
        reason="Stop + remove an MCP server.", evidence=f"{MCP}/index.js:322")],
    operation_semantic="delete_mcp_server", statuses=[200, 403], identity_statuses=ST_KEYED,
    sem_in_decisions=[_mcpname_in], route_confirmed=True, vis_reason="Documented developer endpoint (Swagger 'MCP Servers').",
    evidence=[ev("source", f"{MCP}/index.js:322", "DELETE /v1/mcp-servers/:name [validApiKey]")]))

PAGE_NODES = []
EDGES = []
