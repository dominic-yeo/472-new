# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Bookmarks + Drafts. Routes ~1353,1401 (bookmarks) + drafts."""
from common import key as K, snode, V, rf, of, resp_json, resp_empty, IDST_USER

B = "app/controllers/bookmarks_controller.rb"
D = "app/controllers/drafts_controller.rb"
BID = [{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Bookmark id."}]
DID = [{"name": "id", "in": "path", "type": "string", "required": True, "flow": True, "description": "Draft key."}]

NODES = [
    snode("/bookmarks", ["POST"], "create_bookmark", IDST_USER,
          [V("POST", [rf("bookmarkable_id", "body", "integer", required=True, flow=True, description="Target id."),
                      rf("bookmarkable_type", "body", "string", required=True, flow=True, description="Post/Topic/..."),
                      rf("reminder_at", "body", "string", required=False, flow=False, description="Reminder time."),
                      rf("name", "body", "string", required=False, flow=True, description="Note.")],
             resp_json([of("id", "integer", True, "Bookmark id.")]),
             reason="Bookmarks a post/topic for the caller.", src=f"{B}:6", ex={"bookmarkable_type": "Post"})],
          "Self bookmark create.", f"{B}:6"),
    snode("/bookmarks/{id}", ["PUT", "DELETE"], "bookmark_update_delete", IDST_USER,
          [V("PUT", [rf("name", "body", "string", required=False, flow=True, description="Note."),
                     rf("reminder_at", "body", "string", required=False, flow=False, description="Reminder.")],
             reason="Edits a bookmark.", src=f"{B}:49"),
           V("DELETE", reason="Removes a bookmark.", src=f"{B}:42")],
          "Self bookmark management.", f"{B}:49", params=BID),
    snode("/bookmarks/{id}/toggle_pin", ["PUT"], "toggle_bookmark_pin", IDST_USER,
          [V("PUT", reason="Pins/unpins a bookmark.", src=f"{B}:69")], "Self bookmark pin.", f"{B}:69", params=BID),
    snode("/bookmarks/bulk", ["PUT"], "bulk_bookmarks", IDST_USER,
          [V("PUT", [rf("bookmark_ids", "body", "array", required=True, flow=True, description="Bookmarks to operate on.")],
             reason="Bulk bookmark operation.", src=f"{B}:81")], "Self bulk bookmarks.", f"{B}:81"),
    snode("/drafts", ["GET", "POST"], "drafts_index_create", IDST_USER,
          [V("GET", resp=resp_json([of("drafts", "array", True, "The caller's drafts.")]),
             reason="Lists the caller's drafts.", src=f"{D}:1"),
           V("POST", [rf("draft_key", "body", "string", required=True, flow=True, description="Draft key."),
                      rf("data", "body", "string", required=True, flow=True, description="Serialized draft content."),
                      rf("sequence", "body", "integer", required=True, flow=False, description="Sequence.")],
             resp_json([of("draft_sequence", "integer", False, "New sequence.")]),
             reason="Saves a composer draft.", src=f"{D}:39", ex={"draft_key": "topic_5"})],
          "Self draft list/save.", f"{D}:39",
          notes="Draft data is user content persisted server-side (reflected back to the composer).",
          sin=[{"raw_field": "data", "resource": "DraftContent(content)", "mergeable": True, "value_kind": "content",
                "reference_capable": False, "reference_fields": [], "reason": "Serialized draft body."}]),
    snode("/drafts/{id}", ["GET", "DELETE"], "draft_show_delete", IDST_USER,
          [V("GET", resp=resp_json([of("draft", "object", True, "Draft content.")]), reason="Reads a draft.", src=f"{D}:1"),
           V("DELETE", reason="Deletes a draft.", src=f"{D}:142")],
          "Self draft read/delete.", f"{D}:142", params=DID, notes="Groups bulk_destroy."),
]
