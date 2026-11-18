# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Tags (TagsController). Routes ~1810-1881."""
from common import (key as K, snode, V, rf, of, resp_json, resp_empty, dec,
                    IDST_PUB, IDST_USER, IDST_STAFF)

T = "app/controllers/tags_controller.rb"
TID = [{"name": "tag_id", "in": "path", "type": "string", "required": True, "flow": True, "description": "Tag name/id."}]

NODES = [
    snode("/tags", ["GET"], "list_tags", IDST_PUB,
          [V("GET", resp=resp_json([of("tags", "array", True, "Visible tags.")]), reason="Lists tags.", src=f"{T}:107")],
          "Public tag list.", f"{T}:107"),
    snode("/tag/{tag_id}", ["GET", "PUT", "DELETE"], "tag_crud", IDST_PUB,
          [V("GET", resp=resp_json([of("topic_list", "object", True, "Topics for the tag.")]),
             reason="Shows topics for a tag (groups edit/l filters).", src=f"{T}:11"),
           V("PUT", [rf("tag", "body", "object", required=True, flow=True, description="New tag name/target.")],
             reason="Renames a tag (staff).", src=f"{T}:269", ex={"tag": {"id": "newname"}}),
           V("DELETE", reason="Deletes a tag (staff).", src=f"{T}:374")],
          "Public read; staff edit/delete.", f"{T}:11", params=TID,
          notes="Rename/delete are staff ops affecting all tagged topics."),
    snode("/tag/{tag_id}/notifications", ["GET", "PUT"], "tag_notifications", IDST_USER,
          [V("GET", resp=resp_json([of("notification_level", "integer", True, "Caller's level.")]),
             reason="Reads the caller's tag notification level.", src=f"{T}:424"),
           V("PUT", [rf("notification_level", "body", "integer", required=True, flow=True, description="watching/muted/...")],
             reason="Sets the caller's tag notification level.", src=f"{T}:443", ex={"notification_level": 2})],
          "Self tag notification level.", f"{T}:424", params=TID),
    snode("/tag/{tag_id}/synonyms", ["POST"], "create_tag_synonyms", IDST_STAFF,
          [V("POST", [rf("synonyms", "body", "array", required=True, flow=True, description="Synonym tag names.")],
             reason="Adds synonyms to a tag.", src=f"{T}:459", ex={"synonyms": ["js"]})],
          "Staff synonym add.", f"{T}:459", params=TID, notes="Groups DELETE /synonyms/:synonym_id."),
    snode("/tags/filter/search", ["GET"], "search_tags", IDST_PUB,
          [V("GET", resp=resp_json([of("results", "array", True, "Matching tags.")]), reason="Tag typeahead search.", src=f"{T}:400")],
          "Public tag search.", f"{T}:400"),
    snode("/tags/upload", ["POST"], "upload_tags", IDST_STAFF,
          [V("POST", [rf("file", "body", "file", required=True, flow=True, description="CSV of tags.")],
             reason="Bulk-imports tags from a CSV.", src=f"{T}:308", cts=["multipart/form-data"])],
          "Staff tag CSV import.", f"{T}:308", notes="File ingestion (CSV)."),
    snode("/tags/bulk_create", ["POST"], "bulk_create_tags", IDST_STAFF,
          [V("POST", [rf("tag_names", "body", "array", required=True, flow=True, description="Tags to create.")],
             reason="Bulk-creates tags.", src=f"{T}:351", ex={"tag_names": ["a", "b"]})],
          "Staff bulk create.", f"{T}:351"),
]
