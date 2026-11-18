# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Tags."""
from common import key as K
from l2lib import qa

T = "app/controllers/tags_controller.rb"
qa("disc_list_tags", "List tags", "Read", "list_tags", "Anonymous", K("/tags"), ["GET"], "TagList",
   vis_reason="Public list.", src=f"{T}:107", description="Lists visible tags.")
qa("disc_show_tag", "Show tag topics", "Read", "show_tag", "Anonymous", K("/tag/{tag_id}"), ["GET"], "TagTopicList",
   vis_reason="Public read.", src=f"{T}:11", description="Shows topics for a tag.")
qa("disc_update_tag", "Rename tag", "Update", "update_tag", "Staff", K("/tag/{tag_id}"), ["PUT"], "Tag",
   vis_reason="Staff edit.", src=f"{T}:269", description="Renames a tag.", notes="Affects all tagged topics.")
qa("disc_delete_tag", "Delete tag", "Delete", "destroy_tag", "Staff", K("/tag/{tag_id}"), ["DELETE"], "Tag",
   vis_reason="Staff delete.", src=f"{T}:374", description="Deletes a tag.")
qa("disc_read_tag_notif", "Read tag notification level", "Read", "tag_notifications", "User",
   K("/tag/{tag_id}/notifications"), ["GET"], "TagNotification", vis_reason="Self read.", src=f"{T}:424",
   description="Reads the caller's tag notification level.")
qa("disc_set_tag_notif", "Set tag notification level", "Update", "update_tag_notifications", "User",
   K("/tag/{tag_id}/notifications"), ["PUT"], "TagNotification", vis_reason="Self set.", src=f"{T}:443",
   description="Sets the caller's tag notification level.")
qa("disc_create_tag_synonyms", "Add tag synonyms", "Create", "create_tag_synonyms", "Staff",
   K("/tag/{tag_id}/synonyms"), ["POST"], "TagSynonym", vis_reason="Staff.", src=f"{T}:459",
   description="Adds synonyms to a tag.", notes="Groups synonym delete.")
qa("disc_search_tags", "Search tags", "Read", "search_tags", "Anonymous", K("/tags/filter/search"), ["GET"], "TagList",
   vis_reason="Public search.", src=f"{T}:400", description="Tag typeahead search.")
qa("disc_upload_tags", "Import tags CSV", "Create", "upload_tags", "Staff", K("/tags/upload"), ["POST"], "Tag",
   vis_reason="Staff CSV import.", src=f"{T}:308", description="Bulk-imports tags from CSV.", notes="File ingestion.")
qa("disc_bulk_create_tags", "Bulk create tags", "Create", "bulk_create_tags", "Staff", K("/tags/bulk_create"), ["POST"], "Tag",
   vis_reason="Staff bulk create.", src=f"{T}:351", description="Bulk-creates tags.")
