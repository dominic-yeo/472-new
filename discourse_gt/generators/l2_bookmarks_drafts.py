# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Bookmarks + Drafts."""
from common import key as K
from l2lib import qa

B = "app/controllers/bookmarks_controller.rb"
D = "app/controllers/drafts_controller.rb"
qa("disc_create_bookmark", "Create bookmark", "Create", "create_bookmark", "User", K("/bookmarks"), ["POST"], "Bookmark",
   vis_reason="Self.", src=f"{B}:6", description="Bookmarks a post/topic.")
qa("disc_update_bookmark", "Edit bookmark", "Update", "update_bookmark", "User", K("/bookmarks/{id}"), ["PUT"], "Bookmark",
   vis_reason="Self.", src=f"{B}:49", description="Edits a bookmark.")
qa("disc_delete_bookmark", "Delete bookmark", "Delete", "destroy_bookmark", "User", K("/bookmarks/{id}"), ["DELETE"], "Bookmark",
   vis_reason="Self.", src=f"{B}:42", description="Removes a bookmark.")
qa("disc_toggle_bookmark_pin", "Toggle bookmark pin", "Update", "toggle_bookmark_pin", "User",
   K("/bookmarks/{id}/toggle_pin"), ["PUT"], "Bookmark", vis_reason="Self.", src=f"{B}:69", description="Pins/unpins a bookmark.")
qa("disc_bulk_bookmarks", "Bulk bookmark op", "Update", "bulk_bookmarks", "User", K("/bookmarks/bulk"), ["PUT"], "Bookmark",
   vis_reason="Self.", src=f"{B}:81", description="Bulk bookmark operation.")
qa("disc_list_drafts", "List drafts", "Read", "list_drafts", "User", K("/drafts"), ["GET"], "DraftList",
   vis_reason="Self.", src=f"{D}:1", description="Lists the caller's drafts.")
qa("disc_save_draft", "Save draft", "Create", "save_draft", "User", K("/drafts"), ["POST"], "Draft",
   vis_reason="Self.", src=f"{D}:39", description="Saves a composer draft.")
qa("disc_read_draft", "Read draft", "Read", "read_draft", "User", K("/drafts/{id}"), ["GET"], "Draft",
   vis_reason="Self.", src=f"{D}:1", description="Reads a draft.")
qa("disc_delete_draft", "Delete draft", "Delete", "destroy_draft", "User", K("/drafts/{id}"), ["DELETE"], "Draft",
   vis_reason="Self.", src=f"{D}:142", description="Deletes a draft.", notes="Groups bulk_destroy.")
