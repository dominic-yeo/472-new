# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Categories."""
from common import key as K
from l2lib import qa

C = "app/controllers/categories_controller.rb"

qa("disc_list_categories", "List categories", "Read", "list_categories", "Anonymous",
   K("/categories"), ["GET"], "CategoryList", vis_reason="Public list (visibility-gated).", src=f"{C}:45",
   description="Lists visible categories.")
qa("disc_create_category", "Create category", "Create", "create_category", "Admin",
   K("/categories"), ["POST"], "Category", vis_reason="Admin create.", src=f"{C}:177",
   description="Creates a category.", notes="Permissions define group-level access.")
qa("disc_update_category", "Update category", "Update", "update_category", "Admin",
   K("/categories/{id}"), ["PUT"], "Category", vis_reason="Admin edit.", src=f"{C}:249",
   description="Updates a category.", notes="Permission edits change visibility/posting rights.")
qa("disc_delete_category", "Delete category", "Delete", "destroy_category", "Admin",
   K("/categories/{id}"), ["DELETE"], "Category", vis_reason="Admin delete.", src=f"{C}:362",
   description="Deletes a category.")
qa("disc_reorder_categories", "Reorder categories", "Update", "reorder_categories", "Admin",
   K("/categories/reorder"), ["POST"], "CategoryOrder", vis_reason="Admin reorder.", src=f"{C}:110",
   description="Reorders categories.")
qa("disc_move_category", "Move category", "Update", "move_category", "Admin",
   K("/category/{category_id}/move"), ["POST"], "Category", vis_reason="Admin move.", src=f"{C}:95",
   description="Moves a category under a new parent.")
qa("disc_category_slug", "Change category slug", "Update", "update_category_slug", "Admin",
   K("/category/{category_id}/slug"), ["PUT"], "Category", vis_reason="Admin slug.", src=f"{C}:331",
   description="Changes a category slug.")
qa("disc_category_notifications", "Set category notification level", "Update", "set_category_notifications", "User",
   K("/category/{category_id}/notifications"), ["POST"], "CategoryNotification",
   vis_reason="Self notification level.", src=f"{C}:347", description="Sets the caller's category notification level.")
qa("disc_show_category", "Read category", "Read", "show_category", "Anonymous",
   K("/c/{id}/show"), ["GET"], "Category", vis_reason="Public read.", src=f"{C}:150",
   description="Reads a single category.")
qa("disc_category_visible_groups", "List category visible groups", "Read", "category_visible_groups", "Anonymous",
   K("/c/{id}/visible_groups"), ["GET"], "GroupList", vis_reason="Read.", src=f"{C}:400",
   description="Lists groups that can see the category.")
qa("disc_search_categories", "Search categories", "Read", "search_categories", "Anonymous",
   K("/categories/search"), ["POST"], "CategoryList", vis_reason="Public search.", src=f"{C}:458",
   description="Searches categories.")
qa("disc_hier_search_categories", "Hierarchical category search", "Read", "hierarchical_search_categories", "Anonymous",
   K("/categories/hierarchical_search"), ["GET"], "CategoryList", vis_reason="Read.", src=f"{C}:444",
   description="Hierarchical category search.")
qa("disc_find_categories", "Find categories", "Read", "find_categories", "Anonymous",
   K("/categories/find"), ["GET"], "CategoryList", vis_reason="Read.", src=f"{C}:411",
   description="Finds categories by id/slug.")
