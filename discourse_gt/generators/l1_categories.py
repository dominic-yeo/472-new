# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Categories (CategoriesController). Routes ~1445-1480."""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, dec, ev

C = "app/controllers/categories_controller.rb"
PUB = {"anonymous": [200, 403, 404], "user": [200]}
USER = {"anonymous": [403], "user": [200]}
ADMIN = {"anonymous": [403], "user": [403], "staff": [403], "admin": [200]}


def n(path, methods, sem, idst, variants, vis_reason, src, notes=None, params=None, statuses=None, sin=None, sout=None):
    return node(K(path), "api", methods, variants=variants, operation_semantic=sem,
                statuses=statuses or [200, 403, 404], identity_statuses=idst, params=params or [],
                sem_in_decisions=sin or [], sem_out_decisions=sout or [], route_confirmed=True,
                vis_reason=vis_reason, evidence=[ev("source", src, sem)], notes=notes)


def V(method, fields=None, resp=None, reason="", src="", ex=None):
    return variant(method, body_format="json" if fields else "none", body_example=ex or {},
                   request_fields=fields or [], response=resp if resp is not None else resp_empty(),
                   reason=reason, evidence=src)


_CID = [{"name": "category_id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Category id."}]
_CAT_FIELDS = [rf("name", "body", "string", required=True, flow=True, description="Category name."),
               rf("color", "body", "string", required=False, flow=False, description="Hex color."),
               rf("permissions", "body", "object", required=False, flow=True, description="Per-group permission map."),
               rf("parent_category_id", "body", "integer", required=False, flow=True, description="Parent category."),
               rf("custom_fields", "body", "object", required=False, flow=True, description="Custom fields.")]

NODES = [
    n("/categories", ["GET", "POST"], "categories", PUB,
      [V("GET", resp=resp_json([of("category_list", "object", True, "Visible categories.")]),
         reason="Lists categories visible to the caller.", src=f"{C}:45"),
       V("POST", _CAT_FIELDS, resp_json([of("category", "object", True, "Created category.")]),
         reason="Creates a category (admin).", src=f"{C}:177", ex={"name": "Support"})],
      "Public list; admin create.", f"{C}:45",
      notes="Create/permissions define read/write access for whole groups (authorization surface).",
      sin=[dec("permissions", "CategoryPermissions(authz)", "content", reason="Per-group read/create/reply grants.")],
      sout=[dec("category_list", "CategoryList(taxonomy)", "collection", reason="Visible categories.")]),

    n("/categories/{id}", ["PUT", "DELETE"], "category_crud", ADMIN,
      [V("PUT", _CAT_FIELDS, reason="Updates a category (name/permissions/settings).", src=f"{C}:249", ex={"name": "Help"}),
       V("DELETE", reason="Deletes a category.", src=f"{C}:362")],
      "Admin category edit/delete.", f"{C}:249",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Category id."}],
      notes="Permission edits change who can see/post in the category.",
      sin=[dec("permissions", "CategoryPermissions(authz)", "content", reason="Per-group grants.")]),

    n("/categories/reorder", ["POST"], "reorder_categories", ADMIN,
      [V("POST", [rf("mapping", "body", "string", required=True, flow=True, description="id->position map.")],
         reason="Reorders categories.", src=f"{C}:110")], "Admin reorder.", f"{C}:110"),

    n("/category/{category_id}/move", ["POST"], "move_category", ADMIN,
      [V("POST", [rf("parent_category_id", "body", "integer", required=False, flow=True, description="New parent.")],
         reason="Moves a category under a new parent.", src=f"{C}:95")], "Admin move.", f"{C}:95", params=_CID),

    n("/category/{category_id}/slug", ["PUT"], "update_category_slug", ADMIN,
      [V("PUT", [rf("slug", "body", "string", required=True, flow=True, description="New slug.")],
         reason="Changes a category slug.", src=f"{C}:331", ex={"slug": "help"})], "Admin slug.", f"{C}:331", params=_CID),

    n("/category/{category_id}/notifications", ["POST"], "set_category_notifications", USER,
      [V("POST", [rf("notification_level", "body", "integer", required=True, flow=True, description="watching/tracking/muted/...")],
         reason="Sets the caller's category notification level.", src=f"{C}:347", ex={"notification_level": 3})],
      "Self category notification level.", f"{C}:347", params=_CID),

    n("/c/{id}/show", ["GET"], "show_category", PUB,
      [V("GET", resp=resp_json([of("category", "object", True, "Serialized category.")]),
         reason="Reads a single category.", src=f"{C}:150")], "Public read (visibility-gated).", f"{C}:150",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Category id."}]),

    n("/c/{id}/visible_groups", ["GET"], "category_visible_groups", PUB,
      [V("GET", resp=resp_json([of("groups", "array", True, "Groups that can see the category.")]),
         reason="Lists groups with visibility of a category.", src=f"{C}:400")], "Read.", f"{C}:400",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Category id."}]),

    n("/categories/search", ["POST"], "search_categories", PUB,
      [V("POST", [rf("term", "body", "string", required=False, flow=True, description="Search term.")],
         resp_json([of("categories", "array", True, "Matches.")]), reason="Searches categories.", src=f"{C}:458")],
      "Public category search.", f"{C}:458"),

    n("/categories/hierarchical_search", ["GET"], "hierarchical_search_categories", PUB,
      [V("GET", resp=resp_json([of("categories", "array", True, "Matches.")]),
         reason="Hierarchical category search.", src=f"{C}:444")], "Read.", f"{C}:444"),

    n("/categories/find", ["GET"], "find_categories", PUB,
      [V("GET", resp=resp_json([of("categories", "array", True, "Matches by id/slug.")]),
         reason="Finds categories by id/slug.", src=f"{C}:411")], "Read.", f"{C}:411"),
]
