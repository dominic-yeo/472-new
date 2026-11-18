# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Notifications (NotificationsController). Routes ~1405-1412."""
from common import key as K, snode, V, rf, of, resp_json, resp_empty, IDST_USER, IDST_STAFF

N = "app/controllers/notifications_controller.rb"
NID = [{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Notification id."}]

NODES = [
    snode("/notifications", ["GET", "POST"], "notifications_index_create", IDST_USER,
          [V("GET", resp=resp_json([of("notifications", "array", True, "The caller's notifications.")]),
             reason="Lists the caller's notifications.", src=f"{N}:1"),
           V("POST", [rf("notification_type", "body", "integer", required=True, flow=True, description="Type."),
                      rf("data", "body", "object", required=True, flow=True, description="Payload."),
                      rf("user_id", "body", "integer", required=True, flow=True, description="Recipient.")],
             reason="Creates a notification for a user (admin).", src=f"{N}:146")],
          "Self list; admin create.", f"{N}:1",
          notes="POST create is admin-only; GET is self-scoped."),
    snode("/notifications/{id}", ["PUT", "DELETE"], "notification_update_delete", IDST_USER,
          [V("PUT", [rf("read", "body", "boolean", required=False, flow=True, description="Mark read/unread.")],
             reason="Updates a notification (mark read).", src=f"{N}:151"),
           V("DELETE", reason="Deletes a notification.", src=f"{N}:156")],
          "Self notification management.", f"{N}:151", params=NID),
    snode("/notifications/mark-read", ["PUT"], "mark_notifications_read", IDST_USER,
          [V("PUT", [rf("id", "body", "integer", required=False, flow=True, description="Specific id, or all if omitted.")],
             reason="Marks one/all notifications read.", src=f"{N}:120")], "Self mark-read.", f"{N}:120",
          notes="Groups the /read alias."),
    snode("/notifications/totals", ["GET"], "notification_totals", IDST_USER,
          [V("GET", resp=resp_json([of("totals", "object", True, "Unread counts by type.")]),
             reason="Returns unread notification totals.", src=f"{N}:161")], "Self totals.", f"{N}:161"),
]
