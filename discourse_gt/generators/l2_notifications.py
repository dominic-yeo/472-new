# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Notifications."""
from common import key as K
from l2lib import qa

N = "app/controllers/notifications_controller.rb"
qa("disc_list_notifications", "List notifications", "Read", "list_notifications", "User",
   K("/notifications"), ["GET"], "NotificationList", vis_reason="Self list.", src=f"{N}:1",
   description="Lists the caller's notifications.")
qa("disc_create_notification", "Create notification", "Create", "create_notification", "Admin",
   K("/notifications"), ["POST"], "Notification", vis_reason="Admin create.", src=f"{N}:146",
   description="Creates a notification for a user.")
qa("disc_update_notification", "Update notification", "Update", "update_notification", "User",
   K("/notifications/{id}"), ["PUT"], "Notification", vis_reason="Self.", src=f"{N}:151",
   description="Marks a notification read/unread.")
qa("disc_delete_notification", "Delete notification", "Delete", "destroy_notification", "User",
   K("/notifications/{id}"), ["DELETE"], "Notification", vis_reason="Self.", src=f"{N}:156",
   description="Deletes a notification.")
qa("disc_mark_notifications_read", "Mark notifications read", "Update", "mark_read", "User",
   K("/notifications/mark-read"), ["PUT"], "NotificationList", vis_reason="Self mark-read.", src=f"{N}:120",
   description="Marks one/all notifications read.")
qa("disc_notification_totals", "Read notification totals", "Read", "notification_totals", "User",
   K("/notifications/totals"), ["GET"], "NotificationTotals", vis_reason="Self.", src=f"{N}:161",
   description="Returns unread totals.")
