# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Groups."""
from common import key as K
from l2lib import qa

G = "app/controllers/groups_controller.rb"
qa("disc_show_group", "Read group", "Read", "show_group", "Anonymous", K("/g/{id}"), ["GET"], "Group",
   vis_reason="Public read (visibility-gated).", src=f"{G}:1", description="Reads a group profile.")
qa("disc_update_group", "Update group", "Update", "update_group", "Staff", K("/g/{id}"), ["PUT"], "Group",
   vis_reason="Owner/admin edit.", src=f"{G}:103", description="Updates group settings.",
   notes="Visibility/membership-policy changes.")
qa("disc_group_members_list", "List group members", "Read", "group_members", "Anonymous",
   K("/g/{id}/members"), ["GET"], "GroupMembers", vis_reason="Public read.", src=f"{G}:201",
   description="Lists group members.")
qa("disc_group_add_members", "Add group members", "Update", "add_group_members", "Staff",
   K("/g/{id}/members"), ["PUT"], "GroupMembership", vis_reason="Owner/admin.", src=f"{G}:302",
   description="Adds members.", notes="Grants group-scoped access.")
qa("disc_group_remove_members", "Remove group members", "Delete", "remove_group_members", "Staff",
   K("/g/{id}/members"), ["DELETE"], "GroupMembership", vis_reason="Owner/admin.", src=f"{G}:395",
   description="Removes members.")
qa("disc_group_add_owners", "Add group owners", "Update", "add_group_owners", "Admin",
   K("/g/{id}/owners"), ["PUT"], "GroupOwner", vis_reason="Owner/admin.", src=f"{G}:330",
   description="Adds group owners.", notes="Privilege delegation.")
qa("disc_group_remove_owner", "Remove group owner", "Delete", "remove_group_owner", "Admin",
   K("/g/{id}/owners"), ["DELETE"], "GroupOwner", vis_reason="Owner/admin.", src=f"{G}:1",
   description="Removes a group owner.")
qa("disc_join_group", "Join group", "Update", "join_group", "User", K("/g/{id}/join"), ["PUT"], "GroupMembership",
   vis_reason="Self join.", src=f"{G}:347", description="Joins a public group.", notes="Groups /leave.")
qa("disc_request_group_membership", "Request group membership", "Create", "request_group_membership", "User",
   K("/g/{id}/request_membership"), ["POST"], "MembershipRequest", vis_reason="Self request.", src=f"{G}:426",
   description="Requests to join a group.")
qa("disc_handle_membership_request", "Handle membership request", "Update", "handle_membership_request", "User",
   K("/g/{id}/handle_membership_request"), ["PUT"], "MembershipRequest", vis_reason="Owner request handling.",
   src=f"{G}:356", description="Accepts/denies a membership request.")
qa("disc_group_notifications", "Set group notification level", "Update", "set_group_notifications", "User",
   K("/g/{id}/notifications"), ["POST"], "GroupNotification", vis_reason="Self level.", src=f"{G}:437",
   description="Sets the caller's group notification level.")
qa("disc_check_group_name", "Check group name", "Read", "check_group_name", "User", K("/groups/check-name"), ["GET"],
   "GroupNameAvailability", vis_reason="Name check.", src=f"{G}:389", description="Group-name availability.")
qa("disc_search_groups", "Search groups", "Read", "search_groups", "Anonymous", K("/groups/search"), ["GET"], "GroupList",
   vis_reason="Public search.", src=f"{G}:482", description="Searches groups.")
qa("disc_admin_create_group", "Create group", "Create", "admin_create_group", "Admin", K("/admin/groups"), ["POST"], "Group",
   vis_reason="Admin create.", src=f"{G}:1", description="Creates a group.", notes="Groups admin group delete.")
