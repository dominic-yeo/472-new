# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Admin / Users."""
from common import key as K, reference, entity, f_state, f_auth, f_can, f_exists, eff, subj
from l2lib import qa

A = subj()
AU = "app/controllers/admin/users_controller.rb"
TGT = entity("target_user", "User", "target")
INST = entity("instance", "Instance", "authority")


def st(field, val):
    return [eff(f_state(TGT, field, val), "state_transition", f"Target user {field} -> {val}.")]


qa("disc_admin_list_users", "List users (admin)", "Read", "admin_list_users", "Staff", K("/admin/users/list"), ["GET"],
   "AdminUserList", vis_reason="Staff.", src=f"{AU}:1", description="Lists users with staff detail.",
   notes="Discloses emails/IPs/flags.")
qa("disc_admin_show_user", "Read user (admin)", "Read", "admin_show_user", "Staff", K("/admin/users/{id}.json"), ["GET"],
   "AdminUserDetail", vis_reason="Staff.", src=f"{AU}:1", description="Full admin detail for a user.",
   notes="Sensitive PII + security history.")
qa("disc_admin_delete_user", "Delete user (admin)", "Delete", "admin_delete_user", "Staff", K("/admin/users/{id}"), ["DELETE"],
   "User", vis_reason="Staff.", src=f"{AU}:457", description="Deletes a user account.", notes="Destructive.")
qa("disc_admin_suspend", "Suspend user", "Update", "admin_suspend_user", "Staff", K("/admin/users/{id}/suspend"), ["PUT"],
   "User", gen=st("suspended", "true"), vis_reason="Staff.", src=f"{AU}:211",
   description="Suspends a user (blocks login).", notes="Account lockout; groups unsuspend.")
qa("disc_admin_silence", "Silence user", "Update", "admin_silence_user", "Staff", K("/admin/users/{id}/silence"), ["PUT"],
   "User", gen=st("silenced", "true"), vis_reason="Staff.", src=f"{AU}:397",
   description="Silences a user (blocks posting).", notes="Groups unsilence.")
qa("disc_admin_grant_admin", "Grant admin", "Update", "admin_grant_admin", "Admin", K("/admin/users/{id}/grant_admin"), ["PUT"],
   "User", gen=st("role", "admin") + [eff(f_can(A, "Administer", INST), "auth_transition", "Target gains admin authority.")],
   vis_reason="Admin.", src=f"{AU}:261", description="Grants admin privileges.",
   notes="PRIVILEGE ESCALATION; may require 2FA/email confirm.")
qa("disc_admin_revoke_admin", "Revoke admin", "Update", "admin_revoke_admin", "Admin", K("/admin/users/{id}/revoke_admin"), ["PUT"],
   "User", gen=st("role", "user"), vis_reason="Admin.", src=f"{AU}:254", description="Revokes admin privileges.")
qa("disc_admin_grant_moderation", "Grant moderation", "Update", "admin_grant_moderation", "Admin",
   K("/admin/users/{id}/grant_moderation"), ["PUT"], "User", gen=st("moderator", "true"), vis_reason="Admin.",
   src=f"{AU}:277", description="Grants moderator privileges.", notes="Groups revoke_moderation.")
qa("disc_admin_log_out_user", "Log out user", "Delete", "admin_log_out_user", "Admin", K("/admin/users/{id}/log_out"), ["POST"],
   "Session", kill=[eff(f_auth(A, "Session"), "auth_transition", "All target sessions terminated.")],
   vis_reason="Admin.", src=f"{AU}:243", description="Terminates all of a user's sessions.")
qa("disc_admin_approve", "Approve user", "Update", "admin_approve_user", "Staff", K("/admin/users/{id}/approve"), ["PUT"],
   "User", gen=st("approved", "true"), vis_reason="Staff.", src=f"{AU}:365", description="Approves a pending user.",
   notes="Groups approve-bulk.")
qa("disc_admin_activate", "Activate user", "Update", "admin_activate_user", "Staff", K("/admin/users/{id}/activate"), ["PUT"],
   "User", gen=st("active", "true"), vis_reason="Staff.", src=f"{AU}:381", description="Activates/deactivates a user.",
   notes="Groups deactivate.")
qa("disc_admin_trust_level", "Set trust level", "Update", "admin_set_trust_level", "Staff",
   K("/admin/users/{id}/trust_level"), ["PUT"], "User", gen=st("trust_level", "set"), vis_reason="Staff.",
   src=f"{AU}:329", description="Sets a user's trust level.", notes="Governs capabilities; groups trust_level_lock.")
qa("disc_admin_primary_group", "Set primary group", "Update", "admin_set_primary_group", "Staff",
   K("/admin/users/{id}/primary_group"), ["PUT"], "User", vis_reason="Staff.", src=f"{AU}:311",
   description="Sets a user's primary group.")
qa("disc_admin_add_group", "Add user to group", "Update", "admin_add_user_group", "Admin", K("/admin/users/{id}/groups"), ["POST"],
   "GroupMembership", vis_reason="Admin.", src=f"{AU}:284", description="Adds a user to a group.",
   notes="Access grant; groups member removal.")
qa("disc_admin_anonymize", "Anonymize user", "Update", "admin_anonymize_user", "Staff", K("/admin/users/{id}/anonymize"), ["PUT"],
   "User", gen=st("anonymized", "true"), vis_reason="Staff.", src=f"{AU}:600", description="Anonymizes a user.",
   notes="Irreversible identity scrub.")
qa("disc_admin_merge", "Merge user", "Update", "admin_merge_user", "Staff", K("/admin/users/{id}/merge"), ["POST"], "User",
   vis_reason="Staff.", src=f"{AU}:613", description="Merges one user into another.")
qa("disc_admin_disable_2fa", "Disable user 2FA (admin)", "Delete", "admin_disable_2fa", "Staff",
   K("/admin/users/{id}/disable_second_factor"), ["PUT"], "SecondFactor", vis_reason="Staff.", src=f"{AU}:442",
   description="Removes a user's second factor.", notes="Recovery path; takeover enabler if abused.")
qa("disc_admin_delete_sso", "Delete SSO record", "Delete", "admin_delete_sso_record", "Staff",
   K("/admin/users/{id}/sso_record"), ["DELETE"], "SsoRecord", vis_reason="Staff.", src=f"{AU}:636",
   description="Deletes a user's SSO/associated record.")
qa("disc_admin_delete_posts_batch", "Batch-delete user posts", "Delete", "admin_delete_posts_batch", "Staff",
   K("/admin/users/{id}/delete_posts_batch"), ["PUT"], "Post", vis_reason="Staff.", src=f"{AU}:146",
   description="Batch-deletes a user's posts.")
qa("disc_admin_impersonate", "Impersonate user", "Create", "admin_impersonate", "Admin", K("/admin/impersonate"), ["POST"],
   "Session", gen=[eff(f_auth(A, "ImpersonatedSession"), "auth_transition", "Admin assumes the target user's session.")],
   vis_reason="Admin.", src="app/controllers/admin/impersonate_controller.rb:1",
   description="Starts impersonating another user.", notes="FULL ACCOUNT TAKEOVER by design (audited).")
qa("disc_admin_sync_sso", "Sync SSO user", "Update", "admin_sync_sso", "Admin", K("/admin/users/sync_sso"), ["POST"], "User",
   vis_reason="Admin.", src=f"{AU}:547", description="Provisions/updates a user from a signed SSO payload.",
   notes="Identity + group sync.")
qa("disc_admin_ip_info", "Look up IP info", "Read", "admin_ip_info", "Staff", K("/admin/users/ip-info"), ["GET"], "IpInfo",
   vis_reason="Staff.", src=f"{AU}:540", description="IP geolocation/ISP lookup.", notes="Groups same-IP account tools.")
