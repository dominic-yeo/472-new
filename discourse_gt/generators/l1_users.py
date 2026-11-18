# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Users + Account (UsersController, UsersEmailController).

Routes under /u (and /users), config/routes.rb ~721-1060. Source: app/controllers/
users_controller.rb (2412 lines) + users_email_controller.rb. The many read-only
preference sub-views (users#preferences for notifications/tracking/tags/interface/...)
and user show-view aliases (activity/badges/messages filters) are grouped into one
profile-read and one preferences-read node (noted on those nodes); mutating + security
endpoints are modeled individually. Exports NODES (consumed by l1_data.py).
"""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, resp_scalar, resp_raw, dec, dec_for, ev

UC = "app/controllers/users_controller.rb"
UE = "app/controllers/users_email_controller.rb"

ST_PUBLIC = {"anonymous": [200, 400, 403]}
ST_PUBLIC_RL = {"anonymous": [200, 400, 403, 429]}
ST_USER = {"anonymous": [403, 404], "user": [200]}
ST_SELF = {"anonymous": [403], "other_user": [403], "user": [200]}   # self-or-staff guarded

D_USERNAME = dec_for("username")
D_EMAIL = dec_for("email")
D_PASSWD = dec_for("password")
D_TOKEN = dec_for("token")
D_2FA = dec_for("second_factor_token")

NODES = []

# ---- Registration + availability checks (public, enumeration surface) -------
NODES.append(node(
    K("/u"), "api", ["POST"],
    variants=[variant("POST", body_format="json",
        body_example={"username": "alice", "email": "a@b.co", "password": "***", "name": "Alice"},
        request_fields=[rf("username", "body", "string", required=True, flow=True, description="Desired username."),
                        rf("email", "body", "string", required=True, flow=True, description="Account email."),
                        rf("password", "body", "string", required=True, flow=True, description="Account password."),
                        rf("name", "body", "string", required=False, flow=True, description="Display name."),
                        rf("invite_code", "body", "string", required=False, flow=False, description="Invite code if required."),
                        rf("user_fields", "body", "object", required=False, flow=True, description="Custom user-field values."),
                        rf("external_ids", "body", "object", required=False, flow=False, description="External auth ids (gated).")],
        response=resp_json([of("success", "boolean", False, "Whether the account was created."),
                            of("active", "boolean", False, "Whether immediately active."),
                            of("user_id", "integer", True, "New user id."),
                            of("message", "string", False, "Activation/approval message.")]),
        reason="Self-registration; honeypot + approval/activation gating.", evidence=f"{UC}:737")],
    operation_semantic="register_account", statuses=[200, 403, 422, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_USERNAME, D_EMAIL, D_PASSWD, dec("name", "DisplayName(identity)", "attribute", reason="Name."),
                      dec("user_fields", "UserFields(profile)", "content", reason="Custom fields (stored-reflected).")],
    sem_out_decisions=[dec("user_id", "UserId(identity)", "identifier", reference_capable=True, reason="New user id.")],
    route_confirmed=True, vis_reason="Public registration boundary.",
    reach_conds=["allow_new_registrations", "not invite-only (else invite_code required)"],
    evidence=[ev("source", f"{UC}:737", "POST /u require(:email,:username); honeypot; user_params")],
    notes="Registration boundary; user_fields/name are stored-reflected. external_ids gated by ensure_external_ids_allowed!."))

NODES.append(node(
    K("/u/check_username"), "api", ["GET"],
    params=[{"name": "username", "in": "query", "type": "string", "required": False, "flow": True, "description": "Username to test."},
            {"name": "email", "in": "query", "type": "string", "required": False, "flow": True, "description": "Email context."}],
    variants=[variant("GET", response=resp_json([of("available", "boolean", True, "Whether the username is free."),
                                                 of("suggestion", "string", False, "Alternative suggestion.")]),
        reason="Username availability check.", evidence=f"{UC}:634")],
    operation_semantic="check_username", statuses=[200], identity_statuses={"anonymous": [200]},
    route_confirmed=True, vis_reason="Public signup helper.",
    evidence=[ev("source", f"{UC}:634", "GET /u/check_username")],
    notes="Username enumeration surface (available/taken)."))

NODES.append(node(
    K("/u/check_email"), "api", ["GET"],
    params=[{"name": "email", "in": "query", "type": "string", "required": True, "flow": True, "description": "Email to test."}],
    variants=[variant("GET", response=resp_json([of("available", "boolean", True, "Whether the email is free.")]),
        reason="Email availability check (rate limited).", evidence=f"{UC}:697")],
    operation_semantic="check_email", statuses=[200, 429], identity_statuses={"anonymous": [200, 429]},
    route_confirmed=True, vis_reason="Public signup helper.",
    evidence=[ev("source", f"{UC}:697", "GET /u/check_email")],
    notes="Email enumeration surface; rate-limited."))

NODES.append(node(
    K("/u/search/users"), "api", ["GET"],
    params=[{"name": "term", "in": "query", "type": "string", "required": False, "flow": True, "description": "Search term."},
            {"name": "topic_id", "in": "query", "type": "integer", "required": False, "flow": False, "description": "Context topic."}],
    variants=[variant("GET", response=resp_json([of("users", "array", True, "Matching users (username/name/avatar).")]),
        reason="Typeahead user search (mentions/messages).", evidence=f"{UC}:1342")],
    operation_semantic="search_users", statuses=[200], identity_statuses={"anonymous": [200], "user": [200]},
    sem_out_decisions=[dec("users", "UserDirectory(identity)", "collection", reason="Matched user summaries.")],
    route_confirmed=True, vis_reason="Public/typeahead directory search.",
    evidence=[ev("source", f"{UC}:1342", "GET /u/search/users")],
    notes="User-directory disclosure; honors visibility settings but is an enumeration surface."))

# ---- Profile + preferences reads (grouped views) ---------------------------
NODES.append(node(
    K("/u/{username}.json"), "api", ["GET"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("GET", response=resp_json([of("user", "object", True, "Serialized user profile.")]),
        reason="Public profile read; also backs /activity, /badges, /notifications, /messages view aliases.",
        evidence=f"{UC}:134")],
    operation_semantic="show_user", statuses=[200, 403, 404], identity_statuses={"anonymous": [200, 403, 404], "user": [200]},
    sem_out_decisions=[dec("user", "UserProfile(identity)", "content", reason="Public profile fields (respecting visibility).")],
    route_confirmed=True, vis_reason="Public profile (visibility-gated).",
    evidence=[ev("source", f"{UC}:134", "GET /u/:username.json -> users#show")],
    notes="GROUPS the users#show view aliases (activity/badges/notifications/messages filters). Visibility via Guardian."))

NODES.append(node(
    K("/u/{username}/summary"), "api", ["GET"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("GET", response=resp_json([of("user_summary", "object", True, "Activity summary (counts, top topics).")]),
        reason="User activity summary.", evidence=f"{UC}:526")],
    operation_semantic="user_summary", statuses=[200, 403, 404], identity_statuses={"anonymous": [200, 403, 404]},
    sem_out_decisions=[dec("user_summary", "UserSummary(identity)", "summary", reason="Aggregate activity.")],
    route_confirmed=True, vis_reason="Public summary (visibility-gated).",
    evidence=[ev("source", f"{UC}:526", "GET /u/:username/summary")],
    notes="Cached activity aggregate."))

NODES.append(node(
    K("/u/{username}/preferences"), "api", ["GET"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username (self/staff)."}],
    variants=[variant("GET", response=resp_json([of("user", "object", True, "Full editable preference payload.")]),
        reason="Preferences read; backs all /preferences/* sub-views.", evidence=f"{UC}:507")],
    operation_semantic="read_preferences", statuses=[200, 403, 404], identity_statuses=ST_SELF,
    sem_out_decisions=[dec("user", "UserPreferences(account)", "content", reason="Editable account/preference state.")],
    route_confirmed=True, vis_reason="Self (or staff) preference view.",
    evidence=[ev("source", f"{UC}:507", "GET /u/:username/preferences -> users#preferences")],
    notes="GROUPS all /preferences/* GET sub-views (notifications/tracking/tags/interface/security/...). Self-or-staff guarded."))

NODES.append(node(
    K("/u/{username}/emails"), "api", ["GET"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username (self/staff)."}],
    variants=[variant("GET", response=resp_json([of("email", "string", True, "Primary email."),
                                                 of("secondary_emails", "array", True, "Secondary emails.")]),
        reason="Reveals the account's email addresses (self or staff).", evidence=f"{UC}:319")],
    operation_semantic="check_emails", statuses=[200, 403], identity_statuses=ST_SELF,
    sem_out_decisions=[dec("email", "UserEmail(identity)", "identifier", reference_capable=True, reason="Account emails.")],
    route_confirmed=True, vis_reason="Self-or-staff email disclosure.",
    evidence=[ev("source", f"{UC}:319", "GET /u/:username/emails (guardian.can_check_emails?)")],
    notes="Sensitive PII read; staff can view other users' emails (logged as a staff action)."))

# ---- Account profile mutations (self/staff) --------------------------------
NODES.append(node(
    K("/u/{username}"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("PUT", body_format="json",
        body_example={"name": "Alice", "bio_raw": "hi", "user_fields": {}},
        request_fields=[rf("name", "body", "string", required=False, flow=True, description="Display name."),
                        rf("bio_raw", "body", "string", required=False, flow=True, description="Profile bio (markdown)."),
                        rf("user_fields", "body", "object", required=False, flow=True, description="Custom field values."),
                        rf("website", "body", "string", required=False, flow=True, description="Profile website.")],
        response=resp_json([of("user", "object", True, "Updated user.")]),
        reason="Updates profile + preferences via the permitted user_params list.", evidence=f"{UC}:219")],
    operation_semantic="update_user", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    sem_in_decisions=[dec("bio_raw", "Bio(profile)", "content", reason="Bio (rendered; stored-reflected)."),
                      dec("user_fields", "UserFields(profile)", "content", reason="Custom fields."),
                      dec("website", "Website(profile)", "locator", reference_capable=True, reason="Profile URL.")],
    route_confirmed=True, vis_reason="Self (or staff) profile edit.",
    evidence=[ev("source", f"{UC}:219", "PUT /u/:username -> update; user_params permit list")],
    notes="Large permitted-params surface; bio/website/user_fields are stored-reflected (XSS/SSRF-on-render class)."))

NODES.append(node(
    K("/u/{username}/preferences/username"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Current username."}],
    variants=[variant("PUT", body_format="json", body_example={"new_username": "alice2"},
        request_fields=[rf("new_username", "body", "string", required=True, flow=True, description="Desired new username.")],
        response=resp_json([of("username", "string", True, "The new username.")]),
        reason="Renames the account (guarded by can_edit_username? + rate/age rules).", evidence=f"{UC}:288")],
    operation_semantic="change_username", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    sem_in_decisions=[dec("new_username", "Username(identity)", "identifier", reference_capable=True, reason="New handle.")],
    route_confirmed=True, vis_reason="Self (or staff) username change.",
    evidence=[ev("source", f"{UC}:288", "PUT /u/:username/preferences/username require(:new_username)")],
    notes="Identity rename; impacts @mentions and historical references."))

NODES.append(node(
    K("/u/{username}/preferences/primary-email"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("PUT", body_format="json", body_example={"email": "new@b.co"},
        request_fields=[rf("email", "body", "string", required=True, flow=True, description="Email to promote to primary.")],
        response=resp_empty(), reason="Promotes a confirmed secondary email to primary.", evidence=f"{UC}:372")],
    operation_semantic="set_primary_email", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    sem_in_decisions=[D_EMAIL],
    route_confirmed=True, vis_reason="Self (or staff) primary-email change.",
    evidence=[ev("source", f"{UC}:372", "PUT /u/:username/preferences/primary-email require(:email)")],
    notes="Changes the identity/recovery email (account-takeover-relevant)."))

NODES.append(node(
    K("/u/{username}/preferences/email"), "api", ["POST", "PUT", "DELETE"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("POST", body_format="json", body_example={"email": "add@b.co"},
                      request_fields=[rf("email", "body", "string", required=True, flow=True, description="Secondary email to add.")],
                      response=resp_empty(), reason="Adds a secondary email (confirmation sent).", evidence=f"{UE}:0"),
              variant("PUT", body_format="json", body_example={"email": "change@b.co"},
                      request_fields=[rf("email", "body", "string", required=True, flow=True, description="Replacement email.")],
                      response=resp_empty(), reason="Changes the account email (confirmation flow).", evidence=f"{UE}:0"),
              variant("DELETE", body_format="json", body_example={"email": "old@b.co"},
                      request_fields=[rf("email", "body", "string", required=True, flow=True, description="Email to remove.")],
                      response=resp_empty(), reason="Removes a secondary email.", evidence=f"{UC}:406")],
    operation_semantic="manage_email", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    sem_in_decisions=[D_EMAIL],
    route_confirmed=True, vis_reason="Self (or staff) email management.",
    evidence=[ev("source", f"{UE}:1", "POST/PUT /u/:username/preferences/email -> UsersEmailController"),
              ev("source", f"{UC}:406", "DELETE /u/:username/preferences/email -> destroy_email require(:email)")],
    notes="Email add/change triggers a confirmation flow (confirm-old/new-email tokens)."))

NODES.append(node(
    K("/u/{username}/preferences/badge_title"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("PUT", body_format="json", body_example={"user_badge_id": 12},
        request_fields=[rf("user_badge_id", "body", "integer", required=True, flow=True, description="Owned badge to set as title.")],
        response=resp_empty(), reason="Sets the profile title from an owned badge.", evidence=f"{UC}:459")],
    operation_semantic="set_badge_title", statuses=[200, 403], identity_statuses=ST_SELF,
    route_confirmed=True, vis_reason="Self badge-title set.",
    evidence=[ev("source", f"{UC}:459", "PUT .../badge_title require(:user_badge_id)")],
    notes="Must own the badge."))

NODES.append(node(
    K("/u/{username}/preferences/avatar/pick"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("PUT", body_format="json", body_example={"upload_id": 99, "type": "uploaded"},
        request_fields=[rf("upload_id", "body", "integer", required=False, flow=True, description="Uploaded avatar id."),
                        rf("type", "body", "string", required=False, flow=False, description="Avatar type.")],
        response=resp_empty(), reason="Sets the avatar to an uploaded/gravatar image.", evidence=f"{UC}:1430")],
    operation_semantic="pick_avatar", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    route_confirmed=True, vis_reason="Self avatar set.",
    evidence=[ev("source", f"{UC}:1430", "PUT .../avatar/pick -> pick_avatar")],
    notes="upload_id must reference the user's own upload."))

NODES.append(node(
    K("/u/{username}/preferences/avatar/select"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("PUT", body_format="json", body_example={"url": "https://.../a.png"},
        request_fields=[rf("url", "body", "string", required=False, flow=True, description="Avatar source URL.")],
        response=resp_empty(), reason="Selects an avatar by URL (download-avatar flow).", evidence=f"{UC}:1465")],
    operation_semantic="select_avatar", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    sem_in_decisions=[dec("url", "AvatarUrl(locator)", "locator", reference_capable=True, reason="Avatar source URL.")],
    route_confirmed=True, vis_reason="Self avatar select.",
    evidence=[ev("source", f"{UC}:1465", "PUT .../avatar/select -> select_avatar")],
    notes="URL-sourced avatar (server-side fetch -> SSRF-relevant when enabled)."))

NODES.append(node(
    K("/u/{username}/preferences/user_image"), "api", ["DELETE"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("DELETE", body_format="json", body_example={"type": "profile_background"},
        request_fields=[rf("type", "body", "string", required=True, flow=True, description="Image type to clear.")],
        response=resp_empty(), reason="Clears a profile/card background image.", evidence=f"{UC}:1496")],
    operation_semantic="destroy_user_image", statuses=[200, 403], identity_statuses=ST_SELF,
    route_confirmed=True, vis_reason="Self image removal.",
    evidence=[ev("source", f"{UC}:1496", "DELETE .../user_image require(:type)")],
    notes=None))

NODES.append(node(
    K("/u/{username}/preferences/revoke-account"), "api", ["POST"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("POST", body_format="json", body_example={"provider_name": "google_oauth2"},
        request_fields=[rf("provider_name", "body", "string", required=True, flow=True, description="OAuth provider to unlink.")],
        response=resp_empty(), reason="Unlinks an associated OAuth/external account.", evidence=f"{UC}:1915")],
    operation_semantic="revoke_associated_account", statuses=[200, 403, 422], identity_statuses=ST_SELF,
    route_confirmed=True, vis_reason="Self OAuth-link removal.",
    evidence=[ev("source", f"{UC}:1915", "POST .../revoke-account require(:provider_name)")],
    notes="Detaches a federated-login provider from the account."))

NODES.append(node(
    K("/u/{username}/preferences/revoke-auth-token"), "api", ["POST"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("POST", body_format="json", body_example={"token_id": 5},
        request_fields=[rf("token_id", "body", "integer", required=False, flow=True, description="Specific session token to revoke (all if omitted).")],
        response=resp_empty(), reason="Revokes one or all active session tokens (log out other devices).", evidence=f"{UC}:1948")],
    operation_semantic="revoke_auth_token", statuses=[200, 403], identity_statuses=ST_SELF,
    route_confirmed=True, vis_reason="Self session revocation.",
    evidence=[ev("source", f"{UC}:1948", "POST .../revoke-auth-token")],
    notes="Session management; revokes device sessions."))

NODES.append(node(
    K("/u/{username}/notification_level"), "api", ["PUT"],
    params=[{"name": "username", "in": "path", "type": "string", "required": True, "flow": True, "description": "Target username."}],
    variants=[variant("PUT", body_format="json", body_example={"notification_level": "watched"},
        request_fields=[rf("notification_level", "body", "string", required=True, flow=True, description="ignore/mute/normal/... for this user."),
                        rf("expiring_at", "body", "string", required=False, flow=False, description="Optional expiry.")],
        response=resp_empty(), reason="Sets the caller's notification/ignore/mute relation to another user.", evidence=f"{UC}:1521")],
    operation_semantic="set_user_notification_level", statuses=[200, 403, 422], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Caller sets a relation to another user.",
    evidence=[ev("source", f"{UC}:1521", "PUT /u/:username/notification_level")],
    notes="Ignore/mute is a per-caller relation; ignoring staff is restricted."))

# ---- Two-factor + passkey management (self, confirmed session) -------------
NODES.append(node(
    K("/u/second_factors"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"password": "***"},
        request_fields=[rf("password", "body", "string", required=False, flow=True, description="Password to confirm session.")],
        response=resp_json([of("totps", "array", True, "Configured TOTP authenticators."),
                            of("security_keys", "array", True, "Configured security keys.")]),
        reason="Lists the account's second factors (requires a confirmed session).", evidence=f"{UC}:1673")],
    operation_semantic="list_second_factors", statuses=[200, 403], identity_statuses=ST_USER,
    sem_in_decisions=[D_PASSWD],
    route_confirmed=True, vis_reason="Self 2FA inventory (confirmed session).",
    evidence=[ev("source", f"{UC}:1673", "POST /u/second_factors (check_confirmed_session)")],
    notes="Gated behind a recently-confirmed session."))

NODES.append(node(
    K("/u/second_factor"), "api", ["PUT"],
    variants=[variant("PUT", body_format="json", body_example={"second_factor_target": 1, "id": 3, "name": "phone"},
        request_fields=[rf("second_factor_target", "body", "integer", required=True, flow=True, description="2FA type target."),
                        rf("id", "body", "integer", required=False, flow=True, description="Specific factor id."),
                        rf("name", "body", "string", required=False, flow=True, description="Rename.")],
        response=resp_empty(), reason="Edits/renames/toggles a configured second factor.", evidence=f"{UC}:1872")],
    operation_semantic="update_second_factor", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self 2FA edit (confirmed session).",
    evidence=[ev("source", f"{UC}:1872", "PUT /u/second_factor require(:second_factor_target)")],
    notes=None))

NODES.append(node(
    K("/u/create_second_factor_totp"), "api", ["POST"],
    variants=[variant("POST", response=resp_json([of("key", "string", True, "TOTP secret to provision."),
                                                  of("qr", "string", False, "QR provisioning URI.")]),
        reason="Generates a pending TOTP secret for enrollment.", evidence=f"{UC}:1706")],
    operation_semantic="create_second_factor_totp", statuses=[200, 403], identity_statuses=ST_USER,
    sem_out_decisions=[dec("key", "TotpSecret(credential)", "credential", reason="Provisioning secret.")],
    route_confirmed=True, vis_reason="Self 2FA enrollment (confirmed session).",
    evidence=[ev("source", f"{UC}:1706", "POST /u/create_second_factor_totp")],
    notes="Issues a TOTP secret; activated by enable_second_factor_totp."))

NODES.append(node(
    K("/u/enable_second_factor_totp"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"second_factor_token": "123456", "name": "phone"},
        request_fields=[rf("second_factor_token", "body", "string", required=True, flow=True, description="TOTP code proving possession."),
                        rf("name", "body", "string", required=False, flow=True, description="Authenticator name.")],
        response=resp_empty(), reason="Activates TOTP after verifying a code.", evidence=f"{UC}:1830")],
    operation_semantic="enable_second_factor_totp", statuses=[200, 403, 422], identity_statuses=ST_USER,
    sem_in_decisions=[D_2FA],
    route_confirmed=True, vis_reason="Self 2FA activation.",
    evidence=[ev("source", f"{UC}:1830", "POST /u/enable_second_factor_totp")],
    notes=None))

NODES.append(node(
    K("/u/disable_second_factor"), "api", ["PUT"],
    variants=[variant("PUT", body_format="json", body_example={"second_factor_target": 1, "id": 3},
        request_fields=[rf("second_factor_target", "body", "integer", required=False, flow=True, description="Factor type."),
                        rf("id", "body", "integer", required=False, flow=True, description="Factor id.")],
        response=resp_empty(), reason="Removes a second factor (confirmed session).", evidence=f"{UC}:1858")],
    operation_semantic="disable_second_factor", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self 2FA removal (confirmed session).",
    evidence=[ev("source", f"{UC}:1858", "PUT /u/disable_second_factor")],
    notes="Weakens account auth; gated by confirmed session."))

NODES.append(node(
    K("/u/create_second_factor_security_key"), "api", ["POST"],
    variants=[variant("POST", response=resp_json([of("challenge", "string", True, "WebAuthn registration challenge.")]),
        reason="Stages a WebAuthn security-key registration challenge.", evidence=f"{UC}:1721")],
    operation_semantic="create_security_key", statuses=[200, 403], identity_statuses=ST_USER,
    sem_out_decisions=[dec("challenge", "WebauthnChallenge(credential)", "opaque", reason="Registration challenge.")],
    route_confirmed=True, vis_reason="Self security-key enrollment.",
    evidence=[ev("source", f"{UC}:1721", "POST /u/create_second_factor_security_key")],
    notes=None))

NODES.append(node(
    K("/u/register_second_factor_security_key"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"name": "key", "attestation": "...", "clientData": "..."},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="Key name."),
                        rf("attestation", "body", "string", required=True, flow=True, description="WebAuthn attestation object."),
                        rf("clientData", "body", "string", required=True, flow=True, description="WebAuthn client data.")],
        response=resp_empty(), reason="Completes security-key registration.", evidence=f"{UC}:1740")],
    operation_semantic="register_security_key", statuses=[200, 403, 422], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self security-key enrollment.",
    evidence=[ev("source", f"{UC}:1740", "POST /u/register_second_factor_security_key require(:name,:attestation,:clientData)")],
    notes=None))

NODES.append(node(
    K("/u/security_key"), "api", ["PUT"],
    variants=[variant("PUT", body_format="json", body_example={"id": 2, "name": "key", "enabled": True},
        request_fields=[rf("id", "body", "integer", required=True, flow=True, description="Security-key id."),
                        rf("name", "body", "string", required=False, flow=True, description="Rename."),
                        rf("enabled", "body", "boolean", required=False, flow=False, description="Toggle.")],
        response=resp_empty(), reason="Edits/toggles/removes a security key.", evidence=f"{UC}:1820")],
    operation_semantic="update_security_key", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self security-key management.",
    evidence=[ev("source", f"{UC}:1820", "PUT /u/security_key")],
    notes=None))

NODES.append(node(
    K("/u/second_factors_backup"), "api", ["PUT"],
    variants=[variant("PUT", response=resp_json([of("backup_codes", "array", True, "Generated one-time backup codes.")]),
        reason="Regenerates 2FA backup codes.", evidence=f"{UC}:1700")],
    operation_semantic="create_second_factor_backup", statuses=[200, 403], identity_statuses=ST_USER,
    sem_out_decisions=[dec("backup_codes", "BackupCodes(credential)", "credential", reason="One-time 2FA recovery codes.")],
    route_confirmed=True, vis_reason="Self 2FA backup-code generation.",
    evidence=[ev("source", f"{UC}:1700", "PUT /u/second_factors_backup")],
    notes="Returns recovery credentials (shown once)."))

NODES.append(node(
    K("/u/create_passkey"), "api", ["POST"],
    variants=[variant("POST", response=resp_json([of("challenge", "string", True, "Passkey registration challenge.")]),
        reason="Stages a passkey registration challenge.", evidence=f"{UC}:1756")],
    operation_semantic="create_passkey", statuses=[200, 403], identity_statuses=ST_USER,
    sem_out_decisions=[dec("challenge", "WebauthnChallenge(credential)", "opaque", reason="Registration challenge.")],
    route_confirmed=True, vis_reason="Self passkey enrollment.",
    evidence=[ev("source", f"{UC}:1756", "POST /u/create_passkey")],
    notes=None))

NODES.append(node(
    K("/u/register_passkey"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"name": "phone", "attestation": "...", "clientData": "..."},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="Passkey name."),
                        rf("attestation", "body", "string", required=True, flow=True, description="WebAuthn attestation."),
                        rf("clientData", "body", "string", required=True, flow=True, description="WebAuthn client data.")],
        response=resp_empty(), reason="Completes passkey registration.", evidence=f"{UC}:1771")],
    operation_semantic="register_passkey", statuses=[200, 403, 422], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self passkey enrollment.",
    evidence=[ev("source", f"{UC}:1771", "POST /u/register_passkey require(:name,:attestation,:clientData)")],
    notes=None))

NODES.append(node(
    K("/u/rename_passkey/{id}"), "api", ["PUT"],
    params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Passkey id."}],
    variants=[variant("PUT", body_format="json", body_example={"name": "newname"},
        request_fields=[rf("name", "body", "string", required=True, flow=True, description="New passkey name.")],
        response=resp_empty(), reason="Renames a passkey.", evidence=f"{UC}:1807")],
    operation_semantic="rename_passkey", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self passkey rename.",
    evidence=[ev("source", f"{UC}:1807", "PUT /u/rename_passkey/:id require(:id,:name)")],
    notes=None))

NODES.append(node(
    K("/u/delete_passkey/{id}"), "api", ["DELETE"],
    params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Passkey id."}],
    variants=[variant("DELETE", response=resp_empty(), reason="Deletes a passkey.", evidence=f"{UC}:1791")],
    operation_semantic="delete_passkey", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self passkey removal.",
    evidence=[ev("source", f"{UC}:1791", "DELETE /u/delete_passkey/:id")],
    notes=None))

NODES.append(node(
    K("/u/trusted-session"), "api", ["GET"],
    variants=[variant("GET", response=resp_json([of("failed", "string", False, "OK or failure reason.")]),
        reason="Reports whether the session is recently password-confirmed.", evidence=f"{UC}:1669")],
    operation_semantic="trusted_session", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self confirmed-session check.",
    evidence=[ev("source", f"{UC}:1669", "GET /u/trusted-session")],
    notes="Gate state for sensitive-action step-up."))

NODES.append(node(
    K("/u/confirm-session"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"password": "***"},
        request_fields=[rf("password", "body", "string", required=False, flow=True, description="Password to confirm the session.")],
        response=resp_json([of("success", "string", False, "Confirmation result.")]),
        reason="Confirms the current session (password/passkey) for sensitive operations.", evidence=f"{UC}:1655")],
    operation_semantic="confirm_session", statuses=[200, 403], identity_statuses=ST_USER,
    sem_in_decisions=[D_PASSWD],
    route_confirmed=True, vis_reason="Self session confirmation (step-up).",
    evidence=[ev("source", f"{UC}:1655", "POST /u/confirm-session")],
    notes="Elevates the session to 'trusted' for 2FA/account changes."))

# ---- Account lifecycle / token flows (anonymous, token-gated) --------------
NODES.append(node(
    K("/u/password-reset/{token}"), "api", ["GET", "PUT"],
    params=[{"name": "token", "in": "path", "type": "string", "required": True, "flow": True, "description": "Password-reset token."}],
    variants=[variant("GET", response=resp_json([of("can_edit", "boolean", False, "Whether the token is valid."),
                                                 of("second_factor_required", "boolean", False, "Whether 2FA is needed.")]),
                      reason="Validates a reset token and reports 2FA requirement.", evidence=f"{UC}:897"),
              variant("PUT", body_format="json", body_example={"password": "***", "second_factor_token": "123456"},
                      request_fields=[rf("password", "body", "string", required=True, flow=True, description="New password."),
                                      rf("second_factor_token", "body", "string", required=False, flow=True, description="2FA token.")],
                      response=resp_json([of("success", "boolean", False, "Reset result.")]),
                      reason="Sets a new password via the reset token (enforces 2FA).", evidence=f"{UC}:955")],
    operation_semantic="password_reset", statuses=[200, 400, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_PASSWD, D_2FA],
    route_confirmed=True, vis_reason="Token-gated credential reset.",
    evidence=[ev("source", f"{UC}:897", "GET /u/password-reset/:token -> password_reset_show"),
              ev("source", f"{UC}:955", "PUT /u/password-reset/:token -> password_reset_update")],
    notes="Primary password-reset redemption; token is the credential; 2FA enforced; rate-limited."))

NODES.append(node(
    K("/u/activate-account/{token}"), "api", ["GET", "PUT"],
    params=[{"name": "token", "in": "path", "type": "string", "required": True, "flow": True, "description": "Email activation token."}],
    variants=[variant("GET", response=resp_raw("Activation confirmation page / JSON."),
                      reason="Shows account activation for a token.", evidence=f"{UC}:1197"),
              variant("PUT", response=resp_json([of("success", "boolean", False, "Activation result.")]),
                      reason="Activates the account (perform_account_activation).", evidence=f"{UC}:1208")],
    operation_semantic="activate_account", statuses=[200, 400], identity_statuses=ST_PUBLIC,
    route_confirmed=True, vis_reason="Token-gated account activation.",
    evidence=[ev("source", f"{UC}:1197", "GET/PUT /u/activate-account/:token")],
    notes="Confirms email ownership; may auto-approve."))

NODES.append(node(
    K("/u/update-activation-email"), "api", ["PUT"],
    variants=[variant("PUT", body_format="json", body_example={"username": "alice", "password": "***", "email": "new@b.co"},
        request_fields=[rf("username", "body", "string", required=False, flow=True, description="Account username."),
                        rf("password", "body", "string", required=False, flow=True, description="Password (for unactivated account)."),
                        rf("email", "body", "string", required=True, flow=True, description="Corrected activation email.")],
        response=resp_empty(), reason="Changes the email on an as-yet-unactivated account.", evidence=f"{UC}:1256")],
    operation_semantic="update_activation_email", statuses=[200, 403, 422, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_USERNAME, D_PASSWD, D_EMAIL],
    route_confirmed=True, vis_reason="Pre-activation email correction.",
    evidence=[ev("source", f"{UC}:1256", "PUT /u/update-activation-email")],
    notes="Pre-activation email change (password-gated when a password exists)."))

NODES.append(node(
    K("/u/action/send_activation_email"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"username": "alice"},
        request_fields=[rf("username", "body", "string", required=True, flow=True, description="Account to resend activation to.")],
        response=resp_empty(), reason="Resends the activation email (rate limited).", evidence=f"{UC}:1312")],
    operation_semantic="send_activation_email", statuses=[200, 422, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_USERNAME],
    route_confirmed=True, vis_reason="Public activation-resend.",
    evidence=[ev("source", f"{UC}:1312", "POST /u/action/send_activation_email")],
    notes="Rate-limited; enumeration-resistant."))

NODES.append(node(
    K("/u/confirm-email-token/{token}"), "api", ["GET"],
    params=[{"name": "token", "in": "path", "type": "string", "required": True, "flow": True, "description": "Email confirmation token."}],
    variants=[variant("GET", response=resp_json([of("success", "string", False, "Confirmation result.")]),
        reason="Confirms an email-change token.", evidence=f"{UC}:1066")],
    operation_semantic="confirm_email_token", statuses=[200, 400], identity_statuses=ST_PUBLIC,
    route_confirmed=True, vis_reason="Token-gated email confirmation.",
    evidence=[ev("source", f"{UC}:1066", "GET /u/confirm-email-token/:token")],
    notes=None))

NODES.append(node(
    K("/u/admin-login"), "api", ["GET", "PUT"],
    variants=[variant("GET", response=resp_raw("Admin email-login request page."),
                      reason="Shows the emergency admin email-login form.", evidence=f"{UC}:1086"),
              variant("PUT", body_format="json", body_example={"email": "admin@b.co"},
                      request_fields=[rf("email", "body", "string", required=True, flow=True, description="Admin email to send a login link to.")],
                      response=resp_raw("Generic acknowledgement."),
                      reason="Emails an admin a one-time login link (recovery path).", evidence=f"{UC}:1086")],
    operation_semantic="admin_login", statuses=[200, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[D_EMAIL],
    route_confirmed=True, vis_reason="Emergency admin-recovery login.",
    reach_conds=["Only effective for admin accounts / recovery scenarios"],
    evidence=[ev("source", f"{UC}:1086", "GET/PUT /u/admin-login")],
    notes="Admin account-recovery path; sends a login link to the admin email."))

NODES.append(node(
    K("/u/confirm-admin/{token}"), "api", ["GET", "POST"],
    params=[{"name": "token", "in": "path", "type": "string", "required": True, "flow": True, "description": "Grant-admin token."}],
    variants=[variant("GET", response=resp_raw("Confirm-admin page."), reason="Shows the grant-admin confirmation.", evidence=f"{UC}:1636"),
              variant("POST", response=resp_empty(), reason="Redeems a grant-admin token (bootstrap admin).", evidence=f"{UC}:1636")],
    operation_semantic="confirm_admin", statuses=[200, 400], identity_statuses=ST_PUBLIC,
    route_confirmed=True, vis_reason="Token-gated admin grant (bootstrap).",
    evidence=[ev("source", f"{UC}:1636", "GET/POST /u/confirm-admin/:token")],
    notes="PRIVILEGE GRANT: redeeming the emailed token makes the account an admin."))

NODES.append(node(
    K("/u/email-login"), "api", ["POST"],
    variants=[variant("POST", body_format="json", body_example={"login": "alice@b.co"},
        request_fields=[rf("login", "body", "string", required=True, flow=True, description="Email/username to send a login link.")],
        response=resp_empty(), reason="Requests a passwordless email-login link.", evidence=f"{UC}:1112")],
    operation_semantic="request_email_login", statuses=[200, 429], identity_statuses=ST_PUBLIC_RL,
    sem_in_decisions=[dec("login", "LoginName(identity)", "identifier", reference_capable=True, reason="Account to email.")],
    route_confirmed=True, vis_reason="Public email-login request.",
    reach_conds=["enable_local_logins_via_email"],
    evidence=[ev("source", f"{UC}:1112", "POST /u/email-login require(:login)")],
    notes="Pairs with SessionController email-login redemption; enumeration-resistant."))

# ---- Minor self endpoints --------------------------------------------------
NODES.append(node(
    K("/u/toggle-anon"), "api", ["POST"],
    variants=[variant("POST", response=resp_empty(), reason="Toggles anonymous posting mode.", evidence=f"{UC}:1153")],
    operation_semantic="toggle_anon", statuses=[200, 403], identity_statuses=ST_USER,
    route_confirmed=True, vis_reason="Self anon-mode toggle.",
    reach_conds=["allow_anonymous_mode"],
    evidence=[ev("source", f"{UC}:1153", "POST /u/toggle-anon")],
    notes="Switches to the shadow anonymous account."))

NODES.append(node(
    K("/u/recent-searches"), "api", ["GET", "DELETE"],
    variants=[variant("GET", response=resp_json([of("recent_searches", "array", True, "The caller's recent searches.")]),
                      reason="Reads recent search history.", evidence=f"{UC}:1581"),
              variant("DELETE", response=resp_empty(), reason="Clears recent search history.", evidence=f"{UC}:1611")],
    operation_semantic="recent_searches", statuses=[200, 403], identity_statuses=ST_USER,
    sem_out_decisions=[dec("recent_searches", "SearchHistory(privacy)", "collection", reason="Caller's own search terms.")],
    route_confirmed=True, vis_reason="Self search-history management.",
    evidence=[ev("source", f"{UC}:1581", "GET/DELETE /u/recent-searches")],
    notes="Per-user search history (privacy-relevant)."))
