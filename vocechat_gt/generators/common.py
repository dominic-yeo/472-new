"""Shared helpers for the VoceChat GT generator (source-first)."""
import re, os, functools

ROOT = "C:/Users/User/Documents/pengent_web_gt_schema_student_v1/"
SRV = ROOT + "vocechat_src/vocechat-server-rust-0.5.36/"
WEB = ROOT + "vocechat_src/vocechat-web/"
BASE = "http://localhost:3009"
API = BASE + "/api"

# ---------------------------------------------------------------- source line resolution
@functools.lru_cache(None)
def _lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().split("\n")

def srv_ref(fname, fn):
    """file:line of the #[oai(...)] attribute of handler `fn` in src/api/<fname>."""
    p = SRV + "src/api/" + fname
    L = _lines(p)
    for i, l in enumerate(L):
        if re.search(r"async fn %s\s*\(" % re.escape(fn), l):
            j = i
            while j > 0 and "#[oai(" not in L[j]:
                j -= 1
            return f"vocechat-server-rust-0.5.36/src/api/{fname}:{j+1}"
    raise KeyError((fname, fn))

def web_ref(fname, ep):
    """file:line of an RTK endpoint definition `ep:` in src/app/services/<fname>, or a raw grep in src/."""
    if "/" in fname or not os.path.exists(WEB + "src/app/services/" + fname):
        p = WEB + "src/" + fname
        L = _lines(p)
        for i, l in enumerate(L):
            if ep in l:
                return f"vocechat-web/src/{fname}:{i+1}"
        raise KeyError((fname, ep))
    p = WEB + "src/app/services/" + fname
    L = _lines(p)
    for i, l in enumerate(L):
        if re.match(r"\s*%s: builder\." % re.escape(ep), l):
            return f"vocechat-web/src/app/services/{fname}:{i+1}"
    raise KeyError((fname, ep))

def src_line(rel, pattern):
    """file:line of first regex match in a server/web relative path."""
    p = ROOT + "vocechat_src/" + rel
    for i, l in enumerate(_lines(p)):
        if re.search(pattern, l):
            return f"{rel}:{i+1}"
    raise KeyError((rel, pattern))

# ---------------------------------------------------------------- field constructors
def F(name, loc, type="string", required=True, flow=True, desc="", path="", sel=None):
    d = {"name": name, "location": loc, "path": path or (name if loc == "body" else ""), "type": type,
         "required": required, "flow": flow, "description": desc}
    if sel: d["_sel"] = sel
    return d

def P(name, type="integer", desc="", flow=True):
    return F(name, "path", type, True, flow, desc)

def Q(name, type="string", required=True, flow=True, desc=""):
    return F(name, "query", type, required, flow, desc)

def H(name, type="string", required=True, flow=False, desc=""):
    return F(name, "header", type, required, flow, desc)

def B(name, type="string", required=True, flow=True, desc="", path=None, sel=None):
    return F(name, "body", type, required, flow, desc, path=path if path is not None else name, sel=sel)

def R(name, path=None, type="string", flow=True, desc=""):
    return {"name": name, "path": path if path is not None else name, "type": type, "flow": flow, "description": desc}

TOKEN_H = H("X-API-Key", desc="Access token (JWT-like, HS256) issued by /token/login; authentication header, not business data.")
BOTKEY_H = H("x-api-key", desc="Bot API key (hex HMAC blob) created by an admin; authentication header.")
PROPS_H = H("X-Properties", required=False,
            desc="Optional base64(JSON) message properties (mentions, local_id, reply metadata); presentation metadata.")

# ---------------------------------------------------------------- reusable response shapes
def userinfo(prefix="", extra=False):
    p = (prefix + ".") if prefix and not prefix.endswith("]") else prefix
    if prefix.endswith("]"):
        p = prefix + "."
    out = [
        R("uid", p + "uid", "integer", True, "User id."),
        R("email", p + "email", "string", True, "Account e-mail (nullable)."),
        R("name", p + "name", "string", True, "Display name (unique)."),
        R("gender", p + "gender", "integer", False, "Gender code."),
        R("language", p + "language", "string", False, "UI language tag."),
        R("is_admin", p + "is_admin", "boolean", True, "Administrator flag."),
        R("is_bot", p + "is_bot", "boolean", False, "Bot account flag."),
        R("avatar_updated_at", p + "avatar_updated_at", "integer", False, "Avatar version timestamp (ms)."),
        R("create_by", p + "create_by", "string", False, "Account creation method."),
    ]
    return out

def admin_user(prefix=""):
    p = prefix + "." if prefix else ""
    return [
        R("uid", p + "uid", "integer", True, "User id."),
        R("email", p + "email", "string", True, "Account e-mail."),
        R("password", p + "password", "string", False, "Always empty string in api_user() (state.rs:169); not disclosed."),
        R("name", p + "name", "string", True, "Display name."),
        R("gender", p + "gender", "integer", False, "Gender code."),
        R("is_admin", p + "is_admin", "boolean", True, "Administrator flag."),
        R("language", p + "language", "string", False, "Language tag."),
        R("create_by", p + "create_by", "string", False, "Creation method."),
        R("in_online", p + "in_online", "boolean", False, "Online flag."),
        R("online_devices", p + "online_devices[].device", "string", True, "Logged-in device ids of the user."),
        R("device_token", p + "online_devices[].device_token", "string", True, "FCM push token of each device (sensitive)."),
        R("created_at", p + "created_at", "integer", False, "Creation timestamp."),
        R("updated_at", p + "updated_at", "integer", False, "Update timestamp."),
        R("avatar_updated_at", p + "avatar_updated_at", "integer", False, "Avatar version."),
        R("status", p + "status", "string", True, "Account status normal|frozen."),
        R("webhook_url", p + "webhook_url", "string", True, "Bot webhook URL."),
        R("is_bot", p + "is_bot", "boolean", False, "Bot flag."),
    ]

def group(prefix=""):
    p = (prefix + ".") if prefix and not prefix.endswith("]") else (prefix + "." if prefix else "")
    return [
        R("gid", p + "gid", "integer", True, "Group (channel) id."),
        R("owner", p + "owner", "integer", True, "Owner uid; null for public groups."),
        R("group_name", p + "name", "string", True, "Group name."),
        R("description", p + "description", "string", True, "Group description."),
        R("members", p + "members[]", "integer", True, "Member uids (empty for public groups)."),
        R("is_public", p + "is_public", "boolean", True, "Public/private group flag."),
        R("avatar_updated_at", p + "avatar_updated_at", "integer", False, "Avatar version."),
        R("pinned_mid", p + "pinned_messages[].mid", "integer", True, "Pinned message ids."),
        R("pinned_content", p + "pinned_messages[].content", "string", True, "Pinned message content."),
    ]

def chatmsg(prefix="[]"):
    p = prefix + "." if prefix else ""
    return [
        R("mid", p + "mid", "integer", True, "Message id."),
        R("from_uid", p + "from_uid", "integer", True, "Sender uid."),
        R("created_at", p + "created_at", "integer", False, "Send timestamp."),
        R("target_uid", p + "target.uid", "integer", True, "DM peer uid (DM messages)."),
        R("target_gid", p + "target.gid", "integer", True, "Group id (group messages)."),
        R("detail_type", p + "detail.type", "string", False, "normal|reaction|reply discriminator."),
        R("content", p + "detail.content", "string", True, "Message body / file path."),
        R("content_type", p + "detail.content_type", "string", False, "MIME of content."),
        R("ref_mid", p + "detail.mid", "integer", True, "Referenced message id for reaction/reply records."),
        R("properties", p + "detail.properties", "object", False, "Extended attributes."),
    ]

def archive(prefix=""):
    p = prefix + "." if prefix else ""
    return [
        R("archive_user_name", p + "users[].name", "string", True, "Display names of archived message senders."),
        R("archive_mid", p + "messages[].mid", "integer", True, "Original message ids in archive."),
        R("archive_from_user", p + "messages[].from_user", "integer", False, "Index into users[] (not a uid)."),
        R("archive_source_uid", p + "messages[].source.uid", "integer", True, "DM source uid."),
        R("archive_source_gid", p + "messages[].source.gid", "integer", True, "Group source gid."),
        R("archive_content", p + "messages[].content", "string", True, "Archived message content."),
        R("archive_file_id", p + "messages[].file_id", "integer", True, "Attachment index (attachment_id) of a file message."),
        R("num_attachments", p + "num_attachments", "integer", False, "Attachment count."),
    ]

# ---------------------------------------------------------------- semantic dictionary
# raw_field -> (resource, mergeable, value_kind, reference_capable, reason)
SEM = {
    "uid": ("UserID(user)", True, "identifier", True, "Stable numeric user id used across user/admin/message/avatar endpoints."),
    "target_uid": ("UserID(user)", True, "identifier", True, "Stable user id of the DM peer / contact target."),
    "from_uid": ("UserID(user)", True, "identifier", True, "Stable user id of the sender."),
    "owner": ("UserID(user)", True, "identifier", True, "Owner uid; a stable user reference."),
    "members": ("UserID(user)", True, "identifier", True, "Each element is a stable user id."),
    "created_by": ("UserID(user)", True, "identifier", True, "Uid of the creator."),
    "bot_uid": ("UserID(user)", True, "identifier", True, "Uid of a bot account."),
    "archive_source_uid": ("UserID(user)", True, "identifier", True, "Uid of a DM peer inside the archive."),
    "gid": ("GroupID(group)", True, "identifier", True, "Stable group (channel) id used across group/message/avatar endpoints."),
    "target_gid": ("GroupID(group)", True, "identifier", True, "Stable group id of a group message."),
    "archive_source_gid": ("GroupID(group)", True, "identifier", True, "Group id inside the archive."),
    "mid": ("MessageID(message)", True, "identifier", True, "Stable message id used by edit/like/delete/reply/pin/read-index/archive."),
    "mids": ("MessageID(message)", True, "identifier", True, "Comma-separated stable message ids."),
    "mid_list": ("MessageID(message)", True, "identifier", True, "Each element is a stable message id."),
    "ref_mid": ("MessageID(message)", True, "identifier", True, "Id of the message a reaction/reply refers to."),
    "pinned_mid": ("MessageID(message)", True, "identifier", True, "Id of a pinned message."),
    "archive_mid": ("MessageID(message)", True, "identifier", True, "Original message id preserved in the archive."),
    "before": ("MessageID(message)", True, "identifier", True, "Pagination cursor: a stable message id."),
    "after_mid": ("MessageID(message)", True, "identifier", True, "Resume cursor: a stable message id."),
    "email": ("UserEmail(user)", True, "attribute", False, "Account e-mail address; business attribute of the account, not used as an object reference in URLs."),
    "name": ("UserName(user)", True, "attribute", False, "User display name; attribute, not a reference."),
    "password": ("UserPassword(user)", True, "credential", False, "Account password (credential)."),
    "old_password": ("UserPassword(user)", True, "credential", False, "Current password presented as proof (credential)."),
    "new_password": ("UserPassword(user)", True, "credential", False, "New password value (credential)."),
    "is_admin": ("UserAdminFlag(user)", True, "state", False, "Privilege state of the account."),
    "status": ("UserStatus(user)", True, "state", False, "Account status normal/frozen."),
    "webhook_url": ("UserWebhookURL(user)", True, "attribute", False, "Bot webhook URL attribute."),
    "token": ("AccessToken(session)", True, "credential", False, "Short-lived access token (credential)."),
    "api-key": ("AccessToken(session)", True, "credential", False, "Access token passed in query for EventSource (credential)."),
    "refresh_token": ("RefreshToken(session)", True, "credential", False, "Refresh token (credential)."),
    "server_id": ("ServerID(server)", True, "attribute", False, "Server identity string; informational, not passed to other APIs."),
    "device": ("DeviceID(device)", True, "identifier", True, "Device id; identifies a login session/device and is accepted by DELETE /user/devices/{device}."),
    "online_devices": ("DeviceID(device)", True, "identifier", True, "Device ids of a user."),
    "device_token": ("DeviceToken(device)", True, "credential", False, "FCM push token bound to a device (secret-like)."),
    "fcm_token": ("DeviceToken(device)", True, "credential", False, "FCM push token bound to a device."),
    "magic_token": ("MagicToken(magic_link)", True, "credential", False, "Signed magic-link / invitation token (bearer credential)."),
    "new_magic_token": ("MagicToken(magic_link)", True, "credential", False, "Signed registration magic token (bearer credential)."),
    "magic_link": ("MagicLinkURL(magic_link)", True, "credential", False, "Invitation URL embedding a bearer magic token."),
    "group_name": ("GroupName(group)", True, "attribute", False, "Group display name."),
    "description": ("GroupDescription(group)", True, "attribute", False, "Group description text."),
    "is_public": ("GroupVisibility(group)", True, "state", False, "Public/private state of a group."),
    "pinned_content": ("MessageContent(message)", True, "content", False, "Message content."),
    "content": ("MessageContent(message)", True, "content", False, "Message content (free text / markdown / file path payload)."),
    "archive_content": ("MessageContent(message)", True, "content", False, "Archived message content."),
    "archive_user_name": ("UserName(user)", True, "attribute", False, "Sender display name embedded in archive."),
    "action": ("ReactionEmoji(reaction)", True, "attribute", False, "Emoji reaction value from a fixed allow-list."),
    "file_id": ("UploadID(upload)", True, "identifier", True, "UUID of an in-progress upload returned by /file/prepare and consumed by /file/upload."),
    "upload_id": ("UploadID(upload)", True, "identifier", True, "UUID of an in-progress upload returned by /file/prepare."),
    "file_path": ("FilePath(file)", True, "locator", True, "Stored file locator {yyyy}/{m}/{d}/{uuid} used by /resource/file and file messages."),
    "path": ("FilePath(file)", True, "locator", True, "Stored file locator returned after the last chunk."),
    "chunk_data": ("FileContent(file)", True, "content", False, "Raw file bytes (content)."),
    "hash": ("FileHash(file)", True, "attribute", False, "SHA-256 of stored file; attribute."),
    "size": ("FileSize(file)", False, "attribute", False, "File size; display attribute."),
    "filename": ("FileName(file)", True, "attribute", False, "Original filename attribute."),
    "archive_path": ("ArchivePath(archive)", True, "locator", True, "Archive locator {yyyy}/{m}/{d}/{uuid} accepted by /resource/archive and vocechat/archive messages."),
    "archive_file_id": ("ArchiveAttachmentID(archive_attachment)", True, "identifier", True, "Attachment index inside an archive accepted as attachment_id."),
    "attachment_id": ("ArchiveAttachmentID(archive_attachment)", True, "identifier", True, "Attachment index inside an archive."),
    "favorite_id": ("FavoriteID(favorite)", True, "identifier", True, "Favorite archive UUID used by /favorite/{id}."),
    "id": ("FavoriteID(favorite)", True, "identifier", True, "Favorite archive UUID."),
    "kid": ("BotKeyID(bot_key)", True, "identifier", True, "Bot API key row id used by DELETE /admin/user/bot-api-key/{uid}/{kid}."),
    "bot_key_id": ("BotKeyID(bot_key)", True, "identifier", True, "Bot API key row id."),
    "bot_key_name": ("BotKeyName(bot_key)", True, "attribute", False, "Label of a bot key."),
    "api_key": ("BotAPIKey(bot_key)", True, "credential", False, "Bot API key secret (credential)."),
    "third_party_secret": ("ThirdPartySecret(server)", True, "credential", False, "Server-wide shared secret for third-party login key minting."),
    "X-SECRET": ("ThirdPartySecret(server)", True, "credential", False, "Server-wide third-party secret presented in header."),
    "third_party_key": ("ThirdPartyLoginKey(session)", True, "credential", False, "HMAC-signed short-lived third-party login key."),
    "key": ("ThirdPartyLoginKey(session)", True, "credential", False, "Third-party login key presented as credential."),
    "userid": ("ThirdPartyUserID(external_account)", True, "identifier", False, "External user id embedded in third-party key (not an object reference inside VoceChat)."),
    "username": ("ThirdPartyUserName(external_account)", True, "attribute", False, "External username."),
    "license": ("LicenseBlob(license)", True, "credential", False, "Signed base58 license blob."),
    "base58": ("LicenseBlob(license)", True, "credential", False, "Signed base58 license blob."),
    "url": ("ExternalURL(url)", True, "locator", False, "Arbitrary external URL fetched server-side; not an object of this application."),
    "frontend_url": ("FrontendURL(server)", True, "attribute", False, "Public frontend URL used in magic links."),
    "org_name": ("OrganizationName(server)", True, "attribute", False, "Organization display name."),
    "org_description": ("OrganizationDescription(server)", True, "attribute", False, "Organization description."),
    "logo": ("OrganizationLogo(server)", True, "content", False, "Organization logo bytes."),
    "avatar": ("AvatarImage(user)", True, "content", False, "PNG avatar bytes."),
    "group_avatar": ("AvatarImage(group)", True, "content", False, "PNG group avatar bytes."),
    "file_bytes": ("FileContent(file)", True, "content", False, "File bytes."),
    "attachment_bytes": ("FileContent(archive_attachment)", True, "content", False, "Archive attachment bytes."),
    "agora_token": ("AgoraToken(call)", True, "credential", False, "RTC token for Agora channel."),
    "channel_name": ("AgoraChannelName(call)", True, "identifier", False, "Agora channel name vocechat:group:{gid}; derived from gid."),
    "app_id": ("AgoraAppID(server)", True, "attribute", False, "Agora app id."),
    "config_secret": ("IntegrationSecret(server)", True, "credential", False, "Integration secret (client_secret/app_certificate/private_key/password)."),
    "config_value": ("IntegrationConfig(server)", True, "attribute", False, "Integration configuration attribute."),
    "enabled": ("FeatureEnabled(server)", True, "state", False, "Feature enabled flag."),
    "login_config": ("LoginPolicy(server)", True, "state", False, "Login/sign-up policy flag."),
    "public_address": ("WalletAddress(external_account)", True, "attribute", False, "MetaMask wallet address."),
    "nonce": ("WalletNonce(external_account)", True, "credential", False, "Single-use MetaMask signing nonce."),
    "signature": ("WalletSignature(external_account)", True, "credential", False, "Wallet signature (credential)."),
    "id_token": ("ExternalIdToken(external_account)", True, "credential", False, "Google ID token (credential)."),
    "code": ("OAuthCode(external_account)", True, "credential", False, "OAuth authorisation code (credential)."),
    "state": ("OAuthState(external_account)", True, "credential", False, "OIDC CSRF state (credential-like nonce)."),
    "issuer": ("OIDCIssuer(server)", True, "attribute", False, "OIDC issuer domain configured by admin."),
    "redirect_uri": ("ExternalURL(url)", True, "locator", False, "Client redirect URL; not an application object."),
    "auth_url": ("ExternalURL(url)", True, "locator", False, "Provider authorisation URL."),
    "expired_in": ("TokenExpiry(session)", False, "attribute", False, "Expiry seconds; protocol attribute."),
    "expires_in": ("BurnAfterReadingSeconds(conversation_setting)", True, "state", False, "Burn-after-reading period setting."),
    "mute_expired_in": ("MuteExpiry(conversation_setting)", True, "state", False, "Mute duration seconds."),
    "announcement": ("GroupAnnouncementContent(group)", True, "content", False, "Group announcement text."),
    "remark": ("ContactRemark(contact)", True, "attribute", False, "Private remark on a contact."),
    "contact_action": ("ContactAction(contact)", True, "state", False, "add/remove/block/unblock transition."),
    "contact_status": ("ContactStatus(contact)", True, "state", False, "Contact relation status added/blocked."),
    "search_type": ("UserSearchType(search)", False, "attribute", False, "Search discriminator id|email|name."),
    "keyword": ("UserSearchKeyword(search)", True, "attribute", False, "Search term (uid/email/name of target)."),
    "credential_id": ("PasskeyCredentialID(passkey)", True, "identifier", True, "WebAuthn credential id; accepted by DELETE /token/passkey/{credential_id}."),
    "challenge_id": ("PasskeyChallengeID(passkey_challenge)", True, "identifier", True, "Challenge id issued by */start and consumed by */finish."),
    "passkey_name": ("PasskeyName(passkey)", True, "attribute", False, "Passkey label."),
    "webauthn": ("WebAuthnAssertion(passkey)", True, "credential", False, "WebAuthn attestation/assertion payload."),
    "notif_channel_id": ("NotificationChannelID(notification_channel)", True, "identifier", True, "Per-user notification channel id used by PUT/DELETE/test."),
    "channel_type": ("NotificationChannelType(notification_type)", True, "identifier", True, "Notification provider type key (telegram, discord ...); used in DELETE /admin/notification/channel-types/{channel_type}."),
    "notif_config": ("NotificationChannelConfig(notification_channel)", True, "credential", False, "Provider config (webhook URLs / bot tokens)."),
    "page": ("CustomPageName(custom_page)", True, "identifier", True, "Custom page slot landing|after_signin."),
    "html": ("CustomPageHTML(custom_page)", True, "content", False, "Admin-supplied HTML content."),
    "page_api_key": ("PageAPIKey(custom_page)", True, "credential", False, "API key for page management."),
    "css": ("WidgetCSS(server)", True, "content", False, "Widget extra CSS content."),
    "common_setting": ("SystemSetting(server)", True, "state", False, "Server-wide feature switch / setting."),
    "page_no": ("PageNumber(pagination)", False, "attribute", False, "Pagination index."),
    "page_size": ("PageSize(pagination)", False, "attribute", False, "Pagination size."),
    "limit": ("PageSize(pagination)", False, "attribute", False, "Pagination size."),
    "users_version": ("UserLogVersion(user_log)", True, "state", False, "Client-side users snapshot version cursor."),
    "group_ext": ("GroupSetting(group)", True, "state", False, "Group behaviour switch."),
    "vocespace": ("VocespaceConfig(server)", True, "attribute", False, "VoceSpace integration setting."),
    "tunnel": ("TunnelStatus(server)", True, "state", False, "Cloudflared tunnel status/url."),
    "metrics": ("ServerMetric(server)", False, "summary", False, "Aggregate counts."),
    "version": ("ServerVersion(server)", True, "attribute", False, "Server build version string."),
    "initialized": ("ServerInitialized(server)", True, "state", False, "Whether an admin account exists."),
    "bool_result": ("OperationResult(result)", False, "summary", False, "Boolean result flag."),
    "count_result": ("OperationResult(result)", False, "summary", False, "Affected-row count."),
    "og": ("OpenGraphMetadata(url)", False, "summary", False, "Open-Graph metadata scraped from an external page."),
    "events": ("EventStream(session)", True, "collection", False, "SSE stream of users_snapshot/related_groups/chat/... events."),
    "html_page": ("StaticDocument(frontend)", False, "content", False, "HTML document."),
    "agora_channels": ("AgoraChannelName(call)", True, "collection", False, "Active voice channel names."),
    "files_list": ("FilePath(file)", True, "collection", False, "File listing."),
    "license_domains": ("LicenseDomain(license)", True, "attribute", False, "Licensed domains."),
    "user_limit": ("LicenseUserLimit(license)", True, "attribute", False, "Licensed user cap."),
    "sign": ("LicenseSignatureValid(license)", True, "state", False, "Signature validity flag."),
    "mail_to": ("EmailRecipient(mail)", True, "attribute", False, "Recipient address of an outgoing mail."),
    "mail_subject": ("EmailSubject(mail)", True, "content", False, "Mail subject."),
    "mail_content": ("EmailContent(mail)", True, "content", False, "Mail body."),
    "mail_is_sent": ("OperationResult(result)", False, "summary", False, "Whether mail was dispatched."),
    "credential_flags": ("LinkedCredential(account_credential)", True, "attribute", False, "Which login credentials are bound to the account."),
    "conv_last_mid": ("MessageID(message)", True, "identifier", True, "Last message id in a conversation."),
    "agora_users": ("UserID(user)", True, "identifier", True, "Uids present in an Agora channel."),
    "file_list_mid": ("MessageID(message)", True, "identifier", True, "Id of the message that carries the file."),
    "file_type": ("FileType(file)", False, "attribute", False, "Filter category."),
    "creation_time_type": ("FileAge(file)", False, "attribute", False, "Filter window."),
    "rtc_target_uid": ("UserID(user)", True, "identifier", True, "DM peer uid for a call token."),
    "rtc_target_gid": ("GroupID(group)", True, "identifier", True, "Group id for a call token."),
    # ---- binary-only 0.5.36 endpoints (from /api/spec) ----
    "command": ("BotCommandText(bot_command)", True, "content", False, "Slash-command trigger text of a bot command."),
    "command_desc": ("BotCommandDescription(bot_command)", True, "attribute", False, "Human description of a bot command."),
    "command_id": ("BotCommandID(bot_command)", True, "identifier", True, "Stable id of a bot slash-command row."),
    "bot_secret": ("BotSecret(bot)", True, "credential", False, "Per-bot shared secret used to verify webhook callbacks."),
    "to_uid": ("UserID(user)", True, "identifier", True, "Recipient uid of an in-server mail."),
    "avo_params": ("AvatarParams(user)", True, "attribute", False, "Generative avatar (Avo) parameters of the user."),
    "avo_name": ("AvatarParams(user)", True, "attribute", False, "Avo seed name."),
    "avo_variant": ("AvatarParams(user)", True, "attribute", False, "Avo variant."),
    "avo_hue": ("AvatarParams(user)", True, "attribute", False, "Avo hue."),
    "avo_style": ("AvatarParams(user)", True, "attribute", False, "Avo style."),
    "avo_energy": ("AvatarParams(user)", True, "attribute", False, "Avo energy."),
    "conv_comment": ("ConversationComment(conversation_setting)", True, "attribute", False, "Per-conversation comment/note."),
    "context": ("MessageContext(message)", False, "attribute", False, "Message context discriminator for bot message history."),
    "hosts_only": ("AgoraHostsFilter(call)", False, "attribute", False, "Filter: only channel hosts."),
    "agora_event": ("AgoraChannelEvent(call)", True, "content", False, "Agora channel event payload delivered to the webhook."),
    "webclient_update": ("WebClientVersion(server)", True, "state", False, "Web client self-update trigger/state."),
    "parse_result": ("TokenClaims(session)", False, "summary", False, "Decoded token claims echoed back by parse_tokens."),
    "agora_user_property": ("AgoraUserProperty(call)", False, "summary", False, "Per-user property inside an Agora channel."),
    "command_list": ("BotCommandID(bot_command)", True, "identifier", True, "Bot command ids in a listing."),
    "user_id": ("UserID(user)", True, "identifier", True, "Sender uid filter for bot group message history."),
    "room_type": ("VoiceRoomType(voice_room)", False, "attribute", False, "Voice/Avo room type (group|dm)."),
    "room_id": ("GroupID(group)", True, "identifier", True, "Voice/Avo room id (group/dm id)."),
    "events_uid": ("UserID(user)", True, "identifier", True, "User id delivered inside the event stream."),
    "events_gid": ("GroupID(group)", True, "identifier", True, "Group id delivered inside the event stream."),
    "events_mid": ("MessageID(message)", True, "identifier", True, "Message id delivered inside the event stream."),
    "events_email": ("UserEmail(user)", True, "attribute", False, "User e-mail disclosed in the event stream."),
}

def decision(raw, override=None, fields_paths=None):
    res, merge, vk, refc, reason = (override or SEM[raw])
    return {"raw_field": raw, "resource": res, "mergeable": merge, "value_kind": vk,
            "reference_capable": refc, "reference_fields": (fields_paths or [raw]) if refc else [], "reason": reason}
