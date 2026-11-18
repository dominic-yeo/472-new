# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Uploads (UploadsController). Routes ~1209-1257.
Security-critical: file ingestion + lookup_urls (server-side URL resolution) +
external/presigned S3 upload flow + secure-upload serving (authz-gated download).
"""
from common import (key as K, snode, V, P1, rf, of, resp_json, resp_empty, resp_raw, dec,
                    IDST_PUB, IDST_USER, IDST_STAFF)

U = "app/controllers/uploads_controller.rb"

NODES = [
    snode("/uploads", ["POST"], "create_upload", IDST_USER,
          [V("POST", [rf("file", "body", "file", required=False, flow=True, description="Uploaded file (multipart)."),
                      rf("url", "body", "string", required=False, flow=True, description="Remote URL to download (type-gated)."),
                      rf("type", "body", "string", required=True, flow=True, description="avatar/composer/profile_background/..."),
                      rf("synchronous", "body", "boolean", required=False, flow=False, description="Sync processing.")],
             resp_json([of("id", "integer", True, "Upload id."), of("url", "string", True, "Stored upload URL."),
                        of("short_url", "string", True, "upload:// short URL.")]),
             reason="Creates an upload from a file or a remote URL.", src=f"{U}:26",
             ex={"type": "composer"}, cts=["multipart/form-data", "application/json"])],
          "Authenticated upload boundary.", f"{U}:26",
          notes="FILE-INGESTION + SSRF surface: `url` triggers a server-side download (UploadCreator); "
                "type gates which upload kinds accept a URL. File type/size validated; images may be processed.",
          sin=[dec("url", "RemoteUrl(locator)", "locator", reference_capable=True, reason="Server-fetched source URL."),
               dec("type", "UploadType(attribute)", "attribute", reason="Upload kind.")],
          sout=[dec("short_url", "UploadShortUrl(locator)", "locator", reference_capable=True, reason="upload:// ref."),
                dec("url", "UploadUrl(locator)", "locator", reference_capable=True, reason="Stored file URL.")],
          statuses=[200, 403, 422, 429]),

    snode("/uploads/lookup-urls", ["POST"], "lookup_upload_urls", IDST_USER,
          [V("POST", [rf("short_urls", "body", "array", required=True, flow=True, description="upload:// short URLs to resolve.")],
             resp_json([of("urls", "array", True, "Resolved CDN/download URLs.")]),
             reason="Resolves upload:// short URLs to download URLs.", src=f"{U}:97")],
          "Authenticated short-url resolution.", f"{U}:97",
          notes="Resolves references to signed/CDN URLs; honors secure-upload access.",
          sin=[dec("short_urls", "UploadShortUrl(locator)", "collection", reason="References to resolve.")]),

    snode("/uploads/lookup-metadata", ["POST"], "lookup_upload_metadata", IDST_USER,
          [V("POST", [rf("url", "body", "string", required=True, flow=True, description="Upload URL to describe.")],
             resp_json([of("metadata", "object", True, "Upload metadata.")]),
             reason="Returns metadata for an upload.", src=f"{U}:246")],
          "Authenticated metadata lookup.", f"{U}:246"),

    snode("/uploads/generate-presigned-put", ["POST"], "generate_presigned_put", IDST_USER,
          [V("POST", [rf("file_name", "body", "string", required=True, flow=True, description="Target file name."),
                      rf("file_size", "body", "integer", required=True, flow=True, description="File size."),
                      rf("type", "body", "string", required=True, flow=True, description="Upload type.")],
             resp_json([of("url", "string", True, "Presigned S3 PUT URL."), of("unique_identifier", "string", True, "Temp key.")]),
             reason="Issues a presigned S3 PUT URL for direct external upload.", src=f"{U}:409")],
          "Authenticated external-upload init.", f"{U}:409",
          notes="Direct-to-S3 upload; size/type validated before signing.",
          reach=["enable_direct_s3_uploads"]),

    snode("/uploads/complete-external-upload", ["POST"], "complete_external_upload", IDST_USER,
          [V("POST", [rf("unique_identifier", "body", "string", required=True, flow=True, description="Temp upload key.")],
             resp_json([of("id", "integer", True, "Upload id."), of("url", "string", True, "Stored URL.")]),
             reason="Finalizes a direct external upload into an Upload record.", src=f"{U}:409")],
          "Authenticated external-upload finalize.", f"{U}:409", reach=["enable_direct_s3_uploads"]),

    snode("/uploads/create-multipart", ["POST"], "create_multipart_upload", IDST_USER,
          [V("POST", [rf("file_name", "body", "string", required=True, flow=True, description="File name."),
                      rf("file_size", "body", "integer", required=True, flow=True, description="Size.")],
             resp_json([of("external_upload_identifier", "string", True, "Multipart id.")]),
             reason="Begins a multipart external upload.", src=f"{U}:409")],
          "Authenticated multipart init.", f"{U}:409",
          notes="Groups complete/abort/batch-presign multipart steps.", reach=["enable_direct_s3_uploads"]),

    snode("/uploads/{site}/{sha}", ["GET"], "show_upload", IDST_PUB,
          [V("GET", resp=resp_raw("The upload file bytes (or 404)."),
             reason="Serves a (public) upload by site/sha.", src=f"{U}:161", cts=["application/octet-stream"])],
          "Public upload serving.", f"{U}:161",
          params=[{"name": "site", "in": "path", "type": "string", "required": True, "flow": False, "description": "Site."},
                  {"name": "sha", "in": "path", "type": "string", "required": True, "flow": True, "description": "File sha."}],
          notes="Groups show_short (/uploads/short-url/:base62). Public uploads only."),

    snode("/secure-uploads/{path}", ["GET"], "show_secure_upload", IDST_USER,
          [V("GET", resp=resp_raw("The secure upload bytes if authorized, else 403."),
             reason="Serves a secure (access-controlled) upload after an authorization check.", src=f"{U}:190",
             cts=["application/octet-stream"])],
          "Authz-gated secure download.", f"{U}:190",
          params=[{"name": "path", "in": "path", "type": "string", "required": True, "flow": True, "description": "Secure upload path."}],
          notes="SECURE MEDIA: access controlled via Guardian#can_see? on the owning post/topic (IDOR surface)."),
]
