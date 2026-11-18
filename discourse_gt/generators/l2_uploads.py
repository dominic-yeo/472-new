# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Uploads."""
from common import key as K, reference, entity, f_know, eff, subj
from l2lib import qa

A = subj()
U = "app/controllers/uploads_controller.rb"

qa("disc_create_upload", "Create upload", "Create", "create_upload", "User",
   K("/uploads"), ["POST"], "Upload", vis_reason="Authenticated upload boundary.", src=f"{U}:26",
   description="Creates an upload from a file or remote URL.",
   notes="FILE-INGESTION + SSRF: `url` triggers a server-side download; type/size validated.")
qa("disc_lookup_upload_urls", "Resolve upload short-urls", "Read", "lookup_upload_urls", "User",
   K("/uploads/lookup-urls"), ["POST"], "UploadUrl", vis_reason="Authenticated resolution.", src=f"{U}:97",
   description="Resolves upload:// short URLs to download URLs.", notes="Honors secure-upload access.")
qa("disc_lookup_upload_metadata", "Lookup upload metadata", "Read", "lookup_upload_metadata", "User",
   K("/uploads/lookup-metadata"), ["POST"], "UploadMetadata", vis_reason="Authenticated lookup.", src=f"{U}:246",
   description="Returns metadata for an upload.")
qa("disc_presigned_put", "Generate presigned PUT", "Create", "generate_presigned_put", "User",
   K("/uploads/generate-presigned-put"), ["POST"], "PresignedUrl", vis_reason="Authenticated external-upload init.",
   src=f"{U}:409", description="Issues a presigned S3 PUT URL.", notes="Size/type validated before signing.")
qa("disc_complete_external_upload", "Complete external upload", "Create", "complete_external_upload", "User",
   K("/uploads/complete-external-upload"), ["POST"], "Upload", vis_reason="Authenticated finalize.", src=f"{U}:409",
   description="Finalizes a direct external upload.")
qa("disc_create_multipart", "Begin multipart upload", "Create", "create_multipart_upload", "User",
   K("/uploads/create-multipart"), ["POST"], "ExternalUpload", vis_reason="Authenticated multipart init.",
   src=f"{U}:409", description="Begins a multipart external upload.", notes="Groups complete/abort/batch-presign.")
qa("disc_show_upload", "Serve upload", "Read", "show_upload", "Anonymous",
   K("/uploads/{site}/{sha}"), ["GET"], "Upload", vis_reason="Public upload serving.", src=f"{U}:161",
   description="Serves a public upload by site/sha.")
qa("disc_show_secure_upload", "Serve secure upload", "Read", "show_secure_upload", "User",
   K("/secure-uploads/{path}"), ["GET"], "Upload", vis_reason="Authz-gated secure download.", src=f"{U}:190",
   extra_req=[{"type": "authorization",
               "fact": {"predicate": "Can", "arguments": [A, "Read", entity("secure_upload", "SecureUpload", "target")]},
               "reason": "Guardian#can_see? on the owning post/topic gates the download."}],
   gen=[eff(f_know(A, reference("SecureUpload", entity("secure_upload", "SecureUpload", "target"))), "io_reference",
            "Serves the secure file when authorized.")],
   description="Serves a secure upload after an access check.", notes="IDOR surface on secure media.")
