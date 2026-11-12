<#
  WriteFreely attack-surface probe  (GT runtime grounding)
  ---------------------------------------------------------
  Fills the four gaps the HAR left open:
    (1) anonymous POST /api/posts -> mint + use an edit token   (issue-003)
    (2) POST /api/alias positive branch (free username)         (enumeration oracle)
    (3) cross-user authorization (userb/anon on usera's blog+post)
    (4) identity-status matrix across {anonymous, usera, userb, wfadmin}

  Prereqs: the writefreely-local container serving on $BaseUrl, admin 'wfadmin'
  already created. usera/userb are self-seeded via /api/auth/signup if missing.

  Output: writefreely_gt/runtime/probe_results/
    - matrix.json     every request: identity, method, path, status, body excerpt
    - fixtures.json   tokens + created collection/post ids (the edit token included)
    - summary.txt     human-readable rollup

  Run (PowerShell 5.1 or 7):
    cd C:\Users\User\Documents\472-new\writefreely_gt\runtime
    .\probe.ps1
  Non-destructive: it only creates new test data; it never changes wfadmin's pass.
#>

[CmdletBinding()]
param(
  [string]$BaseUrl   = "http://localhost:8080",
  [string]$AdminUser = "wfadmin",   [string]$AdminPass = "admin12345",
  # usera/userb are provisioned FRESH each run (random suffix) so quota/state stays clean
  # across repeated probes (max_blogs, collected posts, etc.). Admin is fixed.
  [string]$UserA     = "pa$(Get-Random -Maximum 999999)",  [string]$UserAPass = "usera12345",
  [string]$UserB     = "pb$(Get-Random -Maximum 999999)",  [string]$UserBPass = "userb12345"
)

$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Records  = New-Object System.Collections.ArrayList
$Fixtures = [ordered]@{}
$script:TokenScheme = "Token"   # auto-corrected after first login

# --- core HTTP helper: returns @{status; body; json} for success OR error ----
function Invoke-Probe {
  param(
    [string]$Method,
    [string]$Path,                 # e.g. /api/posts  (leading slash)
    [string]$Token = $null,        # bearer/token value, or $null for anonymous
    $Body = $null,                 # hashtable -> JSON, or raw string
    [switch]$Form,                 # send as application/x-www-form-urlencoded
    [string]$Phase = "",
    [string]$Identity = "",
    [string]$Note = ""
  )
  $uri = "$BaseUrl$Path"
  $headers = @{ "Accept" = "application/json" }   # WF negotiates JSON via Accept; without it GETs 406
  if ($Token) { $headers["Authorization"] = "$($script:TokenScheme) $Token" }

  $contentType = $null
  $payload = $null
  if ($null -ne $Body) {
    if ($Form) {
      $contentType = "application/x-www-form-urlencoded"
      if ($Body -is [hashtable]) {
        $payload = ($Body.GetEnumerator() | ForEach-Object {
          "$([uri]::EscapeDataString($_.Key))=$([uri]::EscapeDataString([string]$_.Value))" }) -join "&"
      } else { $payload = [string]$Body }
    } else {
      $contentType = "application/json"
      if ($Body -is [string]) { $payload = $Body } else { $payload = ($Body | ConvertTo-Json -Compress -Depth 8) }
    }
  }

  $status = $null; $text = ""
  try {
    $p = @{ Uri = $uri; Method = $Method; Headers = $headers; UseBasicParsing = $true;
            MaximumRedirection = 0; ErrorAction = "Stop" }
    if ($contentType) { $p["ContentType"] = $contentType; $p["Body"] = $payload }
    $resp = Invoke-WebRequest @p
    $status = [int]$resp.StatusCode
    $text = $resp.Content
  } catch {
    $r = $_.Exception.Response
    if ($r) {
      try { $status = [int]$r.StatusCode } catch { $status = $null }
      # PS5.1: read the error stream; PS7: .Content already on exception
      try {
        if ($r.GetResponseStream) {
          $sr = New-Object System.IO.StreamReader($r.GetResponseStream())
          $text = $sr.ReadToEnd(); $sr.Close()
        } elseif ($_.ErrorDetails -and $_.ErrorDetails.Message) {
          $text = $_.ErrorDetails.Message
        }
      } catch { $text = "" }
    } else {
      $status = -1; $text = $_.Exception.Message
    }
  }

  $excerpt = if ($text) { ($text -replace '\s+',' ').Substring(0, [Math]::Min(300, $text.Length)) } else { "" }
  $json = $null; try { if ($text) { $json = $text | ConvertFrom-Json } } catch {}

  $rec = [ordered]@{ phase=$Phase; identity=$Identity; method=$Method; path=$Path;
                     status=$status; note=$Note; body=$excerpt }
  [void]$Records.Add([pscustomobject]$rec)
  $color = "Red"
  if ($status -ge 200 -and $status -lt 400) { $color = "Green" }
  elseif ($status -ge 400 -and $status -lt 500) { $color = "Yellow" }
  Write-Host ("  [{0,-5}] {1,-6} {2,-40} {3}" -f $Identity, $Method, $Path, $status) -ForegroundColor $color
  return @{ status=$status; text=$text; json=$json }
}

# --- login (JSON); auto-detect token scheme; self-seed via signup if needed ---
function Get-Token {
  param([string]$User, [string]$Pass)
  $tok = $null
  $r = Invoke-Probe -Method POST -Path "/api/auth/login" -Body @{ alias=$User; pass=$Pass } `
                    -Phase "auth" -Identity $User -Note "login"
  if ($r.status -eq 200 -and $r.json) {
    $tok = $r.json.data.access_token
  } else {
    # Fresh user: register and take the token from the SIGNUP response directly.
    # (Re-logging-in trips WriteFreely's login rate-limiter -> 429.)
    $s = Invoke-Probe -Method POST -Path "/api/auth/signup" -Body @{ alias=$User; pass=$Pass } `
                      -Phase "auth" -Identity $User -Note "signup (seed; token from response)"
    if ($s.status -eq 201 -and $s.json) { $tok = $s.json.data.access_token }
  }
  if (-not $tok) { Write-Warning "could not obtain token for $User"; return $null }
  # verify scheme with /api/me; flip to Bearer if Token is rejected
  $me = Invoke-Probe -Method GET -Path "/api/me" -Token $tok -Phase "auth" -Identity $User -Note "verify $($script:TokenScheme)"
  if ($me.status -ne 200 -and $script:TokenScheme -eq "Token") {
    $script:TokenScheme = "Bearer"
    Invoke-Probe -Method GET -Path "/api/me" -Token $tok -Phase "auth" -Identity $User -Note "verify Bearer" | Out-Null
  }
  return $tok
}

Write-Host "`n=== Phase 0: identities ===" -ForegroundColor Cyan
$TA = Get-Token -User $UserA  -Pass $UserAPass
$TB = Get-Token -User $UserB  -Pass $UserBPass
$TAdm = Get-Token -User $AdminUser -Pass $AdminPass
$Fixtures.token_scheme = $script:TokenScheme
$Fixtures.usera_token  = $TA
$Fixtures.userb_token  = $TB
$Fixtures.admin_token  = $TAdm

Write-Host "`n=== Phase 1: anonymous post -> edit token (issue-003) ===" -ForegroundColor Cyan
$anon = Invoke-Probe -Method POST -Path "/api/posts" -Body @{ body="anon probe $(Get-Random)"; title="" } `
                     -Phase "anon-post" -Identity "anon" -Note "create anonymous post (no auth)"
$anonId = $null; $editTok = $null
if ($anon.json) { $anonId = $anon.json.data.id; $editTok = $anon.json.data.token }
$Fixtures.anon_post_id    = $anonId
$Fixtures.anon_edit_token = $editTok
Write-Host "    -> anon post id=$anonId  edit-token=$editTok" -ForegroundColor Magenta
if ($anonId -and $editTok) {
  Invoke-Probe -Method POST -Path "/api/posts/$anonId" -Body @{ body="edited with token"; token=$editTok } `
               -Phase "anon-post" -Identity "anon" -Note "edit WITH token (expect 200)" | Out-Null
  Invoke-Probe -Method POST -Path "/api/posts/$anonId" -Body @{ body="edited no token" } `
               -Phase "anon-post" -Identity "anon" -Note "edit WITHOUT token (expect 401/403)" | Out-Null
}

Write-Host "`n=== Phase 1b: edit-token MINT via disperse (issue-003) ===" -ForegroundColor Cyan
# newPost always requires login (no anon-posting flag exists). The anonymous-editable
# post + modify_token is instead minted by creating a draft then DISPERSING it (owner_id->NULL).
$draft = Invoke-Probe -Method POST -Path "/api/posts" -Token $TA -Body @{ body="draft to disperse $(Get-Random)"; title="" } `
                      -Phase "mint" -Identity "usera" -Note "create draft (no collection)"
$draftId = $null; if ($draft.json) { $draftId = $draft.json.data.id }
$mintTok = $null
if ($draftId) {
  $disp = Invoke-Probe -Method POST -Path "/api/posts/disperse" -Token $TA -Body ('["' + $draftId + '"]') `
                       -Phase "mint" -Identity "usera" -Note "disperse (un-own) -> mint modify_token"
  if ($disp.json) {
    $d = $disp.json.data
    if ($d -is [array]) { $d = $d[0] }
    if ($d.post) { $mintTok = $d.post.token }
  }
}
$Fixtures.dispersed_post_id   = $draftId
$Fixtures.dispersed_edit_token = $mintTok
Write-Host "    -> dispersed post id=$draftId  modify-token=$mintTok" -ForegroundColor Magenta
if ($draftId -and $mintTok) {
  Invoke-Probe -Method POST   -Path "/api/posts/$draftId" -Body @{ body="anon-edited via token"; token=$mintTok } `
               -Phase "mint" -Identity "anon" -Note "edit WITH modify token (expect 200)" | Out-Null
  Invoke-Probe -Method POST   -Path "/api/posts/$draftId" -Body @{ body="anon-edit no token" } `
               -Phase "mint" -Identity "anon" -Note "edit WITHOUT token (expect 401/403)" | Out-Null
  Invoke-Probe -Method DELETE -Path "/api/posts/$draftId`?token=$mintTok" `
               -Phase "mint" -Identity "anon" -Note "delete WITH modify token in query (expect 204)" | Out-Null
}

Write-Host "`n=== Phase 2: alias oracle (enumeration) ===" -ForegroundColor Cyan
$freeName = "free$(Get-Random -Maximum 99999)"
Invoke-Probe -Method POST -Path "/api/alias" -Token $TA -Body @{ username=$freeName } `
             -Phase "alias" -Identity "usera" -Note "FREE username (expect 2xx)" | Out-Null
Invoke-Probe -Method POST -Path "/api/alias" -Token $TA -Body @{ username=$AdminUser } `
             -Phase "alias" -Identity "usera" -Note "TAKEN username (expect 409)" | Out-Null
Invoke-Probe -Method POST -Path "/api/alias" -Body @{ username=$freeName } `
             -Phase "alias" -Identity "anon" -Note "alias as anon (auth probe)" | Out-Null

Write-Host "`n=== Phase 3: seed usera fixtures (collection + post) ===" -ForegroundColor Cyan
$collAlias = "coll$(Get-Random -Maximum 99999)"
$c = Invoke-Probe -Method POST -Path "/api/collections" -Token $TA `
                  -Body @{ alias=$collAlias; title="usera blog" } `
                  -Phase "fixture" -Identity "usera" -Note "create collection"
if ($c.json) { $collAlias = $c.json.data.alias }
$Fixtures.usera_collection = $collAlias
$cp = Invoke-Probe -Method POST -Path "/api/collections/$collAlias/posts" -Token $TA `
                   -Body @{ body="usera collection post"; title="hello" } `
                   -Phase "fixture" -Identity "usera" -Note "create collection post"
$collPostId = $null; $collPostSlug = $null
if ($cp.json) { $collPostId = $cp.json.data.id; $collPostSlug = $cp.json.data.slug }
$Fixtures.usera_coll_post_id   = $collPostId
$Fixtures.usera_coll_post_slug = $collPostSlug

Write-Host "`n=== Phase 4: identity matrix (incl. cross-user authz) ===" -ForegroundColor Cyan
$ids = @{ anon=$null; usera=$TA; userb=$TB; wfadmin=$TAdm }

# read-only / self endpoints across every identity
$readProbes = @(
  @{ m="GET"; p="/api/me" },
  @{ m="GET"; p="/api/me/posts" },
  @{ m="GET"; p="/api/me/collections" },
  @{ m="GET"; p="/api/collections/$collAlias" },
  @{ m="GET"; p="/api/collections/$collAlias/posts" }
)
foreach ($pr in $readProbes) {
  foreach ($id in $ids.Keys) {
    Invoke-Probe -Method $pr.m -Path $pr.p -Token $ids[$id] -Phase "matrix-read" -Identity $id -Note "" | Out-Null
  }
}

# write / ownership-gated endpoints: usera owns them, so userb+anon must be rejected
# read the single collection post (public) across identities
foreach ($id in @("anon","usera","userb","wfadmin")) {
  Invoke-Probe -Method GET -Path "/api/collections/$collAlias/posts/$collPostSlug" -Token $ids[$id] `
               -Phase "matrix-read" -Identity $id -Note "read usera collection post (public)" | Out-Null
}

$writeProbes = @(
  @{ m="POST";   p="/api/collections/$collAlias";    b=@{ title="MUTATED" }; note="update usera collection" },
  @{ m="POST";   p="/api/posts/$collPostId";         b=@{ body="MUTATED" };  note="update usera post by id" },
  @{ m="DELETE"; p="/api/posts/$collPostId";         b=$null;                note="delete usera post by id" }
)
# order identities so the destructive case runs as the OWNER last (keeps earlier rejects clean)
$order = @("anon","userb","wfadmin","usera")
foreach ($pr in $writeProbes) {
  foreach ($id in $order) {
    $expect = if ($id -eq "usera") { "owner (expect 2xx)" } else { "non-owner (expect 401/403/404)" }
    Invoke-Probe -Method $pr.m -Path $pr.p -Token $ids[$id] -Body $pr.b `
                 -Phase "matrix-authz" -Identity $id -Note "$($pr.note) - $expect" | Out-Null
  }
}

# admin-only surface: HTML form routes gated by IsAdmin() -> 404 to non-admins (issue-006)
Write-Host "`n=== Phase 5: admin gate (404-masking) ===" -ForegroundColor Cyan
# (a) API token on /admin/* -> proves the token transport does NOT reach web-session routes
foreach ($id in @("anon","usera","wfadmin")) {
  Invoke-Probe -Method GET -Path "/admin/users" -Token $ids[$id] -Phase "admin-token" -Identity $id `
               -Note "API token on /admin (expect 404: wrong transport)" | Out-Null
}

# (b) cookie web-session -> the correct transport. admin sees 200; non-admin sees the 404 mask.
function Get-WebSession {
  param([string]$User, [string]$Pass)
  $sv = $null
  try {
    Invoke-WebRequest -Uri "$BaseUrl/auth/login" -Method POST -UseBasicParsing `
      -Body @{ alias=$User; pass=$Pass } -SessionVariable sv -MaximumRedirection 5 -ErrorAction Stop | Out-Null
  } catch { }
  return $sv
}
function Invoke-CookieProbe {
  param($Session, [string]$Path, [string]$Identity, [string]$Note)
  $status = $null; $text = ""
  try {
    $resp = Invoke-WebRequest -Uri "$BaseUrl$Path" -WebSession $Session -UseBasicParsing `
              -MaximumRedirection 0 -ErrorAction Stop
    $status = [int]$resp.StatusCode; $text = $resp.Content
  } catch {
    $r = $_.Exception.Response
    if ($r) { try { $status = [int]$r.StatusCode } catch {} } else { $status = -1 }
  }
  $color = "Red"
  if ($status -ge 200 -and $status -lt 400) { $color = "Green" }
  elseif ($status -ge 400 -and $status -lt 500) { $color = "Yellow" }
  Write-Host ("  [{0,-13}] {1,-6} {2,-28} {3}" -f $Identity, "GET", $Path, $status) -ForegroundColor $color
  [void]$Records.Add([pscustomobject]@{ phase="admin-cookie"; identity=$Identity; method="GET";
    path=$Path; status=$status; note=$Note; body=(($text -replace '\s+',' ')[0..200] -join '') })
}
$adminSess = Get-WebSession -User $AdminUser -Pass $AdminPass
$useraSess = Get-WebSession -User $UserA    -Pass $UserAPass
foreach ($pg in @("/admin/users","/admin/settings","/me/settings")) {
  Invoke-CookieProbe -Session $adminSess -Path $pg -Identity "wfadmin(cookie)" -Note "admin via cookie (expect 200)"
}
foreach ($pg in @("/admin/users","/me/settings")) {
  Invoke-CookieProbe -Session $useraSess -Path $pg -Identity "usera(cookie)" -Note "non-admin via cookie (/admin expect 404 mask)"
}

Write-Host "`n=== Phase 6: remaining endpoints ===" -ForegroundColor Cyan

# fresh collection post (Phase 4 deleted $collPostId) for property/pin/collect
$fresh = Invoke-Probe -Method POST -Path "/api/collections/$collAlias/posts" -Token $TA `
                      -Body @{ body="phase6 post"; title="p6" } `
                      -Phase "extra" -Identity "usera" -Note "fresh collection post for property/pin"
$p6Id = $null; if ($fresh.json) { $p6Id = $fresh.json.data.id }
$Fixtures.phase6_post_id = $p6Id

# markdown render (handler.All; JSON {raw_body, collection_url})
foreach ($id in @("anon","usera")) {
  Invoke-Probe -Method POST -Path "/api/markdown" -Token $ids[$id] `
               -Body @{ raw_body="**bold** _em_ [x](http://a)"; collection_url="" } `
               -Phase "extra" -Identity $id -Note "render markdown" | Out-Null
}

# post property: only 'views' is valid (propSelects), anything else -> 400
if ($p6Id) {
  foreach ($id in @("anon","usera")) {
    Invoke-Probe -Method GET -Path "/api/posts/$p6Id/views" -Token $ids[$id] `
                 -Phase "extra" -Identity $id -Note "post property 'views' (expect 200)" | Out-Null
  }
  Invoke-Probe -Method GET -Path "/api/posts/$p6Id/bogusprop" `
               -Phase "extra" -Identity "anon" -Note "invalid property (expect 400)" | Out-Null
}

# pin / unpin (owner of collection; body [{id,position}])
if ($collAlias -and $p6Id) {
  $pinBody = '[{"id":"' + $p6Id + '","position":1}]'
  Invoke-Probe -Method POST -Path "/api/collections/$collAlias/pin"   -Token $TA -Body $pinBody `
               -Phase "extra" -Identity "usera" -Note "pin own post (expect 200)" | Out-Null
  Invoke-Probe -Method POST -Path "/api/collections/$collAlias/pin"   -Token $TB -Body $pinBody `
               -Phase "extra" -Identity "userb" -Note "pin as non-owner (expect 403)" | Out-Null
  Invoke-Probe -Method POST -Path "/api/collections/$collAlias/unpin" -Token $TA -Body $pinBody `
               -Phase "extra" -Identity "usera" -Note "unpin own post (expect 200)" | Out-Null
}

# collect & claim (token-capability; no real token exists -> capture validation behaviour)
$claimBody = '[{"id":"' + $p6Id + '","token":""}]'
Invoke-Probe -Method POST -Path "/api/collections/$collAlias/collect" -Token $TA -Body $claimBody `
             -Phase "extra" -Identity "usera" -Note "collect w/ empty token (vestigial; capture status)" | Out-Null
Invoke-Probe -Method POST -Path "/api/posts/claim" -Token $TA -Body $claimBody `
             -Phase "extra" -Identity "usera" -Note "claim w/ empty token (vestigial; capture status)" | Out-Null

# passphrase change: ACTUAL fields are form 'current'/'new' (NOT json current_pass/new_pass).
# Use userb and revert so nothing is left changed.
Invoke-Probe -Method POST -Path "/api/me/password" -Token $TB -Form -Body @{ current=$UserBPass; new="userb67890" } `
             -Phase "extra" -Identity "userb" -Note "change passphrase (form current/new; expect 200)" | Out-Null
Invoke-Probe -Method POST -Path "/api/me/password" -Token $TB -Form -Body @{ current="userb67890"; new=$UserBPass } `
             -Phase "extra" -Identity "userb" -Note "revert passphrase" | Out-Null
Invoke-Probe -Method POST -Path "/api/me/password" -Form -Body @{ current="x"; new="y" } `
             -Phase "extra" -Identity "anon" -Note "passphrase no auth (expect 401/400)" | Out-Null

# logout: DELETE /api/auth/me invalidates the caller's token. Done LAST (userb token dies here).
Invoke-Probe -Method DELETE -Path "/api/auth/me" -Token $TB `
             -Phase "extra" -Identity "userb" -Note "logout/invalidate token (expect 204)" | Out-Null
Invoke-Probe -Method DELETE -Path "/api/auth/me" `
             -Phase "extra" -Identity "anon" -Note "logout no token (expect 401)" | Out-Null

# --- write outputs ----------------------------------------------------------
$matrixPath   = Join-Path $OutDir "matrix.json"
$fixturesPath = Join-Path $OutDir "fixtures.json"
$summaryPath  = Join-Path $OutDir "summary.txt"

$Records   | ConvertTo-Json -Depth 6 | Out-File -FilePath $matrixPath   -Encoding utf8
$Fixtures  | ConvertTo-Json -Depth 6 | Out-File -FilePath $fixturesPath -Encoding utf8

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("WriteFreely probe summary  ($(Get-Date -Format s))")
[void]$sb.AppendLine("base=$BaseUrl  token_scheme=$($script:TokenScheme)")
[void]$sb.AppendLine("anon_edit_token=$($Fixtures.anon_edit_token)")
[void]$sb.AppendLine("usera_collection=$($Fixtures.usera_collection)  coll_post_slug=$($Fixtures.usera_coll_post_slug)")
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("{0,-14} {1,-7} {2,-42} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach ($r in $Records) {
  [void]$sb.AppendLine(("{0,-14} {1,-7} {2,-42} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note))
}
$sb.ToString() | Out-File -FilePath $summaryPath -Encoding utf8

Write-Host "`nWrote:" -ForegroundColor Cyan
Write-Host "  $matrixPath"
Write-Host "  $fixturesPath"
Write-Host "  $summaryPath"
Write-Host "`nKey results:" -ForegroundColor Cyan
Write-Host "  anon edit token : $($Fixtures.anon_edit_token)"
Write-Host "  token scheme    : $($script:TokenScheme)"
Write-Host "  usera collection: $($Fixtures.usera_collection)"
