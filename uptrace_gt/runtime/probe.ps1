<#
  Uptrace (OSS) attack-surface probe -- GT runtime grounding.
  Target: example/docker stack, uptrace/uptrace:2.1.0-rc.1 on http://localhost:14318.

  Identities:
    anonymous : no auth
    admin     : Authorization: Bearer user1_secret   (configured user token = login as admin)
    dsn       : uptrace-dsn: http://project1_secret@localhost:14318  (ingestion client)

  Grounds: full internal API identity matrix, project-DSN disclosure (issue-002),
  trace-id oracle (issue-003), public-path user-gating vs DSN (issue-004),
  dashboard CRUD, DSN ingestion, and the existence-only project gate (issue-001).

  Output: uptrace_gt/runtime/probe_results/{matrix.json,fixtures.json,summary.txt}
#>
[CmdletBinding()]
param(
  [string]$BaseUrl  = "http://localhost:14318",
  [string]$Email    = "admin@uptrace.local",
  [string]$Password = "admin",
  [string]$Token    = "user1_secret",
  [string]$Dsn      = "http://project1_secret@localhost:14318",
  [int]$ProjectId   = 1
)

$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Records  = New-Object System.Collections.ArrayList
$Fixtures = [ordered]@{}

function Invoke-Probe {
  param(
    [string]$Method, [string]$Path,
    [ValidateSet("none","admin","dsn")] [string]$As = "none",
    $Body = $null, [string]$ContentType = "application/json",
    [string]$Phase = "", [string]$Note = ""
  )
  $uri = "$BaseUrl$Path"
  $headers = @{ "Accept" = "application/json" }
  $ident = "anon"
  if ($As -eq "admin") { $headers["Authorization"] = "Bearer $Token"; $ident = "admin" }
  elseif ($As -eq "dsn") { $headers["uptrace-dsn"] = $Dsn; $ident = "dsn" }

  $payload = $null
  if ($null -ne $Body) { $payload = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Compress -Depth 10 } }

  $status = $null; $text = ""
  try {
    $p = @{ Uri=$uri; Method=$Method; Headers=$headers; UseBasicParsing=$true; MaximumRedirection=0; ErrorAction="Stop" }
    if ($null -ne $payload) { $p["ContentType"] = $ContentType; $p["Body"] = $payload }
    $r = Invoke-WebRequest @p
    $status = [int]$r.StatusCode; $text = $r.Content
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      try { $status = [int]$resp.StatusCode } catch {}
      try {
        if ($resp.GetResponseStream) { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $text = $sr.ReadToEnd(); $sr.Close() }
        elseif ($_.ErrorDetails) { $text = $_.ErrorDetails.Message }
      } catch {}
    } else { $status = -1; $text = $_.Exception.Message }
  }
  $excerpt = if ($text) { ($text -replace '\s+',' ').Substring(0, [Math]::Min(280,$text.Length)) } else { "" }
  $json = $null; try { if ($text) { $json = $text | ConvertFrom-Json } } catch {}
  [void]$Records.Add([pscustomobject]@{ phase=$Phase; identity=$ident; method=$Method; path=$Path; status=$status; note=$Note; body=$excerpt })
  $c = "Red"; if ($status -ge 200 -and $status -lt 400) { $c = "Green" } elseif ($status -ge 400 -and $status -lt 500) { $c = "Yellow" }
  Write-Host ("  [{0,-5}] {1,-6} {2,-46} {3}" -f $ident,$Method,$Path,$status) -ForegroundColor $c
  return @{ status=$status; text=$text; json=$json }
}

$P = "/internal/v1"
$T = "$P/tracing/$ProjectId"
$M = "$P/metrics/$ProjectId"

Write-Host "`n=== Phase 0: login (cookie) + token sanity ===" -ForegroundColor Cyan
# verify the login endpoint sets a cookie (realistic UI auth) -- separate from the Bearer path we use elsewhere
try {
  $login = Invoke-WebRequest -Uri "$BaseUrl$P/users/login" -Method POST -UseBasicParsing `
            -ContentType "application/json" -Body (@{ email=$Email; password=$Password } | ConvertTo-Json) `
            -SessionVariable sess -MaximumRedirection 0 -ErrorAction Stop
  $Fixtures.login_status = [int]$login.StatusCode
  $ck = $sess.Cookies.GetCookies($BaseUrl) | Where-Object { $_.Name -eq "token" }
  $Fixtures.login_cookie_set = [bool]$ck
  Write-Host ("  login -> {0}; token cookie set: {1}" -f $login.StatusCode, [bool]$ck) -ForegroundColor Green
} catch { $Fixtures.login_status = "err"; Write-Host "  login error: $($_.Exception.Message)" -ForegroundColor Red }
Invoke-Probe GET "$P/users/current" -As admin -Phase "auth" -Note "bearer token sanity (expect 200)" | Out-Null

Write-Host "`n=== Phase 1: internal API identity matrix (anon vs admin) ===" -ForegroundColor Cyan
$reads = @("$P/users/current","$P/data-usage","$T/systems","$T/spans","$T/groups","$T/attributes",
           "$M","$M/attributes")
foreach ($r in $reads) {
  Invoke-Probe GET $r -As none  -Phase "matrix" -Note "anon (expect 401)" | Out-Null
  Invoke-Probe GET $r -As admin -Phase "matrix" -Note "admin (expect 200)" | Out-Null
}
Invoke-Probe GET "$M/table?query=count()" -As admin -Phase "matrix" -Note "metrics table query" | Out-Null

Write-Host "`n=== Phase 2: project DSN disclosure (issue-002) ===" -ForegroundColor Cyan
$pr = Invoke-Probe GET "$P/projects/$ProjectId" -As admin -Phase "dsn-disclosure" -Note "admin reads project -> DSN?"
if ($pr.json) { $Fixtures.project_dsn = $pr.json.dsn; Write-Host ("  disclosed dsn: {0}" -f $pr.json.dsn) -ForegroundColor Magenta }
Invoke-Probe GET "$P/projects/$ProjectId" -As none -Phase "dsn-disclosure" -Note "anon (expect 401)" | Out-Null
# existence-only gate (issue-001): a non-existent project id -> 404 project-not-found (not an ACL 403)
Invoke-Probe GET "$P/projects/999999" -As admin -Phase "acl" -Note "nonexistent project (expect 404 not 403)" | Out-Null
Invoke-Probe GET "$P/tracing/999999/spans" -As admin -Phase "acl" -Note "spans for nonexistent project (gate=existence)" | Out-Null

Write-Host "`n=== Phase 3: trace-id oracle (issue-003) ===" -ForegroundColor Cyan
$fakeTrace = "0123456789abcdef0123456789abcdef"
Invoke-Probe GET "$P/traces/search?trace_id=$fakeTrace" -As admin -Phase "oracle" -Note "search trace (m.User only, no project)" | Out-Null
Invoke-Probe GET "$P/traces/search?trace_id=$fakeTrace" -As none  -Phase "oracle" -Note "anon (expect 401)" | Out-Null

Write-Host "`n=== Phase 4: /api/v1 public-path auth split (issue-004) ===" -ForegroundColor Cyan
Invoke-Probe GET "/api/v1/tracing/$ProjectId/spans" -As none  -Phase "pubpath" -Note "public path, anon (expect 401 = user-gated)" | Out-Null
Invoke-Probe GET "/api/v1/tracing/$ProjectId/spans" -As admin -Phase "pubpath" -Note "public path, admin cookie/bearer (expect 200)" | Out-Null
Invoke-Probe GET "/api/v1/tracing/$ProjectId/spans" -As dsn   -Phase "pubpath" -Note "public path, DSN only (expect 401 = NOT dsn-gated)" | Out-Null

Write-Host "`n=== Phase 5: dashboard CRUD (admin) ===" -ForegroundColor Cyan
$dc = Invoke-Probe POST "$M/dashboards" -As admin -Body @{ name="probe-dash" } -Phase "dash" -Note "create dashboard"
$dashId = $null; if ($dc.json) { $dashId = $dc.json.dashboard.id }
if (-not $dashId -and $dc.json) { $dashId = $dc.json.id }
$Fixtures.dashboard_id = $dashId
Invoke-Probe GET "$M/dashboards" -As admin -Phase "dash" -Note "list dashboards" | Out-Null
if ($dashId) {
  Invoke-Probe GET    "$M/dashboards/$dashId" -As admin -Phase "dash" -Note "show dashboard" | Out-Null
  Invoke-Probe PUT    "$M/dashboards/$dashId" -As admin -Body @{ name="probe-dash-2" } -Phase "dash" -Note "update dashboard" | Out-Null
  Invoke-Probe POST   "$M/dashboards/$dashId/rows" -As admin -Body @{ title="row" } -Phase "dash" -Note "create grid row" | Out-Null
  Invoke-Probe DELETE "$M/dashboards/$dashId" -As admin -Phase "dash" -Note "delete dashboard" | Out-Null
}
Invoke-Probe POST "$M/dashboards" -As none -Body @{ name="x" } -Phase "dash" -Note "create as anon (expect 401)" | Out-Null

Write-Host "`n=== Phase 6: ingestion (DSN auth) ===" -ForegroundColor Cyan
$otlpTrace = '{"resourceSpans":[]}'
Invoke-Probe POST "/v1/traces"  -As dsn  -Body $otlpTrace -Phase "ingest" -Note "OTLP traces w/ DSN (expect 2xx)" | Out-Null
Invoke-Probe POST "/v1/traces"  -As none -Body $otlpTrace -Phase "ingest" -Note "OTLP traces NO dsn (expect 401/400)" | Out-Null
Invoke-Probe POST "/v1/logs"    -As dsn  -Body '{"resourceLogs":[]}' -Phase "ingest" -Note "OTLP logs w/ DSN" | Out-Null
Invoke-Probe POST "/v1/metrics" -As dsn  -Body '{"resourceMetrics":[]}' -Phase "ingest" -Note "OTLP metrics w/ DSN" | Out-Null
Invoke-Probe POST "/api/v1/vector-logs" -As dsn -Body '[]' -ContentType "application/x-ndjson" -Phase "ingest" -Note "vector logs w/ DSN" | Out-Null

# --- write outputs ---
$Records  | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "matrix.json") -Encoding utf8
$Fixtures | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "fixtures.json") -Encoding utf8
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Uptrace probe summary  ($(Get-Date -Format s))  base=$BaseUrl")
[void]$sb.AppendLine("login_status=$($Fixtures.login_status) cookie=$($Fixtures.login_cookie_set) disclosed_dsn=$($Fixtures.project_dsn)")
[void]$sb.AppendLine(("{0,-14} {1,-7} {2,-46} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach ($r in $Records) { [void]$sb.AppendLine(("{0,-14} {1,-7} {2,-46} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note)) }
$sb.ToString() | Out-File (Join-Path $OutDir "summary.txt") -Encoding utf8
Write-Host "`nWrote probe_results/{matrix.json,fixtures.json,summary.txt}" -ForegroundColor Cyan
Write-Host ("disclosed project DSN: {0}" -f $Fixtures.project_dsn)
