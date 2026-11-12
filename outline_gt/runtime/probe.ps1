<#
  Outline attack-surface probe -- GT runtime grounding.
  Target: outlinewiki/outline:1.12.0 (official image), http://localhost:3001.
  Grounds: the PUBLIC + denial surface (auth.config pre-auth, 401 convention), a REAL
  login via the email magic-link (two-step: GET interstitial -> POST token, read from
  Mailpit), the authenticated/admin matrix, the token transports (header | body |
  ?token= query == token-in-URL), and the published-share unauth read + by-id denial.
  Output: runtime/probe_results/{matrix.json,summary.txt}
#>
[CmdletBinding()]
param(
  [string]$BaseUrl    = "http://localhost:3001",
  [string]$MailpitUrl = "http://localhost:8025",
  [string]$Email      = "gtadmin@example.com"
)
$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Records = New-Object System.Collections.ArrayList
$script:Tok = $null   # a working token (session JWT) used as Bearer for the authed matrix

function Rec($phase,$ident,$method,$path,$status,$note){
  [void]$Records.Add([pscustomobject]@{phase=$phase;identity=$ident;method=$method;path=$path;status=$status;note=$note})
  $c="Red"; if($status -ge 200 -and $status -lt 400){$c="Green"}elseif($status -ge 400 -and $status -lt 500){$c="Yellow"}
  Write-Host ("  [{0,-6}] {1,-5} {2,-34} {3}" -f $ident,$method,$path,$status) -ForegroundColor $c
}

function Post($path,$body,$ident,$phase,$note,$bearer){
  $h=@{Accept="application/json"}; if($bearer){$h["Authorization"]="Bearer $bearer"}
  $b= if($body -is [string]){$body}else{$body|ConvertTo-Json -Depth 8}
  try{ $x=Invoke-WebRequest -Uri "$BaseUrl$path" -Method POST -ContentType "application/json" -Body $b -Headers $h -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop
       Rec $phase $ident "POST" $path ([int]$x.StatusCode) $note; return @{s=[int]$x.StatusCode;j=($x.Content|ConvertFrom-Json)} }
  catch{ $r=$_.Exception.Response; $s= if($r){[int]$r.StatusCode}else{-1}; Rec $phase $ident "POST" $path $s $note; return @{s=$s;j=$null} }
}

Write-Host "`n=== Phase 0: public / pre-auth (denial convention) ===" -ForegroundColor Cyan
Post "/api/auth.config" @{} "anon" "public" "PUBLIC (expect 200)" $null | Out-Null
foreach($ep in @("auth.info","users.list","collections.list","documents.list","shares.list","apiKeys.list","integrations.list","installation.info")){
  Post "/api/$ep" @{} "anon" "public" "anon (expect 401)" $null | Out-Null
}
Post "/api/auth.info?token=deadbeef" @{} "anon" "transport" "bogus ?token= parses->401" $null | Out-Null

Write-Host "`n=== Phase 1: email magic-link login (two-step) ===" -ForegroundColor Cyan
try {
  try { Invoke-RestMethod -Method Delete -Uri "$MailpitUrl/api/v1/messages" | Out-Null } catch {}
  Post "/auth/email" @{email=$Email;client="web"} "anon" "signin" "request magic link" $null | Out-Null
  Start-Sleep -Seconds 2
  $msgs = Invoke-RestMethod -Uri "$MailpitUrl/api/v1/messages"
  if ($msgs.messages.Count -gt 0) {
    $full = Invoke-RestMethod -Uri "$MailpitUrl/api/v1/message/$($msgs.messages[0].ID)"
    $link = [regex]::Match("$($full.Text) $($full.HTML)",'https?://[^"\s<>]*/auth/email\.callback[^"\s<>]*').Value -replace '&amp;','&'
    # step 1: GET the interstitial (sets csrfToken), parse its auto-submit hidden fields
    $g = Invoke-WebRequest -Uri $link -SessionVariable sess -MaximumRedirection 0 -UseBasicParsing
    $fields=@{}; foreach($mm in [regex]::Matches($g.Content,'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"')){ $fields[$mm.Groups[1].Value]=$mm.Groups[2].Value }
    $csrf=($sess.Cookies.GetCookies($BaseUrl)|?{$_.Name -eq 'csrfToken'}).Value
    $body=($fields.GetEnumerator()|%{ [Uri]::EscapeDataString($_.Key)+'='+[Uri]::EscapeDataString($_.Value) }) -join '&'
    # step 2: POST the token -> sets accessToken
    try { Invoke-WebRequest -Uri "$BaseUrl/auth/email.callback" -Method POST -ContentType "application/x-www-form-urlencoded" -Body $body -Headers @{'x-csrf-token'=$csrf} -WebSession $sess -MaximumRedirection 0 -UseBasicParsing -ErrorAction Stop | Out-Null } catch {}
    $script:Tok = ($sess.Cookies.GetCookies($BaseUrl)|?{$_.Name -eq 'accessToken'}).Value
    Rec "signin" "user" "POST" "/auth/email.callback" ($(if($script:Tok){200}else{-1})) "two-step magic-link login"
  } else { Rec "signin" "user" "GET" "mailpit" -1 "no email (SMTP not wired?)" }
} catch { Rec "signin" "user" "GET" "mailpit" -1 "login error: $($_.Exception.Message)" }

Write-Host "`n=== Phase 2: authenticated / admin matrix ===" -ForegroundColor Cyan
if ($script:Tok) {
  foreach($ep in @("auth.info","users.list","collections.list","documents.list","shares.list","apiKeys.list",
                   "integrations.list","groups.list","oauthClients.list","events.list")){
    Post "/api/$ep" @{} "admin" "authed" "admin (expect 200)" $script:Tok | Out-Null
  }

  Write-Host "`n=== Phase 3: published-share unauth read + by-id denial ===" -ForegroundColor Cyan
  $c = Post "/api/collections.create" @{name="GT Notes";permission="read"} "admin" "share" "create collection" $script:Tok
  $cid=$c.j.data.id
  $d = Post "/api/documents.create" @{title="Secret";text="top secret body";collectionId=$cid;publish=$true} "admin" "share" "create document" $script:Tok
  $did=$d.j.data.id
  $s = Post "/api/shares.create" @{documentId=$did;published=$true} "admin" "share" "publish share" $script:Tok
  $sid=$s.j.data.id
  Post "/api/documents.info" @{shareId=$sid} "anon" "share" "ANON read via share (expect 200 w/ content)" $null | Out-Null
  Post "/api/shares.info" @{id=$sid} "anon" "share" "ANON share.info oracle (expect 200)" $null | Out-Null
  Post "/api/documents.info" @{id=$did} "anon" "share" "ANON same doc by id (expect 401)" $null | Out-Null

  Write-Host "`n=== Phase 4: token transports -- API key via header | body | ?token= (token-in-URL) ===" -ForegroundColor Cyan
  $k = Post "/api/apiKeys.create" @{name="probe-key"} "admin" "transport" "mint API key" $script:Tok
  $apikey = $k.j.data.value; if(-not $apikey){ $apikey = $k.j.data.secret }
  if($apikey){
    Post "/api/auth.info" @{} "apikey" "transport" "header Bearer (expect 200)" $apikey | Out-Null
    # body token
    $r1=$null; try{ $x=Invoke-WebRequest -Uri "$BaseUrl/api/auth.info" -Method POST -ContentType "application/json" -Body (@{token=$apikey}|ConvertTo-Json) -UseBasicParsing; $r1=[int]$x.StatusCode }catch{ $r1=[int]$_.Exception.Response.StatusCode }
    Rec "transport" "apikey" "POST" "/api/auth.info (body token)" $r1 "body token (expect 200)"
    # query ?token=
    $r2=$null; try{ $x=Invoke-WebRequest -Uri "$BaseUrl/api/auth.info?token=$apikey" -Method POST -ContentType "application/json" -Body "{}" -UseBasicParsing; $r2=[int]$x.StatusCode }catch{ $r2=[int]$_.Exception.Response.StatusCode }
    Rec "transport" "apikey" "POST" "/api/auth.info?token= (URL)" $r2 "?token= query == TOKEN-IN-URL (expect 200)"
  }
} else {
  Rec "authed" "user" "-" "(skipped)" -1 "no session -- check Mailpit/SMTP, then re-run"
}

# --- outputs ---
$Records | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "matrix.json") -Encoding utf8
$sb=New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Outline probe summary ($(Get-Date -Format s)) base=$BaseUrl loggedIn=$([bool]$script:Tok)")
[void]$sb.AppendLine(("{0,-7} {1,-5} {2,-38} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach($r in $Records){[void]$sb.AppendLine(("{0,-7} {1,-5} {2,-38} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note))}
$sb.ToString() | Out-File (Join-Path $OutDir "summary.txt") -Encoding utf8
Write-Host "`nWrote probe_results/{matrix.json,summary.txt}" -ForegroundColor Cyan
