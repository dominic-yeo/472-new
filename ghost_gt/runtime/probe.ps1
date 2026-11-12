<#
  Ghost (OSS) attack-surface probe -- GT runtime grounding.
  Target: official ghost:6 image, dev/SQLite, http://localhost:2368.

  Grounds the three auth planes + bootstrap surface:
    - public admin site (publicAdminApi)
    - setup (create owner, pre-setup only)  -> session cookie  (issue ghost-003)
    - Content API key-gating                 (issue ghost-002)
    - Admin API auth matrix (anon vs owner)
    - unauthenticated password-reset request (issue ghost-003)
    - members magic-link request + public site
  Output: runtime/probe_results/{matrix.json,fixtures.json,summary.txt}
#>
[CmdletBinding()]
param(
  [string]$BaseUrl  = "http://localhost:2368",
  [string]$Email    = "owner@gt.local",
  [string]$Password = "Str0ng-GT-Passw0rd!",
  [string]$BlogTitle = "GT Target"
)
$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Records  = New-Object System.Collections.ArrayList
$Fixtures = [ordered]@{}
$script:Sess = $null

function Rec($phase,$ident,$method,$path,$status,$note,$body){
  $ex = if ($body) { ($body -replace '\s+',' ').Substring(0,[Math]::Min(240,$body.Length)) } else { "" }
  [void]$Records.Add([pscustomobject]@{phase=$phase;identity=$ident;method=$method;path=$path;status=$status;note=$note;body=$ex})
  $c="Red"; if($status -ge 200 -and $status -lt 400){$c="Green"}elseif($status -ge 400 -and $status -lt 500){$c="Yellow"}
  Write-Host ("  [{0,-8}] {1,-6} {2,-48} {3}" -f $ident,$method,$path,$status) -ForegroundColor $c
}

function Invoke-Probe {
  param([string]$Method,[string]$Path,[ValidateSet("none","owner","contentkey")] [string]$As="none",
        $Body=$null,[string]$Key=$null,[string]$Phase="",[string]$Note="")
  $uri="$BaseUrl$Path"
  if($As -eq "contentkey" -and $Key){ $sep = if($Path -match '\?'){'&'}else{'?'}; $uri="$uri$sep key=$Key" -replace ' ','' }
  $headers=@{ "Accept"="application/json"; "Origin"=$BaseUrl }   # Origin required for admin session CSRF
  $payload=$null
  if($null -ne $Body){ $payload = if($Body -is [string]){$Body}else{$Body|ConvertTo-Json -Compress -Depth 8} }
  $status=$null;$text=""
  try{
    $p=@{Uri=$uri;Method=$Method;Headers=$headers;UseBasicParsing=$true;MaximumRedirection=0;ErrorAction="Stop"}
    if($payload){$p["ContentType"]="application/json";$p["Body"]=$payload}
    if($As -eq "owner" -and $script:Sess){$p["WebSession"]=$script:Sess}
    $r=Invoke-WebRequest @p; $status=[int]$r.StatusCode; $text=$r.Content
  }catch{
    $resp=$_.Exception.Response
    if($resp){ try{$status=[int]$resp.StatusCode}catch{}
      try{ if($resp.GetResponseStream){$sr=New-Object System.IO.StreamReader($resp.GetResponseStream());$text=$sr.ReadToEnd();$sr.Close()} elseif($_.ErrorDetails){$text=$_.ErrorDetails.Message} }catch{} }
    else{$status=-1;$text=$_.Exception.Message}
  }
  $ident = @{none="anon";owner="owner";contentkey="contentkey"}[$As]
  Rec $Phase $ident $Method $Path $status $Note $text
  $json=$null; try{ if($text){$json=$text|ConvertFrom-Json} }catch{}
  return @{status=$status;text=$text;json=$json}
}

Write-Host "`n=== Phase 0: public + setup state ===" -ForegroundColor Cyan
Invoke-Probe GET "/ghost/api/admin/site/" -Phase "public" -Note "publicAdminApi (expect 200)" | Out-Null
$isset = Invoke-Probe GET "/ghost/api/admin/authentication/setup/" -Phase "bootstrap" -Note "isSetup"
$Fixtures.isSetup_body = $isset.text

Write-Host "`n=== Phase 1: create owner (setup -> session cookie) ===" -ForegroundColor Cyan
$setupBody = @{ setup=@(@{ name="GT Owner"; email=$Email; password=$Password; blogTitle=$BlogTitle }) } | ConvertTo-Json -Depth 6
$status=$null;$text=""
try{
  $r=Invoke-WebRequest -Uri "$BaseUrl/ghost/api/admin/authentication/setup/" -Method POST -UseBasicParsing `
      -ContentType "application/json" -Body $setupBody -SessionVariable s -MaximumRedirection 0 -ErrorAction Stop
  $status=[int]$r.StatusCode;$text=$r.Content;$script:Sess=$s
}catch{ $resp=$_.Exception.Response; if($resp){try{$status=[int]$resp.StatusCode}catch{}; try{if($resp.GetResponseStream){$sr=New-Object System.IO.StreamReader($resp.GetResponseStream());$text=$sr.ReadToEnd();$sr.Close()}}catch{}; if($s){$script:Sess=$s}} else {$status=-1;$text=$_.Exception.Message} }
Rec "bootstrap" "anon" "POST" "/ghost/api/admin/authentication/setup/" $status "create owner (expect 201)" $text
$Fixtures.setup_status = $status
# explicit login to establish the admin session cookie (setup alone does not)
$ls=$null;$lt=""
try{
  $lr=Invoke-WebRequest -Uri "$BaseUrl/ghost/api/admin/session/" -Method POST -UseBasicParsing `
      -ContentType "application/json" -Headers @{Origin=$BaseUrl} `
      -Body (@{username=$Email;password=$Password}|ConvertTo-Json) -SessionVariable s2 -MaximumRedirection 0 -ErrorAction Stop
  $ls=[int]$lr.StatusCode;$script:Sess=$s2
}catch{ $resp=$_.Exception.Response; if($resp){try{$ls=[int]$resp.StatusCode}catch{}}; if($s2){$script:Sess=$s2} }
Rec "bootstrap" "anon" "POST" "/ghost/api/admin/session/" $ls "login -> admin session cookie (expect 201)" ""
$Fixtures.login_status = $ls
$Fixtures.owner_cookie = [bool]$script:Sess

Write-Host "`n=== Phase 2: admin API auth matrix (anon vs owner cookie) ===" -ForegroundColor Cyan
foreach($pth in @("/ghost/api/admin/posts/","/ghost/api/admin/users/","/ghost/api/admin/members/","/ghost/api/admin/settings/","/ghost/api/admin/integrations/?include=api_keys")){
  Invoke-Probe GET $pth -As none  -Phase "admin-matrix" -Note "anon (expect 401/403)" | Out-Null
  $r = Invoke-Probe GET $pth -As owner -Phase "admin-matrix" -Note "owner cookie (expect 200)"
  if($pth -match "integrations"){
    try{ $ck = ($r.json.integrations | ForEach-Object { $_.api_keys } | Where-Object { $_.type -eq "content" } | Select-Object -First 1).secret; $Fixtures.content_key=$ck }catch{}
  }
}
# owner can create a post
$pc = Invoke-Probe POST "/ghost/api/admin/posts/" -As owner -Body @{ posts=@(@{ title="probe post"; status="draft" }) } -Phase "admin-matrix" -Note "owner create post (expect 201)"
$Fixtures.created_post = [bool]($pc.status -ge 200 -and $pc.status -lt 300)

Write-Host "`n=== Phase 3: setup-race (re-run setup after done) ===" -ForegroundColor Cyan
Invoke-Probe POST "/ghost/api/admin/authentication/setup/" -As none -Body $setupBody -Phase "bootstrap" -Note "re-setup after owner exists (expect 403)" | Out-Null

Write-Host "`n=== Phase 4: Content API key-gating ===" -ForegroundColor Cyan
Invoke-Probe GET "/ghost/api/content/posts/" -As none -Phase "content" -Note "content posts NO key (expect 401/403)" | Out-Null
if($Fixtures.content_key){
  Invoke-Probe GET "/ghost/api/content/posts/" -As contentkey -Key $Fixtures.content_key -Phase "content" -Note "content posts WITH key (expect 200)" | Out-Null
  Invoke-Probe GET "/ghost/api/content/settings/" -As contentkey -Key $Fixtures.content_key -Phase "content" -Note "content settings WITH key" | Out-Null
  Write-Host ("  content key: {0}..." -f $Fixtures.content_key.Substring(0,[Math]::Min(8,$Fixtures.content_key.Length))) -ForegroundColor Magenta
} else { Write-Host "  (no content key extracted; positive content case skipped)" -ForegroundColor Yellow }

Write-Host "`n=== Phase 5: unauthenticated bootstrap surfaces ===" -ForegroundColor Cyan
Invoke-Probe POST "/ghost/api/admin/authentication/password_reset/" -As none -Body @{ password_reset=@(@{ email=$Email }) } -Phase "unauth" -Note "reset request, real email (enumeration)" | Out-Null
Invoke-Probe POST "/ghost/api/admin/authentication/password_reset/" -As none -Body @{ password_reset=@(@{ email="nobody@nope.invalid" }) } -Phase "unauth" -Note "reset request, unknown email (enum oracle?)" | Out-Null

Write-Host "`n=== Phase 6: Members API ===" -ForegroundColor Cyan
Invoke-Probe GET  "/members/api/site/" -As none -Phase "members" -Note "members public site (expect 200)" | Out-Null
Invoke-Probe POST "/members/api/send-magic-link/" -As none -Body @{ email="reader@gt.local"; emailType="signin" } -Phase "members" -Note "magic-link request (expect 2xx/201)" | Out-Null
Invoke-Probe GET  "/members/api/member/" -As none -Phase "members" -Note "member self NO session (expect 204/401)" | Out-Null

# --- outputs ---
$Records  | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "matrix.json") -Encoding utf8
$Fixtures | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "fixtures.json") -Encoding utf8
$sb=New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Ghost probe summary ($(Get-Date -Format s)) base=$BaseUrl")
[void]$sb.AppendLine("setup_status=$($Fixtures.setup_status) owner_cookie=$($Fixtures.owner_cookie) content_key=$([bool]$Fixtures.content_key)")
[void]$sb.AppendLine(("{0,-10} {1,-6} {2,-50} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach($r in $Records){[void]$sb.AppendLine(("{0,-10} {1,-6} {2,-50} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note))}
$sb.ToString() | Out-File (Join-Path $OutDir "summary.txt") -Encoding utf8
Write-Host "`nWrote probe_results/{matrix.json,fixtures.json,summary.txt}" -ForegroundColor Cyan
