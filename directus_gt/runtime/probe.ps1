<#
  Directus attack-surface probe -- GT runtime grounding.
  Target: directus/directus (official image), http://localhost:8055.
  Admin seeded via compose (ADMIN_EMAIL/ADMIN_PASSWORD). Grounds: the bootstrap
  oracle, auth planes (anon | user | admin), the policy/permission boundary, and
  the dynamic item CRUD incl. a Public-read collection + IDOR probe.
  Output: runtime/probe_results/{matrix.json,fixtures.json,summary.txt}
#>
[CmdletBinding()]
param(
  [string]$BaseUrl    = "http://localhost:8055",
  [string]$AdminEmail = "gtadmin@example.com",
  [string]$AdminPass  = "Gt-Adm1n-Secret-9xQ"
)
$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Records  = New-Object System.Collections.ArrayList
$Fixtures = [ordered]@{}
$script:Tokens = @{}   # ident -> bearer string

function Rec($phase,$ident,$method,$path,$status,$note,$body){
  $collapsed = if ($body) { [string]($body -replace '\s+',' ') } else { "" }
  $ex = if ($collapsed.Length -gt 240) { $collapsed.Substring(0,240) } else { $collapsed }
  [void]$Records.Add([pscustomobject]@{phase=$phase;identity=$ident;method=$method;path=$path;status=$status;note=$note;body=$ex})
  $c="Red"; if($status -ge 200 -and $status -lt 400){$c="Green"}elseif($status -ge 400 -and $status -lt 500){$c="Yellow"}
  Write-Host ("  [{0,-7}] {1,-6} {2,-42} {3}" -f $ident,$method,$path,$status) -ForegroundColor $c
}

function Invoke-Probe {
  param([string]$Method,[string]$Path,[string]$As="anon",$Body=$null,[string]$Phase="",[string]$Note="")
  $uri="$BaseUrl$Path"
  $headers=@{ "Accept"="application/json" }
  if($As -ne "anon" -and $script:Tokens[$As]){ $headers["Authorization"]="Bearer " + $script:Tokens[$As] }
  $payload=$null; if($null -ne $Body){ $payload = if($Body -is [string]){$Body}else{$Body|ConvertTo-Json -Compress -Depth 10} }
  $status=$null;$text=""
  try{
    $p=@{Uri=$uri;Method=$Method;Headers=$headers;UseBasicParsing=$true;MaximumRedirection=0;ErrorAction="Stop"}
    if($payload){$p["ContentType"]="application/json";$p["Body"]=$payload}
    $r=Invoke-WebRequest @p; $status=[int]$r.StatusCode; $text=$r.Content
  }catch{
    $resp=$_.Exception.Response
    if($resp){ try{$status=[int]$resp.StatusCode}catch{}
      try{ if($resp.GetResponseStream){$sr=New-Object System.IO.StreamReader($resp.GetResponseStream());$text=$sr.ReadToEnd();$sr.Close()} elseif($_.ErrorDetails){$text=$_.ErrorDetails.Message} }catch{} }
    else{$status=-1;$text=$_.Exception.Message}
  }
  Rec $Phase $As $Method $Path $status $Note $text
  $json=$null; try{ if($text){$json=$text|ConvertFrom-Json} }catch{}
  return @{status=$status;text=$text;json=$json}
}

function Login-Admin($email,$pass){
  $r = Invoke-Probe POST "/auth/login" -As "anon" -Body @{ email=$email; password=$pass } -Phase "auth" -Note "admin login"
  if($r.json -and $r.json.data -and $r.json.data.access_token){ $script:Tokens["admin"]=$r.json.data.access_token; return $true }
  return $false
}

Write-Host "`n=== Phase 0: public / bootstrap ===" -ForegroundColor Cyan
Invoke-Probe GET  "/server/health" -As "anon" -Phase "public" -Note "health (expect 200)" | Out-Null
Invoke-Probe GET  "/server/info"   -As "anon" -Phase "public" -Note "server info (public fields)" | Out-Null
Invoke-Probe GET  "/auth"          -As "anon" -Phase "public" -Note "auth providers" | Out-Null
Invoke-Probe POST "/server/setup"  -As "anon" -Body @{ admin=@{email="x@x.com";password="Zzz-123456!"} } -Phase "public" -Note "setup (expect 403: already set up)" | Out-Null
Invoke-Probe POST "/users/register" -As "anon" -Body @{ email=("reg"+(Get-Random)+"@ex.com"); password="Reg-Pass-123!" } -Phase "public" -Note "self-register (expect 404/403 if disabled)" | Out-Null

Write-Host "`n=== Phase 1: admin login + matrix ===" -ForegroundColor Cyan
$Fixtures.admin_login = (Login-Admin $AdminEmail $AdminPass)
Invoke-Probe POST "/auth/login" -As "anon" -Body @{ email=$AdminEmail; password="wrong-$(Get-Random)" } -Phase "auth" -Note "wrong password (expect 401)" | Out-Null
if($script:Tokens["admin"]){
  foreach($p in @("/users/me","/users","/roles","/policies","/permissions","/settings","/files","/flows",
                  "/extensions","/collections","/schema/snapshot","/server/specs/oas")){
    Invoke-Probe GET $p -As "admin" -Phase "admin" -Note "admin (expect 200)" | Out-Null
  }
}

Write-Host "`n=== Phase 2: anon vs admin on system reads (policy boundary) ===" -ForegroundColor Cyan
foreach($p in @("/users","/roles","/policies","/permissions","/settings","/files","/collections")){
  Invoke-Probe GET $p -As "anon" -Phase "boundary" -Note "anon (expect 401/403)" | Out-Null
}
Invoke-Probe GET "/users/me" -As "anon" -Phase "boundary" -Note "anon /users/me (expect 401)" | Out-Null

Write-Host "`n=== Phase 3: dynamic items + Public-read collection + IDOR ===" -ForegroundColor Cyan
if($script:Tokens["admin"]){
  $coll = "gtnotes"
  # create a collection with a text field
  Invoke-Probe POST "/collections" -As "admin" -Body @{ collection=$coll; schema=@{}; meta=@{} } -Phase "items" -Note "admin create collection" | Out-Null
  Invoke-Probe POST "/fields/$coll" -As "admin" -Body @{ field="title"; type="string"; meta=@{}; schema=@{} } -Phase "items" -Note "admin add field" | Out-Null
  # grant the PUBLIC policy read on the collection (public policy id is well-known-ish; discover via /policies)
  $pol = Invoke-Probe GET "/policies?filter[name][_eq]=`$t_directus_public_policy" -As "admin" -Phase "items" -Note "find public policy"
  $publicPolicyId = $null
  if($pol.json -and $pol.json.data){ foreach($row in $pol.json.data){ if($row.name -match 'Public' -or $row.admin_access -eq $false){ $publicPolicyId=$row.id } } }
  $Fixtures.public_policy_id = $publicPolicyId
  if($publicPolicyId){
    Invoke-Probe POST "/permissions" -As "admin" -Body @{ policy=$publicPolicyId; collection=$coll; action="read"; fields=@("*") } -Phase "items" -Note "grant public read on collection" | Out-Null
  }
  # create two items as admin
  $i1 = Invoke-Probe POST "/items/$coll" -As "admin" -Body @{ title="alpha" } -Phase "items" -Note "admin create item1"
  $id1 = if($i1.json -and $i1.json.data){ $i1.json.data.id } else { $null }
  $Fixtures.item1_id = $id1
  # anon read the collection (Public find) + one item (IDOR surface)
  Invoke-Probe GET "/items/$coll"        -As "anon" -Phase "items" -Note "anon list (200 if Public read granted)" | Out-Null
  if($id1){ Invoke-Probe GET "/items/$coll/$id1" -As "anon" -Phase "items" -Note "anon read item by pk" | Out-Null }
  # anon write attempt (expect 403)
  Invoke-Probe POST "/items/$coll" -As "anon" -Body @{ title="anon-write" } -Phase "items" -Note "anon create (expect 403)" | Out-Null
  # system collection via items (expect 403)
  Invoke-Probe GET "/items/directus_users" -As "admin" -Phase "items" -Note "system collection via /items (expect 403)" | Out-Null
}

# --- outputs ---
$Records  | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "matrix.json") -Encoding utf8
$Fixtures | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "fixtures.json") -Encoding utf8
$sb=New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Directus probe summary ($(Get-Date -Format s)) base=$BaseUrl admin_login=$($Fixtures.admin_login)")
[void]$sb.AppendLine(("{0,-8} {1,-6} {2,-42} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach($r in $Records){[void]$sb.AppendLine(("{0,-8} {1,-6} {2,-42} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note))}
$sb.ToString() | Out-File (Join-Path $OutDir "summary.txt") -Encoding utf8
Write-Host "`nWrote probe_results/{matrix.json,fixtures.json,summary.txt}" -ForegroundColor Cyan
