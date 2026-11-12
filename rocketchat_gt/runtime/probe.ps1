<#
  Rocket.Chat (OSS) attack-surface probe -- GT runtime grounding.
  Target: rocket.chat:latest (MongoDB replica set), http://localhost:3000.
  Admin seeded via compose (gtadmin). Grounds: public routes, auth matrix
  (anon|user|admin), permission boundaries (rc-002), and login behaviour.
  Output: runtime/probe_results/{matrix.json,fixtures.json,summary.txt}
#>
[CmdletBinding()]
param(
  [string]$BaseUrl   = "http://localhost:3000",
  [string]$AdminUser = "gtadmin",
  [string]$AdminPass = "Gt-Adm1n-Secret-9xQ"
)
$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Records  = New-Object System.Collections.ArrayList
$Fixtures = [ordered]@{}
$script:Tokens = @{}   # ident -> @{tok;uid}

function Rec($phase,$ident,$method,$path,$status,$note,$body){
  $ex = if ($body) { ($body -replace '\s+',' ').Substring(0,[Math]::Min(220,$body.Length)) } else { "" }
  [void]$Records.Add([pscustomobject]@{phase=$phase;identity=$ident;method=$method;path=$path;status=$status;note=$note;body=$ex})
  $c="Red"; if($status -ge 200 -and $status -lt 400){$c="Green"}elseif($status -ge 400 -and $status -lt 500){$c="Yellow"}
  Write-Host ("  [{0,-7}] {1,-5} {2,-42} {3}" -f $ident,$method,$path,$status) -ForegroundColor $c
}

function Invoke-Probe {
  param([string]$Method,[string]$Path,[string]$As="anon",$Body=$null,[string]$Phase="",[string]$Note="")
  $uri="$BaseUrl/api/v1/$Path"
  $headers=@{ "Accept"="application/json" }
  if($As -ne "anon" -and $script:Tokens[$As]){ $headers["X-Auth-Token"]=$script:Tokens[$As].tok; $headers["X-User-Id"]=$script:Tokens[$As].uid }
  $payload=$null; if($null -ne $Body){ $payload = if($Body -is [string]){$Body}else{$Body|ConvertTo-Json -Compress -Depth 8} }
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

function Login($ident,$user,$pass){
  $r = Invoke-Probe POST "login" -As "anon" -Body @{ user=$user; password=$pass } -Phase "auth" -Note "login $ident"
  if($r.json -and $r.json.data -and $r.json.data.authToken){
    $script:Tokens[$ident]=@{tok=$r.json.data.authToken; uid=$r.json.data.userId}
    return $true
  }
  return $false
}

Write-Host "`n=== Phase 0: public (no auth) ===" -ForegroundColor Cyan
Invoke-Probe GET "settings.public" -As "anon" -Phase "public" -Note "public settings (expect 200)" | Out-Null
Invoke-Probe GET "me" -As "anon" -Phase "public" -Note "me without auth (expect 401)" | Out-Null
Invoke-Probe GET "channels.list" -As "anon" -Phase "public" -Note "channels.list anon (expect 401)" | Out-Null

Write-Host "`n=== Phase 1: admin login ===" -ForegroundColor Cyan
$okAdmin = Login "admin" $AdminUser $AdminPass
$Fixtures.admin_login = $okAdmin
Invoke-Probe POST "login" -As "anon" -Body @{ user=$AdminUser; password="wrong-password" } -Phase "auth" -Note "wrong password (expect 401)" | Out-Null

Write-Host "`n=== Phase 2: admin matrix ===" -ForegroundColor Cyan
foreach($p in @("me","users.list","channels.list","settings","rooms.adminRooms","statistics","permissions.listAll","integrations.list")){
  Invoke-Probe GET $p -As "admin" -Phase "admin" -Note "admin (expect 200)" | Out-Null
}
$cc = Invoke-Probe POST "channels.create" -As "admin" -Body @{ name=("gtchan"+(Get-Random -Maximum 99999)) } -Phase "admin" -Note "admin create channel (expect 200)"
if($cc.json.channel){ $Fixtures.channel_id=$cc.json.channel._id }

Write-Host "`n=== Phase 3: seed regular user + permission boundary ===" -ForegroundColor Cyan
$ubUser = "gtuserb"+(Get-Random -Maximum 99999)
$uc = Invoke-Probe POST "users.create" -As "admin" -Body @{ username=$ubUser; email=($ubUser+"@example.com"); password="Gt-User-Secret-7wZ"; name="GT UserB" } -Phase "admin" -Note "create regular user"
$okUb = Login "userb" $ubUser "Gt-User-Secret-7wZ"
$Fixtures.userb_login = $okUb
if($okUb){
  Invoke-Probe GET "me"            -As "userb" -Phase "boundary" -Note "userb me (expect 200)" | Out-Null
  Invoke-Probe GET "users.list"    -As "userb" -Phase "boundary" -Note "userb users.list (expect 403: no perm)" | Out-Null
  Invoke-Probe GET "settings"      -As "userb" -Phase "boundary" -Note "userb settings (expect 403)" | Out-Null
  Invoke-Probe GET "rooms.adminRooms" -As "userb" -Phase "boundary" -Note "userb adminRooms (expect 403)" | Out-Null
  Invoke-Probe GET "statistics"    -As "userb" -Phase "boundary" -Note "userb statistics (expect 403)" | Out-Null
  Invoke-Probe POST "roles.addUserToRole" -As "userb" -Body @{ roleName="admin"; username=$ubUser } -Phase "boundary" -Note "userb self-elevate to admin (expect 403)" | Out-Null
  Invoke-Probe POST "channels.create" -As "userb" -Body @{ name=("ubchan"+(Get-Random -Maximum 99999)) } -Phase "boundary" -Note "userb create channel (expect 200: create-c default)" | Out-Null
}

Write-Host "`n=== Phase 4: open-registration + anon method bridge ===" -ForegroundColor Cyan
Invoke-Probe POST "users.register" -As "anon" -Body @{ username=("reg"+(Get-Random -Maximum 99999)); email=("reg"+(Get-Random -Maximum 99999)+"@example.com"); pass="Gt-Reg-Secret-3kP"; name="Reg" } -Phase "public" -Note "self-register (config-dependent)" | Out-Null

# --- outputs ---
$Records  | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "matrix.json") -Encoding utf8
$Fixtures | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "fixtures.json") -Encoding utf8
$sb=New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Rocket.Chat probe summary ($(Get-Date -Format s)) base=$BaseUrl admin_login=$($Fixtures.admin_login) userb_login=$($Fixtures.userb_login)")
[void]$sb.AppendLine(("{0,-8} {1,-5} {2,-42} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach($r in $Records){[void]$sb.AppendLine(("{0,-8} {1,-5} {2,-42} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note))}
$sb.ToString() | Out-File (Join-Path $OutDir "summary.txt") -Encoding utf8
Write-Host "`nWrote probe_results/{matrix.json,fixtures.json,summary.txt}" -ForegroundColor Cyan
