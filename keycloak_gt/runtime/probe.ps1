<#
  Keycloak attack-surface probe -- GT runtime grounding.
  Target: quay.io/keycloak/keycloak start-dev, http://localhost:8080 (realm 'master').
  Grounds: the PUBLIC surface (OIDC discovery, JWKS, realm info, authorize, token with a
  bad client), the admin-API denial convention (401 without a token), and the MASTER-ADMIN
  plane (admin token via the password grant on master/admin-cli, then admin reads).
  Output: runtime/probe_results/{matrix.json,summary.txt}
#>
[CmdletBinding()]
param(
  [string]$BaseUrl   = "http://localhost:8080",
  [string]$Realm     = "master",
  [string]$AdminUser = "gtadmin",
  [string]$AdminPass = "Gt-Adm1n-Secret-9xQ"
)
$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "probe_results"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Records = New-Object System.Collections.ArrayList
$script:AdminTok = $null

function Rec($phase,$ident,$method,$path,$status,$note){
  [void]$Records.Add([pscustomobject]@{phase=$phase;identity=$ident;method=$method;path=$path;status=$status;note=$note})
  $c="Red"; if($status -ge 200 -and $status -lt 400){$c="Green"}elseif($status -ge 400 -and $status -lt 500){$c="Yellow"}
  Write-Host ("  [{0,-7}] {1,-5} {2,-52} {3}" -f $ident,$method,$path,$status) -ForegroundColor $c
}

function Req {
  param([string]$Method,[string]$Path,[string]$Ident="anon",[string]$Phase="",[string]$Note="",
        $Body=$null,[string]$ContentType="application/json",[string]$Bearer=$null)
  $h=@{Accept="application/json"}; if($Bearer){$h["Authorization"]="Bearer $Bearer"}
  try{
    $p=@{Uri="$BaseUrl$Path";Method=$Method;Headers=$h;UseBasicParsing=$true;MaximumRedirection=0;ErrorAction="Stop"}
    if($null -ne $Body){ $p["ContentType"]=$ContentType; $p["Body"]=$Body }
    $r=Invoke-WebRequest @p; $s=[int]$r.StatusCode; $txt=$r.Content
  }catch{
    $resp=$_.Exception.Response; $s= if($resp){[int]$resp.StatusCode}else{-1}; $txt=""
    try{ if($resp -and $resp.GetResponseStream){$sr=New-Object System.IO.StreamReader($resp.GetResponseStream());$txt=$sr.ReadToEnd();$sr.Close()} }catch{}
  }
  Rec $Phase $Ident $Method $Path $s $Note
  $json=$null; try{ if($txt){$json=$txt|ConvertFrom-Json} }catch{}
  return @{s=$s;txt=$txt;json=$json}
}

Write-Host "`n=== Phase 0: PUBLIC protocol surface ===" -ForegroundColor Cyan
Req GET "/realms/$Realm/.well-known/openid-configuration" "anon" "public" "OIDC discovery (expect 200)" | Out-Null
Req GET "/realms/$Realm/protocol/openid-connect/certs"    "anon" "public" "JWKS (expect 200)" | Out-Null
Req GET "/realms/$Realm"                                   "anon" "public" "realm info (expect 200)" | Out-Null
Req GET "/realms/$Realm/protocol/openid-connect/auth?client_id=account&response_type=code&redirect_uri=http://localhost:8080/x&scope=openid" "anon" "public" "authorize (expect 200 login / 302)" | Out-Null
# token with a bad client -> 401 (client auth fails)
Req POST "/realms/$Realm/protocol/openid-connect/token" "anon" "public" "token bad client (expect 401)" `
    ("grant_type=client_credentials&client_id=nope&client_secret=nope") "application/x-www-form-urlencoded" | Out-Null

Write-Host "`n=== Phase 1: admin-API DENIAL convention (no token) ===" -ForegroundColor Cyan
foreach($p in @("/admin/serverinfo","/admin/realms","/admin/realms/$Realm","/admin/realms/$Realm/users","/admin/realms/$Realm/clients")){
  Req GET $p "anon" "denial" "no token (expect 401)" | Out-Null
}

Write-Host "`n=== Phase 2: master-admin token (password grant on admin-cli) ===" -ForegroundColor Cyan
$tokBody = "grant_type=password&client_id=admin-cli&username=$AdminUser&password=$([uri]::EscapeDataString($AdminPass))"
$t = Req POST "/realms/master/protocol/openid-connect/token" "admin" "auth" "admin-cli password grant (expect 200)" `
     $tokBody "application/x-www-form-urlencoded"
if($t.json -and $t.json.access_token){ $script:AdminTok = $t.json.access_token }

Write-Host "`n=== Phase 3: master-admin matrix ===" -ForegroundColor Cyan
if($script:AdminTok){
  foreach($p in @("/admin/serverinfo","/admin/realms","/admin/realms/$Realm",
                  "/admin/realms/$Realm/users","/admin/realms/$Realm/clients","/admin/realms/$Realm/roles",
                  "/admin/realms/$Realm/groups","/admin/realms/$Realm/identity-provider/instances",
                  "/admin/realms/$Realm/components","/admin/realms/$Realm/authentication/flows")){
    Req GET $p "admin" "authed" "admin (expect 200)" -Bearer $script:AdminTok | Out-Null
  }
  # userinfo with the admin token (bearer transport check)
  Req GET "/realms/master/protocol/openid-connect/userinfo" "admin" "authed" "userinfo bearer (expect 200)" -Bearer $script:AdminTok | Out-Null
} else {
  Rec "authed" "admin" "-" "(skipped)" -1 "no admin token -- check bootstrap admin env"
}

# --- outputs ---
$Records | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "matrix.json") -Encoding utf8
$sb=New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Keycloak probe summary ($(Get-Date -Format s)) base=$BaseUrl adminToken=$([bool]$script:AdminTok)")
[void]$sb.AppendLine(("{0,-8} {1,-5} {2,-52} {3,-5} {4}" -f "IDENTITY","METHOD","PATH","CODE","NOTE"))
foreach($r in $Records){[void]$sb.AppendLine(("{0,-8} {1,-5} {2,-52} {3,-5} {4}" -f $r.identity,$r.method,$r.path,$r.status,$r.note))}
$sb.ToString() | Out-File (Join-Path $OutDir "summary.txt") -Encoding utf8
Write-Host "`nWrote probe_results/{matrix.json,summary.txt}" -ForegroundColor Cyan
