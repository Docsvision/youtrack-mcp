[CmdletBinding()]
param(
    [string]$YouTrackUrl,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$deployDir = Join-Path $repoRoot "deploy"
$secretsDir = Join-Path $deployDir "secrets"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Read-SecretText([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Write-PrivateFile([string]$Path, [string]$Value) {
    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "File already exists: $Path. Use -Force to replace production configuration."
    }
    [IO.File]::WriteAllText($Path, $Value, $utf8NoBom)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        $acl.RemoveAccessRuleAll($existingRule)
    }
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if (-not $YouTrackUrl) {
    $YouTrackUrl = Read-Host "YouTrack URL (for example https://youtrack.company.ru)"
}
$YouTrackUrl = $YouTrackUrl.Trim().TrimEnd("/")
if (-not $YouTrackUrl.StartsWith("https://")) {
    throw "Production YouTrack URL must use HTTPS"
}

New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null

foreach ($name in "mcp-sanitized", "mcp-plain") {
    $example = Join-Path $deployDir "$name.env.example"
    $target = Join-Path $deployDir "$name.env"
    if ((Test-Path -LiteralPath $target) -and -not $Force) {
        throw "File already exists: $target. Use -Force to replace production configuration."
    }
    $content = (Get-Content -LiteralPath $example -Raw).Replace(
        "https://youtrack.example.com",
        $YouTrackUrl
    )
    [IO.File]::WriteAllText($target, $content, $utf8NoBom)
}

$sanitizedToken = Read-SecretText "Read-only YouTrack token for sanitized MCP"
if (-not $sanitizedToken) {
    throw "The sanitized MCP token cannot be empty"
}

$reuse = Read-Host "Use the same read-only token for plain MCP? [Y/n]"
if ([string]::IsNullOrWhiteSpace($reuse) -or $reuse -match "^[Yy]") {
    $plainToken = $sanitizedToken
}
else {
    $plainToken = Read-SecretText "Read-only YouTrack token for plain MCP"
}
if (-not $plainToken) {
    throw "The plain MCP token cannot be empty"
}

$randomBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $random.GetBytes($randomBytes)
}
finally {
    $random.Dispose()
}
$pseudonymKey = -join ($randomBytes | ForEach-Object { $_.ToString("x2") })

Write-PrivateFile (Join-Path $secretsDir "youtrack-sanitized.token") $sanitizedToken
Write-PrivateFile (Join-Path $secretsDir "youtrack-plain.token") $plainToken
Write-PrivateFile (Join-Path $secretsDir "sanitizer-pseudonym.key") $pseudonymKey

Write-Host "Production files created. Next command:"
Write-Host "docker compose -f docker-compose.production.yml config --quiet"
