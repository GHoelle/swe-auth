# Generates .env with fresh random secrets.
#
# Nothing in this project has default credentials: ENVIRONMENT, DATABASE_URL and REDIS_URL
# are required with no fallbacks, and Compose refuses to start if a secret is missing. That
# is deliberate (a forgotten default is how "changeme" reaches production), so first-time
# setup needs a generator instead of being zero-config.

$ErrorActionPreference = 'Stop'

Set-Location (Join-Path $PSScriptRoot '..')

if (Test-Path .env) {
    Write-Error @"
.env already exists. Refusing to overwrite it.
Delete it first if you want new secrets, but note that existing Postgres and Redis
containers keep the old password: run 'docker compose down -v' as well.
"@
}

if (-not (Test-Path .env.example)) {
    Write-Error '.env.example not found. Run this from inside the repository.'
}

# URL-safe output only. These values are interpolated into postgresql:// and redis:// URLs,
# where a '/', '@' or ':' would silently change what the URL means.
function New-Secret {
    $bytes = New-Object byte[] 32
    # Cryptographically secure, unlike Get-Random. Create() works on both Windows
    # PowerShell 5.1 and PowerShell 7+; RandomNumberGenerator::Fill is 7-only.
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

$postgresPassword = New-Secret
$redisPassword = New-Secret

Get-Content .env.example | ForEach-Object {
    if ($_ -like 'POSTGRES_PASSWORD=*') { "POSTGRES_PASSWORD=$postgresPassword" }
    elseif ($_ -like 'REDIS_PASSWORD=*') { "REDIS_PASSWORD=$redisPassword" }
    else { $_ }
} | Set-Content .env -Encoding utf8

Write-Host 'Wrote .env with freshly generated secrets.'
Write-Host 'It is covered by .gitignore and must never be committed.'
Write-Host ''
Write-Host 'Next: docker compose up --build'
