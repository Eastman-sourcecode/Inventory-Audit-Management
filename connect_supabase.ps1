$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigPath = Join-Path $ProjectRoot 'config\app.json'
$EncryptedKeyPath = Join-Path $ProjectRoot 'config\supabase-key.dpapi'

$Existing = netstat -ano | Select-String '^\s*TCP\s+127\.0\.0\.1:8080\s+.*LISTENING'
if ($Existing) { throw 'Port 8080 is already in use. Stop the existing server before running this secure launcher.' }

Write-Host 'Inventory Audit Management - Secure Supabase Connection'
Write-Host 'Paste the Supabase secret key when prompted. It will not be displayed; Windows will save an encrypted user-only copy.'
$SecureKey = Read-Host 'Supabase secret key (sb_secret_...)' -AsSecureString
$KeyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
try {
    $env:IAM_SUPABASE_SECRET_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($KeyPointer).Trim()
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($KeyPointer)
}
if (-not $env:IAM_SUPABASE_SECRET_KEY.StartsWith('sb_secret_')) {
    throw 'This is not a current Supabase secret key. Create an sb_secret_ key under Settings > API Keys.'
}
$SecureKey | ConvertFrom-SecureString | Set-Content -LiteralPath $EncryptedKeyPath -Encoding ASCII

$Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$Config.supabase.enabled = $true
$Config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
Write-Host 'Secure key accepted and protected with Windows user encryption. Starting the local server...'
& (Join-Path $ProjectRoot 'start.ps1')
