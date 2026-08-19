$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundledPython = 'C:\Users\adminpc\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$PythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($PythonCommand) { $PythonExe = $PythonCommand.Source }
elseif (Test-Path -LiteralPath $BundledPython) { $PythonExe = $BundledPython }
else { throw 'Python 3.10+ is required. Install Python from python.org and retry.' }
Set-Location -LiteralPath $ProjectRoot
$EncryptedKeyPath = Join-Path $ProjectRoot 'config\supabase-key.dpapi'
if ((-not $env:IAM_SUPABASE_SECRET_KEY) -and (Test-Path -LiteralPath $EncryptedKeyPath)) {
    try {
        $EncryptedKey = (Get-Content -LiteralPath $EncryptedKeyPath -Raw).Trim()
        $SecureKey = $EncryptedKey | ConvertTo-SecureString
        $KeyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
        try { $env:IAM_SUPABASE_SECRET_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($KeyPointer).Trim() }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($KeyPointer) }
    } catch {
        throw 'The encrypted Supabase key belongs to a different Windows sign-in session. Run connect_supabase.ps1 once to replace it safely.'
    }
}
& $PythonExe backend\app.py
