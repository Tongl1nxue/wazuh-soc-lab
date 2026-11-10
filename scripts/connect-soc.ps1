param([switch]$Shell)
$ErrorActionPreference = 'Stop'
$socRoot = Split-Path -Parent $PSScriptRoot
$socPrivate = Join-Path $socRoot 'local-evidence'
$socAccess = Get-Content -LiteralPath (Join-Path $socPrivate 'access.json') -Raw | ConvertFrom-Json
$socSshArgs = @('-i', (Join-Path $socPrivate 'soc_ed25519'), '-o', 'BatchMode=yes', '-o', ('UserKnownHostsFile=' + (Join-Path $socPrivate 'known_hosts')), '-o', 'ServerAliveInterval=30')
if ($Shell) {
    & ssh @socSshArgs ('soc@' + $socAccess.ip)
} else {
    Write-Host 'Keep this window open. Dashboard: https://localhost:8443 ; Nginx: http://localhost:18080'
    Write-Host 'Dashboard credentials are in local-evidence/dashboard-login.txt (private; do not publish).'
    & ssh @socSshArgs -o ExitOnForwardFailure=yes -N -L '127.0.0.1:8443:127.0.0.1:8443' -L '127.0.0.1:18080:127.0.0.1:8080' ('soc@' + $socAccess.ip)
}
exit $LASTEXITCODE
