$ErrorActionPreference = "Continue"
$repo = Split-Path $PSScriptRoot -Parent
$proxy  = "$repo\tools\dtls_negative_proxy.ps1"
$server = "$repo\build\dtls13_psk_server.exe"
$client = "$repo\build\dtls13_psk_client.exe"
$lib    = "$repo\build"
$pdir   = "$env:TEMP\ascon-dtls-work"
$proxyLog = "$pdir\ku_proxy.out"
$srvLog   = "$pdir\ku_srv.out"
$cliLog   = "$pdir\ku_cli.out"

# Kill anything still holding the listen/server ports (a stale proxy from a
# previous run would otherwise forward un-corrupted traffic and the new proxy
# would fail to bind). Also kill leftover endpoint exes.
function Kill-Port($p) {
    Get-NetTCPConnection -LocalPort $p -ErrorAction 0 |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction 0 }
}
Kill-Port 13000; Kill-Port 13111
Get-Process -Name dtls13_psk_server -ErrorAction 0 | Stop-Process -Force -ErrorAction 0
Get-Process -Name dtls13_psk_client -ErrorAction 0 | Stop-Process -Force -ErrorAction 0

# Launch without an in-scriptblock `*> $log` (that redirect is swallowed by
# Start-Job); capture output via Receive-Job instead.
$proxyJob = Start-Job -ScriptBlock {
    param($script, $lib)
    $env:PATH = "$lib;$env:PATH"
    & pwsh -File $script -ListenPort 13000 -ServerPort 13111 -Mode flood -DurationSeconds 30
} -ArgumentList $proxy, $lib

$srvJob = Start-Job -ScriptBlock {
    param($exe, $lib)
    $env:PATH = "$lib;$env:PATH"
    & $exe 13111 20
} -ArgumentList $server, $lib

Start-Sleep -Seconds 3
# Run the client as a background job with a hard time bound: against a
# corrupting flood proxy it can retransmit forever and never exit, which would
# hang a foreground launch. Cap the exchange at ~25s, then collect output.
$clientJob = Start-Job -ScriptBlock {
    param($exe, $lib)
    $env:PATH = "$lib;$env:PATH"
    & $exe 127.0.0.1 13000 10 --short-timeout
} -ArgumentList $client, $lib
Start-Sleep -Seconds 25

Receive-Job $clientJob | Set-Content $cliLog
Receive-Job $proxyJob | Set-Content $proxyLog
Receive-Job $srvJob   | Set-Content $srvLog

Write-Output "=== PROXY (lines=$((Get-Content $proxyLog -Raw -ErrorAction 0 | Measure-Object -Line).Lines)) ==="
Get-Content $proxyLog -Raw
Write-Output "=== SERVER (KeyUpdate?) ==="
Get-Content $srvLog -Raw | Select-String -Pattern "HANDSHAKE OK|SendTls13KeyUpdate|dropCount|Dtls13CheckAEADFailLimit|got app|read fail|bad record"
Write-Output "=== CLIENT ==="
Get-Content $cliLog -Raw | Select-String -Pattern "HANDSHAKE OK|echo ok|write|connect fail"

Stop-Job $proxyJob -ErrorAction 0; Stop-Job $srvJob -ErrorAction 0
Remove-Job $proxyJob -Force -ErrorAction 0; Remove-Job $srvJob -Force -ErrorAction 0
Get-Process -Name dtls13_psk_server -ErrorAction 0 | Stop-Process -Force -ErrorAction 0
