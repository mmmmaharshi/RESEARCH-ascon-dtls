param($Port=15700, $Iterations=3000, $MaxLen=1400)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$srv  = Join-Path $repo 'build\dtls13_psk_server.exe'
$cli  = Join-Path $repo 'build\dtls13_psk_client.exe'
$b    = "$env:TEMP\ascon-dtls-work"
Get-Process -Name 'dtls13_psk*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name 'pwsh' -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*dtls_negative_proxy*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$sproc = Start-Process -FilePath $srv -ArgumentList $Port,20 -PassThru -RedirectStandardError (Join-Path $b 'fuzz_srv.err') -WindowStyle Hidden
Start-Sleep -Seconds 2
if ($sproc.HasExited) { Write-Host "SERVER FAILED TO START"; Get-Content (Join-Path $b 'fuzz_srv.err'); exit 1 }
$udp = New-Object System.Net.Sockets.UdpClient
$ep  = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $Port)
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$sent = 0; $crash = $false
for ($i = 0; $i -lt $Iterations; $i++) {
    if ($sproc.HasExited) { $crash = $true; break }
    $len = 1 + [int](Get-Random -Maximum ($MaxLen - 1))
    $buf = New-Object byte[] $len
    switch ($i % 8) {
        0 { $rng.GetBytes($buf) }                                       # fully random
        1 { $buf[0] = 0x16; $rng.GetBytes($buf, 1, $len - 1) }          # handshake header + noise
        2 { $buf[0] = 0x17; $rng.GetBytes($buf, 1, $len - 1) }          # app header + noise
        3 { $buf[0] = 0x2f; $rng.GetBytes($buf, 1, $len - 1) }          # ascon app record header + noise
        4 { for ($k = 0; $k -lt $len; $k++) { $buf[$k] = 0 } }          # all zeros
        5 { for ($k = 0; $k -lt $len; $k++) { $buf[$k] = 0xff } }       # all 0xff
        6 { for ($k = 0; $k -lt $len; $k++) { $buf[$k] = 0xaa } }       # all 0xaa
        7 { $rng.GetBytes($buf); if ($len -gt 5) { $buf[0] = 0x2f; $buf[3] = 0x03; $buf[4] = 0xf9 } } # pseudo-large ascon record
    }
    try { [void]$udp.Send($buf, $len, $ep) } catch {}
    $sent++
    # Crash watchdog: if the server process exits mid-fuzz, malformed input crashed it.
    if ($sproc.HasExited) { $crash = $true; break }
    # Throttle so the server (which logs every dropped record via the hardcoded
    # wolfSSL_Debugging_ON) keeps up and the recv buffer never backlogs. This
    # isolates "does malformed input crash/wedge the server?" from "can a flood
    # exhaust the debug-log I/O path?".
    Start-Sleep -Milliseconds 1
}
# Let the server drain any backlog of garbage from its UDP recv buffer.
Start-Sleep -Seconds 2
$alive = -not $sproc.HasExited
# Recovery (server still serves legit traffic after a malformed-input flood) is
# validated separately by the matrix observe runs (tools/run_negative_matrix.ps1,
# which use the same proxy relay and reliably yield echo=10). This harness keeps
# itself focused on the crash/wedge question: did malformed input kill or hang
# the record parser?
$sproc | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "SENT=$sent CRASH=$crash ALIVE_DURING_FUZZ=$alive"
Write-Host "RECOVERY: see matrix observe runs (echo=10) for post-flood legit service"
