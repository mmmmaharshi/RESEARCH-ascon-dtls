[CmdletBinding()]
param(
    [switch]$Quick
)
$ErrorActionPreference = "Stop"
$root  = Split-Path $PSScriptRoot -Parent
$proxy = "$root\tools\dtls_negative_proxy.ps1"
$srv   = "$root\build\dtls13_psk_server.exe"
$cli   = "$root\build\dtls13_psk_client.exe"
$pdir  = "$env:TEMP\ascon-dtls-work"
$csv   = "$pdir\negative_matrix_results.csv"

# (1) Kill leftover proxy/server/client so ports are free (a killed prior run
#     leaves orphans that hold 140xx/150xx and make new proxies fail to bind).
Get-Process -Name dtls13_psk_server -ErrorAction 0 | Stop-Process -Force -ErrorAction 0
Get-Process -Name dtls13_psk_client -ErrorAction 0 | Stop-Process -Force -ErrorAction 0
Get-CimInstance Win32_Process -Filter "Name='pwsh.exe' AND CommandLine LIKE '%dtls_negative_proxy%'" -ErrorAction 0 |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction 0 }
Start-Sleep -Seconds 1

$sizes     = @(14, 1000)
$positions = @(1, 5, 10)
$reps      = if ($Quick) { 1 } else { 3 }
$modes     = @('tamper', 'truncate', 'sequence', 'epoch')
$script:id   = 0
$script:rows = @()

function Run-One($mode, $size, $pos, $rep) {
    $script:id++
    $lp = 14000 + $script:id
    $sp = 15000 + $script:id
    $pf = "$pdir\nm_$($script:id)_proxy.txt"
    $sf = "$pdir\nm_$($script:id)_srv.txt"
    $cf = "$pdir\nm_$($script:id)_cli.txt"
    $pe = "$pdir\nm_$($script:id)_proxy.err"
    $se = "$pdir\nm_$($script:id)_srv.err"
    # R2 ('ku') corrupts every record via flood and relies on WOLFSSL_ASCON_KU_LIMIT
    # (test-only, see wolfssl/src/dtls13.c) to fire an active KeyUpdate fast.
    $proxyMode = if ($mode -eq 'ku') { 'flood' } else { $mode }

    $pp = Start-Process pwsh -ArgumentList "-File", "$proxy", "-ListenPort", $lp, "-ServerPort", $sp, "-Mode", $proxyMode, "-CorruptIndex", $pos, "-MinLen", 1, "-MaxLen", 2000 `
        -RedirectStandardOutput $pf -RedirectStandardError $pe -WindowStyle Hidden -PassThru
    # R2 harness: force the Ascon KeyUpdate threshold low so a small forgery
    # flood triggers an active peer rekey (WOLFSSL_ASCON_KU_LIMIT is test-only).
    if ($mode -eq 'ku') { $env:WOLFSSL_ASCON_KU_LIMIT = '0' }
    $sproc = Start-Process $srv -ArgumentList $sp, 20 `
        -RedirectStandardOutput $sf -RedirectStandardError $se -WindowStyle Hidden -PassThru
    if ($mode -eq 'ku') { $env:WOLFSSL_ASCON_KU_LIMIT = $null }
    # (2) Give the proxy time to bind. <1s caused a client-connect-before-bind
    #     race (Connection reset, 0 echoes) in the earlier matrix run.
    Start-Sleep -Seconds 4
    $cproc = Start-Process $cli -ArgumentList "127.0.0.1", $lp, "--msgs", 10, "--size", $size `
        -RedirectStandardOutput $cf -RedirectStandardError "$pdir\nm_$($script:id)_cli.err" -WindowStyle Hidden -PassThru
    $cproc.WaitForExit(30000)
    # Kill the proxy first so the server's receive side closes; the server then
    # exits its read loop and FLUSHES its debug log (otherwise it blocks and a
    # force-kill truncates the stderr pipe, hiding most records).
    Stop-Process -Id $pp.Id -Force -ErrorAction 0
    $sproc.WaitForExit(15000)

    $echo = (Select-String -Path $cf -Pattern "echo ok"      | Measure-Object).Count
    $act   = (Select-String -Path $pf -Pattern "action="      | Measure-Object).Count
    $kuLog= (Select-String -Path $se -Pattern "Issuing key update" | Measure-Object).Count

    if ($mode -eq 'observe')       { $pass = ($act -eq 0 -and $echo -eq 10) }
    elseif ($mode -eq 'replay')    { $pass = ($act -ge 1 -and $echo -eq 10) }
    elseif ($mode -eq 'ku')        { $pass = ($kuLog -ge 1) }
    else                           { $pass = ($act -ge 1 -and $echo -lt 10) }

    Stop-Process -Id $pp.Id    -Force -ErrorAction 0
    Stop-Process -Id $sproc.Id -Force -ErrorAction 0
    Stop-Process -Id $cproc.Id -Force -ErrorAction 0

    $script:rows += [PSCustomObject]@{ id = $script:id; mode = $mode; size = $size; pos = $pos; rep = $rep; echo = $echo; act = $act; pass = $pass }
    "$($script:id) $mode size=$size pos=$pos rep=$rep echo=$echo act=$act -> $(if ($pass) { 'PASS' } else { 'FAIL' })"
}

if ($Quick) {
    Run-One 'observe' 14   1 1
    Run-One 'observe' 1000 1 1
    Run-One 'tamper'  14   1 1
    Run-One 'tamper'  1000 1 1
    Run-One 'flood'  1000 1 1
    Run-One 'replay'  14   1 1
    Run-One 'ku'     1000 1 1
}
else {
    foreach ($sz in $sizes)           { Run-One 'observe' $sz 1 1 }
    foreach ($sz in $sizes)           { for ($r = 1; $r -le 3; $r++) { Run-One 'replay' $sz 1 $r } }
    foreach ($m in $modes) {
        foreach ($sz in $sizes) {
            foreach ($p in $positions) {
                for ($r = 1; $r -le 3; $r++) { Run-One $m $sz $p $r }
            }
        }
    }
}

$script:rows | Export-Csv -Path $csv -NoTypeInformation
"MATRIX DONE TOTAL=$($script:rows.Count) FAIL=$(($script:rows | Where-Object { -not $_.pass }).Count)"
