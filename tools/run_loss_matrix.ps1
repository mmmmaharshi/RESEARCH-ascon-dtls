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
$csv   = "$pdir\loss_matrix_results.csv"

# Kill leftover proxy/server/client so ports are free.
Get-Process -Name dtls13_psk_server -ErrorAction 0 | Stop-Process -Force -ErrorAction 0
Get-Process -Name dtls13_psk_client -ErrorAction 0 | Stop-Process -Force -ErrorAction 0
Get-CimInstance Win32_Process -Filter "Name='pwsh.exe' AND CommandLine LIKE '%dtls_negative_proxy%'" -ErrorAction 0 |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction 0 }
Start-Sleep -Seconds 1

# R10: sustained uniform packet loss at 1% / 5% / 10%. DTLS 1.3 retransmission
# (RFC 9147 4.2.4) must recover and deliver the full application exchange.
$rates = @(0.01, 0.05, 0.10)
$sizes = if ($Quick) { @(14) } else { @(14, 1000) }
$reps  = if ($Quick) { 1 } else { 3 }
$script:id   = 0
$script:rows = @()

function Run-One($rate, $size, $rep) {
    $script:id++
    $lp = 16000 + $script:id
    $sp = 17000 + $script:id
    $pf = "$pdir\lm_$($script:id)_proxy.txt"
    $sf = "$pdir\lm_$($script:id)_srv.txt"
    $cf = "$pdir\lm_$($script:id)_cli.txt"
    $pe = "$pdir\lm_$($script:id)_proxy.err"
    $se = "$pdir\lm_$($script:id)_srv.err"

    $pp = Start-Process pwsh -ArgumentList "-File", "$proxy", "-ListenPort", $lp, "-ServerPort", $sp, "-Mode", "loss", "-LossRate", $rate, "-DurationSeconds", 30 `
        -RedirectStandardOutput $pf -RedirectStandardError $pe -WindowStyle Hidden -PassThru
    $sproc = Start-Process $srv -ArgumentList $sp, 20 `
        -RedirectStandardOutput $sf -RedirectStandardError $se -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 4
    $cproc = Start-Process $cli -ArgumentList "127.0.0.1", $lp, "--msgs", 10, "--size", $size `
        -RedirectStandardOutput $cf -RedirectStandardError "$pdir\lm_$($script:id)_cli.err" -WindowStyle Hidden -PassThru
    $cproc.WaitForExit(40000)
    Stop-Process -Id $pp.Id -Force -ErrorAction 0
    $sproc.WaitForExit(15000)

    $echo = (Select-String -Path $cf -Pattern "echo ok" | Measure-Object).Count
    $c2sDrop = (Select-String -Path $pf -Pattern "c2s-drop" | Measure-Object).Count
    $s2cDrop = (Select-String -Path $pf -Pattern "s2c-drop" | Measure-Object).Count
    # Recovery PASS = all 10 application messages delivered despite sustained loss.
    $pass = ($echo -eq 10)

    Stop-Process -Id $pp.Id    -Force -ErrorAction 0
    Stop-Process -Id $sproc.Id -Force -ErrorAction 0
    Stop-Process -Id $cproc.Id -Force -ErrorAction 0

    $script:rows += [PSCustomObject]@{ id = $script:id; rate = $rate; size = $size; rep = $rep; echo = $echo; c2sDrop = $c2sDrop; s2cDrop = $s2cDrop; pass = $pass }
    "$($script:id) loss rate=$rate size=$size rep=$rep echo=$echo dropped(c2s/s2c)=$c2sDrop/$s2cDrop -> $(if ($pass) { 'PASS' } else { 'FAIL' })"
}

foreach ($r in $rates) {
    foreach ($sz in $sizes) {
        for ($x = 1; $x -le $reps; $x++) { Run-One $r $sz $x }
    }
}

$script:rows | Export-Csv -Path $csv -NoTypeInformation
"LOSS MATRIX DONE TOTAL=$($script:rows.Count) FAIL=$(($script:rows | Where-Object { -not $_.pass }).Count)"
