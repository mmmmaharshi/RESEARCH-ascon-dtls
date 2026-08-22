# Multi-target Renode matrix: builds + runs bench for m0plus/m3/m4/m33
# Usage: ./run_matrix.ps1 -Cores @("m0plus","m3","m4","m33") -Repeats 10
# Output: out/matrix.tsv (core, MiB/s avg, cyc/rec avg)
param(
    [string[]]$Cores = @("m0plus","m3","m4","m33"),
    [int]$Repeats = 10
)
$ErrorActionPreference = "Stop"
$tsv = "$PSScriptRoot/out/matrix.tsv"
New-Item -ItemType Directory -Force -Path "$PSScriptRoot/out" | Out-Null
"core`tMiB/s`tcyc/rec`tRepeats" | Set-Content $tsv
foreach ($c in $Cores) {
    Write-Output "=== $c ==="
    & "$PSScriptRoot/build_bench.ps1" -Core $c
    if ($LASTEXITCODE -ne 0) { Write-Error "build failed for $c"; exit 1 }
    $mibs = @(); $cycs = @()
    for ($i = 0; $i -lt $Repeats; $i++) {
        $out = & "$PSScriptRoot/run_driver.ps1" -Elf "$PSScriptRoot/out/bench-$c.elf" -Platform "$PSScriptRoot/platforms/bench-$c.repl" 2>&1 | Out-String
        foreach ($m in [regex]::Matches($out, "([0-9]+\.[0-9]+)\s*MiB/s")) { $mibs += [double]$m.Groups[1].Value }
        foreach ($m in [regex]::Matches($out, "([0-9]+\.[0-9]+)\s*cyc/rec")) { $cycs += [double]$m.Groups[1].Value }
    }
    $avgMib = if ($mibs.Count) { "{0:F3}" -f (($mibs | Measure-Object -Average).Average) } else { "TBD" }
    $avgCyc = if ($cycs.Count) { "{0:F1}" -f (($cycs | Measure-Object -Average).Average) } else { "TBD" }
    "$c`t$avgMib`t$avgCyc`t$Repeats" | Add-Content $tsv
}
Write-Output "matrix written to $tsv"
Get-Content $tsv
