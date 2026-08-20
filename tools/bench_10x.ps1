# bench_10x.ps1 — statistical-rigor harness for R6.
# Host mode: runs wolfSSL benchmark.exe -csv N times per algorithm, reports mean+/-std of MB/s.
# Renode mode: runs run_driver.ps1 N times per core, reports mean+/-std of throughput (MiB/s)
#   and record cost (cyc/rec). Renode is a deterministic emulator, so std is expected ~0.
param(
    [ValidateSet("host","renode","all")][string]$Mode = "all",
    [int]$Runs = 10,
    [string]$Root = (Resolve-Path "$PSScriptRoot\..").Path
)

$ErrorActionPreference = "Stop"

function MeanStd([double[]]$xs) {
    $n = $xs.Count
    if ($n -eq 0) { return @{mean=0; std=0} }
    $mean = ($xs | Measure-Object -Average).Average
    if ($n -eq 1) { return @{mean=$mean; std=0.0} }
    $var = ($xs | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Average).Average
    return @{mean=$mean; std=[math]::Sqrt($var)}
}

# ---------------- HOST ----------------
function Run-Host {
    $bin = Join-Path $Root "build\wolfcrypt\benchmark\benchmark.exe"
    $env:PATH = (Join-Path $Root "build") + ";$env:PATH"
    if (-not (Test-Path $bin)) { throw "host benchmark not found: $bin" }

    # Exact wolfSSL CSV labels (case-insensitive -match).
    $algos = @("ASCON-AEAD","AES-128-GCM","CHA-POLY","CHACHA","AES-128-CBC","ASCON hash","HMAC-SHA256")
    $flags = "-ascon-aead","-aes-gcm","-chacha20-poly1305","-chacha20","-aes-cbc","-ascon-hash","-hmac"
    Write-Output "=== HOST: mean +/- std MB/s over $Runs runs (1 MiB block, current build) ==="
    $series = @{}
    foreach ($k in $algos) { $series[$k] = @() }
    for ($i = 1; $i -le $Runs; $i++) {
        $out = & $bin -csv $flags 2>$null
        foreach ($k in $algos) {
            $line = $out | Where-Object { $_ -match "^.*$k.*,[\d.]+,[\d.]+," } | Select-Object -First 1
            if ($line -match "^.*,\s*([\d.]+)\s*,[\d.]+,$") {
                $series[$k] += [double]$Matches[1]
            }
        }
    }
    foreach ($k in $algos) {
        $s = MeanStd $series[$k]
        Write-Output ("{0,-18}: {1,10:F4} +/- {2,8:F4}  (n={3})" -f $k, $s.mean, $s.std, $series[$k].Count)
    }
}

# ---------------- RENODE ----------------
function Run-Renode {
    $driver = Join-Path $Root "tools\renode\run_driver.ps1"
    $cores = @(
        @{name="m0plus"; elf="tools\renode\out\bench-m0plus.elf"; repl="tools\renode\platforms\bench-m0plus.repl"},
        @{name="m3";     elf="tools\renode\out\bench-m3.elf";     repl="tools\renode\platforms\bench-m3.repl"}
    )
    foreach ($c in $cores) {
        Write-Output "=== RENODE $($c.name): mean +/- std over $Runs runs ==="
        $tp = @{}   # label -> [mb/s]
        $rec = @{}  # encrypt/decrypt/mask -> [cyc/rec]
        for ($i = 1; $i -le $Runs; $i++) {
            $out = & $driver -Elf (Join-Path $Root $c.elf) -Platform (Join-Path $Root $c.repl) -TimeoutSeconds 120 2>$null
            $text = ($out | Select-String -Pattern "BENCH OUTPUT" -Context 0,200)
            if ($text) { $block = $text.Context.PostContext -join "`n" } else { $block = $out -join "`n" }
            foreach ($line in ($block -split "`n")) {
                # throughput: "LABEL  N MiB took X seconds,    Y MiB/s"
                if ($line -match "^(.*?)\s+\d+\s+MiB took .*?,\s*([\d.]+)\s+MiB/s") {
                    $lab = $Matches[1].Trim(); $mb = [double]$Matches[2]
                    if (-not $tp.ContainsKey($lab)) { $tp[$lab] = @() }
                    $tp[$lab] += $mb
                }
                # record: "ascon-record-(kind): N.NNN cyc/rec"
                if ($line -match "^ascon-record-(encrypt|decrypt|mask):\s*([\d.]+)\s+cyc/rec") {
                    $kind = $Matches[1]; $v = [double]$Matches[2]
                    if (-not $rec.ContainsKey($kind)) { $rec[$kind] = @() }
                    $rec[$kind] += $v
                }
            }
        }
        Write-Output "  -- throughput (MiB/s) --"
        foreach ($k in ($tp.Keys | Sort-Object)) {
            $s = MeanStd $tp[$k]
            Write-Output ("  {0,-22}: {1,8:F4} +/- {2,8:F4}  (n={3})" -f $k, $s.mean, $s.std, $tp[$k].Count)
        }
        Write-Output "  -- record cost (cyc/rec) --"
        foreach ($k in ($rec.Keys | Sort-Object)) {
            $s = MeanStd $rec[$k]
            Write-Output ("  {0,-10}: {1,10:F3} +/- {2,8:F3}  (n={3})" -f $k, $s.mean, $s.std, $rec[$k].Count)
        }
    }
}

switch ($Mode) {
    "host"   { Run-Host }
    "renode" { Run-Renode }
    "all"    { Run-Host; Run-Renode }
}
