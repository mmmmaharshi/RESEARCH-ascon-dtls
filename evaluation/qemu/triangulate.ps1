param(
    [string]$Elf = "$PSScriptRoot/../renode/out/bench-m3.elf",
    [ValidateSet("system","user")][string]$Mode = "system",
    [string]$QemuLog = "$PSScriptRoot/qemu.log",
    [string]$QemuBin = "",
    [int]$BenchBytes = 1024,
    [int]$NumBlocks = 25,
    [int]$RecBytes = 32
)
# QEMU instruction-count triangulation (not cycle-accurate, triangulation only).
# WSL/Linux compatible: on Windows tries `wsl -- qemu-*`, on Linux runs natively.
# System-mode: qemu-system-arm -M mps2-an385 -nographic -kernel bench-m*.elf -d instr -D qemu.log -semihosting
# User-mode : qemu-arm -d instr -D qemu.log ./bench.elf  (requires ARM user ELF, not Cortex-M semihosting)
$ErrorActionPreference = "Stop"

function Resolve-Qemu([string]$name, [string]$override){
    if($override){ return $override }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if($cmd){ return $name }
    # WSL fallback on Windows
    if($IsWindows -or $env:OS -match "Windows"){
        $wslCheck = & wsl -- which $name 2>$null
        if($LASTEXITCODE -eq 0){ return "wsl -- $name" }
    }
    return $name
}

if(!(Test-Path $Elf)){
    # expand wildcard bench-m*.elf
    $hits = Get-ChildItem -Path (Split-Path $Elf -Parent) -Filter "bench-m*.elf" -ErrorAction SilentlyContinue
    if($hits){ $Elf = $hits[0].FullName; Write-Output "Using $Elf" }
    else { Write-Error "ELF not found: $Elf (build with evaluation/renode/build_bench.ps1 first)"; exit 1 }
}

if($Mode -eq "system"){
    $qemu = Resolve-Qemu "qemu-system-arm" $QemuBin
    $args = @("-M","mps2-an385","-nographic","-kernel",$Elf,"-d","instr","-D",$QemuLog,"-semihosting")
    Write-Output "Running: $qemu $($args -join ' ')"
    Write-Output "Caveat: not cycle-accurate, triangulation only — instr count, not timing."
    if($qemu -like "wsl --*"){ & wsl -- qemu-system-arm @args 2>&1 | Out-Null } else { & qemu-system-arm @args 2>&1 | Out-Null }
} else {
    $qemu = Resolve-Qemu "qemu-arm" $QemuBin
    $args = @("-d","instr","-D",$QemuLog,$Elf)
    Write-Output "Running: $qemu $($args -join ' ')"
    Write-Output "Caveat: not cycle-accurate, triangulation only — user-mode instr count."
    if($qemu -like "wsl --*"){ & wsl -- qemu-arm @args 2>&1 | Out-Null } else { & qemu-arm @args 2>&1 | Out-Null }
}

if(!(Test-Path $QemuLog)){ Write-Error "qemu.log not produced at $QemuLog"; exit 1 }
$instr = (Get-Content $QemuLog | Measure-Object -Line).Lines
Write-Output "instr total: $instr"

# Triangulation ratios — instr/byte and instr/record.
# Bench throughput loop: BENCH_SIZE * NUM_BLOCKS bytes per iteration; record: 32 B.
$benchTotalBytes = $BenchBytes * $NumBlocks
if($benchTotalBytes -gt 0){
    $ipb = [double]$instr / [double]$benchTotalBytes
    Write-Output ("instr/byte (bench window {0} B): {1:F2}" -f $benchTotalBytes, $ipb)
}
$instrPerRec = [double]$instr / 1 # per full run; divide externally by rec count if needed
Write-Output ("instr/record est (32 B rec): {0:F1} instr/rec if one record per run" -f $instrPerRec)

# Example ratio computation (fill with two logs):
#   Ascon instr/byte vs ChaCha/AES-GCM instr/byte — compare qemu.log from each build.
#   $ascon = (Get-Content qemu-ascon.log | Measure).Lines
#   $chacha = (Get-Content qemu-chacha.log | Measure).Lines
#   "Ascon/ChaCha instr ratio: {0:F2}x" -f ($ascon/$chacha)
Write-Output "Done. Compare Ascon vs ChaCha/AES-GCM: repeat with each ELF and ratio instr counts."
Write-Output "Note: not cycle-accurate, triangulation only — use Renode DWT (hal.h PQM4_DWT) for cycle estimates."
