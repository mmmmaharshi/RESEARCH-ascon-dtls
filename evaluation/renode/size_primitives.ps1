param(
    [string]$Core = "m0plus"   # m0plus | m3
)
$ErrorActionPreference = "Stop"
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$gcc = "arm-none-eabi-gcc"
$mcpu = if ($Core -eq "m0plus") { "cortex-m0plus" } else { "cortex-m3" }

$defs = @(
    "-DWOLFSSL_USER_SETTINGS",
    "-DWOLFSSL_CURRTIME_REMAP=bench_current_time",
    "-DXPRINTF=bench_xprintf",
    "-DBENCH_EMBEDDED",
    "-DNO_MAIN_DRIVER",
    "-DNO_WOLFSSL_DIR",
    "-DWC_NO_RNG",
    "-DSINGLE_THREADED",
    "-DNO_DES",
    "-DNO_DES3",
    "-DNO_SHA512",
    "-DNO_RSA",
    "-DNO_DH",
    "-DNO_PWDBASED",
    "-DWOLFSSL_BENCHMARK_FIXED_UNITS_MB", "-DWOLFSSL_ASCON_32BIT"
)
$incs = @(
    "-I$root",
    "-I$root\wolfssl",
    "-I$root\wolfssl\wolfssl",
    "-I$root\wolfssl\wolfcrypt\benchmark",
    "-I$PSScriptRoot"
)

# source -> label used for the suite-footprint table
$sources = @{
    "ascon.c"                  = "ascon"
    "chacha.c"                 = "chacha"
    "poly1305.c"               = "poly1305"
    "chacha20_poly1305.c"      = "chacha20_poly1305"
    "aes.c"                    = "aes"
    "sha256.c"                 = "sha256"
}

New-Item -ItemType Directory -Force -Path "$PSScriptRoot\out" | Out-Null
$objDir = "$PSScriptRoot\out\size-$Core"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$results = @{}
foreach ($src in $sources.Keys) {
    $label = $sources[$src]
    $obj = "$objDir\$label.o"
    $gccArgs = @(
        "-mthumb", "-mcpu=$mcpu", "-mfloat-abi=soft", "-Os", "-ffreestanding", "-nostartfiles", "-fno-builtin",
        "-c",
        "-include", "$PSScriptRoot\bench_stub.h",
        $defs, $incs,
        "$root\wolfssl\wolfcrypt\src\$src",
        "-o", $obj
    )
    & $gcc @gccArgs 2> "$objDir\$label.build.log"
    if ($LASTEXITCODE -ne 0) {
        Write-Output "BUILD_FAILED: $src"
        Get-Content "$objDir\$label.build.log" -Raw
        exit 1
    }
    # default size: text data bss; grab text column
    $sizeOut = & arm-none-eabi-size $obj
    # first line header, second line numbers: text data bss dec hex
    $lines = $sizeOut -split "`n" | Where-Object { $_.Trim() -ne "" }
    $nums = ($lines[1] -split "\s+") | Where-Object { $_ -ne "" }
    $results[$label] = [int]$nums[0]   # text
}

# Second Ascon build: size-optimized DEFAULT 64-bit-word path (no WOLFSSL_ASCON_32BIT).
# This is the build behind the report's 2,827 B figure. Requires WORD64_AVAILABLE on
# 32-bit cores (software-emulated 64-bit arithmetic).
$cpuFlag = if ($Core -eq "m0plus") { "-mcpu=cortex-m0plus" } else { "-mcpu=cortex-m3" }
$ascon64Obj = "$objDir\ascon64.o"
& $gcc -mthumb $cpuFlag -mfloat-abi=soft -Os -ffreestanding -nostartfiles -fno-builtin -c -include "$PSScriptRoot\bench_stub.h" @defs -UWOLFSSL_ASCON_32BIT -DWORD64_AVAILABLE @incs "$root\wolfssl\wolfcrypt\src\ascon.c" -o $ascon64Obj 2> "$objDir\ascon64.build.log"
if ($LASTEXITCODE -eq 0) {
    $s64 = & arm-none-eabi-size $ascon64Obj
    $l64 = $s64 -split "`n" | Where-Object { $_.Trim() -ne "" }
    $n64 = ($l64[1] -split "\s+") | Where-Object { $_ -ne "" }
    $ascon64Text = [int]$n64[0]
} else {
    Write-Output "WARN: ascon 64-bit-path build failed (see $objDir\ascon64.build.log)"
    $ascon64Text = $null
}

# Emit machine-readable + human table
$out = "$objDir\footprint.tsv"
"object`ttext_bytes" | Out-File -Encoding ascii $out
foreach ($k in $results.Keys) { "$k`t$($results[$k])" | Out-File -Encoding ascii -Append $out }
if ($ascon64Text) { "ascon_sizeopt64`t$ascon64Text" | Out-File -Encoding ascii -Append $out }

Write-Output "=== Cortex-$mcpu per-object .text (bytes) ==="
foreach ($k in $results.Keys) { "{0,-20} {1,8}" -f $k, $results[$k] }
Write-Output ""
Write-Output "=== Full DTLS-suite footprint (.text bytes, sum of primitives) ==="
$asconSuite32 = $results["ascon"]
$asconSuite64 = $ascon64Text
$chachaSuite  = $results["chacha"] + $results["poly1305"] + $results["chacha20_poly1305"] + $results["sha256"]
$aesSuite     = $results["aes"] + $results["sha256"]
"{0,-48} {1,8} {2,8}" -f "Suite (primitives a DTLS node must link)", "32BIT", "size-opt"
"{0,-48} {1,8} {2,8}" -f "Ascon 0x006E (ascon.o: AEAD128+Hash256, 1 prim)" , $asconSuite32, $(if($asconSuite64){$asconSuite64}else{"n/a"})
"{0,-48} {1,8} {2,8}" -f "ChaCha20-Poly1305 (+SHA-256)"              , $chachaSuite, $chachaSuite
"{0,-48} {1,8} {2,8}" -f "AES-128-GCM (+SHA-256)"                    , $aesSuite,    $aesSuite
if ($asconSuite32 -gt 0) {
    "{0,-48} {1,8:F2}x" -f "ChaCha-Poly / Ascon ratio (32BIT build)"   , ($chachaSuite / $asconSuite32)
    "{0,-48} {1,8:F2}x" -f "AES-GCM / Ascon ratio (32BIT build)"       , ($aesSuite / $asconSuite32)
}
if ($asconSuite64) {
    "{0,-48} {1,8:F2}x" -f "ChaCha-Poly / Ascon ratio (size-opt build)", ($chachaSuite / $asconSuite64)
    "{0,-48} {1,8:F2}x" -f "AES-GCM / Ascon ratio (size-opt build)"    , ($aesSuite / $asconSuite64)
}
Write-Output "TSV: $out"
