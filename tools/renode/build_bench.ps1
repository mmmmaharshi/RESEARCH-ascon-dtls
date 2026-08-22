param(
    [string]$Core = "m0plus",  # m0plus | m0 | m3 | m4 | m33
    [switch]$SizeOpt,          # when set, build with 64-bit-word Ascon (WOLFSSL_ASCON_32BIT undefined)
    [switch]$Dwt               # when set, use pqm4 DWT CYCCNT (-DPQM4_DWT, -O2)
)
$ErrorActionPreference = "Stop"
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$gcc = "arm-none-eabi-gcc"
$mcpuMap = @{ "m0plus"="cortex-m0plus"; "m0"="cortex-m0"; "m3"="cortex-m3"; "m4"="cortex-m4"; "m33"="cortex-m33" }
if (-not $mcpuMap.ContainsKey($Core)) { Write-Error "Unknown Core '$Core' (expected m0plus|m0|m3|m4|m33)"; exit 1 }
$mcpu = $mcpuMap[$Core]
$asconDef = if ($SizeOpt) { "-UWOLFSSL_ASCON_32BIT" } else { "-DWOLFSSL_ASCON_32BIT" }
$suffix = if ($SizeOpt) { "-sizeopt" } else { "" }
if ($Dwt) { $suffix += "-dwt" }
$dwtDef = if ($Dwt) { "-DPQM4_DWT" } else { $null }
$opt = if ($Dwt) { "-O2" } else { "-Os" }

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
    "-DWOLFSSL_BENCHMARK_FIXED_UNITS_MB", $asconDef
)
if ($Dwt) { $defs += $dwtDef }
$incs = @(
    "-I$root",
    "-I$root\wolfssl",
    "-I$root\wolfssl\wolfssl",
    "-I$root\wolfssl\wolfcrypt\benchmark",
    "-I$PSScriptRoot"
)
$srcs = @(
    "$PSScriptRoot\bench_main.c",
    "$PSScriptRoot\bench_record.c",
    "$PSScriptRoot\probe\startup.s",
    "$root\wolfssl\wolfcrypt\benchmark\benchmark.c",
    "$root\wolfssl\wolfcrypt\src\ascon.c",
    "$root\wolfssl\wolfcrypt\src\aes.c",
    "$root\wolfssl\wolfcrypt\src\chacha.c",
    "$root\wolfssl\wolfcrypt\src\chacha20_poly1305.c",
    "$root\wolfssl\wolfcrypt\src\poly1305.c",
    "$root\wolfssl\wolfcrypt\src\sha256.c",
    "$root\wolfssl\wolfcrypt\src\md5.c",
    "$root\wolfssl\wolfcrypt\src\sha.c",
    "$root\wolfssl\wolfcrypt\src\hmac.c",
"$root\wolfssl\wolfcrypt\src\error.c",
    "$root\wolfssl\wolfcrypt\src\misc.c",
    "$root\wolfssl\wolfcrypt\src\memory.c",
    "$root\wolfssl\wolfcrypt\src\logging.c",
    "$root\wolfssl\wolfcrypt\src\wc_port.c"
)

New-Item -ItemType Directory -Force -Path "$PSScriptRoot\out" | Out-Null
$gccArgs = @(
    "-mthumb", "-mcpu=$mcpu", "-mfloat-abi=soft", $opt, "-ffreestanding", "-nostartfiles", "-fno-builtin",
    "-Wno-unused-function", "-Wno-unused-variable", "-Wno-comment", "-Wno-attributes",
    "-include", "$PSScriptRoot\bench_stub.h",
    $defs, $incs, $srcs,
    "-T", "$PSScriptRoot\probe\bench.ld",
    "-Wl,-e,reset_handler",
    "-Wl,-u,_printf_float",
    "--specs=nano.specs", "--specs=nosys.specs",
    "-o", "$PSScriptRoot\out\bench-$Core$suffix.elf"
)
& $gcc @gccArgs 2> "$PSScriptRoot\out\bench-$Core.build.log"
$buildLog = Get-Content "$PSScriptRoot\out\bench-$Core.build.log" -Raw
if ($LASTEXITCODE -ne 0) {
    Write-Output $buildLog
    Write-Error "BUILD_FAILED (exit $LASTEXITCODE)"
    exit 1
}
Write-Output "BUILD_OK bench-$Core.elf"
& arm-none-eabi-size "$PSScriptRoot\out\bench-$Core.elf"