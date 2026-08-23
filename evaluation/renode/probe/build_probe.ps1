$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$here = $PSScriptRoot
$out = Join-Path $root "out"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$gcc = "arm-none-eabi-gcc"
$common = @("-mthumb", "-Os", "-ffreestanding",
    "-nostartfiles",
    "--specs=nano.specs", "--specs=nosys.specs",
    "-T", (Join-Path $here "bench.ld"),
    "-Wl,-e,reset_handler")

foreach ($t in @("m0plus", "m3")) {
    $mcpu = if ($t -eq "m0plus") { "-mcpu=cortex-m0plus" } else { "-mcpu=cortex-m3" }
    & $gcc @common $mcpu (Join-Path $here "startup.s") (Join-Path $here "hello.c") `
        -o (Join-Path $out "hello-$t.elf") 2>&1 | ForEach-Object { $_ }
    if ($LASTEXITCODE -ne 0) { throw "build failed for $t" }
    Write-Output "BUILD_OK hello-$t.elf"
}