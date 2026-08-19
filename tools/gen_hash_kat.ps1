# Generate ascon_hash_kat2.c from wolfSSL's reference hash KAT array (i0..i31)
$katFile = Join-Path (Split-Path $PSScriptRoot -Parent) "wolfssl\tests\api\test_ascon_kats.h"
$outFile = Join-Path $PSScriptRoot "ascon_hash_kat2.c"
$lines = Get-Content $katFile | Select-Object -Skip 39 -First 32

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("#include <picotls.h>")
[void]$sb.AppendLine("#include <picotls/minicrypto.h>")
[void]$sb.AppendLine("#include <stdint.h>")
[void]$sb.AppendLine("#include <stdio.h>")
[void]$sb.AppendLine("#include <string.h>")
[void]$sb.AppendLine("static const uint8_t kat[32][32] = {")
foreach ($l in $lines) {
    $hexes = [regex]::Matches($l, '0x([0-9A-Fa-f]{2})')
    $bytes = ($hexes | ForEach-Object { "0x" + $_.Groups[1].Value }) -join ","
    [void]$sb.AppendLine("    { $bytes },")
}
[void]$sb.AppendLine("};")
[void]$sb.AppendLine("int main(void) {")
[void]$sb.AppendLine("    int fail = 0;")
[void]$sb.AppendLine("    for (int i = 0; i < 32; i++) {")
[void]$sb.AppendLine("        uint8_t msg[64], out[32];")
[void]$sb.AppendLine("        for (int j = 0; j < i; j++) msg[j] = (uint8_t)j;")
[void]$sb.AppendLine("        ptls_hash_context_t *h = ptls_ascon_hash256.create();")
[void]$sb.AppendLine("        h->update(h, msg, (size_t)i);")
[void]$sb.AppendLine("        h->final(h, out, PTLS_HASH_FINAL_MODE_FREE);")
[void]$sb.AppendLine("        if (memcmp(out, kat[i], 32) != 0) {")
[void]$sb.AppendLine('            printf("i=%d FAIL ", i);')
[void]$sb.AppendLine('            for (int j = 0; j < 32; j++) printf("%02x", out[j]);')
[void]$sb.AppendLine('            printf("\n");')
[void]$sb.AppendLine("            fail = 1;")
[void]$sb.AppendLine("        }")
[void]$sb.AppendLine("    }")
[void]$sb.AppendLine('    if (!fail) printf("ALL 32 HASH KAT PASS\n");')
[void]$sb.AppendLine("    return fail;")
[void]$sb.AppendLine("}")
Set-Content -LiteralPath $outFile -Value $sb.ToString() -Encoding utf8
Write-Host "generated"
