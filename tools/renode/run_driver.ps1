param(
    [string]$Elf = "$PSScriptRoot\out\bench-m0plus.elf",
    [string]$Platform = "$PSScriptRoot\platforms\bench-m0plus.repl",
    [string]$LogFile = "$env:TEMP\ascon-dtls-work\renode_bench.log",
    [int]$TimeoutSeconds = 120
)
$ErrorActionPreference = "Stop"
$renode = "$env:LOCALAPPDATA\RenodePortable\renode_1.16.1-dotnet_portable\renode.exe"
$port = 4567

$logDir = Split-Path -Parent $LogFile
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
if (Test-Path $LogFile) { Remove-Item $LogFile }

$proc = Start-Process -FilePath $renode -ArgumentList "--port", "$port", "--disable-xwt", "--hide-monitor" `
    -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err" -PassThru -WindowStyle Hidden

try {
    $client = $null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $port)
            break
        } catch { }
    }
    if ($null -eq $client) { throw "renode monitor port $port not reachable" }

    $stream = $client.GetStream()
    function Send-Cmd([string]$cmd) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        Start-Sleep -Milliseconds 500
    }
    function Rcv {
        Start-Sleep -Milliseconds 600
        $buf = New-Object byte[] 65536
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -gt 0) { [System.Text.Encoding]::ASCII.GetString($buf, 0, $n) } else { "" }
    }
    function Read-HexWord([string]$addr) {
        Send-Cmd "sysbus ReadDoubleWord $addr"
        $resp = Rcv
        $m = [regex]::Matches($resp, "0x([0-9a-fA-F]{1,8})")
        if ($m.Count -gt 0) { [Convert]::ToInt64($m[$m.Count - 1].Groups[1].Value, 16) } else { -1 }
    }

    Send-Cmd 'mach create "bench"'
    Rcv | Out-Null
    Send-Cmd "machine LoadPlatformDescription @$Platform"
    Rcv | Out-Null
    Send-Cmd "sysbus LoadELF @$Elf"
    Rcv | Out-Null
    Send-Cmd "start"
    Rcv | Out-Null

    $done = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($done -eq 0 -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 5
        Send-Cmd "pause"
        $done = Read-HexWord "0x2003D00C"
        if ($done -eq 0) { Send-Cmd "start" }
    }
    $sw.Stop()

    if ($done -eq 0) {
        Write-Output "WARN: done=0 after ${TimeoutSeconds}s; dumping partial SRAM output (best-effort)"
    }

    $magic  = Read-HexWord "0x2003D000"
    $outLen = Read-HexWord "0x2003D008"
    Write-Output "magic=0x$($magic.ToString('X8')) outLen=$outLen elapsed=$($sw.Elapsed.TotalSeconds)s"

    $dumpLen = if ($outLen -gt 0) { $outLen } else { 4096 }
    Send-Cmd "sysbus ReadBytes 0x2003E000 $dumpLen"
    $dump = Rcv
    $bytes = [regex]::Matches($dump, "0x([0-9a-fA-F]{2})") | ForEach-Object { [Convert]::ToByte($_.Groups[1].Value, 16) }
    $text = [System.Text.Encoding]::ASCII.GetString([byte[]]$bytes)
    Write-Output "=== BENCH OUTPUT (dumpLen=$dumpLen) ==="
    Write-Output $text
    $hex = ($bytes[0..([Math]::Min(319, $bytes.Length - 1))] | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    Write-Output "=== HEX DUMP (first 320 bytes) ==="
    Write-Output $hex
    Send-Cmd "quit"
    Start-Sleep -Milliseconds 500
} finally {
    if ($null -ne $client) { $client.Dispose() }
    if (-not $proc.HasExited) { $proc.Kill() }
}