param(
    [ValidateSet('observe','tamper','replay','truncate','sequence','epoch','flood')]
    [string]$Mode = 'observe',
    [int]$ListenPort = 12000,
    [int]$ServerPort = 11111,
    [int]$DurationSeconds = 15
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path "$env:TEMP\ascon-dtls-work" | Out-Null
$udp.Client.ReceiveTimeout = 200
$server = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $ServerPort)
$client = $null
$clientPackets = 0
$serverPackets = 0
$changed = $false
$deadline = [DateTime]::UtcNow.AddSeconds($DurationSeconds)

try {
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $bytes = $udp.Receive([ref]$from)
        }
        catch [System.Net.Sockets.SocketException] {
            continue
        }

        if ($from.Port -eq $ServerPort) {
            $serverPackets++
            if ($null -ne $client) {
                [void]$udp.Send($bytes, $bytes.Length, $client)
            }
            if ($Mode -eq 'observe') { "s2c,$serverPackets,$($bytes.Length)" }
            continue
        }

        $client = [System.Net.IPEndPoint]::new($from.Address, $from.Port)
        $clientPackets++
        $out = $bytes

        # The custom client sends the application record after four or more
        # client-to-server handshake records. Select the first later record.
        # Flood mode ignores the packet count and corrupts EVERY application_data
        # record (type 0x17) so it drives the failed-auth counter without
        # disturbing the handshake itself.
        $isApp = $bytes[0] -eq 0x17
        if ($Mode -eq 'flood') {
            # DTLS 1.3 no longer puts 0x17 in the *outer* header for app data
            # (the real type is encrypted in the inner record), so the $isApp
            # byte test used by the other modes is unreliable here. Instead gate
            # purely on client packet order: packets 1-3 are the handshake
            # flight, so anything at index >=4 is application_data. Corrupt all
            # of those (loose length filter just avoids tiny non-record noise).
            $candidate = $clientPackets -ge 4 -and $bytes.Length -ge 30
        }
        else {
            $candidate = $clientPackets -ge 4 -and $bytes.Length -ge 40 -and $bytes.Length -le 80
        }
        if ($candidate -and $Mode -ne 'observe' -and ($Mode -eq 'flood' -or $Mode -ne 'replay' -or -not $changed)) {
            $changed = $true
            switch ($Mode) {
                'tamper' {
                    $out = [byte[]]$bytes.Clone()
                    $out[$out.Length - 1] = $out[$out.Length - 1] -bxor 1
                }
                'truncate' {
                    $newLength = [Math]::Max(1, $bytes.Length - 8)
                    $out = [byte[]]::new($newLength)
                    [Array]::Copy($bytes, $out, $newLength)
                }
                'replay' {
                    $out = $bytes
                }
                'sequence' {
                    # Unified DTLS 1.3 header: flags, 16-bit wire record
                    # number, then 16-bit length. Change only the wire number.
                    $out = [byte[]]$bytes.Clone()
                    $out[2] = $out[2] -bxor 1
                }
                'epoch' {
                    # The low two flags bits carry the compact-header epoch
                    # bits (EE_MASK = 0x3). Change only one epoch bit.
                    $out = [byte[]]$bytes.Clone()
                    $out[0] = $out[0] -bxor 1
                }
                'flood' {
                    # Corrupt EVERY qualifying record (used to drive the
                    # forced-KeyUpdate path); same mutation as 'tamper'.
                    $out = [byte[]]$bytes.Clone()
                    $out[$out.Length - 1] = $out[$out.Length - 1] -bxor 1
                }
            }
            "action=$Mode,client_packet=$clientPackets,length=$($bytes.Length),sent_length=$($out.Length)"
        }

        if ($Mode -eq 'observe') {
            $hex = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
            "c2s,$clientPackets,$($bytes.Length),$hex"
        }
        [void]$udp.Send($out, $out.Length, $server)
        if ($Mode -eq 'replay' -and $changed) {
            [void]$udp.Send($out, $out.Length, $server)
        }
    }
}
finally {
    $udp.Dispose()
}
