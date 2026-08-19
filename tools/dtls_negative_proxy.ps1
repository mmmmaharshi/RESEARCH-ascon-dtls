param(
    [ValidateSet('observe','tamper','replay','truncate','sequence','epoch','flood')]
    [string]$Mode = 'observe',
    [int]$ListenPort = 12000,
    [int]$ServerPort = 11111,
    [int]$DurationSeconds = 15,
    [int]$CorruptIndex = 1,
    [int]$MinLen = 1,
    [int]$MaxLen = 2000
)

function Corrupt-Tags($arr) {
    # Flip the last byte of the AEAD tag of every record in $arr.
    # DTLS 1.3 record: 5-byte header, length at bytes[3,4] (big-endian),
    # record = header + len bytes, tag = last 16 bytes. Flipping any tag
    # byte makes AEAD verification fail, so the server rejects it
    # regardless of payload size. ponytail: fixed 5-byte header matches our
    # client's records; extend if real-wire variable headers appear.
    $off = 0
    while ($off + 5 -le $arr.Length) {
        $len = ([int]$arr[$off + 3] -shl 8) + $arr[$off + 4]
        $recEnd = $off + 5 + $len
        if ($recEnd -gt $arr.Length) { break }
        if ($len -ge 16) { $arr[$recEnd - 1] = [byte]($arr[$recEnd - 1] -bxor 1) }
        $off = $recEnd
    }
}

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path "$env:TEMP\ascon-dtls-work" | Out-Null
$udp.Client.ReceiveBufferSize = 1MB
$udp.Client.SendBufferSize = 1MB
$udp.Client.ReceiveTimeout = 200
$server = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $ServerPort)
$client = $null
$clientPackets = 0
$serverPackets = 0
$changed = $false
$qualifyingCount = 0
$seen = @{}          # distinct app-record identity (content hash) -> $true
$distinctCount = 0   # how many distinct app records seen so far
$targetId = $null    # content hash of the Nth app record to corrupt
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
                try { [void]$udp.Send($bytes, $bytes.Length, $client) }
                catch { "s2c-fwd-ERR:$_" }
            }
            "s2c,serverPkt=$serverPackets,len=$($bytes.Length)"
            continue
        }

        $client = [System.Net.IPEndPoint]::new($from.Address, $from.Port)
        $clientPackets++
        $out = $bytes
        # DIAGNOSTIC: log every received datagram (client + server) so we can
        # see how wolfSSL actually fragments the handshake/app traffic.
        "rcv,fromport=$($from.Port),len=$($bytes.Length),clientPkt=$clientPackets"

        # Select application_data records: in DTLS 1.3 the outer header is 0x17
        # for every record (the real type is encrypted inside), so we gate on
        # client packet order instead. Packets 1-3 are the handshake flight;
        # >=4 are application_data. Size range is configurable (-MinLen/-MaxLen)
        # so we can exercise tiny and large records. -CorruptIndex selects which
        # qualifying record to corrupt (flood corrupts all of them).
        # Identify application_data records by their outer header byte (0x2f for our
        # client). Count DISTINCT app records by content hash so retransmissions
        # don't inflate the index. Corrupt the Nth distinct app record AND every
        # retransmit of it, so the server rejects it on first receipt (a duplicate
        # retransmit is still corrupted, keeping it rejected). ponytail: header
        # byte 0x2f is our client's app-record marker; widen if other types appear.
        $isApp = ($bytes[0] -eq 0x2f)
        # Identity by the CLEARTEXT 5-byte header (flags+epoch+length). In DTLS 1.3
        # the sequence number is encrypted (not in the cleartext header), so a
        # retransmitted record has the SAME header but different ciphertext/tag.
        # Targeting by full content hash would miss retransmits; targeting by the
        # stable header corrupts EVERY transmission of the target record.
        $recId = ($bytes[0..4] | ForEach-Object { $_.ToString('x2') }) -join ''
        if ($isApp) {
            if (-not $seen.ContainsKey($recId)) { $seen[$recId] = $true; $distinctCount++ }
            if ($distinctCount -eq $CorruptIndex) { $targetId = $recId }
        }
        $alreadyForwarded = $false
        if ($Mode -ne 'observe' -and ($isApp -or $Mode -eq 'replay')) {
                if ($Mode -eq 'replay') {
                    if (-not $changed) {
                        $changed = $true
                        # replay: forward this record a second time (anti-replay test)
                        [void]$udp.Send($bytes, $bytes.Length, $server)
                        $alreadyForwarded = $true
                        "action=replay,idx=$distinctCount,client_packet=$clientPackets,length=$($bytes.Length),sent_length=$($bytes.Length)"
                    }
                    $out = $bytes
                }
            else {
                $qualifyingCount++
                # Corrupt the Nth distinct app record and every retransmit of it.
                $isTarget = ($Mode -eq 'flood') -or ($targetId -ne $null -and $recId -eq $targetId)
                if ($isTarget) {
                    # Corrupt a byte INSIDE the first record's AEAD region.
                    # The DTLS 1.3 unified header has a VARIABLE length: the
                    # sequence number is encoded in 1-4 bytes by value, so a
                    # fixed early offset (byte[5]) lands inside the header for
                    # later/large records and is ignored by AEAD (server
                    # accepts -> see tools/_diag_tamper.ps1). Instead we flip a
                    # byte that is always past the header and inside the
                    # ciphertext/tag of the first (application) record: offset
                    # 16, or the last byte for very small records. Flipping any
                    # byte in the AEAD ciphertext or tag makes verification
                    # fail, so the record is rejected regardless of size or
                    # header length.
                    [System.IO.File]::WriteAllText("$env:TEMP\ascon-dtls-work\tamper_raw_$clientPackets.hex", ($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
                    $out = [byte[]]$bytes.Clone()
                    switch ($Mode) {
                        'tamper'   { Corrupt-Tags $out }
                        'flood'    { Corrupt-Tags $out }
                        'truncate' { $n = [Math]::Max(1, $bytes.Length - 1); $o2 = [byte[]]::new($n); [Array]::Copy($bytes,$o2,$n); $out = $o2 }
                        'sequence' { $out[2] = $out[2] -bxor 1 }
                        'epoch'    { $out[0] = $out[0] -bxor 1 }
                    }
                    $hLen = [Math]::Min(16, $out.Length); $oh = ($out[0..($hLen - 1)] | ForEach-Object { '{0:x2}' -f $_ }) -join ''
                    $otHex = if ($out.Length -ge 16) { ($out[($out.Length - 16)..($out.Length - 1)] | ForEach-Object { '{0:x2}' -f $_ }) -join '' } else { '' }
                    "action=$Mode,idx=$qualifyingCount,client_packet=$clientPackets,length=$($bytes.Length),sent_length=$($out.Length),out_head=$oh,out_tail=$otHex"
                    [System.IO.File]::WriteAllText("$env:TEMP\ascon-dtls-work\tamper_out_$clientPackets.hex", ($out | ForEach-Object { $_.ToString('x2') }) -join '')
                }
                else {
                    $out = $bytes
                }
            }
        }

        if ($Mode -eq 'observe') {
            $hex = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
            "c2s,$clientPackets,$($bytes.Length),$hex"
        }
        if (-not $alreadyForwarded) {
            "fwd,to=$($server.Address):$($server.Port),len=$($out.Length),c2s=$clientPackets"
            try { $n = $udp.Send($out, $out.Length, $server); "fwd-ok,n=$n" }
            catch { "fwd-ERR:$_" }
        }
    }
}
finally {
    $udp.Dispose()
}
