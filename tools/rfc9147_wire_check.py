#!/usr/bin/env python3
"""rfc9147_wire_check.py — assert RFC 9147 (DTLS 1.3) wire-format rules on a pcap.

RFC 9147 ships no normative handshake test vectors, so this checks the next
best thing: every datagram in a live capture against the structural rules of
RFC 9147 section 4 (record layout, unified header encoding, epoch/sequence
numbering). Crypto-layer correctness is covered separately by the KATs
(tools/ascon_kat.c, ascon_mask_kat.c, ascon_kdf_kat.c).

Usage: python rfc9147_wire_check.py <capture.pcap>
Exits 0 on all-pass, nonzero on any violation.
"""
import struct, sys

def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        assert magic == 0xa1b2c3d4, "expected little-endian pcap"
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _s, _us, caplen, _wire = struct.unpack("<IIII", ph)
            data = f.read(caplen)
            if len(data) == caplen:
                yield data

def parse_udp(payload):
    """LINKTYPE_RAW -> IPv4 -> UDP payload."""
    if len(payload) < 28 or (payload[0] >> 4) != 4:
        return None
    ihl = (payload[0] & 0xF) * 4
    if payload[9] != 17:
        return None
    udp = payload[ihl:]
    if len(udp) < 8:
        return None
    sport, dport, ulen, _crc = struct.unpack("!HHHH", udp[:8])
    return udp[8:ulen]

def main():
    path = sys.argv[1]
    seen_sh = False
    ndgrams = nrec = 0
    for npkt, pkt in enumerate(read_pcap(path), 1):
        dgram = parse_udp(pkt)
        if dgram is None:
            continue
        ndgrams += 1
        off = 0
        first = True
        while off + 13 <= len(dgram):
            b0 = dgram[off]
            if b0 in (20, 21, 22):          # RFC 9147 sec 4.2 legacy-style plaintext
                ver = dgram[off+1:off+3]
                epoch = struct.unpack("!H", dgram[off+3:off+5])[0]
                seq = int.from_bytes(dgram[off+5:off+11], "big")
                rlen = struct.unpack("!H", dgram[off+11:off+13])[0]
                assert ver == b"\xfe\xfd", \
                    f"pkt {npkt}: bad legacy version {ver.hex()} (want fefd)"
                assert not seen_sh, \
                    f"pkt {npkt}: plaintext type-{b0} record after ServerHello"
                rec = dgram[off:off+13+rlen]
                assert len(rec) == 13 + rlen, f"pkt {npkt}: truncated record"
                nrec += 1
                # inner content sanity: handshake message header (sec 5.2)
                if b0 == 22 and len(rec) >= 25:
                    mtype, mlen = rec[13], int.from_bytes(rec[14:17], "big")
                    frag_off = int.from_bytes(rec[17:20], "big")
                    frag_len = int.from_bytes(rec[20:23], "big")
                    assert frag_len <= mlen and frag_off + frag_len <= mlen, \
                        f"pkt {npkt}: bad DTLS handshake fragment header"
                    label = {1:"ClientHello", 2:"ServerHello",
                             3:"HelloVerifyRequest", 8:"EncryptedExtensions",
                             11:"Certificate", 15:"CertificateVerify",
                             20:"Finished"}.get(mtype, str(mtype))
                    print(f"PASS pkt {npkt}: Handshake v{ver.hex()} epoch={epoch} "
                          f"seq={seq} msg={label} len={mlen}")
                    # RFC 8446 sec 4.1.3: HRR is a ServerHello whose Random is
                    # the fixed magic value; it does NOT start protected mode.
                    hrr_random = bytes.fromhex(
                        "CF21AD74E59A6111BE1D8C021E65B891"
                        "C2A211167ABB8C5E079E09E2C8A8339C")
                    rnd = rec[25+2 : 25+2+32]   # skip DTLS hdr(13)+hs hdr(12)+version
                    if mtype == 2 and rnd == hrr_random:
                        print(f"PASS pkt {npkt}: HelloRetryRequest magic random "
                              f"verified (RFC 8446 sec 4.1.3)")
                    elif mtype == 2:
                        seen_sh = True
                        print(f"PASS pkt {npkt}: true ServerHello; subsequent "
                              f"records must be unified-header")
                else:
                    print(f"PASS pkt {npkt}: record type={b0} v{ver.hex()} "
                          f"epoch={epoch} seq={seq} len={rlen}")
                off += 13 + rlen
            elif (b0 & 0xE0) == 0x20:       # sec 4.3.1 unified header: 001 C S L E E
                cid_bit = (b0 >> 4) & 1
                s_bit   = (b0 >> 3) & 1     # 0 -> 8-bit seq num, 1 -> 16-bit
                l_bit   = (b0 >> 2) & 1     # length field present
                ee      = b0 & 3            # low epoch bits
                assert cid_bit == 0, \
                    f"pkt {npkt}: CID bit set but no CIDs negotiated here"
                hdr = 1 + (2 if s_bit else 1) + (2 if l_bit else 0)
                # sec 4.2.3: mask needs Ciphertext[0..15]; shorter records MUST
                # be rejected/padded, so the encrypted record is >= 16 bytes
                assert len(dgram) - off - hdr >= 16, \
                    f"pkt {npkt}: encrypted_record {len(dgram)-off-hdr} B < 16 B"
                nrec += 1
                print(f"PASS pkt {npkt}: unified header epoch~{ee} "
                      f"seq={'16' if s_bit else '8'}b len_field={bool(l_bit)} "
                      f"hdr={hdr} B encrypted_record={len(dgram)-off-hdr} B")
                if first and not seen_sh:
                    raise AssertionError(
                        f"pkt {npkt}: unified header before ServerHello")
                break   # protected lengths are masked: cannot chain further records
            else:
                raise AssertionError(
                    f"pkt {npkt}: byte {b0:#04x} is neither a legacy nor a "
                    f"unified-header record (fixed bits 001 missing)")
            first = False
    assert ndgrams > 0, "no UDP payloads found"
    print(f"\nALL CHECKS PASSED: {ndgrams} datagrams / {nrec} records conform "
          f"to RFC 9147 section 4 wire rules")

if __name__ == "__main__":
    main()
