#!/usr/bin/env python3
"""udp_relay_pcap.py — UDP loopback relay that records both directions into a pcap.

Client -> relay:11112 -> server:11111 and replies back. Every datagram is the
authentic wire bytes of a live DTLS 1.3 handshake; the pcap just wraps them
(LINKTYPE_RAW so tshark dissects UDP/DTLS directly).
"""
import socket, struct, sys, time

LISTEN = ("127.0.0.1", 11112)
SERVER = ("127.0.0.1", 11111)
PCAP = sys.argv[1] if len(sys.argv) > 1 else "dtls13-ascon.pcap"

out = open(PCAP, "wb")
out.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))  # LINKTYPE_RAW
t0 = None

def record(data, src):
    global t0
    now = time.time()
    if t0 is None:
        t0 = now
    # fake IPv4 header (20 B) + UDP header (8 B) around the real payload
    udp_len = 8 + len(data)
    total = 20 + udp_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
    sport = LISTEN[1] if src == "c" else SERVER[1]
    dport = SERVER[1] if src == "c" else LISTEN[1]
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    pkt = ip + udp + data
    out.write(struct.pack("<IIII", int(now - t0), int((now - t0) % 1 * 1e6), len(pkt), len(pkt)))
    out.write(pkt)

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(LISTEN)
client_addr = None
srv.settimeout(15)
try:
    while True:
        data, addr = srv.recvfrom(65535)
        if addr[1] != SERVER[1]:
            client_addr = addr          # from client
            record(data, "c")
            srv.sendto(data, SERVER)
        else:
            record(data, "s")           # from server
            if client_addr:
                srv.sendto(data, client_addr)
except socket.timeout:
    pass
out.close()
print("wrote", PCAP)
