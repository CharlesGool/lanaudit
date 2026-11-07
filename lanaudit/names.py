"""Best-effort device-name lookup for a LAN host: reverse DNS (via whatever
nameserver the system/router already uses — many home routers' dnsmasq
know the DHCP hostname of every device they've leased an address to) and
a NetBIOS name-service query (works well against Windows/Samba machines,
which usually don't register DNS names at all).

Both are read-only queries; neither sends any credentials.
"""
import socket
import struct


# ---------------------------------------------------------------------------
# Reverse DNS (PTR), hand-rolled so each lookup gets its own bounded timeout
# instead of fighting over socket.setdefaulttimeout() across scanner threads.
# ---------------------------------------------------------------------------

def _resolv_conf_nameserver():
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except OSError:
        pass
    return None


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _read_dns_name(data: bytes, offset: int, _depth=0):
    """Decode a (possibly compressed) DNS name starting at `offset`. Returns
    (name, offset_after). Follows compression pointers with a depth guard.
    """
    if _depth > 20:
        return "", offset
    labels = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            pointed, _ = _read_dns_name(data, pointer, _depth + 1)
            labels.append(pointed)
            offset += 2
            return ".".join(filter(None, labels)), offset
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(filter(None, labels)), offset


def reverse_dns(ip: str, timeout: float, nameserver: str = None) -> str:
    nameserver = nameserver or _resolv_conf_nameserver()
    if not nameserver:
        return ""
    try:
        octets = ip.split(".")
        ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa"
        qname = _encode_dns_name(ptr_name)
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        query = header + qname + struct.pack(">HH", 12, 1)  # PTR, IN

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(query, (nameserver, 53))
            data, _ = s.recvfrom(1024)
        finally:
            s.close()

        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount < 1:
            return ""
        # Skip the question section we sent (same qname length + 4 bytes).
        offset = 12 + len(qname) + 4
        for _ in range(ancount):
            _, offset = _read_dns_name(data, offset)
            rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 12:  # PTR
                name, _ = _read_dns_name(data, offset)
                return name.rstrip(".")
            offset += rdlength
        return ""
    except (OSError, struct.error, UnicodeDecodeError):
        return ""


# ---------------------------------------------------------------------------
# NetBIOS Name Service (NBSTAT) query, UDP/137 — identifies the machine name
# of Windows/Samba hosts, which typically have no reverse DNS at all.
# ---------------------------------------------------------------------------

# The fixed wildcard NetBIOS name "*" (padded to 16 bytes with 0x00, which is
# itself a non-standard-but-widely-used variant some stacks need; the classic
# nbtscan wildcard works against essentially everything), first-level-encoded
# per RFC 1001/1002's half-ASCII scheme.
_NBSTAT_QUERY = (
    b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    b"\x00\x21\x00\x01"
)


def netbios_name(ip: str, timeout: float) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(_NBSTAT_QUERY, (ip, 137))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()

        # Header(12) + queried name echoed back (34) + TYPE/CLASS/TTL/RDLEN(10)
        rdata_offset = 12 + 34 + 10
        if len(data) <= rdata_offset:
            return ""
        num_names = data[rdata_offset]
        entries = data[rdata_offset + 1:]
        for i in range(num_names):
            entry = entries[i * 18:(i + 1) * 18]
            if len(entry) < 18:
                break
            raw_name, suffix = entry[:15], entry[15]
            if suffix == 0x00:  # workstation/computer name, not a service alias
                name = raw_name.decode("ascii", "replace").strip()
                if name:
                    return name
        return ""
    except (OSError, IndexError):
        return ""
