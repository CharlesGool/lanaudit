"""Read-only network discovery: port scan + banner grab + best-effort service
fingerprint. Never sends credentials. Safe to run against your own LAN at
any time.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field

from . import names

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 81: "http", 88: "http", 139: "smb", 443: "https",
    445: "smb", 554: "rtsp", 631: "ipp", 808: "http", 873: "rsync",
    1080: "socks", 1400: "http", 1883: "mqtt", 2222: "ssh", 3000: "http",
    3306: "mysql", 3389: "rdp", 4443: "https", 5000: "http", 5001: "https",
    5432: "postgres", 5555: "http", 5900: "vnc", 6379: "redis",
    7000: "http", 7001: "http", 7788: "http", 8000: "http", 8008: "http",
    8080: "http", 8081: "http", 8082: "http", 8083: "http", 8443: "https",
    8888: "http", 8899: "http", 9000: "http", 9090: "http", 9100: "jetdirect",
    10001: "http", 20000: "http", 32400: "http", 37777: "dvr", 49152: "upnp",
}

HTTP_PORTS = {80, 81, 88, 808, 1400, 3000, 5000, 5555, 7000, 7001, 7788,
              8000, 8008, 8080, 8081, 8082, 8083, 8888, 8899, 9000, 9090,
              10001, 20000, 32400}
HTTPS_PORTS = {443, 4443, 5001, 8443}


@dataclass
class PortInfo:
    port: int
    guessed_service: str
    banner: str = ""
    http_title: str = ""
    http_server: str = ""
    http_auth: str = ""
    # True once we've actually exchanged protocol data with the port, not
    # just had connect() succeed — see transparent_proxy_warning() for why
    # a bare connect() isn't trustworthy on a machine running a TUN proxy/VPN.
    confirmed: bool = False


@dataclass
class HostResult:
    ip: str
    ports: list = field(default_factory=list)
    name: str = ""


def _tcp_connect(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0:
            return None
        return s
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return None


def _grab_banner(s, timeout):
    try:
        s.settimeout(timeout)
        return s.recv(256)
    except OSError:
        return b""


def _http_probe(ip, port, use_tls, timeout):
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
        else:
            sock = raw_sock
        sock.settimeout(timeout)
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: lanaudit\r\n\r\n".encode())
        data = b""
        while len(data) < 8000:
            chunk = sock.recv(2048)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data
    except OSError:
        return b""


# Active probes for protocols that stay silent until the client speaks first
# (so a passive recv() after connect() tells us nothing — and nothing is
# exactly what a transparent-proxy false "open" port also looks like).
# Each returns raw response bytes, or b"" if nothing protocol-shaped came back.

_REDIS_PING = b"*1\r\n$4\r\nPING\r\n"
# Classic "cookie-less" RDP X.224 Connection Request (TPKT + X.224 CR with an
# RDP Negotiation Request requesting SSL/CredSSP/RDP) — widely used by RDP
# health-check tools to elicit a Connection Confirm without a real session.
# Written as an explicit byte list (not a hex string) so a stray character
# can't silently corrupt the packet.
_RDP_CONNECTION_REQUEST = bytes([
    0x03, 0x00, 0x00, 0x13,  # TPKT: version 3, reserved, length=0x0013 (19 bytes)
    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,  # X.224 Connection Request TPDU
    0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00,  # RDP Negotiation Request
])


def _active_probe(ip, port, timeout, send: bytes, read_len=2048):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return b""
    try:
        s.sendall(send)
        s.settimeout(timeout)
        return s.recv(read_len)
    except OSError:
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def _probe_redis(ip, port, timeout):
    resp = _active_probe(ip, port, timeout, _REDIS_PING)
    return resp if resp[:1] in (b"+", b"-") else b""


def _probe_rdp(ip, port, timeout):
    resp = _active_probe(ip, port, timeout, _RDP_CONNECTION_REQUEST, read_len=64)
    # TPKT header (0x03 0x00) followed by an X.224 Connection Confirm (0xd0).
    return resp if resp[:2] == b"\x03\x00" and b"\xd0" in resp[:8] else b""


def _probe_rtsp(ip, port, timeout):
    req = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
    resp = _active_probe(ip, port, timeout, req)
    return resp if resp.startswith(b"RTSP/1.0") else b""


ACTIVE_PROBES = {
    "redis": _probe_redis,
    "rdp": _probe_rdp,
    "rtsp": _probe_rtsp,
}


def _parse_http(raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    title = ""
    m = re.search(r"<title[^>]*>([^<]{1,160})</title>", text, re.I)
    if m:
        title = m.group(1).strip()
    server = ""
    m = re.search(r"^Server:\s*([^\r\n]{1,100})", text, re.I | re.M)
    if m:
        server = m.group(1).strip()
    auth = ""
    m = re.search(r"^WWW-Authenticate:\s*([^\r\n]{1,160})", text, re.I | re.M)
    if m:
        auth = m.group(1).strip()
    return title, server, auth


def _clean_banner(raw: bytes) -> str:
    """Most text-banner protocols (SSH, FTP, Telnet, SMTP...) send one
    greeting line and then immediately start a binary handshake (SSH's
    KEX_INIT, in particular) that our 256-byte banner read also happens to
    catch the start of. Keep only the first line, and only if it looks like
    actual text — otherwise there's nothing readable to show.
    """
    first_line = raw.split(b"\n", 1)[0].split(b"\r", 1)[0]
    if not first_line:
        return ""
    text = first_line.decode("utf-8", errors="replace").strip()
    # A banner that's mostly replacement/control characters isn't text at
    # all (binary protocol with no greeting line) -- don't show it.
    printable = sum(1 for c in text if c.isprintable())
    if not text or printable / max(len(text), 1) < 0.9:
        return ""
    return text[:200]


def _scan_port(ip, port, connect_timeout, read_timeout):
    # Most of a /24 is dead IPs and closed/filtered ports — paying the full
    # (generously long, for proxied/relayed real services) read timeout on
    # every single one of those makes a full scan crawl. So: fail fast on
    # connect(), only spend the longer timeout once something is actually
    # listening and we're trying to read real protocol data out of it.
    s = _tcp_connect(ip, port, connect_timeout)
    if s is None:
        return None
    banner = _grab_banner(s, read_timeout)
    try:
        s.close()
    except OSError:
        pass

    info = PortInfo(port=port, guessed_service=COMMON_PORTS.get(port, "unknown"),
                     banner=_clean_banner(banner))
    # A real but binary/line-less banner (MySQL's greeting packet, say)
    # still proves the port answered with protocol data even if there was
    # no readable text to show for it -- track that separately from what
    # ends up in the (cosmetic) `banner` field.
    got_evidence = bool(banner)

    if port in HTTP_PORTS or port in HTTPS_PORTS:
        raw = _http_probe(ip, port, use_tls=port in HTTPS_PORTS, timeout=read_timeout)
        if raw:
            title, server, auth = _parse_http(raw)
            info.http_title, info.http_server, info.http_auth = title, server, auth
            info.guessed_service = "https" if port in HTTPS_PORTS else "http"
    elif info.guessed_service in ACTIVE_PROBES and not info.banner:
        # Services that stay silent until spoken to: a bare connect() success
        # tells us nothing (and is exactly what a transparent proxy fakes), so
        # send the real handshake and only trust a protocol-shaped reply.
        # These protocols (RDP, Redis, RTSP) don't hand back human-readable
        # text even when they're genuinely confirmed, so show a fixed label
        # instead of dumping raw/partly-binary bytes to the console.
        resp = ACTIVE_PROBES[info.guessed_service](ip, port, read_timeout)
        if resp:
            info.banner = f"{info.guessed_service.upper()} 握手确认"
            got_evidence = True

    info.confirmed = bool(got_evidence or info.http_title or info.http_server or info.http_auth)
    return info


def transparent_proxy_warning(sample_ip: str, timeout=1.0) -> bool:
    """Return True if this machine looks like it has a system-wide
    transparent proxy / TUN VPN that makes every TCP connect() succeed
    regardless of the real destination (common with Clash/mihomo/Surge in
    TUN mode, some corporate VPN clients, etc.). When that's the case, a
    plain connect()-based port scan is meaningless — every port on every
    host looks "open". We probe a few almost-certainly-unused high ports on
    the first scan target; if they *all* connect instantly, something is
    intercepting the traffic.
    """
    probe_ports = (54321, 23457, 48213)
    hits = 0
    for port in probe_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((sample_ip, port)) == 0:
                hits += 1
        except OSError:
            pass
        finally:
            s.close()
    return hits == len(probe_ports)


def scan_subnet(subnet: str, ports=None, connect_timeout=0.35, read_timeout=1.2,
                 max_workers=200, progress_cb=None, lookup_names=True):
    """Scan every host address in `subnet` (CIDR) for `ports`. Returns a list
    of HostResult for hosts that had at least one open port.

    `connect_timeout` bounds the initial connect() attempt (kept short since
    most of a /24 is dead IPs/closed ports); `read_timeout` only applies once
    a connection actually succeeds, while we try to read a real banner or do
    an active protocol probe — give that one more room, especially if the
    path to the target goes through a relay/tunnel.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    ports = ports or list(COMMON_PORTS)
    hosts = [str(h) for h in net.hosts()]

    results = {}
    tasks = [(ip, p) for ip in hosts for p in ports]
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_scan_port, ip, p, connect_timeout, read_timeout): (ip, p)
                for ip, p in tasks}
        for fut in concurrent.futures.as_completed(futs):
            ip, _port = futs[fut]
            done += 1
            if progress_cb and done % 200 == 0:
                progress_cb(done, len(tasks))
            info = fut.result()
            if info is not None:
                results.setdefault(ip, []).append(info)

    out = [HostResult(ip=ip, ports=sorted(infos, key=lambda i: i.port))
           for ip, infos in results.items()]
    out.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")))

    if out and lookup_names:
        _attach_names(out, timeout=read_timeout, max_workers=max_workers)
    return out


def _attach_names(hosts, timeout, max_workers):
    """One reverse-DNS + one NetBIOS query per discovered host, in parallel.
    Best-effort — a name that can't be found just stays empty."""
    def resolve(h):
        name = names.reverse_dns(h.ip, timeout=min(timeout, 0.8))
        if not name:
            name = names.netbios_name(h.ip, timeout=min(timeout, 0.8))
        return h.ip, name

    by_ip = {h.ip: h for h in hosts}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(hosts) or 1)) as ex:
        futs = {ex.submit(resolve, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            ip, name = fut.result()
            by_ip[ip].name = name
