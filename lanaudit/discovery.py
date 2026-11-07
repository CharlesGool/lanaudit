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


def _scan_port(ip, port, timeout):
    s = _tcp_connect(ip, port, timeout)
    if s is None:
        return None
    banner = _grab_banner(s, min(timeout, 0.6))
    try:
        s.close()
    except OSError:
        pass

    info = PortInfo(port=port, guessed_service=COMMON_PORTS.get(port, "unknown"),
                     banner=banner.decode("utf-8", errors="replace").strip()[:200])

    if port in HTTP_PORTS or port in HTTPS_PORTS:
        raw = _http_probe(ip, port, use_tls=port in HTTPS_PORTS, timeout=timeout)
        if raw:
            title, server, auth = _parse_http(raw)
            info.http_title, info.http_server, info.http_auth = title, server, auth
            info.guessed_service = "https" if port in HTTPS_PORTS else "http"

    info.confirmed = bool(info.banner or info.http_title or info.http_server or info.http_auth)
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


def scan_subnet(subnet: str, ports=None, timeout=0.6, max_workers=80, progress_cb=None):
    """Scan every host address in `subnet` (CIDR) for `ports`. Returns a list
    of HostResult for hosts that had at least one open port.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    ports = ports or list(COMMON_PORTS)
    hosts = [str(h) for h in net.hosts()]

    results = {}
    tasks = [(ip, p) for ip in hosts for p in ports]
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_scan_port, ip, p, timeout): (ip, p) for ip, p in tasks}
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
    return out
