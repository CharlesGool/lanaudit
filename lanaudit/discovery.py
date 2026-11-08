"""Read-only network discovery: port scan + banner grab + best-effort service
fingerprint. Never sends credentials. Safe to run against your own LAN at
any time.
"""
from __future__ import annotations

import concurrent.futures
import errno
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
    111: "rpcbind", 135: "msrpc", 2179: "vmconnect", 3702: "ws-discovery",
    5357: "wsdapi", 5985: "winrm", 5986: "winrm-https", 7680: "wu-do",
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
    mac: str = ""
    vendor: str = ""
    possibly_banned: bool = False


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


def _sniff_service_from_banner(banner: str) -> str:
    """When a port's number tells us nothing (moved off its well-known port,
    or found via a --full sweep with no --service hint), the banner itself
    often still gives it away -- most usefully for SSH, since that's also
    what `audit`'s checker registry needs to actually test it."""
    if banner.startswith("SSH-"):
        return "ssh"
    if banner.startswith("220") and "FTP" in banner.upper():
        return "ftp"
    return ""


def _scan_port(ip, port, connect_timeout, read_timeout, service_map):
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

    clean = _clean_banner(banner)
    guessed = service_map.get(port, "unknown")
    if guessed == "unknown":
        guessed = _sniff_service_from_banner(clean) or guessed
    info = PortInfo(port=port, guessed_service=guessed, banner=clean)
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
            got_evidence = True  # a real HTTP response even without a <title>/Server header
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
    elif not info.banner:
        # Connected, but neither the port number nor a passive banner told us
        # anything. A huge share of "random" open ports on modern machines
        # (dev servers, container dashboards, self-hosted UIs) are plain
        # HTTP/HTTPS regardless of port number, so try that as a generic
        # fallback before giving up and calling it "unknown" -- try HTTP
        # first (cheaper, no TLS handshake), then HTTPS.
        raw = _http_probe(ip, port, use_tls=False, timeout=read_timeout)
        used_tls = False
        if not raw:
            raw = _http_probe(ip, port, use_tls=True, timeout=read_timeout)
            used_tls = True
        if raw:
            title, server, auth = _parse_http(raw)
            info.http_title, info.http_server, info.http_auth = title, server, auth
            info.guessed_service = "https" if used_tls else "http"
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


def _arp_table_hosts():
    """{ip: mac} for every address with a *resolved* entry in this machine's
    ARP cache (includes STALE, which is still a real past reply, just not
    refreshed recently) -- these got there because the device actually
    answered an ARP request at some point, independent of whether it has
    any TCP port open. /proc/net/arp's Flags column's ATF_COM bit (0x2) is
    what distinguishes an actual resolved entry from an incomplete one
    (flags 0x0, HW address 00:00:00:00:00:00) left behind by an ARP
    request that nothing ever answered -- e.g. every dead address a
    previous port scan tried to connect() to. Without this check, those
    unanswered entries looked exactly like real devices.
    """
    hosts = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 4 or parts[0].count(".") != 3:
                    continue
                try:
                    flags = int(parts[2], 16)
                except ValueError:
                    continue
                if flags & 0x2:  # ATF_COM -- actually resolved, not a pending/failed attempt
                    hosts[parts[0]] = parts[3]
    except OSError:
        pass
    return hosts


def _classify_connect(ip, port, timeout):
    """Like _tcp_connect, but keeps the *reason* a connection didn't open
    instead of collapsing it to None -- that distinction is exactly what
    tells a genuinely-closed port apart from one a firewall is silently
    dropping packets for (see _looks_banned)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        err = s.connect_ex((ip, port))
    except socket.timeout:
        s.close()
        return "timeout"
    except OSError:
        s.close()
        return "error"
    if err == 0:
        s.close()
        return "open"
    s.close()
    # ECONNREFUSED (Linux 111, same errno constant cross-platform via the
    # errno module) means the kernel on the other end actually answered
    # with a TCP RST -- a real "nothing is listening here" answer. Any
    # other non-zero errno from a *timed-out* settimeout() socket would
    # have raised socket.timeout above instead of landing here, so by
    # elimination everything else here is also a real (if unusual) refusal.
    return "refused" if err == errno.ECONNREFUSED else "error"


def _looks_banned(ip, ports, timeout, max_workers=32, sample_size=12):
    """Best-effort guess at whether *this machine specifically* is
    currently being firewalled by the target (e.g. its own fail2ban/banip
    reacting to an earlier, unrelated scan/audit against it) rather than
    the target genuinely having nothing listening. The tell: a real closed
    port answers with an immediate TCP RST (classified "refused" above);
    a firewall rule silently dropping this source's packets just times
    out, with no RST at all. If every single port we tried timed out and
    not one came back refused, that's the ban/drop signature, not "a
    quiet device" -- a quiet device still has *some* closed ports that
    answer normally.
    """
    sample = ports[:sample_size] if len(ports) > sample_size else ports
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(lambda p: _classify_connect(ip, p, timeout), sample))
    return ("open" not in results and "refused" not in results
            and results.count("timeout") >= 3)


def _ping_sweep(hosts, timeout=1.0, max_workers=256):
    """Best-effort ICMP ping of each address, mainly to *provoke* an ARP
    reply from devices that have gone quiet (and don't otherwise show up
    in _arp_table_hosts()) -- most smart-home/IoT gear answers ARP/ICMP
    even though it has no TCP service worth auditing. Silently returns an
    empty set if the `ping` binary isn't usable (no privilege, sandboxed,
    etc.) rather than failing the whole scan over a liveness nicety."""
    import shutil
    import subprocess

    if not shutil.which("ping"):
        return set()

    def _ping_one(ip):
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout + 1,
            )
            return ip if r.returncode == 0 else None
        except Exception:
            return None

    alive = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for ip, ok in zip(hosts, ex.map(_ping_one, hosts)):
            if ok:
                alive.add(ip)
    return alive


def scan_subnet(subnet: str = None, ports=None, extra_ports=None, connect_timeout=0.35,
                 read_timeout=1.2, max_workers=200, progress_cb=None, lookup_names=True,
                 target_ips=None, include_portless=False):
    """Scan hosts for `ports`. Returns a list of HostResult for hosts that
    had at least one open port.

    Give either `subnet` (a CIDR, every address in it is scanned) or
    `target_ips` (an explicit list of addresses — the full-port two-phase
    scan uses this to sweep 1-65535 only against hosts a first, cheap pass
    already confirmed are alive, instead of every address in the subnet).

    `connect_timeout` bounds the initial connect() attempt (kept short since
    most of a /24 is dead IPs/closed ports); `read_timeout` only applies once
    a connection actually succeeds, while we try to read a real banner or do
    an active protocol probe — give that one more room, especially if the
    path to the target goes through a relay/tunnel.

    `extra_ports` is a {port: service} dict layered on top of the built-in
    COMMON_PORTS table (added, not replacing it) — the only way to find a
    service you've deliberately moved off its well-known port, since this
    scanner never sweeps the full 1-65535 range on its own.

    `include_portless`: also report addresses that answered ARP/ICMP but
    had no TCP port open at all (as a HostResult with an empty `ports`
    list) -- most smart-home/IoT devices fall in this bucket, and without
    this they'd simply be missing from the output with no indication they
    were even looked at. Only applies when scanning a `subnet` (a CIDR);
    ignored for an explicit `target_ips` list, since that's already a
    known-live set from a previous pass.
    """
    service_map = {**COMMON_PORTS, **(extra_ports or {})}
    ports = ports or list(service_map)
    if target_ips is not None:
        hosts = list(target_ips)
    else:
        net = ipaddress.ip_network(subnet, strict=False)
        # .hosts() returns a plain list (not a generator) for /31 and /32 --
        # either way a for-loop/comprehension over it works fine.
        hosts = [str(h) for h in net.hosts()]

    results = {}
    tasks = [(ip, p) for ip in hosts for p in ports]
    done = 0
    report_every = max(200, len(tasks) // 500)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_scan_port, ip, p, connect_timeout, read_timeout, service_map): (ip, p)
                for ip, p in tasks}
        for fut in concurrent.futures.as_completed(futs):
            ip, _port = futs[fut]
            done += 1
            if progress_cb and done % report_every == 0:
                progress_cb(done, len(tasks))
            info = fut.result()
            if info is not None:
                results.setdefault(ip, []).append(info)

    out = [HostResult(ip=ip, ports=sorted(infos, key=lambda i: i.port))
           for ip, infos in results.items()]

    if include_portless and target_ips is None:
        subnet_ips = set(hosts)
        _ping_sweep(hosts, timeout=connect_timeout, max_workers=max_workers)
        # Re-read the ARP cache *after* pinging -- a successful ping just
        # populated fresh entries for anything that was quiet before.
        arp_map = _arp_table_hosts()
        portless = (set(arp_map) & subnet_ips) - set(results)
        out.extend(HostResult(ip=ip, ports=[], mac=arp_map.get(ip, ""),
                               possibly_banned=_looks_banned(ip, ports, connect_timeout))
                   for ip in portless)
        for h in out:
            if not h.mac and h.ip in arp_map:
                h.mac = arp_map[h.ip]
        _attach_vendors(out, timeout=read_timeout)

    out.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")))

    if out and lookup_names:
        _attach_names(out, timeout=read_timeout, max_workers=max_workers)
    return out


def _mac_vendor(mac, timeout=2.0):
    """Best-effort OUI vendor lookup via the free macvendors.com API --
    network-dependent and silently returns "" on any failure (offline,
    rate-limited, unknown prefix), since this is a nice-to-have label, not
    something the scan should ever block or fail on."""
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{mac}",
                                      headers={"User-Agent": "lanaudit"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _attach_vendors(hosts, timeout):
    """One vendor lookup per unique MAC (several hosts can share nothing,
    but no point re-querying the same OUI twice in one run). Low
    concurrency on purpose -- macvendors.com's free tier is rate-limited
    per second, and a burst just means more empty results, not faster
    ones."""
    macs = sorted({h.mac for h in hosts if h.mac and not h.vendor})
    if not macs:
        return
    vendor_by_mac = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(_mac_vendor, m, timeout): m for m in macs}
        for fut in concurrent.futures.as_completed(futs):
            vendor_by_mac[futs[fut]] = fut.result()
    for h in hosts:
        if h.mac in vendor_by_mac:
            h.vendor = vendor_by_mac[h.mac]


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
