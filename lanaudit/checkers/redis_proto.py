"""Redis AUTH check over the raw RESP protocol (no redis-py dependency).

Also flags the far more common real-world issue: Redis with NO password at
all, reachable from the LAN — that's a bigger problem than a weak one.
"""
import socket


def _send_cmd(sock, *args):
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        b = a.encode() if isinstance(a, str) else a
        out += f"${len(b)}\r\n".encode() + b + b"\r\n"
    sock.sendall(out)
    sock.settimeout(1.5)
    return sock.recv(1024)


def check(ip, port, username, password, timeout):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        # Any Redis-looking service responds to PING with +PONG even before auth
        # if no password is required at all; that's not a "weak password" per se
        # but worth surfacing. We encode it as success for the empty password.
        resp = _send_cmd(sock, "PING")
        if resp.startswith(b"+PONG") and password == "":
            return True
        if password:
            resp = _send_cmd(sock, "AUTH", password)
            if resp.startswith(b"+OK"):
                return True
            if resp.startswith(b"-WRONGPASS") or resp.startswith(b"-ERR"):
                return False
        return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
