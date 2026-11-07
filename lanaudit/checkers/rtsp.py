"""RTSP (IP camera) login check: DESCRIBE with Basic or Digest auth,
hand-rolled since no good stdlib/lightweight RTSP client exists.
"""
import base64
import hashlib
import re
import socket


def _parse_status(data: bytes):
    m = re.match(rb"RTSP/1\.0\s+(\d+)", data)
    return int(m.group(1)) if m else None


def _digest_header(www_auth: str, username, password, uri, method="DESCRIBE"):
    def field(name):
        m = re.search(name + r'="([^"]*)"', www_auth)
        return m.group(1) if m else ""
    realm, nonce = field("realm"), field("nonce")
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{response}"')


def check(ip, port, username, password, timeout):
    uri = f"rtsp://{ip}:{port}/"
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock.sendall(f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        sock.settimeout(1.5)
        resp = sock.recv(2048)
        status = _parse_status(resp)
        if status == 200:
            return None  # no auth required at all, not a "weak password" finding
        if status != 401:
            return None
        text = resp.decode("utf-8", errors="replace")
        m = re.search(r"WWW-Authenticate:\s*(.+)", text, re.I)
        if not m:
            return None
        www_auth = m.group(1).strip()

        sock.close()
        sock = socket.create_connection((ip, port), timeout=timeout)
        if www_auth.lower().startswith("digest"):
            auth_header = _digest_header(www_auth, username, password, uri)
        else:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            auth_header = f"Basic {token}"
        sock.sendall(
            f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\nAuthorization: {auth_header}\r\n\r\n".encode()
        )
        sock.settimeout(1.5)
        resp2 = sock.recv(2048)
        status2 = _parse_status(resp2)
        if status2 == 200:
            return True
        if status2 == 401:
            return False
        return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
