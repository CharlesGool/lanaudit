"""Best-effort Telnet login check over a raw socket.

`telnetlib` was removed from the stdlib in Python 3.13, so this talks the
(tiny, option-negotiation-free) subset of the protocol by hand: it just
reads whatever the server sends, replies to IAC option negotiation with a
generic "won't/don't", and looks for login/password prompts in plain text.
Success detection is heuristic — treat a `True` result as "worth checking
by hand", not as certain.
"""
import socket
import time

IAC, DONT, WONT = 255, 254, 252


def _strip_and_ack_iac(sock, data: bytes) -> bytes:
    """Remove Telnet IAC option-negotiation sequences, replying WONT/DONT to
    keep the server from waiting on us, and return the remaining plain text.
    """
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd = data[i + 1]
            opt = data[i + 2]
            if cmd in (251, 253):  # WILL / DO -> refuse
                reply = bytes([IAC, WONT if cmd == 251 else DONT, opt])
                try:
                    sock.sendall(reply)
                except OSError:
                    pass
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def _read_for(sock, seconds):
    sock.settimeout(seconds)
    buf = b""
    end = time.time() + seconds
    while time.time() < end:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf += _strip_and_ack_iac(sock, chunk)
    return buf


def check(ip, port, username, password, timeout):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        banner = _read_for(sock, timeout)
        low = banner.lower()
        if b"login" in low or b"username" in low:
            sock.sendall(username.encode() + b"\r\n")
            after_user = _read_for(sock, timeout)
            low2 = after_user.lower()
            if b"password" in low2:
                sock.sendall(password.encode() + b"\r\n")
                final = _read_for(sock, timeout).lower()
                if any(w in final for w in (b"incorrect", b"failed", b"denied",
                                             b"login:", b"invalid")):
                    return False
                if any(c in final for c in (b"$", b"#", b">", b"welcome")):
                    return True
                return None
        return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
