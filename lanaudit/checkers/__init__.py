"""Per-protocol weak-credential checkers.

Every checker function has the signature:
    check(ip, port, username, password, timeout) -> bool | None
returning True on a confirmed successful login, False on a confirmed
rejection, or None if the protocol/library required isn't available or the
attempt was inconclusive (treated as a failure by the caller, but logged
differently so the user knows to check manually).
"""
from .ssh import check as check_ssh
from .ftp import check as check_ftp
from .telnet import check as check_telnet
from .http_basic import check as check_http_basic
from .redis_proto import check as check_redis
from .rtsp import check as check_rtsp

REGISTRY = {
    "ssh": check_ssh,
    "ftp": check_ftp,
    "telnet": check_telnet,
    "http": check_http_basic,
    "https": check_http_basic,
    "redis": check_redis,
    "rtsp": check_rtsp,
}
