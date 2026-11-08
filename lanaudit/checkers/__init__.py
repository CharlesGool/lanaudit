"""Per-protocol weak-credential checkers.

Every checker function has the signature:
    check(ip, port, username, password, timeout) -> bool | None
returning True on a confirmed successful login, False on a confirmed
rejection, or None if the protocol/library required isn't available or the
attempt was inconclusive (treated as a failure by the caller, but logged
differently so the user knows to check manually).

A checker may also appear in PRECHECKS: precheck(ip, port, timeout) -> bool,
called once per target *before* running any password through it. Returning
False means the whole password list would be pointless here (e.g. a plain
HTTP page that was never gated by Basic auth at all) and the caller should
skip the target entirely instead of learning the same "not applicable"
answer again on every single attempt.
"""
import functools

from .ssh import check as check_ssh, precheck as precheck_ssh
from .ftp import check as check_ftp
from .telnet import check as check_telnet
from .http_basic import check as check_http_basic, precheck as precheck_http_basic
from .redis_proto import check as check_redis
from .rtsp import check as check_rtsp

REGISTRY = {
    "ssh": check_ssh,
    "ftp": check_ftp,
    "telnet": check_telnet,
    "http": functools.partial(check_http_basic, use_tls=False),
    "https": functools.partial(check_http_basic, use_tls=True),
    "redis": check_redis,
    "rtsp": check_rtsp,
}

PRECHECKS = {
    "http": functools.partial(precheck_http_basic, use_tls=False),
    "https": functools.partial(precheck_http_basic, use_tls=True),
    "ssh": precheck_ssh,
}
