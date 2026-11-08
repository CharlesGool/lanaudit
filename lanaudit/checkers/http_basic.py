"""HTTP/HTTPS Basic-Auth check (routers, printers, NVRs, cheap IoT UIs).

`use_tls` says which of "http"/"https" this target was found as (discovery
already determined this — a service found on a nonstandard port doesn't
necessarily match the handful of hardcoded HTTPS ports this used to guess
from, which silently used the wrong scheme for anything else).
"""
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _url(ip, port, use_tls):
    return f"{'https' if use_tls else 'http'}://{ip}:{port}/"


def precheck(ip, port, timeout, use_tls=False):
    """Called once per target, before spending any attempts on it: is this
    page even gated by Basic auth at all? A page that just returns its
    content (or any non-401 status) will never show a "right password" no
    matter what's tried, so there's no point running the whole password
    list against it a request at a time."""
    try:
        bare = requests.get(_url(ip, port, use_tls), timeout=timeout, verify=False)
    except requests.RequestException:
        return False
    return bare.status_code == 401 and "basic" in bare.headers.get("WWW-Authenticate", "").lower()


def check(ip, port, username, password, timeout, use_tls=False):
    # precheck() already confirmed this target is Basic-auth-gated; callers
    # that skip it (using this checker directly) get the same "not
    # applicable" -> None behavior, just paying for it on every attempt.
    try:
        bare = requests.get(_url(ip, port, use_tls), timeout=timeout, verify=False)
        if bare.status_code != 401 or "basic" not in bare.headers.get("WWW-Authenticate", "").lower():
            return None
        r = requests.get(_url(ip, port, use_tls), auth=(username, password),
                          timeout=timeout, verify=False)
    except requests.RequestException:
        return None
    if r.status_code == 401:
        return False
    if r.status_code in (200, 301, 302, 303):
        return True
    return None
