"""HTTP/HTTPS Basic-Auth check (routers, printers, NVRs, cheap IoT UIs)."""
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check(ip, port, username, password, timeout):
    scheme = "https" if port in (443, 4443, 5001, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        # First confirm the page actually gates on Basic auth at all — otherwise
        # every "password" would look like a hit just because the page is public.
        bare = requests.get(url, timeout=timeout, verify=False)
        if bare.status_code != 401 or "basic" not in bare.headers.get("WWW-Authenticate", "").lower():
            return None
        r = requests.get(url, auth=(username, password), timeout=timeout, verify=False)
    except requests.RequestException:
        return None
    if r.status_code == 401:
        return False
    if r.status_code in (200, 301, 302, 303):
        return True
    return None
