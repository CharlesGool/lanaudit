"""SSH password-auth check. Requires `paramiko` (optional dependency)."""
try:
    import paramiko
    _HAVE_PARAMIKO = True
except ImportError:
    _HAVE_PARAMIKO = False


def check(ip, port, username, password, timeout):
    if not _HAVE_PARAMIKO:
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, port=port, username=username, password=password,
            timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        # Connection refused, protocol mismatch, etc. — not a credential result.
        return None
