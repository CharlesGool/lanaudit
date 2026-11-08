"""SSH password-auth check. Requires `paramiko` (optional dependency)."""
import logging

try:
    import paramiko
    _HAVE_PARAMIKO = True
    # paramiko logs every dropped/reset connection (which is most of a scan's
    # misses, not an actual problem) through its own logger at ERROR level,
    # which by default prints a full traceback straight to stderr — drowning
    # out the one line per host that actually matters. Our caller already
    # treats these as a normal "inconclusive" result; no need to also spam
    # the terminal.
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
except ImportError:
    _HAVE_PARAMIKO = False


def precheck(ip, port, timeout):
    """Called once per target: does this sshd even accept password auth at
    all? A key-only server (password auth disabled, the now-common hardened
    state) will reject every single one of 10k+ passwords identically — no
    point spending the whole list to learn that, when one auth_none probe
    tells us up front via the server's advertised auth-method list."""
    if not _HAVE_PARAMIKO:
        return False
    transport = None
    try:
        transport = paramiko.Transport((ip, port))
        transport.start_client(timeout=timeout)
        try:
            transport.auth_none("lanaudit-precheck")
            return True  # no auth required at all -- worth trying real creds
        except paramiko.BadAuthenticationType as e:
            return "password" in e.allowed_types
        except paramiko.AuthenticationException:
            return True
    except Exception:
        # Connection/protocol error -- let the real attempts surface it
        # rather than silently skipping a target we couldn't even probe.
        return True
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass


def check(ip, port, username, password, timeout):
    if not _HAVE_PARAMIKO:
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(
                ip, port=port, username=username, password=password,
                timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
                allow_agent=False, look_for_keys=False,
            )
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            # Connection refused, protocol mismatch, etc. — not a credential result.
            return None
    finally:
        # Every rejected/failed attempt used to skip this (close() was only
        # on the success path), leaking the Transport thread + socket for
        # every single wrong guess -- thousands of them across a real audit
        # run. Left enough of those running concurrently at process exit to
        # cause native-level corruption (observed as a glibc "double free or
        # corruption (fasttop)" abort right after a real run finished).
        try:
            client.close()
        except Exception:
            pass
