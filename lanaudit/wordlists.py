"""Built-in wordlists. Extend further via --password/--username or
--password-file/--username-file on the CLI.
"""
import os

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

DEFAULT_USERNAMES = [
    "admin", "root", "administrator", "user", "guest", "support",
    "ubnt", "pi", "cisco", "service", "manager", "default",
]

# Default/known-weak passwords seen on routers, cameras, DVRs, NAS boxes
# and other home-network devices that wouldn't otherwise show up in a
# general password list.
_DEVICE_DEFAULTS = [
    "", "admin", "password", "123456", "12345678", "admin123",
    "root", "toor", "pass", "1234", "123456789", "default",
    "guest", "support", "888888", "666666", "000000", "111111",
    "smcadmin", "ubnt", "raspberry", "changeme", "letmein",
    "qwerty", "1qaz2wsx", "P@ssw0rd", "passw0rd",
]


def _load_common_passwords():
    """The ~10k most common real-world passwords (SecLists'
    Common-Credentials/10k-most-common.txt, MIT licensed — see
    https://github.com/danielmiessler/SecLists). Bundled so the default
    `audit` run covers a meaningfully large set of known-weak passwords,
    not just a handful of device defaults.
    """
    path = os.path.join(_DATA_DIR, "common_passwords.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [line.rstrip("\n") for line in fh if line.strip()]
    except OSError:
        return []


# Device defaults first (more likely to be the real finding on IoT-ish
# gear, and short enough that trying them never meaningfully slows a scan
# down), then the big common-password list.
DEFAULT_PASSWORDS = list(dict.fromkeys(_DEVICE_DEFAULTS + _load_common_passwords()))


def load_list(cli_values, file_path):
    """Merge CLI-provided values with a file (one entry per line), de-duplicated,
    order-preserving. Returns [] entries for empty-password checks are kept as "".
    """
    out = []
    seen = set()

    def add(v):
        if v not in seen:
            seen.add(v)
            out.append(v)

    for v in cli_values or []:
        add(v)
    if file_path:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n").rstrip("\r")
                if line.startswith("#"):
                    continue
                add(line)
    return out
