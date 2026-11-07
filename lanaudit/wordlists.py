"""Small built-in wordlists. Kept intentionally short: this tool is meant to
check a handful of obvious/default/known-leaked credentials on your OWN
devices, not to run a dictionary attack. Extend via --password/--username
or --password-file/--username-file on the CLI.
"""

DEFAULT_USERNAMES = [
    "admin", "root", "administrator", "user", "guest", "support",
    "ubnt", "pi", "cisco", "service", "manager", "default",
]

# Common default / known-weak passwords seen on routers, cameras, DVRs,
# NAS boxes and other home-network devices. Intentionally short.
DEFAULT_PASSWORDS = [
    "", "admin", "password", "123456", "12345678", "admin123",
    "root", "toor", "pass", "1234", "123456789", "default",
    "guest", "support", "888888", "666666", "000000", "111111",
    "smcadmin", "ubnt", "raspberry", "changeme", "letmein",
    "qwerty", "1qaz2wsx", "P@ssw0rd", "passw0rd",
]


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
