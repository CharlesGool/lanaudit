"""FTP login check using the stdlib ftplib."""
import ftplib


def check(ip, port, username, password, timeout):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception:
        return None
