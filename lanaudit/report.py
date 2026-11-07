"""Render scan/audit results as JSON and a human-readable Markdown report."""
import json
from dataclasses import asdict


def discovery_to_dict(hosts):
    return [{"ip": h.ip, "name": h.name, "ports": [asdict(p) for p in h.ports]} for h in hosts]


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


RISK_HINTS = {
    "telnet": "Telnet 明文传输账号密码,建议直接关闭,改用 SSH。",
    "ftp": "FTP 明文传输账号密码,建议关闭或换成 SFTP。",
    "redis": "Redis 对局域网开放且允许空密码/弱密码,任何能访问这个网段的设备都能直接读写数据,建议设置强密码并限制访问来源。",
    "rtsp": "摄像头/NVR 的视频流可以被任何知道密码的人直接查看,建议立即修改密码。",
    "vnc": "VNC 开放意味着能远程操作这台设备的桌面,建议确认是否必要,并设置强密码。",
    "http": "网页管理后台暴露在局域网里,建议修改为强密码,并考虑限制访问来源。",
    "https": "网页管理后台暴露在局域网里,建议修改为强密码,并考虑限制访问来源。",
    "ssh": "SSH 允许弱密码登录,建议立即修改密码,并考虑改为仅密钥登录。",
    "ftp_anon": "FTP 允许匿名访问。",
}


def render_markdown(subnet, hosts, findings):
    lines = [f"# 局域网安全扫描报告", "", f"目标网段: `{subnet}`", ""]
    lines.append("## 发现的设备")
    lines.append("")
    if not hosts:
        lines.append("(没有发现开放端口的主机)")
    for h in hosts:
        lines.append(f"### {h.ip}" + (f"  —  {h.name}" if h.name else ""))
        for p in h.ports:
            label = p.http_title or p.http_server or p.banner or ""
            tag = "" if p.confirmed else " **[未确认,可能是本机代理/VPN 造成的误判]**"
            lines.append(f"- 端口 {p.port} ({p.guessed_service}) {('— ' + label) if label else ''}{tag}")
        lines.append("")

    lines.append("## 弱密码 / 风险发现")
    lines.append("")
    if not findings:
        lines.append("本次没有用提供的用户名/密码组合测出任何能登录的服务。")
    else:
        for f in findings:
            hint = RISK_HINTS.get(f["service"], "")
            pw_display = f["password"] if f["password"] else "(空密码)"
            lines.append(
                f"- **{f['ip']}:{f['port']}** ({f['service']}) — "
                f"用户名 `{f['username']}` / 密码 `{pw_display}` 登录成功。{hint}"
            )
    lines.append("")
    lines.append("---")
    lines.append("这份报告只对你在命令行里指定的网段和账号密码生效,没有尝试任何其他网络或密码。")
    return "\n".join(lines)
