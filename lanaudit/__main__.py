"""lanaudit CLI.

  lanaudit scan  --subnet 192.168.1.0/24
  lanaudit audit --subnet 192.168.1.0/24 --i-own-this-network \
                  --password "myOldWifiPassword" --password-file extra.txt

`scan` only does read-only port/banner discovery — no credentials are ever
sent. `audit` additionally tries a short list of default/known-weak
passwords (plus anything you supply) against the services it finds, so you
can tell whether any device on your own network is still using one of them.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import sys
import threading
import time

# Banners/titles pulled off random devices can contain bytes that don't map
# cleanly to the host's console code page (this bit Windows cmd/PowerShell
# with non-UTF-8 code pages). Never let a garbled banner crash the scan.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

from . import discovery, report
from .checkers import REGISTRY
from .wordlists import DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_list

BANNER = """\
lanaudit — local-network service & weak-password auditor
只能用于你自己拥有或已获得明确授权测试的网络。对别人的网络账号/设备做密码尝试,
未经允许在大多数地方是违法的(例如美国的 CFAA、中国的网络安全法)。
"""


def _print_progress(done, total):
    print(f"\r扫描中... {done}/{total}", end="", file=sys.stderr, flush=True)


def _findings_table(findings):
    cols = [("IP", "ip"), ("端口", "port"), ("服务", "service"),
            ("用户名", "username"), ("密码", "password")]
    rows = [[str(f[key]) if f[key] != "" else "(空)" for _, key in cols] for f in findings]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, (h, _) in enumerate(cols)]
    def fmt_row(cells):
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths))
    lines = [fmt_row([h for h, _ in cols]), fmt_row(["-" * w for w in widths])]
    lines += [fmt_row(r) for r in rows]
    return "\n".join(lines)


def _detect_lockout(timeline):
    """timeline: [(submission_seq, True/False/None), ...] for every attempt
    that actually ran against one host/port (skipped-because-already-done
    entries are excluded by the caller). If the device started out giving
    real rejections (False) and then, later in submission order, the tail
    turns into an unbroken run of None (checker couldn't even complete the
    protocol handshake — connection refused/reset/timed out), that's the
    signature of a self-protecting lockout/ban kicking in partway through,
    not just noise: a device with no such protection keeps answering False
    the whole way through.
    """
    if len(timeline) < 10:
        return None
    timeline = sorted(timeline, key=lambda t: t[0])
    results = [r for _, r in timeline]
    last_real = max((i for i, r in enumerate(results) if r is False), default=-1)
    if last_real < 0:
        return None  # never got a real rejection at all -- nothing to compare against
    tail = results[last_real + 1:]
    if len(tail) < 5:
        return None
    none_run = 0
    for r in reversed(tail):
        if r is None:
            none_run += 1
        else:
            break
    if none_run >= 5 and none_run / len(tail) > 0.8:
        return {"rejected": last_real + 1, "stalled": none_run}
    return None


def _preflight_check(args):
    import ipaddress
    net = ipaddress.ip_network(args.subnet, strict=False)
    sample_ip = str(next(net.hosts()))
    if discovery.transparent_proxy_warning(sample_ip):
        print(
            "\n[!] 警告: 这台机器上好像有一个系统级透明代理/VPN(比如开着 TUN 模式的"
            "Clash/mihomo、某些企业 VPN),会让任意端口的 connect() 都立刻'成功',"
            "导致扫出来的'开放端口'大量是假的。\n"
            "    建议:先关掉代理的 TUN 模式,或者把这个网段加入代理的直连/绕过名单,"
            "再重新扫描。\n"
            "    报告里没有抓到真实协议回应(banner/HTTP 响应)的端口会被标成"
            "'未确认',请不要直接采信这些端口。\n", file=sys.stderr)
        if not args.force:
            try:
                ans = input("仍要继续吗? (结果里的'未确认'端口会不可信) 输入 yes 继续: ")
            except EOFError:
                ans = ""
            if ans.strip().lower() != "yes":
                raise SystemExit(1)


def cmd_scan(args):
    print(BANNER, file=sys.stderr)
    _preflight_check(args)
    print(f"[*] 正在扫描 {args.subnet} ...", file=sys.stderr)
    t0 = time.time()
    hosts = discovery.scan_subnet(args.subnet, connect_timeout=args.connect_timeout,
                                   read_timeout=args.timeout, max_workers=args.workers,
                                   progress_cb=_print_progress, lookup_names=not args.no_names)
    print(f"\n[*] 完成,用时 {time.time()-t0:.1f}s,发现 {len(hosts)} 台有开放端口的主机",
          file=sys.stderr)
    for h in hosts:
        print(f"\n{h.ip}" + (f"  ({h.name})" if h.name else ""))
        for p in h.ports:
            label = p.http_title or p.http_server or p.banner
            tag = "" if p.confirmed else "  [未确认,可能是代理误判]"
            print(f"  {p.port:>6}  {p.guessed_service:<8} {label[:80]}{tag}")
    if args.json:
        report.write_json(args.json, report.discovery_to_dict(hosts))
        print(f"\n[*] JSON 已保存到 {args.json}", file=sys.stderr)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(report.render_markdown(args.subnet, hosts, []))
        print(f"[*] Markdown 报告已保存到 {args.markdown}", file=sys.stderr)
    return hosts


def _confirm_scope(args, usernames, passwords):
    if args.i_own_this_network:
        return True
    print(BANNER, file=sys.stderr)
    print(f"即将对网段 {args.subnet} 尝试登录 {len(usernames)} 个用户名 x "
          f"{len(passwords)} 个密码的组合。", file=sys.stderr)
    try:
        ans = input("你确认这整个网段的设备都归你所有或已获得明确授权测试吗? 输入 yes 继续: ")
    except EOFError:
        return False
    return ans.strip().lower() == "yes"


def cmd_audit(args):
    usernames = load_list(args.usernames_extra, args.username_file) or list(DEFAULT_USERNAMES)
    passwords = load_list(args.passwords_extra, args.password_file) or list(DEFAULT_PASSWORDS)

    if not _confirm_scope(args, usernames, passwords):
        print("已取消。", file=sys.stderr)
        return 1

    hosts = cmd_scan(args)

    cap = args.max_fail if args.max_fail > 0 else None
    cap_desc = f"每台设备累计失败 {cap} 次后跳过" if cap else "每台设备会把密码表试完,不会提前放弃"
    print(f"\n[*] 用户名 {len(usernames)} 个 x 密码 {len(passwords)} 个,"
          f"每台设备 {args.audit_workers} 个线程并发尝试({cap_desc})...", file=sys.stderr)

    findings = []
    lockout_suspects = []
    for h in hosts:
        for p in h.ports:
            checker = REGISTRY.get(p.guessed_service)
            if checker is None:
                continue
            found = threading.Event()
            cap_hit = threading.Event()
            fail_count = [0]
            lock = threading.Lock()
            timeline = []  # (seq, result) in submission order, filled in as completed

            combos = [(u, pw) for u in usernames for pw in passwords]

            def attempt(seq, username, password):
                if found.is_set() or cap_hit.is_set():
                    return seq, username, password, None, True  # skipped, not a real outcome
                result = checker(h.ip, p.port, username, password, args.timeout)
                if args.delay:
                    time.sleep(args.delay)
                with lock:
                    if result is True:
                        found.set()
                    elif result is False:
                        fail_count[0] += 1
                        if cap and fail_count[0] >= cap:
                            cap_hit.set()
                return seq, username, password, result, False

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.audit_workers) as ex:
                futs = [ex.submit(attempt, i, u, pw) for i, (u, pw) in enumerate(combos)]
                for fut in concurrent.futures.as_completed(futs):
                    seq, username, password, result, skipped = fut.result()
                    if not skipped:
                        timeline.append((seq, result))
                    if result is True:
                        findings.append({"ip": h.ip, "port": p.port,
                                          "service": p.guessed_service,
                                          "username": username, "password": password})
                        print(f"\n[!] {h.ip}:{p.port} ({p.guessed_service}) "
                              f"{username}/{password or '(空)'} 登录成功", file=sys.stderr)

            suspect = _detect_lockout(timeline)
            if suspect:
                suspect.update(ip=h.ip, port=p.port, service=p.guessed_service)
                lockout_suspects.append(suspect)

    print(f"\n[*] 完成,共 {len(findings)} 处弱密码/无密码可登录。", file=sys.stderr)
    if findings:
        print("\n" + _findings_table(findings))
    if lockout_suspects:
        print(f"\n[*] {len(lockout_suspects)} 处疑似触发了设备自己的失败锁定/封禁"
              f"(前面还在正常拒绝,后面一段全部连不上/没反应):", file=sys.stderr)
        for s in lockout_suspects:
            print(f"  - {s['ip']}:{s['port']} ({s['service']}): 正常拒绝 {s['rejected']} 次后,"
                  f"后面 {s['stalled']} 次全部无响应", file=sys.stderr)
    if args.json:
        data = report.discovery_to_dict(hosts)
        report.write_json(args.json, {"hosts": data, "findings": findings})
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(report.render_markdown(args.subnet, hosts, findings))
        print(f"[*] Markdown 报告已保存到 {args.markdown}", file=sys.stderr)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="lanaudit", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--subnet", required=True, help="CIDR,例如 192.168.1.0/24")
    common.add_argument("--timeout", type=float, default=1.2,
                         help="连上之后读取 banner/协议回应的超时(秒)。局域网里如果有"
                              "透明代理/TUN VPN 或要跨隧道访问,真实服务的数据可能要多转"
                              "一道手,适当调大能减少漏判(不影响扫描速度,只有真连上的"
                              "端口才会等这么久)")
    common.add_argument("--connect-timeout", type=float, default=0.35,
                         help="TCP connect() 本身的超时(秒),决定扫描速度的主要是这个,"
                              "网络好的话可以调小,比如 0.15")
    common.add_argument("--workers", type=int, default=200,
                         help="扫描并发线程数,纯 I/O 等待,调大基本不费 CPU,"
                              "网络/对端能扛得住的话可以调到 500+ 提速")
    common.add_argument("--json", help="把结果写成 JSON 文件")
    common.add_argument("--markdown", help="把结果写成 Markdown 报告文件")
    common.add_argument("--force", action="store_true",
                         help="跳过透明代理/VPN 的预检查警告,直接开始扫描")
    common.add_argument("--no-names", action="store_true",
                         help="不尝试反查设备名(反向 DNS / NetBIOS),扫描会快一点")

    s = sub.add_parser("scan", parents=[common], help="只做端口/服务发现,不尝试任何密码")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("audit", parents=[common],
                        help="在 scan 的基础上,用指定的用户名/密码尝试登录发现的服务")
    a.add_argument("--i-own-this-network", action="store_true",
                    help="跳过交互式确认(用于非交互/CI 环境,仍然只在确认过的范围内运行)")
    a.add_argument("--username", dest="usernames_extra", action="append",
                    help="额外尝试的用户名,可重复传入")
    a.add_argument("--password", dest="passwords_extra", action="append",
                    help="额外尝试的密码,可重复传入(你怀疑泄露的密码放这里)")
    a.add_argument("--username-file", help="每行一个用户名的文件")
    a.add_argument("--password-file", help="每行一个密码的文件")
    a.add_argument("--max-fail", type=int, default=0,
                    help="同一台设备累计失败多少次后跳过。默认 0 = 不设上限,"
                         "密码表会试完;担心把有登录锁定机制的设备越试越锁,"
                         "可以设一个数,比如 6(并发下这个数不再是\"连续\"失败,"
                         "是总的失败次数)")
    a.add_argument("--audit-workers", type=int, default=16,
                    help="对同一台设备同一个服务,同时并发尝试几个用户名/密码组合"
                         "(默认 16)。调大能明显提速,也正好用来看这台设备有没有"
                         "\"同 IP 短时间内多次失败就封禁/限速\"的防护——如果开大了之后"
                         "后面全部连不上,报告里会提示疑似触发了锁定")
    a.add_argument("--delay", type=float, default=0.3,
                    help="每个线程每次尝试之间的延迟(秒),默认 0.3;改成 0 就是不限速")
    a.set_defaults(func=cmd_audit)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
