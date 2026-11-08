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
import collections
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
from .checkers import PRECHECKS, REGISTRY
from .wordlists import DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_list

BANNER = """\
lanaudit — local-network service & weak-password auditor
只能用于你自己拥有或已获得明确授权测试的网络。对别人的网络账号/设备做密码尝试,
未经允许在大多数地方是违法的(例如美国的 CFAA、中国的网络安全法)。
"""


def _print_progress(done, total):
    print(f"\r扫描中... {done}/{total}", end="", file=sys.stderr, flush=True)


def _table(headers, rows):
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    def fmt_row(cells):
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths))
    lines = [fmt_row(headers), fmt_row(["-" * w for w in widths])]
    lines += [fmt_row(r) for r in rows]
    return "\n".join(lines)


def _findings_table(findings):
    cols = [("IP", "ip"), ("端口", "port"), ("服务", "service"),
            ("用户名", "username"), ("密码", "password")]
    rows = [[str(f[key]) if f[key] != "" else "(空)" for _, key in cols] for f in findings]
    return _table([h for h, _ in cols], rows)


def _scan_table(hosts):
    headers = ["IP", "设备名", "端口", "服务", "信息"]
    rows = []
    for h in hosts:
        for i, p in enumerate(h.ports):
            label = p.http_title or p.http_server or p.banner
            if not p.confirmed:
                label = (label + " " if label else "") + "[未确认,可能是代理误判]"
            rows.append([h.ip if i == 0 else "", h.name if i == 0 else "",
                         str(p.port), p.guessed_service, label[:80]])
    return _table(headers, rows)


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
    # .hosts() is a generator for most networks but a plain list for /31 and
    # /32 (no distinct network/broadcast address to exclude there) -- iter()
    # makes next() work either way.
    sample_ip = str(next(iter(net.hosts()), net.network_address))
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


def _parse_extra_ports(args):
    port_nums = load_list([str(p) for p in (args.extra_ports or [])], args.port_file)
    service_overrides = {}
    for entry in args.port_services or []:
        port_str, _, svc = entry.partition(":")
        if port_str.strip().isdigit() and svc:
            service_overrides[int(port_str)] = svc
    extra = {}
    for p in port_nums:
        p = int(p)
        extra[p] = service_overrides.get(p, "unknown")
    extra.update(service_overrides)  # a --service for a port not in --port still counts
    return extra


def cmd_scan(args):
    """CLI entry point for `scan` -- returns a process exit code."""
    _run_scan(args)
    return 0


def _run_scan(args):
    """The actual scan, returning the discovered hosts. Shared by `cmd_scan`
    (which must return an int exit code to the CLI, not this) and `cmd_audit`
    (which needs the hosts list to run credential checks against)."""
    print(BANNER, file=sys.stderr)
    _preflight_check(args)
    extra_ports = _parse_extra_ports(args)
    t0 = time.time()

    if not args.full:
        print(f"[*] 正在扫描 {args.subnet} ...", file=sys.stderr)
        hosts = discovery.scan_subnet(args.subnet, extra_ports=extra_ports,
                                       connect_timeout=args.connect_timeout,
                                       read_timeout=args.timeout, max_workers=args.workers,
                                       progress_cb=_print_progress, lookup_names=not args.no_names)
    else:
        # Two phases: a cheap common-ports pass finds which addresses in the
        # subnet actually have something listening at all, then only THOSE
        # hosts get the expensive full 1-65535 sweep -- scanning every dead
        # IP in a /24 across all 65535 ports is the part this tool was never
        # going to do efficiently, and skipping dead addresses is exactly
        # what a real attacker's recon would do too (no point port-sweeping
        # an address nothing answers on at all).
        print(f"[*] 第一阶段:用常见端口表快速摸一遍 {args.subnet},找出哪些地址在线...",
              file=sys.stderr)
        live_hosts = discovery.scan_subnet(args.subnet, extra_ports=extra_ports,
                                            connect_timeout=args.connect_timeout,
                                            read_timeout=args.timeout, max_workers=args.workers,
                                            progress_cb=_print_progress, lookup_names=False)
        live_ips = [h.ip for h in live_hosts]
        print(f"\n[*] 第一阶段完成,用时 {time.time()-t0:.1f}s,{len(live_ips)} 台地址有响应",
              file=sys.stderr)

        n_tasks = len(live_ips) * 65535
        if n_tasks > 2_000_000 and not args.force:
            print(
                f"[!] 这 {len(live_ips)} 台在线设备全部做 --full 全端口扫描,粗算约 "
                f"{n_tasks:,} 个任务,这台 Python 实现会在提交阶段就占用大量内存、花很久。"
                f"真的全都要扫的话继续,或者改用 --subnet 只对着你最关心的那几台单独跑。\n",
                file=sys.stderr)
            try:
                ans = input("继续对这些设备做全端口扫描吗? 输入 yes 继续(或者用 --force 跳过这个确认): ")
            except EOFError:
                ans = ""
            if ans.strip().lower() != "yes":
                raise SystemExit(1)

        if not live_ips:
            hosts = []
        else:
            print(f"[*] 第二阶段:对这 {len(live_ips)} 台地址扫描全部 1-65535 端口...",
                  file=sys.stderr)
            t1 = time.time()
            hosts = discovery.scan_subnet(target_ips=live_ips, ports=list(range(1, 65536)),
                                           extra_ports=extra_ports,
                                           connect_timeout=args.connect_timeout,
                                           read_timeout=args.timeout, max_workers=args.workers,
                                           progress_cb=_print_progress, lookup_names=not args.no_names)
            print(f"\n[*] 第二阶段完成,用时 {time.time()-t1:.1f}s", file=sys.stderr)

    print(f"\n[*] 完成,总用时 {time.time()-t0:.1f}s,发现 {len(hosts)} 台有开放端口的主机",
          file=sys.stderr)
    if hosts:
        print("\n" + _scan_table(hosts))
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
    # --password/--password-file ADD to the default list, they don't replace
    # it -- `--password` was silently skipping the ~10k built-in list
    # entirely (load_list(...) or DEFAULT_PASSWORDS never falls through once
    # you've supplied anything), so "试试这个 + 默认弱密码表" was actually
    # only ever testing "这个". Put the user's own guesses first since
    # they're the most likely hit, then the generic list; --no-defaults
    # opts back out for anyone who really does want an exact, narrow list.
    extra_users = load_list(args.usernames_extra, args.username_file)
    extra_pw = load_list(args.passwords_extra, args.password_file)
    if args.no_defaults:
        usernames = extra_users or list(DEFAULT_USERNAMES)
        passwords = extra_pw or list(DEFAULT_PASSWORDS)
    else:
        usernames = list(dict.fromkeys(extra_users + DEFAULT_USERNAMES))
        passwords = list(dict.fromkeys(extra_pw + DEFAULT_PASSWORDS))

    if not _confirm_scope(args, usernames, passwords):
        print("已取消。", file=sys.stderr)
        return 1

    hosts = _run_scan(args)

    cap = args.max_fail if args.max_fail > 0 else None
    cap_desc = f"每个目标累计失败 {cap} 次后跳过" if cap else "每个目标会把密码表试完,不会提前放弃"
    targets = [(h, p, REGISTRY[p.guessed_service]) for h in hosts for p in h.ports
               if p.guessed_service in REGISTRY]
    print(f"\n[*] 用户名 {len(usernames)} 个 x 密码 {len(passwords)} 个,"
          f"{len(targets)} 个目标(设备+端口)。每个目标内部 {args.audit_workers} 个线程并发,"
          f"目标之间也并发(最多同时 {args.target_workers} 个目标)。{cap_desc}...",
          file=sys.stderr)

    def audit_one_target(h, p, checker):
        findings_here, lockout_here = [], None
        precheck = PRECHECKS.get(p.guessed_service)
        if precheck is not None and not precheck(h.ip, p.port, args.timeout):
            # E.g. an HTTP(S) page that was never gated by Basic auth at
            # all -- running the whole password list against it one request
            # at a time would just re-learn "not applicable" every single
            # time, for nothing.
            return findings_here, lockout_here, True
        found = threading.Event()
        cap_hit = threading.Event()
        fail_count = [0]
        lock = threading.Lock()
        timeline = []  # (seq, result) in submission order, filled in as completed
        combos = [(u, pw) for u in usernames for pw in passwords]

        lockout_hit = threading.Event()
        real_rejections_seen = [0]
        recent = collections.deque(maxlen=10)

        def attempt(seq, username, password):
            if found.is_set() or cap_hit.is_set() or lockout_hit.is_set():
                return seq, username, password, None, True  # skipped, not a real outcome
            result = checker(h.ip, p.port, username, password, args.timeout)
            if args.delay:
                time.sleep(args.delay)
            with lock:
                if result is True:
                    found.set()
                elif result is False:
                    fail_count[0] += 1
                    real_rejections_seen[0] += 1
                    if cap and fail_count[0] >= cap:
                        cap_hit.set()
                recent.append(result)
                # The device was genuinely rejecting guesses (so auth was
                # really happening), then a run of attempts in a row can't
                # even complete the protocol handshake at all -- that's a
                # live lockout/rate-limit kicking in right now, not noise;
                # stop spending the rest of a huge password list on a target
                # that's actively refusing to talk to us, exactly what
                # --max-fail couldn't catch since those are "accepted the
                # connection, rejected the password" failures, not this.
                if (real_rejections_seen[0] >= 1 and len(recent) == recent.maxlen
                        and all(r is None for r in recent)):
                    lockout_hit.set()
            return seq, username, password, result, False

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.audit_workers) as ex:
            futs = [ex.submit(attempt, i, u, pw) for i, (u, pw) in enumerate(combos)]
            for fut in concurrent.futures.as_completed(futs):
                seq, username, password, result, skipped = fut.result()
                if not skipped:
                    timeline.append((seq, result))
                if result is True:
                    finding = {"ip": h.ip, "port": p.port, "service": p.guessed_service,
                               "username": username, "password": password}
                    findings_here.append(finding)
                    print(f"\n[!] {h.ip}:{p.port} ({p.guessed_service}) "
                          f"{username}/{password or '(空)'} 登录成功", file=sys.stderr)

        suspect = _detect_lockout(timeline)
        if suspect:
            suspect.update(ip=h.ip, port=p.port, service=p.guessed_service)
            lockout_here = suspect
        return findings_here, lockout_here, False

    findings = []
    lockout_suspects = []
    skipped_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.target_workers)) as ex:
        futs = [ex.submit(audit_one_target, h, p, checker) for h, p, checker in targets]
        for fut in concurrent.futures.as_completed(futs):
            findings_here, lockout_here, skipped = fut.result()
            findings.extend(findings_here)
            if lockout_here:
                lockout_suspects.append(lockout_here)
            if skipped:
                skipped_count += 1
    if skipped_count:
        print(f"[*] 其中 {skipped_count} 个目标一看就不需要测密码(比如网页压根没启用 "
              f"Basic 认证),直接跳过了,没有浪费密码表去反复确认这件事", file=sys.stderr)

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
    common.add_argument("--full", action="store_true",
                         help="扫描全部 1-65535 端口,而不是内置的常见端口表。"
                              "真要'假设对方会用非标准端口躲你'这种思路,就不能只扫"
                              "自己知道的端口——但这比常见端口表慢得多,建议配合"
                              "--subnet 只指定你关心的那一个/几个 IP(比如 x.x.x.x/32),"
                              "并把 --workers/--connect-timeout 往上调")
    common.add_argument("--port", dest="extra_ports", action="append", type=int,
                         help="额外扫描的端口,可重复传入(--full 时无意义,常见端口表"
                              "模式下用来补充你自己知道的非标准端口,比如自己改过的 SSH)")
    common.add_argument("--port-file", help="每行一个端口号的文件,同 --port 一起用")
    common.add_argument("--service", dest="port_services", action="append",
                         metavar="PORT:SERVICE",
                         help="指定某个额外端口对应什么服务,格式 PORT:SERVICE,"
                              "比如 --port 51049 --service 51049:ssh;不指定的话"
                              "额外端口会按 unknown 处理,弱密码测试也就不会用上它"
                              "(--full 模式下所有端口都按端口号常规猜测,不受此项影响"
                              "除非也传了 --service 覆盖)")

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
    a.add_argument("--no-defaults", action="store_true",
                    help="--username/--password 只用你给的,不自动加上内置的默认用户名/"
                         "弱密码表(默认是两边一起试)")
    a.add_argument("--max-fail", type=int, default=0,
                    help="同一台设备累计失败多少次后跳过。默认 0 = 不设上限,"
                         "密码表会试完;担心把有登录锁定机制的设备越试越锁,"
                         "可以设一个数,比如 6(并发下这个数不再是\"连续\"失败,"
                         "是总的失败次数)")
    a.add_argument("--audit-workers", type=int, default=16,
                    help="对同一个目标(一台设备的一个服务),同时并发尝试几个用户名/密码组合"
                         "(默认 16)。调大能明显提速,也正好用来看这台设备有没有"
                         "\"同 IP 短时间内多次失败就封禁/限速\"的防护——如果开大了之后"
                         "后面全部连不上,报告里会提示疑似触发了锁定")
    a.add_argument("--target-workers", type=int, default=8,
                    help="同时对几个目标(不同设备,或同一设备不同服务)做密码测试"
                         "(默认 8)。之前是一个目标测完才测下一个,CPU/网络基本闲着;"
                         "调大这个能让多台设备同时测,真正把并发用起来")
    a.add_argument("--delay", type=float, default=0.3,
                    help="每个线程每次尝试之间的延迟(秒),默认 0.3;改成 0 就是不限速")
    a.set_defaults(func=cmd_audit)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
