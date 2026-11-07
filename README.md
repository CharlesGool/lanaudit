# lanaudit

扫描你自己的局域网，看看都开着哪些服务，再用你指定的（常见弱密码 + 你怀疑已经泄露的密码）去试一下，告诉你哪台设备还在用这些密码。

Scan your own LAN for exposed services, then check them against a short list of default/known-weak passwords — plus any passwords you personally supply — so you can find out which of your devices still use them.

> ⚠️ **只能用在你自己拥有、或已经得到明确书面/口头授权测试的网络上。**
> 对不属于你的网络或设备尝试登录，在几乎所有国家和地区都是违法的（比如美国的 CFAA、中国的《网络安全法》《刑法》第 285/286 条）。这个工具默认的 `audit` 子命令会要求你输入 `yes` 明确确认范围，才会开始尝试密码。
>
> **Only use this against networks/devices you own or have explicit permission to test.** Attempting logins against systems that aren't yours is illegal almost everywhere. The `audit` subcommand requires an explicit `yes` confirmation of scope before it sends a single credential.

## 这个工具做什么 / What it does

- `lanaudit scan` — 纯粹的端口扫描 + banner/标题抓取，**不发送任何密码**，随时可以安全运行，看看网段里有什么。
- `lanaudit audit` — 在 `scan` 的基础上，对发现的服务（SSH / FTP / Telnet / HTTP(S) Basic Auth / Redis / RTSP 摄像头）尝试一组默认弱密码，外加你用 `--password` / `--password-file` 自己提供的密码（比如你怀疑已经泄露的那个密码）。

一台设备只要有一次登录成功，就立刻停止继续在它身上试，并记录是哪个用户名/密码组合，报告里会显示。

## 安装 / Install

```bash
git clone https://github.com/CharlesGool/lanaudit.git && cd lanaudit
pip install -r requirements.txt
# 想测 SSH 弱密码的话再装一个：
pip install paramiko
```

Debian 12/13、Ubuntu 23.04+ 这些系统的系统 Python 默认不让直接 `pip install`
(会报 `externally-managed-environment`)。用下面任意一种方式都行：

```bash
# 方式一: 建一个虚拟环境(推荐)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 方式二: 明确告诉 pip 你知道风险(只装了 requests/urllib3/paramiko 这几个常见包,问题不大)
pip install --break-system-packages -r requirements.txt
```

## 跨网段扫描一定要在目标网段内部运行

如果你的电脑和要扫的局域网不在同一个地方（比如你人在甲地，要扫的是异地的
乙地家庭网络），**不要**在甲地的电脑上直接扫乙地的网段——哪怕甲乙之间用
Tailscale/VPN 连着也一样：

- 跨地域的隧道会让真实服务的握手变慢、不稳定，结果时有时无。
- 如果你电脑本身开着全局代理/TUN 模式的 VPN（很多人用 Clash/mihomo 的 TUN
  模式），它会让所有 TCP 连接看起来都"连上了"，不管目标端口到底有没有在
  监听——这时候扫出来的"开放端口"基本全是假的（`lanaudit` 会自动检测这种
  情况并警告你，见下面"预检查"）。

正确做法：把这个仓库 `git clone` 到**那个局域网内部**的一台 Linux 机器上
（随便一台你已经能登录的就行），在那台机器上跑 `lanaudit`，再把生成的
`.md`/`.json` 报告传回来看。

## 用法 / Usage

```bash
# 只看局域网里有什么,不碰密码
python -m lanaudit scan --subnet 192.168.1.0/24 --markdown scan.md

# 用默认弱密码表 + 你怀疑泄露的密码,测一遍
python -m lanaudit audit --subnet 192.168.1.0/24 \
    --password "你怀疑泄露的那个密码" \
    --password-file more_passwords.txt \
    --markdown audit_report.md --json audit_report.json
```

或者装好之后直接用命令：

```bash
lanaudit scan  --subnet 192.168.1.0/24
lanaudit audit --subnet 192.168.1.0/24 --i-own-this-network --password "xxx"
```

### 常用参数

| 参数 | 说明 |
|---|---|
| `--subnet` | 必填，CIDR 格式，例如 `192.168.1.0/24` |
| `--password` / `-password-file` | 追加密码（可重复传 `--password`，或一行一个放文件里） |
| `--username` / `--username-file` | 追加用户名，用法同上 |
| `--full` | 扫描全部 1-65535 端口,而不是内置的常见端口表。默认的常见端口表本质上是"假设对方不会用冷门端口"——真要按攻击者的思路来,就不能只扫自己知道的端口。比常见端口表慢很多,建议配合 `--subnet x.x.x.x/32` 只对着你关心的一两台机器用,不要直接对一整个 /24 开 `--full`(纯 Python 线程实现,扫一整个网段的全端口会非常慢,工具会在这种情况下先警告你并要求确认) |
| `--port` / `--port-file` / `--service` | 给常见端口表之外的端口补充信息:`--port 51049` 让没扫过的端口也进扫描范围,`--service 51049:ssh` 告诉工具这个端口是什么服务(不告诉的话会按端口号猜,猜不出来的会尝试从 banner 文字里认,比如认出 `SSH-2.0-...` 开头的是 SSH) |
| `--max-fail` | 同一台设备连续失败几次后跳过，默认 0(不设上限，密码表会试完)，担心触发设备锁定机制可以自己设一个数 |
| `--delay` | 每次尝试之间的延迟（秒），默认 0.3，别把家里路由器打崩了 |
| `--i-own-this-network` | 跳过交互确认（非交互环境用，仍然建议先手动跑一次确认范围） |
| `--json` / `--markdown` | 导出报告 |

## 支持的协议

| 服务 | 说明 |
|---|---|
| SSH | 需要 `pip install paramiko`，没装就自动跳过这一项 |
| FTP | 标准库 `ftplib` |
| Telnet | 手写了最小的协商子集,成功判断是启发式的，建议人工复核 |
| HTTP(S) Basic Auth | 先确认页面真的要求 Basic 认证，再去试密码，不会把"随便谁都能打开的页面"误判成"密码对了" |
| Redis | 原生 RESP 协议，顺带标出"完全不设密码也能连上"这种更严重的情况 |
| RTSP（摄像头/NVR） | 支持 Basic 和 Digest 两种认证方式 |

## 设备名

`scan`/`audit` 默认会给每台发现的主机顺带做一次设备名反查：

- **反向 DNS**：问一下系统本来配置的那个 DNS 服务器（很多家庭路由器的
  dnsmasq 会记得每个 DHCP 租约的主机名，这种情况下不用发任何额外探测包
  就能拿到名字）。
- **NetBIOS 查询**（UDP 137）：问 Windows/Samba 机器自己叫什么名字，这类
  机器通常不会注册 DNS 名字。有的系统防火墙会屏蔽这个查询，查不到就是
  空的，不代表设备有问题。

查不到名字很正常，不影响其他发现结果；不想等这一步可以加 `--no-names`。

VNC、SMB 等协议目前只做端口发现，不做密码破解（这些协议的真实认证流程更复杂，错误实现容易产生误报，这个工具选择不做，而是提醒你手动检查）。

## 默认密码表

默认的 `--password`(不额外指定时)= 设备常见默认密码(几十个) + 内置的
[SecLists](https://github.com/danielmiessler/SecLists)
`Common-Credentials/10k-most-common.txt`(MIT 协议,约 1 万个真实世界最常
见密码),一共一万零几个。用户名默认 12 个。一万个密码 × 十几个用户名听着很
多,默认会把一万个全部试一遍(`--max-fail` 默认 0 = 不设上限)。想在还没试完
就跳过(比如担心把有锁定机制的设备越试越锁)可以自己设 `--max-fail`。想完全
自定义就用 `--password-file` 换成自己的列表。

## 为什么要写这个

家里设备一多（路由器、NAS、摄像头、小主机……），很容易出现"随手设的密码用了好几个地方，结果一个泄露了，一圈设备都在裸奔"的情况。这个工具就是把"挨个设备手动试密码"这件机械的事自动化一下，报告里会明确告诉你——哪台设备、哪个服务、用哪个用户名密码能登进去，方便你一次性把暴露面收紧。

## 安全设计

- 默认不带任何破坏性操作，只读登录测试，成功后立刻停止，不会继续在同一台设备上反复尝试。
- `audit` 命令默认需要交互式输入 `yes` 才会真正发送密码。
- 默认会把密码表试完（`--max-fail` 默认 0 = 不设上限），尝试之间有延迟；担心把有登录锁定机制或 fail2ban 之类防护的设备越试越锁，可以自己设 `--max-fail`。
- 内置的默认密码表很短，只是常见的默认值（`admin`/`admin`、空密码等），不是字典攻击规模的词表；真正有价值的密码应该由你自己通过 `--password` 传入。
