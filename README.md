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
pip install -r requirements.txt
# 想测 SSH 弱密码的话再装一个：
pip install paramiko
```

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
| `--max-fail` | 同一台设备连续失败几次后跳过，默认 6，避免触发设备的锁定机制 |
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

VNC、SMB 等协议目前只做端口发现，不做密码破解（这些协议的真实认证流程更复杂，错误实现容易产生误报，这个工具选择不做，而是提醒你手动检查）。

## 为什么要写这个

家里设备一多（路由器、NAS、摄像头、小主机……），很容易出现"随手设的密码用了好几个地方，结果一个泄露了，一圈设备都在裸奔"的情况。这个工具就是把"挨个设备手动试密码"这件机械的事自动化一下，报告里会明确告诉你——哪台设备、哪个服务、用哪个用户名密码能登进去，方便你一次性把暴露面收紧。

## 安全设计

- 默认不带任何破坏性操作，只读登录测试，成功后立刻停止，不会继续在同一台设备上反复尝试。
- `audit` 命令默认需要交互式输入 `yes` 才会真正发送密码。
- 每台设备默认最多连续失败 6 次就跳过，并在尝试之间加延迟，减少把设备的账号锁定机制触发到、或者被设备防护机制（比如 fail2ban）拉黑的概率。
- 内置的默认密码表很短，只是常见的默认值（`admin`/`admin`、空密码等），不是字典攻击规模的词表；真正有价值的密码应该由你自己通过 `--password` 传入。
