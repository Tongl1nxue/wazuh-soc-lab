# Suricata 与 Nginx 双源取证

2026 年 11 月 10 日在现有 Ubuntu 22.04 上完成。Ubuntu 软件源提供 Suricata 6.0.4，安装新增磁盘占用约 25.2 MB。安装前 guest 可用内存约 5.1 GiB、根分区可用约 38 GiB。本次联调时 systemd 报告传感器内存约 142 MiB，为单次采样。

## 流量与日志路径

`ip -4 route get 127.0.0.1` 实测选择 `lo`，`ss` 确认 Nginx 监听 `127.0.0.1:8080`。传感器使用 libpcap 的 `lo` 单线程模式，只接收源或目标为 `127.0.0.1` 且涉及 TCP `8080` 的流量。Ubuntu 软件包的默认 Suricata 服务保持屏蔽，实验由独立的 `soc-suricata.service` 管理。

```text
本地 GET 请求 → lo → Nginx → access.log → Wazuh Agent → Web 规则 100110
                   └→ Suricata → EVE JSON → Wazuh Agent → 原生规则 86601
```

只加载 SID `1000001`，在 HTTP URI 中匹配 `/.env` 或紧接查询串的 `/.env?…`。EVE 只启用告警输出，保留关联所需 HTTP 元数据，不写包内容和 HTTP 正文。日志轮转每日检查，检查时文件超过 2 MB 可提前轮转，保留两份；该大小是轮转条件。仅在回环捕获配置中调整校验策略，并关闭自动尝试更改网卡 offload 设置。参阅 [Suricata 6.0.4 命令行](https://docs.suricata.io/en/suricata-6.0.4/command-line-options.html)、[Suricata 6.0.4 日志轮转](https://docs.suricata.io/en/suricata-6.0.4/output/log-rotation.html)和 [Wazuh 官方 EVE 接入](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)。

## 实测与研判

首轮通过批次 `soc-ids-014ed23650fa`，四条请求分别加上同一轮标记。每个 URL 都能在 Nginx 的 Wazuh 归档中找到，且 HTTP 状态与客户端一致。

| 请求路径 | HTTP | Suricata SID 1000001 / Wazuh 86601 | Nginx 的 Wazuh 100110 |
| --- | ---: | --- | --- |
| `/index.html` | 200 | 未命中 | 未命中 |
| `/.env.example` | 404 | 未命中 | 未命中 |
| `/docs/.env-guide` | 404 | 未命中 | 未命中 |
| `/.env` | 404 | 命中 | 命中 |

`/.env` 对应 EVE `flow_id` 为 `892729779513776`。Wazuh EVE 告警 `1794300261.255564` 对应同一 URI、流编号、签名和 EVE 时间。Nginx 分支告警 `1794300261.258098` 记录同一 URI 的 HTTP 404。两条告警来自同一次请求，应合并成一条实验事件。两个普通 404 仍匹配通用规则 `31101`。

**研判结论**　授权的敏感路径探测模拟。Suricata 证明请求到达被观察链路，Nginx 证明本次请求返回 404。EVE 的 `action` 为 `allowed`，验证范围是被动 IDS；这里的 404 来自 Nginx。扫描器、管理员验证等合法行为也可能命中该 URI，需结合测试标记、发起方和服务端响应区分，告警本身不能判定数据是否泄露。

强制轮转后确认旧 inode 保存在 `eve.json.1`，新文件开始写入。复跑批次 `soc-ids-8eb967339ec3` 再次通过四个请求，当前 EVE 文件大小 704 字节。新告警 `1794300322.278542`（`86601`）和 `1794300322.274541`（`100110`）仍可查询。以请求标记、URI 和流编号对齐，两个来源的写入时间可能不同。

[首轮脱敏证据](../evidence/detection/suricata-live.json) · [Dev Tools 实测截图](../evidence/screenshots/wazuh-suricata-nginx-devtools.png) · [轮转后复跑证据](../evidence/detection/suricata-after-rotation.json)

## 联调修复

- 初次按 `full_log` 查索引，找到了 EVE 归档，却漏掉 EVE 告警。Wazuh 4.14.9 的 `86601` 配置为 `no_full_log`。验证脚本改为同时查 EVE 的结构化 `data.http.url` 和 Nginx 原始日志。 [Wazuh 4.14.9 Suricata 规则](https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0475-suricata_rules.xml#L307)
- Wazuh 将本轮 EVE 整数 `flow_id` 解码成可能带 `.000000` 后缀的字符串。脚本用 `Decimal` 对齐，并同时核对 EVE 时间和 SID，避免按字符串外观误判成不同的流。

## 复跑与恢复

现有环境在 Windows 项目根目录运行下面的命令。它向 Ubuntu 内的 Nginx 发 4 条请求，验证通过时返回 `passed: true`。输出保存到 `local-evidence/last-suricata-lab.out`。

```powershell
python scripts/lab_transport.py scripts/suricata-lab.py --argument verify
```

按首轮文档编号在 Dashboard Dev Tools 查询两条告警。

```http
GET wazuh-alerts-4.x-2026.11.10/_search
{
  "_source": ["id", "timestamp", "location", "rule.id", "rule.level", "data.url", "data.http.url", "data.flow_id"],
  "query": {"ids": {"values": ["6ww-xqEBQhHEctzNwj1q", "7gw-xqEBQhHEctzNwj1q"]}}
}
```

在新建的同类实验 VM 上，先用 Ubuntu 软件源安装，并屏蔽默认服务。以下命令在 Ubuntu 执行。

```bash
sudo systemctl mask suricata.service
sudo apt-get install --no-install-recommends suricata
```

再从 Windows 执行配置和验收。四份配置由 [项目配置目录](../config/suricata/) 管理，`configure` 会备份 Agent 配置到 `/opt/soc-lab/suricata/ossec.conf.before-suricata`，校验 IDS、轮转和 Agent 配置，安装并启用持久化的实验服务。`restore` 停用实验服务并撤销本模块添加的 EVE 输入，保留软件包、默认服务屏蔽状态、日志和索引证据。恢复后可重新执行 `configure`。

```powershell
python scripts/lab_transport.py scripts/suricata-lab.py --argument configure
python scripts/lab_transport.py scripts/suricata-lab.py --argument verify
# 需要回退本模块时执行
python scripts/lab_transport.py scripts/suricata-lab.py --argument restore
```
