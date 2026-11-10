# 威胁情报富化与工单闭环

2026 年 11 月 10 日完成本地验收。告警通知按项目作者决定暂缓。本模块通过真实 Wazuh 数据验证指标提取与工单关联，两家服务商的响应与错误分支使用模拟测试。当前运行批次未向 AbuseIPDB 或 VirusTotal 发送请求。

## 指标和数据边界

- SSH 和 Suricata 取告警里的来源 IP。回环、私网、共享、链路本地、文档保留、多播等地址在本地跳过。符合条件的公网 IP 才进入 AbuseIPDB 的 `/api/v2/check`，查询最近 90 天举报。 [AbuseIPDB API](https://docs.abuseipdb.com/) · [Python IP 地址分类](https://docs.python.org/3/library/ipaddress.html)
- Wazuh 文件完整性监控（FIM）告警优先取 `syscheck.sha256_after`，可回退到 SHA-1、MD5。VirusTotal 适配器只按哈希读取 `/api/v3/files/{id}`。本次实测发现删除告警也可能携带旧哈希，删除记录只作为清理证据。 [VirusTotal 文件报告](https://docs.virustotal.com/reference/file-info)
- 本地 SQLite 缓存查询成功结果 24 小时、VirusTotal 404 结果 6 小时。每批默认至多 5 次实际请求，使用 8 秒套接字超时。收到 429 时记录该服务商的冷却时间，优先采用 `Retry-After`，缺失时用 5 分钟。超时、认证失败、响应格式异常、无结果分别记录。`success` 表示查询成功，零举报和 `not_found` 都不能证明安全。 [VirusTotal 错误与配额说明](https://docs.virustotal.com/reference/errors)

## 实机验证

专用 Ubuntu 的 Agent 新增一个实时 FIM 目录 `/opt/soc-lab/ti-fim`，以限定范围捕获文件元数据。新增并删除一份无害文本，实时触发 `554` 和 `553`。首次告警的 SHA-256 与本地计算一致，删除告警与同一路径关联。Agent 配置备份在 `/opt/soc-lab/threat-intel/ossec.conf.before-fim`。 [Wazuh FIM 实时设置](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html)

| 输入 | 实测结果 |
| --- | --- |
| SSH 序列首轮 | 8 条告警的来源是回环，全部跳过 |
| Suricata 首轮 | EVE 来源回环，跳过；脱敏 Web 摘要未留独立来源 IP |
| FIM 文本实验 | 规则 `554` 提取 SHA-256，状态为 `offline`；规则 `553` 仅作清理证据 |

共处理 12 条真实告警，9 条 `skipped_non_public`、2 条 `no_indicator`（无适用指标）、1 条 `offline`。10 项本地测试覆盖两家 API 的请求和响应形状、IP 过滤、哈希提取、SQLite 跨连接缓存、缓存过期、限额、超时、无结果及索引证据关联。

[FIM 脱敏证据](../evidence/detection/threat-intel-fim.json) · [离线结果](../evidence/detection/threat-intel-offline.json) · [已关闭的模拟工单](../output/tickets/LAB-20261110-FIM-001.md)

## 复跑与恢复

在 Windows 的项目目录执行。

```powershell
python scripts/test-threat-intel.py
python scripts/threat_intel.py --input evidence/detection/ssh-sequence-live.json --input evidence/detection/suricata-live.json --input evidence/detection/threat-intel-fim.json --output local-evidence/threat-intel/replay.json
$report = Get-Content -Raw local-evidence/threat-intel/replay.json | ConvertFrom-Json
$report.alerts | ForEach-Object { $_.lookups } | Group-Object status | Select-Object Name,Count
```

在已配置的 SOC Ubuntu 上可另取一个新的 FIM 样本。`configure` 校验并备份 Agent 配置，只新增专用目录；`restore` 只撤销该目录的监控条目，保留其他输入、索引和证据。

```powershell
python scripts/lab_transport.py scripts/threat-intel-fim.py --argument configure
python scripts/lab_transport.py scripts/threat-intel-fim.py --argument verify
python scripts/threat_intel.py --input local-evidence/last-threat-intel-fim.out
# 需要停用这项实验采集时执行
python scripts/lab_transport.py scripts/threat-intel-fim.py --argument restore
```

将来取得 API 密钥并授权查询后，可把 `ABUSEIPDB_API_KEY` 或 `VIRUSTOTAL_API_KEY` 配在同名环境变量，或作为 JSON 字段保存在 `local-evidence/threat-intel/credentials.json`。缓存和凭据位于私有目录。显式使用 `--online` 才会对适用指标尝试外部查询。下方命令为本次已验证的离线样本路由，使用 AbuseIPDB 文档公开示例，来源与实验告警分开记录。

```powershell
python scripts/threat_intel.py --sample ip 118.25.6.39 --sample-source https://docs.abuseipdb.com/
```
