# SSH 失败后成功的序列研判

2026 年 11 月 10 日在专用 SOC Ubuntu 虚拟机内完成两轮实机实验。首轮 `socseq2721380324` 的 [脱敏索引证据](../evidence/detection/ssh-sequence-live.json) 可离线重跑。第二轮 `socseq495c14de2b` 用本文的在线命令复跑，另存 [复跑证据](../evidence/detection/ssh-sequence-repeat.json)。两轮各返回 36 条归档、20 条告警，其中各有 8 条用于认证序列。总量包含会话开关等辅助记录，两轮分开统计。

## 检测边界

Wazuh 4.14.9 在首轮将单次公钥失败、成功分别识别为 `5716`、`5715`，未触发 `40112`。复跑距首轮约 112 秒，两轮用了不同的临时账户，同源 IP 均为 `127.0.0.1`。第二轮换钥复测时，旧密钥被拒触发 `5720`（`1794299506.116764`），随后新密钥登录成功触发 `40112`（`1794299506.119529`）。`5720` 按同源 IP 累计 `5716`，`40112` 在 240 秒内按同源 IP 关联 `authentication_failures` 组事件和成功登录。两轮合计 8 次失败与这条原生链的触发一致。Python 在复跑仍只输出一条较早的、满足同账号三次失败条件的序列，换钥复测未新增结果。Python 输出是**离线研判记录**，Dashboard 中可查看两轮的原生告警。参阅 [原生 SSH 规则 5720](https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0095-sshd_rules.xml#L1451) 和 [原生规则 40112](https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0280-attack_rules.xml#L641)。

脚本按主机、来源 IP、目标账户分组，按事件时间排序。默认在 60 秒内要求至少 3 个不同 SSH 连接先失败，再出现成功登录。归档里同一连接的重复认证记录只计一次，成功后清空该组累计失败。实验采集器用 sshd 进程号和来源端口建立连接别名，时间采用 Wazuh 索引时间戳。这个阈值用于小样本演示，实际环境需要结合时间延迟、共享出口、自动化重试和正常运维基线调优。

## 首轮实测

| 场景 | 证据 | 研判输出 |
| --- | --- | --- |
| 账号 A 使用未授权测试密钥连接 3 次 | `conn-01` 至 `conn-03`，均为 `5716` | 等待后续成功事件 |
| 同一来源的账号 B 正常登录 | `conn-04`，`5715` | 0 条，未关联到 A 的失败 |
| 账号 A 随后正常登录 | `conn-05`，`5715`，告警 `1794299394.82178` | 1 条，关联 A 的 3 次失败 |
| 账号 A 再次正常登录 | `conn-06`，`5715` | 0 条新增，未重复计数 |
| 替换 A 的授权密钥后复测 | `conn-07` 旧密钥失败，`conn-08` 替换密钥成功 | 0 条新增，仅一次失败 |

序列命中证明 SSH 曾先拒绝公钥认证、后来接受了有效密钥。本次发起者是授权实验脚本，操作都在回环接口上完成。真实排查时，密钥选错、SSH 客户端轮流尝试密钥或定时任务重试也可能形成类似序列，需结合账号持有人、授权密钥变更和会话行为判定。换钥复测与关闭依据见 [模拟工单](../output/tickets/LAB-20261110-SSH-SEQ-001.md)。

## 复跑命令

在 Windows 项目目录执行。第一条命令检查阈值、过期窗口、重复记录、跨账户／主机／来源隔离、重复成功及同时间戳的顺序。单元测试采用合成输入。后两条命令分别读取两轮真实索引快照，每轮预期得到 1 条结果，账号为 `A`、`failure_count` 为 `3`。

```powershell
python scripts/test-ssh-sequence.py
python scripts/ssh_sequence.py --input evidence/detection/ssh-sequence-live.json
python scripts/ssh_sequence.py --input evidence/detection/ssh-sequence-repeat.json
```

在 Dashboard 的 Dev Tools 可按复跑证据中的文档编号查这两条原生告警。

```http
GET wazuh-alerts-4.x-2026.11.10/_search
{
  "_source": ["timestamp", "id", "rule.id", "rule.level"],
  "query": {"ids": {"values": ["cgw-xqEBQhHEctzNwjpq", "dQw-xqEBQhHEctzNwjpq"]}},
  "sort": [{"timestamp": "asc"}]
}
```

需要重新取证时，先启动专用 SOC Ubuntu，再执行下面两条命令。实验在 Ubuntu 内以独立的回环端口运行临时 sshd，禁用密码认证、转发和 TTY，登录后仅执行 `true`。临时账户无主目录和提权授权。脚本结束时停止测试 sshd、移除账户和临时文件，日常 SSH 配置继续使用原文件。若脚本被强制终止，先检查 `/run/soc-sequence-*` 和对应本轮的 `socseq…a`、`socseq…b` 账户，确认归属后再清理。

```powershell
python scripts/lab_transport.py scripts/ssh-sequence-lab.py --argument verify
python scripts/ssh_sequence.py --input local-evidence/last-ssh-sequence-lab.out
```

首轮公开快照保留账户别名、回环来源、时间、连接别名、索引文档编号和告警编号，排除实际账号名、密钥指纹、原始日志文本和连接凭据。它与 11 月 8 日 SSH/Web 批次分别保存。
