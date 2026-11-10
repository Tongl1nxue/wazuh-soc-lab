# 作品集交付与简历

这个项目在一台专用 Ubuntu 上完成 SSH、Nginx、Suricata EVE 和文件完整性监控的采集与研判。公开材料以可复跑的索引快照、配置和报告为主。

## 演示顺序

| 要展示的能力 | 证据与预期结果 |
| --- | --- |
| 端到端采集与统计 | [基础快照](../evidence/detection/public-snapshot.json)复现 17 条归档和 10 条告警，可对账 CSV |
| 规则验证与误报分析 | [Web 回放矩阵](../evidence/detection/replay-matrix.json)显示从 `.env` 子串匹配调整为精确路径，区分正例和普通 404 |
| 有状态关联 | [SSH 复跑](08-ssh-sequence.md)比较 Wazuh 同源关联和 Python 同账号关联，确认同源另一账号的正常登录未被串入 |
| 双源取证 | [Dashboard 查询截图](../evidence/screenshots/wazuh-suricata-nginx-devtools.png)显示同一 `/.env` 请求的两条 Wazuh 告警；[轮转后复测](../evidence/detection/suricata-after-rotation.json)保留 EVE 和 Nginx 404 的关联证据 |
| 工单和指标提取 | [FIM 模拟工单](../output/tickets/LAB-20261110-FIM-001.md)以真实新增、SHA-256、删除告警记录关闭依据；[离线报告](../evidence/detection/threat-intel-offline.json)记录查询边界 |

复跑从 [README](../README.md#离线复跑) 开始。各实验批次的数字分开统计，工单记录的告警 ID 可在对应脱敏证据中查到。通知暂缓，外部情报 API 待密钥联调。Suricata 的验收范围是被动 IDS。

## 可用的简历文案

**Wazuh Linux / Web 安全日志监测与告警研判｜本地 SOC 实验项目**

- 在 VMware Ubuntu 环境使用 Wazuh 与 Docker Compose 开展 SSH、Nginx 日志监测，通过 Dashboard 查询原始事件和告警。用 Python 复跑脱敏快照并导出 CSV，对账 17 条归档和 10 条告警。
- 验证 `/.env` 自定义规则的正反例和误报边界，复现同账号多次 SSH 认证失败后成功的关联。结合 Suricata EVE 与 Nginx 404 研判同一次请求，保留回归和轮转复测证据。
- 将原始告警编号、处置和复测关联至模拟工单。使用 FIM 告警核对文件 SHA-256，并完成威胁情报指标提取与过滤的本地验收。

其中项目配置、实验批次和数据以仓库证据为准。简历可按本人能复现和说明的范围选用，发布链接在实际上传后再填写。

## 提交前核查

公开内容包括脚本、规则、脱敏 JSON、CSV、工单和已审查的运营产物。主机标识和旧虚拟机路径已从公开环境记录移除。`local-evidence`、原始连接资料、凭据和重跑输出由 `.gitignore` 隔离。

在 Windows 的项目目录查看候选文件，核对 `.gitignore` 和暂存范围。

```powershell
git status --short
git check-ignore local-evidence/access.json local-evidence/dashboard-login.txt output/reproduced/threat-intel.json
git add -- .gitignore README.md Open-SOC.cmd SSH-SOC.cmd Stop-SOC.cmd config docs evidence scripts output/blog output/operations output/tickets outputs
git diff --cached --name-only
git diff --cached --stat
```

核对暂存后，创建本地提交。若发布到 GitHub，在自己账户创建空仓库后，将 `origin` 指向该仓库，再推送当前分支。

```powershell
git commit -m "Add reproducible Wazuh SOC lab portfolio"
git remote add origin '<你的 GitHub 仓库 URL>'
git push -u origin HEAD
```
