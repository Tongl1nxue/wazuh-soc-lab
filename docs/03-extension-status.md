# SOC 扩展检查与模块顺序

检查日期：2026-11-08。沿用现有 4 vCPU / 8 GiB / 50 GiB 虚拟机及 Docker Compose，不重建、不升级、不改变网络结构。

2026-11-10 状态更新。SSH 序列研判和授权实验工单已完成，Suricata 回环 IDS 已验证到 Wazuh 告警，并完成 EVE 轮转复测。告警通知暂缓。威胁情报已用真实告警和模拟 API 响应完成本地验收，真实 API 查询待密钥。下方状态表保留 11 月 8 日检查基线。[SSH 序列](08-ssh-sequence.md) · [Suricata 双源取证](09-suricata.md) · [威胁情报](10-threat-intel.md)

**进度更新：用户启动现有 VM 后，已完成日志链路模块在线配置与实际查询验收。下文“当前缺项”表为本轮起始基线，后续结果见文末。两类异常事件、自定义规则及运营闭环尚未完成。**

后续模块更新：已完成两类受控异常事件、规则 100110、真实日志重放调优及实时复测，见 [检测与研判记录](04-detection-and-triage.md)。该模块用户验收待完成；统计/Excel/工单闭环等材料模块仍未完成。manager 重建后发现并修复 archives 转发开关持久化问题，当前运行状态以该记录的最终复测为准。

材料模块更新：检测模块用户查询已通过；已从真实快照实现 Python 分类、统计和 CSV 导出，见 [Python 与 CSV](05-python-csv-analysis.md)。Excel、模拟工单和运营周报尚未完成。

后续材料进度：用户独立统计对账已通过，已生成两份关联真实告警的模拟工单草稿及 CSV/JSON，见 [模拟工单](06-simulated-tickets.md)。默认待关闭复核，关闭未执行。Excel 与运营周报仍未完成。

## 证据与当前状态

已读取 docs/01-environment-and-plan.md、docs/02-deployment.md 和现有部署/启动/检查脚本；在项目根、scripts、docs 及上级目录未找到适用的 AGENTS.md。本地 Git 尚无已提交的项目基线；现有文件不代表已发布到 GitHub。未读取或输出私有密码/密钥正文。

| 模块 | 已配置 | 已验证 | 当前缺项 |
| --- | --- | --- | --- |
| Wazuh 三组件、agent、SSH、Nginx | 原部署脚本有配置 | 11/05 历史健康记录 | 11/08 开机及资源复验 |
| SSH 日志 | agent 配置中有 auth.log | 历史记录不足以证明索引查询 | 实际 SSH 操作、源日志、告警 ID、索引查询对账 |
| Nginx 日志 | agent 配置中有 soc_access.log | 历史 HTTP 200 只证明网站可用 | 正常请求原始事件查询、异常与正常对照 |
| 自定义规则与误报 | 未找到本项目成果 | 未验证 | 从真实日志提取字段，正例/反例/边界测试 |
| 两类研判、模拟工单 | 未找到本项目成果 | 未验证 | SSH / Web 两类本地有限次数事件与处置复测 |
| Python、CSV、Excel、周报 | 现有 Python 是部署脚本；未找到专用分类统计/运营数据 | 未验证 | 基于本次真实告警实现，统计与原始记录对账 |
| Suricata | 未核实安装情况 | 未验证 | 先验证 lo 流量路径，再小规则集 IDS；不声称 IPS |
| 通知 | 未找到配置/成果 | 未验证 | 用户账号条件、渠道网络、外发授权、去重/超时/失败记录 |
| AbuseIPDB / VirusTotal | 未找到配置/成果 | 未验证 | API 条件、指标过滤、缓存/限额、无结果处理与合法样本说明 |
| 品牌定制 | 未实施 | 未验证 | 核对官方支持及挂载持久化；排在必要闭环之后 |

项目内另有简历及参考资料，但不将它们计入安全监测实验结果。缺项结论基于当前本地文件与历史部署说明；guest 内如存在额外成果，需要开机后再检查，不能据本地未发现断言 guest 一定不存在。

本次 Windows 实测：虚拟机起初关闭，空闲 RAM 约 2.68 GiB；用户释放应用后约 4.77 GiB。vmrun 启动返回 Unknown error；发现 VMware Authorization Service 停止，尝试启动时 Windows 返回服务访问权限错误。未修改虚拟机资源或网络；需要用户启动授权服务/专用虚拟机后继续在线检查。这不是 Wazuh 服务故障的已证实结论，也不是自动审批拒绝。

## 实施顺序与学习检查点

1. **日志链路模块（当前）**：实际复验版本/服务/资源；备份；小流量启用 JSON archives 与 Filebeat shipping；真实正常请求和 SSH 登录；用索引查询关联真实事件。保存原始私有证据和脱敏摘要。
2. **检测研判模块**：有限 SSH 失败认证、Nginx 敏感路径请求；基于实际 decoder 字段写一条 100000–120000 范围内不冲突的规则；验证正反例及边界，讨论 404、管理员误操作等误报。不改动公共目标、不启用自动封禁。
3. **基础闭环材料模块**：分类统计程序、CSV、Excel、两类模拟工单、周报和复测；只从已验证事件生成材料。工单“关闭”必须有复测依据。
4. **Suricata 模块**：资源复测，先确认回环路径；EVE JSON → agent → manager → indexer；规则用明确标注的测试特征，验证仅 IDS。设置日志轮转。
5. **通知模块**：询问用户可用渠道和外发授权后接通一个渠道，再验证筛选、去重、超时和失败记录。密钥仅进本地私有配置。
6. **情报/工单扩展模块**：区分公网 IP 与文件哈希；跳过私有/保留指标；无命中不等于安全；API 配额、缓存、失败与历史样本来源进入证据记录。
7. **可选扩展评估**：pfSense 需独立 VM、真实经过的实验网络；TheHive/Cortex 需额外资源及版本/依赖/许可检查；Microsoft 365 缺租户/审计/应用权限则不实施；品牌定制不优先于闭环。

每个模块通过后给出原理说明和用户独立操作/验收题。用户验收及技术验证均应记录；不提前把后续阶段或未实现功能写入简历。

## 当前新增工具与恢复

- `scripts/lab_transport.py`：复用私有连接信息；远端输出和错误保存到 local-evidence；连接失败不会打印密钥或密码。
- `scripts/phase1-log-pipeline.py audit`：只读审计版本、服务、来源路径、archives 开关与回环路由；输出不包含 Filebeat 认证字段。
- `configure`：备份至 guest `/opt/soc-lab/phase1-pipeline/backup`，启用 manager JSON archives 和 Filebeat archives shipping，验证配置，按 Compose 重启 manager。备份存在时拒绝覆盖。
- `verify`：仅向 guest `127.0.0.1:8080` 发出一次带唯一标记的真实请求，查询 archives，并查询本次时间窗口的 SSH 成功事件；原始结果保存在 guest 私有目录。
- `restore`：恢复 manager 模板、运行配置及 Filebeat 配置，Compose 重启 manager；不删除已收集证据。恢复工具不负责删除索引、工单或原始日志。

Windows 使用示例：

```powershell
python scripts/lab_transport.py scripts/phase1-log-pipeline.py --argument audit
python scripts/lab_transport.py scripts/phase1-log-pipeline.py --argument configure
python scripts/lab_transport.py scripts/phase1-log-pipeline.py --argument verify
# 需要恢复时：
python scripts/lab_transport.py scripts/phase1-log-pipeline.py --argument restore
```

首次启用前必须完成在线审计并确认资源；以上是工具入口，不代表已执行成功。当前新增 Python 文件只通过本地语法检查，还没有在线结果。

archives 包含正常日志，告警仅包含规则达到阈值的事件，两者不能混用。全量 archives 会增加写入和磁盘占用，需结合现有日志轮转和 85% 磁盘保护观察；小流量验证后决定是否继续保留，不把当前小型 VM 描述为生产容量。

## 日志链路模块：本轮实际完成

用户启动原有虚拟机后，通过 SSH 完成只读审计：manager/indexer/dashboard 镜像均为 4.14.9，agent 为 4.14.9-1；各服务运行。guest 总内存 7.8 GiB、available 约 5.2 GiB；根分区 49G，约剩 39G。配置变更复验后 available 约 5.1 GiB、剩余约 38G。本次没有升级版本或重新部署。

原配置中 manager `<logall_json>no</logall_json>`，Filebeat `archives.enabled: false`。已在修改前备份 manager 模板、manager 运行配置、Filebeat 和 agent 配置，备份位于 guest `/opt/soc-lab/phase1-pipeline/backup`；agent 本轮未修改。启用 JSON archives 和 Filebeat archives shipping，执行配置检查并仅通过既有 Compose 重启 manager。配置保留在原挂载模板及命名卷中。

实际请求和索引查询验证：

| 项目 | 真实验证结果 |
| --- | --- |
| 最终运行标记 | `soc-pipeline-c63df288ed76` |
| 本地请求 | `GET /index.html?lab_run=soc-pipeline-c63df288ed76`，目标 guest 127.0.0.1:8080，HTTP 200 |
| Nginx 索引过滤 | `agent.name=soc-ubuntu`、`location=/var/log/nginx/soc_access.log`、full_log 包含唯一标记 |
| Nginx 查询 | archives 返回 1 条；事件 ID `1794124802.53569`；索引文档 ID `2xPeu6EBGa9eTEWM-dBN` |
| SSH 索引过滤 | `agent.name=soc-ubuntu`、`location=/var/log/auth.log`、rule.id=5715、本次三分钟时间窗口 |
| SSH 查询 | 返回 5 条成功认证告警，查询上限为 5，不能据此推断总登录次数 |
| 验收 | 程序 passed=true；用户独立查询已完成，概念问答待回答 |

原始 JSON 保存于 guest 私有目录及 Windows `local-evidence/phase1-pipeline`，不公开；公开验收摘要为 `evidence/pipeline/verification.json`，只允许导出标记、计数、事件 ID 和通过状态。实际普通请求与 SSH 登录是连通性/采集实验，并非安全攻击或工单关闭成果。

首个查询客户端出现 URLError，manager 归档文件已实际存在。修复查询客户端为直接访问已有 127.0.0.1:9200，并同时验证 CA 签名及证书 DNS SAN 必须为 wazuh.indexer；未修改网络或关闭证书校验。最初失败探针已退出，最终结果由修复后的脚本生成。错误是否确由 cloud-init 重置主机别名造成，未单独验证，不能写成已证实根因。

全量 archives 当前保持启用；现有轮转及磁盘保护继续使用。下一模块前应复查增长速度与空间，必要时使用 restore 恢复原归档配置。未创建自动删证据策略。

### 用户独立验收

运行项目 `Open-SOC.cmd` 并登录，在 Dashboard 的 Dev Tools 查询：

```json
GET wazuh-archives-*/_search
{
  "size": 5,
  "query": {
    "bool": {
      "filter": [
        {"match_phrase": {"full_log": "soc-pipeline-c63df288ed76"}},
        {"term": {"location": "/var/log/nginx/soc_access.log"}},
        {"term": {"agent.name": "soc-ubuntu"}}
      ]
    }
  }
}
```

检查 hits 中的原始路径与唯一标记，再回答：为什么正常 HTTP 200 请求能够在 archives 查询到，却不必出现在安全告警列表？本模块用户验收通过后，进入有限次数 SSH 异常与 Web 探测、自定义规则和误报分析模块。

### 用户实际查询反馈

2026-11-08 用户独立在 Dashboard 查询并提交 JSON。聊天中给出的简化查询仅搜索 full_log 标记，没有日志路径过滤，因此实际命中 3 条。逐条审阅确认：1 条为预期 Nginx GET/200，文档 ID 与程序验收一致；另 2 条为此前收集证据时 `sudo cat` 读取实验 JSON 的管理操作，分别来自 journald 和 auth.log，命中规则 5402。不能将 3 条结果解释成 3 次 Web 访问，也不能将该 sudo 操作或其 MITRE 标签直接认定为攻击。

此结果证明用户已独立检索到目标 Nginx 原始事件，查询操作验收通过；概念问答尚未由用户独立回答。精确路径过滤查询仍见上文。用户查询的脱敏审阅摘要保存在 evidence/pipeline/user-query-review.json；用户原始 JSON 不复制到公开目录。本次未执行新的异常请求或新增事件研判结论。

参考：[官方事件归档说明](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)、[官方自定义规则说明](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)。实际规则以 4.14.9 本机 ruleset 和 logtest 结果为准，不照搬 current 文档里的新版本示例。
