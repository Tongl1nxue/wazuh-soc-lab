# Python 分类统计与 CSV 导出

本步骤使用本地已经保存的真实实验快照 `soc-detect-1d64d29b1512`，不产生新请求，不查询外部平台，不读取/输出连接密码。它不是全平台统计，也不是完整周报。

## 实际输入与输出

输入：Windows 私有目录 `local-evidence/detection-lab/soc-detect-1d64d29b1512.json`。其中保存了指定实验批次的四次查询结果：Web archives、Web alerts、SSH archives、SSH alerts。

Python 先确认查询没有超时、失败分片或未取完的结果，再以索引名 + 索引文档 ID 去重。archives 和 alerts 分开处理，不合并累加为事件总数。原始 archives 的事件 ID 在这批数据中存在重复，不能独自作为唯一键。

| 统计项 | 本次快照实算值 |
| --- | --- |
| Web archives | 5 |
| SSH archives | 12 |
| 合计 archives | 17 |
| 自定义 Web 规则 100110 | 1 |
| 普通 Web 4xx 规则 31101 | 3 |
| SSH 无效用户规则 5710 | 6 |
| 合计 alerts | 10 |

6 次 SSH 连接在该快照中留下 12 条归档记录，不意味着有 12 次连接。每次连接可能有不同阶段日志。同理 10 条告警不等于 10 起独立安全事件，2 类受控场景也不等于确认发生 2 起真实攻击。

输出位于 `output/operations`：

- `alerts.csv`：10 条告警明细，含规则、级别、时间、证据定位字段与分类。
- `archives.csv`：17 条归档明细，保留正常/异常对照。
- `alert-statistics.csv`：按规则及分类汇总告警数。
- `analysis-summary.json`：统计口径、查询完整性和输入文件 SHA-256，供复核。

明细导出仅允许选定字段，主机统一显示 LAB-UBUNTU，不导出原始日志正文、原始用户名、源 IP、密码或令牌。URL 仅保留路径及符合本实验格式的 soc_run 参数，其他查询参数移除。时间同时提供 UTC 与北京时间（+08:00）。CSV 使用 UTF-8 BOM 便于 Excel 读取中文，并将可能成为表格公式的外部字符串转为文本。

## 具体执行

在项目文件夹空白处右键打开 PowerShell，执行以下命令。

```powershell
python scripts/analyze-alerts.py --input 'local-evidence/detection-lab/soc-detect-1d64d29b1512.json' --output 'output/operations'
```

预期输出中包括：

```json
{
  "run_id": "soc-detect-1d64d29b1512",
  "archive_records": 17,
  "alert_records": 10,
  "alert_counts_by_rule": {
    "100110": 1,
    "31101": 3,
    "5710": 6
  }
}
```

程序仅依赖 Python 标准库，不需要安装 pandas 或联网。重新运行会覆盖同一输出目录中的四个导出文件，不修改输入证据。

CSV 中的 document_id、event_id、rule_id 是标识，不应作数学运算。Excel 直接打开可能自动将长数字或带小数点的事件编号转换为数值；如需精确保留，通过“数据 → 从文本/CSV”导入，并把标识列设为文本。规范证据仍以原始 JSON 为准。下一步正式生成 XLSX 时会明确设置这些列为文本。

## 验证与学习说明

已实际执行导出，并用 csv 模块重新读取，对账：告警明细行数等于分组数量之和，归档明细行数等于快照记录数。使用单独的单元测试验证索引文档去重、archives 事件 ID 碰撞、CSV 公式字符串处理、URL 查询参数脱敏和超时查询拒绝。单元测试中的人工元数据仅是测试夹具，不计为实验日志。

参考解释：分类是对已有记录加标签；统计按选定口径计数；CSV 是明细/汇总文件格式。它们不会自动完成事件研判，也不会将工单标记为关闭。

用户操作不设问答考核。可以直接执行上述命令，观察 17、10 及规则分组是否一致；出现不同结果时保留输出，由助手协助解释。

用户已独立执行并提交输出，结果为 archive_records=17、alert_records=10、规则 100110=1、31101=3、5710=6，与程序及原始证据对账一致。本步骤操作确认完成。

下一小步：用这些真实告警建立明确标注“模拟”的工单，再生成 Excel 和运营周报。尚未执行的封禁、账号处置、通知发送不能被自动填为已完成。
