# 复现与查询说明

## 离线验证

在项目根目录运行以下命令。公开样本保留索引文档 ID、时间、规则、日志类型和 Web 测试路径，适合验证分类与统计。

```powershell
python scripts/test-alert-analysis.py
python scripts/analyze-alerts.py --input evidence/detection/public-snapshot.json --output output/reproduced
```

打开 `output/reproduced/alert-statistics.csv`，预期规则 `5710` 有 6 条、`31101` 有 3 条、`100110` 有 1 条。`archives.csv` 有 17 行数据，`alerts.csv` 有 10 行数据。CSV 的事件编号列应按文本导入 Excel，以保留完整精度。

进阶模块的离线命令集中在 [README](../README.md#离线复跑)。在线实验分别见 [SSH 序列](08-ssh-sequence.md)、[Suricata 双源取证](09-suricata.md)和 [FIM 与情报](10-threat-intel.md)。已生成的 Excel 和周报是 11 月 8 日批次的运营材料，重建工作簿所需的本地制表运行时与 Python 标准库复跑分开。

## 在线实验前提

在线查询需要自己的 Wazuh 实验实例和访问权限。本项目现有虚拟机的搭建、端口和版本记录见 [02-deployment.md](02-deployment.md)。使用自有环境时，按 [官方 Docker 部署说明](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)选择对应版本，并配置 Ubuntu Agent、SSH 和 Nginx。4.14.9 的自定义规则位于 [config/rules](../config/rules/soc_web_rules.xml)。

项目的 Windows 启动脚本依赖原实验的本地路径与 SSH 配置。跨机器部署时需要为自己的虚拟机配置连接参数，按实际 VM 路径启动。密码、私钥、原始采集快照和主机连接文件保存在本机的忽略目录。

以下查询可在保存了本项目实验数据的 Dashboard Dev Tools 中执行。新部署时替换为自己的实验标记和日志路径。每段查询可单独粘贴执行。

### 1. 查询正常 Nginx 归档

```http
GET wazuh-archives-*/_search
{
  "size": 5,
  "_source": ["timestamp", "location", "data.url", "data.id", "decoder.name"],
  "query": {
    "bool": {
      "filter": [
        {"term": {"location": "/var/log/nginx/soc_access.log"}},
        {"match_phrase": {"full_log": "soc-pipeline-c63df288ed76"}}
      ]
    }
  }
}
```

原实验命中一条，HTTP 状态码为 `200`。日志路径过滤排除了碰巧含同一标记的 sudo 证据读取记录。

### 2. 查询 Web 自定义告警

```http
GET wazuh-alerts-*/_search
{
  "size": 5,
  "_source": ["id", "timestamp", "location", "rule.id", "rule.level", "data.url", "data.id"],
  "query": {
    "bool": {
      "filter": [
        {"term": {"rule.id": "100110"}},
        {"term": {"location": "/var/log/nginx/soc_access.log"}},
        {"match_phrase": {"full_log": "soc-detect-1d64d29b1512"}}
      ]
    }
  }
}
```

原实验命中一条，规则为 `100110`，级别为 `7`，路径为 `/.env`，HTTP 状态码为 `404`。`data.id` 在 Web 日志里表示 HTTP 状态码，`id` 是关联工单使用的事件编号。

### 3. 按证据编号核对 SSH 告警

```http
GET wazuh-alerts-*/_search
{
  "size": 10,
  "_source": ["id", "timestamp", "location", "rule.id", "rule.level"],
  "query": {
    "bool": {
      "filter": [
        {"term": {"rule.id": "5710"}},
        {"term": {"location": "/var/log/auth.log"}},
        {"terms": {"id": [
          "1794126908.223173", "1794126910.227942", "1794126910.228479",
          "1794126912.230072", "1794126912.231838", "1794126914.232903"
        ]}}
      ]
    }
  }
}
```

原实验对应六条 auth.log 告警。查询使用固定证据编号，因此统计范围与模拟工单一致。
