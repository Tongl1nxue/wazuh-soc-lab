# 用 Wazuh 搭建 Linux/Web 安全监测实验：从日志采集到告警研判

记录日期：2026 年 11 月 8 日  
项目状态：已完成基础监测、两类受控事件检测、自定义规则验证和 Python 统计，运营材料与扩展集成仍在推进。

为了练习 SOC 安全运营中的日志监测与告警研判，我搭建了一套基于 Wazuh 的本地 Linux/Web 实验环境。这篇文章记录目前实际完成的内容，以及过程中遇到的问题。

实验全部发生在自有虚拟机中，测试请求仅访问本机回环地址。文中的告警和统计来自真实操作产生的日志；工单属于明确标注的模拟记录。对于尚未完成的通知、威胁情报和事件管理集成，我会放在后续计划中。

## 一、目前做到哪一步了

| 模块 | 当前进度 |
| --- | --- |
| Wazuh 单节点平台 | 已部署，三组件健康状态已验证 |
| SSH、Nginx 日志 | 已验证采集、归档与索引查询 |
| 两类事件研判 | 已完成 SSH 无效用户连接、Web 敏感路径访问实验 |
| 自定义检测规则 | 已部署规则 100110，完成正反例与边界测试 |
| 误报分析 | 已复现宽泛匹配造成的问题，并验证收紧后的效果 |
| Python 分类统计、CSV | 已实现，并独立运行对账 |
| 模拟工单 | 已生成两份，技术复测完成，尚待关闭复核 |
| Excel、运营周报 | 尚未完成 |
| Suricata、外部通知、威胁情报 | 后续计划，尚未实施 |

当前完成的是一套小型实验环境，以及有证据支撑的检测流程。它还不能被描述为完整的生产 SOC，也没有验证 IPS 阻断能力。

## 二、环境与架构：用一台 Ubuntu 控制资源占用

考虑到宿主机只有约 16 GB 运行内存，我采用一台 Ubuntu 虚拟机承载实验，而没有同时运行多台大型安全平台。

| 项目 | 实际配置 |
| --- | --- |
| 宿主机 | Windows 11，约 16 GB RAM |
| 虚拟化 | VMware |
| 实验系统 | Ubuntu Server 22.04，amd64，无桌面 |
| 虚拟机资源 | 4 vCPU、8 GiB RAM |
| 虚拟硬盘 | 50 GiB，按需增长 |
| Wazuh | Manager、Indexer、Dashboard 和 Agent 均为 4.14.9 |
| Filebeat | 7.10.2 |
| 日志源 | Ubuntu SSH、Nginx |

这些版本是本次实验的实际版本，不代表软件的最新版本。

整体链路如下：

```text
Ubuntu SSH / Nginx
        │
        │ 产生真实日志
        ▼
Ubuntu 本机 Wazuh Agent
        │
        ▼
Wazuh Manager：日志解码、规则匹配
        │
        ├── archives：原始事件归档
        └── alerts：规则产生的告警
                │
                ▼
             Filebeat
                │
                ▼
Wazuh Indexer：索引与查询
                │
                ▼
Wazuh Dashboard：展示与检索
```

Wazuh 三个中心组件运行在 Docker Compose 中，Agent 则安装在 Ubuntu 本机，用于读取宿主系统日志。这里的“宿主系统”指容器外的 Ubuntu，不是 Windows。

Nginx 监听 Ubuntu 的 `127.0.0.1:8080`，Dashboard 和 Indexer 的宿主发布端口也绑定回环地址。Windows 浏览器通过 SSH 本地转发访问平台。VMware 可以通过 `vmrun ... nogui` 在后台运行，因此没有打开管理窗口，并不代表虚拟机没有占用资源。

安装阶段使用 VMware NAT 下载依赖。NAT 仍然允许出网，不能直接称为完全隔离；本次事件构造只访问 `127.0.0.1`，没有扫描第三方目标。

50 GiB 磁盘还要容纳 Ubuntu，本次实际运行后剩余空间约 38 GiB。这个结果只证明当前小流量实验可以运行，不能据此推断长期存储能力。平台已设置容器日志轮转，以及磁盘达到 85% 时暂停 Manager 采集的保护机制。

## 三、第一步不是看告警数量，而是验证日志链路

部署完成后，Dashboard 能打开、Agent 显示在线，只能说明基础服务可用，还不能证明日志已经按预期进入可查询的数据集。

我分别检查了：

1. Ubuntu 是否产生了真实日志。
2. Agent 是否配置了对应日志路径。
3. Manager 是否接收到并解析事件。
4. 数据是否进入 Indexer。
5. Dashboard 查询能否找到同一条记录。

日志来源主要包括：

```text
/var/log/auth.log
/var/log/nginx/soc_access.log
```

验证 Nginx 时，脚本向本地站点发出带唯一批次标记的正常请求，再用这个标记查询索引。这样可以把“请求已经发出”和“平台收到的是这次请求”关联起来。

### archives 和 alerts 的区别

这是目前最有帮助的一个知识点：

- **archives** 保存进入归档链路的事件，正常访问也可以存在其中。
- **alerts** 保存达到告警条件的规则匹配结果，并不是全部日志。

因此，一次正常的 HTTP 200 请求没有出现在安全告警列表，并不一定是采集失败。它可能已经被正常解析和归档，只是没有生成告警。

原环境中的 Manager JSON archives 和 Filebeat archives 转发都处于关闭状态。我在备份配置后启用了这条链路，再用真实请求验证查询结果。

### 查询条件过宽，也会影响判断

第一次独立查询时，只搜索了实验标记，结果返回三条记录：

- 一条 Nginx 访问日志。
- 一条来自 journald 的 sudo 操作日志。
- 一条来自 auth.log 的同类 sudo 操作日志。

后两条是收集实验 JSON 证据时执行的管理操作，命令参数恰好也包含批次标记。

因此，三条结果并不代表三次 Web 请求。加入主机和日志路径过滤后，才能准确定位目标访问记录。这也提醒我：检索数量需要结合数据来源解释，不能直接把命中数当成攻击次数。

## 四、事件一：SSH 无效用户名连接

这一部分使用一次性、不存在的用户名，对本机 `127.0.0.1:22` 顺序发起有限次数连接。

测试采用非交互、公钥认证方式，没有进行密码字典猜测，没有创建账户，也没有更改真实凭据。

最终通过的复测批次结果为：

| 项目 | 结果 |
| --- | --- |
| SSH 连接次数 | 6 |
| 客户端非零退出次数 | 6 |
| auth.log 中的 Invalid user 记录 | 6 |
| 对应规则 | 5710 |
| 对应告警 | 6 条 |

统计时只选择本批次唯一测试用户名、实验主机以及 `/var/log/auth.log`，没有把 journald 中的同类数据再次累计。

我的研判结论是：**已知授权模拟活动产生的无效用户连接，检测符合预期。**

这里没有证据支持“口令爆破成功”或“主机已被入侵”。即使在真实环境中，管理员输错用户名、失效的自动化任务，也可能产生类似日志，需要结合来源、频率、成功认证和授权背景继续调查。

另外，本模块因排查归档问题进行了两批异常测试，每批六次，共十二次 SSH 连接。上表只统计最终通过的那一批，不能把它写成整个实验过程只有六次连接。

## 五、事件二：Web 敏感配置路径访问

第二类实验是访问自有 Nginx 的 `/.env` 路径。

`.env` 常用于保存应用配置。如果它被错误地放进网站公开目录，并且 Web 服务允许读取，就可能造成数据库凭据、API 令牌等信息泄露。但一次请求本身并不能证明泄露发生，必须继续核对响应和后续行为。

本次最终批次包含以下对照：

| 请求路径 | 实际状态码 | 调优后规则回放结果 |
| --- | --- | --- |
| `/index.html` | 200 | 原生 31100，level 0 |
| `/ordinary-missing-page` | 404 | 原生 31101，level 5 |
| `/docs/.env-guide` | 404 | 原生 31101，不命中自定义规则 |
| `/.env` | 404 | 自定义 100110，level 7 |
| `/.env.example` | 404 | 原生 31101，不命中自定义规则 |

实际请求附加了唯一的 `soc_run` 查询参数，用于关联证据。五条访问都进入了 archives，其中 `/.env` 产生了一条自定义告警。

以下摘录自实际告警的部分字段：

```json
{
  "timestamp": "2026-11-08T08:35:08.175+0000",
  "data": {
    "id": "404",
    "url": "/.env?soc_run=soc-detect-1d64d29b1512"
  },
  "rule": {
    "id": "100110",
    "level": 7
  },
  "location": "/var/log/nginx/soc_access.log"
}
```

其中 `data.id` 是解码器提取的 HTTP 状态码，不是规则编号。时间字段使用 UTC，对应北京时间为 16:35:08.175。

### 404 能说明什么

本次 404 表明请求的资源没有找到，记录中没有显示目标配置文件成功返回。

但它不能证明防火墙、WAF 或 IPS 已成功阻断攻击，因为本轮没有配置或验证这些阻断机制。即使以后看到 HTTP 200，也需要检查响应内容：有些站点会把不存在的路径统一返回首页或登录页。

所以，这次事件应描述为：**检测到敏感配置路径访问，返回 404，结合已知实验背景判定为授权测试。**

## 六、自定义规则：从宽泛匹配到边界控制

当前部署的规则如下：

```xml
<group name="web,accesslog,soc_lab,">
  <rule id="100110" level="7">
    <if_sid>31101</if_sid>
    <id>^404$</id>
    <url type="pcre2">^/\.env(?:\?.*)?$</url>
    <description>Denied request for environment configuration path (lab).</description>
    <group>soc_sensitive_path,</group>
  </rule>
</group>
```

规则的判断过程是：先满足原生 Web 4xx 规则 31101，再要求状态码准确为 404，最后检查请求路径是否为 `/.env`，并允许后面带查询参数。

`100110` 是规则编号，`7` 是该规则设定的告警级别。两者互相独立：编号较大不代表危险程度更高，级别也不是攻击成功概率。本项目把该事件放在普通 404 的 level 5 之上，用于提示优先复核；这是实验中的规则设计选择。

规则描述中的 `Denied` 只是文字标签，也不代表已经执行 IPS 阻断。

### 候选规则确实出现了误报

最初候选规则只匹配 `.env` 子串。使用真实访问日志进行 `wazuh-logtest` 重放时，以下三个路径都命中了自定义规则：

```text
/.env
/docs/.env-guide
/.env.example
```

其中 `/docs/.env-guide` 是本实验明确设置的文档路径对照。仅凭它包含 `.env` 就提升告警，扩大了原本想检测的范围。

收紧起止边界后，`/.env` 及其查询参数仍可命中，其余四个正常或边界对照均不命中自定义规则。随后又通过新请求验证了实时告警，避免只凭离线回放判断规则已经生效。

需要保留两个限制：

1. 普通 404 仍可能触发原生 31101；没有命中自定义规则，不等于完全没有告警。
2. 五个测试样本不足以推断生产误报率。当前规则也不覆盖其他目录的 `.env`、编码变体、其他敏感文件或 HTTP 200 暴露。

## 七、一个实际故障：容器重启通过，不代表重建后仍然正确

这次实验中，告警链路曾经正常，而 archives 查询没有找到新 Web 记录。

排查发现：Manager 的 `logall_json` 仍为 `yes`，但 Filebeat 的 archives 配置在容器重建后恢复为 `false`。也就是说，Manager 还在生成原始归档，但转发环节没有按预期启用。

此前只做过容器 restart 验证，不能据此证明 recreate 后配置仍然有效。

修复过程包括：

1. 备份当前 Compose 和 Filebeat 服务启动脚本。
2. 针对固定版本镜像，持久挂载对应启动脚本。
3. 使用 Filebeat 支持的启动覆盖参数：

   ```text
   -M wazuh.archives.enabled=true
   ```

4. 重建 Manager 容器。
5. 先发一次新的正常请求验证归档，再重复有限异常批次复测。

最终，新的 archives 与告警查询都通过了验证。这里的 `-M` 是运行时覆盖，不会把基础 YAML 文件自动改成 `true`，因此后续检查还要结合启动参数和真实索引结果。

初始化过程为什么会恢复基础值，目前没有进一步定位到完整根因，不能把猜测写成已证实结论。

另一个小问题发生在验收脚本：当前版本的 `wazuh-logtest` 把结果写入 stderr，最初只解析 stdout，误报了回放失败。合并读取两条输出流后，才正确取得规则匹配结果。

这些问题让我意识到，验证需要覆盖实际生命周期和完整数据链路，而不只是检查某一个配置文件。

## 八、用 Python 把日志变成可核对的数据

检测完成后，我使用 Python 标准库实现了快照分析程序，读取已经保存的真实查询结果，完成：

- 按规则和日志类型分类。
- 分别统计 archives 与 alerts。
- 按索引名与文档 ID 去重。
- 检查查询是否超时、是否有失败分片、是否完整取回结果。
- 导出明细 CSV、分类汇总和来源摘要。

最终批次的结果为：

| 统计项 | 数量 |
| --- | --- |
| Web archives | 5 |
| SSH archives | 12 |
| **archives 合计** | **17** |
| 规则 100110 告警 | 1 |
| 规则 31101 告警 | 3 |
| 规则 5710 告警 | 6 |
| **alerts 合计** | **10** |

这里的 17 条归档和 10 条告警不能相加当作事件总数，也不能把 10 条告警写成 10 起攻击。

六次 SSH 连接留下十二条归档记录，是因为连接可以在不同阶段产生日志。另一方面，实际 archives 中部分记录的源事件 ID 相同，因此程序使用“索引名＋文档 ID”去重，避免误删不同日志。

在项目目录中，实际执行命令为：

```powershell
python scripts/analyze-alerts.py --input 'local-evidence/detection-lab/soc-detect-1d64d29b1512.json' --output 'output/operations'
```

输出的核心统计为：

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

这些命令依赖本项目已有脚本及本地实验快照，并不是复制到任意电脑就能得到相同结果的一键部署命令。原始快照不随博客公开；文章中的统计与已保存证据对账一致。

输出文件包括 `alerts.csv`、`archives.csv`、`alert-statistics.csv` 和 `analysis-summary.json`。程序使用 UTF-8 BOM，便于 Excel 读取中文，同时限制导出字段，移除原始用户名、地址、原始日志正文及非实验查询参数，并处理可能被表格解释为公式的字符串。

统计程序已经独立重跑，对账结果一致。单元测试覆盖了文档去重、事件 ID 碰撞、CSV 公式处理、查询参数脱敏和超时查询拒绝；测试夹具与真实实验日志分开保存。

## 九、从告警到工单：先记录依据，再谈关闭

目前已生成两份模拟工单：

| 主题 | 主要关联告警 | 当前状态 |
| --- | --- | --- |
| SSH 无效用户名连接 | 6 条规则 5710 告警 | 技术复测完成，待关闭复核 |
| Web 环境配置路径访问 | 1 条规则 100110 告警 | 技术复测完成，待关闭复核 |

每份工单记录发现、研判结论、实际操作、复测结果和关联告警编号，并提供 Markdown、CSV 与 JSON。

工单中的操作只填写已经执行的内容，例如核对日志、调整规则和复测。没有把 IP 封禁、密码重置或外部通知写成已完成，也没有自动填入关闭时间。

目前两份工单尚未关闭。后续复核记录后，可以由本地程序记录模拟关闭动作和实际时间；这个状态只表示授权实验记录处理完成，不等于完成了一次生产攻击处置。

## 十、目前形成了哪些可复核材料

目前项目中已有：

```text
config/rules/
  soc_web_rules.xml             自定义规则

scripts/
  phase1-log-pipeline.py        日志链路检查与验证
  detection-lab.py              受控事件、回放与实时验证
  fix-archive-persistence.py    归档转发持久化修复
  analyze-alerts.py             分类统计与 CSV 导出
  build-lab-tickets.py          模拟工单生成

evidence/detection/
  verification.json            脱敏验收结果
  events.json                  选定证据字段
  replay-matrix.json           正反例回放矩阵

output/operations/             统计与 CSV
output/tickets/                模拟工单
```

部署记录、规则研判、问题修复和操作步骤也已整理成 Markdown。配置修改前保留备份，并编写了恢复入口，但目前尚未执行完整的恢复演练。

私有证据目录不随博客公开，其中保存原始快照及连接资料。公开内容只使用选定字段和实验标识，不包含密钥、密码、Webhook 或真实访问令牌。

## 十一、接下来的实现顺序

下一步先把现有 CSV 和工单整理成 Excel 与运营周报，再按资源和账号条件推进扩展：

1. **Suricata：**先确认本地请求经过的接口，针对回环流量验证 EVE JSON 到 Wazuh 的链路。只在实际验证后记录 IDS 成果，不把它直接描述为 IPS。
2. **告警通知：**先接通一个具备账号条件且网络可达的渠道，加入筛选、去重、超时和失败记录。
3. **威胁情报：**区分公网 IP 信誉与文件哈希查询，处理缓存、限额和无结果情况。本次回环地址应跳过公网信誉查询。
4. **其他平台：**pfSense、TheHive/Cortex、Microsoft 365 等需要额外网络、资源或权限条件，暂不计入已完成成果。

当前这段实践中，我已经完成了从真实操作、日志采集、规则匹配，到查询复核和统计记录的验证。更需要继续练习的，是如何把检测结果转化为有依据的处置决定，并准确记录哪些动作完成了、哪些仍待验证。

## 参考资料

- [Wazuh 官方 Docker 部署说明](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh 官方部署仓库](https://github.com/wazuh/wazuh-docker)
- [Wazuh 事件归档说明](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Wazuh 自定义规则说明](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh 4.14.9 SSH 规则](https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0095-sshd_rules.xml)
- [Wazuh 4.14.9 Web 规则](https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0245-web_rules.xml)
- [Filebeat 7.10 命令参数说明](https://www.elastic.co/guide/en/beats/filebeat/7.10/command-line-options.html)
- [SOC 实践案例参考](https://github.com/timmanning2022/wazuh-soc-investigation)
- [Python 安全分析项目参考](https://github.com/MatthewDawkins/security-portfolio)

案例仓库用于学习证据组织与分析思路，本项目的统计和验证结果来自自己的本地实验记录。
