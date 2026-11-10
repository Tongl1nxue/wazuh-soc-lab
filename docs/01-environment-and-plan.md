# 第一阶段：环境检查与最简实施方案

检查日期：2026-11-05（Asia/Shanghai）。本文件记录实际只读检查及待验证事项，不代表 SIEM 已部署。

后续执行更新：已按用户新要求另建专用 SOC Ubuntu，4 核、8 GiB RAM、50 GiB 按需增长磁盘；原逆向虚拟机保持原状。Wazuh 基础设施部署与健康复验结果见 [第二阶段部署记录](02-deployment.md)。下文保留最初检查与方案演进，不再作为当前操作指令。

方案更新：用户已选择优先尝试单台 Ubuntu（约 8 GiB）承载 Docker 中的 Wazuh，以及 guest 本机的 SSH、Nginx 和 agent。下文原双环境预算仅作比较；当前不启动 Windows Docker Desktop，Ubuntu 也不再按日志源专用的 2 GiB 配置。当前操作以本文末尾“单 Ubuntu 路线”小节为准。

## 实测结果

| 项目 | 本次观察 | 判断 |
| --- | --- | --- |
| Windows | Windows 11 家庭版中文版，64 位，10.0.26200 | 可使用 Docker Desktop / WSL 2 路线 |
| CPU | Intel Core Ultra 9 275HX，24 核、24 逻辑处理器 | CPU 足够；虚拟机不必分配 8 核 |
| 内存 | 系统可见总量 15.38 GiB，检查时空闲 2.95 GiB | 当前不能直接启动完整实验栈 |
| 磁盘 | C 盘空闲 153.1 GiB；D 盘 19.9 GiB；E 盘 180.2 GiB | C/E 容量较充裕；不能按 D 盘容量规划完整 SIEM |
| 虚拟化 | HypervisorPresent=True；CIM 的固件虚拟化/SLAT 字段为 False | 已存在 hypervisor，不能据 False 单独断言 BIOS 未启用；需运行验证 |
| Docker CLI | 29.4.0；Compose v5.1.2；context 为 本机上下文（已脱敏） | 客户端存在 |
| Docker Engine | docker version 未取得 Server；Linux Engine 命名管道不存在 | 引擎未就绪；不能据此判定损坏 |
| WSL | 仅列出 docker-desktop，WSL 2，Stopped | 未列出 Ubuntu WSL；VMware Ubuntu 是另一套环境 |
| VMware Ubuntu | 配置名指向 Ubuntu 22.04；8 vCPU；16384 MiB；NAT | 需降低资源配置；系统实际版本需开机验证 |
| 虚拟磁盘 | Ubuntu VMDK 文件约 54.05 GiB，位于 D 盘 | 文件大小不是 guest 剩余空间或虚拟磁盘上限 |
| 运行状态 | 未检出 vmware-vmx 进程；未检出 Docker 相关进程 | 检查时未发现上述引擎/虚拟机进程 |
| 工具 | Python 3.14.3、Git 2.53.0、OpenSSH 客户端存在 | Python 标准库路线可优先考虑；项目代码尚未实现 |
| 当前项目 | 只有 Git 元数据；无提交、无现成部署程序 | 从自己的实验记录开始 |

CIM、服务与 WSL 初次查询受沙箱限制，已使用获准的沙箱外只读检查复核。WSL 输出有编码乱码，但发行版名称、版本及 Stopped 字段可辨。未读取 SSH 密钥、密码或 Docker 认证文件。

尚未验证：Ubuntu 内核/发行版、guest 可用内存和磁盘、SSH/Nginx/agent 服务、网络隔离、Docker daemon 资源配额与数据盘位置、镜像下载连通性、端口占用、vm.max_map_count。没有生成事件日志或运行截图。

## 参考内容核对

- [Wazuh 官方 Docker 文档](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)：单节点至少 4 核、Docker host 8 GB RAM、50 GB 存储；Linux 内核 vm.max_map_count 至少 262144。Windows Docker Desktop 使用 WSL 2。
- [官方部署仓库](https://github.com/wazuh/wazuh-docker)：确有 single-node 目录；main 用于开发。本次文档指向 v4.14.9，已读取该版本 Compose，manager/indexer/dashboard 镜像均为 4.14.9。后续以此版本及实际提交 SHA 固定部署，不混用 main 配置。
- [v4.14.9 Compose](https://github.com/wazuh/wazuh-docker/blob/v4.14.9/single-node/docker-compose.yml)：包含持久卷及多个宿主发布端口。正式启动前需调整监听范围、凭据及证书；当前没有运行原始 Compose。
- [SOC 案例](https://github.com/timmanning2022/wazuh-soc-investigation)：主要是 Windows/Sysmon 实验，顶层包含 evidence、rules、README、案例 PDF；本次已核对 README 和目录，未审阅 PDF。借鉴证据组织、规则验证与误报分析，不视为 Linux/Web 一键部署程序。
- [Python 参考](https://github.com/MatthewDawkins/security-portfolio)：顶层 README 介绍 project-03-python-log-parser，按来源 IP、用户名聚合 SSH 失败认证。子目录/README 的网页抓取失败，尚未完成代码审阅，不声称其已有代码满足本项目需求。

## 最简方案与切换条件

优先尝试 Windows Docker Desktop/WSL 2 运行官方单节点三组件；现有 VMware Ubuntu 仅作为 SSH + Nginx + Wazuh agent 日志源。Windows 只访问本地 Dashboard 并运行 Python 分析。

建议实验预算（不是已修改配置）：Docker/WSL 2 8 GiB、4 vCPU；Ubuntu 2 GiB、2 vCPU。Ubuntu 桌面若不足，可停用不必要的桌面负载，或改用轻量 Server 日志源。两套 Linux 同时运行对 16 GB 电脑较紧，需要以实测稳定性决定。

启动门槛：先关闭自己不需要的应用，复测宿主空闲内存，争取至少约 10 GiB；Docker 数据盘所在卷至少空闲 50 GB（建议留更多余量）。启动后若持续严重换页、进程 OOM 或交互明显卡顿，不继续堆组件。不能将 WSL 的内存上限当成当前已预留内存，也不能把 Windows 总内存当成 Docker host 已获分配的内存。

备选：在单台 Ubuntu 中分配约 8 GiB、4 vCPU，同时承载 Docker 栈与本机日志源，避免并行运行两套 Linux；需先解决其 D 盘空间与 guest 容量问题。若完整栈仍不能稳定运行，降级为 Wazuh manager + 本地日志 + wazuh-logtest + JSON/CSV/Python 离线分析，省去 indexer/dashboard。该降级方案不等于完成完整 SIEM 或 Dashboard 查询，成果中必须明确其边界。

网络：NAT 可出网，不等于隔离。实验流量只访问本机或明确确认的实验地址；不使用桥接网络。下载依赖时可临时用 NAT；事件模拟前切换 host-only 或 internal 网络并验证。Dashboard 绑定 loopback；日志源连接所需端口仅允许实验网访问，其余管理端口不向局域网开放。具体互通方式在第二阶段按实际网卡/路由验证后确定，不预填 IP。默认不启用自动封禁。

日志链路：SSH/Nginx 真实操作 → guest 日志 → agent → manager 解码/规则 → alerts JSON → indexer → Dashboard。注意告警不等于全部原始日志；普通访问未触发告警很正常。后续单独验证正常日志的采集，并为少量实验数据按需启用 archives/索引，以实现原始事件查询，同时控制空间。

## 截止 11 月 20 日的范围

| 时间 | 模块 | 验收证据 |
| --- | --- | --- |
| 11/05–11/06 | 资源与隔离、Docker/Ubuntu 检查 | 本文、用户独立运行的检查输出、实际资源配额 |
| 11/07–11/09 | 单节点部署、agent 与两类日志接入 | 版本/SHA、服务状态、两类实际日志与查询截图 |
| 11/10–11/12 | SSH 连续失败、Web 敏感路径/404 探测两类事件 | 有限次数本地请求、时间线、原始日志与告警证据；探测不写成入侵成功 |
| 11/13–11/14 | 一条自定义规则、误报调优 | 正例、反例、阈值边界与重复验证；实测规则 ID |
| 11/15–11/16 | Python 分类/统计/CSV | 读取自己的脱敏日志，统计对账与可复现命令 |
| 11/17–11/18 | 研判记录、模拟工单、Excel 与周报 | 每条结论回指证据；模拟工单明确标注 |
| 11/19–11/20 | 复跑、README/架构/截图、GitHub 与简历 | 仓库可复现；简历只引用已通过数据 |

每个模块完成后解释原理并由用户独立操作或回答验收题，再进入下一模块。不提前写检测成功、统计数字、工单结论或简历成果。本次只形成第一阶段检查材料。

## 当前动作与验收

1. 保持虚拟机关机，在 VMware 中将此 Ubuntu 调为 2 GiB、2 vCPU；先不要启动它。不要删除/移动 VMDK。自行关闭不必要应用，避免强行结束有未保存内容的程序。
2. 打开 Docker Desktop，待其显示引擎运行；独立执行 `docker version`，应同时出现 Client 和 Server。仅显示 Docker 版本号不算通过。查看资源限制与磁盘位置，记录实际值；暂不拉取 Wazuh 镜像。
3. 满足宿主内存预算后再启动 Ubuntu。在其终端运行下列只读检查，或运行本项目 scripts/linux-preflight.sh。若开机后宿主压力过大，先关闭 guest，改选备选方案。

```bash
date -Is
cat /etc/os-release
uname -m
free -h
df -h / /var
nproc
ip -br address
ip route
systemctl is-active ssh nginx wazuh-agent
ls -l /var/log/auth.log /var/log/nginx/access.log
sysctl vm.max_map_count
```

未安装 nginx/agent 或没有对应日志时按原样记录，第一阶段无需为了让检查全绿而安装。IP/用户名/路径属于本地证据，公开前另做脱敏。

验收题：

- 为什么 Windows 能找到 docker.exe，还不能证明 Wazuh 可以部署？
- 为什么 NAT 不等于隔离？
- 为什么一次正常 Nginx 访问没有出现在告警页，不足以证明采集失败？

通过标准：用户能解释至少前两题；提供 Docker Server 状态及 Ubuntu 实际资源/网络检查结果；资源预算和隔离路径经确认。本模块状态：部分完成，等待用户独立操作结果。

## 单 Ubuntu 路线（用户当前选择）

来源核验：Windows 当前用户的 VMware 清单记录了一台早期 Ubuntu 虚拟机，已核对其 VMX 与同目录虚拟磁盘。这里只保留环境判断，省略旧实验名称及本机路径。挂载介质文件名指向 Ubuntu 22.04.2 Desktop amd64，实际 guest 版本和健康状态需开机验证。

当前结论：可作为候选，不需要立刻重新下载 Ubuntu。先将关机状态的 VM 调为内存 8192 MB、CPU 共 4 核（如 1 个处理器 × 4 核），不要启动 Windows Docker Desktop 或 Kali。关闭不必要的宿主程序后再启动 guest。Docker Engine/Compose 将安装在 guest 中，8 GiB 是整台 guest 的预算，桌面、Docker、Wazuh、Nginx、SSH、agent 共同使用，稳定性尚未验证。

开机后运行上面的 Ubuntu 只读检查。重点确认登录可用、实际发行版/架构、guest 剩余磁盘与内存，再决定是否复用。D 盘宿主仅约 19.9 GiB 空闲，即使 guest 显示较大剩余空间，稀疏 VMDK 的后续增长也可能耗尽宿主空间，因此当前不向该盘拉取完整栈。后续若复用，应先在关机状态规划将整个 VM 目录迁到容量充足的 C/E 盘并重新验证；本次未执行迁移。

若该 VM 来历不明、旧实验较多且不宜修改、无法正常登录或系统损坏，则保留旧 VM，改用 Ubuntu 官方安装介质新建轻量 Server VM。新 VM 可规划 4 vCPU、8 GiB RAM、80–100 GiB 可增长虚拟磁盘（规划值，不是已分配），存放在容量充足的卷。重建不是因为 Ubuntu 22.04 名称本身不适用；最终版本选择需按实际依赖支持情况核对。
