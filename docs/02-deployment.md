# 单机 SOC 实验环境部署记录

日期：2026-11-05。此记录对应新建的 SOC 虚拟机，不涉及原有逆向学习 Ubuntu。这里只完成基础设施，事件检测、日志端到端查询、自定义规则和分析报告仍待后续模块验收。

## 实际部署

| 项目 | 配置 / 实测 |
| --- | --- |
| 虚拟机 | VMware，`E:\SOC-Lab\SOC-Ubuntu\SOC-Ubuntu.vmx` |
| Ubuntu | 官方 Ubuntu Server 22.04 amd64 云镜像，无桌面；cloud-init 初始化完成 |
| 资源 | 4 vCPU、8192 MiB RAM、50 GiB 按需增长虚拟硬盘 |
| 磁盘 | 根分区显示约 49G；最终复验用 9.6G、剩余 39G，20% |
| guest 内存 | 总量约 7.8 GiB，最终复验 used 约 2.3 GiB、available 约 5.2 GiB；缓存可回收 |
| Docker | guest 内的 Docker Engine 29.9.3、Compose 5.7.0 |
| Wazuh | manager/indexer/dashboard/agent 均为 4.14.9 |
| 官方仓库提交 | `56ece955b1107b7b62823afae5b7057e1dab9d98`，来自 `v4.14.9` |
| 服务位置 | guest 中 `/opt/soc-lab/wazuh-docker/single-node/compose.lab.yml` |
| 日志源 | guest 上的 SSH、Nginx 与本机 Wazuh agent |

镜像来源：[Ubuntu 官方 release](https://cloud-images.ubuntu.com/releases/jammy/release/)。下载 SHA-256：`eac978cac67cc40afe3785c4d78c97c77a36b16b4db57ae893a69f62de7736b2`，已与同站点 SHA256SUMS 比对。使用 VMware 自带工具将官方 VMDK 转换为可写、按需增长磁盘，再扩展到 50 GiB；cloud-init 扩展根分区。

这份 SHA256SUMS 来自 HTTPS 官方站点，本次未额外验证其 GPG 签名。使用的依赖仓库为 Ubuntu、Docker 与 Wazuh 官方签名软件源，没有关闭 apt 签名校验。

50 GiB 指虚拟硬盘容量上限，既不是立即占满宿主 50 GiB，也不是整个 VM 目录的空间上限。VMware 运行时可能另建约 8 GiB 的内存后备文件，下载源镜像也会额外占空间。宿主和 guest 的可用空间都需要观察。官方建议至少给 Docker 镜像和数据卷 50 GB；本实验将系统也放入 50 GiB，因此属于小流量实验配置，不能据初次启动成功推断长期容量充足。

## 连接与日常操作

- 双击项目根目录 `Open-SOC.cmd`：启动专用虚拟机（若已启动则复用），建立本地 SSH 通道并打开浏览器。若新建通道窗口保持运行，不要关闭窗口。
- 仪表盘：`https://localhost:8443`；用户名 `admin`，随机密码保存在 `local-evidence/dashboard-login.txt`。
- Windows 上访问 Nginx：`http://localhost:18080`。SSH 隧道将该入口转发到 Ubuntu 内的 `127.0.0.1:8080`，Ubuntu 内的实验脚本仍使用 `8080`。
- 双击 `SSH-SOC.cmd`：以本项目生成的专用密钥登录 `soc` 用户。该账户没有设置控制台登录密码，不要拿 Dashboard 密码尝试 Ubuntu 控制台。
- 双击 `Stop-SOC.cmd`：通过 SSH 请求正常关机；确认 VMware 已关闭后再启动其他大型实验环境。
- 当前 IP 和虚拟机路径见 `local-evidence/access.json`。若 VMware DHCP 地址改变，需要核对虚拟网卡 MAC、租约与 SSH 主机密钥，再更新地址；启动入口尚未实现自动发现新地址。

2026-11-10，Windows 的 `8080` 无法绑定。SSH 同时申请两个本地端口，`ExitOnForwardFailure` 使任一绑定失败时整条隧道退出，Dashboard 也会失联。Ubuntu 内的 Dashboard 和 Nginx 分别返回 HTTP 302 和 200。修复将 Windows 的 Nginx 入口移至 `18080`。用 `python scripts/start-soc.py --no-browser` 启动隧道后，从 Windows 请求 Dashboard 得到 HTTP 302，Nginx 得到 HTTP 200。若需要回退启动脚本，可从 `local-evidence/host-forwarding-backup-*` 将三份脚本复制回 `scripts/`，将部署说明复制回 `docs/`。回退前需确认 Windows 的 `8080` 可绑定。

仪表盘使用本实验生成的自签名证书，浏览器可能显示证书不受信任。不要将其与未知网站提示混淆；只在确认访问地址确为上述本地通道、证书属于本实验后手动继续。未向 Windows 安装根证书或修改系统安全设置。

`local-evidence` 包含密钥、密码、证书、连接参数和原始检查结果，已经由 `.gitignore` 排除，不应上传 GitHub。公开成果使用另行脱敏的证据。

## 网络和空间控制

当前使用 VMware NAT 进行安装下载；没有建立桥接网络，也没有配置 NAT 入站端口转发。NAT 仍允许出网，不能称为完全隔离。

Wazuh 宿主发布端口和 Nginx 均只监听 guest 的回环地址，通过 SSH 本地转发访问。SSH 在 guest NAT 网卡上提供密钥认证。事件构造仅访问 guest 的 `127.0.0.1`；若需要其他实验地址，先配置和验收隔离网络。

已配置：Docker 容器 JSON 日志每份 10 MB、最多 3 份；systemd journal 上限 100 MB；磁盘保护每分钟检查根分区，达到 85% 时停止 Wazuh manager 采集，不删除证据。该保护不是所有文件的硬性容量配额，也不自动恢复采集。发生保护后应先导出证据、查明增长来源，再手动恢复。

Wazuh 漏洞情报下载不属于本项目范围，已在 manager 配置中关闭漏洞检测模块；原始日志 archives 全量索引尚未开启。后续按少量实验数据验证正常日志查询，避免无限保存原始日志。

## 实测验收与边界

2026-11-05 22:14 首次通过，23:12（Asia/Shanghai）移除临时 Docker 代理配置并重启 Docker 后再次通过：

- 三个 Wazuh 容器均 running；indexer 单节点 health 为 green、HTTP 200。
- Dashboard `/api/status` 为 green、HTTP 200。
- manager 列出 `soc-ubuntu` agent 为 Active。
- SSH、Nginx、Docker、agent 的 systemd 状态均 active。
- Nginx 本地首页 HTTP 200。
- Windows SSH 通道访问 Dashboard 返回 HTTP 302（进入登录流程），Nginx 返回 HTTP 200。

上述检查通过 API、CLI 和实际请求完成；没有生成或声称存在运行截图。首页访问属于基础设施连通性检查，会留下真实普通访问日志，不能写成安全事件检测成果。

私有机器可读记录：`local-evidence/infrastructure-verification.json`。guest 部署过程：`/opt/soc-lab/deploy.log`。本地脚本的 Python/Bash 语法检查已执行；完整从空白 VM 再部署一次尚未执行。

最终复验包含 Docker daemon 重启后的三组件恢复和 agent 重连；未执行整台虚拟机冷启动复验。临时下载通道不再写入 Docker 配置；未来若需更新或重拉镜像，需重新提供可用下载网络。下载源 VMDK 暂留 VM 目录，约 0.66 GiB；它不是运行盘。

部署中实际遇到并修正：虚拟网卡 PCIe 插槽兼容、Docker Hub 解析/连接失败、apt 公钥读取权限、Nginx 首页权限，以及 Python 3.14 对官方证书生成器旧格式 CA 的严格验证差异。下载使用电脑已有代理经临时 SSH 反向通道访问官方仓库，未使用第三方镜像替代。Windows 连通性检查保留证书链和签名验证，仅使用兼容旧 CA 的 OpenSSL 验证模式；SSH 主机密钥已记录。

## 本模块原理与用户验收

agent 在 Ubuntu 上读取 SSH 与 Nginx 日志，发送给容器中的 manager；manager 解码并匹配规则，告警经索引后由 Dashboard 查询。三者分工：manager 分析、indexer 存储查询、dashboard 展示。普通访问不一定产生告警，因此基础设施在线不等于所有原始日志已可在告警页查询。

请独立完成：打开 Dashboard 登录，找到 agent `soc-ubuntu` 并确认在线，再访问 Nginx 首页。回答：为什么这个实验里只开一台 Ubuntu，却能运行 Wazuh 的三个中心组件？完成后再进入日志采集和查询验收模块。
