# 可选网站连接审计

基础一键安装仅提供网速控制、节点备注和审计网页入口，不会自动开启访问日志、审计任务或邮件。附加组件要求管理员已明确告知使用者，且仅用于获授权的公司设备/节点管理。

## 能统计什么

- 经过本 VPS 并实际记入日志的目标域名或 IP、连接次数、首末记录时间、连接出现的小时。
- 各节点独立显示；新增节点会在下一次成功汇总时被发现，通常约 2 分钟。
- “疑似网站/服务”只按实际记录的域名匹配本地规则，表格可查看依据。公网 IP 可点击“反查 IP”查询 PTR：仅把所选 IP 的反向 DNS 问题发送给服务器配置的 DNS 解析器，不发送整份访问记录。额外的“可能服务”参考独立展示，不改变原始服务分类、连接统计、日报或邮件。

连接记录不等于网页浏览次数、访问成功、前台 App 使用时间或员工工作时长。后台同步也会建立连接。不能读取 HTTPS 网页正文、微信/QQ/Telegram 聊天内容或视频内容，也不采集截图、键盘和客户端活动。旧汇总缺少字段时不会补造历史数据。

## IP 反查的可能服务参考（v1.2.1）

在原审计表格点击“反查 IP”，可查看主机名、可能关联的服务/基础设施、常见用途、匹配依据和官方来源。下面只是规则示例，不代表任何真实员工活动：

| PTR 名称匹配 | 可能关联 | 规则依据 |
| --- | --- | --- |
| 精确 `dns.google` | Google Public DNS 域名解析 | [Google Public DNS](https://developers.google.com/speed/public-dns/docs/doh) |
| `1e100.net` 后缀 | Google 共享网络；无法区分搜索、视频等产品 | [Google 域名说明](https://support.google.com/faqs/answer/174717?hl=en-GB) |
| `googleusercontent.com` 后缀 | Google 托管资源 / 云基础设施 | [Google Cloud PTR](https://docs.cloud.google.com/compute/docs/instances/create-ptr-record) |
| `amazonaws.com` 后缀 | AWS 云基础设施，不直接认定 EC2 或具体网站 | [AWS 服务端点](https://docs.aws.amazon.com/general/latest/gr/rande.html) |
| `cloudfront.net` 后缀 | CloudFront 内容分发，具体站点未知 | [CloudFront 域名](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LinkFormat.html) |
| `cloudapp.azure.com` 后缀 | Azure 云服务 / 虚拟机，具体应用未知 | [Azure 域名表](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains) |
| `telegram.org` / `t.me` 后缀 | Telegram 网站 / 服务，不代表正在聊天 | [Telegram 配置域名](https://core.telegram.org/api/config) |
| `github.com` / `githubassets.com` / `githubusercontent.com` 后缀 | GitHub 网站 / API / 托管资源，不代表具体仓库操作 | [GitHub 网络域名](https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/hardening-security-for-your-enterprise/restricting-access-to-githubcom-using-a-corporate-proxy) |

后缀按完整域名标签边界匹配，`1e100.net.evil.example` 不会命中 Google。没有 PTR、查询失败或未命中规则时显示“无法确定”，不做关键词猜测或虚构概率。所有命中均标“可信度低”：PTR 可自定义或失真，并未验证 IP 归属；官方来源只说明域名的常见用途，不证明该 IP 属于该服务，更不证明员工的前台活动。可参考 [Azure 自定义反向 DNS 的限制](https://learn.microsoft.com/en-us/azure/dns/dns-reverse-dns-for-azure-services)。

参考规则在本地执行，不调用第三方 IP 画像 / 内容分析接口，不自动访问返回的主机名，也不会把推测追加到审计记录中。此功能不提供网页正文、聊天内容、观看内容或使用时长。

## 安装前提

当前附加组件支持 Debian/Ubuntu、systemd、原生 3x-ui SQLite 和 **Linux AMD64 Xray**，不是 ARM/Docker 通用安装器。

1. 先安装本项目 v1.2.0 或更新版本，确保节点备注可保存。
2. 在 3x-ui 的 Xray 配置中将 `log.access` 设置为 `/var/log/x-ui/access.log`，保留其他日志设置及已有的回环 `LoggerService`。通过面板保存配置可能重启 Xray，请选择合适时段。
3. 该日志必须实际存在，属主 root、权限 0600；如权限不符，管理员核对路径后执行 `sudo chmod 600 /var/log/x-ui/access.log`。安装器不会自动改变日志路径，也不会读取聊天正文。
4. 安装依赖：`sudo apt-get install -y logrotate tzdata`。
5. 如需日报，在 3x-ui 的 SMTP 设置填写自己的邮箱和授权码。只支持校验证书的隐式 TLS 或 STARTTLS；不要把授权码写进命令、Git 或 README。

把示例地址替换成自己的收件邮箱，明确启用附加组件：

```bash
curl -fsSL https://raw.githubusercontent.com/skylucao/3x-ui-qos-manager/v1.2.1/scripts/install-audit.sh \
  | sudo bash -s -- --acknowledge-notice --recipient owner@example.com
```

也可下载/克隆 v1.2.1 后运行（参考提示需要先更新基础组件至 v1.2.1）：

```bash
sudo bash scripts/install-audit.sh --acknowledge-notice --recipient owner@example.com
```

这会安装根用户汇总/清理任务、低权限按需 PTR 查询，并启用每两分钟网页汇总、每整点清理。邮件初始为北京时间 09:00，可在同页“管理设置”中修改。不会发送测试邮件或重启 Xray。SMTP 未配置时日报不能发出，不能把“已安装”理解为已确认邮件送达。

首次启用按安装时间标记部分覆盖，不把之前未知来源的日志视作完整员工历史。安装更新保留采集起始时间和用户发送时间，只更新显式传入的收件人及固定 2 天保留上限。应用恢复点只备份代码/配置，不复制访问记录；已过期清理的数据不会在回滚时恢复。

邮件定时器每分钟检查网页设置，不是每分钟发信。修改从下次选定时间到点生效，不会立即补发，也不撤销已经启动的日报。整点清理占锁或短暂离线后可延后处理；每个报告日期自动尝试一次，失败/中断后须管理员检查，已有成功或不确定 SMTP 回执会阻止盲目重发。设置文件损坏时停止自动发信，不静默恢复默认时间。

## 保留与备注

- 原始访问记录、服务器日报、网页日期汇总和日期发信回执，最多保留北京时间今天和昨天，共 2 个自然日，不是完整滚动 48 小时。
- 网页接口立即拒绝过期日期；磁盘清理由每个整点（含午夜）及开机后的独立任务执行，不依赖 SMTP 成功。服务器停机、锁等待或日志重开失败可能延迟物理删除，恢复后继续；请关注任务失败状态。
- 原始日志最多 64 个轮转文件；每小时检查 64 MiB 轮转阈值，高流量时可能不足 2 天，不承诺日志完整。
- 备注属于当前管理配置，不随日志删除。备注按节点 ID、端口和协议关联，变更端口/协议不会继承旧备注；完全相同组合删除再建须人工核对。历史页显示当前备注，不代表历史人员归属。
- 已进入收件邮箱的邮件不由本服务器删除。外部备份或自行导出的文件需管理员另行管理。

## 验证与安全停用

```bash
sudo systemctl list-timers xray-audit-snapshot.timer xray-audit-logrotate.timer xray-audit-daily.timer
sudo systemctl status xray-audit-logrotate.service --no-pager
sudo journalctl -u xray-audit-logrotate.service --since today --no-pager
sudo python3 /opt/xray-audit/mail_report.py --recipient owner@example.com --check-config
```

只停止邮件：`sudo systemctl disable --now xray-audit-daily.timer`。不影响日志清理和网页汇总。

完全停止采集时，**先在 3x-ui 将 `log.access` 改回 `none` 并保存，确认日志不再写入**；然后停止网页汇总和邮件定时器。保留清理定时器直至旧数据过期清完，再停清理服务。不要在仍写日志时只停止轮转/清理。基础 QoS 卸载会保留独立审计任务与备注，不会静默改变此策略。

不要上传 `/etc/xray-audit/config.json`、日志、日报、缓存、备注数据库、真实部署备份或 SMTP 配置。本仓库只包含程序、测试和使用示例。

QoS 卸载会停用 PTR socket，但保留独立审计任务及 `/etc/xray-qos/daily-schedule.json` 中的发送时间。PTR 查询结果仅在网页进程内缓存最多 10 分钟、最多 512 项；每次查询仍重新核对目标属于保留期内的报告。
