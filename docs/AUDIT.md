# 可选网站连接审计

基础一键安装仅提供网速控制、节点备注和审计网页入口，不会自动开启访问日志、审计任务或邮件。附加组件要求管理员已明确告知使用者，且仅用于获授权的公司设备/节点管理。

## 能统计什么

- 经过本 VPS 并实际记入日志的目标域名或 IP、连接次数、首末记录时间、连接出现的小时。
- 各节点独立显示；新增节点会在下一次成功汇总时被发现，通常约 2 分钟。
- “疑似网站/服务”只按本地域名规则关联，表格可查看依据。不反查共享 IP，不向第三方发送访问记录。

连接记录不等于网页浏览次数、访问成功、前台 App 使用时间或员工工作时长。后台同步也会建立连接。不能读取 HTTPS 网页正文、微信/QQ/Telegram 聊天内容或视频内容，也不采集截图、键盘和客户端活动。旧汇总缺少字段时不会补造历史数据。

## 安装前提

当前附加组件支持 Debian/Ubuntu、systemd、原生 3x-ui SQLite 和 **Linux AMD64 Xray**，不是 ARM/Docker 通用安装器。

1. 先安装本项目 v1.1.0 或更新版本，确保节点备注可保存。
2. 在 3x-ui 的 Xray 配置中将 `log.access` 设置为 `/var/log/x-ui/access.log`，保留其他日志设置及已有的回环 `LoggerService`。通过面板保存配置可能重启 Xray，请选择合适时段。
3. 该日志必须实际存在，属主 root、权限 0600；如权限不符，管理员核对路径后执行 `sudo chmod 600 /var/log/x-ui/access.log`。安装器不会自动改变日志路径，也不会读取聊天正文。
4. 安装依赖：`sudo apt-get install -y logrotate tzdata`。
5. 如需日报，在 3x-ui 的 SMTP 设置填写自己的邮箱和授权码。只支持校验证书的隐式 TLS 或 STARTTLS；不要把授权码写进命令、Git 或 README。

把示例地址替换成自己的收件邮箱，明确启用附加组件：

```bash
curl -fsSL https://raw.githubusercontent.com/skylucao/3x-ui-qos-manager/v1.1.0/scripts/install-audit.sh \
  | sudo bash -s -- --acknowledge-notice --recipient owner@example.com
```

也可下载/克隆 v1.1.0 后运行：

```bash
sudo bash scripts/install-audit.sh --acknowledge-notice --recipient owner@example.com
```

这会安装根用户汇总/清理任务，并启用每两分钟网页汇总、每整点清理、每天北京时间 09:00 前一天的节点分组邮件。不会发送测试邮件或重启 Xray。SMTP 未配置时日报不能发出，不能把“已安装”理解为已确认邮件送达。

首次启用按安装时间标记部分覆盖，不把之前未知来源的日志视作完整员工历史。安装更新保留采集起始时间与其他现有配置，只更新显式传入的收件人及固定 7 天保留上限。应用恢复点只备份代码/配置，不复制访问记录；已过期清理的数据不会在回滚时恢复。

## 保留与备注

- 原始访问记录、服务器日报、网页日期汇总和日期发信回执，最多保留北京时间今天及前 6 天。今天加过去 6 天共 7 个自然日，不是完整滚动 168 小时。
- 网页接口立即拒绝过期日期；磁盘清理由每个整点（含午夜）及开机后的独立任务执行，不依赖 SMTP 成功。服务器停机、锁等待或日志重开失败可能延迟物理删除，恢复后继续；请关注任务失败状态。
- 原始日志最多 64 个轮转文件；每小时检查 64 MiB 轮转阈值，高流量时可能不足 7 天，不承诺日志完整。
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
