# 3x-ui QoS Manager

把每个 3x-ui 入站节点做成独立的可视化限速卡片，并直接嵌入 3x-ui 页面。新增或删除入站后，页面会自动同步，无需再次安装。

## 功能

- 每个本机入站分别设置上传、下载上限。
- 新节点自动显示，默认不限速。
- 最多同时限速 32 个节点；所有节点仍会显示。
- 保留 SSH、3x-ui 面板和订阅端口的管理带宽。
- 启用 Linux BBR 与 `fq`。
- 使用 3x-ui 登录状态，不需要第二套网页登录。
- QoS 后端和 3x-ui 上游只监听回环地址。
- 安装切换带 5 分钟 systemd 自动回滚。
- 重复安装保留首次安装前的监听信息，后续仍可安全卸载。
- 卸载切换同样带 5 分钟自动回滚，失败会恢复集成状态。
- 所有密钥均在目标机现场随机生成，不进入 Git。

## 支持范围

- Debian 12/13、Ubuntu 22.04/24.04。
- systemd、传统非容器版 [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui)。
- 3x-ui SQLite 数据库。PostgreSQL 和 Docker 版暂不支持。
- Nginx 必须带 `auth_request` 与 `sub_filter` 模块（发行版标准包已包含）。
- 如果面板已经位于自定义 Nginx、Caddy 或 CDN 后面，安装器会停止，避免覆盖未知反向代理。

## 一键安装

线路带宽无法从虚拟网卡可靠判断，必须填写 VPS 套餐的实际 Mbps。下面示例是总线路 250 Mbps、管理保留 50 Mbps：

```bash
curl -fsSL https://raw.githubusercontent.com/skylucao/3x-ui-qos-manager/v1.0.0/install.sh \
  | sudo bash -s -- --yes --link-mbps 250 --reserve-mbps 50
```

如果直接运行且不加 `--yes`，安装器会询问线路速度并展示变更计划：

```bash
curl -fsSL https://raw.githubusercontent.com/skylucao/3x-ui-qos-manager/v1.0.0/install.sh | sudo bash
```

3x-ui 尚未安装时，会调用经过 SHA-256 校验的官方 `v3.7.0` 安装器，并固定安装 `v3.7.0`；它会生成随机账号、密码和访问路径。官方凭据保存在目标机的 `/etc/x-ui/install-result.env`。

安装后，刷新 3x-ui，点击右下角的“网速管理”。

## 常用参数

```text
--link-mbps N       VPS 实际总带宽，非交互安装必须提供
--reserve-mbps N    SSH/面板等管理流量保留带宽
--wan IFACE         指定公网网卡，默认从唯一 IPv4 默认路由检测
--panel-host HOST   指定面板公网 IPv4 或域名
--extra-mgmt PORTS  额外保护端口，用逗号分隔
--no-bbr            不修改 BBR 设置
--dry-run           只检测并输出计划
--yes               非交互确认
```

示例：

```bash
sudo ./install.sh --dry-run --link-mbps 1000 --reserve-mbps 50
sudo ./install.sh --yes --link-mbps 1000 --reserve-mbps 50 --extra-mgmt 80,443
```

## 验证与卸载

```bash
sudo xui-qos-verify
sudo xui-qos-uninstall
```

安装与卸载备份位于 `/var/backups/xui-qos/`。卸载会停止限速并恢复 3x-ui 原来的监听方式；过程失败时会自动恢复当前集成状态。BBR 配置会保留，因为它也是独立的系统网络优化。

## 安全设计

- 浏览器不会得到 3x-ui API Token。
- 每个 `/qos-speed/` 请求都通过 Nginx `auth_request` 校验当前 3x-ui Cookie。
- Nginx 只在回环代理时添加两枚随机内部令牌。
- 写操作还需要精确的 Origin 和 CSRF Token。
- 3x-ui 公网端口保持不变，内部上游只监听 `127.0.0.1`。
- 仓库不应包含 `web.env`、`nodes.json`、证书、节点 UUID 或任何部署压缩包。

## 说明

本项目不创建代理节点，也不修改客户端订阅格式；Clash/Mihomo 能否使用取决于你在 3x-ui 中创建的协议。请遵守所在地法律及服务商条款。
