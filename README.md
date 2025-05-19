# Hysteria 2 & MTProto 安装与管理脚本 (hy)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

这是一个轻量级多功能 Bash 脚本，旨在简化在 **Debian 系 (Ubuntu 等)、RHEL 系 (Rocky, AlmaLinux, CentOS/RHEL 8/9, Fedora 等) 及 Alpine Linux** 系统上自动安装、配置和管理 [Hysteria 2](https://github.com/apernet/hysteria) 和 [MTProto 代理 (9seconds/mtg)](https://github.com/9seconds/mtg) 服务的过程。脚本提供了一个便捷的 `hy` 命令行工具来执行各种管理任务，支持交互式菜单和直接命令。

---

## ✨ 主要功能

- **广泛的系统兼容性**：自动检测并适配 Debian 系 (Ubuntu 等)、RHEL 系 (Rocky, AlmaLinux, CentOS/RHEL 8/9, Fedora 等) 及 Alpine Linux 系统。
- **多协议支持**：同时支持 **Hysteria 2** 和 **MTProto 代理**。
- **交互式菜单**：提供友好的交互式菜单，方便选择管理哪个服务。
- **依赖自动处理**：使用 `apt`, `dnf` 或 `apk` 自动安装所需依赖包。
- **灵活的 TLS 配置**：
  - 支持 **自定义证书**、**自签名证书** 和 **ACME (Let's Encrypt)** 自动申请。
- **自动生成配置文件**：分别位于 `/etc/hysteria/config.yaml` 和 `/etc/mtg/config.toml`。
- **自动下载最新程序**：安装或更新时，若本地版本非最新，则自动下载。
- **智能节点备注**：安装或查看信息时，可根据服务器IP地理位置自动生成节点备注 (例如: `美国Hysteria-US`)，方便识别。
- **服务管理集成**：支持 systemd (Debian/RHEL 系) 和 OpenRC (Alpine)，自动设置开机自启。
- **内置 `hy` 管理命令**：
  - 启动、停止、重启、查看状态
  - 设置/取消开机自启
  - 修改配置并自动显示新链接/二维码
  - 查看订阅链接、显示二维码、查看日志
  - 更新程序和 `hy` 脚本自身（带版本对比）
  - 卸载、显示版本

---

## 🚀 一键安装

使用以下命令自动安装：

## 使用 curl
```bash
curl -fsSL https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/Hysteria2.sh | sudo bash -s install
```
## 或使用 wget
```bash
wget -qO- https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/Hysteria2.sh | sudo bash -s install
```

---

## 🛠 常用命令（hy）

### 服务命令 (带交互式菜单)

```bash
sudo hy i  [hy|mtp]   # 安装或重装服务
sudo hy st [hy|mtp]   # 启动服务
sudo hy sp [hy|mtp]   # 停止服务
sudo hy re [hy|mtp]   # 重启服务
sudo hy s  [hy|mtp]   # 查看服务状态
sudo hy e  [hy|mtp]   # 设置开机自启
sudo hy d  [hy|mtp]   # 禁止开机自启
sudo hy n  [hy|mtp]   # 显示订阅链接和二维码
sudo hy l  [hy|mtp]   # 查看输出日志
sudo hy le [hy|mtp]   # 查看错误日志
```

### 配置命令 (带交互式菜单)

```bash
sudo hy ad [hy|mtp]   # 添加/更换服务配置
sudo hy de [hy|mtp]   # 删除服务配置
sudo hy co [hy|mtp]   # 显示服务配置摘要
sudo hy ce [hy|mtp]   # 手动编辑服务配置文件
sudo hy cc [hy|mtp]   # 交互修改服务配置 (Hysteria 2 特性)
sudo hy ly [hy|mtp]   # 查看 systemd 日志 (仅适用于 systemd 系统)
```

### 通用命令

```bash
sudo hy u            # 卸载 Hysteria 2, MTProto 及此管理脚本
sudo hy up           # 更新 Hysteria, MTG 程序和此管理脚本
sudo hy v            # 显示此脚本及已安装服务的版本
sudo hy h            # 显示帮助菜单
```

> **提示**: 所有命令后不加服务类型（hy 或 mtp）时，将显示交互式选择菜单

---

## 🔗 订阅链接格式

### Hysteria 2
```
hysteria2://<password>@<server_address>:<port>/?sni=<sni>&alpn=h3&insecure=<insecure>#Hysteria-<sni_value>
```

说明：
- `<server_address>`：服务器地址（IP 或域名）
- `<port>`：监听端口
- `<password>`：连接密码
- `<sni>`：TLS 握手用域名（通常是伪装域名）
- `<insecure>`：是否跳过证书验证（1 = 是，0 = 否）

> **注意**: 自签名证书或自定义证书时，请确保 `insecure=1`。ACME HTTP 验证需确保80端口可用并指向本机IP。

### MTProto
```
tg://proxy?server=<server_address>&port=<port>&secret=<secret>
```

---

## 📁 文件位置说明

### Hysteria 2
- 配置文件：`/etc/hysteria/config.yaml`
- 日志文件：
  - 输出日志：`/var/log/hysteria.log`
  - 错误日志：`/var/log/hysteria.error.log`
- 默认配置：
  - 端口：34567
  - 密码：随机 UUID
  - 伪装 URL：`https://www.bing.com`
  - 默认 SNI：`www.bing.com`

### MTProto
- 配置文件：`/etc/mtg/config.toml`
- 日志文件：
  - 输出日志：`/var/log/mtg.log`
  - 错误日志：`/var/log/mtg.error.log`
- 默认配置：
  - 端口：45678
  - 密钥：自动生成
  - 伪装域名：`cn.bing.com`

---

## ♻️ 更新方法

执行以下命令自动更新程序和脚本：

```bash
sudo hy up
```

---

## 🧹 卸载方法

执行以下命令自动卸载：

```bash
sudo hy u
```

卸载过程包括：
- 停止服务、删除配置文件
- 删除程序文件和服务
- 删除 hy 命令

---

## 🙋‍♂️ 贡献指南

如果您有任何改进建议或发现了 bug 欢迎提交 Issue 或 Pull Request 来完善脚本。项目地址：

👉 [GitHub 仓库](https://github.com/LeoJyenn/Hysteria2)

---

## 📄 许可证

本脚本采用 [MIT 许可证](https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/LICENSE) 开源。

---
