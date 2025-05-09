# Hysteria 2 安装与管理脚本 (hy)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

这是一个轻量级多功能 Bash 脚本，旨在简化在 **Debian、Ubuntu 和 Alpine Linux** 系统上自动安装、配置和管理 [Hysteria 2](https://github.com/apernet/hysteria) 服务的过程。脚本提供了一个便捷的 `hy` 命令行工具来执行各种管理任务。

---

## ✨ 主要功能

- **跨平台兼容**：自动检测并适配 Debian, Ubuntu, Alpine Linux 系统。
- **依赖自动处理**：使用 `apt` 或 `apk` 自动安装所需依赖包。
- **灵活的 TLS 配置**：
  - 支持 **自定义证书**、**自签名证书** 和 **ACME (Let's Encrypt)** 自动申请。
- **自动生成配置文件**：位于 `/etc/hysteria/config.yaml`。
- **自动下载最新 Hysteria 2 程序**。
- **服务管理集成**：支持 systemd (Debian/Ubuntu) 和 OpenRC (Alpine)，自动设置开机自启。
- **内置 hy 管理命令**：
  - 启动、停止、重启、查看状态
  - 设置/取消开机自启
  - 修改配置、查看订阅链接、显示二维码、查看日志
  - 更新程序和脚本、卸载、显示版本

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

```bash
sudo hy help           # 显示帮助菜单（所有可用命令）
sudo hy start          # 启动服务
sudo hy stop           # 停止服务
sudo hy restart        # 重启服务
sudo hy status         # 查看服务状态
sudo hy enable         # 设置开机启动
sudo hy disable        # 禁用开机启动
sudo hy info           # 显示节点订阅
sudo hy config         # 显示配置摘要
sudo hy config_edit    # 编辑配置文件
sudo hy config_change  # 交互修改端口、密码、伪装 URL
sudo hy logs           # 查看输出日志
sudo hy logs_err       # 查看错误日志
sudo hy logs_sys       # 查看 systemd 日志（仅限 systemd 系统）
sudo hy update         # 一键更新程序和脚本
sudo hy version        # 显示当前版本
sudo hy uninstall      # 卸载 Hysteria 2 和 hy
```

---

## 🔗 订阅链接格式

```txt
hysteria2://<password>@<server_address>:<port>/?sni=<sni>&alpn=h3&insecure=<insecure>#Hysteria-<sni_value>
```

说明：

- `<server_address>`：服务器地址（IP 或域名）
- `<port>`：监听端口
- `<password>`：连接密码
- `<sni>`：TLS 握手用域名（通常是伪装域名）
- `<insecure>`：是否跳过证书验证（1 = 是，0 = 否）

> 自签名证书或自定义证书时，请确保 `insecure=1`  ACME HTTP 验证确保80端口可用并指向本机ip

---

## 📁 文件位置说明

- 配置文件：`/etc/hysteria/config.yaml`
- 日志文件：
  - 输出日志：`/var/log/hysteria.log`
  - 错误日志：`/var/log/hysteria.error.log`

默认配置：
- 端口：34567
- 密码：随机 UUID
- 伪装 URL：`https://www.bing.com`
- 默认 SNI：`www.bing.com`

---

## ♻️ 更新方法

执行以下命令自动更新程序和脚本：

```bash
sudo hy update
```

---

## 🧹 卸载方法

执行以下命令自动卸载：

```bash
sudo hy uninstall
```

- 停止服务、删除配置文件
- 可选是否移除 hy 命令和 qrencode

---

## 🙋‍♂️ 贡献指南

如果您有任何改进建议或发现了 bug 欢迎提交 Issue 或 Pull Request 来完善脚本。项目地址：

👉 [GitHub 仓库](https://github.com/LeoJyenn/Hysteria2)

---

## 📄 许可证

本脚本采用 [MIT 许可证](https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/LICENSE) 开源。

---
