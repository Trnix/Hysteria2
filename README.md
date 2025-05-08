# Hysteria 2 安装与管理脚本 (hy)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

这是一个多功能 Bash 脚本，旨在简化在 **Debian、Ubuntu 和 Alpine Linux** 系统上自动安装、配置和管理 [Hysteria 2](https://github.com/apernet/hysteria) 服务的过程。脚本提供了一个便捷的 `hy` 命令行工具来执行各种管理任务。

## 主要功能

* **跨平台兼容**：自动检测并适配 Debian, Ubuntu, Alpine Linux 系统。
* **依赖自动处理**：根据检测到的系统，使用 `apt` 或 `apk` 自动安装所需依赖包。
* **灵活的 TLS 配置**：
    * 支持**自定义证书** (可提供现有证书，或自动生成自签名证书)。
    * 支持 **ACME (Let's Encrypt)** 自动证书申请 (需要域名指向服务器 IP)。
* **自动化配置**：自动生成 Hysteria 2 配置文件 (`/etc/hysteria/config.yaml`)。
* **自动下载**：获取最新的 Hysteria 2 官方二进制文件。
* **服务管理集成**：自动配置 **systemd** (Debian/Ubuntu) 或 **OpenRC** (Alpine) 服务，并实现开机自启。
* **便捷的管理命令**：安装后提供全局 `hy` 命令，用于服务的全生命周期管理。
* **丰富的功能集**：
    * 启动 (`start`), 停止 (`stop`), 重启 (`restart`), 查看状态 (`status`)。
    * 设置 (`enable`), 取消 (`disable`) 开机自启。
    * 查看配置 (`config`), 手动编辑 (`config_edit`), 交互式修改部分配置 (`config_change` - 端口/密码/伪装URL)。
    * 显示当前订阅链接 (`info`)。
    * 显示订阅链接二维码 (`qrcode` - 需安装 `qrencode`)。
    * 查看日志 (`logs`, `logs_err`, `logs_sys` - 后者仅 systemd)。
    * 一键更新 Hysteria 程序及 `hy` 脚本自身 (`update`)。
    * 一键卸载 (`uninstall` - 清理 Hysteria 相关文件，并可选移除 `hy` 命令和 `qrencode`)。
    * 查看版本信息 (`version`)。
* **用户友好**：提供清晰的安装向导和管理菜单 (`hy help`)。

## 一键安装

使用以下命令下载并执行脚本，完成 Hysteria 2 的首次安装和 `hy` 管理命令的设置：

**重要提示**：请将下面的 URL 替换为您脚本在 GitHub 上的**实际 Raw 链接**！

**使用 curl:**
```bash
curl -fsSL [https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/Hysteria2.sh](https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/Hysteria2.sh) | sudo bash -s install
