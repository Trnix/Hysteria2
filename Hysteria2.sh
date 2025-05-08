#!/bin/bash

# --- Script Setup ---
SCRIPT_COMMAND_NAME="hy" # The command name to be installed in PATH
SCRIPT_FILE_BASENAME="Hysteria2.sh" # The typical filename of this script
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2025-05-08" # 当前日期

HY_SCRIPT_URL_ON_GITHUB="https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPONAME/YOUR_BRANCH/${SCRIPT_FILE_BASENAME}"

HYSTERIA_INSTALL_PATH="/usr/local/bin/hysteria"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
HYSTERIA_CONFIG_FILE="${HYSTERIA_CONFIG_DIR}/config.yaml"
HYSTERIA_CERTS_DIR="${HYSTERIA_CONFIG_DIR}/certs"
HYSTERIA_SERVICE_NAME_SYSTEMD="hysteria.service"
HYSTERIA_SERVICE_NAME_OPENRC="hysteria"
LOG_FILE_OUT="/var/log/hysteria.log"
LOG_FILE_ERR="/var/log/hysteria.error.log"

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Global OS Detection Variables ---
DISTRO_FAMILY=""
PKG_INSTALL_CMD=""
PKG_UPDATE_CMD=""
INIT_SYSTEM=""
SERVICE_CMD=""
ENABLE_CMD_PREFIX=""
ENABLE_CMD_SUFFIX=""
SETCAP_DEPENDENCY_PKG=""
REQUIRED_PKGS_OS_SPECIFIC=""
CURRENT_HYSTERIA_SERVICE_NAME=""

# --- Utility Functions ---
_log_error() { echo -e "${RED}错误: $1${NC}" >&2; }
_log_success() { echo -e "${GREEN}$1${NC}" >&2; }
_log_warning() { echo -e "${YELLOW}警告: $1${NC}" >&2; }
_log_info() { echo -e "${BLUE}信息: $1${NC}" >&2; }

_ensure_root() {
    if [ "$(id -u)" -ne 0 ]; then
        _log_error "此操作需要 root 权限。请使用 sudo 运行。"
        exit 1
    fi
}

_detect_os() {
    if [ -n "$DISTRO_FAMILY" ]; then return 0; fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "alpine" ]]; then
            DISTRO_FAMILY="alpine"
        elif [[ "$ID" == "debian" || "$ID" == "ubuntu" || "$ID_LIKE" == "debian" || "$ID_LIKE" == "ubuntu" ]]; then
            DISTRO_FAMILY="debian"
        else
            _log_error "不支持的发行版 '$ID'. 此脚本主要支持 Debian, Ubuntu, 和 Alpine."
            exit 1
        fi
    elif command -v apk >/dev/null 2>&1; then DISTRO_FAMILY="alpine";
    elif command -v apt-get >/dev/null 2>&1; then DISTRO_FAMILY="debian";
    else
        _log_error "无法确定发行版类型 (Debian/Ubuntu 或 Alpine)."
        exit 1
    fi

    if [[ "$DISTRO_FAMILY" == "alpine" ]]; then
        PKG_INSTALL_CMD="apk add --no-cache"
        PKG_UPDATE_CMD="apk update"
        INIT_SYSTEM="openrc"
        SERVICE_CMD="service"
        ENABLE_CMD_PREFIX="rc-update add"
        ENABLE_CMD_SUFFIX="default"
        SETCAP_DEPENDENCY_PKG="libcap"
        REQUIRED_PKGS_OS_SPECIFIC="openrc"
        CURRENT_HYSTERIA_SERVICE_NAME="$HYSTERIA_SERVICE_NAME_OPENRC"
    elif [[ "$DISTRO_FAMILY" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        PKG_INSTALL_CMD="apt-get install -y -q"
        PKG_UPDATE_CMD="apt-get update -q"
        INIT_SYSTEM="systemd"
        SERVICE_CMD="systemctl"
        ENABLE_CMD_PREFIX="systemctl enable"
        ENABLE_CMD_SUFFIX=""
        SETCAP_DEPENDENCY_PKG="libcap2-bin"
        REQUIRED_PKGS_OS_SPECIFIC=""
        CURRENT_HYSTERIA_SERVICE_NAME="$HYSTERIA_SERVICE_NAME_SYSTEMD"
    fi
}

_is_hysteria_installed() {
    _detect_os
    if [ -f "$HYSTERIA_INSTALL_PATH" ] && [ -f "$HYSTERIA_CONFIG_FILE" ]; then
        if [ "$INIT_SYSTEM" == "systemd" ] && [ -f "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME" ]; then
            return 0
        elif [ "$INIT_SYSTEM" == "openrc" ] && [ -f "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME" ]; then
            return 0
        fi
    fi
    return 1
}

_install_dependencies() {
    _log_info "正在更新软件包列表 (${DISTRO_FAMILY})..."
    if ! $PKG_UPDATE_CMD >/dev/null; then
        _log_warning "更新软件包列表失败，尝试继续..."
    fi

    REQUIRED_PKGS_COMMON="wget curl git openssl lsof coreutils realpath"
    REQUIRED_PKGS="$REQUIRED_PKGS_COMMON"
    if [ -n "$REQUIRED_PKGS_OS_SPECIFIC" ]; then
        REQUIRED_PKGS="$REQUIRED_PKGS $REQUIRED_PKGS_OS_SPECIFIC"
    fi

    for pkg in $REQUIRED_PKGS; do
        installed=false
        if [[ "$DISTRO_FAMILY" == "alpine" ]]; then
            if apk info -e "$pkg" &>/dev/null; then installed=true; fi
        elif [[ "$DISTRO_FAMILY" == "debian" ]]; then
            if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then installed=true; fi
        fi

        if $installed; then
            _log_info "$pkg 已安装。"
        else
            _log_info "正在安装 $pkg..."
            if ! $PKG_INSTALL_CMD "$pkg" > /dev/null; then
                _log_error "安装 $pkg 失败。请手动安装后重试。"
                exit 1
            fi
        fi
    done
    _log_success "依赖包安装成功。"
}

_generate_uuid() {
    local bytes=$(od -x -N 16 /dev/urandom | head -1 | awk '{OFS=""; $1=""; print}')
    local byte7=${bytes:12:4}; byte7=$((0x${byte7} & 0x0fff | 0x4000)); byte7=$(printf "%04x" $byte7)
    local byte9=${bytes:20:4}; byte9=$((0x${byte9} & 0x3fff | 0x8000)); byte9=$(printf "%04x" $byte9)
    echo "${bytes:0:8}-${bytes:8:4}-${byte7}-${byte9}-${bytes:24:12}" | tr '[:upper:]' '[:lower:]'
}

_generate_random_lowercase_string() {
    LC_ALL=C tr -dc 'a-z' < /dev/urandom | head -c 8
}

_get_server_address() {
    local ipv6_ip; local ipv4_ip
    _log_info "正在检测服务器公网 IP 地址..."
    _log_info "尝试获取 IPv6 地址..."
    ipv6_ip=$(curl -s -m 5 -6 https://ifconfig.me || curl -s -m 5 -6 https://ip.sb || curl -s -m 5 -6 https://api64.ipify.org)
    if [ -n "$ipv6_ip" ] && [[ "$ipv6_ip" == *":"* ]]; then _log_success "检测到 IPv6 地址: $ipv6_ip (将优先使用)"; echo "[$ipv6_ip]"; return; else _log_warning "未检测到 IPv6 地址或获取失败。"; fi
    _log_info "尝试获取 IPv4 地址..."
    ipv4_ip=$(curl -s -m 5 -4 https://ifconfig.me || curl -s -m 5 -4 https://ip.sb || curl -s -m 5 -4 https://api.ipify.org)
    if [ -n "$ipv4_ip" ] && [[ "$ipv4_ip" != *":"* ]]; then _log_success "检测到 IPv4 地址: $ipv4_ip"; echo "$ipv4_ip"; return; else _log_warning "未检测到 IPv4 地址或获取失败。"; fi
    _log_error "无法获取服务器公网 IP 地址 (IPv4 或 IPv6)。请检查网络连接。"; exit 1
}

_setup_hy_command() {
    _ensure_root
    _log_info "正在设置 '${SCRIPT_COMMAND_NAME}' 管理命令到 /usr/local/bin/${SCRIPT_COMMAND_NAME}..."
    
    if [[ "$HY_SCRIPT_URL_ON_GITHUB" == *"YOUR_USERNAME"* ]]; then
        _log_error "脚本中的 HY_SCRIPT_URL_ON_GITHUB 未配置! 无法自动安装/更新 '${SCRIPT_COMMAND_NAME}' 命令。"
        _log_warning "请编辑此脚本(${0})，将 HY_SCRIPT_URL_ON_GITHUB 变量替换为实际的 GitHub Raw URL。"
        _log_warning "您可以手动复制此脚本: sudo cp \"${0:-${SCRIPT_FILE_BASENAME}}\" /usr/local/bin/${SCRIPT_COMMAND_NAME} && sudo chmod +x /usr/local/bin/${SCRIPT_COMMAND_NAME}"
        return 1
    fi

    _log_info "从 URL ($HY_SCRIPT_URL_ON_GITHUB) 下载最新版管理脚本..."
    # Create a temporary file for download
    TMP_SCRIPT_DOWNLOAD_PATH=$(mktemp)
    if wget -qO "$TMP_SCRIPT_DOWNLOAD_PATH" "$HY_SCRIPT_URL_ON_GITHUB"; then
        # Verify if download is a shell script (basic check)
        if head -n 1 "$TMP_SCRIPT_DOWNLOAD_PATH" | grep -q -E "^#!/(usr/)?bin/(bash|sh)"; then
            if mv "$TMP_SCRIPT_DOWNLOAD_PATH" "/usr/local/bin/${SCRIPT_COMMAND_NAME}"; then
                chmod +x "/usr/local/bin/${SCRIPT_COMMAND_NAME}"
                _log_success "'${SCRIPT_COMMAND_NAME}' 命令已从 URL 安装/更新到 /usr/local/bin/${SCRIPT_COMMAND_NAME}"
                _log_info "您现在应该可以在任何地方使用 'sudo ${SCRIPT_COMMAND_NAME} <action>' 来管理 Hysteria。"
            else
                _log_error "移动下载的脚本到 /usr/local/bin/${SCRIPT_COMMAND_NAME} 失败。权限问题？"
                rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"
            fi
        else
            _log_error "从 URL 下载的文件似乎不是一个有效的 shell 脚本。请检查 URL: $HY_SCRIPT_URL_ON_GITHUB"
            _log_warning "下载的内容开头: $(head -n 1 "$TMP_SCRIPT_DOWNLOAD_PATH")"
            rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"
        fi
    else
        _log_error "从 URL 下载脚本到临时文件失败。"
        _log_warning "您可以手动下载此脚本 (${SCRIPT_FILE_BASENAME}) 并将其复制到您的 PATH 中并命名为 '${SCRIPT_COMMAND_NAME}'。"
        rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"
    fi
}


_do_install() {
    _ensure_root
    _detect_os

    if _is_hysteria_installed; then
        _log_warning "Hysteria 似乎已安装。如果您想重新安装或更改配置，请考虑使用 '${SCRIPT_COMMAND_NAME} uninstall' 或 '${SCRIPT_COMMAND_NAME} config_change'。"
        read -p "是否继续强制安装 (可能覆盖现有配置)? [y/N]: " confirm_install
        if [[ "$confirm_install" != "y" && "$confirm_install" != "Y" ]]; then
            _log_info "安装取消。"
            exit 0
        fi
        _log_warning "正在执行强制安装..."
    fi

    _install_dependencies

    DEFAULT_MASQUERADE_URL="https://www.bing.com"
    DEFAULT_PORT="34567"
    DEFAULT_ACME_EMAIL="$(_generate_random_lowercase_string)@gmail.com"

    echo ""; _log_info "请选择 TLS 验证方式:"
    echo "1. 自定义证书 (适用于已有证书或 NAT VPS 生成自签名证书)"
    echo "2. ACME HTTP 验证 (需要域名指向本机IP，且本机80端口可被 Hysteria 使用)"
    read -p "请选择 [1-2, 默认 1]: " TLS_TYPE; TLS_TYPE=${TLS_TYPE:-1}

    CERT_PATH=""; KEY_PATH=""; DOMAIN=""; SNI_VALUE=""; ACME_EMAIL=""

    case $TLS_TYPE in
        1)
            _log_info "--- 自定义证书模式 ---"
            read -p "请输入证书 (.crt 或 .pem) 文件绝对路径 (留空则生成自签名证书): " USER_CERT_PATH
            if [ -z "$USER_CERT_PATH" ]; then
                if ! command -v openssl &> /dev/null; then _log_error "openssl 未安装，请手动运行 '$PKG_INSTALL_CMD openssl' 后重试"; exit 1; fi
                read -p "请输入用于自签名证书的伪装域名/SNI (默认 www.bing.com): " SELF_SIGN_SNI; SELF_SIGN_SNI=${SELF_SIGN_SNI:-"www.bing.com"}
                SNI_VALUE="$SELF_SIGN_SNI"
                mkdir -p "$HYSTERIA_CERTS_DIR"
                CERT_PATH="$HYSTERIA_CERTS_DIR/server.crt"
                KEY_PATH="$HYSTERIA_CERTS_DIR/server.key"
                _log_info "正在生成自签名证书 (CN=$SNI_VALUE)..."
                if ! openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                    -keyout "$KEY_PATH" -out "$CERT_PATH" \
                    -subj "/CN=$SNI_VALUE" -days 36500; then
                    _log_error "自签名证书生成失败，请检查 openssl 配置！"
                    exit 1
                fi
                _log_success "自签名证书已生成: $CERT_PATH, $KEY_PATH"
            else
                read -p "请输入私钥 (.key 或 .pem) 文件绝对路径: " USER_KEY_PATH
                if [ -z "$USER_CERT_PATH" ] || [ -z "$USER_KEY_PATH" ]; then _log_error "证书和私钥路径都不能为空。"; exit 1; fi
                if ! CERT_PATH=$(realpath "$USER_CERT_PATH" 2>/dev/null); then _log_error "证书路径 '$USER_CERT_PATH' 无效。"; exit 1; fi
                if ! KEY_PATH=$(realpath "$USER_KEY_PATH" 2>/dev/null); then _log_error "私钥路径 '$USER_KEY_PATH' 无效。"; exit 1; fi
                if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then _log_error "提供的证书或私钥文件路径无效或文件不存在。"; exit 1; fi
                SNI_VALUE=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2 | tr -d ' ' | head -n 1)
                if [ -z "$SNI_VALUE" ]; then SNI_VALUE=$(openssl x509 -noout -text -in "$CERT_PATH" 2>/dev/null | grep 'DNS:' | sed 's/DNS://g' | tr -d ' ' | cut -d, -f1 | head -n 1); fi
                if [ -z "$SNI_VALUE" ]; then read -p "无法从证书自动提取CN或SAN作为SNI，请输入您希望使用的SNI: " MANUAL_SNI; if [ -z "$MANUAL_SNI" ]; then _log_error "SNI 不能为空！"; exit 1; fi; SNI_VALUE="$MANUAL_SNI"; else _log_info "从证书中提取到的 SNI (CN/SAN): $SNI_VALUE"; fi
            fi;;
        2)
            _log_info "--- ACME HTTP 验证模式 ---"
            read -p "请输入您的域名 (例如: example.com): " DOMAIN; if [ -z "$DOMAIN" ]; then _log_error "域名不能为空！"; exit 1; fi
            read -p "请输入用于 ACME 证书申请的邮箱 (默认 $DEFAULT_ACME_EMAIL): " INPUT_ACME_EMAIL; ACME_EMAIL=${INPUT_ACME_EMAIL:-$DEFAULT_ACME_EMAIL}
            if [ -z "$ACME_EMAIL" ]; then _log_error "邮箱不能为空！"; exit 1; fi; SNI_VALUE=$DOMAIN
            _log_info "检查 80 端口占用情况..."
            if lsof -i:80 -sTCP:LISTEN -P -n &>/dev/null; then _log_warning "检测到 80 端口已被占用。Hysteria 将尝试使用此端口进行 ACME 验证。"; PID_80=$(lsof -t -i:80 -sTCP:LISTEN); [ -n "$PID_80" ] && _log_info "占用80端口的进程 PID(s): $PID_80"; else _log_info "80 端口未被占用，可用于 ACME HTTP 验证。"; fi;;
        *) _log_error "无效TLS选项，退出脚本。"; exit 1;;
    esac

    read -p "请输入 Hysteria 监听端口 (默认 $DEFAULT_PORT): " PORT; PORT=${PORT:-$DEFAULT_PORT}
    read -p "请输入 Hysteria 密码 (回车则使用随机UUID): " PASSWORD_INPUT; if [ -z "$PASSWORD_INPUT" ]; then PASSWORD=$(_generate_uuid); _log_info "使用随机密码: $PASSWORD"; else PASSWORD="$PASSWORD_INPUT"; fi
    read -p "请输入伪装访问的目标URL (默认 $DEFAULT_MASQUERADE_URL): " MASQUERADE_URL; MASQUERADE_URL=${MASQUERADE_URL:-$DEFAULT_MASQUERADE_URL}
    
    SERVER_PUBLIC_ADDRESS=$(_get_server_address)
    mkdir -p "$HYSTERIA_CONFIG_DIR"

    _log_info "正在下载 Hysteria 最新版..."
    ARCH=$(uname -m); case ${ARCH} in x86_64) HYSTERIA_ARCH="amd64";; aarch64) HYSTERIA_ARCH="arm64";; armv7l) HYSTERIA_ARCH="arm";; *) _log_error "不支持的系统架构: ${ARCH}"; exit 1;; esac
    if ! wget -qO "$HYSTERIA_INSTALL_PATH" "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${HYSTERIA_ARCH}"; then
        _log_warning "从 GitHub Releases 下载失败，尝试旧的下载地址 download.hysteria.network ..."
        if ! wget -qO "$HYSTERIA_INSTALL_PATH" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"; then _log_error "下载 Hysteria 失败!"; exit 1; fi
    fi
    chmod +x "$HYSTERIA_INSTALL_PATH"; _log_success "Hysteria 下载并设置权限完成: $HYSTERIA_INSTALL_PATH"

    if [ "$TLS_TYPE" -eq 2 ]; then
        _log_info "为 Hysteria 二进制文件设置 cap_net_bind_service 权限 (用于 ACME)..."
        if ! command -v setcap &>/dev/null; then
            _log_warning "setcap 命令未找到，尝试安装 $SETCAP_DEPENDENCY_PKG..."
            if ! $PKG_INSTALL_CMD "$SETCAP_DEPENDENCY_PKG" >/dev/null; then _log_error "安装 $SETCAP_DEPENDENCY_PKG 失败。"; else _log_success "$SETCAP_DEPENDENCY_PKG 安装成功。"; fi
        fi
        if command -v setcap &>/dev/null; then if ! setcap 'cap_net_bind_service=+ep' "$HYSTERIA_INSTALL_PATH"; then _log_error "setcap 'cap_net_bind_service=+ep' $HYSTERIA_INSTALL_PATH 失败。"; else _log_success "setcap 成功。"; fi
        else _log_error "setcap 命令在尝试安装后仍然不可用。"; fi
    fi

    _log_info "正在生成配置文件 $HYSTERIA_CONFIG_FILE..."
    cat > "$HYSTERIA_CONFIG_FILE" << EOF
listen: :$PORT
auth:
  type: password
  password: $PASSWORD
masquerade:
  type: proxy
  proxy:
    url: $MASQUERADE_URL
    rewriteHost: true
EOF
    LINK_INSECURE=0
    case $TLS_TYPE in 1) cat >> "$HYSTERIA_CONFIG_FILE" << EOF
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
           LINK_SNI="$SNI_VALUE"; LINK_ADDRESS="$SERVER_PUBLIC_ADDRESS"; LINK_INSECURE=1; _log_warning "自定义证书通常需要客户端设置 'insecure: true'";;
        2) cat >> "$HYSTERIA_CONFIG_FILE" << EOF
acme:
  domains:
    - $DOMAIN
  email: $ACME_EMAIL
EOF
           LINK_SNI="$DOMAIN"; LINK_ADDRESS="$DOMAIN"; LINK_INSECURE=0;;
    esac; _log_success "配置文件生成完毕。"

    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _log_info "正在创建 systemd 服务文件 /etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME..."
        cat > "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME" << EOF
[Unit]
Description=Hysteria 2 Service by $SCRIPT_COMMAND_NAME
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$HYSTERIA_INSTALL_PATH server --config $HYSTERIA_CONFIG_FILE
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_FILE_OUT
StandardError=append:$LOG_FILE_ERR
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME"; $SERVICE_CMD daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        _log_info "正在创建 OpenRC 服务文件 /etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME..."
        cat > "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME" << EOF
#!/sbin/openrc-run
name="$HYSTERIA_SERVICE_NAME_OPENRC"
command="$HYSTERIA_INSTALL_PATH"
command_args="server --config $HYSTERIA_CONFIG_FILE"
pidfile="/var/run/\${name}.pid"
command_background="yes"
output_log="$LOG_FILE_OUT"
error_log="$LOG_FILE_ERR"

depend() { need net; after firewall; }
start_pre() { checkpath -f \$output_log -m 0644 \$RC_SVCNAME; checkpath -f \$error_log -m 0644 \$RC_SVCNAME; }
start() { ebegin "Starting \$name"; start-stop-daemon --start --quiet --background --make-pidfile --pidfile \$pidfile --stdout \$output_log --stderr \$error_log --exec \$command -- \$command_args; eend \$?; }
stop() { ebegin "Stopping \$name"; start-stop-daemon --stop --quiet --pidfile \$pidfile; eend \$?; }
EOF
        chmod +x "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME"
    fi; _log_success "服务文件创建成功。"

    _control_service "enable"
    _control_service "restart"

    sleep 2
    if _control_service "status" > /dev/null; then _log_success "Hysteria 服务已成功启动并运行！"; else _log_error "Hysteria 服务启动后状态异常。请使用 '${SCRIPT_COMMAND_NAME} status' 和 '${SCRIPT_COMMAND_NAME} logs' 查看详情。"; fi

    # Install/Update the 'hy' command itself
    _setup_hy_command

    SUBSCRIPTION_LINK="hysteria2://${PASSWORD}@${LINK_ADDRESS}:${PORT}/?sni=${LINK_SNI}&alpn=h3&insecure=${LINK_INSECURE}#Hysteria-${SNI_VALUE}"
    echo ""; echo "------------------------------------------------------------------------"
    _log_success "Hysteria 2 安装和配置完成！"
    echo "------------------------------------------------------------------------"
    echo "服务器地址: $LINK_ADDRESS"; echo "端口: $PORT"; echo "密码: $PASSWORD"; echo "SNI: $LINK_SNI"
    echo "伪装目标站点: $MASQUERADE_URL"; echo "TLS 模式: $TLS_TYPE (1:Custom, 2:ACME)"
    if [ "$TLS_TYPE" -eq 1 ]; then echo "证书路径: $CERT_PATH; 私钥路径: $KEY_PATH"; elif [ "$TLS_TYPE" -eq 2 ]; then echo "ACME 邮箱: $ACME_EMAIL"; fi
    echo "客户端 insecure (0=false, 1=true): $LINK_INSECURE"
    echo "------------------------------------------------------------------------"
    echo -e "${YELLOW}订阅链接 (Hysteria V2):${NC}"; echo "$SUBSCRIPTION_LINK"
    echo "------------------------------------------------------------------------"
    if command -v qrencode &> /dev/null; then echo -e "${YELLOW}订阅链接二维码:${NC}"; qrencode -t ANSIUTF8 "$SUBSCRIPTION_LINK"; else _log_warning "提示: 安装 'qrencode' ($PKG_INSTALL_CMD qrencode) 后可显示二维码。"; fi
    echo "------------------------------------------------------------------------"
    _show_management_commands_hint
}

_do_uninstall() {
    _ensure_root
    _detect_os
    if ! _is_hysteria_installed; then
        _log_warning "Hysteria 似乎未安装或未被此脚本正确管理。"
        read -p "是否仍然尝试执行标准卸载步骤? [y/N]: " confirm_force_uninstall
        if [[ "$confirm_force_uninstall" != "y" && "$confirm_force_uninstall" != "Y" ]]; then _log_info "卸载取消。"; exit 0; fi
    fi

    _log_warning "这将卸载 Hysteria 2 并删除所有相关配置和文件。"
    read -p "确定要卸载吗? [y/N]: " confirm_uninstall
    if [[ "$confirm_uninstall" != "y" && "$confirm_uninstall" != "Y" ]]; then _log_info "卸载取消。"; exit 0; fi

    _log_info "正在停止 Hysteria 服务..."; _control_service "stop" >/dev/null 2>&1

    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        _log_info "正在禁用 Hysteria systemd 服务..."; $SERVICE_CMD disable "$CURRENT_HYSTERIA_SERVICE_NAME" >/dev/null 2>&1
        _log_info "正在移除 Hysteria systemd 服务文件..."; rm -f "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME"; find /etc/systemd/system/ -name "$CURRENT_HYSTERIA_SERVICE_NAME" -delete
        $SERVICE_CMD daemon-reload; $SERVICE_CMD reset-failed "$CURRENT_HYSTERIA_SERVICE_NAME" >/dev/null 2>&1 || true
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        _log_info "正在移除 Hysteria OpenRC 服务..."; rc-update del "$CURRENT_HYSTERIA_SERVICE_NAME" default >/dev/null 2>&1
        _log_info "正在移除 Hysteria OpenRC 初始化脚本..."; rm -f "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME"
    fi

    _log_info "正在移除 Hysteria 二进制文件: $HYSTERIA_INSTALL_PATH"; rm -f "$HYSTERIA_INSTALL_PATH"
    _log_info "正在移除 Hysteria 配置目录: $HYSTERIA_CONFIG_DIR"; rm -rf "$HYSTERIA_CONFIG_DIR"
    _log_info "正在移除 Hysteria 日志文件: $LOG_FILE_OUT, $LOG_FILE_ERR"; rm -f "$LOG_FILE_OUT" "$LOG_FILE_ERR"

    if [ -f "/usr/local/bin/$SCRIPT_COMMAND_NAME" ]; then
        read -p "管理命令 '$SCRIPT_COMMAND_NAME' (/usr/local/bin/$SCRIPT_COMMAND_NAME) 也被检测到。是否一并移除? [y/N]: " confirm_remove_hy
        if [[ "$confirm_remove_hy" == "y" || "$confirm_remove_hy" == "Y" ]]; then
            _log_info "正在移除 /usr/local/bin/$SCRIPT_COMMAND_NAME ..."
            if rm -f "/usr/local/bin/$SCRIPT_COMMAND_NAME"; then _log_success "/usr/local/bin/$SCRIPT_COMMAND_NAME 已移除。"; else _log_error "移除 /usr/local/bin/$SCRIPT_COMMAND_NAME 失败。"; fi
        else _log_info "保留 /usr/local/bin/$SCRIPT_COMMAND_NAME。"; fi
    fi
    _log_success "Hysteria 卸载完成。"
}

_control_service() {
    _detect_os; local action="$1"
    if [[ "$action" == "start" || "$action" == "stop" || "$action" == "restart" || "$action" == "status" ]]; then
        if ! _is_hysteria_installed; then _log_error "Hysteria 未安装或服务未正确配置。请使用 '${SCRIPT_COMMAND_NAME} install' 安装。"; return 1; fi
    fi
    case "$action" in
        start|stop|restart) _ensure_root; _log_info "正在执行: $SERVICE_CMD $action $CURRENT_HYSTERIA_SERVICE_NAME"
            if [[ "$INIT_SYSTEM" == "systemd" && "$action" == "stop" ]] && ! $SERVICE_CMD is-active --quiet "$CURRENT_HYSTERIA_SERVICE_NAME"; then _log_info "服务 ($CURRENT_HYSTERIA_SERVICE_NAME) 已停止。"; return 0; fi
            if $SERVICE_CMD "$action" "$CURRENT_HYSTERIA_SERVICE_NAME"; then _log_success "操作 '$action' 成功。"
                if [[ "$action" == "start" || "$action" == "restart" ]]; then sleep 1; $SERVICE_CMD status "$CURRENT_HYSTERIA_SERVICE_NAME" | head -n 5; fi
            else _log_error "操作 '$action' 失败。"; _log_warning "请检查日志:"; echo "  输出日志: tail -n 30 $LOG_FILE_OUT"; echo "  错误日志: tail -n 30 $LOG_FILE_ERR"
                if [ "$INIT_SYSTEM" == "systemd" ]; then echo "  Systemd状态: $SERVICE_CMD status $CURRENT_HYSTERIA_SERVICE_NAME"; echo "  Systemd日志: journalctl -u $CURRENT_HYSTERIA_SERVICE_NAME -n 20 --no-pager"; fi
                return 1; fi;;
        status) _log_info "Hysteria 服务状态 ($CURRENT_HYSTERIA_SERVICE_NAME):"; $SERVICE_CMD "$action" "$CURRENT_HYSTERIA_SERVICE_NAME"; return $?;;
        enable) _ensure_root; _log_info "正在启用 Hysteria 服务开机自启..."
            if $ENABLE_CMD_PREFIX "$CURRENT_HYSTERIA_SERVICE_NAME" $ENABLE_CMD_SUFFIX >/dev/null 2>&1; then _log_success "Hysteria 服务已启用开机自启。"; else _log_error "启用 Hysteria 服务开机自启失败。"; return 1; fi;;
        disable) _ensure_root; _log_info "正在禁用 Hysteria 服务开机自启..."
            if [[ "$INIT_SYSTEM" == "systemd" ]]; then $SERVICE_CMD disable "$CURRENT_HYSTERIA_SERVICE_NAME" >/dev/null 2>&1; elif [[ "$INIT_SYSTEM" == "openrc" ]]; then rc-update del "$CURRENT_HYSTERIA_SERVICE_NAME" default >/dev/null 2>&1; fi
            _log_success "Hysteria 服务已禁用开机自启。";;
        *) _log_error "未知的服务操作: $action"; return 1;;
    esac
}

_show_config() {
    _detect_os
    if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。没有配置可显示。请使用 '${SCRIPT_COMMAND_NAME} install' 安装。"; return 1; fi
    _log_info "当前 Hysteria 配置文件 ($HYSTERIA_CONFIG_FILE):"; echo "----------------------------------------------------"
    if [ -f "$HYSTERIA_CONFIG_FILE" ]; then cat "$HYSTERIA_CONFIG_FILE"; else _log_error "配置文件不存在。"; fi
    echo "----------------------------------------------------"; _log_info "配置摘要:"
    local port=$(grep -E '^listen: :[0-9]+' "$HYSTERIA_CONFIG_FILE" | sed 's/listen: ://' || echo "未知")
    local password=$(grep -A1 '^auth:$' "$HYSTERIA_CONFIG_FILE" | grep 'password:' | awk '{print $2}' || echo "未知")
    local masquerade_url=$(grep -A2 '^masquerade:' "$HYSTERIA_CONFIG_FILE" | grep 'url:' | awk '{print $2}' || echo "未知")
    echo "  监听端口: $port"; echo "  密码: $password"; echo "  伪装URL: $masquerade_url"
    if grep -q '^tls:' "$HYSTERIA_CONFIG_FILE"; then local cert_path=$(grep -A2 '^tls:' "$HYSTERIA_CONFIG_FILE" | grep 'cert:' | awk '{print $2}' || echo "未知"); local key_path=$(grep -A2 '^tls:' "$HYSTERIA_CONFIG_FILE" | grep 'key:' | awk '{print $2}' || echo "未知"); echo "  TLS模式: 自定义证书"; echo "    证书路径: $cert_path"; echo "    私钥路径: $key_path";
    elif grep -q '^acme:' "$HYSTERIA_CONFIG_FILE"; then local domain=$(grep -A2 '^acme:' "$HYSTERIA_CONFIG_FILE" | grep -- '- ' | sed 's/^- // ; s/"//g' || echo "未知"); local email=$(grep -A2 '^acme:' "$HYSTERIA_CONFIG_FILE" | grep 'email:' | awk '{print $2}' || echo "未知"); echo "  TLS模式: ACME (Let's Encrypt)"; echo "    域名: $domain"; echo "    邮箱: $email";
    else echo "  TLS模式: 未配置或未知"; fi; echo "----------------------------------------------------"
}

_change_config_interactive() {
    _ensure_root; _detect_os
    if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。无法更改配置。请使用 '${SCRIPT_COMMAND_NAME} install' 安装。"; return 1; fi
    _log_info "更改 Hysteria 配置（部分选项）"; _log_warning "此功能通过 sed/awk 修改配置文件，对于复杂情况可能不够健壮。"; _log_warning "强烈建议在更改前备份 $HYSTERIA_CONFIG_FILE 文件。"; _log_warning "当前仅支持修改：监听端口、密码、伪装URL。"

    CURRENT_PORT=$(grep -E '^listen: :[0-9]+' "$HYSTERIA_CONFIG_FILE" | sed 's/listen: ://' || echo "")
    CURRENT_PASSWORD_RAW=$(grep -A 2 '^auth:' "$HYSTERIA_CONFIG_FILE" | grep 'password:' | sed 's/ *password: *//' || echo "")
    CURRENT_MASQUERADE=$(grep -A 2 '^masquerade:' "$HYSTERIA_CONFIG_FILE" | grep 'url:' | sed 's/ *url: *//' || echo "")

    _log_info "当前监听端口: ${CURRENT_PORT:-未设置}"; read -p "新监听端口 (直接回车不更改 '$CURRENT_PORT'): " NEW_PORT; NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    _log_info "当前密码: ${CURRENT_PASSWORD_RAW:+(已设置，此处不显示)}"; read -p "新密码 (直接回车不更改, 输入 'random' 生成随机密码): " NEW_PASSWORD_INPUT
    NEW_PASSWORD=""; if [ -n "$NEW_PASSWORD_INPUT" ]; then if [ "$NEW_PASSWORD_INPUT" == "random" ]; then NEW_PASSWORD=$(_generate_uuid); _log_info "生成新随机密码: $NEW_PASSWORD"; else NEW_PASSWORD="$NEW_PASSWORD_INPUT"; fi; else NEW_PASSWORD="$CURRENT_PASSWORD_RAW"; fi
    _log_info "当前伪装URL: ${CURRENT_MASQUERADE:-未设置}"; read -p "新伪装URL (直接回车不更改 '$CURRENT_MASQUERADE'): " NEW_MASQUERADE_URL_INPUT; NEW_MASQUERADE=${NEW_MASQUERADE_URL_INPUT:-$CURRENT_MASQUERADE} # Renamed variable to avoid conflict

    CONFIG_BACKUP_FILE="${HYSTERIA_CONFIG_FILE}.bak.$(date +%s)"; cp "$HYSTERIA_CONFIG_FILE" "$CONFIG_BACKUP_FILE"; _log_info "配置文件已备份至 $CONFIG_BACKUP_FILE"
    local config_changed=false; temp_config_file=$(mktemp)

    # Change Port
    if [ "$NEW_PORT" != "$CURRENT_PORT" ]; then _log_info "正在更改端口从 '$CURRENT_PORT' 到 '$NEW_PORT'..."; sed "s/^listen: :${CURRENT_PORT}/listen: :${NEW_PORT}/" "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改端口失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; return 1; }; config_changed=true; fi
    # Change Password
    if [ "$NEW_PASSWORD" != "$CURRENT_PASSWORD_RAW" ]; then _log_info "正在更改密码..."; awk -v new_pass="$NEW_PASSWORD" 'BEGIN{pb=0} /^auth:/{pb=1;print;next} pb&&/password:/{print "  password: " new_pass;pb=0;next} pb&&NF>0&&!/^[[:space:]]/{pb=0} {print}' "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改密码失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; return 1; }; config_changed=true; fi
    # Change Masquerade URL
    if [ "$NEW_MASQUERADE" != "$CURRENT_MASQUERADE" ]; then _log_info "正在更改伪装URL到 '$NEW_MASQUERADE'..."; awk -v new_url="$NEW_MASQUERADE" 'BEGIN{mb=0} /^masquerade:/{mb=1;print;next} mb&&/url:/{print "    url: " new_url;mb=0;next} mb&&NF>0&&!/^[[:space:]]/{mb=0} {print}' "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改伪装URL失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; return 1; }; config_changed=true; fi
    
    rm -f "$temp_config_file" # Clean up temp file
    if $config_changed; then _log_success "配置已更新。正在重启 Hysteria 服务..."; _control_service "restart"; rm -f "$CONFIG_BACKUP_FILE"; else _log_info "未检测到配置更改。"; rm -f "$CONFIG_BACKUP_FILE"; fi # Remove backup if no changes or if successful
}

_show_menu() {
    echo ""; _log_info "Hysteria 管理面板 (${SCRIPT_COMMAND_NAME} v$SCRIPT_VERSION - $SCRIPT_DATE)"
    echo "--------------------------------------------"; echo " 服务管理:";
    echo "   start         - 启动 Hysteria 服务"; echo "   stop          - 停止 Hysteria 服务"; echo "   restart       - 重启 Hysteria 服务"; echo "   status        - 查看 Hysteria 服务状态"; echo "   enable        - 设置 Hysteria 服务开机自启"; echo "   disable       - 禁止 Hysteria 服务开机自启"
    echo " 配置管理:"; echo "   config        - 显示当前配置摘要"; echo "   config_edit   - (高级) 手动编辑配置文件 (使用 \$EDITOR)"; echo "   config_change - 交互式更改部分配置 (端口, 密码, 伪装URL)"
    echo " 日志查看:"; echo "   logs          - 查看 Hysteria 输出日志 ($LOG_FILE_OUT)"; echo "   logs_err      - 查看 Hysteria 错误日志 ($LOG_FILE_ERR)"
    _detect_os # Ensure INIT_SYSTEM is available
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then echo "   logs_sys      - 查看 systemd 服务日志 (journalctl)"; fi
    echo " 安装与卸载:"; echo "   install       - 安装或重新安装 Hysteria"; echo "   uninstall     - 卸载 Hysteria"
    echo " 其他:"; echo "   version       - 显示此脚本和 Hysteria 版本"; echo "   help          - 显示此帮助菜单"
    echo "--------------------------------------------"; echo "用法: sudo ${SCRIPT_COMMAND_NAME} <命令>"; echo "例如: sudo ${SCRIPT_COMMAND_NAME} start"; echo "      sudo ${SCRIPT_COMMAND_NAME} config_change"; echo ""
    _log_info "此管理脚本 (${SCRIPT_COMMAND_NAME}) 在执行 'sudo ${SCRIPT_COMMAND_NAME} install' 时会尝试自动安装到 /usr/local/bin/${SCRIPT_COMMAND_NAME}."
    _log_info "如果自动安装失败或您想手动更新, 可以执行 (请确保下面的URL正确):"
    echo "  sudo wget -qO \"/usr/local/bin/${SCRIPT_COMMAND_NAME}\" \"$HY_SCRIPT_URL_ON_GITHUB\""
    echo "  sudo chmod +x \"/usr/local/bin/${SCRIPT_COMMAND_NAME}\""
    echo ""
}

_show_management_commands_hint() {
    _log_info "您可以使用 'sudo ${SCRIPT_COMMAND_NAME} help' 或不带参数运行 'sudo ${SCRIPT_COMMAND_NAME}' 来查看管理命令面板。"
}

# --- Main Script Logic ---
if [[ "$1" != "version" && "$1" != "help" && "$1" != "" && "$1" != "-h" && "$1" != "--help" ]]; then
    # For most commands, OS detection is needed early.
    # For install/uninstall, _ensure_root is called within _do_install/_do_uninstall.
    # For service controls, _ensure_root is called within _control_service.
    # For config_change & config_edit, _ensure_root is called within them.
    _detect_os
fi

ACTION="$1"

case "$ACTION" in
    install)         _do_install ;; # _ensure_root is inside
    uninstall)       _do_uninstall ;; # _ensure_root is inside
    start)           _control_service "start" ;;
    stop)            _control_service "stop" ;;
    restart)         _control_service "restart" ;;
    status)          _control_service "status" ;; # No root usually needed by underlying cmd
    enable)          _control_service "enable" ;;
    disable)         _control_service "disable" ;;
    config|show_config) _show_config ;;
    config_edit)
        _ensure_root
        if ! _is_hysteria_installed; then _log_error "Hysteria未安装."; exit 1; fi
        if [ -z "$EDITOR" ]; then EDITOR="vi"; fi
        _log_info "使用 $EDITOR 打开 $HYSTERIA_CONFIG_FILE ..."
        if $EDITOR "$HYSTERIA_CONFIG_FILE"; then _log_info "编辑完成。如果更改了配置，请考虑重启服务: sudo $SCRIPT_COMMAND_NAME restart"; else _log_error "编辑器 '$EDITOR' 返回错误。"; fi ;;
    config_change)   _change_config_interactive ;; # _ensure_root is inside
    logs)
        if ! _is_hysteria_installed; then _log_error "Hysteria 未安装，无法查看日志。"; exit 1; fi
        if [ ! -f "$LOG_FILE_OUT" ]; then _log_error "日志文件 $LOG_FILE_OUT 不存在或不可读。"; exit 1; fi
        _log_info "按 CTRL+C 退出日志查看 ($LOG_FILE_OUT)。"; tail -f "$LOG_FILE_OUT" ;;
    logs_err)
        if ! _is_hysteria_installed; then _log_error "Hysteria 未安装，无法查看日志。"; exit 1; fi
        if [ ! -f "$LOG_FILE_ERR" ]; then _log_error "日志文件 $LOG_FILE_ERR 不存在或不可读。"; exit 1; fi
        _log_info "按 CTRL+C 退出日志查看 ($LOG_FILE_ERR)。"; tail -f "$LOG_FILE_ERR" ;;
    logs_sys)
        _detect_os
        if [[ "$INIT_SYSTEM" == "systemd" ]]; then _log_info "按 Q 退出日志查看 (journalctl)。"; journalctl -u "$CURRENT_HYSTERIA_SERVICE_NAME" -f --no-pager;
        else _log_error "此命令仅适用于 systemd 系统。"; _log_info "对于 OpenRC 系统，请使用 '${SCRIPT_COMMAND_NAME} logs' 和 '${SCRIPT_COMMAND_NAME} logs_err'。"; fi ;;
    version)
        echo "$SCRIPT_COMMAND_NAME 管理脚本版本: $SCRIPT_VERSION ($SCRIPT_DATE)"; echo "脚本文件: $SCRIPT_FILE_BASENAME"
        if _is_hysteria_installed && command -v "$HYSTERIA_INSTALL_PATH" &>/dev/null; then echo -n "已安装 Hysteria 版本: "; "$HYSTERIA_INSTALL_PATH" version;
        else _log_warning "Hysteria 未安装或 $HYSTERIA_INSTALL_PATH 未找到。"; fi ;;
    help|--help|-h|"") _show_menu ;; # Also show menu if no arguments
    *) _log_error "未知命令: $ACTION"; _show_menu; exit 1 ;;
esac

exit 0
