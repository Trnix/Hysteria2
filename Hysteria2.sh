#!/bin/bash

# --- Script Setup ---
SCRIPT_COMMAND_NAME="hy"
SCRIPT_FILE_BASENAME="Hysteria2.sh"
SCRIPT_VERSION="1.5.1" # Incremented for qrencode package name fix on Alpine and robust dependency install
SCRIPT_DATE="2025-05-09"

HY_SCRIPT_URL_ON_GITHUB="https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/${SCRIPT_FILE_BASENAME}" 

HYSTERIA_INSTALL_PATH="/usr/local/bin/hysteria"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
HYSTERIA_CONFIG_FILE="${HYSTERIA_CONFIG_DIR}/config.yaml"
HYSTERIA_CERTS_DIR="${HYSTERIA_CONFIG_DIR}/certs"
# HYSTERIA_INSTALL_VARS_FILE is no longer actively used, only removed on uninstall if exists
HYSTERIA_INSTALL_VARS_FILE="${HYSTERIA_CONFIG_DIR}/install_vars.conf"
HYSTERIA_SERVICE_NAME_SYSTEMD="hysteria.service"
HYSTERIA_SERVICE_NAME_OPENRC="hysteria"
LOG_FILE_OUT="/var/log/hysteria.log"
LOG_FILE_ERR="/var/log/hysteria.error.log"

# --- Color Definitions ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Global OS Detection Variables ---
DISTRO_FAMILY=""; PKG_INSTALL_CMD=""; PKG_UPDATE_CMD=""; PKG_REMOVE_CMD=""
INIT_SYSTEM=""; SERVICE_CMD=""; ENABLE_CMD_PREFIX=""; ENABLE_CMD_SUFFIX=""
SETCAP_DEPENDENCY_PKG=""; REQUIRED_PKGS_OS_SPECIFIC=""; CURRENT_HYSTERIA_SERVICE_NAME=""
QRENCODE_PACKAGE_NAME="" # 新增：用于存放 qrencode 工具的包名

# --- Utility Functions ---
_log_error() { echo -e "${RED}错误: $1${NC}" >&2; }
_log_success() { echo -e "${GREEN}$1${NC}" >&2; }
_log_warning() { echo -e "${YELLOW}警告: $1${NC}" >&2; }
_log_info() { echo -e "${BLUE}信息: $1${NC}" >&2; }

_ensure_root() { if [ "$(id -u)" -ne 0 ]; then _log_error "此操作需 root 权限。请用 sudo。"; exit 1; fi; }
_read_from_tty() { local var_name="$1"; local prompt_str="$2"; local default_val_display="$3"; local actual_prompt="${BLUE}${prompt_str}${NC}"; if [ -n "$default_val_display" ]; then actual_prompt="${BLUE}${prompt_str} (当前: ${default_val_display:-未设置}, 回车不改): ${NC}"; if [[ "$prompt_str" == *"密码"* && -n "$default_val_display" ]]; then actual_prompt="${BLUE}${prompt_str} (当前: ******, 回车不改, 输入'random'生成): ${NC}"; elif [[ "$prompt_str" == *"密码"* ]]; then actual_prompt="${BLUE}${prompt_str} (回车随机, 输入'random'生成): ${NC}"; fi; fi; echo -n -e "$actual_prompt"; read "$var_name" </dev/tty; }
_read_confirm_tty() { local var_name="$1"; local prompt_str="$2"; echo -n -e "${YELLOW}${prompt_str}${NC}"; read "$var_name" </dev/tty; }

_detect_os() {
    if [ -n "$DISTRO_FAMILY" ]; then return 0; fi # Avoid re-detection
    QRENCODE_PACKAGE_NAME="" # Reset in case of re-call, though not typical

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "alpine" ]]; then DISTRO_FAMILY="alpine";
        elif [[ "$ID" == "debian" || "$ID" == "ubuntu" || "$ID_LIKE" == "debian" || "$ID_LIKE" == "ubuntu" ]]; then DISTRO_FAMILY="debian";
        else _log_error "不支持发行版 '$ID'."; exit 1; fi
    elif command -v apk >/dev/null 2>&1; then DISTRO_FAMILY="alpine";
    elif command -v apt-get >/dev/null 2>&1; then DISTRO_FAMILY="debian";
    else _log_error "无法确定发行版."; exit 1; fi

    if [[ "$DISTRO_FAMILY" == "alpine" ]]; then
        PKG_INSTALL_CMD="apk add --no-cache"; PKG_UPDATE_CMD="apk update"; PKG_REMOVE_CMD="apk del";
        INIT_SYSTEM="openrc"; SERVICE_CMD="service"; ENABLE_CMD_PREFIX="rc-update add"; ENABLE_CMD_SUFFIX="default";
        SETCAP_DEPENDENCY_PKG="libcap"; REQUIRED_PKGS_OS_SPECIFIC="openrc"; CURRENT_HYSTERIA_SERVICE_NAME="$HYSTERIA_SERVICE_NAME_OPENRC";
        QRENCODE_PACKAGE_NAME="libqrencode-tools";
    elif [[ "$DISTRO_FAMILY" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive; PKG_INSTALL_CMD="apt-get install -y -q"; PKG_UPDATE_CMD="apt-get update -q"; PKG_REMOVE_CMD="apt-get remove -y -q";
        INIT_SYSTEM="systemd"; SERVICE_CMD="systemctl"; ENABLE_CMD_PREFIX="systemctl enable"; ENABLE_CMD_SUFFIX="";
        SETCAP_DEPENDENCY_PKG="libcap2-bin"; REQUIRED_PKGS_OS_SPECIFIC=""; CURRENT_HYSTERIA_SERVICE_NAME="$HYSTERIA_SERVICE_NAME_SYSTEMD";
        QRENCODE_PACKAGE_NAME="qrencode";
    else
        _log_error "在 _detect_os 中未能识别发行版 '$DISTRO_FAMILY' 以设置包命令。"
        exit 1
    fi
}

_is_hysteria_installed() { _detect_os; if [ -f "$HYSTERIA_INSTALL_PATH" ] && [ -f "$HYSTERIA_CONFIG_FILE" ]; then if [ "$INIT_SYSTEM" == "systemd" ] && [ -f "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME" ]; then return 0; elif [ "$INIT_SYSTEM" == "openrc" ] && [ -f "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME" ]; then return 0; fi; fi; return 1; }

_install_dependencies() {
    _log_info "更新包列表 (${DISTRO_FAMILY})...";
    if ! $PKG_UPDATE_CMD; then # Removed >/dev/null, show output
        _log_error "更新包列表 (${PKG_UPDATE_CMD}) 失败。请检查您的网络和软件源配置。"
        exit 1
    fi
    _log_success "包列表更新成功。"

    REQUIRED_PKGS_COMMON="wget curl git openssl lsof coreutils" # qrencode removed from here
    REQUIRED_PKGS="$REQUIRED_PKGS_COMMON"

    if [ -n "$QRENCODE_PACKAGE_NAME" ]; then
        REQUIRED_PKGS="$REQUIRED_PKGS $QRENCODE_PACKAGE_NAME"
    else
        _log_warning "QRENCODE_PACKAGE_NAME 未为发行版 '$DISTRO_FAMILY' 设置。qrencode 可能不会被安装。"
        # Fallback for safety, though _detect_os should always set it for supported distros
        # If truly unknown, installing "qrencode" might fail but is a common name.
        # However, for Alpine, this would be wrong. Best to rely on _detect_os.
    fi

    if [ -n "$REQUIRED_PKGS_OS_SPECIFIC" ]; then REQUIRED_PKGS="$REQUIRED_PKGS $REQUIRED_PKGS_OS_SPECIFIC"; fi

    # Ensure realpath command is available (part of coreutils)
    if ! command -v realpath &>/dev/null && [[ "$DISTRO_FAMILY" == "debian" || "$DISTRO_FAMILY" == "alpine" ]]; then
        _log_info "确保 realpath 命令可用 (通过 coreutils)..."
        # Ensure coreutils is installed first if realpath isn't found
        if ! $PKG_INSTALL_CMD coreutils; then # Removed > /dev/null, show output
            _log_warning "尝试安装/确保 coreutils 失败。"
        fi
        if ! command -v realpath &>/dev/null; then _log_error "realpath 命令在安装 coreutils 后仍然不可用。请检查您的系统。"; exit 1; fi
    fi

    for pkg in $REQUIRED_PKGS; do
        installed=false
        if [[ "$DISTRO_FAMILY" == "alpine" ]]; then if apk info -e "$pkg" &>/dev/null; then installed=true; fi
        elif [[ "$DISTRO_FAMILY" == "debian" ]]; then if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then installed=true; fi; fi

        if $installed; then
            _log_info "$pkg 已安装。"
        else
            _log_info "正在安装 $pkg..."
            if ! $PKG_INSTALL_CMD "$pkg"; then # Removed > /dev/null, show output
                _log_error "安装 $pkg 失败。请检查上面的输出，并手动安装后重试。"
                exit 1
            fi
            _log_success "$pkg 安装成功。"
        fi
    done
    _log_success "依赖包安装成功。"
}

_generate_uuid() { local bytes=$(od -x -N 16 /dev/urandom | head -1 | awk '{OFS=""; $1=""; print}'); local byte7=${bytes:12:4}; byte7=$((0x${byte7} & 0x0fff | 0x4000)); byte7=$(printf "%04x" $byte7); local byte9=${bytes:20:4}; byte9=$((0x${byte9} & 0x3fff | 0x8000)); byte9=$(printf "%04x" $byte9); echo "${bytes:0:8}-${bytes:8:4}-${byte7}-${byte9}-${bytes:24:12}" | tr '[:upper:]' '[:lower:]'; }
_generate_random_lowercase_string() { LC_ALL=C tr -dc 'a-z' < /dev/urandom | head -c 8; }
_get_server_address() { local ipv6_ip; local ipv4_ip; _log_info "检测公网IP..."; _log_info "尝试IPv6..."; ipv6_ip=$(curl -s -m 5 -6 https://ifconfig.me || curl -s -m 5 -6 https://ip.sb || curl -s -m 5 -6 https://api64.ipify.org); if [ -n "$ipv6_ip" ] && [[ "$ipv6_ip" == *":"* ]]; then _log_success "IPv6: $ipv6_ip"; echo "[$ipv6_ip]"; return; else _log_warning "无IPv6."; fi; _log_info "尝试IPv4..."; ipv4_ip=$(curl -s -m 5 -4 https://ifconfig.me || curl -s -m 5 -4 https://ip.sb || curl -s -m 5 -4 https://api.ipify.org); if [ -n "$ipv4_ip" ] && [[ "$ipv4_ip" != *":"* ]]; then _log_success "IPv4: $ipv4_ip"; echo "$ipv4_ip"; return; else _log_warning "无IPv4."; fi; _log_error "无法获取公网IP."; exit 1; }

_setup_hy_command() {
    _ensure_root; _log_info "设置'${SCRIPT_COMMAND_NAME}'命令到/usr/local/bin/${SCRIPT_COMMAND_NAME}..."; if [[ "$HY_SCRIPT_URL_ON_GITHUB" == *"YOUR_USERNAME"* ]]; then _log_error "HY_SCRIPT_URL_ON_GITHUB 未配置!"; _log_warning "请编辑脚本设置URL或手动复制: sudo cp \"${0:-${SCRIPT_FILE_BASENAME}}\" /usr/local/bin/${SCRIPT_COMMAND_NAME} && sudo chmod +x /usr/local/bin/${SCRIPT_COMMAND_NAME}"; return 1; fi
    _log_info "从URL($HY_SCRIPT_URL_ON_GITHUB)下载..."; TMP_SCRIPT_DOWNLOAD_PATH=$(mktemp); if wget -qO "$TMP_SCRIPT_DOWNLOAD_PATH" "$HY_SCRIPT_URL_ON_GITHUB"; then if head -n 1 "$TMP_SCRIPT_DOWNLOAD_PATH" | grep -q -E "^#!/(usr/)?bin/(bash|sh)"; then if [ -f "/usr/local/bin/${SCRIPT_COMMAND_NAME}" ] && ! cmp -s "$TMP_SCRIPT_DOWNLOAD_PATH" "/usr/local/bin/${SCRIPT_COMMAND_NAME}"; then _log_info "备份现有命令..."; cp "/usr/local/bin/${SCRIPT_COMMAND_NAME}" "/usr/local/bin/${SCRIPT_COMMAND_NAME}.old.$(date +%s)"; fi; if mv "$TMP_SCRIPT_DOWNLOAD_PATH" "/usr/local/bin/${SCRIPT_COMMAND_NAME}"; then chmod +x "/usr/local/bin/${SCRIPT_COMMAND_NAME}"; _log_success "'${SCRIPT_COMMAND_NAME}'命令已从 URL 安装/更新."; return 0; else _log_error "移动下载脚本失败."; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi; else _log_error "下载内容非有效脚本. URL: $HY_SCRIPT_URL_ON_GITHUB"; _log_warning "开头: $(head -n 1 "$TMP_SCRIPT_DOWNLOAD_PATH")"; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi; else _log_error "下载脚本失败."; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi
}

_get_link_params_from_config() {
    unset HY_PASSWORD HY_LINK_ADDRESS HY_PORT HY_LINK_SNI HY_LINK_INSECURE HY_SNI_VALUE DOMAIN_FROM_CONFIG CERT_PATH_FROM_CONFIG KEY_PATH_FROM_CONFIG
    if [ ! -f "$HYSTERIA_CONFIG_FILE" ]; then _log_error "配置文件 $HYSTERIA_CONFIG_FILE 未找到。"; return 1; fi
    _log_info "正从 $HYSTERIA_CONFIG_FILE 解析配置以生成链接..."
    HY_PORT=$(grep -E '^\s*listen:\s*:([0-9]+)' "$HYSTERIA_CONFIG_FILE" | sed -E 's/^\s*listen:\s*://' || echo "")
    HY_PASSWORD=$(grep 'password:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^.*password:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/["'\'']//g' || echo "")
    if grep -q '^\s*acme:' "$HYSTERIA_CONFIG_FILE"; then
        _log_info "检测到 ACME 配置。"
        DOMAIN_FROM_CONFIG=$(grep -A 1 '^\s*domains:' "$HYSTERIA_CONFIG_FILE" | grep '^\s*-\s*' | sed -e 's/^\s*-\s*//' -e 's/#.*//' -e 's/[ \t]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//')
        if [ -z "$DOMAIN_FROM_CONFIG" ]; then _log_error "无法从配置解析ACME域名。"; return 1; fi
        HY_LINK_SNI="$DOMAIN_FROM_CONFIG"; HY_LINK_ADDRESS="$DOMAIN_FROM_CONFIG"; HY_LINK_INSECURE="0"; HY_SNI_VALUE="$DOMAIN_FROM_CONFIG"
    elif grep -q '^\s*tls:' "$HYSTERIA_CONFIG_FILE"; then
        _log_info "检测到自定义 TLS 配置。"
        CERT_PATH_FROM_CONFIG=$(grep '^\s*cert:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^\s*cert:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//' || echo "")
        if [ -z "$CERT_PATH_FROM_CONFIG" ]; then _log_error "无法从配置解析证书路径。"; return 1; fi
        if [[ "$CERT_PATH_FROM_CONFIG" != /* ]]; then CERT_PATH_FROM_CONFIG="${HYSTERIA_CONFIG_DIR}/${CERT_PATH_FROM_CONFIG}"; fi
        if command -v realpath &>/dev/null; then CERT_PATH_FROM_CONFIG=$(realpath -m "$CERT_PATH_FROM_CONFIG" 2>/dev/null || echo "$CERT_PATH_FROM_CONFIG"); fi
        if [ ! -f "$CERT_PATH_FROM_CONFIG" ]; then _log_error "配置文件中的证书路径 '$CERT_PATH_FROM_CONFIG' 无效或文件不存在。"; return 1; fi
        _log_info "证书路径: $CERT_PATH_FROM_CONFIG"; _log_info "尝试从证书提取 SNI..."
        HY_SNI_VALUE=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CERT_PATH_FROM_CONFIG" 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p'); if [ -z "$HY_SNI_VALUE" ]; then HY_SNI_VALUE=$(openssl x509 -noout -subject -in "$CERT_PATH_FROM_CONFIG" 2>/dev/null | sed -n 's/.*CN ?= ?\([^,]*\).*/\1/p' | head -n 1 | sed 's/^[ \t]*//;s/[ \t]*$//'); fi
        if [ -z "$HY_SNI_VALUE" ]; then HY_SNI_VALUE=$(openssl x509 -noout -text -in "$CERT_PATH_FROM_CONFIG" 2>/dev/null | grep 'DNS:' | head -n 1 | sed 's/.*DNS://' | tr -d ' ' | cut -d, -f1); fi
        if [ -z "$HY_SNI_VALUE" ]; then _log_warning "无法提取有效SNI(CN或SAN), 使用'sni_unknown'代替。"; HY_SNI_VALUE="sni_unknown"; else _log_info "提取到 SNI: $HY_SNI_VALUE"; fi
        HY_LINK_SNI="$HY_SNI_VALUE"; HY_LINK_ADDRESS=$(_get_server_address); if [ $? -ne 0 ] || [ -z "$HY_LINK_ADDRESS" ]; then _log_error "获取公网地址失败。"; return 1; fi; HY_LINK_INSECURE="1"
    else _log_error "无法确定TLS模式。"; return 1; fi
    if [ -z "$HY_PORT" ] || [ -z "$HY_PASSWORD" ] || [ -z "$HY_LINK_ADDRESS" ] || [ -z "$HY_LINK_SNI" ] || [ -z "$HY_LINK_INSECURE" ] || [ -z "$HY_SNI_VALUE" ]; then _log_error "未能解析生成链接所需的所有参数。"; if [ -z "$HY_PORT" ]; then _log_error "  - 端口解析失败。"; fi; if [ -z "$HY_PASSWORD" ]; then _log_error "  - 密码解析失败。"; fi; if [ -z "$HY_LINK_ADDRESS" ]; then _log_error "  - 链接地址获取失败。"; fi; if [ -z "$HY_LINK_SNI" ]; then _log_error "  - 链接SNI解析失败。"; fi; if [ -z "$HY_SNI_VALUE" ]; then _log_error "  - SNI值解析失败。"; fi; return 1; fi
    return 0
}

_display_link_and_qrcode() {
    # Helper function to display link and QR code
    # Assumes global HY_* vars are set by _get_link_params_from_config
    SUBSCRIPTION_LINK="hysteria2://${HY_PASSWORD}@${HY_LINK_ADDRESS}:${HY_PORT}/?sni=${HY_LINK_SNI}&alpn=h3&insecure=${HY_LINK_INSECURE}#Hysteria-${HY_SNI_VALUE}"
    echo ""; _log_info "Hysteria2 订阅链接 (根据当前配置生成):"
    echo -e "${GREEN}${SUBSCRIPTION_LINK}${NC}"
    echo "" # Add a newline
    if command -v qrencode &>/dev/null; then
        _log_info "Hysteria2 订阅链接二维码:"
        qrencode -t ANSIUTF8 "$SUBSCRIPTION_LINK"
    else
        _log_warning "提示: 'qrencode' 未安装, 无法显示二维码。"
        # Use QRENCODE_PACKAGE_NAME if set, otherwise default to 'qrencode'
        # _detect_os should have been called by the parent function (_show_info_and_qrcode)
        local install_hint_pkg_name="${QRENCODE_PACKAGE_NAME:-qrencode}"
        if [ -z "$QRENCODE_PACKAGE_NAME" ] && [ -n "$DISTRO_FAMILY" ] && [ "$DISTRO_FAMILY" == "alpine" ]; then
             install_hint_pkg_name="libqrencode-tools" # Explicitly for Alpine if var somehow not set
        fi
        _log_info "(可运行 'sudo $PKG_INSTALL_CMD ${install_hint_pkg_name}' 安装)"
    fi
    echo "" # Add a newline after QR code or message
}

_do_install() {
    _ensure_root; _detect_os
    if _is_hysteria_installed; then _read_confirm_tty confirm_install "Hysteria 已安装。是否强制安装(覆盖配置)? [y/N]: "; if [[ "$confirm_install" != "y" && "$confirm_install" != "Y" ]]; then _log_info "安装取消。"; exit 0; fi; _log_warning "正强制安装..."; fi
    _install_dependencies # Now installs qrencode using QRENCODE_PACKAGE_NAME
    DEFAULT_MASQUERADE_URL="https://www.bing.com"; DEFAULT_PORT="34567"; DEFAULT_ACME_EMAIL="$(_generate_random_lowercase_string)@gmail.com"
    echo ""; _log_info "请选择 TLS 验证方式:"; echo "1. 自定义证书"; echo "2. ACME HTTP 验证"; _read_from_tty TLS_TYPE "选择 [1-2, 默认 1]: "; TLS_TYPE=${TLS_TYPE:-1}
    CERT_PATH=""; KEY_PATH=""; DOMAIN=""; SNI_VALUE=""; ACME_EMAIL=""
    case $TLS_TYPE in 1) _log_info "--- 自定义证书模式 ---"; _read_from_tty USER_CERT_PATH "证书路径(.crt/.pem)(留空则自签): ";
        if [ -z "$USER_CERT_PATH" ]; then _log_info "将生成自签名证书。"; if ! command -v openssl &>/dev/null; then _log_error "openssl未安装 ($PKG_INSTALL_CMD openssl)"; exit 1; fi; _read_from_tty SELF_SIGN_SNI "自签名证书SNI(默认www.bing.com): "; SELF_SIGN_SNI=${SELF_SIGN_SNI:-"www.bing.com"}; SNI_VALUE="$SELF_SIGN_SNI"; mkdir -p "$HYSTERIA_CERTS_DIR"; CERT_PATH="$HYSTERIA_CERTS_DIR/server.crt"; KEY_PATH="$HYSTERIA_CERTS_DIR/server.key"; _log_info "正生成自签证书(CN=$SNI_VALUE)..."; if ! openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=$SNI_VALUE" -days 36500; then _log_error "自签证书生成失败!"; exit 1; fi; _log_success "自签证书已生成: $CERT_PATH, $KEY_PATH";
        else _log_info "提供证书路径: $USER_CERT_PATH"; _read_from_tty USER_KEY_PATH "私钥路径(.key/.pem): "; if [ -z "$USER_KEY_PATH" ]; then _log_error "私钥路径不能为空。"; exit 1; fi; TMP_CERT_PATH=$(realpath "$USER_CERT_PATH" 2>/dev/null); TMP_KEY_PATH=$(realpath "$USER_KEY_PATH" 2>/dev/null); if [ ! -f "$TMP_CERT_PATH" ]; then _log_error "证书'$USER_CERT_PATH'('$TMP_CERT_PATH')无效."; exit 1; fi; if [ ! -f "$TMP_KEY_PATH" ]; then _log_error "私钥'$USER_KEY_PATH'('$TMP_KEY_PATH')无效."; exit 1; fi; CERT_PATH="$TMP_CERT_PATH"; KEY_PATH="$TMP_KEY_PATH"; SNI_VALUE=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CERT_PATH" 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p'); if [ -z "$SNI_VALUE" ]; then SNI_VALUE=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | sed -n 's/.*CN ?= ?\([^,]*\).*/\1/p' | head -n 1 | sed 's/^[ \t]*//;s/[ \t]*$//'); fi; if [ -z "$SNI_VALUE" ]; then SNI_VALUE=$(openssl x509 -noout -text -in "$CERT_PATH" 2>/dev/null | grep 'DNS:' | head -n 1 | sed 's/.*DNS://' | tr -d ' ' | cut -d, -f1); fi; if [ -z "$SNI_VALUE" ]; then _read_from_tty MANUAL_SNI "无法提取SNI, 请手动输入: "; if [ -z "$MANUAL_SNI" ]; then _log_error "SNI不能为空!"; exit 1; fi; SNI_VALUE="$MANUAL_SNI"; else _log_info "提取到SNI: $SNI_VALUE"; fi; fi;;
        2) _log_info "--- ACME HTTP 验证 ---"; _read_from_tty DOMAIN "域名(eg: example.com): "; if [ -z "$DOMAIN" ]; then _log_error "域名不能为空!"; exit 1; fi; _read_from_tty INPUT_ACME_EMAIL "ACME邮箱(默认 $DEFAULT_ACME_EMAIL): "; ACME_EMAIL=${INPUT_ACME_EMAIL:-$DEFAULT_ACME_EMAIL}; if [ -z "$ACME_EMAIL" ]; then _log_error "邮箱不能为空!"; exit 1; fi; SNI_VALUE=$DOMAIN; _log_info "检查80端口..."; if lsof -i:80 -sTCP:LISTEN -P -n &>/dev/null; then _log_warning "80端口被占用!"; PID_80=$(lsof -t -i:80 -sTCP:LISTEN); [ -n "$PID_80" ] && _log_info "占用进程PID: $PID_80"; else _log_info "80端口可用。"; fi;;
        *) _log_error "无效TLS选项。"; exit 1;;
    esac
    _read_from_tty PORT_INPUT "Hysteria监听端口(默认 $DEFAULT_PORT): "; PORT=${PORT_INPUT:-$DEFAULT_PORT}
    _read_from_tty PASSWORD_INPUT "Hysteria密码(回车随机): " "random"; if [ -z "$PASSWORD_INPUT" ] || [ "$PASSWORD_INPUT" == "random" ]; then PASSWORD=$(_generate_uuid); _log_info "使用随机密码: $PASSWORD"; else PASSWORD="$PASSWORD_INPUT"; fi
    _read_from_tty MASQUERADE_URL_INPUT "伪装URL(默认 $DEFAULT_MASQUERADE_URL): "; MASQUERADE_URL=${MASQUERADE_URL_INPUT:-$DEFAULT_MASQUERADE_URL}
    SERVER_PUBLIC_ADDRESS=$(_get_server_address); mkdir -p "$HYSTERIA_CONFIG_DIR"
    _log_info "下载Hysteria..."; ARCH=$(uname -m); case ${ARCH} in x86_64) HYSTERIA_ARCH="amd64";; aarch64) HYSTERIA_ARCH="arm64";; armv7l) HYSTERIA_ARCH="arm";; *) _log_error "不支持架构: ${ARCH}"; exit 1;; esac
    if ! wget -qO "$HYSTERIA_INSTALL_PATH" "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${HYSTERIA_ARCH}"; then _log_warning "GitHub下载失败,尝试旧地址..."; if ! wget -qO "$HYSTERIA_INSTALL_PATH" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"; then _log_error "下载Hysteria失败!"; exit 1; fi; fi
    chmod +x "$HYSTERIA_INSTALL_PATH"; _log_success "Hysteria下载设置完成: $HYSTERIA_INSTALL_PATH"
    if [ "$TLS_TYPE" -eq 2 ]; then _log_info "设置cap_net_bind_service权限(ACME)..."; if ! command -v setcap &>/dev/null; then _log_warning "setcap未找到,尝试安装$SETCAP_DEPENDENCY_PKG..."; if ! $PKG_INSTALL_CMD "$SETCAP_DEPENDENCY_PKG"; then _log_error "安装$SETCAP_DEPENDENCY_PKG失败."; else _log_success "$SETCAP_DEPENDENCY_PKG安装成功."; fi; fi; if command -v setcap &>/dev/null; then if ! setcap 'cap_net_bind_service=+ep' "$HYSTERIA_INSTALL_PATH"; then _log_error "setcap失败."; else _log_success "setcap成功."; fi; else _log_error "setcap仍不可用."; fi; fi
    _log_info "生成配置文件 $HYSTERIA_CONFIG_FILE..."; cat > "$HYSTERIA_CONFIG_FILE" << EOF
# Hysteria 2 服务器配置文件
# 由 ${SCRIPT_COMMAND_NAME} v${SCRIPT_VERSION} 在 $(date) 生成

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
    LOCAL_LINK_SNI=""; LOCAL_LINK_ADDRESS=""; LOCAL_LINK_INSECURE=0; LOCAL_SNI_VALUE="$SNI_VALUE"
    case $TLS_TYPE in 1) cat >> "$HYSTERIA_CONFIG_FILE" << EOF

tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
        LOCAL_LINK_SNI="$SNI_VALUE"; LOCAL_LINK_ADDRESS="$SERVER_PUBLIC_ADDRESS"; LOCAL_LINK_INSECURE=1; _log_warning "自定义证书客户端需设insecure:true";; 2) cat >> "$HYSTERIA_CONFIG_FILE" << EOF

acme:
  domains:
    - $DOMAIN
  email: $ACME_EMAIL
EOF
        LOCAL_LINK_SNI="$DOMAIN"; LOCAL_LINK_ADDRESS="$DOMAIN"; LOCAL_LINK_INSECURE=0;; esac; _log_success "配置文件完成。"
    if [ "$INIT_SYSTEM" == "systemd" ]; then _log_info "创建systemd服务..."; cat > "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME" << EOF
[Unit]
Description=Hysteria 2 Service by $SCRIPT_COMMAND_NAME
After=network.target network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$HYSTERIA_INSTALL_PATH server --config $HYSTERIA_CONFIG_FILE
Restart=on-failure; RestartSec=10; StandardOutput=append:$LOG_FILE_OUT; StandardError=append:$LOG_FILE_ERR; LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME"; $SERVICE_CMD daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then _log_info "创建OpenRC服务..."; cat > "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME" << EOF
#!/sbin/openrc-run
name="$HYSTERIA_SERVICE_NAME_OPENRC"; command="$HYSTERIA_INSTALL_PATH"; command_args="server --config $HYSTERIA_CONFIG_FILE"; pidfile="/var/run/\${name}.pid"; command_background="yes"; output_log="$LOG_FILE_OUT"; error_log="$LOG_FILE_ERR"
depend() { need net; after firewall; }
start_pre() { checkpath -f \$output_log -m 0644 \$RC_SVCNAME; checkpath -f \$error_log -m 0644 \$RC_SVCNAME; }
start() { ebegin "Starting \$name"; start-stop-daemon --start --quiet --background --make-pidfile --pidfile \$pidfile --stdout \$output_log --stderr \$error_log --exec \$command -- \$command_args; eend \$?; }
stop() { ebegin "Stopping \$name"; start-stop-daemon --stop --quiet --pidfile \$pidfile; eend \$?; }
EOF
        chmod +x "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME"; fi; _log_success "服务文件创建成功。"
    _control_service "enable"; _control_service "restart"
    sleep 2; if _control_service "status" > /dev/null; then _log_success "Hysteria服务已成功运行！"; else _log_error "Hysteria服务状态异常!"; fi
    _setup_hy_command

    # --- Display final info and QR code ---
    _log_success "Hysteria 2安装配置完成！"
    echo "------------------------------------------------------------------------"
    # Call the combined info/qrcode display function
    _show_info_and_qrcode
    echo "------------------------------------------------------------------------"
    _show_management_commands_hint
}

_do_uninstall() {
    _ensure_root; _detect_os # Ensures QRENCODE_PACKAGE_NAME and PKG_REMOVE_CMD are set
    _read_confirm_tty confirm_uninstall "这将卸载 Hysteria 2 并删除所有相关配置和文件。确定? [y/N]: "
    if [[ "$confirm_uninstall" != "y" && "$confirm_uninstall" != "Y" ]]; then _log_info "卸载取消。"; exit 0; fi

    _log_info "停止Hysteria服务..."; _control_service "stop" >/dev/null 2>&1
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then _log_info "禁用systemd服务..."; $SERVICE_CMD disable "$CURRENT_HYSTERIA_SERVICE_NAME" >/dev/null 2>&1; _log_info "移除systemd服务文件..."; rm -f "/etc/systemd/system/$CURRENT_HYSTERIA_SERVICE_NAME"; find /etc/systemd/system/ -name "$CURRENT_HYSTERIA_SERVICE_NAME" -delete; $SERVICE_CMD daemon-reload; $SERVICE_CMD reset-failed "$CURRENT_HYSTERIA_SERVICE_NAME" >/dev/null 2>&1 || true
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then _log_info "移除OpenRC服务..."; rc-update del "$CURRENT_HYSTERIA_SERVICE_NAME" default >/dev/null 2>&1; _log_info "移除OpenRC脚本..."; rm -f "/etc/init.d/$CURRENT_HYSTERIA_SERVICE_NAME"; fi
    _log_info "移除Hysteria二进制: $HYSTERIA_INSTALL_PATH"; rm -f "$HYSTERIA_INSTALL_PATH"
    _log_info "移除Hysteria配置: $HYSTERIA_CONFIG_DIR"; rm -rf "$HYSTERIA_CONFIG_DIR" # Removes config, certs, and install_vars if exists
    _log_info "移除Hysteria日志: $LOG_FILE_OUT, $LOG_FILE_ERR"; rm -f "$LOG_FILE_OUT" "$LOG_FILE_ERR"

    # Automatically attempt to remove qrencode package
    if command -v qrencode &>/dev/null; then # Check if the command 'qrencode' exists
        local pkg_to_remove_name="${QRENCODE_PACKAGE_NAME}"
        if [ -z "$pkg_to_remove_name" ]; then # Fallback if QRENCODE_PACKAGE_NAME is somehow not set
            _log_warning "QRENCODE_PACKAGE_NAME 未设置，将尝试使用 'qrencode' 作为包名卸载。"
            pkg_to_remove_name="qrencode"
            if [ "$DISTRO_FAMILY" == "alpine" ]; then # Specific fallback for Alpine if variable was empty
                pkg_to_remove_name="libqrencode-tools"
            fi
        fi
        _log_info "尝试自动卸载 qrencode (包: ${pkg_to_remove_name})..."
        if $PKG_REMOVE_CMD "$pkg_to_remove_name" >/dev/null; then # Suppress output for remove
            _log_success "${pkg_to_remove_name} 已卸载。"
        else
            _log_warning "卸载 ${pkg_to_remove_name} 失败 (可能未通过此名称安装或出错)。"
        fi
    fi

    # Automatically attempt to remove hy command if it exists
    if [ -f "/usr/local/bin/$SCRIPT_COMMAND_NAME" ]; then
        _log_info "尝试自动移除管理命令 /usr/local/bin/$SCRIPT_COMMAND_NAME ..."
        if rm -f "/usr/local/bin/$SCRIPT_COMMAND_NAME"; then _log_success "/usr/local/bin/$SCRIPT_COMMAND_NAME 已移除。"; else _log_error "移除 /usr/local/bin/$SCRIPT_COMMAND_NAME 失败。"; fi
    fi
    _log_success "Hysteria 卸载完成。"
}

_control_service() {
    _detect_os; local action="$1"
    if [[ "$action" == "start" || "$action" == "stop" || "$action" == "restart" || "$action" == "status" ]]; then if ! _is_hysteria_installed; then _log_error "Hysteria未安装或服务未配置。请用'${SCRIPT_COMMAND_NAME} install'安装。"; return 1; fi; fi
    case "$action" in start|stop|restart) _ensure_root; _log_info "执行: $SERVICE_CMD $action $CURRENT_HYSTERIA_SERVICE_NAME"
        if [[ "$INIT_SYSTEM" == "systemd" && "$action" == "stop" ]] && ! $SERVICE_CMD is-active --quiet "$CURRENT_HYSTERIA_SERVICE_NAME"; then _log_info "服务($CURRENT_HYSTERIA_SERVICE_NAME)已停止。"; return 0; fi
        if $SERVICE_CMD "$action" "$CURRENT_HYSTERIA_SERVICE_NAME"; then _log_success "操作'$action'成功。"; if [[ "$action" == "start" || "$action" == "restart" ]]; then sleep 1; $SERVICE_CMD status "$CURRENT_HYSTERIA_SERVICE_NAME" 2>/dev/null | head -n 5 || $SERVICE_CMD status "$CURRENT_HYSTERIA_SERVICE_NAME"; fi
        else _log_error "操作'$action'失败。"; _log_warning "请检查日志:"; echo "  输出: tail -n 30 $LOG_FILE_OUT"; echo "  错误: tail -n 30 $LOG_FILE_ERR"; if [ "$INIT_SYSTEM" == "systemd" ]; then echo "  Systemd状态: $SERVICE_CMD status $CURRENT_HYSTERIA_SERVICE_NAME"; echo "  Systemd日志: journalctl -u $CURRENT_HYSTERIA_SERVICE_NAME -n 20 --no-pager"; fi; return 1; fi;;
        status) _log_info "Hysteria服务状态($CURRENT_HYSTERIA_SERVICE_NAME):"; $SERVICE_CMD "$action" "$CURRENT_HYSTERIA_SERVICE_NAME"; return $?;;
        enable) _ensure_root; _log_info "启用Hysteria开机自启..."; if $ENABLE_CMD_PREFIX "$CURRENT_HYSTERIA_SERVICE_NAME" $ENABLE_CMD_SUFFIX >/dev/null 2>&1; then _log_success "已启用开机自启。"; else _log_error "启用开机自启失败。"; return 1; fi;;
        disable) _ensure_root; _log_info "禁用Hysteria开机自启..."; if [[ "$INIT_SYSTEM" == "systemd" ]]; then $SERVICE_CMD disable "$CURRENT_HYSTERIA_SERVICE_NAME" >/dev/null 2>&1; elif [[ "$INIT_SYSTEM" == "openrc" ]]; then rc-update del "$CURRENT_HYSTERIA_SERVICE_NAME" default >/dev/null 2>&1; fi; _log_success "已禁用开机自启。";;
        *) _log_error "未知服务操作: $action"; return 1;;
    esac
}

_show_config() {
    _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria未安装。无配置显示。"; return 1; fi
    _log_info "当前Hysteria配置文件($HYSTERIA_CONFIG_FILE):"; echo "----------------------------------------------------"
    if [ -f "$HYSTERIA_CONFIG_FILE" ]; then cat "$HYSTERIA_CONFIG_FILE"; else _log_error "配置文件不存在。"; fi; echo "----------------------------------------------------"; _log_info "配置摘要:"
    local port=$(grep -E '^\s*listen:\s*:([0-9]+)' "$HYSTERIA_CONFIG_FILE" | sed -E 's/^\s*listen:\s*://' || echo "未知")
    local password=$(grep 'password:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^.*password:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/["'\'']//g' || echo "未知")
    local masquerade_url=$(grep '^\s*masquerade:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*url: \([^, }]*\).*/\1/p' || echo "未知"); if [ -z "$masquerade_url" ]; then masquerade_url=$(awk '/^\s*masquerade:/,/url:/{if(/url:/) print $2}' "$HYSTERIA_CONFIG_FILE" || echo "未知"); fi
    echo "  监听端口: $port"; echo "  密码: $password"; echo "  伪装URL: $masquerade_url"
    if grep -q '^\s*tls:' "$HYSTERIA_CONFIG_FILE"; then local cert_path=$(grep '^\s*tls:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*cert: \([^, }]*\).*/\1/p' || echo "未知"); local key_path=$(grep '^\s*tls:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*key: \([^ }]*\).*/\1/p' || echo "未知"); echo "  TLS模式: 自定义证书"; echo "    证书路径: $cert_path"; echo "    私钥路径: $key_path";
    elif grep -q '^\s*acme:' "$HYSTERIA_CONFIG_FILE"; then local domain=$(grep -A 1 '^\s*domains:' "$HYSTERIA_CONFIG_FILE" | grep '^\s*-\s*' | sed -e 's/^\s*-\s*//' -e 's/#.*//' -e 's/[ \t]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//'); local email=$(grep -A 2 '^\s*acme:' "$HYSTERIA_CONFIG_FILE" | grep 'email:' | sed -e 's/^\s*email:\s*//' -e 's/#.*//' -e 's/[[:space:]]*$//'); echo "  TLS模式: ACME"; echo "    域名: $domain"; echo "    邮箱: $email";
    else echo "  TLS模式: 未知"; fi; echo "----------------------------------------------------"
}

_change_config_interactive() {
    _ensure_root; _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria未安装。无法更改。"; return 1; fi
    _log_info "更改Hysteria配置(部分)"; _log_warning "此功能通过awk/sed修改配置,复杂情况可能不健壮。"; _log_warning "强烈建议备份$HYSTERIA_CONFIG_FILE。"; _log_warning "当前支持:监听端口,密码,伪装URL。"; _log_warning "如需更改TLS模式等重大配置, 请使用 'sudo ${SCRIPT_COMMAND_NAME} install' 命令。"
    CURRENT_PORT=$(grep -E '^\s*listen:\s*:([0-9]+)' "$HYSTERIA_CONFIG_FILE" | sed -E 's/^\s*listen:\s*://' || echo ""); CURRENT_PASSWORD_RAW=$(grep 'password:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^.*password:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/["'\'']//g' || echo ""); CURRENT_MASQUERADE=$(grep '^\s*masquerade:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*url: \([^, }]*\).*/\1/p' || echo ""); if [ -z "$CURRENT_MASQUERADE" ]; then CURRENT_MASQUERADE=$(awk '/^\s*masquerade:/,/url:/{if(/url:/) print $2}' "$HYSTERIA_CONFIG_FILE" || echo ""); fi
    _read_from_tty NEW_PORT "新监听端口" "$CURRENT_PORT"; NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    _read_from_tty NEW_PASSWORD_INPUT "新密码" "$CURRENT_PASSWORD_RAW"; NEW_PASSWORD=""; if [ -n "$NEW_PASSWORD_INPUT" ]; then if [ "$NEW_PASSWORD_INPUT" == "random" ]; then NEW_PASSWORD=$(_generate_uuid); _log_info "生成新随机密码:$NEW_PASSWORD"; else NEW_PASSWORD="$NEW_PASSWORD_INPUT"; fi; else NEW_PASSWORD="$CURRENT_PASSWORD_RAW"; fi
    _read_from_tty NEW_MASQUERADE_URL_INPUT "新伪装URL" "$CURRENT_MASQUERADE"; NEW_MASQUERADE=${NEW_MASQUERADE_URL_INPUT:-$CURRENT_MASQUERADE}
    CONFIG_BACKUP_FILE="${HYSTERIA_CONFIG_FILE}.bak.$(date +%s)"; cp "$HYSTERIA_CONFIG_FILE" "$CONFIG_BACKUP_FILE"; _log_info "配置文件备份至$CONFIG_BACKUP_FILE"
    local config_changed=false; temp_config_file=$(mktemp)
    if [ "$NEW_PORT" != "$CURRENT_PORT" ]; then _log_info "更改端口 '$CURRENT_PORT' -> '$NEW_PORT'..."; sed "s/^listen: :${CURRENT_PORT}/listen: :${NEW_PORT}/" "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改端口失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; rm -f "$temp_config_file"; return 1; }; config_changed=true; fi
    if [ "$NEW_PASSWORD" != "$CURRENT_PASSWORD_RAW" ]; then _log_info "更改密码..."; awk -v new_pass="$NEW_PASSWORD" 'BEGIN{pb=0} /^auth:/{pb=1;print;next} pb&&/password:/{print "  password: " new_pass;pb=0;next} pb&&NF>0&&!/^[[:space:]]/{pb=0} {print}' "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改密码失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; rm -f "$temp_config_file"; return 1; }; config_changed=true; fi
    if [ "$NEW_MASQUERADE" != "$CURRENT_MASQUERADE" ]; then _log_info "更改伪装URL '$CURRENT_MASQUERADE' -> '$NEW_MASQUERADE'..."; awk -v new_url="$NEW_MASQUERADE" 'BEGIN{mb=0} /^masquerade:/{mb=1;print;next} mb&&/url:/{print "    url: " new_url;mb=0;next} mb&&NF>0&&!/^[[:space:]]/{mb=0} {print}' "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改伪装URL失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; rm -f "$temp_config_file"; return 1; }; config_changed=true; fi
    rm -f "$temp_config_file"; if $config_changed; then _log_success "配置更新。重启服务..."; _control_service "restart"; rm -f "$CONFIG_BACKUP_FILE"; else _log_info "未配置更改。"; rm -f "$CONFIG_BACKUP_FILE"; fi
}

_show_info_and_qrcode() { # Renamed function
    _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; return 1; fi
    if ! _get_link_params_from_config; then _log_error "无法从当前配置生成信息。"; return 1; fi

    # Call the helper function to display link and QR code
    _display_link_and_qrcode
}

_update_hysteria_binary() {
    _ensure_root; _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。无法更新。"; return 1; fi
    _log_info "检查 Hysteria 程序更新..."; VERSION_OUTPUT=$("$HYSTERIA_INSTALL_PATH" version 2>/dev/null); CURRENT_VER=$(echo "$VERSION_OUTPUT" | grep '^Version:' | awk '{print $2}'); if [ -z "$CURRENT_VER" ]; then _log_warning "无法获取当前版本。尝试下载最新。"; CURRENT_VER="unknown"; else _log_info "当前版本: $CURRENT_VER"; fi
    _log_info "获取最新版本号..."; LATEST_VER_TAG=$(curl -s --connect-timeout 5 "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); if [ -z "$LATEST_VER_TAG" ]; then _log_warning "无法从 GitHub API 获取版本号。尝试下载'latest'。"; LATEST_VER_CLEAN="latest"; else LATEST_VER_CLEAN=$(echo "$LATEST_VER_TAG" | sed 's#^app/##'); _log_info "最新版本 Tag: $LATEST_VER_TAG (比较版本: $LATEST_VER_CLEAN)"; if [[ "$CURRENT_VER" == "$LATEST_VER_CLEAN" && "$CURRENT_VER" != "unknown" ]]; then _log_success "当前已是最新版本 ($CURRENT_VER)。"; return 0; fi; fi
    _log_info "下载 Hysteria (版本: ${LATEST_VER_CLEAN:-latest}) ..."; ARCH=$(uname -m); case ${ARCH} in x86_64) HYSTERIA_ARCH="amd64";; aarch64) HYSTERIA_ARCH="arm64";; armv7l) HYSTERIA_ARCH="arm";; *) _log_error "不支持架构: ${ARCH}"; return 1;; esac; TMP_HY_DOWNLOAD=$(mktemp); DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${HYSTERIA_ARCH}"; if ! wget -qO "$TMP_HY_DOWNLOAD" "$DOWNLOAD_URL"; then _log_error "下载失败! URL: $DOWNLOAD_URL"; rm -f "$TMP_HY_DOWNLOAD"; return 1; fi
    if ! file "$TMP_HY_DOWNLOAD" | grep -q "executable"; then _log_error "下载文件非可执行。"; rm -f "$TMP_HY_DOWNLOAD"; return 1; fi; chmod +x "$TMP_HY_DOWNLOAD"; DOWNLOADED_VER_OUTPUT=$("$TMP_HY_DOWNLOAD" version 2>/dev/null); DOWNLOADED_VER=$(echo "$DOWNLOADED_VER_OUTPUT" | grep '^Version:' | awk '{print $2}'); if [[ -n "$DOWNLOADED_VER" && "$DOWNLOADED_VER" == "$CURRENT_VER" && "$CURRENT_VER" != "unknown" ]]; then _log_info "下载版本($DOWNLOADED_VER)与当前相同。"; rm -f "$TMP_HY_DOWNLOAD"; return 0; elif [[ -n "$DOWNLOADED_VER" ]]; then _log_info "下载版本为: $DOWNLOADED_VER"; else _log_warning "无法获取下载文件版本号。"; fi
    _log_info "准备替换..."; _control_service "stop"; sleep 1; if mv "$TMP_HY_DOWNLOAD" "$HYSTERIA_INSTALL_PATH"; then _log_success "Hysteria已更新至$DOWNLOADED_VER(或latest)。"; if getcap "$HYSTERIA_INSTALL_PATH" 2>/dev/null | grep -q "cap_net_bind_service"; then _log_info "重应用setcap权限..."; if ! setcap 'cap_net_bind_service=+ep' "$HYSTERIA_INSTALL_PATH"; then _log_warning "重应用setcap失败。"; fi; fi; _control_service "start"; return 0; else _log_error "替换失败。"; rm -f "$TMP_HY_DOWNLOAD"; _log_info "尝试重启旧服务..."; _control_service "start"; return 1; fi
}

_update_hy_script() {
    _log_info "尝试更新'${SCRIPT_COMMAND_NAME}'管理脚本本身..."; _setup_hy_command; return $?;
}
_do_update() {
    local hy_update_ok=false; local script_update_ok=false
    _log_info "== 正在更新 Hysteria 程序 =="; if _update_hysteria_binary; then hy_update_ok=true; fi
    echo "---"; _log_info "== 正在更新 ${SCRIPT_COMMAND_NAME} 管理脚本 =="; if _update_hy_script; then script_update_ok=true; fi
    echo "---"; if $hy_update_ok && $script_update_ok ; then _log_success "更新过程完成。"; else _log_error "更新过程中遇到错误。请检查上面的日志。"; if ! $hy_update_ok; then _log_error " - Hysteria 程序更新失败。"; fi; if ! $script_update_ok; then _log_error " - 管理脚本 ${SCRIPT_COMMAND_NAME} 更新失败。"; fi; return 1; fi; return 0
}

_show_menu() {
    echo ""; _log_info "Hysteria 管理面板 (${SCRIPT_COMMAND_NAME} v$SCRIPT_VERSION - $SCRIPT_DATE)"
    echo "--------------------------------------------"; echo " 服务管理:";
    echo "   start         - 启动 Hysteria 服务"; echo "   stop          - 停止 Hysteria 服务"; echo "   restart       - 重启 Hysteria 服务"; echo "   status        - 查看 Hysteria 服务状态"; echo "   enable        - 设置 Hysteria 服务开机自启"; echo "   disable       - 禁止 Hysteria 服务开机自启"
    echo " 配置与信息:"; echo "   config        - 显示当前配置摘要"; echo "   config_edit   - (高级) 手动编辑配置文件 (\$EDITOR)"; echo "   config_change - 交互式更改部分配置 (端口, 密码, 伪装URL)"; echo "   info          - 显示当前订阅链接和二维码"
    echo " 日志查看:"; echo "   logs          - 查看 Hysteria 输出日志 ($LOG_FILE_OUT)"; echo "   logs_err      - 查看 Hysteria 错误日志 ($LOG_FILE_ERR)"
    _detect_os; if [[ "$INIT_SYSTEM" == "systemd" ]]; then echo "   logs_sys      - 查看 systemd 服务日志 (journalctl)"; fi
    echo " 安装与更新:"; echo "   install       - 安装或重新安装 Hysteria (会提示覆盖)"; echo "   update        - 更新 Hysteria 程序 和 '${SCRIPT_COMMAND_NAME}' 脚本"
    echo " 卸载:"; echo "   uninstall     - 卸载 Hysteria (自动尝试移除'${SCRIPT_COMMAND_NAME}'和qrencode包)"
    echo " 其他:"; echo "   version       - 显示此脚本和 Hysteria 版本"; echo "   help          - 显示此帮助菜单"
    echo "--------------------------------------------"; echo "用法: sudo ${SCRIPT_COMMAND_NAME} <命令>"; echo "例如: sudo ${SCRIPT_COMMAND_NAME} start"; echo "      sudo ${SCRIPT_COMMAND_NAME} update"; echo ""
    _log_info "此脚本在执行 'install' 时会尝试自动安装为 /usr/local/bin/${SCRIPT_COMMAND_NAME} 命令."
    _log_info "如果自动安装失败或想手动更新(确保URL正确):"
    echo "  sudo wget -qO \"/usr/local/bin/${SCRIPT_COMMAND_NAME}\" \"$HY_SCRIPT_URL_ON_GITHUB\" && sudo chmod +x \"/usr/local/bin/${SCRIPT_COMMAND_NAME}\""
    echo ""
}

_show_management_commands_hint() { _log_info "您可使用 'sudo ${SCRIPT_COMMAND_NAME} help' 或不带参数运行 'sudo ${SCRIPT_COMMAND_NAME}' 查看管理命令面板。"; }

# --- Main Script Logic ---
if [[ "$1" != "version" && "$1" != "help" && "$1" != "" && "$1" != "-h" && "$1" != "--help" ]]; then _detect_os; fi # Ensure OS is detected for most commands
ACTION="$1"
case "$ACTION" in
    install)          _do_install ;;
    uninstall)        _do_uninstall ;;
    update)           _do_update ;;
    start)            _control_service "start" ;;
    stop)             _control_service "stop" ;;
    restart)          _control_service "restart" ;;
    status)           _control_service "status" ;;
    enable)           _control_service "enable" ;;
    disable)          _control_service "disable" ;;
    config|show_config) _show_config ;;
    config_edit)      _ensure_root; if ! _is_hysteria_installed; then _log_error "Hysteria未安装."; exit 1; fi; if [ -z "$EDITOR" ]; then EDITOR="vi"; fi; _log_info "使用 $EDITOR 打开 $HYSTERIA_CONFIG_FILE ..."; if $EDITOR "$HYSTERIA_CONFIG_FILE"; then _log_info "编辑完成。考虑重启服务: sudo $SCRIPT_COMMAND_NAME restart"; else _log_error "编辑器 '$EDITOR' 返回错误。"; fi ;;
    config_change)    _change_config_interactive ;;
    info)             _show_info_and_qrcode ;;
    logs)             if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; exit 1; fi; if [ ! -f "$LOG_FILE_OUT" ]; then _log_error "日志文件 $LOG_FILE_OUT 不存在。"; exit 1; fi; _log_info "按 CTRL+C 退出 ($LOG_FILE_OUT)。"; tail -f "$LOG_FILE_OUT" ;;
    logs_err)         if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; exit 1; fi; if [ ! -f "$LOG_FILE_ERR" ]; then _log_error "日志文件 $LOG_FILE_ERR 不存在。"; exit 1; fi; _log_info "按 CTRL+C 退出 ($LOG_FILE_ERR)。"; tail -f "$LOG_FILE_ERR" ;;
    logs_sys)         _detect_os; if [[ "$INIT_SYSTEM" == "systemd" ]]; then _log_info "按 CTRL+C 退出 (journalctl -f)。"; journalctl -u "$CURRENT_HYSTERIA_SERVICE_NAME" -f --no-pager; else _log_error "此命令仅适用于 systemd 系统。"; fi ;;
    version)
        echo "$SCRIPT_COMMAND_NAME 管理脚本 v$SCRIPT_VERSION ($SCRIPT_DATE)"; echo "脚本文件: $SCRIPT_FILE_BASENAME"
        # Call _detect_os here if not already called, to ensure HYSTERIA_INSTALL_PATH is contextually correct for _is_hysteria_installed
        if ! _is_hysteria_installed && ! _detect_os >/dev/null 2>&1; then :; fi

        if _is_hysteria_installed && command -v "$HYSTERIA_INSTALL_PATH" &>/dev/null; then
            HY_VERSION=$("$HYSTERIA_INSTALL_PATH" version 2>/dev/null | grep '^Version:' | awk '{print $2}')
            if [ -n "$HY_VERSION" ]; then
                echo "已安装 Hysteria 版本: $HY_VERSION"
                echo "--- Hysteria 完整版本信息 ---"
                "$HYSTERIA_INSTALL_PATH" version # Run again to print full output including banner
                echo "-----------------------------"
            else
                _log_warning "无法从 '$HYSTERIA_INSTALL_PATH version' 解析版本号。尝试显示原始输出:"
                "$HYSTERIA_INSTALL_PATH" version
            fi
        else
            _log_warning "Hysteria 未安装或 $HYSTERIA_INSTALL_PATH 未找到。"
        fi ;;
    help|--help|-h|"") _show_menu ;;
    *) _log_error "未知命令: $ACTION"; _show_menu; exit 1 ;;
esac
exit 0
