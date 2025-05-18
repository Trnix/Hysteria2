#!/bin/bash

# --- Script Setup ---
SCRIPT_COMMAND_NAME="hy"
SCRIPT_FILE_BASENAME="Hysteria2.sh"
SCRIPT_VERSION="1.6.6" # Incremented version
SCRIPT_DATE="2025-05-18"

HY_SCRIPT_URL_ON_GITHUB="https://raw.githubusercontent.com/LeoJyenn/Hysteria2/main/${SCRIPT_FILE_BASENAME}"

# Hysteria Paths & Services
HYSTERIA_INSTALL_PATH="/usr/local/bin/hysteria"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
HYSTERIA_CONFIG_FILE="${HYSTERIA_CONFIG_DIR}/config.yaml"
HYSTERIA_CERTS_DIR="${HYSTERIA_CONFIG_DIR}/certs"
HYSTERIA_INSTALL_VARS_FILE="${HYSTERIA_CONFIG_DIR}/install_vars.conf"
HYSTERIA_SERVICE_NAME_SYSTEMD="hysteria.service"
HYSTERIA_SERVICE_NAME_OPENRC="hysteria"
LOG_FILE_HYSTERIA_OUT="/var/log/hysteria.log"
LOG_FILE_HYSTERIA_ERR="/var/log/hysteria.error.log"

# MTProto (mtg) Paths & Services
MTG_INSTALL_PATH="/usr/local/bin/mtg"
MTG_CONFIG_DIR="/etc/mtg"
MTG_CONFIG_FILE="${MTG_CONFIG_DIR}/config.toml"
MTG_VARS_FILE="${MTG_CONFIG_DIR}/install_vars_mtg.conf"
MTG_SERVICE_NAME_SYSTEMD="mtg.service"
MTG_SERVICE_NAME_OPENRC="mtg"
LOG_FILE_MTG_OUT="/var/log/mtg.log"
LOG_FILE_MTG_ERR="/var/log/mtg.error.log"
MTG_TARGET_VERSION="2.1.7"

# --- Color Definitions ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Global OS Detection Variables ---
DISTRO_FAMILY=""; PKG_INSTALL_CMD=""; PKG_UPDATE_CMD=""; PKG_REMOVE_CMD=""
INIT_SYSTEM=""; SERVICE_CMD_SYSTEMCTL="systemctl"; SERVICE_CMD_OPENRC="rc-service";
ENABLE_CMD_PREFIX=""; ENABLE_CMD_SUFFIX=""
SETCAP_DEPENDENCY_PKG=""; REQUIRED_PKGS_OS_SPECIFIC="";
QRENCODE_PACKAGE_NAME=""
MTG_LINK_VAR=""

# --- Utility Functions ---
_log_error() { echo -e "${RED}错误: $1${NC}" >&2; }
_log_success() { echo -e "${GREEN}$1${NC}" >&2; }
_log_warning() { echo -e "${YELLOW}警告: $1${NC}" >&2; }
_log_info() { echo -e "${BLUE}信息: $1${NC}" >&2; }
_log_debug() { :; }

_ensure_root() { if [ "$(id -u)" -ne 0 ]; then _log_error "此操作需 root 权限。请用 sudo。"; exit 1; fi; }
_read_from_tty() { local var_name="$1"; local prompt_str="$2"; local default_val_display="$3"; local actual_prompt="${BLUE}${prompt_str}${NC}"; if [ -n "$default_val_display" ]; then actual_prompt="${BLUE}${prompt_str} (当前: ${default_val_display:-未设置}, 回车不改): ${NC}"; if [[ "$prompt_str" == *"密码"* && -n "$default_val_display" ]]; then actual_prompt="${BLUE}${prompt_str} (当前: ******, 回车不改, 输入'random'生成): ${NC}"; elif [[ "$prompt_str" == *"密码"* ]]; then actual_prompt="${BLUE}${prompt_str} (回车随机, 输入'random'生成): ${NC}"; fi; fi; echo -n -e "$actual_prompt"; read "$var_name" </dev/tty; }
_read_confirm_tty() { local var_name="$1"; local prompt_str="$2"; echo -n -e "${YELLOW}${prompt_str}${NC}"; read "$var_name" </dev/tty; }

_detect_os() {
    if [ -n "$DISTRO_FAMILY" ]; then return 0; fi
    QRENCODE_PACKAGE_NAME=""
    if [ -f /etc/os-release ]; then . /etc/os-release
        if [[ "$ID" == "alpine" ]]; then DISTRO_FAMILY="alpine";
        elif [[ "$ID" == "debian" || "$ID" == "ubuntu" || "$ID_LIKE" == *"debian"* || "$ID_LIKE" == *"ubuntu"* ]]; then DISTRO_FAMILY="debian";
        elif [[ "$ID" == "rhel" || "$ID" == "centos" || "$ID" == "rocky" || "$ID" == "almalinux" || "$ID_LIKE" == *"rhel"* || "$ID_LIKE" == *"fedora"* ]]; then DISTRO_FAMILY="rhel";
        else _log_error "不支持发行版 '$ID'."; exit 1; fi
    elif command -v apk >/dev/null 2>&1; then DISTRO_FAMILY="alpine";
    elif command -v apt-get >/dev/null 2>&1; then DISTRO_FAMILY="debian";
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then DISTRO_FAMILY="rhel";
    else _log_error "无法确定发行版."; exit 1; fi

    if [[ "$DISTRO_FAMILY" == "alpine" ]]; then
        PKG_INSTALL_CMD="apk add --no-cache"; PKG_UPDATE_CMD="apk update"; PKG_REMOVE_CMD="apk del";
        INIT_SYSTEM="openrc"; ENABLE_CMD_PREFIX="rc-update add"; ENABLE_CMD_SUFFIX="default";
        SETCAP_DEPENDENCY_PKG="libcap"; REQUIRED_PKGS_OS_SPECIFIC="openrc ca-certificates";
        QRENCODE_PACKAGE_NAME="libqrencode-tools";
    elif [[ "$DISTRO_FAMILY" == "debian" || "$DISTRO_FAMILY" == "rhel" ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            export DEBIAN_FRONTEND=noninteractive; PKG_INSTALL_CMD="apt-get install -y -q"; PKG_UPDATE_CMD="apt-get update -q"; PKG_REMOVE_CMD="apt-get remove -y -q";
            SETCAP_DEPENDENCY_PKG="libcap2-bin";
        else
            PKG_INSTALL_CMD="dnf install -y -q"; PKG_UPDATE_CMD="dnf makecache -y -q"; PKG_REMOVE_CMD="dnf remove -y -q";
            if ! command -v dnf &>/dev/null && command -v yum &>/dev/null; then
                PKG_INSTALL_CMD="yum install -y -q"; PKG_UPDATE_CMD="yum makecache -y -q"; PKG_REMOVE_CMD="yum remove -y -q";
            fi
            SETCAP_DEPENDENCY_PKG="libcap";
        fi
        INIT_SYSTEM="systemd"; ENABLE_CMD_PREFIX="systemctl enable"; ENABLE_CMD_SUFFIX="";
        REQUIRED_PKGS_OS_SPECIFIC="ca-certificates";
        QRENCODE_PACKAGE_NAME="qrencode";
    else
        _log_error "在 _detect_os 中未能识别或支持的发行版家族 '$DISTRO_FAMILY' 以设置包命令。"
        exit 1
    fi
}

_install_dependencies() {
    _log_info "更新包列表 (${DISTRO_FAMILY})...";
    if ! $PKG_UPDATE_CMD >/dev/null; then
        _log_error "更新包列表 (${PKG_UPDATE_CMD}) 失败。请检查上面可能显示的错误信息，以及您的网络和软件源配置。"
        exit 1
    fi
    _log_debug "检查并安装依赖包..."
    REQUIRED_PKGS_COMMON="wget curl git openssl lsof coreutils"
    REQUIRED_PKGS="$REQUIRED_PKGS_COMMON"
    if [ -n "$QRENCODE_PACKAGE_NAME" ]; then REQUIRED_PKGS="$REQUIRED_PKGS $QRENCODE_PACKAGE_NAME"; fi
    if [ -n "$REQUIRED_PKGS_OS_SPECIFIC" ]; then REQUIRED_PKGS="$REQUIRED_PKGS $REQUIRED_PKGS_OS_SPECIFIC"; fi

    if ! command -v realpath &>/dev/null ; then
        local coreutils_installed=false
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then if dpkg-query -W -f='${Status}' coreutils 2>/dev/null | grep -q "install ok installed"; then coreutils_installed=true; fi
        elif [[ "$DISTRO_FAMILY" == "alpine" ]]; then if apk info -e coreutils &>/dev/null; then coreutils_installed=true; fi
        elif [[ "$DISTRO_FAMILY" == "rhel" ]]; then if rpm -q coreutils &>/dev/null; then coreutils_installed=true; fi
        fi
        if ! $coreutils_installed || ! command -v realpath &>/dev/null ; then
            _log_debug "核心工具 'realpath' (通常由coreutils提供) 未找到或coreutils未安装, 尝试安装 'coreutils'..."
            if ! $PKG_INSTALL_CMD coreutils >/dev/null; then _log_warning "尝试安装/确保 coreutils 失败。" ; fi
        fi
        if ! command -v realpath &>/dev/null; then _log_error "realpath 命令在安装 coreutils 后仍然不可用。请检查您的系统。"; exit 1; fi
    fi
    local missing_pkgs_arr=()
    for pkg in $REQUIRED_PKGS; do
        installed=false
        if [[ "$DISTRO_FAMILY" == "alpine" ]]; then if apk info -e "$pkg" &>/dev/null; then installed=true; fi
        elif [[ "$DISTRO_FAMILY" == "debian" ]]; then if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then installed=true; fi
        elif [[ "$DISTRO_FAMILY" == "rhel" ]]; then if rpm -q "$pkg" >/dev/null 2>&1; then installed=true; fi
        fi
        if ! $installed; then missing_pkgs_arr+=("$pkg"); fi
    done

    if [ ${#missing_pkgs_arr[@]} -gt 0 ]; then
        _log_info "下列依赖包需要安装: ${missing_pkgs_arr[*]}"
        if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
            _log_debug "正在尝试一次性安装所有 RHEL 缺失依赖..."
            if ! $PKG_INSTALL_CMD "${missing_pkgs_arr[@]}" >/dev/null; then
                 _log_error "一次性安装 RHEL 依赖失败。将尝试逐个安装..."
                 for pkg_item in "${missing_pkgs_arr[@]}"; do
                    _log_debug "正在安装 $pkg_item..."
                    if ! $PKG_INSTALL_CMD "$pkg_item" >/dev/null; then
                        _log_error "安装 $pkg_item 失败。请检查上面可能显示的错误信息，或手动运行安装命令查看。"
                        exit 1
                    fi
                done
            fi
        else
            for pkg_item in "${missing_pkgs_arr[@]}"; do
                _log_debug "正在安装 $pkg_item..."
                if ! $PKG_INSTALL_CMD "$pkg_item" >/dev/null; then
                    _log_error "安装 $pkg_item 失败。请检查上面可能显示的错误信息，或手动运行安装命令查看。"
                    exit 1
                fi
            done
        fi
    else
        _log_debug "所有基础依赖已满足。"
    fi
    _log_success "依赖包检查与安装完成。"
}

_generate_uuid() { local bytes=$(od -x -N 16 /dev/urandom | head -1 | awk '{OFS=""; $1=""; print}'); local byte7=${bytes:12:4}; byte7=$((0x${byte7} & 0x0fff | 0x4000)); byte7=$(printf "%04x" $byte7); local byte9=${bytes:20:4}; byte9=$((0x${byte9} & 0x3fff | 0x8000)); byte9=$(printf "%04x" $byte9); echo "${bytes:0:8}-${bytes:8:4}-${byte7}-${byte9}-${bytes:24:12}" | tr '[:upper:]' '[:lower:]'; }
_generate_random_lowercase_string() { LC_ALL=C tr -dc 'a-z' < /dev/urandom | head -c 8; }
_get_server_address() { local ipv6_ip; local ipv4_ip; _log_debug "检测公网IP..."; _log_debug "尝试IPv6..."; ipv6_ip=$(curl -s -m 5 -6 https://ifconfig.me || curl -s -m 5 -6 https://ip.sb || curl -s -m 5 -6 https://api64.ipify.org); if [ -n "$ipv6_ip" ] && [[ "$ipv6_ip" == *":"* ]]; then _log_debug "IPv6: $ipv6_ip"; echo "[$ipv6_ip]"; return; else _log_debug "无IPv6."; fi; _log_debug "尝试IPv4..."; ipv4_ip=$(curl -s -m 5 -4 https://ifconfig.me || curl -s -m 5 -4 https://ip.sb || curl -s -m 5 -4 https://api.ipify.org); if [ -n "$ipv4_ip" ] && [[ "$ipv4_ip" != *":"* ]]; then _log_debug "IPv4: $ipv4_ip"; echo "$ipv4_ip"; return; else _log_debug "无IPv4."; fi; _log_error "无法获取公网IP."; exit 1; }

_setup_hy_command() {
    _ensure_root; local installed_script_path="/usr/local/bin/${SCRIPT_COMMAND_NAME}"; _log_info "设置/更新 '${SCRIPT_COMMAND_NAME}' 命令到 ${installed_script_path}...";
    if [[ "$HY_SCRIPT_URL_ON_GITHUB" == *"YOUR_USERNAME"* || "$HY_SCRIPT_URL_ON_GITHUB" == "" ]]; then _log_error "HY_SCRIPT_URL_ON_GITHUB 未配置! 无法自动下载脚本。"; _log_warning "请编辑脚本顶部的 HY_SCRIPT_URL_ON_GITHUB 设置正确URL，或手动复制:"; _log_warning "sudo cp \"${0:-${SCRIPT_FILE_BASENAME}}\" \"${installed_script_path}\" && sudo chmod +x \"${installed_script_path}\""; return 1; fi
    _log_info "从URL(${HY_SCRIPT_URL_ON_GITHUB})下载最新脚本..."; TMP_SCRIPT_DOWNLOAD_PATH=$(mktemp);
    if ! wget -qO "$TMP_SCRIPT_DOWNLOAD_PATH" "$HY_SCRIPT_URL_ON_GITHUB"; then _log_error "下载脚本失败 (wget出错)。"; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi
    if ! head -n 1 "$TMP_SCRIPT_DOWNLOAD_PATH" | grep -q -E "^#!/(usr/)?bin/(bash|sh)"; then _log_error "下载的内容似乎不是一个有效的shell脚本。URL: $HY_SCRIPT_URL_ON_GITHUB"; _log_warning "文件开头: $(head -n 1 "$TMP_SCRIPT_DOWNLOAD_PATH")"; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi
    local needs_update=true; if [ -f "$installed_script_path" ]; then if cmp -s "$TMP_SCRIPT_DOWNLOAD_PATH" "$installed_script_path"; then _log_info "下载的脚本与已安装的 '${SCRIPT_COMMAND_NAME}' 内容相同。无需更新文件。"; needs_update=false; else _log_info "检测到已安装脚本与远程脚本内容不同。"; fi else _log_info "'${SCRIPT_COMMAND_NAME}' 命令尚未安装。"; fi
    if $needs_update; then if [ -f "$installed_script_path" ]; then _log_info "备份现有命令 ${installed_script_path} 到 ${installed_script_path}.old.$(date +%s)..."; if ! cp "$installed_script_path" "${installed_script_path}.old.$(date +%s)"; then _log_error "备份失败！请检查权限。"; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi; fi; _log_info "正在安装/更新到 ${installed_script_path}..."; if mv "$TMP_SCRIPT_DOWNLOAD_PATH" "$installed_script_path"; then chmod +x "$installed_script_path"; _log_success "'${SCRIPT_COMMAND_NAME}' 命令已成功安装/更新。"; else _log_error "移动下载脚本到 ${installed_script_path} 失败。"; rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 1; fi; else if [ -f "$installed_script_path" ] && [ ! -x "$installed_script_path" ]; then chmod +x "$installed_script_path"; _log_info "已为 ${installed_script_path} 设置执行权限。"; fi; fi
    rm -f "$TMP_SCRIPT_DOWNLOAD_PATH"; return 0
}
_get_remote_script_version() { local remote_version_line; remote_version_line=$(curl -s --connect-timeout 10 "${HY_SCRIPT_URL_ON_GITHUB}" 2>/dev/null | head -n 20 | grep '^SCRIPT_VERSION='); if [ -n "$remote_version_line" ]; then echo "$remote_version_line" | awk -F'"' '/^SCRIPT_VERSION=/{print $2}'; else echo ""; fi; }
_update_hy_script() {
    _log_info "== 正在更新 ${SCRIPT_COMMAND_NAME} 管理脚本 (当前 v${SCRIPT_VERSION}) =="; if [[ "$HY_SCRIPT_URL_ON_GITHUB" == *"YOUR_USERNAME"* || "$HY_SCRIPT_URL_ON_GITHUB" == "" ]]; then _log_error "HY_SCRIPT_URL_ON_GITHUB 未配置! 无法检查脚本更新。"; return 1; fi
    _log_info "正在从 ${HY_SCRIPT_URL_ON_GITHUB} 获取远程脚本版本号 ..."; REMOTE_SCRIPT_VERSION=$(_get_remote_script_version);
    if [ -z "$REMOTE_SCRIPT_VERSION" ]; then _log_warning "无法获取远程脚本版本号。将尝试通过内容比较进行更新 (如果需要)...";
    elif [[ "$SCRIPT_VERSION" == "$REMOTE_SCRIPT_VERSION" ]]; then _log_success "当前管理脚本 (v${SCRIPT_VERSION}) 已是最新版本 (远程版本 v${REMOTE_SCRIPT_VERSION})。"; _log_info "仍将检查 ${SCRIPT_COMMAND_NAME} 命令是否正确安装...";
    else _log_info "检测到新版本管理脚本 (远程: v${REMOTE_SCRIPT_VERSION}, 当前: v${SCRIPT_VERSION})。准备更新..."; fi
    if _setup_hy_command; then if [ -n "$REMOTE_SCRIPT_VERSION" ] && [[ "$SCRIPT_VERSION" != "$REMOTE_SCRIPT_VERSION" ]]; then local new_installed_version=""; if [ -f "/usr/local/bin/${SCRIPT_COMMAND_NAME}" ]; then new_installed_version=$(grep '^SCRIPT_VERSION=' "/usr/local/bin/${SCRIPT_COMMAND_NAME}" | awk -F'"' '{print $2}' || echo "未知"); fi; _log_info "脚本文件已更新至 v${new_installed_version:-$REMOTE_SCRIPT_VERSION}。请重新运行 'sudo ${SCRIPT_COMMAND_NAME} <命令>' 以使用新版本。"; fi; return 0;
    else _log_error "管理脚本 ${SCRIPT_COMMAND_NAME} 更新失败。"; return 1; fi
}
_get_ip_geolocation_remark() {
    local geo_info country_code country_name_en country_cn remark
    _log_debug "正在获取服务器地理位置信息以生成备注..."
    geo_info=$(curl -s --connect-timeout 8 http://ip-api.com/json/)
    if [ -z "$geo_info" ]; then _log_warning "无法获取地理位置信息 (curl失败或超时)。将使用默认备注。"; echo ""; return; fi
    if ! echo "$geo_info" | grep -q '"status":"success"'; then local error_message=$(echo "$geo_info" | grep -o '"message":"[^"]*"' | awk -F'"' '{print $4}'); _log_warning "地理位置API返回错误: ${error_message:-未知API错误}。将使用默认备注。"; echo ""; return; fi
    country_code=$(echo "$geo_info" | grep -o '"countryCode":"[^"]*"' | awk -F'"' '{print $4}')
    country_name_en=$(echo "$geo_info" | grep -o '"country":"[^"]*"' | awk -F'"' '{print $4}')
    if [ -z "$country_code" ]; then _log_warning "无法从API响应解析国家代码。将使用默认备注。"; echo ""; return; fi
    case "$country_code" in
        "US") country_cn="美国";; "DE") country_cn="德国";; "JP") country_cn="日本";;
        "SG") country_cn="新加坡";; "HK") country_cn="香港";; "MO") country_cn="澳门";;
        "TW") country_cn="台湾";; "CN") country_cn="中国大陆";; "GB") country_cn="英国";;
        "NL") country_cn="荷兰";; "FR") country_cn="法国";; "CA") country_cn="加拿大";;
        "AU") country_cn="澳大利亚";; "KR") country_cn="韩国";; "RU") country_cn="俄罗斯";;
        "MY") country_cn="马来西亚";; "TH") country_cn="泰国";; "VN") country_cn="越南";;
        "ID") country_cn="印尼";; "PH") country_cn="菲律宾";; "IN") country_cn="印度";;
        "TR") country_cn="土耳其";; "AE") country_cn="阿联酋";;
        *) if [ -n "$country_name_en" ]; then country_cn="$country_name_en"; else country_cn="未知地区"; fi ;;
    esac
    if [[ "$country_cn" == "未知地区" && -n "$country_code" ]]; then remark="地区${country_code}-Hysteria";
    elif [[ "$country_cn" == "未知地区" ]]; then _log_warning "无法确定有效的国家名称或代码。将使用默认备注。"; echo ""; return;
    else remark="${country_cn}Hysteria-${country_code}"; fi
    _log_debug "根据地理位置生成备注: ${remark}"; echo "$remark"
}

# --- Generic Service Control ---
_generic_control_service() {
    local service_type="$1"; local action="$2"; _detect_os
    local current_service_name_val log_out_val log_err_val service_cmd_val is_installed_func service_name_systemd_val service_name_openrc_val
    if [[ "$service_type" == "hysteria" ]]; then
        is_installed_func="_is_hysteria_installed"; service_name_systemd_val="$HYSTERIA_SERVICE_NAME_SYSTEMD"; service_name_openrc_val="$HYSTERIA_SERVICE_NAME_OPENRC";
        log_out_val="$LOG_FILE_HYSTERIA_OUT"; log_err_val="$LOG_FILE_HYSTERIA_ERR";
    elif [[ "$service_type" == "mtg" ]]; then
        is_installed_func="_is_mtg_installed"; service_name_systemd_val="$MTG_SERVICE_NAME_SYSTEMD"; service_name_openrc_val="$MTG_SERVICE_NAME_OPENRC";
        log_out_val="$LOG_FILE_MTG_OUT"; log_err_val="$LOG_FILE_MTG_ERR";
    else _log_error "内部错误: 未知的服务类型 '$service_type'。"; return 1; fi

    if [[ "$INIT_SYSTEM" == "systemd" ]]; then current_service_name_val="$service_name_systemd_val"; service_cmd_val="$SERVICE_CMD_SYSTEMCTL";
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then current_service_name_val="$service_name_openrc_val"; service_cmd_val="$SERVICE_CMD_OPENRC";
    else _log_error "不支持的初始化系统: $INIT_SYSTEM"; return 1; fi

    local service_file_exists=false
    if [[ "$INIT_SYSTEM" == "systemd" ]] && [ -f "/etc/systemd/system/$current_service_name_val" ]; then service_file_exists=true;
    elif [[ "$INIT_SYSTEM" == "openrc" ]] && [ -f "/etc/init.d/$current_service_name_val" ]; then service_file_exists=true; fi

    if ! $is_installed_func && ! ( [[ "$action" == "enable" || "$action" == "disable" ]] && $service_file_exists ) ; then
        if $is_installed_func; then : ; else _log_error "${service_type^} 服务未安装或服务未配置。 (Action: $action)"; return 1; fi
    fi

    local cmd_to_run=""
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then cmd_to_run="$service_cmd_val $action $current_service_name_val"
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then cmd_to_run="$service_cmd_val $current_service_name_val $action"
    else _log_error "不支持的初始化系统构造命令: $INIT_SYSTEM (action: $action)"; return 1; fi

    case "$action" in
        start|stop|restart)
            _ensure_root; _log_info "执行 (${service_type^}): $cmd_to_run"
            local cmd_output cmd_exit_code; cmd_output=$(eval "$cmd_to_run" 2>&1); cmd_exit_code=$?
            if [[ "$INIT_SYSTEM" == "openrc" && ("$action" == "stop" || "$action" == "restart") ]]; then
                if echo "$cmd_output" | grep -q "service .* already stopped"; then _log_warning "${service_type^} 服务 '$current_service_name_val' 在尝试停止时已停止。"; if [[ "$action" == "stop" ]]; then cmd_exit_code=0; fi; fi
                if [[ "$action" == "restart" && $cmd_exit_code -ne 0 && $(echo "$cmd_output" | grep -q "service .* already stopped") ]]; then
                     _log_debug "由于 ${service_type^} 服务已停止，现在尝试启动 (作为 restart 的一部分)..."; local start_cmd="$service_cmd_val $current_service_name_val start"; cmd_output=$(eval "$start_cmd" 2>&1); cmd_exit_code=$?;
                elif [[ "$action" == "restart" && $cmd_exit_code -eq 0 && $(echo "$cmd_output" | grep -q "Stopping ${current_service_name_val}") && ! $(echo "$cmd_output" | grep -q "Starting ${current_service_name_val}") ]]; then
                     _log_debug "${service_type^} 服务已停止，现在尝试启动 (作为 restart 的一部分)..."; local start_cmd="$service_cmd_val $current_service_name_val start"; cmd_output=$(eval "$start_cmd" 2>&1); cmd_exit_code=$?; fi
            fi
            if [ $cmd_exit_code -eq 0 ]; then _log_success "操作 '$action' (${service_type^}) 成功。";
                if [[ "$action" == "start" || "$action" == "restart" ]]; then sleep 1; local status_cmd_to_run="";
                    if [[ "$INIT_SYSTEM" == "systemd" ]]; then status_cmd_to_run="$service_cmd_val status $current_service_name_val"; elif [[ "$INIT_SYSTEM" == "openrc" ]]; then status_cmd_to_run="$service_cmd_val $current_service_name_val status"; fi
                    if [ -n "$status_cmd_to_run" ]; then status_output=$($status_cmd_to_run 2>&1 | head -n 7); echo "$status_output"; fi
                fi
            else
                 _log_error "操作 '$action' (${service_type^}) 失败。输出:"
                 if [[ "$action" == "stop" && ("$service_type" == "hysteria" || "$service_type" == "mtg") ]]; then
                    echo "$cmd_output" | grep -vE "Service Executable path is not absolute|a \.service file without \[Service\] section" || echo " (无特定于 $service_type 的错误信息从服务停止命令)"
                 else
                    echo "$cmd_output"
                 fi
                _log_warning "请检查 ${service_type^} 日志:"; echo "  输出: tail -n 30 $log_out_val"; echo "  错误: tail -n 30 $log_err_val";
                if [ "$INIT_SYSTEM" == "systemd" ]; then echo "  Systemd状态: $SERVICE_CMD_SYSTEMCTL status $current_service_name_val"; echo "  Systemd日志: journalctl -u $current_service_name_val -n 20 --no-pager";
                elif [ "$INIT_SYSTEM" == "openrc" ]; then echo "  OpenRC状态: $SERVICE_CMD_OPENRC $current_service_name_val status"; fi; return 1;
            fi;;
        status)
            _log_info "${service_type^} 服务状态 ($current_service_name_val):"
            if [[ "$INIT_SYSTEM" == "systemd" ]]; then cmd_to_run="$service_cmd_val $action $current_service_name_val"; elif [[ "$INIT_SYSTEM" == "openrc" ]]; then cmd_to_run="$service_cmd_val $current_service_name_val $action"; else return 1; fi
            eval "$cmd_to_run"; return $?;;
        enable)
            _ensure_root; _log_info "启用 ${service_type^} 开机自启...";
            if $ENABLE_CMD_PREFIX "$current_service_name_val" $ENABLE_CMD_SUFFIX >/dev/null 2>&1; then _log_success "已启用 ${service_type^} 开机自启。"; else _log_error "启用 ${service_type^} 开机自启失败。"; return 1; fi;;
        disable)
            _ensure_root; _log_info "禁用 ${service_type^} 开机自启..."; local disable_cmd_ok=false;
            if [[ "$INIT_SYSTEM" == "systemd" ]]; then if $service_cmd_val disable "$current_service_name_val" >/dev/null 2>/dev/null; then disable_cmd_ok=true; fi
            elif [[ "$INIT_SYSTEM" == "openrc" ]]; then if rc-update del "$current_service_name_val" default >/dev/null 2>&1; then disable_cmd_ok=true; fi; fi
            if $disable_cmd_ok; then _log_success "已禁用 ${service_type^} 开机自启。"; else _log_error "禁用 ${service_type^} 开机自启失败"; return 1; fi;;
        *) _log_error "未知服务操作: $action (针对 ${service_type^})"; return 1;;
    esac
}

# --- Hysteria Functions ---
_is_hysteria_installed() { _detect_os; if [ -f "$HYSTERIA_INSTALL_PATH" ] && [ -f "$HYSTERIA_CONFIG_FILE" ]; then if [ "$INIT_SYSTEM" == "systemd" ] && [ -f "/etc/systemd/system/$HYSTERIA_SERVICE_NAME_SYSTEMD" ]; then return 0; elif [ "$INIT_SYSTEM" == "openrc" ] && [ -f "/etc/init.d/$HYSTERIA_SERVICE_NAME_OPENRC" ]; then return 0; fi; fi; return 1; }
_get_hysteria_link_params() { unset HY_PASSWORD HY_LINK_ADDRESS HY_PORT HY_LINK_SNI HY_LINK_INSECURE HY_SNI_VALUE DOMAIN_FROM_CONFIG CERT_PATH_FROM_CONFIG KEY_PATH_FROM_CONFIG; if [ ! -f "$HYSTERIA_CONFIG_FILE" ]; then _log_error "Hysteria 配置文件 $HYSTERIA_CONFIG_FILE 未找到。"; return 1; fi; _log_debug "正从 $HYSTERIA_CONFIG_FILE 解析 Hysteria 配置以生成链接..."; HY_PORT=$(grep -E '^\s*listen:\s*:([0-9]+)' "$HYSTERIA_CONFIG_FILE" | sed -E 's/^\s*listen:\s*://' || echo ""); HY_PASSWORD=$(grep 'password:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^.*password:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/["'\'']//g' || echo ""); if grep -q '^\s*acme:' "$HYSTERIA_CONFIG_FILE"; then _log_debug "检测到 Hysteria ACME 配置。"; DOMAIN_FROM_CONFIG=$(grep -A 1 '^\s*domains:' "$HYSTERIA_CONFIG_FILE" | grep '^\s*-\s*' | sed -e 's/^\s*-\s*//' -e 's/#.*//' -e 's/[ \t]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//'); if [ -z "$DOMAIN_FROM_CONFIG" ]; then _log_error "无法从 Hysteria 配置解析ACME域名。"; return 1; fi; HY_LINK_SNI="$DOMAIN_FROM_CONFIG"; HY_LINK_ADDRESS="$DOMAIN_FROM_CONFIG"; HY_LINK_INSECURE="0"; HY_SNI_VALUE="$DOMAIN_FROM_CONFIG"; elif grep -q '^\s*tls:' "$HYSTERIA_CONFIG_FILE"; then _log_debug "检测到 Hysteria 自定义 TLS 配置。"; CERT_PATH_FROM_CONFIG=$(grep '^\s*cert:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^\s*cert:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//' || echo ""); if [ -z "$CERT_PATH_FROM_CONFIG" ]; then _log_error "无法从 Hysteria 配置解析证书路径。"; return 1; fi; if [[ "$CERT_PATH_FROM_CONFIG" != /* ]]; then CERT_PATH_FROM_CONFIG="${HYSTERIA_CONFIG_DIR}/${CERT_PATH_FROM_CONFIG}"; fi; if command -v realpath &>/dev/null; then CERT_PATH_FROM_CONFIG=$(realpath -m "$CERT_PATH_FROM_CONFIG" 2>/dev/null || echo "$CERT_PATH_FROM_CONFIG"); fi; if [ ! -f "$CERT_PATH_FROM_CONFIG" ]; then _log_error "Hysteria 配置文件中的证书路径 '$CERT_PATH_FROM_CONFIG' 无效或文件不存在。"; return 1; fi; _log_debug "Hysteria 证书路径: $CERT_PATH_FROM_CONFIG"; _log_debug "尝试从证书提取 SNI..."; HY_SNI_VALUE=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CERT_PATH_FROM_CONFIG" 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p'); if [ -z "$HY_SNI_VALUE" ]; then HY_SNI_VALUE=$(openssl x509 -noout -subject -in "$CERT_PATH_FROM_CONFIG" 2>/dev/null | sed -n 's/.*CN ?= ?\([^,]*\).*/\1/p' | head -n 1 | sed 's/^[ \t]*//;s/[ \t]*$//'); fi; if [ -z "$HY_SNI_VALUE" ]; then HY_SNI_VALUE=$(openssl x509 -noout -text -in "$CERT_PATH_FROM_CONFIG" 2>/dev/null | grep 'DNS:' | head -n 1 | sed 's/.*DNS://' | tr -d ' ' | cut -d, -f1); fi; if [ -z "$HY_SNI_VALUE" ]; then _log_warning "无法提取有效SNI(CN或SAN), 使用'sni_unknown'代替。"; HY_SNI_VALUE="sni_unknown"; else _log_debug "提取到 SNI: $HY_SNI_VALUE"; fi; HY_LINK_SNI="$HY_SNI_VALUE"; HY_LINK_ADDRESS=$(_get_server_address); if [ $? -ne 0 ] || [ -z "$HY_LINK_ADDRESS" ]; then _log_error "获取公网地址失败。"; return 1; fi; HY_LINK_INSECURE="1"; else _log_error "无法确定 Hysteria TLS模式。"; return 1; fi; if [ -z "$HY_PORT" ] || [ -z "$HY_PASSWORD" ] || [ -z "$HY_LINK_ADDRESS" ] || [ -z "$HY_LINK_SNI" ] || [ -z "$HY_LINK_INSECURE" ] || [ -z "$HY_SNI_VALUE" ]; then _log_error "未能解析生成 Hysteria 链接所需的所有参数。"; return 1; fi; return 0; }
_display_hysteria_link_and_qrcode() { local final_remark geo_remark; geo_remark=$(_get_ip_geolocation_remark); if [ -n "$geo_remark" ]; then final_remark="$geo_remark"; else _log_debug "无法生成地理位置备注，将使用基于SNI的默认备注。"; final_remark="Hysteria-${HY_SNI_VALUE}"; fi; local hysteria_subscription_link="hysteria2://${HY_PASSWORD}@${HY_LINK_ADDRESS}:${HY_PORT}/?sni=${HY_LINK_SNI}&alpn=h3&insecure=${HY_LINK_INSECURE}#${final_remark}"; echo ""; _log_info "Hysteria 订阅链接 (备注: ${final_remark}):"; echo -e "${GREEN}${hysteria_subscription_link}${NC}"; echo ""; if command -v qrencode &>/dev/null; then _log_info "Hysteria 订阅链接二维码:"; qrencode -t ANSIUTF8 "$hysteria_subscription_link"; else _log_warning "提示: 'qrencode' 未安装, 无法显示二维码。"; local pkg_name="${QRENCODE_PACKAGE_NAME:-qrencode}"; _log_info "(可运行 'sudo $PKG_INSTALL_CMD ${pkg_name}' 安装)"; fi; echo ""; }
_show_hysteria_info_and_qrcode() { _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; return 1; fi; if ! _get_hysteria_link_params; then _log_error "无法从当前 Hysteria 配置生成信息。"; return 1; fi; _display_hysteria_link_and_qrcode; }
_do_install_hysteria() { _ensure_root; _detect_os; if _is_hysteria_installed; then _read_confirm_tty confirm_install "Hysteria 已安装。是否强制安装(覆盖配置)? [y/N]: "; if [[ "$confirm_install" != "y" && "$confirm_install" != "Y" ]]; then _log_info "Hysteria 安装取消。"; exit 0; fi; _log_warning "正强制安装 Hysteria..."; fi; _log_info "--- 开始 Hysteria 依赖安装 ---"; _install_dependencies; _log_info "--- Hysteria 依赖安装结束 ---"; DEFAULT_MASQUERADE_URL="https://www.bing.com"; DEFAULT_PORT="34567"; DEFAULT_ACME_EMAIL="$(_generate_random_lowercase_string)@gmail.com"; echo ""; _log_info "请选择 Hysteria TLS 验证方式:"; echo "1. 自定义证书"; echo "2. ACME HTTP 验证"; _read_from_tty TLS_TYPE "选择 [1-2, 默认 1]: "; TLS_TYPE=${TLS_TYPE:-1}; CERT_PATH=""; KEY_PATH=""; DOMAIN=""; SNI_VALUE=""; ACME_EMAIL=""; case $TLS_TYPE in 1) _log_info "--- 自定义证书模式 ---"; _read_from_tty USER_CERT_PATH "证书路径(.crt/.pem)(留空则自签): "; if [ -z "$USER_CERT_PATH" ]; then _log_info "将生成自签名证书。"; if ! command -v openssl &>/dev/null; then _log_error "openssl未安装 ($PKG_INSTALL_CMD openssl)"; exit 1; fi; _read_from_tty SELF_SIGN_SNI "自签名证书SNI(默认www.bing.com): "; SELF_SIGN_SNI=${SELF_SIGN_SNI:-"www.bing.com"}; SNI_VALUE="$SELF_SIGN_SNI"; mkdir -p "$HYSTERIA_CERTS_DIR"; CERT_PATH="$HYSTERIA_CERTS_DIR/server.crt"; KEY_PATH="$HYSTERIA_CERTS_DIR/server.key"; _log_debug "正生成自签证书(CN=$SNI_VALUE)..."; if ! openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=$SNI_VALUE" -days 36500 >/dev/null 2>&1; then _log_error "自签证书生成失败!"; exit 1; fi; _log_success "自签证书已生成: $CERT_PATH, $KEY_PATH"; else _log_info "提供证书路径: $USER_CERT_PATH"; _read_from_tty USER_KEY_PATH "私钥路径(.key/.pem): "; if [ -z "$USER_KEY_PATH" ]; then _log_error "私钥路径不能为空。"; exit 1; fi; TMP_CERT_PATH=$(realpath "$USER_CERT_PATH" 2>/dev/null); TMP_KEY_PATH=$(realpath "$USER_KEY_PATH" 2>/dev/null); if [ ! -f "$TMP_CERT_PATH" ]; then _log_error "证书'$USER_CERT_PATH'('$TMP_CERT_PATH')无效."; exit 1; fi; if [ ! -f "$TMP_KEY_PATH" ]; then _log_error "私钥'$USER_KEY_PATH'('$TMP_KEY_PATH')无效."; exit 1; fi; CERT_PATH="$TMP_CERT_PATH"; KEY_PATH="$TMP_KEY_PATH"; SNI_VALUE=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CERT_PATH" 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p'); if [ -z "$SNI_VALUE" ]; then SNI_VALUE=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | sed -n 's/.*CN ?= ?\([^,]*\).*/\1/p' | head -n 1 | sed 's/^[ \t]*//;s/[ \t]*$//'); fi; if [ -z "$SNI_VALUE" ]; then SNI_VALUE=$(openssl x509 -noout -text -in "$CERT_PATH" 2>/dev/null | grep 'DNS:' | head -n 1 | sed 's/.*DNS://' | tr -d ' ' | cut -d, -f1); fi; if [ -z "$SNI_VALUE" ]; then _read_from_tty MANUAL_SNI "无法提取SNI, 请手动输入: "; if [ -z "$MANUAL_SNI" ]; then _log_error "SNI不能为空!"; exit 1; fi; SNI_VALUE="$MANUAL_SNI"; else _log_info "提取到SNI: $SNI_VALUE"; fi; fi;; 2) _log_info "--- ACME HTTP 验证 ---"; _read_from_tty DOMAIN "域名(eg: example.com): "; if [ -z "$DOMAIN" ]; then _log_error "域名不能为空!"; exit 1; fi; _read_from_tty INPUT_ACME_EMAIL "ACME邮箱(默认 $DEFAULT_ACME_EMAIL): "; ACME_EMAIL=${INPUT_ACME_EMAIL:-$DEFAULT_ACME_EMAIL}; if [ -z "$ACME_EMAIL" ]; then _log_error "邮箱不能为空!"; exit 1; fi; SNI_VALUE=$DOMAIN; _log_debug "检查80端口..."; if lsof -i:80 -sTCP:LISTEN -P -n &>/dev/null; then _log_warning "80端口被占用!"; PID_80=$(lsof -t -i:80 -sTCP:LISTEN); [ -n "$PID_80" ] && _log_info "占用进程PID: $PID_80"; else _log_debug "80端口可用。"; fi;; *) _log_error "无效TLS选项。"; exit 1;; esac; _read_from_tty PORT_INPUT "Hysteria监听端口(默认 $DEFAULT_PORT): "; PORT=${PORT_INPUT:-$DEFAULT_PORT}; _read_from_tty PASSWORD_INPUT "Hysteria密码(回车随机): " "random"; if [ -z "$PASSWORD_INPUT" ] || [ "$PASSWORD_INPUT" == "random" ]; then PASSWORD=$(_generate_uuid); _log_info "使用随机密码: $PASSWORD"; else PASSWORD="$PASSWORD_INPUT"; fi; _read_from_tty MASQUERADE_URL_INPUT "伪装URL(默认 $DEFAULT_MASQUERADE_URL): "; MASQUERADE_URL=${MASQUERADE_URL_INPUT:-$DEFAULT_MASQUERADE_URL}; SERVER_PUBLIC_ADDRESS=$(_get_server_address); mkdir -p "$HYSTERIA_CONFIG_DIR"; local perform_hysteria_download=true; if [ -f "$HYSTERIA_INSTALL_PATH" ] && command -v "$HYSTERIA_INSTALL_PATH" &>/dev/null; then _log_debug "检测到已安装的 Hysteria 程序，正在检查版本..."; VERSION_OUTPUT=$("$HYSTERIA_INSTALL_PATH" version 2>/dev/null); CURRENT_HY_VER_RAW=$(echo "$VERSION_OUTPUT" | grep '^Version:' | awk '{print $2}'); CURRENT_HY_VER=$(echo "$CURRENT_HY_VER_RAW" | sed 's#^v##'); if [ -n "$CURRENT_HY_VER" ] && [ "$CURRENT_HY_VER" != "unknown" ]; then _log_debug "当前已安装 Hysteria 版本: $CURRENT_HY_VER_RAW (规范化为: $CURRENT_HY_VER). 正在获取最新版本..."; LATEST_VER_TAG=$(curl -s --connect-timeout 5 "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); if [ -n "$LATEST_VER_TAG" ]; then LATEST_HY_VER_CLEAN=$(echo "$LATEST_VER_TAG" | sed -e 's#^app/##' -e 's#^v##'); _log_debug "GitHub 最新 Hysteria 版本 Tag: $LATEST_VER_TAG (规范化为: $LATEST_HY_VER_CLEAN)"; if [[ "$CURRENT_HY_VER" == "$LATEST_HY_VER_CLEAN" ]]; then _log_success "已安装的 Hysteria 程序 (版本 $CURRENT_HY_VER_RAW) 已是最新。将跳过下载。"; perform_hysteria_download=false; else _log_debug "Hysteria 程序版本不一致 (最新: $LATEST_HY_VER_CLEAN, 当前: $CURRENT_HY_VER)。准备下载更新。"; fi; else _log_warning "无法从 GitHub API 获取最新 Hysteria 版本号。将继续尝试下载以确保最新。"; fi; else _log_warning "无法获取当前已安装 Hysteria 的版本号 (输出: '$VERSION_OUTPUT')。将继续尝试下载。"; fi; else _log_debug "Hysteria 程序未安装或无法执行。准备下载。"; fi
    if $perform_hysteria_download; then if _is_hysteria_installed; then _log_info "准备更新 Hysteria 二进制文件，将先停止现有服务..."; _generic_control_service "hysteria" "stop"; sleep 1; fi; _log_info "下载Hysteria..."; ARCH=$(uname -m); case ${ARCH} in x86_64) HYSTERIA_ARCH="amd64";; aarch64) HYSTERIA_ARCH="arm64";; armv7l) HYSTERIA_ARCH="arm";; *) _log_error "不支持架构: ${ARCH}"; exit 1;; esac; if ! wget -qO "$HYSTERIA_INSTALL_PATH" "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${HYSTERIA_ARCH}"; then _log_warning "GitHub下载失败,尝试旧地址..."; if ! wget -qO "$HYSTERIA_INSTALL_PATH" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"; then _log_error "下载Hysteria失败!"; exit 1; fi; fi; _log_success "Hysteria 程序下载成功。"; fi
    if [ -f "$HYSTERIA_INSTALL_PATH" ]; then chmod +x "$HYSTERIA_INSTALL_PATH"; _log_debug "Hysteria 程序准备就绪: $HYSTERIA_INSTALL_PATH"; else if $perform_hysteria_download; then _log_error "Hysteria 程序文件在尝试下载后未找到于 $HYSTERIA_INSTALL_PATH。安装中止。"; exit 1; else _log_error "Hysteria 程序未安装 (${HYSTERIA_INSTALL_PATH} 不存在) 且下载被跳过。这是一个意外情况。"; exit 1; fi; fi
    if [ "$TLS_TYPE" -eq 2 ]; then _log_debug "设置cap_net_bind_service权限(ACME)..."; if ! command -v setcap &>/dev/null; then _log_warning "setcap未找到,尝试安装$SETCAP_DEPENDENCY_PKG..."; if ! $PKG_INSTALL_CMD "$SETCAP_DEPENDENCY_PKG" >/dev/null; then _log_error "安装$SETCAP_DEPENDENCY_PKG失败."; else _log_success "$SETCAP_DEPENDENCY_PKG安装成功."; fi; fi; if command -v setcap &>/dev/null; then if ! setcap 'cap_net_bind_service=+ep' "$HYSTERIA_INSTALL_PATH"; then _log_error "setcap失败."; else _log_success "setcap成功."; fi; else _log_error "setcap仍不可用."; fi; fi
    _log_debug "生成 Hysteria 配置文件 $HYSTERIA_CONFIG_FILE..."; cat > "$HYSTERIA_CONFIG_FILE" << EOF
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
    case $TLS_TYPE in 1) cat >> "$HYSTERIA_CONFIG_FILE" << EOF

tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
    _log_warning "Hysteria 自定义证书客户端需设insecure:true";; 2) cat >> "$HYSTERIA_CONFIG_FILE" << EOF

acme:
  domains:
    - $DOMAIN
  email: $ACME_EMAIL
EOF
    ;; esac; _log_success "Hysteria 配置文件完成。"
    local current_service_name_for_hysteria=""; if [[ "$INIT_SYSTEM" == "systemd" ]]; then current_service_name_for_hysteria="$HYSTERIA_SERVICE_NAME_SYSTEMD"; _log_debug "创建 Hysteria systemd服务..."; cat > "/etc/systemd/system/$current_service_name_for_hysteria" << EOF
[Unit]
Description=Hysteria 2 Service by $SCRIPT_COMMAND_NAME
After=network.target network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=${HYSTERIA_INSTALL_PATH} server --config ${HYSTERIA_CONFIG_FILE}
Restart=on-failure; RestartSec=10; StandardOutput=append:${LOG_FILE_HYSTERIA_OUT}; StandardError=append:${LOG_FILE_HYSTERIA_ERR}; LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "/etc/systemd/system/$current_service_name_for_hysteria"; $SERVICE_CMD_SYSTEMCTL daemon-reload 2>/dev/null;
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then current_service_name_for_hysteria="$HYSTERIA_SERVICE_NAME_OPENRC"; _log_debug "创建 Hysteria OpenRC服务..."; cat > "/etc/init.d/$current_service_name_for_hysteria" << EOF
#!/sbin/openrc-run
name="$HYSTERIA_SERVICE_NAME_OPENRC"
command="$HYSTERIA_INSTALL_PATH"
command_args="server --config $HYSTERIA_CONFIG_FILE"
pidfile="/var/run/\${name}.pid"
command_background="yes"
output_log="$LOG_FILE_HYSTERIA_OUT"
error_log="$LOG_FILE_HYSTERIA_ERR"
depend() { need net; after firewall; }
start_pre() { checkpath -f "\$output_log" -m 0644; checkpath -f "\$error_log" -m 0644; }
start() { ebegin "Starting \$name"; start-stop-daemon --start --quiet --background --make-pidfile --pidfile "\$pidfile" --stdout "\$output_log" --stderr "\$error_log" --exec "\$command" -- \$command_args; eend \$?; }
stop() { ebegin "Stopping \$name"; start-stop-daemon --stop --quiet --pidfile "\$pidfile"; eend \$?; }
EOF
    chmod +x "/etc/init.d/$current_service_name_for_hysteria"; fi; _log_success "Hysteria 服务文件创建成功。"
    _generic_control_service "hysteria" "enable"; _log_info "准备启动/重启 Hysteria 服务..."; _generic_control_service "hysteria" "restart";
    sleep 2; if _generic_control_service "hysteria" "status" > /dev/null; then _log_success "Hysteria服务已成功运行！"; else _log_error "Hysteria服务状态异常!"; fi
    _setup_hy_command; _log_success "Hysteria 安装配置完成！"; echo "------------------------------------------------------------------------"; _show_hysteria_info_and_qrcode; echo "------------------------------------------------------------------------"; _show_management_commands_hint
}

_do_uninstall_hysteria() {
    local skip_confirm_flag="$1"
    _ensure_root; _detect_os;
    if ! _is_hysteria_installed; then
        _log_info "Hysteria 未安装或未完全安装。跳过 Hysteria 卸载。"
        return 0
    fi

    if [[ "$skip_confirm_flag" != "skip_confirm" ]]; then
        _read_confirm_tty confirm_uninstall "这将卸载 Hysteria 并删除所有相关配置和文件。确定? [y/N]: "
        if [[ "$confirm_uninstall" != "y" && "$confirm_uninstall" != "Y" ]]; then
            _log_info "Hysteria 卸载取消。"
            exit 0
        fi
    fi
    _log_info "正在卸载 Hysteria..."
    _log_info "停止Hysteria服务..."; _generic_control_service "hysteria" "stop"
    local current_service_name_val="";
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        current_service_name_val="$HYSTERIA_SERVICE_NAME_SYSTEMD"
        _log_debug "禁用 Hysteria systemd服务..."; "$SERVICE_CMD_SYSTEMCTL" disable "$current_service_name_val" >/dev/null 2>/dev/null;
        _log_debug "移除 Hysteria systemd服务文件..."; rm -f "/etc/systemd/system/$current_service_name_val"; find /etc/systemd/system/ -name "$current_service_name_val" -delete 2>/dev/null;
        "$SERVICE_CMD_SYSTEMCTL" daemon-reload 2>/dev/null;
        "$SERVICE_CMD_SYSTEMCTL" reset-failed "$current_service_name_val" >/dev/null 2>/dev/null || true;
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        current_service_name_val="$HYSTERIA_SERVICE_NAME_OPENRC"
        _log_debug "移除 Hysteria OpenRC服务..."; rc-update del "$current_service_name_val" default >/dev/null 2>&1;
        _log_debug "移除 Hysteria OpenRC脚本..."; rm -f "/etc/init.d/$current_service_name_val";
    fi;
    _log_debug "移除Hysteria二进制: $HYSTERIA_INSTALL_PATH"; rm -f "$HYSTERIA_INSTALL_PATH";
    _log_debug "移除Hysteria配置: $HYSTERIA_CONFIG_DIR"; rm -rf "$HYSTERIA_CONFIG_DIR";
    _log_debug "移除Hysteria日志: $LOG_FILE_HYSTERIA_OUT, $LOG_FILE_HYSTERIA_ERR"; rm -f "$LOG_FILE_HYSTERIA_OUT" "$LOG_FILE_HYSTERIA_ERR";
    _log_debug "移除 Hysteria 旧版变量文件 (如果存在): $HYSTERIA_INSTALL_VARS_FILE"; rm -f "$HYSTERIA_INSTALL_VARS_FILE";
    _log_success "Hysteria 卸载完成。"
}

_show_hysteria_config() { _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria未安装。无配置显示。"; return 1; fi; _log_info "当前Hysteria配置文件($HYSTERIA_CONFIG_FILE):"; echo "----------------------------------------------------"; if [ -f "$HYSTERIA_CONFIG_FILE" ]; then cat "$HYSTERIA_CONFIG_FILE"; else _log_error "配置文件不存在。"; fi; echo "----------------------------------------------------"; _log_info "Hysteria 配置摘要:"; local port=$(grep -E '^\s*listen:\s*:([0-9]+)' "$HYSTERIA_CONFIG_FILE" | sed -E 's/^\s*listen:\s*://' || echo "未知"); local password=$(grep 'password:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^.*password:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/["'\'']//g' || echo "未知"); local masquerade_url=$(grep '^\s*masquerade:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*url: \([^, }]*\).*/\1/p' || echo "未知"); if [ -z "$masquerade_url" ]; then masquerade_url=$(awk '/^\s*masquerade:/,/url:/{if(/url:/) print $2}' "$HYSTERIA_CONFIG_FILE" || echo "未知"); fi; echo "  监听端口: $port"; echo "  密码: $password"; echo "  伪装URL: $masquerade_url"; if grep -q '^\s*tls:' "$HYSTERIA_CONFIG_FILE"; then local cert_path=$(grep '^\s*tls:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*cert: \([^, }]*\).*/\1/p' || echo "未知"); local key_path=$(grep '^\s*tls:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*key: \([^ }]*\).*/\1/p' || echo "未知"); echo "  TLS模式: 自定义证书"; echo "    证书路径: $cert_path"; echo "    私钥路径: $key_path"; elif grep -q '^\s*acme:' "$HYSTERIA_CONFIG_FILE"; then local domain=$(grep -A 1 '^\s*domains:' "$HYSTERIA_CONFIG_FILE" | grep '^\s*-\s*' | sed -e 's/^\s*-\s*//' -e 's/#.*//' -e 's/[ \t]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//'); local email=$(grep -A 2 '^\s*acme:' "$HYSTERIA_CONFIG_FILE" | grep 'email:' | sed -e 's/^\s*email:\s*//' -e 's/#.*//' -e 's/[[:space:]]*$//'); echo "  TLS模式: ACME"; echo "    域名: $domain"; echo "    邮箱: $email"; else echo "  TLS模式: 未知"; fi; echo "----------------------------------------------------"; }
_change_hysteria_config_interactive() { _ensure_root; _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria未安装。无法更改。"; return 1; fi; _log_info "更改Hysteria配置(部分)"; _log_warning "此功能通过awk/sed修改配置,复杂情况可能不健壮。"; _log_warning "强烈建议备份$HYSTERIA_CONFIG_FILE。"; _log_warning "当前支持:监听端口,密码,伪装URL。"; _log_warning "如需更改TLS模式等重大配置, 请使用 'sudo ${SCRIPT_COMMAND_NAME} install' 命令。"; CURRENT_PORT=$(grep -E '^\s*listen:\s*:([0-9]+)' "$HYSTERIA_CONFIG_FILE" | sed -E 's/^\s*listen:\s*://' || echo ""); CURRENT_PASSWORD_RAW=$(grep 'password:' "$HYSTERIA_CONFIG_FILE" | head -n 1 | sed -e 's/^.*password:[[:space:]]*//' -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/["'\'']//g' || echo ""); CURRENT_MASQUERADE=$(grep '^\s*masquerade:' "$HYSTERIA_CONFIG_FILE" | sed -n 's/.*url: \([^, }]*\).*/\1/p' || echo ""); if [ -z "$CURRENT_MASQUERADE" ]; then CURRENT_MASQUERADE=$(awk '/^\s*masquerade:/,/url:/{if(/url:/) print $2}' "$HYSTERIA_CONFIG_FILE" || echo ""); fi; _read_from_tty NEW_PORT "新监听端口" "$CURRENT_PORT"; NEW_PORT=${NEW_PORT:-$CURRENT_PORT}; _read_from_tty NEW_PASSWORD_INPUT "新密码" "$CURRENT_PASSWORD_RAW"; NEW_PASSWORD=""; if [ -n "$NEW_PASSWORD_INPUT" ]; then if [ "$NEW_PASSWORD_INPUT" == "random" ]; then NEW_PASSWORD=$(_generate_uuid); _log_info "生成新随机密码:$NEW_PASSWORD"; else NEW_PASSWORD="$NEW_PASSWORD_INPUT"; fi; else NEW_PASSWORD="$CURRENT_PASSWORD_RAW"; fi; _read_from_tty NEW_MASQUERADE_URL_INPUT "新伪装URL" "$CURRENT_MASQUERADE"; NEW_MASQUERADE=${NEW_MASQUERADE_URL_INPUT:-$CURRENT_MASQUERADE}; local config_changed=false; if [ "$NEW_PORT" != "$CURRENT_PORT" ] || [ "$NEW_PASSWORD" != "$CURRENT_PASSWORD_RAW" ] || [ "$NEW_MASQUERADE" != "$CURRENT_MASQUERADE" ]; then CONFIG_BACKUP_FILE="${HYSTERIA_CONFIG_FILE}.bak.$(date +%s)"; cp "$HYSTERIA_CONFIG_FILE" "$CONFIG_BACKUP_FILE"; _log_info "配置文件备份至$CONFIG_BACKUP_FILE"; config_changed=true; fi; temp_config_file=$(mktemp); if [ "$NEW_PORT" != "$CURRENT_PORT" ]; then _log_info "更改端口 '$CURRENT_PORT' -> '$NEW_PORT'..."; sed "s/^listen: :${CURRENT_PORT}/listen: :${NEW_PORT}/" "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改端口失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; rm -f "$temp_config_file" "$CONFIG_BACKUP_FILE"; return 1; }; fi; if [ "$NEW_PASSWORD" != "$CURRENT_PASSWORD_RAW" ]; then _log_info "更改密码..."; awk -v new_pass="$NEW_PASSWORD" 'BEGIN{pb=0} /^auth:/{pb=1;print;next} pb&&/password:/{print "  password: " new_pass;pb=0;next} pb&&NF>0&&!/^[[:space:]]/{pb=0} {print}' "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改密码失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; rm -f "$temp_config_file" "$CONFIG_BACKUP_FILE"; return 1; }; fi; if [ "$NEW_MASQUERADE" != "$CURRENT_MASQUERADE" ]; then _log_info "更改伪装URL '$CURRENT_MASQUERADE' -> '$NEW_MASQUERADE'..."; awk -v new_url="$NEW_MASQUERADE" 'BEGIN{mb=0} /^masquerade:/{mb=1;print;next} mb&&/url:/{print "    url: " new_url;mb=0;next} mb&&NF>0&&!/^[[:space:]]/{mb=0} {print}' "$HYSTERIA_CONFIG_FILE" > "$temp_config_file" && mv "$temp_config_file" "$HYSTERIA_CONFIG_FILE" || { _log_error "更改伪装URL失败"; cat "$CONFIG_BACKUP_FILE" > "$HYSTERIA_CONFIG_FILE"; rm -f "$temp_config_file" "$CONFIG_BACKUP_FILE"; return 1; }; fi; if [ -f "$temp_config_file" ]; then rm -f "$temp_config_file"; fi; if $config_changed; then _log_success "配置更新。重启服务以应用更改..."; _generic_control_service "hysteria" "restart"; rm -f "$CONFIG_BACKUP_FILE"; else _log_info "未做配置更改。"; if [ -f "$CONFIG_BACKUP_FILE" ]; then rm -f "$CONFIG_BACKUP_FILE"; fi; fi; echo ""; _log_info "--- 当前 Hysteria 配置的订阅信息 ---"; _show_hysteria_info_and_qrcode; echo "------------------------------------------------------------------------"; }
_update_hysteria_binary() { _ensure_root; _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。无法更新。"; return 1; fi; _log_info "检查 Hysteria 程序更新..."; VERSION_OUTPUT=$("$HYSTERIA_INSTALL_PATH" version 2>/dev/null); CURRENT_VER_RAW=$(echo "$VERSION_OUTPUT" | grep '^Version:' | awk '{print $2}'); CURRENT_VER=$(echo "$CURRENT_VER_RAW" | sed 's#^v##'); if [ -z "$CURRENT_VER" ] || [ "$CURRENT_VER" == "unknown" ]; then _log_warning "无法获取当前版本 (输出: '$VERSION_OUTPUT')。尝试下载最新。"; CURRENT_VER="unknown"; else _log_info "当前版本: $CURRENT_VER_RAW (规范化为: $CURRENT_VER)"; fi; _log_info "获取最新版本号..."; LATEST_VER_TAG=$(curl -s --connect-timeout 5 "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); if [ -z "$LATEST_VER_TAG" ]; then _log_warning "无法从 GitHub API 获取版本号。尝试下载标记为 'latest' 的版本。"; LATEST_VER_CLEAN="latest"; else LATEST_VER_CLEAN=$(echo "$LATEST_VER_TAG" | sed -e 's#^app/##' -e 's#^v##'); _log_info "最新版本 Tag: $LATEST_VER_TAG (规范化为: $LATEST_VER_CLEAN)"; if [[ "$CURRENT_VER" == "$LATEST_VER_CLEAN" && "$CURRENT_VER" != "unknown" ]]; then _log_success "当前已是最新版本 ($CURRENT_VER_RAW)。"; return 0; fi; fi; _log_info "下载 Hysteria (目标版本: ${LATEST_VER_CLEAN:-latest}) ..."; ARCH=$(uname -m); case ${ARCH} in x86_64) HYSTERIA_ARCH="amd64";; aarch64) HYSTERIA_ARCH="arm64";; armv7l) HYSTERIA_ARCH="arm";; *) _log_error "不支持架构: ${ARCH}"; return 1;; esac; TMP_HY_DOWNLOAD=$(mktemp); DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${HYSTERIA_ARCH}"; _log_info "准备停止服务以更新二进制文件..."; _generic_control_service "hysteria" "stop"; sleep 1;  if ! wget -qO "$TMP_HY_DOWNLOAD" "$DOWNLOAD_URL"; then _log_warning "GitHub下载失败,尝试旧地址..."; if ! wget -qO "$TMP_HY_DOWNLOAD" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"; then _log_error "下载 Hysteria 失败! (URL: $DOWNLOAD_URL 和备用地址)"; rm -f "$TMP_HY_DOWNLOAD"; _generic_control_service "hysteria" "start" &>/dev/null || true; return 1; fi; fi; if ! file "$TMP_HY_DOWNLOAD" | grep -q "executable"; then _log_error "下载文件非可执行。"; rm -f "$TMP_HY_DOWNLOAD"; _generic_control_service "hysteria" "start" &>/dev/null || true; return 1; fi; chmod +x "$TMP_HY_DOWNLOAD"; DOWNLOADED_VER_OUTPUT=$("$TMP_HY_DOWNLOAD" version 2>/dev/null); DOWNLOADED_VER_RAW=$(echo "$DOWNLOADED_VER_OUTPUT" | grep '^Version:' | awk '{print $2}'); DOWNLOADED_VER=$(echo "$DOWNLOADED_VER_RAW" | sed 's#^v##'); if [[ -n "$DOWNLOADED_VER" && "$DOWNLOADED_VER" == "$CURRENT_VER" && "$CURRENT_VER" != "unknown" ]]; then _log_info "下载版本($DOWNLOADED_VER_RAW)与当前相同。取消更新。"; rm -f "$TMP_HY_DOWNLOAD"; _generic_control_service "hysteria" "start" &>/dev/null || true; return 0; elif [[ -n "$DOWNLOADED_VER" ]]; then _log_info "下载版本为: $DOWNLOADED_VER_RAW (规范化为: $DOWNLOADED_VER)"; else _log_warning "无法获取下载文件版本号 (输出: '$DOWNLOADED_VER_OUTPUT')。"; fi; _log_info "准备替换二进制文件..."; if mv "$TMP_HY_DOWNLOAD" "$HYSTERIA_INSTALL_PATH"; then _log_success "Hysteria已更新至 $DOWNLOADED_VER_RAW (或 latest)。"; if getcap "$HYSTERIA_INSTALL_PATH" 2>/dev/null | grep -q "cap_net_bind_service"; then _log_info "重应用setcap权限..."; if ! setcap 'cap_net_bind_service=+ep' "$HYSTERIA_INSTALL_PATH"; then _log_warning "重应用setcap失败。"; fi; fi; _generic_control_service "hysteria" "start"; return 0; else _log_error "替换二进制文件失败。"; rm -f "$TMP_HY_DOWNLOAD"; _log_info "尝试重启旧服务..."; _generic_control_service "hysteria" "start" &>/dev/null || true; return 1; fi; }

# --- MTProto (mtg) Functions ---
_is_mtg_installed() { _detect_os; if [ -f "$MTG_INSTALL_PATH" ] && [ -f "$MTG_CONFIG_FILE" ]; then if [ "$INIT_SYSTEM" == "systemd" ] && [ -f "/etc/systemd/system/$MTG_SERVICE_NAME_SYSTEMD" ]; then return 0; elif [ "$INIT_SYSTEM" == "openrc" ] && [ -f "/etc/init.d/$MTG_SERVICE_NAME_OPENRC" ]; then return 0; fi; fi; return 1; }
_get_current_mtg_version() {
    if [ -f "$MTG_INSTALL_PATH" ] && command -v "$MTG_INSTALL_PATH" &>/dev/null; then
        local mtg_version_full
        mtg_version_full=$("$MTG_INSTALL_PATH" --version 2>/dev/null)
        if [ -z "$mtg_version_full" ]; then
            mtg_version_full=$("$MTG_INSTALL_PATH" -v 2>/dev/null)
        fi
        echo "$mtg_version_full" | awk '{print $1}' | sed 's/[(),]//g'
    else
        echo "unknown"
    fi
}
_download_mtg_binary() {
    local expected_version="$1"
    local force_download="${2:-false}"
    local arch_mtg ARCH; ARCH=$(uname -m)

    if ! $force_download && [ -f "$MTG_INSTALL_PATH" ]; then
        local current_mtg_ver=$(_get_current_mtg_version)
        if [[ "$current_mtg_ver" == "$expected_version" ]]; then
            _log_success "MTG 程序 (版本 $current_mtg_ver) 已是目标版本 ($expected_version)。将跳过下载。"
            return 0
        else
            _log_info "MTG 程序版本不一致 (目标: $expected_version, 当前: $current_mtg_ver)。准备下载更新。"
        fi
    fi

    _log_info "下载 MTProto 代理 (9seconds/mtg 版本 ${expected_version})..."
    case ${ARCH} in
        x86_64) arch_mtg="amd64";; aarch64) arch_mtg="arm64";;
        armv7l) arch_mtg="armv7";; armv6l) arch_mtg="armv6";;
        armhf) arch_mtg="armv7";; armel) arch_mtg="armv6";;
        i386|i686) arch_mtg="386";;
        *) _log_error "MTG: 不支持的系统架构: ${ARCH} (版本 ${expected_version})"; return 1;;
    esac
    local mtg_tag="v${expected_version}";
    local download_url="https://github.com/9seconds/mtg/releases/download/${mtg_tag}/mtg-${expected_version}-linux-${arch_mtg}.tar.gz";
    local tmp_archive="/tmp/mtg-${expected_version}-linux-${arch_mtg}.tar.gz"; local tmp_extract_dir="/tmp/mtg_extract_$$";

    _log_debug "从 ${download_url} 下载...";
    if ! wget -qO "$tmp_archive" "$download_url"; then _log_error "下载 MTG 失败。URL: $download_url"; rm -f "$tmp_archive"; return 1; fi

    mkdir -p "$tmp_extract_dir";
    if ! tar -xzf "$tmp_archive" -C "$tmp_extract_dir"; then _log_error "解压 MTG 归档文件失败: $tmp_archive"; rm -f "$tmp_archive"; rm -rf "$tmp_extract_dir"; return 1; fi

    local extracted_binary_path="$tmp_extract_dir/mtg-${expected_version}-linux-${arch_mtg}/mtg";
    if [ ! -f "$extracted_binary_path" ]; then extracted_binary_path="$tmp_extract_dir/mtg"; fi

    if [ -f "$extracted_binary_path" ]; then
        if ! mv "$extracted_binary_path" "$MTG_INSTALL_PATH"; then _log_error "移动 MTG 二进制文件到 $MTG_INSTALL_PATH 失败。"; rm -f "$tmp_archive"; rm -rf "$tmp_extract_dir"; return 1; fi
        chmod +x "$MTG_INSTALL_PATH"; _log_success "MTG 二进制文件已安装/更新到 $MTG_INSTALL_PATH (版本 ${expected_version})";
    else
        _log_error "在解压的归档中未找到 MTG 二进制文件 (尝试路径: $extracted_binary_path)。"; rm -f "$tmp_archive"; rm -rf "$tmp_extract_dir"; return 1;
    fi
    rm -f "$tmp_archive"; rm -rf "$tmp_extract_dir"; return 0
}
_update_mtg_binary() {
    _ensure_root; _detect_os
    if ! _is_mtg_installed && ! [ -f "$MTG_INSTALL_PATH" ]; then
        _log_error "MTProto (mtg) 未安装。无法更新。"
        _log_info "请先运行 'sudo $SCRIPT_COMMAND_NAME install_mtp' 进行安装。"
        return 1
    fi
    _log_info "== 正在更新 MTProto (mtg) 程序 =="
    local current_ver=$(_get_current_mtg_version)
    _log_info "当前已安装 MTG 版本: ${current_ver:-未知}"
    _log_info "MTG 目标版本 (来自 9seconds/mtg): $MTG_TARGET_VERSION"

    if [[ "$current_ver" == "$MTG_TARGET_VERSION" ]]; then
        _log_success "MTG 程序已是目标版本 ($MTG_TARGET_VERSION)。"
        return 0
    fi

    if _is_mtg_installed; then
      _log_info "准备停止 MTG 服务以更新二进制文件..."
      _generic_control_service "mtg" "stop"
      sleep 1
    fi

    if _download_mtg_binary "$MTG_TARGET_VERSION" "true"; then
        _log_success "MTG 程序已更新至版本 $MTG_TARGET_VERSION。"
        if _is_mtg_installed; then
            _log_info "正在启动 MTG 服务..."
            _generic_control_service "mtg" "start"
        fi
        return 0
    else
        _log_error "MTG 程序更新失败。"
        if _is_mtg_installed; then
            _log_info "尝试重启旧的 MTG 服务..."
            _generic_control_service "mtg" "start" &>/dev/null || true
        fi
        return 1
    fi
}
_generate_mtg_config() {
    _log_info "开始配置 MTProto 代理..."; mkdir -p "$MTG_CONFIG_DIR";
    local mtg_port mtg_domain mtg_secret;
    _read_from_tty mtg_port "请输入 MTProto 代理监听端口" "8443"; mtg_port=${mtg_port:-8443}
    _read_from_tty mtg_domain "请输入用于生成FakeTLS密钥的伪装域名 (建议常用可访问域名)" "cn.bing.com"; mtg_domain=${mtg_domain:-"cn.bing.com"}
    if ! command -v "$MTG_INSTALL_PATH" &>/dev/null; then _log_error "MTG 程序 ($MTG_INSTALL_PATH) 未找到或未安装。无法生成密钥。"; return 1; fi
    _log_debug "正在为域名 '${mtg_domain}' 生成 MTProto 密钥 (FakeTLS 'ee' 类型)..."; mtg_secret=$("$MTG_INSTALL_PATH" generate-secret --hex "$mtg_domain")
    if [ -z "$mtg_secret" ] || [[ "$mtg_secret" != ee* ]]; then _log_error "MTProto 密钥生成失败或格式不正确 (需要 'ee' 开头)。请确保 MTG 程序工作正常并能生成 FakeTLS 密钥。输出: $mtg_secret"; return 1; fi
    _log_success "MTProto 密钥已生成。"
    _log_debug "正在创建 MTProto 配置文件: $MTG_CONFIG_FILE";
    cat > "$MTG_CONFIG_FILE" << EOF
# MTProto proxy (mtg) configuration file
# Generated by ${SCRIPT_COMMAND_NAME} v${SCRIPT_VERSION} on $(date)
secret = "${mtg_secret}"
bind-to = "0.0.0.0:${mtg_port}"
EOF
    _log_success "MTProto 配置文件已创建。"
    echo "MTG_PORT='${mtg_port}'" > "$MTG_VARS_FILE"; echo "MTG_SECRET='${mtg_secret}'" >> "$MTG_VARS_FILE"; return 0
}
_create_mtg_service_file() {
    _log_debug "创建 MTProto 服务文件..."; local current_service_name_val=""
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then current_service_name_val="$MTG_SERVICE_NAME_SYSTEMD"; _log_debug "创建 systemd 服务: $current_service_name_val";
        cat > "/etc/systemd/system/$current_service_name_val" << EOF
[Unit]
Description=MTProto Proxy Server (mtg) by ${SCRIPT_COMMAND_NAME}
Documentation=https://github.com/9seconds/mtg
After=network.target network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=${MTG_INSTALL_PATH} run ${MTG_CONFIG_FILE}
Restart=always
RestartSec=3
StandardOutput=append:${LOG_FILE_MTG_OUT}
StandardError=append:${LOG_FILE_MTG_ERR}
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "/etc/systemd/system/$current_service_name_val"; $SERVICE_CMD_SYSTEMCTL daemon-reload 2>/dev/null;
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then current_service_name_val="$MTG_SERVICE_NAME_OPENRC"; _log_debug "创建 OpenRC 服务: $current_service_name_val";
        cat > "/etc/init.d/$current_service_name_val" << EOF
#!/sbin/openrc-run
name="$MTG_SERVICE_NAME_OPENRC"
command="$MTG_INSTALL_PATH"
command_args="run $MTG_CONFIG_FILE"
pidfile="/var/run/\${name}.pid"
command_background="yes"
output_log="$LOG_FILE_MTG_OUT"
error_log="$LOG_FILE_MTG_ERR"
depend() { need net; after firewall; }
start_pre() { checkpath -f "\$output_log" -m 0644; checkpath -f "\$error_log" -m 0644; }
start() { ebegin "Starting \$name"; start-stop-daemon --start --quiet --background --make-pidfile --pidfile "\$pidfile" --stdout "\$output_log" --stderr "\$error_log" --exec "\$command" -- \$command_args; eend \$?; }
stop() { ebegin "Stopping \$name"; start-stop-daemon --stop --quiet --pidfile "\$pidfile"; eend \$?; }
EOF
        chmod +x "/etc/init.d/$current_service_name_val";
    fi
    _log_success "MTProto 服务文件创建成功。"
}
_get_mtg_link_info() {
    MTG_LINK_VAR=""
    if [ ! -f "$MTG_CONFIG_FILE" ]; then _log_error "MTG 配置文件 $MTG_CONFIG_FILE 未找到。"; return 1; fi
    if ! command -v "$MTG_INSTALL_PATH" &>/dev/null; then _log_error "MTG 程序 $MTG_INSTALL_PATH 未找到。"; return 1; fi
    _log_debug "正在从 $MTG_CONFIG_FILE 和 MTG 程序获取连接信息..."; local mtg_access_json
    mtg_access_json=$("$MTG_INSTALL_PATH" access "$MTG_CONFIG_FILE" 2>/dev/null)
    if [ -z "$mtg_access_json" ]; then _log_warning "执行 'mtg access' 命令失败或无输出。尝试手动构造...";
        if [ -f "$MTG_VARS_FILE" ]; then
            local mtg_port_val mtg_secret_val
            mtg_port_val=$(grep '^MTG_PORT=' "$MTG_VARS_FILE" | cut -d"'" -f2)
            mtg_secret_val=$(grep '^MTG_SECRET=' "$MTG_VARS_FILE" | cut -d"'" -f2)
            local server_ip=$(_get_server_address | tr -d '[]')
            if [ -n "$server_ip" ] && [ -n "$mtg_port_val" ] && [ -n "$mtg_secret_val" ]; then
                MTG_LINK_VAR="tg://proxy?server=${server_ip}&port=${mtg_port_val}&secret=${mtg_secret_val}"; _log_debug "手动构造的 MTG 链接: $MTG_LINK_VAR"; return 0;
            fi;
        fi; _log_error "无法构造 MTG 链接。"; return 1;
    fi

    MTG_LINK_VAR=$(echo "$mtg_access_json" | tr -d '\n\r ' | grep -o '"ipv4":{[^}]*"tg_url":"[^"]*' | grep -o '"tg_url":"[^"]*' | sed -e 's/"tg_url":"//' -e 's/"//')
    if [ -z "$MTG_LINK_VAR" ]; then
        MTG_LINK_VAR=$(echo "$mtg_access_json" | tr -d '\n\r ' | grep -o '"ipv6":{[^}]*"tg_url":"[^"]*' | grep -o '"tg_url":"[^"]*' | sed -e 's/"tg_url":"//' -e 's/"//')
    fi
    if [ -z "$MTG_LINK_VAR" ]; then
           MTG_LINK_VAR=$(echo "$mtg_access_json" | grep -o '"tg_url":"[^"]*"' | head -n 1 | sed -e 's/"tg_url":"//' -e 's/"//g' -e 's/\\//g')
    fi

    if [ -z "$MTG_LINK_VAR" ]; then _log_error "无法从 'mtg access' 输出中解析 tg_url。输出内容:\n$mtg_access_json"; return 1; fi
    _log_success "MTProto 连接信息获取成功。"
}
_display_mtg_link_and_qrcode() {
    echo ""; _log_info "MTProto 代理链接 (tg://):"; echo -e "${GREEN}${MTG_LINK_VAR}${NC}";
    local mtg_tme_link;
    if command -v "$MTG_INSTALL_PATH" &>/dev/null && [ -f "$MTG_CONFIG_FILE" ]; then
        local mtg_access_json_for_tme=$("$MTG_INSTALL_PATH" access "$MTG_CONFIG_FILE" 2>/dev/null)
        mtg_tme_link=$(echo "$mtg_access_json_for_tme" | tr -d '\n\r ' | grep -o '"ipv4":{[^}]*"tme_url":"[^"]*' | grep -o '"tme_url":"[^"]*' | sed -e 's/"tme_url":"//' -e 's/"//')
        if [ -z "$mtg_tme_link" ]; then
            mtg_tme_link=$(echo "$mtg_access_json_for_tme" | tr -d '\n\r ' | grep -o '"ipv6":{[^}]*"tme_url":"[^"]*' | grep -o '"tme_url":"[^"]*' | sed -e 's/"tme_url":"//' -e 's/"//')
        fi
        if [ -z "$mtg_tme_link" ]; then
            mtg_tme_link=$(echo "$mtg_access_json_for_tme" | grep -o '"tme_url":"[^"]*"' | head -n 1 | sed -e 's/"tme_url":"//' -e 's/"//g' -e 's/\\//g')
        fi

        if [ -n "$mtg_tme_link" ]; then echo ""; _log_info "MTProto (t.me) 链接:"; echo -e "${GREEN}${mtg_tme_link}${NC}"; fi
    fi
    echo ""; if command -v qrencode &>/dev/null; then _log_info "MTProto 代理 tg:// 链接二维码:"; qrencode -t ANSIUTF8 "$MTG_LINK_VAR";
    else _log_warning "提示: 'qrencode' 未安装 (${QRENCODE_PACKAGE_NAME:-qrencode}), 无法显示二维码。"; _log_info "(可运行 'sudo $PKG_INSTALL_CMD ${QRENCODE_PACKAGE_NAME:-qrencode}' 安装)"; fi; echo ""
}
_show_mtg_info_and_qrcode() {
    _detect_os; if ! _is_mtg_installed; then _log_error "MTProto 代理 (mtg) 未安装。"; return 1; fi
    if ! _get_mtg_link_info; then _log_error "无法获取 MTProto 连接信息。"; return 1; fi
    _display_mtg_link_and_qrcode
}
_do_install_mtp() {
    _ensure_root; _detect_os
    if _is_mtg_installed; then _read_confirm_tty confirm_mtg_install "MTProto 代理 (mtg) 已安装。是否强制安装(覆盖配置)? [y/N]: "; if [[ "$confirm_mtg_install" != "y" && "$confirm_mtg_install" != "Y" ]]; then _log_info "MTG 安装取消。"; return 0; fi; _log_warning "正强制安装 MTG...";
    else _log_info "准备首次安装 MTProto 代理 (mtg)..."; fi
    _log_info "--- 开始 MTProto (mtg) 依赖和程序安装 ---"
    _install_dependencies
    if ! _download_mtg_binary "$MTG_TARGET_VERSION" "true"; then _log_error "MTG 二进制文件下载失败。中止安装。"; return 1; fi
    if ! _generate_mtg_config; then _log_error "MTG 配置文件生成失败。中止安装。"; return 1; fi
    if ! _create_mtg_service_file; then _log_error "MTG 服务文件创建失败。中止安装。"; return 1; fi
    _log_info "--- MTProto (mtg) 安装阶段结束 ---"
    _generic_control_service "mtg" "enable"; _log_info "准备启动/重启 MTProto 代理服务..."; _generic_control_service "mtg" "restart";
    sleep 2; if _generic_control_service "mtg" "status" > /dev/null; then _log_success "MTProto 代理 (mtg) 服务已成功运行！"; else _log_error "MTProto 代理 (mtg) 服务状态异常!"; fi
    _log_success "MTProto 代理 (mtg) 安装配置完成！"; echo "------------------------------------------------------------------------"; _show_mtg_info_and_qrcode; echo "------------------------------------------------------------------------"; _show_management_commands_hint
}

_do_uninstall_mtp() {
    local skip_confirm_flag="$1"
    _ensure_root; _detect_os
    if ! _is_mtg_installed; then
        _log_info "MTProto 代理 (mtg) 未安装或未完全安装。跳过 MTG 卸载。"
        return 0
    fi

    if [[ "$skip_confirm_flag" != "skip_confirm" ]]; then
        _read_confirm_tty confirm_uninstall "这将卸载 MTProto 代理 (mtg) 并删除所有相关配置。确定? [y/N]: "
        if [[ "$confirm_uninstall" != "y" && "$confirm_uninstall" != "Y" ]]; then
            _log_info "MTG 卸载取消。"
            exit 0
        fi
    fi
    _log_info "正在卸载 MTProto (mtg)..."
    _log_info "停止 MTProto (mtg) 服务..."; _generic_control_service "mtg" "stop"
    local current_service_name_val=""
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        current_service_name_val="$MTG_SERVICE_NAME_SYSTEMD"
        _log_debug "禁用 MTG systemd 服务..."; "$SERVICE_CMD_SYSTEMCTL" disable "$current_service_name_val" >/dev/null 2>/dev/null;
        _log_debug "移除 MTG systemd 服务文件: $current_service_name_val"; rm -f "/etc/systemd/system/$current_service_name_val"; find "/etc/systemd/system/" -name "$current_service_name_val" -delete 2>/dev/null;
        "$SERVICE_CMD_SYSTEMCTL" daemon-reload 2>/dev/null;
        "$SERVICE_CMD_SYSTEMCTL" reset-failed "$current_service_name_val" >/dev/null 2>/dev/null || true;
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        current_service_name_val="$MTG_SERVICE_NAME_OPENRC"
        _log_debug "移除 MTG OpenRC 服务脚本: $current_service_name_val"; rc-update del "$current_service_name_val" default >/dev/null 2>&1;
        rm -f "/etc/init.d/$current_service_name_val";
    fi
    _log_debug "移除 MTProto (mtg) 二进制文件: $MTG_INSTALL_PATH"; rm -f "$MTG_INSTALL_PATH"
    _log_debug "移除 MTProto (mtg) 配置目录: $MTG_CONFIG_DIR"; rm -rf "$MTG_CONFIG_DIR"
    _log_debug "移除 MTProto (mtg) 日志文件: $LOG_FILE_MTG_OUT, $LOG_FILE_MTG_ERR"; rm -f "$LOG_FILE_MTG_OUT" "$LOG_FILE_MTG_ERR"
    _log_success "MTProto (mtg) 卸载完成。"
}

_do_uninstall_all() {
    _ensure_root
    _detect_os

    local hysteria_is_installed=false
    local mtg_is_installed=false
    local script_is_installed=false
    local installed_script_path="/usr/local/bin/${SCRIPT_COMMAND_NAME}"

    if _is_hysteria_installed; then hysteria_is_installed=true; fi
    if _is_mtg_installed; then mtg_is_installed=true; fi
    if [ -f "$installed_script_path" ]; then script_is_installed=true; fi

    if ! $hysteria_is_installed && ! $mtg_is_installed && ! $script_is_installed; then
        _log_info "Hysteria, MTProto, 和管理脚本 ${SCRIPT_COMMAND_NAME} 均未安装或未找到。无需卸载。"
        return 0
    fi

    local components_to_uninstall=()
    if $hysteria_is_installed; then components_to_uninstall+=("Hysteria 服务"); fi
    if $mtg_is_installed; then components_to_uninstall+=("MTProto 服务"); fi
    if $script_is_installed; then components_to_uninstall+=("管理脚本 ${SCRIPT_COMMAND_NAME} (${installed_script_path})"); fi
    
    local uninstall_message_list=""
    for i in "${!components_to_uninstall[@]}"; do
        uninstall_message_list+="${components_to_uninstall[$i]}"
        if [ $i -lt $((${#components_to_uninstall[@]} - 1)) ]; then
            uninstall_message_list+=", "
        fi
    done
    if [[ "$uninstall_message_list" == *, ]]; then # Remove trailing comma if only one item had a comma (should not happen with current logic but good practice)
        uninstall_message_list="${uninstall_message_list%, }"
    fi
    
    # Replace last comma with '和' if multiple items
    if [[ "$uninstall_message_list" == *", "* ]]; then
        uninstall_message_list=$(echo "$uninstall_message_list" | sed 's/\(.*\),/\1 和/')
    fi

    _log_warning "此操作将尝试卸载 ${uninstall_message_list} 及其所有相关配置和文件。"
    _read_confirm_tty confirm_all "确定要继续彻底清理吗? [y/N]: "
    if [[ "$confirm_all" != "y" && "$confirm_all" != "Y" ]]; then
        _log_info "卸载操作已取消。"
        exit 0
    fi

    if $hysteria_is_installed; then
        _do_uninstall_hysteria "skip_confirm"
        echo "---"
    fi

    if $mtg_is_installed; then
        _do_uninstall_mtp "skip_confirm"
        echo "---"
    fi

    if $script_is_installed; then
        _log_info "正在移除管理脚本 ${installed_script_path}..."
        if rm -f "${installed_script_path}"; then
            _log_success "管理脚本 ${installed_script_path} 已移除。"
            _log_info "如需再次使用, 请从 GitHub 重新下载并运行。"
        else
            _log_error "移除管理脚本 ${installed_script_path} 失败。请检查权限或手动删除: sudo rm -f ${installed_script_path}"
        fi
        echo "---"
    fi

    _log_success "所有卸载流程执行完毕。"
}


_edit_mtg_config() {
    _ensure_root; _detect_os; if ! _is_mtg_installed; then _log_error "MTProto (mtg) 未安装."; exit 1; fi;
    if [ -z "$EDITOR" ]; then EDITOR="vi"; fi
    _log_info "使用 $EDITOR 打开 MTProto (mtg) 配置文件 $MTG_CONFIG_FILE ...";
    if $EDITOR "$MTG_CONFIG_FILE"; then _log_info "编辑完成。请使用 'sudo $SCRIPT_COMMAND_NAME restart_mtp' 或 'sudo $SCRIPT_COMMAND_NAME re_mtp' 重启服务以应用更改。";
    else _log_error "编辑器 '$EDITOR' 返回错误。"; fi
}

# --- General Update Function ---
_do_update() {
    local hy_program_update_ok=false
    local mtg_program_update_ok=false
    local script_self_update_ok=false

    if _is_hysteria_installed || [ -f "$HYSTERIA_INSTALL_PATH" ]; then
      if _update_hysteria_binary; then hy_program_update_ok=true; fi
    else
      _log_info "Hysteria 未安装, 跳过 Hysteria 程序更新。"
      hy_program_update_ok=true
    fi
    echo "---";

    if _is_mtg_installed || [ -f "$MTG_INSTALL_PATH" ]; then
      if _update_mtg_binary; then mtg_program_update_ok=true; fi
    else
      _log_info "MTProto (mtg) 未安装, 跳过 MTG 程序更新。"
      mtg_program_update_ok=true
    fi
    echo "---";

    if _update_hy_script; then script_self_update_ok=true; fi
    echo "---"

    if $hy_program_update_ok && $mtg_program_update_ok && $script_self_update_ok ; then
        _log_success "更新过程完成。";
    else
        _log_warning "更新过程中遇到部分错误或部分未更新。请检查上面的日志。";
        if ! $hy_program_update_ok; then _log_error " - Hysteria 程序更新失败或未更新。"; fi
        if ! $mtg_program_update_ok; then _log_error " - MTProto (mtg) 程序更新失败或未更新。"; fi
        if ! $script_self_update_ok; then _log_error " - 管理脚本 ${SCRIPT_COMMAND_NAME} 更新失败或未更新。"; fi
        return 1;
    fi
    return 0
}

_show_menu() {
    echo ""; _log_info "${SCRIPT_COMMAND_NAME} 管理面板 (v$SCRIPT_VERSION - $SCRIPT_DATE)"
    echo "--------------------------------------------"
    echo -e "${YELLOW}Hysteria 2 管理:${NC}"
    echo "  install (i)         - 安装或重装 Hysteria 2"
    echo "  start (run)         - 启动 Hysteria 服务"; echo "  stop (sp)           - 停止 Hysteria 服务"
    echo "  restart (re, rs)    - 重启 Hysteria 服务"; echo "  status (st)         - 查看 Hysteria 服务状态"
    echo "  enable (en)         - 设置 Hysteria 开机自启"; echo "  disable (dis)       - 禁止 Hysteria 开机自启"
    echo "  info (nfo)          - 显示 Hysteria 订阅链接和二维码"
    echo "  config (conf)       - 显示 Hysteria 配置摘要"
    echo "  config_edit (ce)    - 手动编辑 Hysteria 配置文件"
    echo "  config_change (cc)  - 交互修改 Hysteria 部分配置"
    echo "  logs (log)          - 查看 Hysteria 输出日志"; echo "  logs_err (loge)     - 查看 Hysteria 错误日志"
    _detect_os
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then echo "  logs_sys (logsy)    - 查看 Hysteria systemd 日志"; fi

    echo -e "\n${YELLOW}MTProto 代理 (mtg) 管理:${NC}"
    echo "  install_mtp (i_mtp) - 安装或重装 MTProto 代理"
    echo "  start_mtp (run_mtp) - 启动 MTProto 服务"; echo "  stop_mtp (sp_mtp)   - 停止 MTProto 服务"
    echo "  restart_mtp (re_mtp)- 重启 MTProto 服务"; echo "  status_mtp (st_mtp) - 查看 MTProto 服务状态"
    echo "  enable_mtp (en_mtp) - 设置 MTProto 开机自启"; echo "  disable_mtp (dis_mtp)- 禁止 MTProto 开机自启"
    echo "  info_mtp (nfo_mtp)  - 显示 MTProto 链接和二维码"
    echo "  config_mtp_edit (ce_mtp) - 手动编辑 MTProto 配置文件"
    echo "  logs_mtp (log_mtp)  - 查看 MTProto 输出日志"
    echo "  logs_err_mtp (loge_mtp) - 查看 MTProto 错误日志"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then echo "  logs_sys_mtp (logsy_mtp) - 查看 MTProto systemd 日志"; fi

    echo -e "\n${YELLOW}通用命令:${NC}"
    echo "  uninstall (un, u) - 同时卸载 Hysteria 2, MTProto 及此管理脚本" # Updated description
    echo "  update (up)       - 更新 Hysteria, MTG 程序和此管理脚本"
    echo "  version (v)       - 显示此脚本及已安装服务的版本"
    echo "  help (h)          - 显示此帮助菜单"
    echo "--------------------------------------------"
    echo "用法: sudo ${SCRIPT_COMMAND_NAME} <命令>"; echo "例如: sudo ${SCRIPT_COMMAND_NAME} i"; echo "      sudo ${SCRIPT_COMMAND_NAME} nfo_mtp"; echo "      sudo ${SCRIPT_COMMAND_NAME} up"; echo ""
    _log_info "此脚本在执行 'install' 或 'install_mtp' 时会尝试自动安装为 /usr/local/bin/${SCRIPT_COMMAND_NAME} 命令."
    _log_info "如果自动安装失败或想手动更新(确保URL正确):"; echo "  sudo wget -qO \"/usr/local/bin/${SCRIPT_COMMAND_NAME}\" \"$HY_SCRIPT_URL_ON_GITHUB\" && sudo chmod +x \"/usr/local/bin/${SCRIPT_COMMAND_NAME}\""
    echo ""
}
_show_management_commands_hint() { _log_info "您可使用 'sudo ${SCRIPT_COMMAND_NAME} help' 或 'sudo ${SCRIPT_COMMAND_NAME} h' 查看管理命令面板。"; }

# --- Main Script Logic ---
if [[ "$1" != "version" && "$1" != "v" && \
      "$1" != "help" && "$1" != "h" && "$1" != "" && \
      "$1" != "--help" && "$1" != "-h"  ]]; then
    _detect_os;
fi
ACTION="$1"
case "$ACTION" in
    install|i)              _do_install_hysteria ;;
    uninstall|un|u)         _do_uninstall_all ;;
    start|run)              _generic_control_service "hysteria" "start" ;;
    stop|sp)                _generic_control_service "hysteria" "stop" ;;
    restart|re|rs)          _generic_control_service "hysteria" "restart" ;;
    status|st)              _generic_control_service "hysteria" "status" ;;
    enable|en)              _generic_control_service "hysteria" "enable" ;;
    disable|dis)            _generic_control_service "hysteria" "disable" ;;
    info|nfo)               _show_hysteria_info_and_qrcode ;;
    config|conf)            _show_hysteria_config ;;
    config_edit|ce)
        _ensure_root; if ! _is_hysteria_installed; then _log_error "Hysteria未安装."; exit 1; fi;
        if [ -z "$EDITOR" ]; then EDITOR="vi"; fi;
        _log_info "使用 $EDITOR 打开 Hysteria 配置文件 $HYSTERIA_CONFIG_FILE ...";
        if $EDITOR "$HYSTERIA_CONFIG_FILE"; then _log_info "编辑完成。考虑重启服务: sudo $SCRIPT_COMMAND_NAME restart (或 re/rs)"; else _log_error "编辑器 '$EDITOR' 返回错误。"; fi ;;
    config_change|cc)       _change_hysteria_config_interactive ;;
    logs|log)
        _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; exit 1; fi;
        if [[ "$INIT_SYSTEM" == "openrc" ]] && [ ! -f "$LOG_FILE_HYSTERIA_OUT" ]; then _log_error "Hysteria 日志文件 $LOG_FILE_HYSTERIA_OUT 不存在。"; exit 1;
        elif [[ "$INIT_SYSTEM" == "systemd" ]] && [ ! -f "$LOG_FILE_HYSTERIA_OUT" ] && ! journalctl -u "$HYSTERIA_SERVICE_NAME_SYSTEMD" -n 1 --no-pager --quiet &>/dev/null; then
             _log_info "Hysteria Systemd 日志似乎也为空或服务从未成功启动过。";
             if [ ! -f "$LOG_FILE_HYSTERIA_OUT" ]; then _log_error "Hysteria 日志文件 $LOG_FILE_HYSTERIA_OUT 也不存在。"; exit 1; fi;
        fi;
        _log_info "按 CTRL+C 退出 (Hysteria 日志 $LOG_FILE_HYSTERIA_OUT)。"; tail -f "$LOG_FILE_HYSTERIA_OUT" ;;
    logs_err|loge)
        _detect_os; if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; exit 1; fi;
        if [[ "$INIT_SYSTEM" == "openrc" ]] && [ ! -f "$LOG_FILE_HYSTERIA_ERR" ]; then _log_error "Hysteria 错误日志 $LOG_FILE_HYSTERIA_ERR 不存在。"; exit 1;
        elif [[ "$INIT_SYSTEM" == "systemd" ]] && [ ! -f "$LOG_FILE_HYSTERIA_ERR" ] && ! journalctl -u "$HYSTERIA_SERVICE_NAME_SYSTEMD" -n 1 --no-pager --quiet &>/dev/null; then
            _log_info "Hysteria Systemd 日志似乎也为空或服务从未成功启动过。";
            if [ ! -f "$LOG_FILE_HYSTERIA_ERR" ]; then _log_error "Hysteria 错误日志 $LOG_FILE_HYSTERIA_ERR 也不存在。"; exit 1; fi;
        fi;
        _log_info "按 CTRL+C 退出 (Hysteria 错误日志 $LOG_FILE_HYSTERIA_ERR)。"; tail -f "$LOG_FILE_HYSTERIA_ERR" ;;
    logs_sys|logsy)
        _detect_os; if [[ "$INIT_SYSTEM" == "systemd" ]]; then if ! _is_hysteria_installed; then _log_error "Hysteria 未安装。"; exit 1; fi; _log_info "按 CTRL+C 退出 (Hysteria systemd 日志)。"; journalctl -u "$HYSTERIA_SERVICE_NAME_SYSTEMD" -f --no-pager;
        else _log_error "此命令仅适用于 systemd 系统上的 Hysteria 服务。"; fi ;;

    install_mtp|i_mtp)      _do_install_mtp ;;
    start_mtp|run_mtp)      _generic_control_service "mtg" "start" ;;
    stop_mtp|sp_mtp)        _generic_control_service "mtg" "stop" ;;
    restart_mtp|re_mtp)     _generic_control_service "mtg" "restart" ;;
    status_mtp|st_mtp)      _generic_control_service "mtg" "status" ;;
    enable_mtp|en_mtp)      _generic_control_service "mtg" "enable" ;;
    disable_mtp|dis_mtp)    _generic_control_service "mtg" "disable" ;;
    info_mtp|nfo_mtp)       _show_mtg_info_and_qrcode ;;
    config_mtp_edit|ce_mtp) _edit_mtg_config ;;
    logs_mtp|log_mtp)
        _detect_os; if ! _is_mtg_installed; then _log_error "MTProto (mtg) 未安装。"; exit 1; fi;
        if [[ "$INIT_SYSTEM" == "openrc" ]]; then if [ ! -f "$LOG_FILE_MTG_OUT" ]; then _log_error "MTG 日志文件 $LOG_FILE_MTG_OUT 不存在。"; exit 1; fi; _log_info "按 CTRL+C 退出 (MTG 日志 $LOG_FILE_MTG_OUT)。"; tail -f "$LOG_FILE_MTG_OUT";
        elif [[ "$INIT_SYSTEM" == "systemd" ]]; then _log_info "对于 systemd 系统, MTG 日志通常在 journald。将尝试显示 systemd 日志。"; "$0" logs_sys_mtp;
        else _log_error "未知初始化系统，无法确定MTG日志位置。"; fi ;;
    logs_err_mtp|loge_mtp)
        _detect_os; if ! _is_mtg_installed; then _log_error "MTProto (mtg) 未安装。"; exit 1; fi;
        if [[ "$INIT_SYSTEM" == "openrc" ]]; then if [ ! -f "$LOG_FILE_MTG_ERR" ]; then _log_error "MTG 错误日志 $LOG_FILE_MTG_ERR 不存在。"; exit 1; fi; _log_info "按 CTRL+C 退出 (MTG 错误日志 $LOG_FILE_MTG_ERR)。"; tail -f "$LOG_FILE_MTG_ERR";
        elif [[ "$INIT_SYSTEM" == "systemd" ]]; then _log_info "对于 systemd 系统, MTG 错误日志通常在 journald。将尝试显示 systemd 日志。"; "$0" logs_sys_mtp;
        else _log_error "未知初始化系统，无法确定MTG错误日志位置。"; fi ;;
    logs_sys_mtp|logsy_mtp)
        _detect_os; if [[ "$INIT_SYSTEM" == "systemd" ]]; then if ! _is_mtg_installed; then _log_error "MTProto (mtg) 未安装。"; exit 1; fi; _log_info "按 CTRL+C 退出 (MTG systemd 日志)。"; journalctl -u "$MTG_SERVICE_NAME_SYSTEMD" -f --no-pager;
        else _log_error "此命令仅适用于 systemd 系统上的 MTProto (mtg) 服务。"; fi ;;

    update|up)              _do_update ;;
    version|v)
        echo "$SCRIPT_COMMAND_NAME 管理脚本 v$SCRIPT_VERSION ($SCRIPT_DATE)"; echo "脚本文件: $SCRIPT_FILE_BASENAME"
        if _is_hysteria_installed || _is_mtg_installed; then _detect_os &>/dev/null; fi

        if command -v "$HYSTERIA_INSTALL_PATH" &>/dev/null; then
            HY_VERSION_RAW=$("$HYSTERIA_INSTALL_PATH" version 2>/dev/null | grep '^Version:' | awk '{print $2}')
            HY_VERSION=$(echo "$HY_VERSION_RAW" | sed 's#^v##')
            if [ -n "$HY_VERSION" ]; then echo "已安装 Hysteria 版本: $HY_VERSION_RAW (规范化为: $HY_VERSION)"; else _log_warning "无法从 '$HYSTERIA_INSTALL_PATH version' 解析 Hysteria 版本号。"; fi
        elif _is_hysteria_installed; then
             _log_warning "Hysteria 部分安装 (程序文件 $HYSTERIA_INSTALL_PATH 未找到或不可执行)。"
        else
            _log_debug "Hysteria 未安装。"
        fi

        if command -v "$MTG_INSTALL_PATH" &>/dev/null; then
            MTG_VERSION_REPORTED=$(_get_current_mtg_version)
            if [[ -n "$MTG_VERSION_REPORTED" && "$MTG_VERSION_REPORTED" != "unknown" ]]; then
                echo "已安装 MTG 版本: $MTG_VERSION_REPORTED (提示: 使用 9seconds/mtg)"
            else
                local mtg_raw_ver_output
                mtg_raw_ver_output=$("$MTG_INSTALL_PATH" --version 2>/dev/null || "$MTG_INSTALL_PATH" -v 2>/dev/null)
                _log_warning "无法从 '$MTG_INSTALL_PATH -v/--version' 解析 MTG 版本号 (原始输出: '$mtg_raw_ver_output')。"
            fi
        elif _is_mtg_installed; then
            _log_warning "MTProto (mtg) 部分安装 (程序文件 $MTG_INSTALL_PATH 未找到或不可执行)。"
        else
            _log_debug "MTProto (mtg) 未安装。"
        fi
        ;;
    help|h|--help|-h|"")   _show_menu ;;
    *)                      _log_error "未知命令: $ACTION"; _show_menu; exit 1 ;;
esac
exit 0
