#!/usr/bin/env bash
#
# nftables 端口转发管理工具 v1.6
# 交互式管理 DNAT 端口转发规则（支持规则命名 + DNS 动态转发）
# v1.5: DNS 动态转发去掉手动 IP，域名解析 IP 同时作为 DNAT 目标
# v1.6: 安装流程默认不清空全局规则，增加 Web 面板管理
#

# ============== 常量定义 ==============
CONF_DIR="/etc/nftables.d"
CONF_FILE="${CONF_DIR}/port-forward.conf"
DNS_CONF_FILE="${CONF_DIR}/dns-forward.conf"
DNS_USER_CONF="${CONF_DIR}/dns-forward.rules"
DNSMASQ_CONF_DIR="/etc/dnsmasq.d"
DNSMASQ_CONF="${DNSMASQ_CONF_DIR}/dns-forward.conf"
DNS_SET_SYNC_TIMER="dns-nft-sync.timer"
DNS_SET_SYNC_SERVICE="dns-nft-sync.service"
DNS_SET_SYNC_SCRIPT="/usr/local/bin/dns-nft-sync.sh"
BACKUP_DIR="${CONF_DIR}/backups"
MAIN_CONF="/etc/nftables.conf"
SYSCTL_CONF="/etc/sysctl.d/99-nft-forward.conf"
LOG_FILE="/var/log/nft-forward.log"
LOGROTATE_CONF="/etc/logrotate.d/nft-forward"
TABLE_NAME="port_forward"
PANEL_BIN="/usr/local/bin/nft-forward-panel"
PANEL_SERVICE="nft-forward-panel.service"
PANEL_SERVICE_FILE="/etc/systemd/system/${PANEL_SERVICE}"
PANEL_PORT_DEFAULT="4788"
PANEL_USER_DEFAULT="admin"
PANEL_PASS_DEFAULT="admin123"
PANEL_CERT_DEFAULT="/root/ygkkkca/cert.crt"
PANEL_KEY_DEFAULT="/root/ygkkkca/private.key"

# ============== 日志函数 ==============
log_action() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

# ============== 输出辅助（用 printf 避免 echo -e 转义副作用） ==============
info()    { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
warn()    { printf '\033[33m[警告]\033[0m %s\n' "$1"; }
err()     { printf '\033[31m[错误]\033[0m %s\n' "$1"; }

# ============== root 权限检查 ==============
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "此脚本需要 root 权限运行，请使用 sudo 或 root 用户执行。"
        exit 1
    fi
}

# ============== 输入验证 ==============
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^0[0-9] ]]; then
        return 1
    fi
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    if [[ "$ip" =~ (^|\.)0[0-9] ]]; then
        return 1
    fi
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet > 255 )); then
            return 1
        fi
    done
    return 0
}

validate_listen_host() {
    local host="$1"
    [[ "$host" == "0.0.0.0" || "$host" == "127.0.0.1" || "$host" == "localhost" ]] && return 0
    validate_ip "$host"
}

validate_public_ipv4() {
    local ip="$1"
    validate_ip "$ip" || return 1

    local IFS='.'
    local a b c d
    read -r a b c d <<< "$ip"

    # IP 证书只能给公网 IP 申请，内网、回环、链路本地、组播/保留地址都拒绝。
    (( a == 0 || a == 10 || a == 127 || a >= 224 )) && return 1
    (( a == 100 && b >= 64 && b <= 127 )) && return 1
    (( a == 169 && b == 254 )) && return 1
    (( a == 172 && b >= 16 && b <= 31 )) && return 1
    (( a == 192 && b == 168 )) && return 1
    (( a == 198 && (b == 18 || b == 19) )) && return 1

    return 0
}

find_acme_sh() {
    if command -v acme.sh &>/dev/null; then
        command -v acme.sh
        return 0
    fi
    if [[ -x "${HOME}/.acme.sh/acme.sh" ]]; then
        echo "${HOME}/.acme.sh/acme.sh"
        return 0
    fi
    if [[ -x "/root/.acme.sh/acme.sh" ]]; then
        echo "/root/.acme.sh/acme.sh"
        return 0
    fi
    return 1
}

install_acme_deps() {
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    case "$pkg_mgr" in
        apt)
            apt-get update -y >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y curl socat openssl ca-certificates >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y curl socat openssl ca-certificates >/dev/null 2>&1
            ;;
        yum)
            yum install -y curl socat openssl ca-certificates >/dev/null 2>&1
            ;;
        pacman)
            pacman -Sy --noconfirm curl socat openssl ca-certificates >/dev/null 2>&1
            ;;
        *)
            command -v curl &>/dev/null && command -v socat &>/dev/null
            ;;
    esac
}

ensure_acme_sh() {
    local acme_bin acme_email
    acme_bin=$(find_acme_sh 2>/dev/null || true)
    if [[ -n "$acme_bin" ]]; then
        echo "$acme_bin"
        return 0
    fi

    warn "未检测到 acme.sh，将自动安装用于申请真实 IP 证书。" >&2
    install_acme_deps || true
    if ! command -v curl &>/dev/null; then
        err "未安装 curl，无法安装 acme.sh。" >&2
        return 1
    fi

    read -rp "Let's Encrypt 账号邮箱 [可留空]: " acme_email
    if [[ -n "$acme_email" ]]; then
        curl -fsSL https://get.acme.sh | sh -s "email=${acme_email}" >/dev/null || return 1
    else
        curl -fsSL https://get.acme.sh | sh >/dev/null || return 1
    fi

    acme_bin=$(find_acme_sh 2>/dev/null || true)
    if [[ -z "$acme_bin" ]]; then
        err "acme.sh 安装后仍未找到可执行文件。" >&2
        return 1
    fi

    echo "$acme_bin"
}

ensure_acme_auto_renew() {
    local acme_bin="$1"

    "$acme_bin" --upgrade --auto-upgrade >/dev/null 2>&1 || true
    "$acme_bin" --install-cronjob >/dev/null 2>&1 || true

    if command -v crontab &>/dev/null && crontab -l 2>/dev/null | grep -q "acme.sh.*--cron"; then
        info "已确认 acme.sh 自动续期任务。"
        return 0
    fi

    warn "未检测到 acme.sh cron 续期任务。证书已安装，但请确认系统允许 cron 运行。"
    warn "可手动检查: crontab -l | grep acme.sh"
}

issue_ip_certificate() {
    local cert_ip="$1"
    local cert_path="$2"
    local key_path="$3"
    local acme_bin cert_dir key_dir reload_cmd

    acme_bin=$(ensure_acme_sh) || {
        err "acme.sh 准备失败，无法申请 IP 证书。"
        return 1
    }

    cert_dir=$(dirname "$cert_path")
    key_dir=$(dirname "$key_path")
    reload_cmd="systemctl restart ${PANEL_SERVICE}"

    warn "开始申请 Let's Encrypt 真实 IP 证书。"
    warn "要求：${cert_ip} 必须是本机公网 IP，并且公网 80 端口能访问到这台服务器。"

    "$acme_bin" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
    "$acme_bin" --upgrade --auto-upgrade >/dev/null 2>&1 || true

    if ! "$acme_bin" --issue --server letsencrypt --standalone -d "$cert_ip" \
        --certificate-profile shortlived --days 3 --force; then
        err "IP 证书申请失败。请确认公网 IP 正确、80 端口未被占用且防火墙/安全组已放行。"
        return 1
    fi

    mkdir -p "$cert_dir" "$key_dir" || {
        err "无法创建证书安装目录。"
        return 1
    }

    if ! "$acme_bin" --install-cert -d "$cert_ip" \
        --key-file "$key_path" \
        --fullchain-file "$cert_path" \
        --reloadcmd "$reload_cmd"; then
        err "证书申请成功，但安装到指定路径失败。"
        return 1
    fi

    ensure_acme_auto_renew "$acme_bin"

    chmod 600 "$key_path" 2>/dev/null || true
    info "IP 证书已申请并安装。"
    info "acme.sh 将自动续期，续期后会执行: ${reload_cmd}"
    info "证书: ${cert_path}"
    info "私钥: ${key_path}"
}

get_panel_env() {
    local key="$1"
    if [[ -f "${PANEL_SERVICE_FILE}" ]]; then
        sed -n -E "s|^Environment=\"${key}=([^\"]*)\"$|\\1|p" "${PANEL_SERVICE_FILE}" | tail -1
    fi
}

verify_panel_https() {
    local host="$1"
    local port="$2"
    local cert_ip="$3"

    if ! command -v python3 &>/dev/null; then
        warn "未安装 python3，已跳过 HTTPS 握手检测。"
        return 0
    fi

    local check_host="127.0.0.1"
    [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]] && check_host="$host"

    if python3 - "$check_host" "$port" "${cert_ip:-$check_host}" <<'PY' >/dev/null 2>&1
import socket
import ssl
import sys

host, port, server_name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl._create_unverified_context()
with socket.create_connection((host, port), timeout=8) as sock:
    with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
        tls.version()
PY
    then
        return 0
    fi

    warn "HTTPS 握手自检未通过，但面板配置已写入并已重启。"
    warn "如果日志显示 listening on https://...，可直接使用 HTTPS 访问。"
    echo "排查命令: journalctl -u ${PANEL_SERVICE} -n 80 --no-pager"
    return 0
}

sanitize_rule_name() {
    local name="$1"
    name="${name//$'\r'/ }"
    name="${name//$'\n'/ }"
    name="${name//|/-}"
    name=$(printf '%s' "$name" | sed -E 's/[[:cntrl:]]//g; s/^[[:space:]]+//; s/[[:space:]]+$//')
    printf '%s' "${name:0:60}"
}

# ============== 自动获取本机 IP ==============
get_local_ip() {
    local ip
    ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1) || true
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    ip=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1) || true
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    hostname -I 2>/dev/null | awk '{print $1}' || true
}

# ============== 发行版检测 ==============
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# ============== iptables 可用性检测 ==============
has_iptables() {
    command -v iptables &>/dev/null && iptables -S &>/dev/null
}

# ============== 安装并启用 iptables 持久化工具 ==============
install_iptables_persistent() {
    # 已安装则直接返回
    if command -v netfilter-persistent &>/dev/null; then
        return 0
    fi

    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    info "正在安装 iptables 持久化工具..."

    case "$pkg_mgr" in
        apt)
            # Debian/Ubuntu: netfilter-persistent + iptables-persistent 插件
            # DEBIAN_FRONTEND=noninteractive 避免交互询问"是否保存当前规则"
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                netfilter-persistent iptables-persistent 2>/dev/null
            ;;
        dnf)
            dnf install -y iptables-services 2>/dev/null
            ;;
        yum)
            yum install -y iptables-services 2>/dev/null
            ;;
        pacman)
            # Arch 用 iptables-nft 或 iptables；持久化通过 systemd service
            pacman -Sy --noconfirm iptables 2>/dev/null
            ;;
        *)
            warn "无法识别包管理器，跳过自动安装持久化工具。"
            return 1
            ;;
    esac

    # 安装后启用服务（确保开机自动加载已保存规则）
    if command -v netfilter-persistent &>/dev/null; then
        systemctl enable netfilter-persistent 2>/dev/null || true
        info "已安装并启用 netfilter-persistent。"
        log_action "安装并启用 netfilter-persistent"
        return 0
    fi

    # CentOS/RHEL 的 iptables-services
    if systemctl list-unit-files 2>/dev/null | grep -q "^iptables.service"; then
        systemctl enable iptables 2>/dev/null || true
        info "已启用 iptables.service（CentOS/RHEL 持久化）。"
        log_action "启用 iptables.service"
        return 0
    fi

    warn "持久化工具安装后未能确认可用，请手动检查。"
    return 1
}

# ============== iptables 规则持久化 ==============
try_persist_iptables() {
    # 优先使用 netfilter-persistent（Debian/Ubuntu 标准工具）
    if command -v netfilter-persistent &>/dev/null; then
        if netfilter-persistent save >/dev/null 2>&1; then
            info "iptables 规则已通过 netfilter-persistent 持久化。"
            log_action "netfilter-persistent save"
            return 0
        fi
    fi

    # 次选：iptables-save 直接写文件（RHEL/CentOS 风格）
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null && {
                info "iptables 规则已保存至 /etc/iptables/rules.v4。"
                log_action "iptables-save > /etc/iptables/rules.v4"
                return 0
            }
        fi
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null && {
                info "iptables 规则已保存至 /etc/sysconfig/iptables。"
                log_action "iptables-save > /etc/sysconfig/iptables"
                return 0
            }
        fi
    fi

    # 末选：service iptables save（旧版 CentOS）
    if command -v service &>/dev/null; then
        service iptables save >/dev/null 2>&1 && {
            info "iptables 规则已通过 service iptables save 持久化。"
            log_action "service iptables save"
            return 0
        }
    fi

    return 1
}

# ============== 确保 iptables 持久化可用（安装 + 保存） ==============
# 在添加/删除 iptables 规则后调用此函数
ensure_iptables_persistent() {
    # 尝试直接保存
    if try_persist_iptables; then
        return 0
    fi

    # 保存失败，尝试安装持久化工具后再保存
    warn "未检测到 iptables 持久化工具，尝试自动安装..."
    if install_iptables_persistent; then
        if try_persist_iptables; then
            return 0
        fi
    fi

    warn "iptables 规则已生效但未能持久化，重启后将丢失。"
    warn "请手动安装: apt install netfilter-persistent iptables-persistent"
    return 1
}

# ============== 检查目标是否仍被其他规则使用 ==============
dest_still_used() {
    local check_ip="$1" check_dport="$2" exclude_lport="$3"
    local rule lport dip dport
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport _ <<< "$rule"
        [[ "$lport" == "$exclude_lport" ]] && continue
        if [[ "$dip" == "$check_ip" && "$dport" == "$check_dport" ]]; then
            return 0
        fi
    done
    return 1
}

# ============== firewalld / iptables 端口放行 ==============
firewall_open_port() {
    local lport="$1" dest_ip="$2" dport="$3"

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --add-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --add-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "已在 firewalld 中放行端口 ${lport} (tcp+udp)。"
        log_action "firewalld 放行端口 ${lport}"
        return
    fi

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        ufw allow "${lport}/tcp" >/dev/null 2>&1 || true
        ufw allow "${lport}/udp" >/dev/null 2>&1 || true
        ufw route allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        ufw route allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        info "已在 UFW 中放行端口 ${lport} 及转发到 ${dest_ip}:${dport} (tcp+udp)。"
        log_action "UFW 放行端口 ${lport} 转发到 ${dest_ip}:${dport}"
        return
    fi

    if has_iptables; then
        iptables -C INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        info "已在 iptables 中放行: INPUT ${lport}, FORWARD → ${dest_ip}:${dport} (tcp+udp)。"
        log_action "iptables 放行 INPUT:${lport} FORWARD:${dest_ip}:${dport}"
        # 自动安装持久化工具并保存
        ensure_iptables_persistent
    fi
}

firewall_close_port() {
    local lport="$1" dest_ip="$2" dport="$3" force="${4:-}"

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --remove-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --remove-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "已从 firewalld 中移除端口 ${lport} 的放行规则。"
        log_action "firewalld 移除端口 ${lport}"
        return
    fi

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        yes | ufw delete allow "${lport}/tcp" >/dev/null 2>&1 || true
        yes | ufw delete allow "${lport}/udp" >/dev/null 2>&1 || true
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            yes | ufw route delete allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
            yes | ufw route delete allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        fi
        info "已从 UFW 中移除端口 ${lport} 的放行规则。"
        log_action "UFW 移除端口 ${lport}"
        return
    fi

    if has_iptables; then
        iptables -D INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            iptables -D FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        fi
        info "已从 iptables 中移除: INPUT ${lport}, FORWARD → ${dest_ip}:${dport}。"
        log_action "iptables 移除 INPUT:${lport} FORWARD:${dest_ip}:${dport}"
        # 删除规则后也持久化
        ensure_iptables_persistent
    fi
}

# ============== 端口占用检测（TCP + UDP） ==============
check_port_conflict() {
    local port="$1"
    local conflict=""
    if ss -tlnp 2>/dev/null | grep -qE ":${port}\b"; then
        conflict="TCP"
    fi
    if ss -ulnp 2>/dev/null | grep -qE ":${port}\b"; then
        if [[ -n "$conflict" ]]; then
            conflict="TCP+UDP"
        else
            conflict="UDP"
        fi
    fi
    if [[ -n "$conflict" ]]; then
        warn "本机端口 ${port} 已被其他服务占用（${conflict}）。"
        warn "添加转发后，该端口的外部流量将被转发，本地服务可能无法从外部访问。"
        read -rp "是否仍要继续添加转发规则？[y/N]: " ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    return 0
}

# ============== 初始化配置文件结构 ==============
init_conf() {
    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" 2>/dev/null || {
        err "无法创建配置目录 ${CONF_DIR}，请检查权限。"
        return 1
    }

    touch "${LOG_FILE}" 2>/dev/null || true

    if [[ ! -f "${LOGROTATE_CONF}" ]]; then
        cat > "${LOGROTATE_CONF}" <<'LOGROTATE'
/var/log/nft-forward.log {
    monthly
    rotate 6
    compress
    missingok
    notifempty
}
LOGROTATE
    fi

    if [[ ! -f "${MAIN_CONF}" ]]; then
        cat > "${MAIN_CONF}" <<'NFTCONF'
#!/usr/sbin/nft -f
include "/etc/nftables.d/*.conf"
NFTCONF
        info "已创建 ${MAIN_CONF}（系统中不存在该文件）。"
        log_action "创建 ${MAIN_CONF}"
    elif ! grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
        echo 'include "/etc/nftables.d/*.conf"' >> "${MAIN_CONF}"
        info "已在 ${MAIN_CONF} 中添加 include 指令。"
        log_action "在 ${MAIN_CONF} 中添加 include 指令"
    fi

    if [[ ! -f "${CONF_FILE}" ]]; then
        write_conf_file || return 1
    fi
}

# ============== 写出配置文件（基于当前 RULES 数组） ==============
declare -a RULES=()

load_rules() {
    RULES=()
    if [[ ! -f "${CONF_FILE}" ]]; then
        return
    fi
    local prev_comment=""
    while IFS= read -r line; do
        # 收集注释行
        if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*(.+)$ ]]; then
            prev_comment="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ tcp\ dport\ ([0-9]+)\ dnat\ to\ ([0-9.]+):([0-9]+) ]]; then
            local lport="${BASH_REMATCH[1]}" dip="${BASH_REMATCH[2]}" dport="${BASH_REMATCH[3]}"
            local name="${prev_comment}"
            RULES+=("${lport}|${dip}|${dport}|${name}")
            prev_comment=""
        else
            prev_comment=""
        fi
    done < "${CONF_FILE}"
}

write_conf_file() {
    local local_ip
    local_ip=$(get_local_ip)

    if [[ -z "$local_ip" ]]; then
        err "无法获取本机 IP 地址，请检查网络配置。"
        return 1
    fi

    local tmp_file="${CONF_FILE}.tmp.$$"

    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f

# --- 本机 IP（自动获取，用于 SNAT 回源）
define LOCAL_IP = ${local_ip}

table ip ${TABLE_NAME} {
    # --- PREROUTING (DNAT) ---
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    local rule lport dip dport name
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport name <<< "$rule"
        if [[ -n "$name" ]]; then
            cat >> "${tmp_file}" <<EOF

        # ${name}
        tcp dport ${lport} dnat to ${dip}:${dport}
        udp dport ${lport} dnat to ${dip}:${dport}
EOF
        else
            cat >> "${tmp_file}" <<EOF

        # 转发: 本机:${lport} -> ${dip}:${dport}
        tcp dport ${lport} dnat to ${dip}:${dport}
        udp dport ${lport} dnat to ${dip}:${dport}
EOF
        fi
    done

    cat >> "${tmp_file}" <<EOF
    }

    # --- POSTROUTING (SNAT) ---
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF

    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport _ <<< "$rule"
        cat >> "${tmp_file}" <<EOF

        # 回源: 发往 ${dip}:${dport} 的已 DNAT 流量, SNAT 为本机 IP
        ip daddr ${dip} tcp dport ${dport} ct status dnat snat to \$LOCAL_IP
        ip daddr ${dip} udp dport ${dport} ct status dnat snat to \$LOCAL_IP
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }
}
EOF

    mv -f "${tmp_file}" "${CONF_FILE}" 2>/dev/null || {
        err "无法写入配置文件 ${CONF_FILE}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
}

# ============== 重新加载规则 ==============
reload_rules() {
    nft flush table ip "${TABLE_NAME}" 2>/dev/null || true
    nft delete table ip "${TABLE_NAME}" 2>/dev/null || true
    if ! nft -f "${CONF_FILE}"; then
        err "加载配置文件失败，请检查 ${CONF_FILE}"
        return 1
    fi
    return 0
}

# ============== 备份配置 ==============
backup_conf() {
    if [[ -f "${CONF_FILE}" ]]; then
        local ts
        ts=$(date '+%Y%m%d_%H%M%S')
        cp "${CONF_FILE}" "${BACKUP_DIR}/port-forward.conf.${ts}" 2>/dev/null || true
    fi
}

# ============== 开启内核参数 ==============
enable_ip_forward() {
    local current
    current=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || current="0"
    if [[ "$current" != "1" ]]; then
        if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
            info "已开启 IPv4 转发。"
        else
            warn "无法开启 IPv4 转发，请手动执行: sysctl -w net.ipv4.ip_forward=1"
        fi
    fi

    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    touch "${SYSCTL_CONF}" 2>/dev/null || true

    if grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "${SYSCTL_CONF}" 2>/dev/null; then
        sed -i -E 's|^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*|net.ipv4.ip_forward=1|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.ipv4.ip_forward=1" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi

    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
}

enable_bbr_fq() {
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        warn "内核不支持 BBR，已跳过。"
        return 0
    fi

    local cur_cc cur_qd
    cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || cur_cc=""
    cur_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null) || cur_qd=""

    if [[ "$cur_cc" == "bbr" && "$cur_qd" == "fq" ]]; then
        info "BBR + fq 已启用（无需修改）。"
        return 0
    fi

    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true

    cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || cur_cc=""
    cur_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null) || cur_qd=""

    if [[ "$cur_cc" == "bbr" && "$cur_qd" == "fq" ]]; then
        info "已开启 BBR + fq。"
        log_action "开启 BBR+fq"
    else
        warn "BBR+fq 未确认生效（cc=${cur_cc:-?}, qdisc=${cur_qd:-?}）。"
    fi

    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    touch "${SYSCTL_CONF}" 2>/dev/null || true

    if grep -qE '^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=' "${SYSCTL_CONF}"; then
        sed -i -E 's|^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=.*|net.core.default_qdisc=fq|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.core.default_qdisc=fq" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi

    if grep -qE '^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=' "${SYSCTL_CONF}"; then
        sed -i -E 's/^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=.*/net.ipv4.tcp_congestion_control=bbr/' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.ipv4.tcp_congestion_control=bbr" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi

    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
    info "已持久化 BBR + fq 到 ${SYSCTL_CONF}。"
    log_action "持久化 BBR+fq 到 ${SYSCTL_CONF}"
}

# ============== 检测防火墙状态（仅提示） ==============
check_firewall_status() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        info "检测到 firewalld 正在运行，添加转发规则时将自动放行对应端口。"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        info "检测到 UFW 正在运行，添加转发规则时将自动放行对应端口。"
    elif has_iptables; then
        info "检测到 iptables 规则集存在，添加转发规则时将自动放行对应端口。"
    fi
}

# ============== 诊断/自检 ==============
do_diagnose() {
    echo ""
    echo "========================================"
    echo "           诊断 / 自检"
    echo "========================================"

    local ip_fwd
    ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || ip_fwd="未知"
    if [[ "$ip_fwd" == "1" ]]; then
        info "IPv4 转发: 已开启"
    else
        err  "IPv4 转发: 未开启 (当前值: ${ip_fwd})"
        echo "  → 修复: 选择菜单【安装 nftables】会自动开启"
    fi

    if command -v nft &>/dev/null; then
        info "nftables: 已安装 ($(nft --version 2>/dev/null || echo '未知版本'))"
    else
        err  "nftables: 未安装"
        echo "  → 修复: 选择菜单【安装 nftables】"
    fi

    local svc_enabled svc_active
    svc_enabled=$(systemctl is-enabled nftables 2>/dev/null) || svc_enabled="unknown"
    svc_active=$(systemctl is-active nftables 2>/dev/null) || svc_active="unknown"

    if [[ "$svc_enabled" == "enabled" ]]; then
        info "nftables 开机启动: 是"
    else
        warn "nftables 开机启动: 否（重启后规则可能丢失）"
        echo "  → 修复: systemctl enable nftables"
    fi

    if [[ "$svc_active" == "active" ]]; then
        info "nftables 服务状态: 运行中"
    else
        warn "nftables 服务状态: 未运行"
        echo "  → 修复: systemctl start nftables"
    fi

    if nft list table ip "${TABLE_NAME}" &>/dev/null; then
        load_rules
        info "转发规则表: 已加载（${#RULES[@]} 条转发规则）"
    else
        warn "转发规则表: 未加载（可能无规则或服务未启动）"
    fi

    # ---- iptables 持久化状态 ----
    echo ""
    echo "--- iptables 持久化状态 ---"
    if command -v netfilter-persistent &>/dev/null; then
        info "netfilter-persistent: 已安装"
        local nfp_status
        nfp_status=$(systemctl is-enabled netfilter-persistent 2>/dev/null) || nfp_status="unknown"
        if [[ "$nfp_status" == "enabled" ]]; then
            info "netfilter-persistent 开机启动: 是"
        else
            warn "netfilter-persistent 开机启动: 否"
            echo "  → 修复: systemctl enable netfilter-persistent"
        fi
        # 检查已保存的规则文件
        if [[ -f /etc/iptables/rules.v4 ]]; then
            local rule_count
            rule_count=$(grep -c '^-' /etc/iptables/rules.v4 2>/dev/null) || rule_count=0
            info "已保存的 iptables 规则: ${rule_count} 条 (/etc/iptables/rules.v4)"
        else
            warn "尚未保存 iptables 规则 (未找到 /etc/iptables/rules.v4)"
        fi
    elif systemctl list-unit-files 2>/dev/null | grep -q "^iptables.service"; then
        local ipt_status
        ipt_status=$(systemctl is-enabled iptables 2>/dev/null) || ipt_status="unknown"
        if [[ "$ipt_status" == "enabled" ]]; then
            info "iptables.service 开机启动: 是"
        else
            warn "iptables.service 开机启动: 否"
            echo "  → 修复: systemctl enable iptables"
        fi
    else
        warn "未检测到 iptables 持久化工具（netfilter-persistent / iptables-persistent）"
        echo "  → 修复: 选择菜单【安装 iptables-persistent】"
    fi

    echo ""
    echo "--- 防火墙状态 ---"
    local fw_found=false

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        fw_found=true
        info "firewalld: 活跃"
    fi

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        fw_found=true
        warn "UFW: 活跃（默认会阻止入站连接，可能影响转发）"
    fi

    if ! $fw_found && has_iptables; then
        fw_found=true
        local fwd_policy
        fwd_policy=$(iptables -S FORWARD 2>/dev/null | grep -- '^-P FORWARD' | awk '{print $3}') || fwd_policy=""
        if [[ "$fwd_policy" == "DROP" || "$fwd_policy" == "REJECT" ]]; then
            warn "iptables FORWARD 默认策略: ${fwd_policy}（可能阻止转发流量）"
        else
            info "iptables FORWARD 默认策略: ${fwd_policy:-ACCEPT}"
        fi
    fi

    if ! $fw_found; then
        info "未检测到活跃的防火墙 (firewalld / UFW / iptables)"
    fi

    echo ""
    echo "--- nftables forward 链 ---"
    local fwd_chains
    fwd_chains=$(nft list chains 2>/dev/null | grep -B1 "hook forward" || true)
    if [[ -n "$fwd_chains" ]]; then
        if echo "$fwd_chains" | grep -qi "drop"; then
            warn "检测到 nftables forward 链默认策略为 drop，会阻止所有转发流量。"
            echo "  查看详情: nft list ruleset | grep -A5 'hook forward'"
        else
            info "nftables forward 链: 未发现 drop 策略"
        fi
    else
        info "未检测到 nftables forward 链（正常）"
    fi

    echo ""
    echo "--- 配置持久化 ---"
    if [[ -f "${MAIN_CONF}" ]]; then
        if grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
            info "主配置 ${MAIN_CONF}: 已包含 include 指令"
        else
            warn "主配置 ${MAIN_CONF}: 缺少 include 指令"
            echo "  → 修复: 选择菜单【安装 nftables】"
        fi
    else
        warn "主配置 ${MAIN_CONF}: 不存在"
    fi

    if [[ -f "${CONF_FILE}" ]]; then
        info "转发配置文件: ${CONF_FILE} 存在"
    else
        info "转发配置文件: 尚未创建（添加首条规则时自动生成）"
    fi

    load_rules
    load_dns_rules
    local test_conn=""
    if [[ ${#RULES[@]} -gt 0 || ${#DNS_RULES[@]} -gt 0 ]]; then
        read -rp "是否测试目标连通性？[y/N]: " test_conn
    fi

    # 普通转发连通性测试
    if [[ ${#RULES[@]} -gt 0 ]]; then
        if [[ "$test_conn" =~ ^[Yy]$ ]]; then
        local rule lport dip dport name
        for rule in "${RULES[@]}"; do
            IFS='|' read -r lport dip dport name <<< "$rule"
            printf "  [%s] %s:%s (TCP) ... " "${name:-unnamed}" "$dip" "$dport"
                if timeout 3 bash -c ">/dev/tcp/${dip}/${dport}" 2>/dev/null; then
                    printf "\033[32m通\033[0m\n"
                else
                    printf "\033[31m不通或超时\033[0m\n"
                fi
            done
        fi
    fi

    # DNS 动态转发状态
    load_dns_rules
    if [[ ${#DNS_RULES[@]} -gt 0 ]]; then
        echo ""
        echo "--- DNS 动态转发 ---"
        info "DNS 转发规则: ${#DNS_RULES[@]} 条"
        if nft list table ip port_forward_dns &>/dev/null; then
            info "DNS 转发表: 已加载"
        else
            warn "DNS 转发表: 未加载"
            echo "  → 修复: 进入菜单 [8] → [4] 手动同步"
        fi
        if systemctl list-unit-files 2>/dev/null | grep -q "^${DNS_SET_SYNC_TIMER}"; then
            if systemctl is-active --quiet "${DNS_SET_SYNC_TIMER}" 2>/dev/null; then
                info "DNS 定时同步: 已启用（每5分钟）"
            else
                warn "DNS 定时同步: 已安装但未运行"
                echo "  → 修复: systemctl start ${DNS_SET_SYNC_TIMER}"
            fi
        else
            warn "DNS 定时同步: 未安装"
            echo "  → 修复: 进入菜单 [8] → [1] 添加规则时会提示安装"
        fi
        # 显示各域名解析状态 + 连通性测试
        local rule domain lport dport set_name ip_list
        for rule in "${DNS_RULES[@]}"; do
            IFS='|' read -r domain lport dport set_name <<< "$rule"
            ip_list=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ',' | sed 's/,$//') || ip_list=""
            if [[ -n "$ip_list" ]]; then
                info "  ${domain}:${lport} -> ${ip_list}:${dport}"
                # 连通性测试（对每个解析 IP）
                if [[ "$test_conn" =~ ^[Yy]$ ]]; then
                    local IFS_BAK="$IFS"
                    IFS=','
                    for rip in $ip_list; do
                        printf "    [%s:%s] TCP ... " "$rip" "$dport"
                        if timeout 3 bash -c ">/dev/tcp/${rip}/${dport}" 2>/dev/null; then
                            printf "\033[32m通\033[0m\n"
                        else
                            printf "\033[31m不通或超时\033[0m\n"
                        fi
                    done
                    IFS="$IFS_BAK"
                fi
            else
                warn "  ${domain}:${lport} -> [未解析]:${dport}"
            fi
        done
    fi

    echo ""
}

# ====================================================
# 功能 1：安装 nftables
# ====================================================
do_install() {
    echo ""
    if command -v nft &>/dev/null; then
        info "nftables 已安装。"
        nft --version 2>/dev/null || true
        echo ""
        info "将只初始化本脚本自己的配置，不会清空全局 nftables 规则集。"

        enable_ip_forward
        read -rp "是否启用 BBR + fq 网络优化？[y/N]: " ans_bbr
        if [[ "$ans_bbr" =~ ^[Yy]$ ]]; then
            enable_bbr_fq
        else
            info "已跳过 BBR + fq。"
        fi
        check_firewall_status
        init_conf

        if ! nft -f "${CONF_FILE}"; then
            err "加载 ${CONF_FILE} 失败，请检查配置。"
            return
        fi

        if systemctl enable --now nftables 2>/dev/null; then
            info "已启用 nftables 服务。"
        else
            warn "nftables 服务启用失败，请手动执行: systemctl enable --now nftables"
        fi

        # 若当前使用 iptables 管理防火墙，顺便确保持久化工具已就绪
        if has_iptables && ! systemctl is-active --quiet firewalld 2>/dev/null; then
            info "检测到 iptables，正在确保持久化工具已安装..."
            install_iptables_persistent || true
        fi

        info "初始化完成。"
        return
    fi

    info "未检测到 nftables，准备安装..."
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    case "$pkg_mgr" in
        apt)
            apt-get update -y && apt-get install -y nftables
            ;;
        dnf)
            dnf install -y nftables
            ;;
        yum)
            yum install -y nftables
            ;;
        pacman)
            pacman -Sy --noconfirm nftables
            ;;
        *)
            err "无法识别包管理器，请手动安装 nftables。"
            return
            ;;
    esac

    if ! command -v nft &>/dev/null; then
        err "安装失败，请手动安装 nftables。"
        return
    fi

    info "nftables 安装成功。"
    nft --version 2>/dev/null || true
    log_action "安装 nftables"

    enable_ip_forward
    read -rp "是否启用 BBR + fq 网络优化？[y/N]: " ans_bbr
    if [[ "$ans_bbr" =~ ^[Yy]$ ]]; then
        enable_bbr_fq
    else
        info "已跳过 BBR + fq。"
    fi
    check_firewall_status
    init_conf

    if systemctl enable --now nftables 2>/dev/null; then
        info "已启用 nftables 服务。"
    else
        warn "nftables 服务启用失败，请手动执行: systemctl enable --now nftables"
    fi

    # 安装 iptables 持久化工具
    if has_iptables && ! systemctl is-active --quiet firewalld 2>/dev/null; then
        info "正在安装 iptables 持久化工具..."
        install_iptables_persistent || true
    fi

    info "安装与初始化完成。"
}

# ====================================================
# 功能 1.5：单独安装 iptables-persistent
# ====================================================
do_install_iptables_persistent() {
    echo ""
    if command -v netfilter-persistent &>/dev/null; then
        info "netfilter-persistent 已安装。"
        local status
        status=$(systemctl is-enabled netfilter-persistent 2>/dev/null) || status="unknown"
        info "开机自启状态: ${status}"
        read -rp "是否立即保存当前 iptables 规则？[Y/n]: " ans
        if [[ ! "$ans" =~ ^[Nn]$ ]]; then
            try_persist_iptables
        fi
        return
    fi

    install_iptables_persistent

    # 安装后立即保存当前规则
    if command -v netfilter-persistent &>/dev/null || \
       systemctl list-unit-files 2>/dev/null | grep -q "^iptables.service"; then
        info "正在保存当前 iptables 规则..."
        try_persist_iptables || warn "保存失败，请手动执行: netfilter-persistent save"
    fi
}

# ====================================================
# 功能 2：查看现有端口转发
# ====================================================
do_list() {
    echo ""
    load_rules
    load_dns_rules

    if [[ ${#RULES[@]} -eq 0 && ${#DNS_RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则。"
        return
    fi

    # 普通转发规则
    if [[ ${#RULES[@]} -gt 0 ]]; then
        printf "\n\033[1m%-6s %-20s %-10s %-10s    %-22s\033[0m\n" "序号" "名称" "协议" "本机端口" "目标地址"
        echo "────────────────────────────────────────────────────────────────────"

        local idx=1
        local rule lport dip dport name
        for rule in "${RULES[@]}"; do
            IFS='|' read -r lport dip dport name <<< "$rule"
            printf "%-6s %-20s %-10s %-10s -> %-22s\n" \
                "$idx" "${name:-（未命名）}" "tcp+udp" "$lport" "${dip}:${dport}"
            ((idx++))
        done
        echo ""
    fi

    # DNS 动态转发规则
    if [[ ${#DNS_RULES[@]} -gt 0 ]]; then
        printf "\n\033[1m--- DNS 动态转发（域名自动解析） ---\033[0m\n"
        printf "\033[1m%-6s %-20s %-10s %-10s    %-22s\033[0m\n" "序号" "域名" "协议" "监听端口" "目标端口"
        echo "────────────────────────────────────────────────────────────────────"

        local idx=1
        local rule domain lport dport set_name ip_list
        for rule in "${DNS_RULES[@]}"; do
            IFS='|' read -r domain lport dport set_name <<< "$rule"
            ip_list=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ',' | sed 's/,$//') || ip_list=""
            local target_str
            if [[ -n "$ip_list" ]]; then
                target_str="${ip_list}:${dport}"
            else
                target_str="\033[33m[未解析]:${dport}\033[0m"
            fi
            printf "%-6s %-20s %-10s %-10s -> %-22b\n" \
                "$idx" "${domain}" "tcp+udp" "$lport" "$target_str"
            ((idx++))
        done
        echo ""

        # 同步状态
        if systemctl list-unit-files 2>/dev/null | grep -q "^${DNS_SET_SYNC_TIMER}"; then
            if systemctl is-active --quiet "${DNS_SET_SYNC_TIMER}" 2>/dev/null; then
                info "DNS 定时同步: 已启用（每5分钟）"
            else
                warn "DNS 定时同步: 未运行"
            fi
        fi
    fi
}

# ====================================================
# 功能 3：新增端口转发
# ====================================================
do_add() {
    echo ""
    if ! command -v nft &>/dev/null; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    init_conf || return
    enable_ip_forward
    load_rules

    local local_ip
    local_ip=$(get_local_ip)
    if [[ -z "$local_ip" ]]; then
        err "无法获取本机 IP 地址，请检查网络配置。"
        return
    fi

    local lport
    while true; do
        read -rp "请输入本机监听端口 (1-65535): " lport
        if validate_port "$lport"; then
            break
        fi
        err "端口无效，请输入 1-65535 之间的数字。"
    done

    local rule rp
    for rule in "${RULES[@]}"; do
        IFS='|' read -r rp _ _ _ <<< "$rule"
        if [[ "$rp" == "$lport" ]]; then
            err "本机端口 ${lport} 已存在转发规则，请先删除后再添加。"
            return
        fi
    done

    if ! check_port_conflict "$lport"; then
        info "已取消。"
        return
    fi

    local dip
    while true; do
        read -rp "请输入目标 IP 地址: " dip
        if validate_ip "$dip"; then
            break
        fi
        err "IP 地址格式无效，请重新输入（如 192.168.1.100）。"
    done

    local dport
    while true; do
        read -rp "请输入目标端口 (1-65535) [默认: ${lport}]: " dport
        dport="${dport:-$lport}"
        if validate_port "$dport"; then
            break
        fi
        err "端口无效，请输入 1-65535 之间的数字。"
    done

    local name
    read -rp "为此规则设置一个名称，方便标识（如 gadi-server, wx-bot）[默认: 不命名]: " name
    name=$(sanitize_rule_name "$name")

    echo ""
    echo "即将添加转发规则:"
    echo "  名称: ${name:-（未命名）}"
    echo "  本机端口 ${lport} (tcp+udp) → ${dip}:${dport}"
    read -rp "确认添加？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    backup_conf
    RULES+=("${lport}|${dip}|${dport}|${name}")
    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
        firewall_open_port "$lport" "$dip" "$dport"
        info "转发规则添加成功: [${name:-unnamed}] ${lport} → ${dip}:${dport}"
        log_action "新增转发: [${name:-unnamed}] ${lport} -> ${dip}:${dport}"
        info "若转发不通，请使用菜单中的【诊断/自检】排查。"
    else
        err "规则加载失败，请检查配置。"
    fi
}

# ====================================================
# 功能 4：删除端口转发
# ====================================================
do_delete() {
    echo ""
    if ! command -v nft &>/dev/null; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    load_rules

    if [[ ${#RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则，无需删除。"
        return
    fi

    printf "\n\033[1m%-6s %-20s %-10s %-10s    %-22s\033[0m\n" "序号" "名称" "协议" "本机端口" "目标地址"
    echo "────────────────────────────────────────────────────────────────────"

    local idx=1
    local rule lport dip dport name
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport name <<< "$rule"
        printf "%-6s %-20s %-10s %-10s -> %-22s\n" \
            "$idx" "${name:-（未命名）}" "tcp+udp" "$lport" "${dip}:${dport}"
        ((idx++))
    done
    echo ""

    local choice
    read -rp "请输入要删除的序号 (0 取消): " choice

    if [[ "$choice" == "0" ]] || [[ -z "$choice" ]]; then
        info "已取消。"
        return
    fi

    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#RULES[@]} )); then
        err "无效的序号。"
        return
    fi

    local target="${RULES[$((choice-1))]}"
    IFS='|' read -r lport dip dport name <<< "$target"

    echo "即将删除转发规则:"
    echo "  名称: ${name:-（未命名）}"
    echo "  本机端口 ${lport} (tcp+udp) → ${dip}:${dport}"
    read -rp "确认删除？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    backup_conf
    unset 'RULES[$((choice-1))]'
    RULES=("${RULES[@]}")

    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
        firewall_close_port "$lport" "$dip" "$dport"
        info "转发规则已删除: [${name:-unnamed}] ${lport} → ${dip}:${dport}"
        log_action "删除转发: [${name:-unnamed}] ${lport} -> ${dip}:${dport}"
    else
        err "规则加载失败，请检查配置。"
    fi
}

# ============== DNS 动态转发规则 ==============
# 格式: domain|lport|dport|set_name
# domain: 远程目标域名（自动解析 IP，IP 变化时自动更新 DNAT 规则）
# lport:  本机监听端口
# dport:  远程目标端口
# set_name: nftables set 名称（存储域名当前解析出的 IP，用于展示和去重）
declare -a DNS_RULES=()

load_dns_rules() {
    DNS_RULES=()
    if [[ ! -f "${DNS_USER_CONF}" ]]; then
        return
    fi
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        DNS_RULES+=("$line")
    done < "${DNS_USER_CONF}"
}

write_dns_user_conf() {
    mkdir -p "${CONF_DIR}" 2>/dev/null
    local tmp_file="${DNS_USER_CONF}.tmp.$$"
    : > "${tmp_file}" 2>/dev/null || {
        err "无法创建临时文件 ${tmp_file}"
        return 1
    }
    local rule
    for rule in "${DNS_RULES[@]}"; do
        echo "$rule" >> "${tmp_file}"
    done
    mv -f "${tmp_file}" "${DNS_USER_CONF}" 2>/dev/null || {
        err "无法写入 ${DNS_USER_CONF}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
    return 0
}
# ============== 备份 DNS 配置 ==============
backup_dns_conf() {
    if [[ -f "${DNS_USER_CONF}" ]]; then
        local ts
        ts=$(date '+%Y%m%d_%H%M%S')
        cp "${DNS_USER_CONF}" "${BACKUP_DIR}/dns-forward.rules.${ts}" 2>/dev/null || true
    fi
}

# ============== 写出 DNS 转发 nftables 配置 ==============
# DNAT 规则的目标 IP 由 sync_dns_to_nftset 动态生成并追加到此文件
# 此函数只生成 table/set/chain 骨架结构
write_dns_nft_conf() {
    local local_ip
    local_ip=$(get_local_ip)
    [[ -z "$local_ip" ]] && local_ip="0.0.0.0"

    local tmp_file="${DNS_CONF_FILE}.tmp.$$"

    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f

# DNS 动态转发 - nftables 配置（骨架 + 动态规则）
# 自动生成，请勿手动修改
# 本机 IP: ${local_ip}
# 注意: DNAT 规则由同步脚本根据域名解析动态生成，修改此文件会被覆盖

table ip port_forward_dns {
EOF

    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        cat >> "${tmp_file}" <<'EOF'
}
EOF
        mv -f "${tmp_file}" "${DNS_CONF_FILE}" 2>/dev/null || {
            err "无法写入 ${DNS_CONF_FILE}"
            rm -f "${tmp_file}" 2>/dev/null || true
            return 1
        }
        return 0
    fi

    # 生成 set 定义（存储域名解析出的 IP）
    local rule domain lport dport set_name
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"
        cat >> "${tmp_file}" <<EOF
    set ${set_name} {
        type ipv4_addr
        size 65536
        flags interval
    }
EOF
    done

    cat >> "${tmp_file}" <<'EOF'

    # --- PREROUTING (DNAT) ---
    chain dns_prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    # DNAT 规则由 generate_dns_dnat_rules 生成并追加
    # 格式: tcp dport <lport> dnat to <resolved_ip>:<dport>

    cat >> "${tmp_file}" <<'EOF'

    }

    # --- POSTROUTING (SNAT 回源) ---
    chain dns_postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF

    # SNAT 规则也由 generate_dns_dnat_rules 动态追加

    cat >> "${tmp_file}" <<'EOF'

    }
}
EOF

    mv -f "${tmp_file}" "${DNS_CONF_FILE}" 2>/dev/null || {
        err "无法写入 ${DNS_CONF_FILE}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
    return 0
}

# ============== 根据 set 中的 IP 动态生成 DNAT/SNAT 规则并重新加载 ==============
generate_dns_dnat_rules() {
    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        return 0
    fi

    local local_ip
    local_ip=$(get_local_ip)
    [[ -z "$local_ip" ]] && local_ip="0.0.0.0"

    local tmp_file="${DNS_CONF_FILE}.tmp.$$"

    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f
# DNS 动态转发 - 完整配置（含动态 DNAT 规则）
# 自动生成，请勿手动修改
# 本机 IP: ${local_ip}

table ip port_forward_dns {
EOF

    # set 定义
    local rule domain lport dport set_name
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"
        cat >> "${tmp_file}" <<EOF
    set ${set_name} {
        type ipv4_addr
        size 65536
        flags interval
    }
EOF
    done

    cat >> "${tmp_file}" <<'EOF'

    chain dns_prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    # 为每条规则，从 set 中读取 IP 生成 DNAT
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"

        # 读取 set 中当前所有 IP
        local resolved_ips
        resolved_ips=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u) || true

        if [[ -n "$resolved_ips" ]]; then
            while IFS= read -r rip; do
                [[ -z "$rip" ]] && continue
                cat >> "${tmp_file}" <<EOF
        # ${domain}:${lport} -> ${rip}:${dport}
        tcp dport ${lport} dnat to ${rip}:${dport}
        udp dport ${lport} dnat to ${rip}:${dport}
EOF
            done <<< "$resolved_ips"
        else
            # set 中没有 IP，写一条注释占位
            cat >> "${tmp_file}" <<EOF
        # ${domain}:${lport} -> [待解析:${dport}]
EOF
        fi
    done

    cat >> "${tmp_file}" <<'EOF'

    }

    chain dns_postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF

    # SNAT 回源规则
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"

        local resolved_ips
        resolved_ips=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u) || true

        if [[ -n "$resolved_ips" ]]; then
            while IFS= read -r rip; do
                [[ -z "$rip" ]] && continue
                cat >> "${tmp_file}" <<EOF
        # 回源: ${domain} -> ${rip}:${dport}
        ip daddr ${rip} tcp dport ${dport} ct status dnat snat to ${local_ip}
        ip daddr ${rip} udp dport ${dport} ct status dnat snat to ${local_ip}
EOF
            done <<< "$resolved_ips"
        fi
    done

    cat >> "${tmp_file}" <<'EOF'

    }
}
EOF

    mv -f "${tmp_file}" "${DNS_CONF_FILE}" 2>/dev/null || {
        err "无法写入 ${DNS_CONF_FILE}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
    return 0
}

# ============== 写出 dnsmasq 配置 ==============
write_dnsmasq_conf() {
    mkdir -p "${DNSMASQ_CONF_DIR}" 2>/dev/null || {
        err "无法创建目录 ${DNSMASQ_CONF_DIR}"
        return 1
    }

    local tmp_file="${DNSMASQ_CONF}.tmp.$$"
    {
        echo "# DNS 动态转发 - dnsmasq 配置"
        echo "# 自动生成，请勿手动修改"
        echo "# 使用 nftset= 指令自动将域名解析 IP 写入 nftables set"
        echo ""

        local rule domain set_name
        for rule in "${DNS_RULES[@]}"; do
            IFS='|' read -r domain _ _ set_name <<< "$rule"
            # nftset= 语法: nftset=/<domain>/[4|6]#<table>#<set>
            # 在 dnsmasq 2.87+ 支持；旧版用定时同步脚本替代
            echo "# nftset=/${domain}/4#ip#port_forward_dns#${set_name}"
            echo "# 注: 若 dnsmasq 不支持 nftset 指令，请使用菜单[4]手动同步或等待定时器"
        done
    } > "${tmp_file}"

    mv -f "${tmp_file}" "${DNSMASQ_CONF}" 2>/dev/null || {
        err "无法写入 ${DNSMASQ_CONF}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
    return 0
}

# ============== 安装并启动 dnsmasq ==============
install_dnsmasq() {
    if command -v dnsmasq &>/dev/null; then
        info "dnsmasq 已安装。"
    else
        local pkg_mgr
        pkg_mgr=$(detect_pkg_manager)
        case "$pkg_mgr" in
            apt)
                DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq 2>/dev/null
                ;;
            dnf)
                dnf install -y dnsmasq 2>/dev/null
                ;;
            yum)
                yum install -y dnsmasq 2>/dev/null
                ;;
            pacman)
                pacman -Sy --noconfirm dnsmasq 2>/dev/null
                ;;
            *)
                err "无法识别包管理器，请手动安装 dnsmasq。"
                return 1
                ;;
        esac
        if ! command -v dnsmasq &>/dev/null; then
            err "dnsmasq 安装失败。"
            return 1
        fi
        info "dnsmasq 安装成功。"
    fi

    # 确保 conf-dir 包含我们的配置目录
    if [[ -f /etc/dnsmasq.conf ]] && ! grep -q "^conf-dir=/etc/dnsmasq.d" /etc/dnsmasq.conf 2>/dev/null; then
        echo 'conf-dir=/etc/dnsmasq.d/,*.conf' >> /etc/dnsmasq.conf
        info "已在 /etc/dnsmasq.conf 添加 conf-dir 指令。"
    fi

    if systemctl restart dnsmasq 2>/dev/null; then
        info "dnsmasq 服务已启动。"
    else
        warn "dnsmasq 启动失败，运行配置测试:"
        dnsmasq --test 2>&1 | head -5
        return 1
    fi
    systemctl enable dnsmasq 2>/dev/null || true
    info "dnsmasq 已设为开机自启。"
    log_action "安装并启动 dnsmasq"
    return 0
}

# ============== DNS 转发防火墙放行 ==============
firewall_open_dns_port() {
    local lport="$1"
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --add-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --add-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "firewalld 放行端口 ${lport}。"
        log_action "firewalld 放行 DNS转发端口 ${lport}"
        return
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        ufw allow "${lport}/tcp" >/dev/null 2>&1 || true
        ufw allow "${lport}/udp" >/dev/null 2>&1 || true
        info "UFW 放行端口 ${lport}。"
        log_action "UFW 放行 DNS转发端口 ${lport}"
        return
    fi
    if has_iptables; then
        iptables -C INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        info "iptables 放行端口 ${lport} (tcp+udp)。"
        log_action "iptables 放行 DNS转发端口 ${lport}"
        ensure_iptables_persistent
    fi
}

# ============== 同步 DNS 到 nftables set 并重新生成 DNAT 规则 ==============
sync_dns_to_nftset() {
    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        info "没有 DNS 转发规则，无需同步。"
        return 0
    fi

    echo ""
    info "开始 DNS 解析并同步到 nftables set..."

    local rule domain lport dport set_name
    local resolved_ips old_ips
    local changed=false

    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"

        # 确保 set 存在（先尝试加载，再检查）
        if ! nft list set ip port_forward_dns "${set_name}" &>/dev/null 2>&1; then
            # set 不存在，先确保配置文件存在且加载
            if [[ ! -f "${DNS_CONF_FILE}" ]]; then
                warn "DNS 配置文件不存在，正在生成..."
                write_dns_nft_conf || { warn "生成 DNS 配置失败，跳过 ${domain}"; continue; }
            fi
            local nft_err
            nft_err=$(nft -f "${DNS_CONF_FILE}" 2>&1)
            if [[ $? -ne 0 ]]; then
                warn "加载 DNS 配置失败: ${DNS_CONF_FILE}"
                warn "错误详情: ${nft_err}"
                warn "尝试跳过...（可手动运行: nft -f ${DNS_CONF_FILE}）"
                continue
            fi
        fi

        # 解析域名
        resolved_ips=$(getent hosts "${domain}" 2>/dev/null | awk '{print $1}' | sort -u) || true

        if [[ -z "$resolved_ips" ]]; then
            warn "无法解析域名: ${domain}"
            continue
        fi

        # 获取当前 set 中的旧 IP
        old_ips=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u) || old_ips=""

        # 差量计算
        local new_ips removed_ips
        new_ips=$(comm -13 <(echo "$old_ips") <(echo "$resolved_ips") 2>/dev/null) || new_ips=""
        removed_ips=$(comm -23 <(echo "$old_ips") <(echo "$resolved_ips") 2>/dev/null) || removed_ips=""

        # 移除已不在 DNS 记录中的 IP
        if [[ -n "$removed_ips" ]]; then
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
                nft delete element ip port_forward_dns "${set_name}" "{ ${ip} }" 2>/dev/null || true
            done <<< "$removed_ips"
            printf "  \033[33m[-]\033[0m ${domain}: 移除 %s\n" "$(echo "$removed_ips" | tr '\n' ' ')"
            changed=true
        fi

        # 添加新解析出的 IP
        if [[ -n "$new_ips" ]]; then
            local ip_list
            ip_list=$(echo "$new_ips" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ',' | sed 's/,$//')
            if [[ -n "$ip_list" ]]; then
                nft add element ip port_forward_dns "${set_name}" "{ ${ip_list} }" 2>/dev/null
                printf "  \033[32m[+]\033[0m ${domain}: 添加 %s\n" "$ip_list"
                changed=true
            fi
        fi

        printf "  \033[36m[*]\033[0m ${domain}:${lport} -> [解析IP]:${dport}  IPs: %s\n" "$(echo "$resolved_ips" | tr '\n' ' ' | sed 's/ $//')"
        log_action "DNS sync: ${domain}:${lport} -> :${dport} [$(echo "$resolved_ips" | tr '\n' ',')]"
    done

    if $changed; then
        # IP 有变化，重新生成 DNAT 规则并加载
        info "IP 发生变化，正在重新生成 DNAT 规则..."
        if generate_dns_dnat_rules; then
            nft -f "${DNS_CONF_FILE}" 2>/dev/null && {
                info "DNAT 规则已更新。"
            } || {
                warn "重新加载 DNAT 规则失败，可手动运行: nft -f ${DNS_CONF_FILE}"
            }
        fi
    else
        info "DNS 解析无变化（所有 IP 均已存在）。"
    fi
}

# ============== 重载 DNS nftables 配置 ==============
reload_dns_rules() {
    nft flush table ip port_forward_dns 2>/dev/null || true
    nft delete table ip port_forward_dns 2>/dev/null || true
    if [[ -f "${DNS_CONF_FILE}" ]] && ! nft -f "${DNS_CONF_FILE}"; then
        err "加载 DNS nftables 配置失败。"
        return 1
    fi
    return 0
}

# ============== 安装 DNS 定时同步服务 ==============
install_dns_sync_timer() {
    cat > "${DNS_SET_SYNC_SCRIPT}" <<'SYNC_SCRIPT'
#!/usr/bin/env bash
# DNS -> nftables set 同步 + DNAT 规则动态生成（自动生成）
# 用法: dns-nft-sync.sh

CONF_USER="/etc/nftables.d/dns-forward.rules"
CONF_NFT="/etc/nftables.d/dns-forward.conf"
LOG="/var/log/nft-dns-sync.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG" 2>/dev/null || true; }

[[ ! -f "$CONF_USER" ]] && exit 0

local_ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1) || local_ip="127.0.0.1"

# 第一遍：更新 set 中的 IP
changed=0
while IFS='|' read -r domain lport dport set_name; do
    [[ "$domain" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$domain" ]] && continue

    resolved=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u) || continue
    [[ -z "$resolved" ]] && { log "failed to resolve: $domain"; continue; }

    # 确保 set 存在
    nft list set ip port_forward_dns "${set_name}" &>/dev/null 2>&1 || {
        nft -f "${CONF_NFT}" 2>/dev/null
    }

    old=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u) || old=""

    # 差量更新 set
    for ip in $resolved; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        if ! echo "$old" | grep -qF "$ip"; then
            nft add element ip port_forward_dns "${set_name}" "{ ${ip} }" 2>/dev/null || true
            changed=1
            log "added $ip to $set_name ($domain)"
        fi
    done

    # 移除不再解析到的旧 IP
    if [[ -n "$old" ]]; then
        while IFS= read -r old_ip; do
            [[ -z "$old_ip" ]] && continue
            if ! echo "$resolved" | grep -qF "$old_ip"; then
                nft delete element ip port_forward_dns "${set_name}" "{ ${old_ip} }" 2>/dev/null || true
                changed=1
                log "removed $old_ip from $set_name ($domain)"
            fi
        done <<< "$old"
    fi
done < "$CONF_USER"

# 第二遍：如果有 IP 变化，重新生成 DNAT 规则并重载
if [[ "$changed" -eq 1 ]]; then
    tmp="${CONF_NFT}.tmp.$$"
    {
        echo "#!/usr/sbin/nft -f"
        echo "# DNS 动态转发 - 自动生成 $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# 本机 IP: ${local_ip}"
        echo ""
        echo "table ip port_forward_dns {"

        # set 定义
        while IFS='|' read -r domain lport dport set_name; do
            [[ "$domain" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$domain" ]] && continue
            echo "    set ${set_name} { type ipv4_addr; size 65536; flags interval; }"
        done < "$CONF_USER"

        echo ""
        echo "    chain dns_prerouting { type nat hook prerouting priority -100; policy accept;"

        # DNAT 规则
        while IFS='|' read -r domain lport dport set_name; do
            [[ "$domain" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$domain" ]] && continue
            ips=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u) || continue
            for rip in $ips; do
                echo "        tcp dport ${lport} dnat to ${rip}:${dport}"
                echo "        udp dport ${lport} dnat to ${rip}:${dport}"
            done
        done < "$CONF_USER"

        echo ""
        echo "    chain dns_postrouting { type nat hook postrouting priority 100; policy accept;"

        # SNAT 规则
        while IFS='|' read -r domain lport dport set_name; do
            [[ "$domain" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$domain" ]] && continue
            ips=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u) || continue
            for rip in $ips; do
                echo "        ip daddr ${rip} tcp dport ${dport} ct status dnat snat to ${local_ip}"
                echo "        ip daddr ${rip} udp dport ${dport} ct status dnat snat to ${local_ip}"
            done
        done < "$CONF_USER"

        echo ""
        echo "    }"
        echo "}"
    } > "$tmp"

    mv -f "$tmp" "${CONF_NFT}" 2>/dev/null && {
        nft -f "${CONF_NFT}" 2>/dev/null
        log "DNAT rules regenerated and reloaded"
    }
fi
SYNC_SCRIPT

    chmod +x "${DNS_SET_SYNC_SCRIPT}"

    cat > "/etc/systemd/system/${DNS_SET_SYNC_SERVICE}" <<EOF
[Unit]
Description=DNS -> nftables set sync
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${DNS_SET_SYNC_SCRIPT}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > "/etc/systemd/system/${DNS_SET_SYNC_TIMER}" <<EOF
[Unit]
Description=DNS -> nftables set sync timer (every 5 min)

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${DNS_SET_SYNC_TIMER}" 2>/dev/null || true
    info "DNS 定时同步已安装（每5分钟自动刷新）。"
    echo "  查看状态: systemctl status ${DNS_SET_SYNC_TIMER}"
    echo "  手动触发: systemctl start ${DNS_SET_SYNC_SERVICE}"
    echo "  查看日志: journalctl -u ${DNS_SET_SYNC_SERVICE} -n 20"
    log_action "安装 DNS 定时同步服务"
}

# ============== DNS 转发：新增 ==============
do_add_dns_forward() {
    echo ""
    if ! command -v nft &>/dev/null; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" 2>/dev/null || true
    load_dns_rules

    local domain
    while true; do
        read -rp "请输入目标域名（如 example.com，将自动解析 IP）: " domain
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        if [[ -n "$domain" && "$domain" =~ ^[a-z0-9][a-z0-9.-]*$ ]]; then
            break
        fi
        err "域名格式无效，请重新输入。"
    done

    # 先试解析域名，验证可达性
    local test_ips
    test_ips=$(getent hosts "${domain}" 2>/dev/null | awk '{print $1}' | sort -u) || true
    if [[ -n "$test_ips" ]]; then
        info "域名解析成功: $(echo "$test_ips" | tr '\n' ' ')"
    else
        warn "域名 ${domain} 当前无法解析，规则仍会添加，定时同步将自动重试。"
    fi

    # 检查域名是否已配置
    local rule d
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r d _ _ _ <<< "$rule"
        if [[ "$d" == "$domain" ]]; then
            err "域名 ${domain} 已存在 DNS 转发规则，请先删除后再添加。"
            return
        fi
    done

    local lport
    while true; do
        read -rp "本机监听端口（1-65535）: " lport
        if validate_port "$lport"; then
            break
        fi
        err "端口无效，请输入 1-65535。"
    done

    if ! check_port_conflict "$lport"; then
        info "已取消。"
        return
    fi

    # 目标远程端口（默认与监听端口相同）
    local dport
    while true; do
        read -rp "目标远程端口（1-65535，默认 ${lport}）: " dport
        dport="${dport:-$lport}"
        if validate_port "$dport"; then
            break
        fi
        err "端口无效，请输入 1-65535。"
    done

    # 自动生成 set_name
    local set_name
    set_name=$(echo "${domain}" | tr '.' '_' | tr '-' '_')
    set_name="${set_name}_${lport}"
    set_name="${set_name:0:31}"
    read -rp "nft set 名称 [默认: ${set_name}]: " input_set_name
    input_set_name=$(sanitize_rule_name "$input_set_name")
    set_name="${input_set_name:-$set_name}"
    if [[ ! "$set_name" =~ ^[a-zA-Z][a-zA-Z0-9_]*$ ]]; then
        err "set 名称只能包含字母、数字、下划线，且必须以字母开头。"
        return
    fi

    echo ""
    echo "即将添加 DNS 动态转发规则:"
    echo "  域名: ${domain}"
    echo "  本机监听端口: ${lport}"
    echo "  目标端口: ${dport}"
    echo "  nft set: ${set_name}"
    echo "  机制: 定时解析 ${domain} → IP 写入 set → 动态生成 DNAT 规则"
    read -rp "确认添加？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    backup_dns_conf
    DNS_RULES+=("${domain}|${lport}|${dport}|${set_name}")

    if ! write_dns_user_conf; then
        return
    fi

    write_dnsmasq_conf || true
    install_dnsmasq || true
    firewall_open_dns_port "$lport"
    write_dns_nft_conf || true
    reload_dns_rules || true
    sync_dns_to_nftset

    if [[ ! -f "/etc/systemd/system/${DNS_SET_SYNC_TIMER}" ]]; then
        read -rp "是否安装定时同步服务（每5分钟自动刷新 IP）？[Y/n]: " ans_timer
        if [[ ! "$ans_timer" =~ ^[Nn]$ ]]; then
            install_dns_sync_timer
        fi
    fi

    info "DNS 动态转发规则添加完成: ${domain}:${lport} -> [自动解析]:${dport}"
    log_action "新增DNS转发: ${domain}:${lport} -> :${dport} (set=${set_name})"
}

# ============== DNS 转发：列表 ==============
do_list_dns_forward() {
    echo ""
    load_dns_rules

    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        info "当前没有 DNS 动态转发规则，使用菜单 [8] → [1] 添加。"
        return
    fi

    printf "\n\033[1m%-6s %-28s %-8s %-8s %s\033[0m\n" "序号" "域名" "监听端口" "目标端口" "当前解析 IP"
    echo "──────────────────────────────────────────────────────────────────────────"

    local idx=1 rule domain lport dport set_name
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"
        local ip_list
        ip_list=$(nft list set ip port_forward_dns "${set_name}" 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ',' | sed 's/,$//') || ip_list=""
        local ip_count
        ip_count=$(echo "$ip_list" | tr ',' '\n' | grep -c '.' 2>/dev/null) || ip_count=0
        printf "%-6s %-28s %-8s %-8s" "$idx" "${domain}" "${lport}" "${dport}"
        if [[ -n "$ip_list" ]]; then
            printf " \033[32m[%s个]\033[0m %s" "$ip_count" "$ip_list"
        else
            printf " \033[33m[未解析]\033[0m"
        fi
        echo ""
        ((idx++))
    done
    echo ""

    if systemctl list-unit-files 2>/dev/null | grep -q "^${DNS_SET_SYNC_TIMER}"; then
        if systemctl is-active --quiet "${DNS_SET_SYNC_TIMER}" 2>/dev/null; then
            info "定时同步: 已启用（每5分钟）"
        else
            warn "定时同步: 未运行"
        fi
    fi
}

# ============== DNS 转发：删除 ==============
do_delete_dns_forward() {
    echo ""
    load_dns_rules

    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        info "当前没有 DNS 动态转发规则。"
        return
    fi

    printf "\n\033[1m%-6s %-28s %-8s %-8s %-25s\033[0m\n" "序号" "域名" "监听端口" "目标端口" "nft set"
    echo "─────────────────────────────────────────────────────────────────────"

    local idx=1 rule domain lport dport set_name
    for rule in "${DNS_RULES[@]}"; do
        IFS='|' read -r domain lport dport set_name <<< "$rule"
        printf "%-6s %-28s %-8s %-8s %-25s\n" "$idx" "${domain}" "${lport}" "${dport}" "${set_name}"
        ((idx++))
    done
    echo ""

    local choice
    read -rp "请输入要删除的序号 (0 取消): " choice

    if [[ "$choice" == "0" ]] || [[ -z "$choice" ]]; then
        info "已取消。"
        return
    fi

    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#DNS_RULES[@]} )); then
        err "无效的序号。"
        return
    fi

    local target="${DNS_RULES[$((choice-1))]}"
    IFS='|' read -r domain lport dport set_name <<< "$target"

    echo "即将删除 DNS 动态转发规则:"
    echo "  域名: ${domain}"
    echo "  监听端口: ${lport}"
    echo "  目标端口: ${dport}"
    echo "  nft set: ${set_name}"
    read -rp "确认删除？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    backup_dns_conf
    unset 'DNS_RULES[$((choice-1))]'
    DNS_RULES=("${DNS_RULES[@]}")

    write_dns_user_conf || { err "写入配置文件失败"; return 1; }
    nft delete set ip port_forward_dns "${set_name}" 2>/dev/null || true
    write_dnsmasq_conf || true
    systemctl restart dnsmasq 2>/dev/null || true
    write_dns_nft_conf || true
    reload_dns_rules || true

    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        systemctl stop "${DNS_SET_SYNC_TIMER}" 2>/dev/null || true
        systemctl disable "${DNS_SET_SYNC_TIMER}" 2>/dev/null || true
        info "已停止 DNS 定时同步服务（无剩余规则）。"
    fi

    info "DNS 动态转发规则已删除: ${domain} (${dport})"
    log_action "删除DNS转发: ${domain}:${lport} -> :${dport}"
}

# ============== DNS 转发：手动同步 ==============
do_sync_dns_now() {
    echo ""
    load_dns_rules
    if [[ ${#DNS_RULES[@]} -eq 0 ]]; then
        info "没有 DNS 转发规则。"
        return
    fi
    sync_dns_to_nftset
}

# ============== DNS 转发子菜单 ==============
do_dns_forward_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "     DNS 动态转发管理"
        echo "     (dnsmasq + nft set)"
        echo "========================================"
        echo "  1) 新增 DNS 动态转发"
        echo "  2) 查看 DNS 转发列表"
        echo "  3) 删除 DNS 转发规则"
        echo "  4) 手动同步 DNS → nft set"
        echo "  5) 安装/重启 dnsmasq"
        echo "  6) 返回主菜单"
        echo "========================================"
        read -rp "请选择操作 [1-6]: " dns_choice

        case "$dns_choice" in
            1) do_add_dns_forward ;;
            2) do_list_dns_forward ;;
            3) do_delete_dns_forward ;;
            4) do_sync_dns_now ;;
            5) install_dnsmasq ;;
            6) break ;;
            *) err "无效选择，请输入 1-6。" ;;
        esac
    done
}

# ============== Web 面板管理 ==============
install_panel() {
    local panel_port panel_user panel_pass panel_host panel_cert panel_key existing_panel
    existing_panel=0
    [[ -f "${PANEL_SERVICE_FILE}" ]] && existing_panel=1

    if (( existing_panel )); then
        panel_port=$(get_panel_env "PANEL_PORT")
        panel_user=$(get_panel_env "PANEL_USER")
        panel_pass=$(get_panel_env "PANEL_PASS")
        panel_host=$(get_panel_env "PANEL_HOST")
        panel_cert=$(get_panel_env "PANEL_CERT")
        panel_key=$(get_panel_env "PANEL_KEY")

        panel_port="${panel_port:-$PANEL_PORT_DEFAULT}"
        panel_user="${panel_user:-$PANEL_USER_DEFAULT}"
        panel_pass="${panel_pass:-$PANEL_PASS_DEFAULT}"
        panel_host="${panel_host:-0.0.0.0}"
        panel_cert="${panel_cert:-}"
        panel_key="${panel_key:-}"
        if [[ -z "$panel_cert" && -z "$panel_key" && -f "$PANEL_CERT_DEFAULT" && -f "$PANEL_KEY_DEFAULT" ]]; then
            panel_cert="$PANEL_CERT_DEFAULT"
            panel_key="$PANEL_KEY_DEFAULT"
            info "检测到默认路径证书，已自动恢复 HTTPS 配置。"
        fi
        info "检测到已安装 Web 面板，本次仅更新面板程序并保留现有配置。"
        echo "端口: ${panel_port}"
        echo "用户名: ${panel_user}"
        echo "监听 IP: ${panel_host}"
        [[ -n "$panel_cert" && -n "$panel_key" ]] && echo "HTTPS: 已启用"
    else
        read -rp "面板端口 [默认: ${PANEL_PORT_DEFAULT}]: " panel_port
        panel_port="${panel_port:-$PANEL_PORT_DEFAULT}"
        if ! validate_port "$panel_port"; then
            err "端口无效。"
            return 1
        fi

        read -rp "面板用户名 [默认: ${PANEL_USER_DEFAULT}]: " panel_user
        panel_user="${panel_user:-$PANEL_USER_DEFAULT}"
        panel_user=$(sanitize_rule_name "$panel_user")
        if [[ -z "$panel_user" ]]; then
            err "用户名不能为空。"
            return 1
        fi

        read -rsp "面板密码 [默认: ${PANEL_PASS_DEFAULT}]: " panel_pass
        echo ""
        panel_pass="${panel_pass:-$PANEL_PASS_DEFAULT}"
        if [[ -z "$panel_pass" ]]; then
            err "密码不能为空。"
            return 1
        fi
        if [[ "$panel_pass" == *\"* || "$panel_pass" == *\\* || "$panel_pass" == *$'\n'* || "$panel_pass" == *$'\r'* ]]; then
            err "密码不能包含双引号、反斜杠或换行。"
            return 1
        fi
        panel_host="0.0.0.0"
        panel_cert=""
        panel_key=""
    fi

    if ! command -v python3 &>/dev/null; then
        err "未检测到 python3，请先安装 python3。"
        return 1
    fi

    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" 2>/dev/null || true

    cat > "${PANEL_BIN}" <<'PY'
#!/usr/bin/env python3
import base64
import html
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

CONF_DIR = "/etc/nftables.d"
CONF_FILE = "/etc/nftables.d/port-forward.conf"
DNS_USER_CONF = "/etc/nftables.d/dns-forward.rules"
DNS_CONF_FILE = "/etc/nftables.d/dns-forward.conf"
MAIN_CONF = "/etc/nftables.conf"
BACKUP_DIR = "/etc/nftables.d/backups"
TABLE_NAME = "port_forward"
DNS_TABLE = "port_forward_dns"
LOG_FILE = "/var/log/nft-forward.log"

PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASS = os.environ.get("PANEL_PASS", "admin123")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "4788"))
PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_CERT = os.environ.get("PANEL_CERT", "")
PANEL_KEY = os.environ.get("PANEL_KEY", "")
PANEL_BG_PC = os.environ.get("PANEL_BG_PC", "https://img.inim.im/file/1769439286929_61891168f564c650f6fb03d1962e5f37.jpeg")
PANEL_BG_MOBILE = os.environ.get("PANEL_BG_MOBILE", "https://img.inim.im/file/1764296937373_bg_m_2.png")

SESSION_TTL = 7 * 24 * 3600
SESSIONS = {}
LOGIN_FAILS = {}

def sh(cmd, check=False):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg + "\n")
    except OSError:
        pass

def valid_port(value):
    try:
        port = int(str(value))
    except ValueError:
        return False
    return 1 <= port <= 65535 and str(value) == str(port)

def valid_ip(value):
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value or ""):
        return False
    return all(0 <= int(part) <= 255 and (part == "0" or not part.startswith("0")) for part in value.split("."))

def valid_domain(value):
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", (value or "").lower()))

def valid_forward_domain(value):
    value = (value or "").strip().lower()
    return "." in value and any(ch.isalpha() for ch in value) and valid_domain(value)

def split_host_port(value):
    value = str(value or "").strip().lower()
    if value.startswith("["):
        raise ValueError("暂不支持 IPv6 目标地址")
    if ":" not in value:
        raise ValueError("目标地址格式应为 host:port")
    host, port = value.rsplit(":", 1)
    host = host.strip()
    port = port.strip()
    if not host or not valid_port(port):
        raise ValueError("目标地址格式应为 host:port")
    return host, port

def valid_test_host(value):
    value = (value or "").strip().lower()
    return valid_ip(value) or valid_domain(value)

def safe_name(value, limit=60):
    value = (value or "").replace("\r", " ").replace("\n", " ").replace("|", "-")
    value = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
    return value[:limit]

def safe_set_name(value):
    value = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    if not re.match(r"^[A-Za-z]", value):
        value = "set_" + value
    return value[:31] or "set_default"

def unique_set_name(base, rules, skip_index=None):
    base = safe_set_name(base)
    used = {r.get("set_name") for i, r in enumerate(rules) if i != skip_index}
    if base not in used:
        return base
    for i in range(2, 1000):
        suffix = "_%d" % i
        candidate = (base[:31 - len(suffix)] + suffix) if len(base) + len(suffix) > 31 else base + suffix
        if candidate not in used:
            return candidate
    raise ValueError("nft set 名称冲突过多")

def get_local_ip():
    for cmd in (["ip", "route", "get", "1.1.1.1"], ["hostname", "-I"]):
        try:
            out = sh(cmd).stdout
        except OSError:
            continue
        m = re.search(r"src\s+([0-9.]+)", out)
        if m:
            return m.group(1)
        m = re.search(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", out)
        if m:
            return m.group(1)
    return "127.0.0.1"

def ensure_dirs():
    os.makedirs(CONF_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

def ensure_persistence():
    ensure_dirs()
    include_line = 'include "/etc/nftables.d/*.conf"'
    try:
        if not os.path.exists(MAIN_CONF):
            with open(MAIN_CONF, "w", encoding="utf-8") as f:
                f.write("#!/usr/sbin/nft -f\n%s\n" % include_line)
        else:
            with open(MAIN_CONF, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if include_line not in content:
                with open(MAIN_CONF, "a", encoding="utf-8") as f:
                    f.write("\n%s\n" % include_line)
        sh(["systemctl", "enable", "nftables"])
    except OSError:
        pass

def backup(path):
    if os.path.exists(path):
        ts = time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(path, os.path.join(BACKUP_DIR, os.path.basename(path) + "." + ts))

def load_rules():
    rules = []
    if not os.path.exists(CONF_FILE):
        return rules
    prev = ""
    with open(CONF_FILE, encoding="utf-8", errors="ignore") as f:
        for line in f:
            cm = re.match(r"\s*#\s*(.+)", line)
            if cm:
                prev = cm.group(1).strip()
                continue
            m = re.search(r"tcp\s+dport\s+(\d+)\s+dnat\s+to\s+([0-9.]+):(\d+)", line)
            if m:
                rules.append({"name": prev, "lport": m.group(1), "dip": m.group(2), "dport": m.group(3)})
                prev = ""
            elif line.strip():
                prev = ""
    return rules

def write_rules(rules):
    ensure_persistence()
    local_ip = get_local_ip()
    tmp = CONF_FILE + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("#!/usr/sbin/nft -f\n\n")
        f.write("# --- 本机 IP（自动获取，用于 SNAT 回源）\n")
        f.write("define LOCAL_IP = %s\n\n" % local_ip)
        f.write("table ip %s {\n" % TABLE_NAME)
        f.write("    chain prerouting {\n        type nat hook prerouting priority -100; policy accept;\n")
        for r in rules:
            name = safe_name(r.get("name")) or "转发: 本机:%s -> %s:%s" % (r["lport"], r["dip"], r["dport"])
            f.write("\n        # %s\n" % name)
            f.write("        tcp dport %s dnat to %s:%s\n" % (r["lport"], r["dip"], r["dport"]))
            f.write("        udp dport %s dnat to %s:%s\n" % (r["lport"], r["dip"], r["dport"]))
        f.write("    }\n\n")
        f.write("    chain postrouting {\n        type nat hook postrouting priority 100; policy accept;\n")
        for r in rules:
            f.write("\n        # 回源: 发往 %s:%s 的已 DNAT 流量, SNAT 为本机 IP\n" % (r["dip"], r["dport"]))
            f.write("        ip daddr %s tcp dport %s ct status dnat snat to $LOCAL_IP\n" % (r["dip"], r["dport"]))
            f.write("        ip daddr %s udp dport %s ct status dnat snat to $LOCAL_IP\n" % (r["dip"], r["dport"]))
        f.write("    }\n}\n")
    os.replace(tmp, CONF_FILE)

def load_dns_rules():
    rules = []
    if not os.path.exists(DNS_USER_CONF):
        return rules
    with open(DNS_USER_CONF, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                rules.append({"domain": parts[0], "lport": parts[1], "dport": parts[2], "set_name": parts[3]})
    return rules

def write_dns_user_rules(rules):
    ensure_persistence()
    tmp = DNS_USER_CONF + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rules:
            f.write("%s|%s|%s|%s\n" % (r["domain"], r["lport"], r["dport"], r["set_name"]))
    os.replace(tmp, DNS_USER_CONF)

def resolve_domain(domain):
    try:
        out = sh(["getent", "hosts", domain]).stdout
    except OSError:
        return []
    ips = []
    for token in out.split():
        if valid_ip(token) and token not in ips:
            ips.append(token)
    return ips

def write_dns_nft(rules):
    ensure_persistence()
    if not rules:
        try:
            os.remove(DNS_CONF_FILE)
        except FileNotFoundError:
            pass
        return
    local_ip = get_local_ip()
    tmp = DNS_CONF_FILE + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("#!/usr/sbin/nft -f\n")
        f.write("# DNS 动态转发 - 面板生成\n")
        f.write("table ip %s {\n" % DNS_TABLE)
        for r in rules:
            f.write("    set %s { type ipv4_addr; size 65536; flags interval; }\n" % r["set_name"])
        f.write("\n    chain dns_prerouting { type nat hook prerouting priority -100; policy accept;\n")
        for r in rules:
            for ip in resolve_domain(r["domain"]):
                f.write("        # %s:%s -> %s:%s\n" % (r["domain"], r["lport"], ip, r["dport"]))
                f.write("        tcp dport %s dnat to %s:%s\n" % (r["lport"], ip, r["dport"]))
                f.write("        udp dport %s dnat to %s:%s\n" % (r["lport"], ip, r["dport"]))
        f.write("    }\n\n")
        f.write("    chain dns_postrouting { type nat hook postrouting priority 100; policy accept;\n")
        for r in rules:
            for ip in resolve_domain(r["domain"]):
                f.write("        ip daddr %s tcp dport %s ct status dnat snat to %s\n" % (ip, r["dport"], local_ip))
                f.write("        ip daddr %s udp dport %s ct status dnat snat to %s\n" % (ip, r["dport"], local_ip))
        f.write("    }\n}\n")
    os.replace(tmp, DNS_CONF_FILE)

def reload_nft():
    results = []
    if os.path.exists(CONF_FILE):
        sh(["nft", "flush", "table", "ip", TABLE_NAME])
        sh(["nft", "delete", "table", "ip", TABLE_NAME])
        r = sh(["nft", "-f", CONF_FILE])
        results.append(("port", r.returncode, r.stderr))
    else:
        sh(["nft", "flush", "table", "ip", TABLE_NAME])
        sh(["nft", "delete", "table", "ip", TABLE_NAME])
    if os.path.exists(DNS_CONF_FILE):
        sh(["nft", "flush", "table", "ip", DNS_TABLE])
        sh(["nft", "delete", "table", "ip", DNS_TABLE])
        r = sh(["nft", "-f", DNS_CONF_FILE])
        results.append(("dns", r.returncode, r.stderr))
    else:
        sh(["nft", "flush", "table", "ip", DNS_TABLE])
        sh(["nft", "delete", "table", "ip", DNS_TABLE])
    bad = [x for x in results if x[1] != 0]
    if bad:
        raise RuntimeError("; ".join("%s: %s" % (name, err.strip()) for name, _, err in bad))
    return results

def open_firewall_port(port, dip=None, dport=None):
    if shutil.which("firewall-cmd") and sh(["systemctl", "is-active", "--quiet", "firewalld"]).returncode == 0:
        sh(["firewall-cmd", "--add-port=%s/tcp" % port, "--permanent"])
        sh(["firewall-cmd", "--add-port=%s/udp" % port, "--permanent"])
        sh(["firewall-cmd", "--reload"])
        return
    if shutil.which("ufw") and "active" in sh(["ufw", "status"]).stdout:
        sh(["ufw", "allow", "%s/tcp" % port])
        sh(["ufw", "allow", "%s/udp" % port])
        return
    if shutil.which("iptables"):
        for proto in ("tcp", "udp"):
            if sh(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"]).returncode != 0:
                sh(["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
            if dip and dport and sh(["iptables", "-C", "FORWARD", "-d", dip, "-p", proto, "--dport", str(dport), "-j", "ACCEPT"]).returncode != 0:
                sh(["iptables", "-I", "FORWARD", "-d", dip, "-p", proto, "--dport", str(dport), "-j", "ACCEPT"])

def close_firewall_port(port, dip=None, dport=None):
    if shutil.which("firewall-cmd") and sh(["systemctl", "is-active", "--quiet", "firewalld"]).returncode == 0:
        sh(["firewall-cmd", "--remove-port=%s/tcp" % port, "--permanent"])
        sh(["firewall-cmd", "--remove-port=%s/udp" % port, "--permanent"])
        sh(["firewall-cmd", "--reload"])
        return
    if shutil.which("ufw") and "active" in sh(["ufw", "status"]).stdout:
        sh(["ufw", "delete", "allow", "%s/tcp" % port])
        sh(["ufw", "delete", "allow", "%s/udp" % port])
        return
    if shutil.which("iptables"):
        for proto in ("tcp", "udp"):
            sh(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
            if dip and dport:
                sh(["iptables", "-D", "FORWARD", "-d", dip, "-p", proto, "--dport", str(dport), "-j", "ACCEPT"])

def status():
    def active(unit):
        return sh(["systemctl", "is-active", unit]).stdout.strip()
    return {
        "nftables": active("nftables"),
        "panel": active("nft-forward-panel"),
        "port_rules": load_rules(),
        "dns_rules": load_dns_rules(),
    }

def export_rules_data():
    return {
        "format": "nft-forward-panel",
        "version": 1,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "port_rules": load_rules(),
        "dns_rules": load_dns_rules(),
    }

def import_rules_data(data):
    if not isinstance(data, dict):
        raise ValueError("导入文件格式无效")
    port_rules = data.get("port_rules", [])
    dns_rules = data.get("dns_rules", [])
    if not isinstance(port_rules, list) or not isinstance(dns_rules, list):
        raise ValueError("导入文件缺少规则列表")

    clean_ports = []
    used_ports = set()
    for item in port_rules:
        if not isinstance(item, dict):
            raise ValueError("普通转发规则格式无效")
        name = safe_name(item.get("name"))
        lport = str(item.get("lport", ""))
        dip = str(item.get("dip", "")).strip()
        dport = str(item.get("dport", ""))
        if not valid_port(lport) or not valid_ip(dip) or not valid_port(dport):
            raise ValueError("普通转发规则包含无效端口或 IP")
        if lport in used_ports:
            raise ValueError("入口端口重复: %s" % lport)
        used_ports.add(lport)
        clean_ports.append({"name": name, "lport": lport, "dip": dip, "dport": dport})

    clean_dns = []
    for item in dns_rules:
        if not isinstance(item, dict):
            raise ValueError("DNS 转发规则格式无效")
        domain = str(item.get("domain", "")).strip().lower()
        lport = str(item.get("lport", ""))
        dport = str(item.get("dport", ""))
        if not valid_forward_domain(domain) or not valid_port(lport) or not valid_port(dport):
            raise ValueError("DNS 转发规则包含无效域名或端口")
        set_name = unique_set_name(item.get("set_name") or ("%s_%s" % (domain.replace(".", "_").replace("-", "_"), lport)), clean_dns)
        clean_dns.append({"domain": domain, "lport": lport, "dport": dport, "set_name": set_name})

    backup(CONF_FILE); backup(DNS_USER_CONF)
    write_rules(clean_ports)
    write_dns_user_rules(clean_dns)
    write_dns_nft(clean_dns)
    reload_nft()
    for r in clean_ports:
        open_firewall_port(r["lport"], r["dip"], r["dport"])
    for r in clean_dns:
        open_firewall_port(r["lport"])
    log("panel import rules: port=%d dns=%d" % (len(clean_ports), len(clean_dns)))
    return {"status": "ok", "port_count": len(clean_ports), "dns_count": len(clean_dns)}

def test_connectivity(host, port, timeout_sec):
    host = str(host or "").strip().lower()
    port = str(port or "").strip()
    try:
        timeout_sec = float(timeout_sec or 3)
    except ValueError:
        timeout_sec = 3
    timeout_sec = max(1.0, min(timeout_sec, 10.0))

    if not valid_test_host(host):
        raise ValueError("目标地址格式无效")
    if not valid_port(port):
        raise ValueError("目标端口格式无效")

    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_sec) as s:
            peer = "%s:%s" % s.getpeername()[:2]
        elapsed = int((time.monotonic() - started) * 1000)
        return {"ok": True, "host": host, "port": int(port), "elapsed_ms": elapsed, "peer": peer}
    except Exception as e:
        elapsed = int((time.monotonic() - started) * 1000)
        return {"ok": False, "host": host, "port": int(port), "elapsed_ms": elapsed, "error": str(e)}

LOGIN_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>&#x767b;&#x5f55; - nftables &#x8f6c;&#x53d1;&#x9762;&#x677f;</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{height:100vh;width:100vw;overflow:hidden;display:flex;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,ui-sans-serif,sans-serif;background-color:#dce8f5;background-image:url('{{BG_PC}}'),linear-gradient(135deg,#e2f0ff 0%,#ebf7f2 42%,#f5eeff 100%);background-position:center;background-size:cover;background-repeat:no-repeat;color:#374151}
@media(max-width:768px){body{background-image:url('{{BG_MOBILE}}'),linear-gradient(135deg,#e2f0ff 0%,#ebf7f2 42%,#f5eeff 100%)}}
.overlay{position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.05)}
.box{position:relative;z-index:2;background:rgba(255,255,255,0.3);backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px);padding:2.5rem;border-radius:24px;border:1px solid rgba(255,255,255,0.4);box-shadow:0 8px 32px rgba(0,0,0,0.05);width:90%;max-width:380px;text-align:center}
.mark{width:44px;height:44px;margin:0 auto 1rem;border-radius:12px;background:rgba(59,130,246,.92);color:#fff;display:grid;place-items:center;font-weight:900;font-size:20px;box-shadow:0 10px 28px rgba(37,99,235,.25)}
h2{margin-bottom:2rem;color:#374151;font-weight:600;letter-spacing:1px;font-size:1.2rem}
input{width:100%;padding:14px;margin-bottom:1.2rem;border:1px solid rgba(255,255,255,0.5);border-radius:12px;outline:none;background:rgba(255,255,255,0.5);transition:.3s;color:#374151;font-size:1rem}
input:focus{background:rgba(255,255,255,0.9);border-color:#3b82f6}
button{width:100%;padding:14px;background:rgba(59,130,246,0.85);color:#fff;border:none;border-radius:12px;cursor:pointer;font-weight:600;font-size:1rem;transition:.3s;backdrop-filter:blur(5px)}
button:hover{background:#2563eb;transform:translateY(-1px)}
button:disabled{opacity:.65;cursor:not-allowed;transform:none}
.err{min-height:20px;margin:-0.4rem 0 .6rem;color:#dc2626;font-size:13px}
</style></head><body><div class="overlay"></div>
<div class="box"><div class="mark">N</div><h2>nftables &#x8f6c;&#x53d1;&#x9762;&#x677f;</h2>
<form id="f"><input type="text" id="u" placeholder="&#x7528;&#x6237;&#x540d;" autocomplete="username" required><input type="password" id="p" placeholder="&#x5bc6;&#x7801;" autocomplete="current-password" required><div class="err" id="err"></div><button type="submit" id="btn">&#x767b; &#x5f55;</button></form></div>
<script>
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const btn=document.getElementById('btn'),err=document.getElementById('err');btn.disabled=true;btn.textContent='登录中...';err.textContent='';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});if(r.ok){location.href='/'}else{const d=await r.json().catch(()=>({}));err.textContent=d.error||'用户名或密码错误';btn.disabled=false;btn.textContent='登 录'}}catch(_){err.textContent='网络错误，请重试';btn.disabled=false;btn.textContent='登 录'}});
</script></body></html>"""

HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>nftables &#x8f6c;&#x53d1;&#x9762;&#x677f;</title>
<style>
:root{--text:#1f2937;--muted:#64748b;--line:rgba(255,255,255,.42);--panel:rgba(255,255,255,.32);--panel-strong:rgba(255,255,255,.56);--blue:#3b82f6;--green:#059669;--amber:#b45309;--red:#ef4444;--soft-blue:rgba(219,234,254,.72);--soft-green:rgba(209,250,229,.72);--soft-amber:rgba(254,243,199,.76)}
*{box-sizing:border-box}html,body{width:100%;min-height:100%;overflow-x:hidden}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,ui-sans-serif,sans-serif;color:var(--text);font-size:14px;background:#dce8f5;background-image:linear-gradient(135deg,rgba(226,240,255,.95) 0%,rgba(235,247,242,.92) 42%,rgba(245,238,255,.90) 100%);background-attachment:fixed}body:before{content:"";position:fixed;inset:0;background:linear-gradient(120deg,rgba(255,255,255,.34),rgba(255,255,255,.08) 46%,rgba(219,234,254,.28));pointer-events:none}.shell{position:relative;min-height:100vh}.topbar{height:66px;background:rgba(255,255,255,.30);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-bottom:1px solid rgba(255,255,255,.38);color:#172033;display:flex;align-items:center;justify-content:space-between;padding:0 28px}.brand{display:flex;align-items:center;gap:12px;font-weight:850;font-size:17px}.mark{width:34px;height:34px;border-radius:10px;background:rgba(59,130,246,.92);color:white;display:grid;place-items:center;font-weight:900;box-shadow:0 10px 28px rgba(37,99,235,.25)}.topmeta{display:flex;align-items:center;gap:10px;color:#475569}
.wrap{width:100%;max-width:1180px;margin:0 auto;padding:24px}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:18px}.title h1{font-size:25px;margin:0 0 4px;letter-spacing:0}.title p{margin:0;color:#516073}.actions{display:flex;gap:10px;flex-wrap:wrap}
button{height:38px;border:0;border-radius:10px;padding:0 14px;background:rgba(59,130,246,.95);color:white;cursor:pointer;font-weight:750;box-shadow:0 8px 22px rgba(37,99,235,.14)}button:hover{filter:brightness(.98)}button:disabled{opacity:.65;cursor:not-allowed}button.secondary{background:rgba(71,85,105,.88)}button.ghost{background:rgba(255,255,255,.52);color:#233044;border:1px solid rgba(255,255,255,.55);box-shadow:none}button.danger{background:rgba(239,68,68,.92)}button.small{height:30px;padding:0 10px;border-radius:8px;font-size:12px}
.status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:18px}.metric{min-width:0;background:var(--panel);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--line);border-radius:18px;padding:15px;box-shadow:0 12px 35px rgba(15,23,42,.08)}.metric .label{color:#5f6e82;font-size:12px;margin-bottom:8px}.metric .value{font-size:26px;font-weight:850;line-height:1}.metric .hint{margin-top:8px;color:#64748b;font-size:12px}.ok{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}
.stack{display:grid;gap:18px}.panel{min-width:0;background:var(--panel);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid var(--line);border-radius:20px;overflow:hidden;box-shadow:0 16px 44px rgba(15,23,42,.09)}.panel-head{display:flex;align-items:center;justify-content:space-between;padding:15px 16px;border-bottom:1px solid rgba(255,255,255,.34)}.panel-head h2{margin:0;font-size:16px}.panel-body{padding:0}.tabs{display:flex;gap:6px;padding:10px;border-bottom:1px solid rgba(255,255,255,.34);background:rgba(255,255,255,.20)}.tab{height:34px;background:transparent;color:#334155;border:1px solid transparent;box-shadow:none}.tab.active{background:rgba(255,255,255,.58);border-color:rgba(255,255,255,.62);color:#0f172a}.tabpane{display:none}.tabpane.active{display:block}
table{width:100%;border-collapse:separate;border-spacing:0 10px;padding:0 14px 14px}th,td{text-align:left;vertical-align:middle}th{position:sticky;top:0;padding:13px 12px;font-size:12px;letter-spacing:0;text-transform:uppercase;color:#64748b;background:rgba(255,255,255,.42);backdrop-filter:blur(15px)}td{font-size:14px;background:rgba(255,255,255,.52);padding:12px}tr td:first-child{border-radius:13px 0 0 13px}tr td:last-child{border-radius:0 13px 13px 0}.target{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.namecell{font-weight:780}.badge{display:inline-flex;align-items:center;gap:6px;min-height:24px;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:750}.badge.blue{background:var(--soft-blue);color:#1d4ed8}.badge.green{background:var(--soft-green);color:#047857}.badge.amber{background:var(--soft-amber);color:#92400e}.testout{display:inline-flex;margin-left:8px;font-size:12px;font-weight:750;color:#64748b;white-space:nowrap}.testout.ok{color:#047857}.testout.bad{color:#dc2626}.empty{padding:52px 20px;text-align:center;color:#64748b}.empty strong{display:block;color:#334155;margin-bottom:6px;font-size:15px}
.form{padding:16px;display:grid;grid-template-columns:1.2fr 1fr 1fr 1.2fr auto;gap:12px;align-items:end}.form.unified-fields{grid-template-columns:1.2fr 1fr 1.8fr auto}.form.dns-fields{grid-template-columns:1.4fr 1fr 1fr 1fr auto}.field{display:grid;gap:6px;min-width:0}.field label{font-size:12px;color:#526071;font-weight:750}input{width:100%;min-width:0;height:38px;border:1px solid rgba(255,255,255,.58);border-radius:10px;padding:0 11px;font-size:14px;background:rgba(255,255,255,.58);color:#111827}input:focus{outline:2px solid rgba(147,197,253,.75);border-color:rgba(96,165,250,.75)}.side-note{padding:12px 14px;margin:0 16px 16px;border-radius:12px;background:rgba(255,255,255,.36);border:1px solid rgba(255,255,255,.46);color:#526071;font-size:13px}.msg{position:fixed;right:20px;bottom:20px;max-width:min(460px,calc(100vw - 40px));white-space:pre-wrap;background:rgba(15,23,42,.88);color:#e5e7eb;border-radius:12px;padding:13px 15px;display:none;font-size:13px;box-shadow:0 18px 50px rgba(15,23,42,.25);z-index:10}.msg.show{display:block}.msg.error{background:rgba(127,29,29,.92)}.msg.success{background:rgba(6,78,59,.92)}
@media(max-width:980px){body{background-attachment:scroll}.form,.form.dns-fields{grid-template-columns:repeat(2,minmax(0,1fr))}.form button{grid-column:1/-1}.toolbar{align-items:flex-start;flex-direction:column}.actions{width:100%}.actions button{flex:1}.topbar{padding:0 16px}}
@media(max-width:680px){.wrap{padding:14px}.form,.form.dns-fields{grid-template-columns:1fr}.topmeta #last{display:none}.brand span{font-size:15px}table{border-spacing:0;padding:0}th{display:none}tr{display:block;border-bottom:1px solid rgba(255,255,255,.30);padding:9px 0;background:rgba(255,255,255,.42)}td{display:flex;justify-content:space-between;gap:14px;border:0;background:transparent;padding:7px 14px;word-break:break-all}tr td:first-child,tr td:last-child{border-radius:0}td:before{content:attr(data-label);color:#64748b;font-size:12px;font-weight:700;flex:0 0 auto}.namecell{font-weight:800}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">N</div><span>nftables &#x8f6c;&#x53d1;&#x9762;&#x677f;</span></div><div class="topmeta"><span id="last">&#x6b63;&#x5728;&#x52a0;&#x8f7d;</span><button class="ghost small" id="logoutBtn">&#x9000;&#x51fa;&#x767b;&#x5f55;</button></div></header>
<main class="wrap"><div class="toolbar"><div class="title"><h1>&#x8f6c;&#x53d1;&#x89c4;&#x5219;&#x63a7;&#x5236;&#x53f0;</h1><p>&#x7ba1;&#x7406; nftables &#x8f6c;&#x53d1;&#x89c4;&#x5219;&#x4e0e;&#x91cd;&#x8f7d;&#x72b6;&#x6001;&#x3002;</p></div><div class="actions"><button class="ghost" id="refreshBtn">&#x5237;&#x65b0;</button><button class="ghost" id="exportBtn">&#x5bfc;&#x51fa;</button><button class="ghost" id="importBtn">&#x5bfc;&#x5165;</button><button class="secondary" id="reloadBtn">&#x91cd;&#x8f7d; nft</button><input id="importFile" type="file" accept="application/json,.json" style="display:none"></div></div>
<div class="status-grid"><div class="metric"><div class="label">nftables</div><div class="value" id="nftState">-</div><div class="hint">&#x7cfb;&#x7edf;&#x670d;&#x52a1;&#x72b6;&#x6001;</div></div><div class="metric"><div class="label">Web &#x9762;&#x677f;</div><div class="value" id="panelState">-</div><div class="hint">&#x9762;&#x677f;&#x670d;&#x52a1;</div></div><div class="metric"><div class="label">&#x666e;&#x901a;&#x8f6c;&#x53d1;</div><div class="value" id="portCount">0</div><div class="hint">DNAT &#x89c4;&#x5219;&#x6570;&#x91cf;</div></div><div class="metric"><div class="label">DNS &#x8f6c;&#x53d1;</div><div class="value" id="dnsCount">0</div><div class="hint">&#x57df;&#x540d;&#x89c4;&#x5219;&#x6570;&#x91cf;</div></div></div>
<div id="msg" class="msg"></div><div class="stack"><section class="panel"><div class="panel-head"><h2>&#x65b0;&#x589e;&#x89c4;&#x5219;</h2><span class="badge green">&#x81ea;&#x52a8;&#x91cd;&#x8f7d;</span></div><div class="tabs" id="formTabs"><button class="tab active" data-form="port">&#x666e;&#x901a;</button><button class="tab" data-form="dns">DNS</button></div><div id="portForm" class="form unified-fields"><div class="field"><label>&#x540d;&#x79f0;</label><input id="name" placeholder="&#x4f8b;&#x5982; web-api"></div><div class="field"><label>&#x672c;&#x673a;&#x7aef;&#x53e3;</label><input id="lport" placeholder="10000"></div><div class="field"><label>&#x76ee;&#x6807;&#x5730;&#x5740;</label><input id="target" placeholder="1.2.3.4:443 ? example.com:443"></div><button id="addRuleBtn">&#x6dfb;&#x52a0;&#x8f6c;&#x53d1;</button></div><div id="dnsForm" class="form dns-fields" style="display:none"><div class="field"><label>&#x57df;&#x540d;</label><input id="domain" placeholder="example.com"></div><div class="field"><label>&#x672c;&#x673a;&#x7aef;&#x53e3;</label><input id="dlport" placeholder="10001"></div><div class="field"><label>&#x76ee;&#x6807;&#x7aef;&#x53e3;</label><input id="ddport" placeholder="443"></div><div class="field"><label>nft set</label><input id="setname" placeholder="&#x53ef;&#x7559;&#x7a7a;"></div><button id="addDnsBtn">&#x6dfb;&#x52a0; DNS &#x8f6c;&#x53d1;</button></div><p class="side-note">&#x76ee;&#x6807;&#x5730;&#x5740;&#x53ef;&#x76f4;&#x63a5;&#x586b; IP:&#x7aef;&#x53e3; &#x6216; &#x57df;&#x540d;:&#x7aef;&#x53e3;&#xff1b;&#x57df;&#x540d;&#x4f1a;&#x81ea;&#x52a8;&#x5199;&#x5165; DNS &#x52a8;&#x6001;&#x8f6c;&#x53d1;&#x3002;&#x7248;&#x672c; <span id="panelVersion">2026.06.27.9</span></p></section>
<section class="panel"><div class="panel-head"><h2>&#x89c4;&#x5219;&#x5217;&#x8868;</h2><span class="badge blue" id="totalBadge">0 &#x6761;</span></div><div class="panel-body"><div id="allRules"></div></div></section></div></main></div>
<script>
const $=id=>document.getElementById(id);let editPort=null;let editDns=null;
function showMsg(t,type='success'){const el=$('msg');el.textContent=t;el.className='msg show '+type;clearTimeout(window.msgTimer);window.msgTimer=setTimeout(()=>{el.className='msg'},4200)}
async function api(url,opt){const r=await fetch(url,opt);if(r.status===401){location.href='/login';throw new Error('登录已过期，请重新登录')}const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||r.statusText);return d}
function stateClass(v){return v==='active'?'ok':(v==='inactive'||!v?'warn':'bad')}
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function switchForm(tab){document.querySelectorAll('#formTabs .tab').forEach((b,i)=>b.classList.toggle('active',(tab==='port'?i===0:i===1)));$('portForm').style.display=tab==='port'?'grid':'none';$('dnsForm').style.display=tab==='dns'?'grid':'none'}
function normalizeRules(d){const rows=[];(d.port_rules||[]).forEach(r=>rows.push({kind:'rules',type:'IP',name:r.name||'\u672a\u547d\u540d',lport:r.lport,target:r.dip,dport:r.dport,host:r.dip,delId:r.lport,raw:r}));(d.dns_rules||[]).forEach(r=>rows.push({kind:'dns',type:'DNS',name:r.domain,lport:r.lport,target:r.domain,dport:r.dport,host:r.domain,delId:r.domain+'|'+r.lport,raw:r}));return rows.sort((a,b)=>(Number(a.lport)||0)-(Number(b.lport)||0)||a.target.localeCompare(b.target))}
function table(rows){if(!rows.length)return '<div class="empty"><strong>\u6682\u65e0\u89c4\u5219</strong><span>\u6dfb\u52a0\u540e\u4f1a\u663e\u793a\u5728\u8fd9\u91cc\u3002</span></div>';const heads=['\u540d\u79f0','\u5165\u53e3','\u76ee\u6807','\u7c7b\u578b','\u8fde\u901a\u6027','\u64cd\u4f5c'];return '<table><thead><tr>'+heads.map(h=>'<th>'+h+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>{const badge=r.type==='DNS'?'<span class="badge amber">DNS</span>':'<span class="badge green">IP</span>';const test='<button class="ghost small testbtn" data-host="'+esc(r.host)+'" data-port="'+esc(r.dport)+'">\u6d4b\u8bd5</button> <span class="testout" data-test="'+esc(r.host)+':'+esc(r.dport)+'"></span>';const editData=r.kind==='rules'?' data-kind="rules" data-id="'+esc(r.lport)+'" data-name="'+esc(r.raw.name||'')+'" data-lport="'+esc(r.lport)+'" data-dip="'+esc(r.target)+'" data-dport="'+esc(r.dport)+'"':' data-kind="dns" data-id="'+esc(r.delId)+'" data-domain="'+esc(r.target)+'" data-lport="'+esc(r.lport)+'" data-dport="'+esc(r.dport)+'" data-set="'+esc(r.raw.set_name)+'"';const ops='<button class="ghost small editbtn"'+editData+'>\u7f16\u8f91</button> <button class="danger small delbtn" data-kind="'+r.kind+'" data-id="'+esc(r.delId)+'">\u5220\u9664</button>';return '<tr><td data-label="'+heads[0]+'" class="namecell">'+esc(r.name)+'</td><td data-label="'+heads[1]+'"><span class="badge blue">'+esc(r.lport)+'</span></td><td data-label="'+heads[2]+'" class="target">'+esc(r.target)+':'+esc(r.dport)+'</td><td data-label="'+heads[3]+'">'+badge+'</td><td data-label="'+heads[4]+'">'+test+'</td><td data-label="\u64cd\u4f5c">'+ops+'</td></tr>'}).join('')+'</tbody></table>'}
async function load(){try{const d=await api('/api/state');const rows=normalizeRules(d);$('nftState').textContent=d.nftables||'-';$('panelState').textContent=d.panel||'-';$('nftState').className='value '+stateClass(d.nftables);$('panelState').className='value '+stateClass(d.panel);$('portCount').textContent=d.port_rules.length;$('dnsCount').textContent=d.dns_rules.length;$('totalBadge').textContent=rows.length+' \u6761';$('allRules').innerHTML=table(rows);$('last').textContent='\u6700\u540e\u5237\u65b0 '+new Date().toLocaleTimeString()}catch(e){$('last').textContent='\u52a0\u8f7d\u5931\u8d25';showMsg(e.message,'error')}}
function clearPortEdit(){editPort=null;['name','lport','target'].forEach(id=>$(id).value='');$('addRuleBtn').textContent='\u6dfb\u52a0\u8f6c\u53d1'}
function clearDnsEdit(){editDns=null;['domain','dlport','ddport','setname'].forEach(id=>$(id).value='');$('addDnsBtn').textContent='\u6dfb\u52a0 DNS \u8f6c\u53d1'}
async function addRule(){try{const wasEdit=!!editPort;const body={name:$('name').value,lport:$('lport').value,target:$('target').value};if(editPort)body.old_lport=editPort.old_lport;const res=await api('/api/rules',{method:'POST',body:JSON.stringify(body)});clearPortEdit();showMsg(res.kind==='dns'?(wasEdit?'DNS \u8f6c\u53d1\u5df2\u4fee\u6539\u5e76\u91cd\u8f7d\u3002':'DNS \u8f6c\u53d1\u5df2\u6dfb\u52a0\u5e76\u91cd\u8f7d\u3002'):(wasEdit?'\u666e\u901a\u8f6c\u53d1\u5df2\u4fee\u6539\u5e76\u91cd\u8f7d\u3002':'\u666e\u901a\u8f6c\u53d1\u5df2\u6dfb\u52a0\u5e76\u91cd\u8f7d\u3002'));load()}catch(e){showMsg(e.message,'error')}}
async function addDns(){try{const wasEdit=!!editDns;const body={domain:$('domain').value,lport:$('dlport').value,dport:$('ddport').value,set_name:$('setname').value};if(editDns)body.old_index=editDns.old_index;await api('/api/dns',{method:'POST',body:JSON.stringify(body)});clearDnsEdit();showMsg(wasEdit?'DNS \u8f6c\u53d1\u5df2\u4fee\u6539\u5e76\u91cd\u8f7d\u3002':'DNS \u8f6c\u53d1\u5df2\u6dfb\u52a0\u5e76\u91cd\u8f7d\u3002');load()}catch(e){showMsg(e.message,'error')}}
function edit(btn){if(btn.dataset.kind==='rules'){editPort={old_lport:btn.dataset.lport};switchForm('port');$('name').value=btn.dataset.name;$('lport').value=btn.dataset.lport;$('target').value=btn.dataset.dip+':'+btn.dataset.dport;$('addRuleBtn').textContent='\u4fdd\u5b58\u8f6c\u53d1'}else{editDns={old_index:btn.dataset.id};switchForm('dns');$('domain').value=btn.dataset.domain;$('dlport').value=btn.dataset.lport;$('ddport').value=btn.dataset.dport;$('setname').value=btn.dataset.set;$('addDnsBtn').textContent='\u4fdd\u5b58 DNS \u8f6c\u53d1'}document.querySelector('.panel').scrollIntoView({behavior:'smooth',block:'start'})}
async function del(kind,id){if(!confirm('\u786e\u8ba4\u5220\u9664\u8fd9\u6761\u89c4\u5219\uff1f'))return;try{await api('/api/'+kind+'/'+encodeURIComponent(id),{method:'DELETE'});showMsg('\u89c4\u5219\u5df2\u5220\u9664\u5e76\u91cd\u8f7d\u3002');load()}catch(e){showMsg(e.message,'error')}}
async function reloadRules(){try{await api('/api/reload',{method:'POST'});showMsg('nftables \u5df2\u91cd\u8f7d\u3002');load()}catch(e){showMsg(e.message,'error')}}
function exportRules(){window.location.href='/api/export'}
async function importRules(file){if(!file)return;if(!confirm('\u5bfc\u5165\u540e\u4f1a\u8986\u76d6\u5f53\u524d\u9762\u677f\u89c4\u5219\uff0c\u786e\u8ba4\u7ee7\u7eed\uff1f'))return;try{const text=await file.text();const data=JSON.parse(text);const res=await api('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});showMsg('\u5bfc\u5165\u5b8c\u6210\uff1a\u666e\u901a '+res.port_count+' \u6761\uff0cDNS '+res.dns_count+' \u6761\u3002');load()}catch(e){showMsg('\u5bfc\u5165\u5931\u8d25\uff1a'+e.message,'error')}finally{$('importFile').value=''}}
async function testConn(btn){const out=btn.parentElement.querySelector('.testout');btn.disabled=true;out.textContent='\u6d4b\u8bd5\u4e2d...';out.className='testout';try{const d=await api('/api/test',{method:'POST',body:JSON.stringify({host:btn.dataset.host,port:btn.dataset.port,timeout:3})});if(d.ok){out.textContent='\u53ef\u8fbe '+d.elapsed_ms+'ms';out.className='testout ok'}else{out.textContent='\u5931\u8d25 '+d.elapsed_ms+'ms';out.className='testout bad';showMsg((d.host||btn.dataset.host)+':'+(d.port||btn.dataset.port)+' '+(d.error||'\u4e0d\u53ef\u8fbe'),'error')}}catch(e){out.textContent='\u5931\u8d25';out.className='testout bad';showMsg(e.message,'error')}finally{btn.disabled=false}}
$('logoutBtn').addEventListener('click',async()=>{try{await fetch('/api/logout',{method:'POST'})}catch(_){}location.href='/login'});$('refreshBtn').addEventListener('click',load);$('reloadBtn').addEventListener('click',reloadRules);$('exportBtn').addEventListener('click',exportRules);$('importBtn').addEventListener('click',()=>$('importFile').click());$('importFile').addEventListener('change',e=>importRules(e.target.files[0]));$('addRuleBtn').addEventListener('click',addRule);$('addDnsBtn').addEventListener('click',addDns);document.querySelectorAll('#formTabs .tab').forEach(btn=>btn.addEventListener('click',()=>switchForm(btn.dataset.form)));document.addEventListener('click',e=>{const delBtn=e.target.closest('.delbtn');if(delBtn)del(delBtn.dataset.kind,delBtn.dataset.id);const testBtn=e.target.closest('.testbtn');if(testBtn)testConn(testBtn);const editBtn=e.target.closest('.editbtn');if(editBtn)edit(editBtn)});load();
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    timeout = 30

    def ok(self, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def fail(self, code, message):
        raw = json.dumps({"error": str(message)}, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def session_token(self):
        header = self.headers.get("Cookie", "")
        for part in header.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "auth_session":
                return value
        return ""

    def auth_ok(self):
        token = self.session_token()
        if token:
            now = time.time()
            expiry = SESSIONS.get(token)
            if expiry and expiry > now:
                SESSIONS[token] = now + SESSION_TTL
                return True
            if expiry:
                SESSIONS.pop(token, None)
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                user_pass = base64.b64decode(header.split(" ", 1)[1]).decode()
            except Exception:
                return False
            return user_pass == PANEL_USER + ":" + PANEL_PASS
        return False

    def require_auth(self):
        if self.auth_ok():
            return True
        self.fail(HTTPStatus.UNAUTHORIZED, "unauthorized")
        return False

    def redirect(self, location):
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def send_page(self, raw, extra_headers=None):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def handle_login(self):
        ip = self.client_address[0]
        now = time.time()
        count, until = LOGIN_FAILS.get(ip, (0, 0))
        if until > now and count >= 5:
            self.fail(HTTPStatus.UNAUTHORIZED, "尝试次数过多，请 10 分钟后再试")
            return
        try:
            data = self.body()
        except Exception:
            self.fail(HTTPStatus.BAD_REQUEST, "请求格式错误")
            return
        user = str(data.get("username", ""))
        password = str(data.get("password", ""))
        if not (secrets.compare_digest(user, PANEL_USER) and secrets.compare_digest(password, PANEL_PASS)):
            LOGIN_FAILS[ip] = ((count + 1) if until > now else 1, now + 600)
            log("panel login failed from %s" % ip)
            time.sleep(1)
            self.fail(HTTPStatus.UNAUTHORIZED, "用户名或密码错误")
            return
        LOGIN_FAILS.pop(ip, None)
        for stale in [t for t, exp in list(SESSIONS.items()) if exp <= now]:
            SESSIONS.pop(stale, None)
        token = secrets.token_hex(32)
        SESSIONS[token] = now + SESSION_TTL
        cookie = "auth_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d" % (token, SESSION_TTL)
        if PANEL_CERT and PANEL_KEY:
            cookie += "; Secure"
        raw = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        log("panel login ok from %s" % ip)

    def handle_logout(self):
        SESSIONS.pop(self.session_token(), None)
        raw = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", "auth_session=; Path=/; HttpOnly; Max-Age=0")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        return json.loads(self.rfile.read(n).decode("utf-8") or "{}")

    def do_GET(self):
        if self.path == "/login":
            if self.auth_ok():
                self.redirect("/")
                return
            raw = LOGIN_HTML.replace("{{BG_PC}}", PANEL_BG_PC).replace("{{BG_MOBILE}}", PANEL_BG_MOBILE).encode("utf-8")
            self.send_page(raw)
            return
        if self.path == "/":
            if not self.auth_ok():
                self.redirect("/login")
                return
            self.send_page(HTML.encode("utf-8"))
            return
        if not self.require_auth():
            return
        if self.path == "/api/state":
            self.ok(status())
        elif self.path == "/api/export":
            raw = json.dumps(export_rules_data(), ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="nft-forward-rules.json"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.fail(HTTPStatus.NOT_FOUND, "not found")

    def do_POST(self):
        if self.path == "/api/login":
            self.handle_login()
            return
        if self.path == "/api/logout":
            self.handle_logout()
            return
        if not self.require_auth():
            return
        try:
            if self.path == "/api/rules":
                data = self.body()
                name = safe_name(data.get("name"))
                lport = str(data.get("lport", ""))
                if data.get("target"):
                    target, dport = split_host_port(data.get("target"))
                else:
                    target = str(data.get("dip", "")).strip().lower()
                    dport = str(data.get("dport", ""))
                if not valid_port(lport) or not valid_port(dport) or not (valid_ip(target) or valid_forward_domain(target)):
                    raise ValueError("???????????????? host:port")
                old_lport = str(data.get("old_lport") or lport)
                if not valid_port(old_lport):
                    raise ValueError("?????????")

                old_port_rules = load_rules()
                removed = [r for r in old_port_rules if r["lport"] == old_lport]
                port_rules = [r for r in old_port_rules if r["lport"] not in (old_lport, lport)]

                if valid_ip(target):
                    port_rules.append({"name": name, "lport": lport, "dip": target, "dport": dport})
                    backup(CONF_FILE); write_rules(port_rules); reload_nft(); open_firewall_port(lport, target, dport)
                    if old_lport != lport:
                        for r in removed:
                            close_firewall_port(r["lport"], r["dip"], r["dport"])
                    log("panel save port forward: %s -> %s:%s" % (lport, target, dport))
                    self.ok({"status": "ok", "kind": "port"})
                    return

                dns_rules = load_dns_rules()
                dns_rules = [r for r in dns_rules if not (r["domain"] == target and r["lport"] == lport)]
                set_name = unique_set_name("%s_%s" % (target.replace(".", "_").replace("-", "_"), lport), dns_rules)
                dns_rules.append({"domain": target, "lport": lport, "dport": dport, "set_name": set_name})
                backup(CONF_FILE); backup(DNS_USER_CONF)
                write_rules(port_rules); write_dns_user_rules(dns_rules); write_dns_nft(dns_rules); reload_nft(); open_firewall_port(lport)
                if old_lport != lport:
                    for r in removed:
                        close_firewall_port(r["lport"], r["dip"], r["dport"])
                log("panel save dns forward from unified form: %s:%s -> :%s" % (target, lport, dport))
                self.ok({"status": "ok", "kind": "dns"})
            elif self.path == "/api/dns":
                data = self.body()
                domain = str(data.get("domain", "")).strip().lower()
                lport, dport = str(data.get("lport", "")), str(data.get("dport", ""))
                if not valid_domain(domain) or not valid_port(lport) or not valid_port(dport):
                    raise ValueError("域名或端口格式无效")
                rules = load_dns_rules()
                old_index = data.get("old_index")
                skip_index = int(old_index) if old_index not in (None, "") else None
                set_name = unique_set_name(data.get("set_name") or ("%s_%s" % (domain.replace(".", "_").replace("-", "_"), lport)), rules, skip_index)
                old_rule = None
                if old_index not in (None, ""):
                    old_index = int(old_index)
                    if old_index < 0 or old_index >= len(rules):
                        raise ValueError("原规则序号无效")
                    old_rule = rules.pop(old_index)
                rules = [r for r in rules if not (r["domain"] == domain and r["lport"] == lport)]
                rules.append({"domain": domain, "lport": lport, "dport": dport, "set_name": set_name})
                backup(DNS_USER_CONF); write_dns_user_rules(rules); write_dns_nft(rules); reload_nft(); open_firewall_port(lport)
                if old_rule and old_rule.get("lport") != lport:
                    close_firewall_port(old_rule["lport"])
                log("panel save dns forward: %s:%s -> :%s" % (domain, lport, dport))
                self.ok({"status": "ok"})
            elif self.path == "/api/reload":
                write_dns_nft(load_dns_rules())
                reload_nft()
                self.ok({"status": "ok"})
            elif self.path == "/api/import":
                data = self.body()
                self.ok(import_rules_data(data))
            elif self.path == "/api/test":
                data = self.body()
                self.ok(test_connectivity(data.get("host"), data.get("port"), data.get("timeout")))
            else:
                self.fail(HTTPStatus.NOT_FOUND, "not found")
        except Exception as e:
            self.fail(HTTPStatus.BAD_REQUEST, e)

    def do_DELETE(self):
        if not self.require_auth():
            return
        try:
            parts = self.path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "rules":
                lport = unquote(parts[2])
                old_rules = load_rules()
                removed = [r for r in old_rules if r["lport"] == lport]
                rules = [r for r in old_rules if r["lport"] != lport]
                backup(CONF_FILE); write_rules(rules); reload_nft()
                for r in removed:
                    close_firewall_port(r["lport"], r["dip"], r["dport"])
                self.ok({"status": "ok"})
            elif len(parts) == 3 and parts[0] == "api" and parts[1] == "dns":
                key = unquote(parts[2])
                rules = load_dns_rules()
                old_rule = None
                if key.isdigit():
                    idx = int(key)
                    if idx < 0 or idx >= len(rules):
                        raise ValueError("????")
                    old_rule = rules.pop(idx)
                else:
                    if "|" not in key:
                        raise ValueError("??????")
                    domain, lport = key.split("|", 1)
                    kept = []
                    for r in rules:
                        if old_rule is None and r.get("domain") == domain and r.get("lport") == lport:
                            old_rule = r
                        else:
                            kept.append(r)
                    if old_rule is None:
                        raise ValueError("?????")
                    rules = kept
                backup(DNS_USER_CONF); write_dns_user_rules(rules); write_dns_nft(rules); reload_nft()
                if not any(r.get("lport") == old_rule.get("lport") for r in rules):
                    close_firewall_port(old_rule["lport"])
                self.ok({"status": "ok"})
            else:
                self.fail(HTTPStatus.NOT_FOUND, "not found")
        except Exception as e:
            self.fail(HTTPStatus.BAD_REQUEST, e)

    def log_message(self, fmt, *args):
        return

if __name__ == "__main__":
    ensure_dirs()
    httpd = ThreadingHTTPServer((PANEL_HOST, PANEL_PORT), Handler)
    scheme = "http"
    if PANEL_CERT and PANEL_KEY:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(PANEL_CERT, PANEL_KEY)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        scheme = "https"
    print("nft-forward-panel listening on %s://%s:%d" % (scheme, PANEL_HOST, PANEL_PORT), flush=True)
    httpd.serve_forever()
PY

    chmod +x "${PANEL_BIN}"

    cat > "${PANEL_SERVICE_FILE}" <<EOF
[Unit]
Description=nftables Port Forward Panel
After=network-online.target
Wants=network-online.target

[Service]
User=root
Environment="PANEL_USER=${panel_user}"
Environment="PANEL_PASS=${panel_pass}"
Environment="PANEL_PORT=${panel_port}"
Environment="PANEL_HOST=${panel_host}"
Environment="PANEL_CERT=${panel_cert}"
Environment="PANEL_KEY=${panel_key}"
ExecStart=${PANEL_BIN}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${PANEL_SERVICE}" >/dev/null 2>&1 || true
    systemctl restart "${PANEL_SERVICE}" >/dev/null 2>&1 || {
        err "面板服务启动失败，请查看: journalctl -u ${PANEL_SERVICE} -n 50"
        return 1
    }

    local ip
    ip=$(curl -s4 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
    ip="${ip:-服务器IP}"
    local scheme="http"
    [[ -n "$panel_cert" && -n "$panel_key" ]] && scheme="https"
    if (( existing_panel )); then
        info "面板已更新并重启，原有配置已保留。"
    else
        info "面板已安装并启动。"
    fi
    echo "访问地址: ${scheme}://${ip}:${panel_port}"
    echo "用户名: ${panel_user}"
    echo "密码: ${panel_pass}"
    log_action "安装/更新 Web 面板: port=${panel_port}"
}

uninstall_panel() {
    systemctl stop "${PANEL_SERVICE}" >/dev/null 2>&1 || true
    systemctl disable "${PANEL_SERVICE}" >/dev/null 2>&1 || true
    rm -f "${PANEL_SERVICE_FILE}" "${PANEL_BIN}"
    systemctl daemon-reload >/dev/null 2>&1 || true
    info "Web 面板已卸载。"
    log_action "卸载 Web 面板"
}

update_panel_port() {
    if [[ ! -f "${PANEL_SERVICE_FILE}" ]]; then
        err "面板尚未安装。"
        return 1
    fi
    local panel_port
    read -rp "新的面板端口: " panel_port
    if ! validate_port "$panel_port"; then
        err "端口无效。"
        return 1
    fi
    sed -i -E "s|Environment=\"PANEL_PORT=[0-9]+\"|Environment=\"PANEL_PORT=${panel_port}\"|" "${PANEL_SERVICE_FILE}"
    systemctl daemon-reload
    systemctl restart "${PANEL_SERVICE}" && info "面板端口已修改为 ${panel_port}。"
}

update_panel_login() {
    if [[ ! -f "${PANEL_SERVICE_FILE}" ]]; then
        err "面板尚未安装。"
        return 1
    fi

    local panel_user panel_pass
    read -rp "新的面板用户名: " panel_user
    panel_user=$(sanitize_rule_name "$panel_user")
    if [[ -z "$panel_user" ]]; then
        err "用户名不能为空。"
        return 1
    fi

    read -rsp "新的面板密码: " panel_pass
    echo ""
    if [[ -z "$panel_pass" ]]; then
        err "密码不能为空。"
        return 1
    fi
    if [[ "$panel_pass" == *\"* || "$panel_pass" == *\\* || "$panel_pass" == *$'\n'* || "$panel_pass" == *$'\r'* ]]; then
        err "密码不能包含双引号、反斜杠或换行。"
        return 1
    fi

    sed -i -E "s|Environment=\"PANEL_USER=.*\"|Environment=\"PANEL_USER=${panel_user}\"|" "${PANEL_SERVICE_FILE}"
    sed -i -E "s|Environment=\"PANEL_PASS=.*\"|Environment=\"PANEL_PASS=${panel_pass}\"|" "${PANEL_SERVICE_FILE}"
    systemctl daemon-reload
    if systemctl restart "${PANEL_SERVICE}"; then
        info "面板登录信息已修改。"
        echo "用户名: ${panel_user}"
        echo "密码: ${panel_pass}"
        log_action "修改 Web 面板登录信息"
    else
        err "面板重启失败，请查看: journalctl -u ${PANEL_SERVICE} -n 50"
        return 1
    fi
}

update_panel_tls() {
    if [[ ! -f "${PANEL_SERVICE_FILE}" ]]; then
        err "面板尚未安装。"
        return 1
    fi

    local panel_host cert_path key_path cert_ip panel_port public_ip
    read -rp "监听 IP [默认 0.0.0.0，填 127.0.0.1 可仅本机访问]: " panel_host
    panel_host="${panel_host:-0.0.0.0}"
    if ! validate_listen_host "$panel_host"; then
        err "监听 IP 无效，请输入 0.0.0.0、127.0.0.1、localhost 或 IPv4 地址。"
        return 1
    fi
    panel_port=$(get_panel_env "PANEL_PORT")
    panel_port="${panel_port:-$PANEL_PORT_DEFAULT}"

    echo "HTTPS 证书配置：直接回车使用默认路径；如需关闭 HTTPS，请两项都输入 none。"
    echo "如填写的证书/私钥不存在，脚本会申请 Let's Encrypt 真实 IP 证书，不会生成自签证书。"
    echo "申请 IP 证书要求：公网 IP、80 端口可从公网访问、不能使用内网/回环 IP。"
    read -rp "证书文件路径 [默认 ${PANEL_CERT_DEFAULT}]: " cert_path
    read -rp "私钥文件路径 [默认 ${PANEL_KEY_DEFAULT}]: " key_path
    cert_path="${cert_path:-$PANEL_CERT_DEFAULT}"
    key_path="${key_path:-$PANEL_KEY_DEFAULT}"
    if [[ "$cert_path" == "none" && "$key_path" == "none" ]]; then
        cert_path=""
        key_path=""
    fi

    if [[ -n "$cert_path" || -n "$key_path" ]]; then
        if [[ -z "$cert_path" || -z "$key_path" ]]; then
            err "启用 HTTPS 时证书和私钥路径都必须填写。"
            return 1
        fi
        if [[ "$cert_path" == *\"* || "$key_path" == *\"* ]]; then
            err "证书路径不能包含双引号。"
            return 1
        fi
        mkdir -p "$(dirname "$cert_path")" "$(dirname "$key_path")" 2>/dev/null || {
            err "无法创建证书目录，请检查路径和权限。"
            return 1
        }
        if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
            echo "证书或私钥不存在，将申请真实 IP 证书。"
            if validate_public_ipv4 "$panel_host"; then
                read -rp "证书 IP [默认 ${panel_host}]: " cert_ip
                cert_ip="${cert_ip:-$panel_host}"
            else
                read -rp "证书 IP [必须填写服务器公网 IPv4，不能填 ${panel_host}]: " cert_ip
            fi

            if ! validate_public_ipv4 "$cert_ip"; then
                err "证书 IP 无效。IP 证书只能申请公网 IPv4，不能使用 0.0.0.0、127.0.0.1 或内网 IP。"
                return 1
            fi

            issue_ip_certificate "$cert_ip" "$cert_path" "$key_path" || {
                err "HTTPS 配置未更新，仍保留当前面板配置。"
                return 1
            }
        fi
    fi

    if grep -q 'Environment="PANEL_HOST=' "${PANEL_SERVICE_FILE}"; then
        sed -i -E "s|Environment=\"PANEL_HOST=.*\"|Environment=\"PANEL_HOST=${panel_host}\"|" "${PANEL_SERVICE_FILE}"
    else
        sed -i "/Environment=\"PANEL_PORT=/a Environment=\"PANEL_HOST=${panel_host}\"" "${PANEL_SERVICE_FILE}"
    fi

    if grep -q 'Environment="PANEL_CERT=' "${PANEL_SERVICE_FILE}"; then
        sed -i -E "s|Environment=\"PANEL_CERT=.*\"|Environment=\"PANEL_CERT=${cert_path}\"|" "${PANEL_SERVICE_FILE}"
    else
        sed -i "/Environment=\"PANEL_HOST=/a Environment=\"PANEL_CERT=${cert_path}\"" "${PANEL_SERVICE_FILE}"
    fi

    if grep -q 'Environment="PANEL_KEY=' "${PANEL_SERVICE_FILE}"; then
        sed -i -E "s|Environment=\"PANEL_KEY=.*\"|Environment=\"PANEL_KEY=${key_path}\"|" "${PANEL_SERVICE_FILE}"
    else
        sed -i "/Environment=\"PANEL_CERT=/a Environment=\"PANEL_KEY=${key_path}\"" "${PANEL_SERVICE_FILE}"
    fi

    systemctl daemon-reload
    if systemctl restart "${PANEL_SERVICE}"; then
        local scheme="http"
        [[ -n "$cert_path" && -n "$key_path" ]] && scheme="https"
        if [[ "$scheme" == "https" ]]; then
            verify_panel_https "$panel_host" "$panel_port" "$cert_ip"
        fi
        public_ip="$panel_host"
        [[ "$public_ip" == "0.0.0.0" || "$public_ip" == "127.0.0.1" || "$public_ip" == "localhost" ]] && public_ip="${cert_ip:-$(get_local_ip)}"
        info "面板监听与证书配置已更新。"
        echo "监听 IP: ${panel_host}"
        echo "面板端口: ${panel_port}"
        echo "访问协议: ${scheme}"
        echo "访问地址: ${scheme}://${public_ip}:${panel_port}"
        log_action "修改 Web 面板监听/TLS: host=${panel_host} scheme=${scheme}"
    else
        err "面板重启失败，请查看: journalctl -u ${PANEL_SERVICE} -n 50"
        return 1
    fi
}

do_panel_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "        Web 面板管理"
        echo "========================================"
        echo "  1) 安装/更新 Web 面板（更新时保留现有配置）"
        echo "  2) 卸载 Web 面板"
        echo "  3) 修改面板端口"
        echo "  4) 修改登录信息"
        echo "  5) 配置监听 IP / HTTPS 证书"
        echo "  6) 查看面板状态"
        echo "  7) 返回主菜单"
        echo "========================================"
        read -rp "请选择操作 [1-7]: " panel_choice

        case "$panel_choice" in
            1) install_panel ;;
            2) uninstall_panel ;;
            3) update_panel_port ;;
            4) update_panel_login ;;
            5) update_panel_tls ;;
            6) systemctl status "${PANEL_SERVICE}" --no-pager || true ;;
            7) break ;;
            *) err "无效选择，请输入 1-7。" ;;
        esac
    done
}

# ====================================================
do_clear_all() {
    echo ""
    if ! command -v nft &>/dev/null; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    load_rules

    if [[ ${#RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则，无需清空。"
        return
    fi

    warn "即将清空全部 ${#RULES[@]} 条转发规则！"
    read -rp "确认清空？[y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "已取消。"
        return
    fi

    backup_conf

    local rule lport dip dport name
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport name <<< "$rule"
        firewall_close_port "$lport" "$dip" "$dport" "force"
    done

    RULES=()
    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
        info "所有转发规则已清空。"
        log_action "清空所有转发规则"
    else
        err "规则加载失败，请检查配置。"
    fi
}

# ====================================================
# 主菜单
# ====================================================
main_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "   nftables 端口转发管理工具 v1.6"
        echo "========================================"
        echo "  1) 安装 nftables"
        echo "  2) 安装 iptables-persistent（持久化）"
        echo "  3) 查看现有端口转发"
        echo "  4) 新增端口转发"
        echo "  5) 删除端口转发"
        echo "  6) 一键清空所有转发"
        echo "  7) 诊断/自检"
        echo "  8) DNS 动态转发管理"
        echo "  9) Web 面板管理"
        echo "  10) 退出"
        echo "========================================"
        read -rp "请选择操作 [1-10]: " choice

        case "$choice" in
            1) do_install ;;
            2) do_install_iptables_persistent ;;
            3) do_list ;;
            4) do_add ;;
            5) do_delete ;;
            6) do_clear_all ;;
            7) do_diagnose ;;
            8) do_dns_forward_menu ;;
            9) do_panel_menu ;;
            10)
                info "再见！"
                exit 0
                ;;
                *)
                err "无效选择，请输入 1-10。"
                ;;
        esac
    done
}

# ============== 入口 ==============
check_root
main_menu
