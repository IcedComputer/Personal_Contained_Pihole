#!/bin/bash
#
# WireGuard VPN Client Manager
# File: wireguard-manager.sh
# Created: 2025-12-07
# Last Modified: 2026-11-11
# Version: 1.1.1
#
# Description: User-friendly manager for WireGuard VPN clients
#              Mimics PiVPN functionality with menu-driven interface
#
# Usage: sudo bash wireguard-manager.sh
#

set -euo pipefail

# Colors
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# Paths
readonly WIREGUARD_DIR="/etc/wireguard"
readonly WIREGUARD_DNS_DIR="/etc/wireguard-dns"
readonly WIREGUARD_HOSTS="${WIREGUARD_DNS_DIR}/hosts"
readonly WIREGUARD_DNS_CONFIG="/etc/dnsmasq.d/02-pihole-wireguard.conf"
CONFIG_FILE="${WIREGUARD_DIR}/wg0.conf"
CLIENTS_DIR="${WIREGUARD_DIR}/clients"

# WireGuard network configuration
readonly WIREGUARD_SERVER_NETWORK="10.7.0"
WIREGUARD_SERVER_IP="${WIREGUARD_SERVER_NETWORK}.1"
readonly WIREGUARD_CIDR="24"

# Helper functions
log_success() {
    echo -e "${COLOR_GREEN}✓${COLOR_RESET} $1"
}

log_error() {
    echo -e "${COLOR_RED}✗ ERROR: $1${COLOR_RESET}"
}

log_warning() {
    echo -e "${COLOR_YELLOW}⚠ WARNING: $1${COLOR_RESET}"
}

log_info() {
    echo -e "${COLOR_BLUE}ℹ${COLOR_RESET} $1"
}

show_header() {
    clear
    echo -e "${COLOR_BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            WireGuard VPN Client Manager                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}\n"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_wireguard() {
    if ! command -v wg >/dev/null 2>&1; then
        log_error "WireGuard is not installed"
        exit 1
    fi
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "WireGuard not configured. Run install-pihole-vpn.sh first."
        exit 1
    fi
}

prepare_wireguard_dns() {
    if [[ -L "${WIREGUARD_DNS_DIR}" || -L "${WIREGUARD_HOSTS}" || -L "${WIREGUARD_DNS_CONFIG}" ]]; then
        log_error "Refusing symlinked WireGuard DNS paths"
        return 1
    fi
    if [[ ! -f "${WIREGUARD_DNS_CONFIG}" ]]; then
        log_error "Missing WireGuard DNS configuration: ${WIREGUARD_DNS_CONFIG}"
        return 1
    fi
    if ! grep -Fxq "addn-hosts=${WIREGUARD_HOSTS}" "${WIREGUARD_DNS_CONFIG}" &&
       ! grep -Fxq "addn-hosts=${WIREGUARD_DIR}/hosts" "${WIREGUARD_DNS_CONFIG}"; then
        log_error "Unexpected addn-hosts configuration; update ${WIREGUARD_DNS_CONFIG} to use ${WIREGUARD_HOSTS}"
        return 1
    fi

    # Publish only hostname mappings; keep all key material under the private directory.
    install -d -o root -g root -m 755 "${WIREGUARD_DNS_DIR}" || return 1
    if [[ ! -e "${WIREGUARD_HOSTS}" ]]; then
        if [[ ! -f "${WIREGUARD_DIR}/hosts" || -L "${WIREGUARD_DIR}/hosts" ]]; then
            log_error "No regular WireGuard hosts file available to migrate"
            return 1
        fi
        install -o root -g root -m 644 "${WIREGUARD_DIR}/hosts" "${WIREGUARD_HOSTS}" || return 1
        log_success "Copied legacy hostname mappings to ${WIREGUARD_HOSTS}"
    fi
    if [[ ! -f "${WIREGUARD_HOSTS}" ]]; then
        log_error "WireGuard hosts path is not a regular file: ${WIREGUARD_HOSTS}"
        return 1
    fi
    chown root:root "${WIREGUARD_HOSTS}" || return 1
    chmod 644 "${WIREGUARD_HOSTS}" || return 1

    if grep -Fxq "addn-hosts=${WIREGUARD_DIR}/hosts" "${WIREGUARD_DNS_CONFIG}"; then
        sed -i "s|^addn-hosts=${WIREGUARD_DIR}/hosts$|addn-hosts=${WIREGUARD_HOSTS}|" "${WIREGUARD_DNS_CONFIG}" || return 1
        if ! systemctl restart pihole-FTL; then
            if ! sed -i "s|^addn-hosts=${WIREGUARD_HOSTS}$|addn-hosts=${WIREGUARD_DIR}/hosts|" "${WIREGUARD_DNS_CONFIG}"; then
                log_error "Could not restore the legacy DNS path after restart failure"
            fi
            log_error "FTL restart failed; fix FTL and retry DNS migration"
            return 1
        fi
        log_success "Migrated WireGuard DNS configuration"
    fi
}

update_client_hostname() {
    local name="$1" ip="${2:-}" temp_file
    if [[ -L "${WIREGUARD_DNS_DIR}" || -L "${WIREGUARD_HOSTS}" || ! -f "${WIREGUARD_HOSTS}" ]]; then
        log_error "WireGuard hosts file must be a regular file in a non-symlinked DNS directory"
        return 1
    fi
    if ! grep -Fxq "addn-hosts=${WIREGUARD_HOSTS}" "${WIREGUARD_DNS_CONFIG}"; then
        log_error "DNS configuration does not use ${WIREGUARD_HOSTS}; retry DNS migration first"
        return 1
    fi
    temp_file=$(mktemp "${WIREGUARD_HOSTS}.tmp.XXXXXX") || return 1
    if ! awk -v name="$name" -v ip="$ip" '
        NF < 2 || $2 != name { print }
        END { if (ip != "") print ip, name }
    ' "${WIREGUARD_HOSTS}" > "$temp_file" ||
       ! chmod 644 "$temp_file" ||
       ! mv "$temp_file" "${WIREGUARD_HOSTS}"; then
        rm -f "$temp_file"
        log_error "Failed to update WireGuard hostname mappings"
        return 1
    fi
    if ! systemctl restart pihole-FTL; then
        log_error "Hostname mappings saved, but FTL restart failed"
        return 1
    fi
}

get_client_public_key() {
    local private_key public_key
    # A client's [Peer] PublicKey belongs to the server, not to the client.
    if ! private_key=$(awk '
        /^[[:space:]]*\[/ { interface = ($0 ~ /^[[:space:]]*\[Interface\][[:space:]]*$/) }
        interface && /^[[:space:]]*PrivateKey[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "")
            sub(/[[:space:]]+$/, "")
            print
            count++
        }
        END { if (count != 1) exit 1 }
    ' "$1") || [[ -z "$private_key" ]]; then
        log_error "Cannot read exactly one client private key from $1" >&2
        return 1
    fi
    if ! public_key=$(wg pubkey <<< "$private_key"); then
        log_error "Failed to derive client public key from $1" >&2
        return 1
    fi
    unset private_key
    if [[ ! "$public_key" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        log_error "WireGuard returned an invalid client public key" >&2
        return 1
    fi
    printf '%s\n' "$public_key"
}

remove_server_peer() {
    local public_key="$1" temp_file
    temp_file=$(mktemp "${CONFIG_FILE}.tmp.XXXXXX") || return 1
    # Buffer complete sections. Blank lines and similar client names are not boundaries.
    # An absent peer is safe on retry; duplicate keys or read failures must abort.
    if ! awk -v key="$public_key" '
        function flush() {
            if (!drop) printf "%s", block
            block = ""; drop = 0; peer = 0; pending = 0
        }
        /^[[:space:]]*# Client:/ { flush(); pending = 1; block = $0 ORS; next }
        /^[[:space:]]*\[/ {
            if (!pending) flush()
            peer = ($0 ~ /^[[:space:]]*\[Peer\][[:space:]]*$/)
            pending = 0
        }
        {
            block = block $0 ORS
            if (peer && $0 ~ /^[[:space:]]*PublicKey[[:space:]]*=/) {
                value = $0
                sub(/^[^=]*=[[:space:]]*/, "", value)
                sub(/[[:space:]]+$/, "", value)
                if (value == key) { drop = 1; matches++ }
            }
        }
        END { flush(); if (matches > 1) exit 1 }
    ' "${CONFIG_FILE}" > "$temp_file"; then
        rm -f "$temp_file"
        log_error "Cannot safely remove peer: duplicate key or configuration read failure; configuration was not changed"
        return 1
    fi
    if ! mv "$temp_file" "${CONFIG_FILE}"; then
        rm -f "$temp_file"
        log_error "Failed to save updated WireGuard configuration"
        return 1
    fi
}

# Main menu
show_menu() {
    show_header
    
    echo "Select an option:"
    echo ""
    echo "  1) Add new VPN client"
    echo "  2) Remove VPN client"
    echo "  3) List all clients"
    echo "  4) Show client configuration"
    echo "  5) Show QR code for client"
    echo "  6) Revoke client access"
    echo "  7) Show VPN statistics"
    echo "  8) Restart WireGuard"
    echo "  9) Backup configurations"
    echo " 10) Show file locations"
    echo "  0) Exit"
    echo ""
    read -p "Enter choice [0-10]: " choice
    
    case $choice in
        1) add_client ;;
        2) remove_client ;;
        3) list_clients ;;
        4) show_client_config ;;
        5) show_qr_code ;;
        6) revoke_client ;;
        7) show_statistics ;;
        8) restart_wireguard ;;
        9) backup_configs ;;
        10) show_file_locations ;;
        0) exit 0 ;;
        *) 
            log_error "Invalid choice"
            sleep 2
            show_menu
            ;;
    esac
}

# Add new client
add_client() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   ADD NEW VPN CLIENT                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    manual_add_client
}

manual_add_client() {
    read -p "Enter client name (alphanumeric only, max 32 chars): " client_name
    
    # Validate client name
    if [[ ! "${client_name}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid client name. Use only letters, numbers, underscore, and hyphen."
        sleep 2
        show_menu
        return
    fi

    if (( ${#client_name} > 32 )); then
        log_error "Invalid client name. Maximum length is 32 characters (got ${#client_name})."
        sleep 2
        show_menu
        return
    fi
    
    # Check if client already exists
    if [[ -f "${CLIENTS_DIR}/${client_name}.conf" ]]; then
        log_error "Client '${client_name}' already exists"
        sleep 2
        show_menu
        return
    fi
    
    log_info "Generating keys for ${client_name}..."
    
    local previous_umask
    previous_umask=$(umask)
    # Key-bearing files must be private from creation, not only after chmod.
    umask 077
    mkdir -p "${CLIENTS_DIR}"
    chmod 700 "${CLIENTS_DIR}"
    
    local private_key public_key preshared_key
    private_key=$(wg genkey)
    public_key=$(wg pubkey <<< "${private_key}")
    preshared_key=$(wg genpsk)  # Additional layer of security (post-quantum)
    
    # Get server info
    local server_public_key
    if [[ -f "${WIREGUARD_DIR}/server-public.key" ]]; then
        server_public_key=$(cat "${WIREGUARD_DIR}/server-public.key")
    else
        # Extract from config if not in separate file. Same here-string pattern
        # to keep the server's private key out of process argv.
        local server_private
        server_private=$(grep "^PrivateKey" "${CONFIG_FILE}" | awk '{print $3}')
        server_public_key=$(wg pubkey <<< "${server_private}")
        unset server_private
    fi
    
    # Get server endpoint (public IP)
    local server_endpoint
    # Try multiple methods to get public IP (TLS 1.3 enforced for security)
    server_endpoint=$(curl -s --tlsv1.3 --max-time 5 https://api.ipify.org 2>/dev/null || \
                      curl -s --tlsv1.3 --max-time 5 https://icanhazip.com 2>/dev/null || \
                      curl -s --tlsv1.3 --max-time 5 https://ifconfig.me 2>/dev/null)
    
    # Validate that the response is actually an IPv4 / IPv6 / DNS hostname.
    # An external IP-echo service returning attacker-controlled text would
    # otherwise be embedded verbatim into the client's Endpoint line.
    local _ip_re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    local _v6_re='^[0-9a-fA-F:]+$'
    local _host_re='^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$'
    if [[ -n "${server_endpoint}" ]] \
        && [[ ! "${server_endpoint}" =~ $_ip_re ]] \
        && [[ ! "${server_endpoint}" =~ $_v6_re ]] \
        && [[ ! "${server_endpoint}" =~ $_host_re ]]; then
        log_warning "Detected endpoint failed validation: '${server_endpoint}'"
        server_endpoint=""
    fi

    if [[ -z "${server_endpoint}" ]]; then
        log_warning "Could not detect public IP automatically"
        read -p "Enter server public IP or hostname: " server_endpoint
        # Re-validate user input with the same rules
        if [[ ! "${server_endpoint}" =~ $_ip_re ]] \
            && [[ ! "${server_endpoint}" =~ $_v6_re ]] \
            && [[ ! "${server_endpoint}" =~ $_host_re ]]; then
            log_error "Invalid endpoint format: '${server_endpoint}'"
            sleep 2
            show_menu
            return
        fi
    fi
    
    local server_port=$(grep "^ListenPort" "${CONFIG_FILE}" | awk '{print $3}')
    
    # Get next available IP. -F (fixed string) prevents the dots in the
    # network prefix from being interpreted as regex metacharacters.
    local next_ip=2
    
    while grep -qF "${WIREGUARD_SERVER_NETWORK}.${next_ip}/32" "${CONFIG_FILE}"; do
        ((++next_ip))
        if [[ ${next_ip} -gt 254 ]]; then
            log_error "No available IP addresses in VPN network"
            sleep 2
            show_menu
            return
        fi
    done
    
    local client_ip="${WIREGUARD_SERVER_NETWORK}.${next_ip}"
    
    log_info "Assigned IP: ${client_ip}/32"
    
    # Rename a private temporary file to avoid publishing a partial configuration.
    local _tmp_server
    _tmp_server=$(mktemp "${CONFIG_FILE}.tmp.XXXXXX")
    {
        cat "${CONFIG_FILE}"
        cat <<EOF

# Client: ${client_name} (Created: $(date --iso-8601=seconds))
[Peer]
PublicKey = ${public_key}
PresharedKey = ${preshared_key}
AllowedIPs = ${client_ip}/32

EOF
    } > "${_tmp_server}"
    chmod 600 "${_tmp_server}"
    mv "${_tmp_server}" "${CONFIG_FILE}"

    # Create client config (umask 077 above ensures it is created mode 600)
    cat > "${CLIENTS_DIR}/${client_name}.conf" <<EOF
# WireGuard Client Configuration: ${client_name}
# Created: $(date --iso-8601=seconds)
# Server: ${server_endpoint}:${server_port}
# ClientPublicKey: ${public_key}

[Interface]
PrivateKey = ${private_key}
Address = ${client_ip}/32
DNS = ${WIREGUARD_SERVER_IP}

# Recommended: Prevent DNS leaks
# PostUp = resolvectl dns %i ${WIREGUARD_SERVER_IP}; resolvectl domain %i ~.

[Peer]
PublicKey = ${server_public_key}
PresharedKey = ${preshared_key}
Endpoint = ${server_endpoint}:${server_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

# Security: PersistentKeepalive maintains NAT mappings and detects dead peers
# AllowedIPs = 0.0.0.0/0, ::/0 routes all traffic through VPN
EOF

    chmod 600 "${CLIENTS_DIR}/${client_name}.conf"
    umask "$previous_umask"
    
    log_success "Client '${client_name}' created successfully"
    # Discard shell references once the keys have been written.
    unset private_key preshared_key
    log_info "Config file: ${CLIENTS_DIR}/${client_name}.conf"
    
    # Restart WireGuard to apply changes
    log_info "Restarting WireGuard..."
    if systemctl restart wg-quick@wg0; then
        log_success "WireGuard restarted"
    else
        log_warning "WireGuard restart failed, trying manual method..."
        wg-quick down wg0 2>/dev/null || true
        sleep 1
        wg-quick up wg0
    fi
    
    # Verify client was added
    if wg show wg0 peers | grep -Fx -- "${public_key}" >/dev/null; then
        log_success "Client successfully added to WireGuard"
    else
        log_warning "Client may not have been added correctly, check configuration"
    fi
    
    # Add hostname to hosts file for DNS resolution
    log_info "Adding hostname to DNS..."
    update_client_hostname "${client_name}" "${client_ip}" || return 1
    log_success "Hostname '${client_name}' added to DNS"
    
    # Ask to show QR code
    echo ""
    read -p "Display QR code for mobile setup? [Y/n]: " show_qr
    if [[ "${show_qr,,}" =~ ^(y|yes|)$ ]]; then
        if command -v qrencode >/dev/null 2>&1; then
            echo ""
            log_info "Scan this QR code with WireGuard mobile app:"
            echo ""
            qrencode -t ansiutf8 < "${CLIENTS_DIR}/${client_name}.conf"
            echo ""
        else
            log_warning "qrencode not installed. Install with: apt install qrencode"
        fi
    fi
    
    # Offer to show config for manual copy
    echo ""
    read -p "Display configuration for manual setup? [y/N]: " show_conf
    if [[ "${show_conf,,}" =~ ^(y|yes)$ ]]; then
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        cat "${CLIENTS_DIR}/${client_name}.conf"
        echo "════════════════════════════════════════════════════════════════"
    fi
    
    echo ""
    log_success "Client ready for use!"
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# Remove client
remove_client() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  REMOVE VPN CLIENT                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    manual_remove_client
}

manual_remove_client() {
    local clients=() conf client_name client_num confirm client_pubkey peers
    for conf in "${CLIENTS_DIR}"/*.conf; do
        [[ -f "$conf" ]] || continue
        client_name="${conf##*/}"
        clients+=("${client_name%.conf}")
    done
    if (( ${#clients[@]} == 0 )); then
        log_warning "No clients found"
        sleep 2
        show_menu
        return
    fi
    
    log_info "Available clients:"
    echo ""
    
    local i=1
    for client_name in "${clients[@]}"; do
        echo "  ${i}) ${client_name}"
        ((++i))
    done
    
    echo ""
    read -r -p "Enter client number to remove [1-${#clients[@]}] or 0 to cancel: " client_num
    
    if [[ "${client_num}" == "0" ]]; then
        show_menu
        return
    fi
    
    if [[ ! "${client_num}" =~ ^[1-9][0-9]{0,2}$ ]] || (( client_num > ${#clients[@]} )); then
        log_error "Invalid selection"
        sleep 2
        show_menu
        return
    fi
    
    client_name="${clients[$((client_num-1))]}"
    
    echo ""
    read -r -p "Remove client '${client_name}'? This cannot be undone! [y/N]: " confirm
    
    if [[ ! "${confirm,,}" =~ ^(y|yes)$ ]]; then
        log_info "Cancelled"
        sleep 1
        show_menu
        return
    fi
    
    client_pubkey=$(get_client_public_key "${CLIENTS_DIR}/${client_name}.conf") || return 1
    if ! peers=$(wg show wg0 peers); then
        log_error "Cannot inspect live WireGuard peers; no client configuration was changed"
        return 1
    fi
    remove_server_peer "${client_pubkey}" || return 1
    # Remove just this peer; restarting the interface would disconnect every client.
    if ! wg set wg0 peer "${client_pubkey}" remove; then
        log_error "Peer removed from disk, but live removal failed; restart WireGuard before considering access revoked"
        return 1
    fi
    if ! peers=$(wg show wg0 peers); then
        log_error "Cannot verify live peer removal"
        return 1
    fi
    if grep -Fxq -- "${client_pubkey}" <<< "$peers"; then
        log_error "Client is still active; access revocation failed"
        return 1
    fi

    local backup_dir="${CLIENTS_DIR}/.removed"
    if ! install -d -m 700 "${backup_dir}" ||
       ! mv "${CLIENTS_DIR}/${client_name}.conf" "${backup_dir}/${client_name}.conf.$(date +%Y%m%d_%H%M%S)"; then
        log_error "Access revoked, but client configuration could not be archived"
        return 1
    fi
    update_client_hostname "${client_name}" || return 1
    log_success "Client '${client_name}' removed successfully"
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# List all clients
list_clients() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   VPN CLIENT LIST                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [[ ! -d "${CLIENTS_DIR}" ]] || [[ -z "$(ls -A ${CLIENTS_DIR}/*.conf 2>/dev/null)" ]]; then
        log_warning "No clients found"
        echo ""
        echo "  Use option 1 to add your first VPN client"
    else
        echo -e "${COLOR_GREEN}Client Name          IP Address       Created              Status    ${COLOR_RESET}"
        echo "──────────────────────────────────────────────────────────────────────────────"
        
        for conf in "${CLIENTS_DIR}"/*.conf; do
            [[ ! -f "${conf}" ]] && continue
            
            local name=$(basename "${conf}" .conf)
            local ip=$(grep "^Address" "${conf}" | awk '{print $3}' | cut -d'/' -f1)
            local created=$(grep "# Created:" "${conf}" | cut -d' ' -f3)
            
            # Get client public key from config (stored in comment)
            local client_pubkey=$(grep "^# ClientPublicKey:" "${conf}" | awk '{print $3}')
            
            # Check if client is in server config
            local in_config="No"
            if grep -q "PublicKey = ${client_pubkey}" "${CONFIG_FILE}" 2>/dev/null; then
                in_config="Yes"
            fi
            
            # Check if client has active connection
            local status="${COLOR_YELLOW}Configured${COLOR_RESET}"
            if [[ "${in_config}" == "Yes" ]]; then
                if wg show wg0 2>/dev/null | grep -A 5 "${client_pubkey}" | grep -q "latest handshake"; then
                    local handshake_time=$(wg show wg0 peer "${client_pubkey}" latest-handshake 2>/dev/null | awk '{print $1}')
                    local current_time=$(date +%s)
                    local time_diff=$((current_time - handshake_time))
                    
                    if [[ ${time_diff} -lt 300 ]]; then  # Active within last 5 minutes
                        status="${COLOR_GREEN}Connected${COLOR_RESET}"
                    else
                        status="${COLOR_YELLOW}Idle${COLOR_RESET}"
                    fi
                else
                    status="${COLOR_BLUE}Ready${COLOR_RESET}"
                fi
            else
                status="${COLOR_RED}Not in Config${COLOR_RESET}"
            fi
            
            printf "%-20s %-16s %-20s %b\n" "${name}" "${ip:-N/A}" "${created:-N/A}" "${status}"
        done
        
        echo ""
        echo "Legend:"
        echo -e "  ${COLOR_GREEN}Connected${COLOR_RESET}      - Client actively connected"
        echo -e "  ${COLOR_YELLOW}Idle${COLOR_RESET}           - Client configured but not connected recently"
        echo -e "  ${COLOR_BLUE}Ready${COLOR_RESET}          - Client in server config, never connected"
        echo -e "  ${COLOR_RED}Not in Config${COLOR_RESET}  - Client file exists but not in server config"
    fi
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# Show client config
show_client_config() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  SHOW CLIENT CONFIG                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [[ ! -d "${CLIENTS_DIR}" ]] || [[ -z "$(ls -A ${CLIENTS_DIR})" ]]; then
        log_warning "No clients found"
        sleep 2
        show_menu
        return
    fi
    
    log_info "Available clients:"
    echo ""
    
    local clients=()
    local i=1
    for conf in "${CLIENTS_DIR}"/*.conf; do
        local name=$(basename "${conf}" .conf)
        echo "  ${i}) ${name}"
        clients+=("${name}")
        ((++i))
    done
    
    echo ""
    read -p "Enter client number [1-${#clients[@]}] or 0 to cancel: " client_num
    
    if [[ "${client_num}" == "0" ]]; then
        show_menu
        return
    fi
    
    if [[ ! "${client_num}" =~ ^[0-9]+$ ]] || [[ "${client_num}" -lt 1 ]] || [[ "${client_num}" -gt "${#clients[@]}" ]]; then
        log_error "Invalid selection"
        sleep 2
        show_menu
        return
    fi
    
    local client_name="${clients[$((client_num-1))]}"
    
    echo ""
    echo "Configuration for '${client_name}':"

    echo "════════════════════════════════════════════════════════════════"
    cat "${CLIENTS_DIR}/${client_name}.conf"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "Config file location: ${CLIENTS_DIR}/${client_name}.conf"
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# Show QR code
show_qr_code() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   SHOW QR CODE                               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    if ! command -v qrencode >/dev/null 2>&1; then
        log_error "qrencode not installed. Install with: sudo apt install qrencode"
        sleep 3
        show_menu
        return
    fi
    
    if [[ ! -d "${CLIENTS_DIR}" ]] || [[ -z "$(ls -A ${CLIENTS_DIR})" ]]; then
        log_warning "No clients found"
        sleep 2
        show_menu
        return
    fi
    
    log_info "Available clients:"
    echo ""
    
    local clients=()
    local i=1
    for conf in "${CLIENTS_DIR}"/*.conf; do
        local name=$(basename "${conf}" .conf)
        echo "  ${i}) ${name}"
        clients+=("${name}")
        ((++i))
    done
    
    echo ""
    read -p "Enter client number [1-${#clients[@]}] or 0 to cancel: " client_num
    
    if [[ "${client_num}" == "0" ]]; then
        show_menu
        return
    fi
    
    if [[ ! "${client_num}" =~ ^[0-9]+$ ]] || [[ "${client_num}" -lt 1 ]] || [[ "${client_num}" -gt "${#clients[@]}" ]]; then
        log_error "Invalid selection"
        sleep 2
        show_menu
        return
    fi
    
    local client_name="${clients[$((client_num-1))]}"
    
    echo ""
    echo "QR Code for '${client_name}':"
    echo ""
    qrencode -t ansiutf8 < "${CLIENTS_DIR}/${client_name}.conf"
    echo ""
    log_info "Scan this QR code with WireGuard mobile app"
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# Revoke client (same as remove)
revoke_client() {
    remove_client
}

# Show statistics
show_statistics() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  VPN STATISTICS                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    if ! wg show wg0 >/dev/null 2>&1; then
        log_error "WireGuard interface wg0 not active"
        echo ""
        read -p "Press Enter to return to menu..."
        show_menu
        return
    fi
    
    wg show wg0
    
    echo ""
    echo "Active Connections:"
    echo "────────────────────────────────────────────────────────────"
    
    local peer_count=$(wg show wg0 peers | wc -l)
    echo "Total Peers: ${peer_count}"
    
    if [[ ${peer_count} -gt 0 ]]; then
        echo ""
        while IFS= read -r peer; do
            local endpoint=$(wg show wg0 peer "${peer}" endpoint 2>/dev/null || echo "N/A")
            local transfer=$(wg show wg0 peer "${peer}" transfer 2>/dev/null || echo "N/A")
            local handshake=$(wg show wg0 peer "${peer}" latest-handshake 2>/dev/null || echo "Never")
            
            echo "Peer: ${peer:0:16}..."
            echo "  Endpoint: ${endpoint}"
            echo "  Transfer: ${transfer}"
            echo "  Last Handshake: ${handshake}"
            echo ""
        done < <(wg show wg0 peers)
    fi
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# Restart WireGuard
restart_wireguard() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 RESTART WIREGUARD                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    read -p "Restart WireGuard service? This will disconnect all clients briefly. [y/N]: " confirm
    
    if [[ ! "${confirm,,}" =~ ^(y|yes)$ ]]; then
        log_info "Cancelled"
        sleep 1
        show_menu
        return
    fi
    
    log_info "Restarting WireGuard..."
    
    # Try systemd first (preferred method)
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        if systemctl restart wg-quick@wg0; then
            log_success "WireGuard restarted successfully (systemd)"
        else
            log_warning "Systemd restart failed, trying manual method..."
            wg-quick down wg0 2>/dev/null || true
            sleep 1
            if wg-quick up wg0; then
                log_success "WireGuard restarted successfully (manual)"
            else
                log_error "Failed to restart WireGuard"
            fi
        fi
    else
        # Manual restart if systemd not managing it
        wg-quick down wg0 2>/dev/null || true
        sleep 1
        if wg-quick up wg0; then
            log_success "WireGuard restarted successfully"
        else
            log_error "Failed to restart WireGuard"
        fi
    fi
    
    # Verify WireGuard is running
    if wg show wg0 >/dev/null 2>&1; then
        log_success "WireGuard interface wg0 is active"
        echo ""
        echo "Active peers: $(wg show wg0 peers | wc -l)"
    else
        log_error "WireGuard interface wg0 is not active!"
    fi
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

# Backup configurations
backup_configs() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  BACKUP CONFIGURATIONS                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    local backup_dir="/root/wireguard-backup-$(date +%Y-%m-%d_%H-%M-%S)"
    
    log_info "Creating backup at: ${backup_dir}"
    
    # umask 077 ensures the staging dir, copied files, and final tarball are
    # all created mode 600/700 (owner-only). The backup contains every
    # client's PrivateKey/PresharedKey — it must NEVER be world-readable.
    umask 077
    mkdir -p "${backup_dir}"
    chmod 700 "${backup_dir}"
    
    # Backup server config
    if [[ -f "${CONFIG_FILE}" ]]; then
        cp "${CONFIG_FILE}" "${backup_dir}/"
        log_success "Backed up server configuration"
    fi
    
    # Backup client configs
    if [[ -d "${CLIENTS_DIR}" ]]; then
        cp -r "${CLIENTS_DIR}" "${backup_dir}/"
        log_success "Backed up client configurations"
    fi
    
    # Backup hosts file
    if [[ -f "${WIREGUARD_HOSTS}" ]]; then
        cp "${WIREGUARD_HOSTS}" "${backup_dir}/"
        log_success "Backed up hosts file"
    fi
    
    # Create archive (quote dirname/basename arguments defensively)
    tar -czf "${backup_dir}.tar.gz" -C "$(dirname "${backup_dir}")" "$(basename "${backup_dir}")"
    chmod 600 "${backup_dir}.tar.gz"
    rm -rf "${backup_dir}"
    umask 022
    
    log_success "Backup created: ${backup_dir}.tar.gz (mode 600)"
    
    echo ""
    read -p "Press Enter to return to menu..."
    show_menu
}

show_file_locations() {
    show_header
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    FILE LOCATIONS                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo -e "${COLOR_BLUE}Server Configuration:${COLOR_RESET}"
    echo "  Server Config:     ${CONFIG_FILE}"
    if [[ -f "${CONFIG_FILE}" ]]; then
        echo -e "                     ${COLOR_GREEN}✓ EXISTS${COLOR_RESET}"
    else
        echo -e "                     ${COLOR_RED}✗ MISSING${COLOR_RESET}"
    fi
    echo ""
    
    echo -e "${COLOR_BLUE}Client Configurations:${COLOR_RESET}"
    echo "  Client Directory:  ${CLIENTS_DIR}"
    if [[ -d "${CLIENTS_DIR}" ]]; then
        local client_count=$(ls -1 "${CLIENTS_DIR}"/*.conf 2>/dev/null | wc -l)
        echo -e "                     ${COLOR_GREEN}✓ EXISTS (${client_count} clients)${COLOR_RESET}"
    else
        echo -e "                     ${COLOR_RED}✗ MISSING${COLOR_RESET}"
    fi
    echo ""
    
    echo -e "${COLOR_BLUE}DNS/Hostname Resolution:${COLOR_RESET}"
    echo "  Hosts File:        ${WIREGUARD_HOSTS}"
    if [[ -f "${WIREGUARD_HOSTS}" ]]; then
        local host_count
        host_count=$(awk 'NF && $0 !~ /^#/ { count++ } END { print count+0 }' "${WIREGUARD_HOSTS}")
        echo -e "                     ${COLOR_GREEN}✓ EXISTS (${host_count} entries)${COLOR_RESET}"
    else
        echo -e "                     ${COLOR_RED}✗ MISSING${COLOR_RESET}"
    fi
    echo "  Dnsmasq Config:    /etc/dnsmasq.d/02-pihole-wireguard.conf"
    if [[ -f "/etc/dnsmasq.d/02-pihole-wireguard.conf" ]]; then
        echo -e "                     ${COLOR_GREEN}✓ EXISTS${COLOR_RESET}"
    else
        echo -e "                     ${COLOR_RED}✗ MISSING${COLOR_RESET}"
    fi
    echo ""
    
    echo -e "${COLOR_BLUE}Keys:${COLOR_RESET}"
    echo "  Server Public Key: ${WIREGUARD_DIR}/server-public.key"
    if [[ -f "${WIREGUARD_DIR}/server-public.key" ]]; then
        echo -e "                     ${COLOR_GREEN}✓ EXISTS${COLOR_RESET}"
    else
        echo -e "                     ${COLOR_YELLOW}⚠ MISSING (extracted from config)${COLOR_RESET}"
    fi
    echo ""
    
    echo -e "${COLOR_BLUE}Backups:${COLOR_RESET}"
    echo "  Removed Clients:   ${CLIENTS_DIR}/.removed"
    if [[ -d "${CLIENTS_DIR}/.removed" ]]; then
        local removed_count=$(ls -1 "${CLIENTS_DIR}/.removed" 2>/dev/null | wc -l)
        echo -e "                     ${COLOR_GREEN}✓ EXISTS (${removed_count} backups)${COLOR_RESET}"
    else
        echo -e "                     ${COLOR_YELLOW}⚠ NO BACKUPS${COLOR_RESET}"
    fi
    echo ""
    
    echo -e "${COLOR_BLUE}Quick Access Commands:${COLOR_RESET}"
    echo "  View server config:   cat ${CONFIG_FILE}"
    echo "  List client files:    ls -lh ${CLIENTS_DIR}"
    echo "  View hosts file:      cat ${WIREGUARD_HOSTS}"
    echo "  View dnsmasq config:  cat /etc/dnsmasq.d/02-pihole-wireguard.conf"
    echo ""
    
    read -p "Press Enter to return to menu..."
    show_menu
}

# Main execution
main() {
    check_root
    check_wireguard
    prepare_wireguard_dns || log_warning "DNS setup failed; VPN management remains available, but hostname updates may fail"
    show_menu
}

main "$@"
