#!/bin/bash
#
# Pi-hole + VPN Installer
# File: install-pihole-vpn.sh
# Created: 2025-12-07
# Last Modified: 2025-12-07
# Version: 1.0.0
#
# Description: Automated installer for Pi-hole with WireGuard VPN
#              Supports Raspberry Pi and Ubuntu Server (Azure)
#              Uses Unbound as recursive DNS resolver for maximum privacy
#              Includes SSH hardening and optional MFA (Google Authenticator)
#
# Security Features:
# - AllowUsers SSH restriction (auto-detects real user via SUDO_USER)
# - Optional Multi-Factor Authentication with google-authenticator
# - Progressive Fail2Ban banning (25min → 7day → permanent)
# - All cron jobs run as root (system-level maintenance)
#
# Following Universal Constants:
# - UC-001: Code clarity over cleverness
# - UC-002: Meaningful naming conventions
# - UC-003: ISO 8601 date format
# - UC-004: Professional communication
#
# Usage: sudo bash install-pihole-vpn.sh [OPTIONS]
#        Options: --debug, --config=FILE, --repair
#

# Note: Using 'set -eu' instead of 'set -euo pipefail' to allow interactive
# prompts when script is piped from curl (one-line installation)
set -eu

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/installer.conf"
DEBUG_MODE=false
LOG_FILE="/var/log/pihole-vpn-install.log"

# Color codes for output
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# Installation paths (from Deployment.sh structure)
readonly PATH_SCRIPTS="/scripts"
readonly PATH_TEMP="/scripts/temp"
readonly PATH_FINISHED="/scripts/Finished"
readonly PATH_CONFIG="/scripts/Finished/CONFIG"
readonly PATH_PIHOLE="/etc/pihole"

# GitHub repository base URLs
readonly GITHUB_REPO="https://github.com/IcedComputer/Personal_Contained_Pihole"
readonly GITHUB_RAW="https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole"
readonly GITHUB_RAW_MASTER="${GITHUB_RAW}/master"
readonly GITHUB_RAW_MAIN="${GITHUB_RAW}/main"

# WireGuard paths
readonly WIREGUARD_DIR="/etc/wireguard"
readonly WIREGUARD_CONFIG="${WIREGUARD_DIR}/wg0.conf"
readonly CLIENTS_DIR="${WIREGUARD_DIR}/clients"
readonly WIREGUARD_SERVER_NETWORK="10.7.0"
readonly WIREGUARD_SERVER_IP="${WIREGUARD_SERVER_NETWORK}.1"
readonly WIREGUARD_CIDR="24"

# Warning tracking
declare -a WARNINGS=()
declare -a ERRORS=()

# Installation state
PLATFORM=""              # "azure", "rpi", or "other"
SERVER_TYPE=""           # "full", "security", etc.
DNS_TYPE="unbound"       # Always use unbound (local recursive DNS)
INSTALL_VPN=""           # "yes" or "no"
WIREGUARD_PORT=""        # Default 51820
PIHOLE_VERSION="6"       # Always install latest (v6)
DETECTED_IPV4=""
STATIC_IPV4=""
REAL_USER=""             # Actual user (not root) who ran sudo
ENABLE_MFA=""            # "yes" or "no" for 2FA setup
REPAIR_MODE=false        # If true, skip completed steps
STATE_FILE="/var/log/pihole-vpn-install.state"  # Track completed steps

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log() {
    local message="$1"
    echo "$(date --iso-8601=seconds) - ${message}" | tee -a "${LOG_FILE}"
}

log_success() {
    local message="$1"
    echo -e "${COLOR_GREEN}✓${COLOR_RESET} ${message}" | tee -a "${LOG_FILE}"
}

log_error() {
    local message="$1"
    echo -e "${COLOR_RED}✗ ERROR: ${message}${COLOR_RESET}" | tee -a "${LOG_FILE}"
    ERRORS+=("${message}")
}

log_warning() {
    local message="$1"
    echo -e "${COLOR_YELLOW}⚠ WARNING: ${message}${COLOR_RESET}" | tee -a "${LOG_FILE}"
    WARNINGS+=("${message}")
    sleep 2  # Give user moment to read
}

log_info() {
    local message="$1"
    echo -e "${COLOR_BLUE}ℹ${COLOR_RESET} ${message}" | tee -a "${LOG_FILE}"
}

debug_log() {
    if [[ "${DEBUG_MODE}" == true ]]; then
        echo -e "${COLOR_BLUE}[DEBUG]${COLOR_RESET} $1" | tee -a "${LOG_FILE}"
    fi
}

wait_for_user() {
    # Prompt user to confirm a step is complete before proceeding
    local step_name="$1"
    local prompt_message="${2:-Is ${step_name} complete?}"
    
    echo ""
    echo -e "${COLOR_YELLOW}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}║                    CONFIRMATION REQUIRED                      ║${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_BLUE}Step completed:${COLOR_RESET} ${step_name}"
    echo ""
    
    while true; do
        read -p "${prompt_message} [y/n]: " confirm
        case ${confirm,,} in
            y|yes)
                log_success "${step_name} confirmed complete"
                echo ""
                return 0
                ;;
            n|no)
                echo ""
                log_warning "User indicated ${step_name} is NOT complete"
                echo "Please complete the step manually, then try again."
                echo "You may need to troubleshoot before continuing."
                echo ""
                read -p "Try again? [y] or abort installation? [n]: " retry
                case ${retry,,} in
                    y|yes|"")
                        continue
                        ;;
                    *)
                        log_error "Installation aborted by user at: ${step_name}"
                        exit 1
                        ;;
                esac
                ;;
            *)
                echo "Please enter 'y' or 'n'"
                ;;
        esac
    done
}

mark_step_complete() {
    local step="$1"
    echo "${step}" >> "${STATE_FILE}"
    debug_log "Marked step complete: ${step}"
}

is_step_complete() {
    local step="$1"
    [[ -f "${STATE_FILE}" ]] && grep -q "^${step}$" "${STATE_FILE}" 2>/dev/null
}

skip_if_complete() {
    local step="$1"
    local description="$2"
    
    if [[ "${REPAIR_MODE}" == true ]] && is_step_complete "${step}"; then
        log_info "Skipping ${description} (already completed)"
        return 0  # Skip this step
    fi
    return 1  # Don't skip
}

show_header() {
    clear
    echo -e "${COLOR_BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         Pi-hole + WireGuard VPN Installer v${VERSION}         ║"
    echo "║                                                              ║"
    echo "║  Automated setup for Pi-hole with WireGuard VPN              ║"
    echo "║  Supports: Raspberry Pi, Ubuntu Server, Azure                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}\n"
}

show_summary_report() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  INSTALLATION SUMMARY                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        echo -e "${COLOR_RED}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
        echo -e "${COLOR_RED}║                    ERRORS ENCOUNTERED                        ║${COLOR_RESET}"
        echo -e "${COLOR_RED}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
        for error in "${ERRORS[@]}"; do
            echo -e "${COLOR_RED}  ✗ ${error}${COLOR_RESET}"
        done
        echo ""
    fi
    
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        echo -e "${COLOR_YELLOW}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}║                   WARNINGS REPORTED                          ║${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
        for warning in "${WARNINGS[@]}"; do
            echo -e "${COLOR_YELLOW}  ⚠ ${warning}${COLOR_RESET}"
        done
        echo ""
    fi
    
    if [[ ${#ERRORS[@]} -eq 0 ]] && [[ ${#WARNINGS[@]} -eq 0 ]]; then
        echo -e "${COLOR_GREEN}✓ Installation completed successfully with no issues!${COLOR_RESET}"
        echo ""
    elif [[ ${#ERRORS[@]} -gt 0 ]]; then
        echo -e "${COLOR_YELLOW}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}║                   REPAIR MODE AVAILABLE                      ║${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_YELLOW}To resume/repair the installation, run:${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}  sudo bash install-pihole-vpn.sh --repair${COLOR_RESET}"
        echo ""
        echo "This will skip completed steps and retry failed ones."
        echo ""
    fi
    
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    IMPORTANT NOTES                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  • All cron jobs run as root (system maintenance)"
    echo "  • SSH access restricted to user: ${REAL_USER}"
    
    if [[ "${ENABLE_MFA}" == "yes" ]]; then
        echo "  • MFA setup required: Run as ${REAL_USER}:"
        echo "      sudo -u ${REAL_USER} google-authenticator"
    fi
    
    if [[ "${INSTALL_VPN}" == "yes" ]]; then
        echo "  • Add VPN clients: ${PATH_FINISHED}/wireguard-manager.sh"
    fi
    
    echo ""
    log_info "Full installation log: ${LOG_FILE}"
    
    if [[ ${#ERRORS[@]} -eq 0 ]]; then
        log_info "Installation state file removed (successful completion)"
    else
        log_info "Installation state saved to: ${STATE_FILE}"
    fi
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_real_user() {
    # Detect the actual user who ran sudo (not root)
    if [[ -n "${SUDO_USER}" ]]; then
        REAL_USER="${SUDO_USER}"
    elif [[ -n "${LOGNAME}" ]] && [[ "${LOGNAME}" != "root" ]]; then
        REAL_USER="${LOGNAME}"
    else
        # Fallback: ask user
        read -p "Enter your username (not root): " REAL_USER
        if [[ -z "${REAL_USER}" ]] || [[ "${REAL_USER}" == "root" ]]; then
            log_error "Valid non-root username required"
            exit 1
        fi
    fi
    
    # Verify user exists
    if ! id "${REAL_USER}" >/dev/null 2>&1; then
        log_error "User '${REAL_USER}' does not exist"
        exit 1
    fi
    
    log_info "Detected user: ${REAL_USER}"
}

detect_platform() {
    debug_log "Detecting platform..."
    
    # Check for Raspberry Pi FIRST (faster, more reliable than network-based Azure check)
    if [[ -f /proc/device-tree/model ]] && grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
        PLATFORM="rpi"
        log_success "Detected platform: Raspberry Pi"
        return 0
    fi
    
    # Check architecture for ARM-based systems (Raspberry Pi variants)
    local arch=$(uname -m)
    if [[ "$arch" == "aarch64" ]] || [[ "$arch" == "armv7l" ]]; then
        # Additional check for Debian-based RPi OS
        if grep -qi "raspbian\|raspberry" /etc/os-release 2>/dev/null; then
            PLATFORM="rpi"
            log_success "Detected platform: Raspberry Pi (from os-release)"
            return 0
        fi
        # Check for common RPi identifiers
        if [[ -f /sys/firmware/devicetree/base/model ]]; then
            local model=$(cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0' || true)
            if [[ "$model" == *"Raspberry"* ]]; then
                PLATFORM="rpi"
                log_success "Detected platform: Raspberry Pi ($model)"
                return 0
            fi
        fi
    fi
    
    # Check for Azure metadata service (with strict timeout to prevent hanging)
    # Use --connect-timeout and --max-time to prevent indefinite hangs
    if curl -s --connect-timeout 2 --max-time 3 -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1; then
        PLATFORM="azure"
        log_success "Detected platform: Azure Ubuntu Server"
        return 0
    fi
    
    # For ARM architecture without RPi identifiers, assume RPi-like environment
    if [[ "$arch" == "aarch64" ]] || [[ "$arch" == "armv7l" ]]; then
        PLATFORM="rpi"
        log_warning "ARM architecture detected, assuming Raspberry Pi-like environment"
        return 0
    fi
    
    # Unknown platform
    PLATFORM="other"
    log_warning "Could not auto-detect platform (Azure or RPi)"
    
    # Prompt user
    echo ""
    echo "Select your platform:"
    echo "1) Ubuntu Server (Azure or other cloud)"
    echo "2) Raspberry Pi"
    echo "3) Other Linux system"
    read -p "Enter choice [1-3]: " choice
    
    case $choice in
        1) PLATFORM="azure" ;;
        2) PLATFORM="rpi" ;;
        3) PLATFORM="other" ;;
        *) 
            log_error "Invalid choice"
            exit 1
            ;;
    esac
    
    log_success "Platform set to: ${PLATFORM}"
}

detect_network() {
    debug_log "Detecting network configuration..."
    
    # Detect primary network interface
    local interface=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++)if($i~/dev/)print $(i+1)}')
    DETECTED_IPV4=$(ip route get 8.8.8.8 | awk '{print $7}')
    local gateway=$(ip route get 8.8.8.8 | awk '{print $3}')
    
    debug_log "Interface: ${interface}"
    debug_log "Detected IPv4: ${DETECTED_IPV4}"
    debug_log "Gateway: ${gateway}"
    
    if [[ -z "${DETECTED_IPV4}" ]]; then
        log_error "Could not detect IPv4 address"
        return 1
    fi
    
    log_success "Detected IPv4: ${DETECTED_IPV4}"
}

validate_ip() {
    local ip=$1
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    if [[ $ip =~ $valid_ip_regex ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# CONFIGURATION FUNCTIONS
# ============================================================================

load_config_file() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        debug_log "No config file found at ${CONFIG_FILE}"
        return 1
    fi
    
    log_info "Loading configuration from ${CONFIG_FILE}..."
    
    # Source the config file
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
    
    # Validate required variables
    local config_valid=true
    
    [[ -z "${SERVER_TYPE:-}" ]] && config_valid=false
    [[ -z "${DNS_TYPE:-}" ]] && config_valid=false
    [[ -z "${INSTALL_VPN:-}" ]] && config_valid=false
    
    if [[ "${config_valid}" == false ]]; then
        log_warning "Config file incomplete or invalid"
        return 1
    fi
    
    # Set defaults for optional variables
    WIREGUARD_PORT="${WIREGUARD_PORT:-51820}"
    STATIC_IPV4="${STATIC_IPV4:-${DETECTED_IPV4}}"
    ENABLE_MFA="${ENABLE_MFA:-no}"
    
    log_success "Configuration loaded successfully"
    return 0
}

show_config_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               DETECTED CONFIGURATION                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Platform:          ${PLATFORM}"
    echo "  Server Type:       ${SERVER_TYPE}"
    echo "  DNS Provider:      ${DNS_TYPE}"
    echo "  Install VPN:       ${INSTALL_VPN}"
    echo "  WireGuard Port:    ${WIREGUARD_PORT}"
    echo "  Static IPv4:       ${STATIC_IPV4}"
    echo ""
}

prompt_configuration() {
    log_info "Starting interactive configuration..."
    
    # Server Type
    echo ""
    echo "Select Pi-hole configuration profile:"
    echo "1) Full (all lists - maximum protection)"
    echo "2) Security (security-focused lists only)"
    echo "3) Basic (minimal lists)"
    read -p "Enter choice [1-3]: " type_choice
    
    case $type_choice in
        1) SERVER_TYPE="full" ;;
        2) SERVER_TYPE="security" ;;
        3) SERVER_TYPE="basic" ;;
        *) 
            log_error "Invalid choice, defaulting to 'full'"
            SERVER_TYPE="full"
            ;;
    esac
    log_success "Server type: ${SERVER_TYPE}"
    
    # DNS Provider - Always Unbound (local recursive DNS, most private)
    DNS_TYPE="unbound"
    log_success "DNS provider: unbound (local recursive resolver)"
    
    # VPN Installation - Default depends on platform
    echo ""
    if [[ "${PLATFORM}" == "rpi" ]]; then
        # Raspberry Pi: Default to NO VPN (resource-constrained, typically home use)
        read -p "Install WireGuard VPN? [y/N]: " vpn_choice
        case ${vpn_choice,,} in
            y|yes) INSTALL_VPN="yes" ;;
            n|no|"") INSTALL_VPN="no" ;;
            *)
                log_info "Invalid choice, defaulting to 'no' for Raspberry Pi"
                INSTALL_VPN="no"
                ;;
        esac
    else
        # Azure/Cloud: Default to YES VPN (typical use case for remote access)
        read -p "Install WireGuard VPN? [Y/n]: " vpn_choice
        case ${vpn_choice,,} in
            y|yes|"") INSTALL_VPN="yes" ;;
            n|no) INSTALL_VPN="no" ;;
            *)
                log_error "Invalid choice, defaulting to 'yes'"
                INSTALL_VPN="yes"
                ;;
        esac
    fi
    log_success "VPN installation: ${INSTALL_VPN}"
    
    # WireGuard Port (set default even if not installing VPN, for config display)
    WIREGUARD_PORT="51820"
    
    if [[ "${INSTALL_VPN}" == "yes" ]]; then
        echo ""
        read -p "WireGuard port [51820]: " wg_port
        WIREGUARD_PORT="${wg_port:-51820}"
        
        if ! [[ "${WIREGUARD_PORT}" =~ ^[0-9]+$ ]] || [[ "${WIREGUARD_PORT}" -lt 1024 ]] || [[ "${WIREGUARD_PORT}" -gt 65535 ]]; then
            log_warning "Invalid port, using default 51820"
            WIREGUARD_PORT="51820"
        fi
        log_success "WireGuard port: ${WIREGUARD_PORT}"
    fi
    
    # Static IP
    echo ""
    echo "Detected IP address: ${DETECTED_IPV4}"
    read -p "Use this IP as static? [Y/n] or enter different IP: " ip_choice
    
    case ${ip_choice,,} in
        y|yes|"")
            STATIC_IPV4="${DETECTED_IPV4}"
            ;;
        *)
            if validate_ip "${ip_choice}"; then
                STATIC_IPV4="${ip_choice}"
            else
                log_warning "Invalid IP format, using detected IP"
                STATIC_IPV4="${DETECTED_IPV4}"
            fi
            ;;
    esac
    log_success "Static IPv4: ${STATIC_IPV4}"
    
    # Multi-Factor Authentication
    echo ""
    read -p "Enable Multi-Factor Authentication (Google Authenticator) for SSH? [y/N]: " mfa_choice
    case ${mfa_choice,,} in
        y|yes) ENABLE_MFA="yes" ;;
        *) ENABLE_MFA="no" ;;
    esac
    log_success "MFA enabled: ${ENABLE_MFA}"
}

confirm_proceed() {
    show_config_summary
    
    echo ""
    read -p "Proceed with installation using these settings? [Y/n]: " confirm
    
    case ${confirm,,} in
        y|yes|"")
            log_success "Configuration confirmed, proceeding with installation"
            return 0
            ;;
        *)
            log_info "Installation cancelled by user"
            exit 0
            ;;
    esac
}

# ============================================================================
# SYSTEM PREPARATION
# ============================================================================

create_directories() {
    log_info "Creating directory structure..."
    
    mkdir -p "${PATH_SCRIPTS}"
    mkdir -p "${PATH_TEMP}"
    mkdir -p "${PATH_FINISHED}"
    mkdir -p "${PATH_CONFIG}"
    mkdir -p "${PATH_CONFIG}/lists"
    
    chmod 755 "${PATH_SCRIPTS}"
    chmod 755 "${PATH_TEMP}"
    chmod 755 "${PATH_FINISHED}"
    chmod 755 "${PATH_CONFIG}"  # Changed to 755 so updates.sh can read config files
    chmod 755 "${PATH_CONFIG}/lists"  # Writable for updates.sh to deploy list files
    
    log_success "Directories created"
}

create_config_files() {
    log_info "Creating configuration files for update scripts..."
    
    # Create type.conf (server type: full, security, basic)
    echo "${SERVER_TYPE}" > "${PATH_CONFIG}/type.conf"
    chmod 644 "${PATH_CONFIG}/type.conf"
    
    # Create dns_type.conf (dns provider: 'unbound')
    echo "${DNS_TYPE}" > "${PATH_CONFIG}/dns_type.conf"
    chmod 644 "${PATH_CONFIG}/dns_type.conf"
    
    # Create test.conf (test mode: 'no' = production, 'yes' = test)
    echo "no" > "${PATH_CONFIG}/test.conf"
    chmod 644 "${PATH_CONFIG}/test.conf"
    
    log_success "Configuration files created"
    debug_log "type.conf: ${SERVER_TYPE}"
    debug_log "dns_type.conf: ${DNS_TYPE}"
    debug_log "test.conf: no (production)"
}

system_update() {
    log_info "Updating system packages..."
    
    apt-get update || {
        log_warning "apt-get update failed, continuing anyway"
    }
    
    apt-get dist-upgrade -y || {
        log_warning "dist-upgrade had issues, continuing anyway"
    }
    
    apt-get autoremove -y || {
        log_warning "autoremove had issues, continuing anyway"
    }
    
    log_success "System updated"
}

install_dependencies() {
    log_info "Installing required dependencies..."
    
    local packages=(
        "curl"
        "wget"
        "git"
        "sqlite3"
        "vim"
        "gnupg"
        "unattended-upgrades"
        "fail2ban"
        "whiptail"
        "qrencode"
    )
    
    for package in "${packages[@]}"; do
        if ! apt-get install -y --no-install-recommends "${package}"; then
            log_warning "Failed to install ${package}, may cause issues later"
        else
            log_success "Installed ${package}"
        fi
    done
}

# ============================================================================
# GPG KEY MANAGEMENT
# ============================================================================

generate_gpg_key() {
    log_info "Generating GPG key for this server..."
    
    local hostname=$(hostname)
    local key_name="Pi-hole Server ${hostname}"
    
    # Generate key non-interactively
    cat > "${PATH_TEMP}/gpg-gen-key.conf" <<EOF
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: ${key_name}
Expire-Date: 2y
%no-protection
%commit
EOF

    debug_log "Generating GPG key with config:"
    debug_log "$(cat ${PATH_TEMP}/gpg-gen-key.conf)"
    
    if gpg --batch --generate-key "${PATH_TEMP}/gpg-gen-key.conf" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "GPG key generated successfully"
        
        # Export public key
        local key_id=$(gpg --list-keys --with-colons | grep "^fpr" | head -n1 | cut -d: -f10)
        local export_path="${PATH_FINISHED}/server-public-key.gpg"
        
        if gpg --armor --export "${key_id}" > "${export_path}"; then
            log_success "Public key exported to: ${export_path}"
            echo ""
            echo -e "${COLOR_GREEN}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
            echo -e "${COLOR_GREEN}║           GPG PUBLIC KEY EXPORTED                            ║${COLOR_RESET}"
            echo -e "${COLOR_GREEN}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
            echo ""
            echo "Your server's public GPG key has been exported to:"
            echo "  ${export_path}"
            echo ""
            echo "Share this public key with anyone who needs to encrypt files"
            echo "for this server."
            echo ""
            sleep 3
        else
            log_warning "Failed to export public key"
        fi
    else
        log_error "Failed to generate GPG key"
        return 1
    fi
    
    rm -f "${PATH_TEMP}/gpg-gen-key.conf"
}

download_public_gpg_keys() {
    log_info "Downloading public GPG keys from repository..."
    
    local github_key_dir="${GITHUB_RAW_MAIN}/installer/public-gpg-keys"
    local dest_dir="${PATH_CONFIG}/public-gpg-keys"
    
    # Create destination directory
    mkdir -p "${dest_dir}"
    
    # Try to get list of key files from GitHub
    log_info "Fetching key list from repository..."
    
    # Download using the GitHub API to list files
    local api_url="https://api.github.com/repos/IcedComputer/Personal_Contained_Pihole/contents/installer/public-gpg-keys"
    
    local key_files=$(curl -s "${api_url}" | grep -oP '"name":\s*"\K[^"]+\.(?:gpg|asc|key)' || true)
    
    if [[ -z "${key_files}" ]]; then
        log_info "No GPG keys found in repository, skipping download"
        return 0
    fi
    
    # Download each key file
    local downloaded=0
    local failed=0
    
    while IFS= read -r key_file; do
        if [[ -n "${key_file}" ]]; then
            local download_url="${github_key_dir}/${key_file}"
            local dest_path="${dest_dir}/${key_file}"
            
            log_info "Downloading: ${key_file}"
            
            if curl -sSL -o "${dest_path}" "${download_url}"; then
                ((downloaded++))
                log_success "Downloaded: ${key_file}"
            else
                ((failed++))
                log_warning "Failed to download: ${key_file}"
            fi
        fi
    done <<< "${key_files}"
    
    log_info "Downloaded ${downloaded} GPG key(s) to ${dest_dir}"
    
    if [[ ${failed} -gt 0 ]]; then
        log_warning "${failed} key download(s) failed"
    fi
    
    return 0
}

import_gpg_keys() {
    log_info "Auto-importing GPG public keys..."
    
    local keys_dir="${PATH_CONFIG}/public-gpg-keys"
    local imported_count=0
    local failed_count=0
    
    # Check if directory exists
    if [[ ! -d "${keys_dir}" ]]; then
        log_warning "GPG keys directory not found: ${keys_dir}"
        log_warning "No public keys available for import"
        return 0
    fi
    
    # Find all .gpg files
    local key_files=("${keys_dir}"/*.gpg)
    
    # Check if any keys exist
    if [[ ! -e "${key_files[0]}" ]]; then
        log_warning "No GPG key files found in ${keys_dir}"
        log_warning "To add keys, place .gpg files in: ${keys_dir}"
        log_info "Installation will continue, but encrypted lists will fail to decrypt"
        return 0
    fi
    
    log_info "Found ${#key_files[@]} key file(s) to import"
    
    # Import each key
    for key_file in "${key_files[@]}"; do
        local key_name=$(basename "${key_file}")
        log_info "Importing: ${key_name}"
        
        if gpg --import "${key_file}" 2>&1 | tee -a "${LOG_FILE}"; then
            log_success "Imported: ${key_name}"
            ((imported_count++))
        else
            log_error "Failed to import: ${key_name}"
            ((failed_count++))
        fi
    done
    
    # Summary
    echo ""
    log_info "GPG Key Import Summary:"
    log_info "  Successfully imported: ${imported_count}"
    if [[ ${failed_count} -gt 0 ]]; then
        log_warning "  Failed imports: ${failed_count}"
    fi
    
    # List imported keys
    echo ""
    log_info "Currently imported GPG keys:"
    gpg --list-keys 2>&1 | tee -a "${LOG_FILE}"
    echo ""
    sleep 2
}

# ============================================================================
# PI-HOLE INSTALLATION
# ============================================================================

install_pihole() {
    log_info "Installing Pi-hole..."
    
    # Set environment for unattended install
    export PIHOLE_SKIP_OS_CHECK=true
    
    # Download and run installer
    if [[ "${PLATFORM}" == "rpi" ]] && [[ -f /etc/debian_version ]]; then
        curl --tlsv1.3 -sSL https://install.pi-hole.net | PIHOLE_SKIP_OS_CHECK=true bash | tee -a "${LOG_FILE}"
    else
        curl --tlsv1.3 -sSL https://install.pi-hole.net | bash | tee -a "${LOG_FILE}"
    fi
    
    if [[ $? -eq 0 ]]; then
        log_success "Pi-hole installed successfully"
    else
        log_error "Pi-hole installation failed"
        return 1
    fi
}

# ============================================================================
# DNS PROVIDER INSTALLATION
# ============================================================================

install_unbound() {
    log_info "Installing Unbound recursive DNS resolver..."
    
    # Download initial root hints BEFORE installing Unbound (required for startup)
    log_info "Downloading DNS root hints (required for Unbound startup)..."
    mkdir -p /var/lib/unbound
    if curl --tlsv1.3 -o "${PATH_TEMP}/root.hints" https://www.internic.net/domain/named.root; then
        mv "${PATH_TEMP}/root.hints" /var/lib/unbound/root.hints
        chmod 644 /var/lib/unbound/root.hints
        log_success "Downloaded and installed root hints"
    else
        log_error "Failed to download root hints - Unbound will not start without this file"
        return 1
    fi
    
    if ! apt-get install -y unbound; then
        log_error "Failed to install unbound"
        return 1
    fi
    
    log_success "Unbound installed"
    
    # Fix ownership after package installation (unbound user now exists)
    chown unbound:unbound /var/lib/unbound/root.hints
    
    # Generate Unbound configuration
    log_info "Configuring Unbound..."
    
    # Create Pi-hole optimized Unbound config (per https://docs.pi-hole.net/guides/dns/unbound/)
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf << 'EOF'
server:
    # If no logfile is specified, syslog is used
    # logfile: "/var/log/unbound/unbound.log"
    verbosity: 0

    # Network settings - listen only on localhost for Pi-hole
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    # May be set to yes if you have IPv6 connectivity
    do-ip6: no
    prefer-ip6: no

    # Root hints for recursive resolution
    root-hints: "/var/lib/unbound/root.hints"

    # Trust glue only if it is within the server's authority
    harden-glue: yes

    # Require DNSSEC data for trust-anchored zones, if such data is absent, the zone becomes BOGUS
    harden-dnssec-stripped: yes

    # Don't use Capitalization randomization as it known to cause DNSSEC issues sometimes
    # see https://discourse.pi-hole.net/t/unbound-stubby-or-dnscrypt-proxy/9378 for further details
    use-caps-for-id: no

    # Reduce EDNS reassembly buffer size (DNS Flag Day 2020 recommendation)
    edns-buffer-size: 1232

    # Perform prefetching of close to expired message cache entries
    prefetch: yes

    # One thread should be sufficient, can be increased on beefy machines
    num-threads: 1

    # Ensure kernel buffer is large enough to not lose messages in traffic spikes
    so-rcvbuf: 1m

    # Ensure privacy of local IP ranges
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10

    # Ensure no reverse queries to non-public IP ranges (RFC6303 4.2)
    private-address: 192.0.2.0/24
    private-address: 198.51.100.0/24
    private-address: 203.0.113.0/24
    private-address: 255.255.255.255/32
    private-address: 2001:db8::/32
EOF
    log_success "Generated Unbound Pi-hole configuration"
    
    # Disable unbound-resolvconf service BEFORE starting (prevents DNS conflicts)
    systemctl disable --now unbound-resolvconf.service 2>/dev/null || true
    sed -Ei 's/^unbound_conf=/#unbound_conf=/' /etc/resolvconf.conf 2>/dev/null || true
    rm -f /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf 2>/dev/null || true
    
    # Start unbound service (root hints were downloaded before package installation)
    if systemctl restart unbound; then
        log_success "Unbound service started"
    else
        log_error "Failed to start Unbound service"
        return 1
    fi
    
    # Configure Pi-hole v6 to use Unbound as upstream DNS
    # Pi-hole v6 uses pihole.toml instead of /etc/dnsmasq.d/*.conf by default
    log_info "Configuring Pi-hole v6 to use Unbound..."
    
    local PIHOLE_TOML="/etc/pihole/pihole.toml"
    
    if [[ -f "${PIHOLE_TOML}" ]]; then
        # Enable loading of /etc/dnsmasq.d/*.conf files (disabled by default in v6)
        # Use pihole-FTL CLI for reliable config changes
        log_info "Setting misc.etc_dnsmasq_d = true..."
        if pihole-FTL --config misc.etc_dnsmasq_d true 2>/dev/null; then
            log_success "Enabled /etc/dnsmasq.d/ config loading via CLI"
        else
            # Fallback to direct file edit if CLI fails
            log_warning "CLI failed, attempting direct file edit..."
            sed -i 's/etc_dnsmasq_d *= *false/etc_dnsmasq_d = true/g' "${PIHOLE_TOML}"
            # If setting doesn't exist, add it
            if ! grep -q "etc_dnsmasq_d.*=.*true" "${PIHOLE_TOML}"; then
                # Append to [misc] section or end of file
                echo -e '\n[misc]\n  etc_dnsmasq_d = true' >> "${PIHOLE_TOML}"
            fi
            log_success "Enabled /etc/dnsmasq.d/ config loading in pihole.toml"
        fi
        
        # Set upstream DNS to only use Unbound (removes any default like 8.8.8.8, 8.8.4.4)
        log_info "Setting dns.upstreams to 127.0.0.1#5335..."
        if pihole-FTL --config dns.upstreams '["127.0.0.1#5335"]' 2>/dev/null; then
            log_success "Configured Pi-hole to use Unbound (127.0.0.1#5335) as only upstream DNS via CLI"
        else
            # Fallback to direct file edit if CLI fails
            log_warning "CLI failed, attempting direct file edit..."
            # Use Python for reliable TOML editing if available, otherwise sed
            if command -v python3 &>/dev/null; then
                python3 << 'PYEOF'
import re
toml_file = "/etc/pihole/pihole.toml"
with open(toml_file, 'r') as f:
    content = f.read()
# Replace upstreams line
content = re.sub(r'upstreams\s*=\s*\[.*?\]', 'upstreams = [ "127.0.0.1#5335" ]', content, flags=re.DOTALL)
with open(toml_file, 'w') as f:
    f.write(content)
PYEOF
                log_success "Configured Pi-hole to use Unbound via Python"
            else
                # sed fallback - match the upstreams line
                sed -i '/^[[:space:]]*upstreams[[:space:]]*=/c\  upstreams = [ "127.0.0.1#5335" ]' "${PIHOLE_TOML}"
                log_success "Configured Pi-hole to use Unbound via sed"
            fi
        fi
        
        # Set listeningMode to SINGLE (required for VPN clients to use Pi-hole)
        # LOCAL only allows queries from local subnet; SINGLE allows all origins on specified interface
        log_info "Setting dns.listeningMode to SINGLE for VPN support..."
        if pihole-FTL --config dns.listeningMode SINGLE 2>/dev/null; then
            log_success "Configured listeningMode = SINGLE via CLI"
        else
            # Fallback to direct file edit
            log_warning "CLI failed, attempting direct file edit..."
            sed -i 's/listeningMode *= *"LOCAL"/listeningMode = "SINGLE"/g' "${PIHOLE_TOML}"
            sed -i 's/listeningMode *= *"local"/listeningMode = "SINGLE"/g' "${PIHOLE_TOML}"
            log_success "Configured listeningMode = SINGLE via sed"
        fi
    else
        log_error "pihole.toml not found at ${PIHOLE_TOML} - Pi-hole v6 may not be installed correctly"
        return 1
    fi
    
    # Create dnsmasq.d directory if it doesn't exist
    mkdir -p /etc/dnsmasq.d
    
    # Create dnsmasq.d config for EDNS settings (now that etc_dnsmasq_d is enabled)
    cat > /etc/dnsmasq.d/51-unbound.conf << 'EOF'
# Unbound integration for Pi-hole
# EDNS packet size to match Unbound's edns-buffer-size
edns-packet-max=1232
EOF
    chmod 644 /etc/dnsmasq.d/51-unbound.conf
    log_success "Created /etc/dnsmasq.d/51-unbound.conf"
    
    # Verify the configuration was applied
    log_info "Verifying Pi-hole configuration..."
    if grep -q 'etc_dnsmasq_d.*=.*true' "${PIHOLE_TOML}"; then
        log_success "Verified: etc_dnsmasq_d = true"
    else
        log_error "FAILED: etc_dnsmasq_d was not set to true"
    fi
    if grep -q '127.0.0.1#5335' "${PIHOLE_TOML}"; then
        log_success "Verified: upstreams contains 127.0.0.1#5335"
    else
        log_error "FAILED: upstreams was not set to 127.0.0.1#5335"
    fi
    if grep -qi 'listeningMode.*=.*"SINGLE"' "${PIHOLE_TOML}"; then
        log_success "Verified: listeningMode = SINGLE"
    else
        log_error "FAILED: listeningMode was not set to SINGLE"
    fi
    if [[ -f /etc/dnsmasq.d/51-unbound.conf ]]; then
        log_success "Verified: /etc/dnsmasq.d/51-unbound.conf exists"
    else
        log_error "FAILED: /etc/dnsmasq.d/51-unbound.conf was not created"
    fi
    
    # Final service restarts to ensure all configuration is applied
    log_info "Restarting services to apply all configuration..."
    
    # 1. Stop Pi-hole FTL first (it depends on Unbound)
    systemctl stop pihole-FTL 2>/dev/null || true
    
    # 2. Restart Unbound to ensure it's ready
    log_info "Restarting Unbound..."
    if systemctl restart unbound; then
        log_success "Unbound restarted successfully"
        # Wait for Unbound to be fully ready
        sleep 2
    else
        log_error "Failed to restart Unbound"
        return 1
    fi
    
    # 3. Verify Unbound is responding
    log_info "Testing Unbound DNS resolution..."
    if dig @127.0.0.1 -p 5335 pi-hole.net +short +time=5 &>/dev/null; then
        log_success "Unbound is responding to queries"
    else
        log_warning "Unbound test query failed - may need more time to initialize"
    fi
    
    # 4. Start Pi-hole FTL with all new configuration
    log_info "Starting Pi-hole FTL with new configuration..."
    if systemctl start pihole-FTL; then
        log_success "Pi-hole FTL started with Unbound configuration"
    else
        log_error "Failed to start Pi-hole FTL"
        return 1
    fi
    
    # 5. Final verification - test Pi-hole DNS
    sleep 2
    log_info "Testing Pi-hole DNS resolution via Unbound..."
    if dig @127.0.0.1 pi-hole.net +short +time=5 &>/dev/null; then
        log_success "Pi-hole DNS is working with Unbound upstream"
    else
        log_warning "Pi-hole DNS test failed - check configuration"
    fi
    
    # Create root hints update script
    cat > "${PATH_FINISHED}/unbound_root_hints_update.sh" << 'EOFSCRIPT'
#!/bin/bash
# Unbound Root Hints Update Script
# Updates DNS root server hints from InterNIC

set -euo pipefail

TEMP="/scripts/temp"
LOG_FILE="/var/log/unbound-root-hints.log"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

mkdir -p "${TEMP}"

log_msg "Starting root hints update..."

# Download latest root hints
if curl --tlsv1.3 -o "${TEMP}/root.hints" https://www.internic.net/domain/named.root; then
    log_msg "Downloaded root hints successfully"
    
    # Verify file is not empty
    if [[ -s "${TEMP}/root.hints" ]]; then
        # Backup existing hints
        if [[ -f "/var/lib/unbound/root.hints" ]]; then
            cp /var/lib/unbound/root.hints "/var/lib/unbound/root.hints.backup.$(date +%Y%m%d)"
        fi
        
        # Move new hints into place
        mv "${TEMP}/root.hints" /var/lib/unbound/root.hints
        chown unbound:unbound /var/lib/unbound/root.hints
        chmod 644 /var/lib/unbound/root.hints
        log_msg "Root hints updated successfully"
        
        # Restart Unbound
        if systemctl restart unbound; then
            log_msg "Unbound restarted successfully"
        else
            log_msg "ERROR: Failed to restart Unbound"
            exit 1
        fi
    else
        log_msg "ERROR: Downloaded file is empty"
        exit 1
    fi
else
    log_msg "ERROR: Failed to download root hints"
    exit 1
fi

log_msg "Root hints update completed"
EOFSCRIPT
    chmod +x "${PATH_FINISHED}/unbound_root_hints_update.sh"
    log_success "Generated Unbound root hints update script"
    
    # Schedule monthly root hints update (first week of each month)
    # Per Pi-hole docs: update roughly every six months, but monthly is fine
    # Ensure at least 45 minutes from other crons (other crons run around 02:45-04:15)
    # So we run at 12:00-14:00 range to be well separated
    local random_day=$((1 + RANDOM % 7))  # Day 1-7 of month
    local random_hour=$((12 + RANDOM % 3))  # Hour 12-14 (noon-2pm, well away from overnight crons)
    local random_minute=$((RANDOM % 60))
    (crontab -l 2>/dev/null; echo "# Unbound root hints update (monthly)"; echo "${random_minute} ${random_hour} ${random_day} * * bash ${PATH_FINISHED}/unbound_root_hints_update.sh >> /var/log/unbound-root-hints.log 2>&1") | crontab -
    log_success "Scheduled Unbound root hints update (monthly: day ${random_day}, $(printf '%02d:%02d' ${random_hour} ${random_minute}))"
}

# ============================================================================
# UPDATE SCRIPT INSTALLATION
# ============================================================================

install_update_scripts() {
    log_info "Installing optimized update scripts..."
    
    local repo_base="https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master"
    
    # Download updates.sh
    if curl --tlsv1.3 -f -o "${PATH_FINISHED}/updates.sh" \
        "${repo_base}/scripts/updates.sh"; then
        chmod +x "${PATH_FINISHED}/updates.sh"
        log_success "Downloaded updates.sh"
    else
        log_error "Failed to download updates.sh"
        return 1
    fi
    
    # Download refresh.sh
    if curl --tlsv1.3 -f -o "${PATH_FINISHED}/refresh.sh" \
        "${repo_base}/scripts/refresh.sh"; then
        chmod +x "${PATH_FINISHED}/refresh.sh"
        log_success "Downloaded refresh.sh"
    else
        log_error "Failed to download refresh.sh"
        return 1
    fi
    
    # Download Research.sh
    if curl --tlsv1.3 -f -o "${PATH_FINISHED}/Research.sh" \
        "${repo_base}/scripts/Research.sh"; then
        chmod +x "${PATH_FINISHED}/Research.sh"
        log_success "Downloaded Research.sh"
    else
        log_warning "Failed to download Research.sh (optional)"
    fi
    
    # Test the update script
    if bash "${PATH_FINISHED}/updates.sh" --help >/dev/null 2>&1; then
        log_success "Update script validated"
    else
        log_warning "Update script may have issues"
    fi
}

setup_cron_jobs() {
    log_info "Setting up cron jobs for automated updates..."
    
    # Calculate randomized times
    # Base time: 3:30 AM (03:30)
    # Random offset: ±45 minutes = between 02:45 and 04:15
    local base_hour=3
    local base_minute=30
    local offset_minutes=$((RANDOM % 91 - 45))  # -45 to +45
    
    local purge_total_minutes=$((base_hour * 60 + base_minute + offset_minutes))
    local purge_hour=$((purge_total_minutes / 60))
    local purge_minute=$((purge_total_minutes % 60))
    
    # Ensure within 0-23 hours
    if [[ ${purge_hour} -lt 0 ]]; then
        purge_hour=$((24 + purge_hour))
    elif [[ ${purge_hour} -ge 24 ]]; then
        purge_hour=$((purge_hour - 24))
    fi
    
    log_info "purge-and-update scheduled at: $(printf "%02d:%02d" ${purge_hour} ${purge_minute})"
    
    # Calculate allow-update times (8 and 16 hours after purge)
    local allow_time1_minutes=$((purge_total_minutes + 480))  # +8 hours after purge
    local allow_time2_minutes=$((purge_total_minutes + 960))  # +16 hours after purge
    
    # Wrap around 24 hours
    allow_time1_minutes=$((allow_time1_minutes % 1440))
    allow_time2_minutes=$((allow_time2_minutes % 1440))
    
    local allow_hour1=$((allow_time1_minutes / 60))
    local allow_minute1=$((allow_time1_minutes % 60))
    local allow_hour2=$((allow_time2_minutes / 60))
    local allow_minute2=$((allow_time2_minutes % 60))
    
    log_info "allow-update scheduled at: $(printf "%02d:%02d" ${allow_hour1} ${allow_minute1}), $(printf "%02d:%02d" ${allow_hour2} ${allow_minute2})"
    
    # Calculate refresh time (1-3 hours before purge-and-update)
    local refresh_offset=$((RANDOM % 121 + 60))  # 60-180 minutes before
    local refresh_total_minutes=$((purge_total_minutes - refresh_offset))
    if [[ ${refresh_total_minutes} -lt 0 ]]; then
        refresh_total_minutes=$((1440 + refresh_total_minutes))
    fi
    local refresh_hour=$((refresh_total_minutes / 60))
    local refresh_minute=$((refresh_total_minutes % 60))
    
    log_info "refresh (gravity update) scheduled at: $(printf "%02d:%02d" ${refresh_hour} ${refresh_minute})"
    
    # Calculate reboot time (45 minutes after purge-and-update)
    local reboot_total_minutes=$((purge_total_minutes + 45))
    reboot_total_minutes=$((reboot_total_minutes % 1440))  # Wrap around 24 hours
    local reboot_hour=$((reboot_total_minutes / 60))
    local reboot_minute=$((reboot_total_minutes % 60))
    
    log_info "daily reboot scheduled at: $(printf "%02d:%02d" ${reboot_hour} ${reboot_minute})"
    
    # Add cron jobs
    (
        crontab -l 2>/dev/null
        echo "# Pi-hole automated updates (installed $(date --iso-8601))"
        echo "${purge_minute} ${purge_hour} * * * bash ${PATH_FINISHED}/updates.sh purge-and-update >> /var/log/pihole-purge-update.log 2>&1"
        echo "${allow_minute1} ${allow_hour1} * * * bash ${PATH_FINISHED}/updates.sh allow-update >> /var/log/pihole-allow-update.log 2>&1"
        echo "${allow_minute2} ${allow_hour2} * * * bash ${PATH_FINISHED}/updates.sh allow-update >> /var/log/pihole-allow-update.log 2>&1"
        echo "${refresh_minute} ${refresh_hour} * * * bash ${PATH_FINISHED}/updates.sh refresh >> /var/log/pihole-refresh.log 2>&1"
        echo "${reboot_minute} ${reboot_hour} * * * /sbin/reboot >> /var/log/pihole-reboot.log 2>&1"
    ) | crontab -
    
    log_success "Cron jobs configured successfully"
    
    # Show summary
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               SCHEDULED UPDATE TIMES                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    printf "  Gravity Refresh:    %02d:%02d daily\n" ${refresh_hour} ${refresh_minute}
    printf "  Full Purge+Update:  %02d:%02d daily\n" ${purge_hour} ${purge_minute}
    printf "  Allow List Update:  %02d:%02d, %02d:%02d daily\n" \
        ${allow_hour1} ${allow_minute1} ${allow_hour2} ${allow_minute2}
    printf "  System Reboot:      %02d:%02d daily\n" ${reboot_hour} ${reboot_minute}
    printf "  Unbound Root Hints: Monthly (day 1-7, 12:00-14:00)\n"
    
    echo ""
    sleep 3
}

# ============================================================================
# WIREGUARD VPN INSTALLATION
# ============================================================================

install_wireguard() {
    if [[ "${INSTALL_VPN}" != "yes" ]]; then
        log_info "Skipping WireGuard installation (not requested)"
        return 0
    fi
    
    log_info "Installing WireGuard VPN (modern implementation)..."
    
    # Install WireGuard packages
    if ! apt-get install -y wireguard wireguard-tools qrencode iptables-persistent; then
        log_error "Failed to install WireGuard packages"
        return 1
    fi
    
    log_success "WireGuard packages installed"
    
    # Create WireGuard directory structure
    mkdir -p "${WIREGUARD_DIR}"
    mkdir -p "${CLIENTS_DIR}"
    chmod 700 "${WIREGUARD_DIR}"
    chmod 700 "${CLIENTS_DIR}"
    
    # Generate server keys
    log_info "Generating WireGuard server keys..."
    local server_private_key=$(wg genkey)
    local server_public_key=$(echo "${server_private_key}" | wg pubkey)
    
    # Determine server network interface
    local server_interface=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++)if($i~/dev/)print $(i+1)}')
    
    # Create server configuration
    log_info "Creating WireGuard server configuration..."
    
    cat > "${WIREGUARD_CONFIG}" <<EOF
# WireGuard Server Configuration
# Created: $(date --iso-8601=seconds)
# Server Public Key: ${server_public_key}

[Interface]
Address = ${WIREGUARD_SERVER_IP}/${WIREGUARD_CIDR}
ListenPort = ${WIREGUARD_PORT}
PrivateKey = ${server_private_key}

# Forwarding and NAT rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${server_interface} -j MASQUERADE
PostUp = iptables -I FORWARD -i %i -o %i -j REJECT --reject-with icmp-admin-prohibited

PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${server_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o %i -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || true

# DNS - Point to Pi-hole
# Clients will use this server's Pi-hole for DNS filtering

# Clients added below:
EOF

    chmod 600 "${WIREGUARD_CONFIG}"
    
    # Save server public key for client configs
    echo "${server_public_key}" > "${WIREGUARD_DIR}/server-public.key"
    chmod 600 "${WIREGUARD_DIR}/server-public.key"
    
    log_success "Server configuration created"
    
    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    fi
    
    sysctl -p >/dev/null 2>&1
    
    log_success "IP forwarding enabled"
    
    # Enable and start WireGuard
    log_info "Starting WireGuard service..."
    
    systemctl enable wg-quick@wg0
    
    if systemctl start wg-quick@wg0; then
        log_success "WireGuard service started"
    else
        log_error "Failed to start WireGuard service"
        return 1
    fi
    
    # Configure firewall for WireGuard
    configure_wireguard_firewall
    
    # Configure dnsmasq for WireGuard VPN network
    log_info "Configuring DNS for VPN clients..."
    cat > /etc/dnsmasq.d/02-pihole-wireguard.conf <<EOF
# WireGuard VPN DNS Configuration
# Created: $(date --iso-8601=seconds)
# Allows VPN clients to use Pi-hole for DNS filtering

# Listen on WireGuard interface for DNS queries from VPN clients
interface=wg0

# Do not bind to WireGuard interface for DHCP (VPN uses static IPs)
no-dhcp-interface=wg0

# Host file for VPN client hostname resolution
addn-hosts=${WIREGUARD_DIR}/hosts
EOF
    chmod 644 /etc/dnsmasq.d/02-pihole-wireguard.conf
    log_success "DNS configuration created for VPN clients"
    
    # Create initial hosts file for WireGuard clients
    log_info "Creating WireGuard hosts file..."
    cat > "${WIREGUARD_DIR}/hosts" <<EOF
# WireGuard VPN Client Hostnames
# Created: $(date --iso-8601=seconds)
# This file is automatically updated by wireguard-manager.sh
# Format: <IP> <hostname>

# Server
${WIREGUARD_SERVER_IP} wg-server
EOF
    chmod 644 "${WIREGUARD_DIR}/hosts"
    log_success "WireGuard hosts file created"
    
    # Restart DNS services to apply dnsmasq config
    log_info "Restarting DNS services..."
    systemctl restart pihole-FTL 2>/dev/null || service pihole-FTL restart
    log_success "DNS services restarted"
    
    # Create client management helper script
    install_wireguard_helpers
    
    log_success "WireGuard VPN installation complete"
    
    # Display server information
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              WIREGUARD SERVER INFORMATION                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Server Public Key: ${server_public_key}"
    echo "  Server IP (VPN):   ${WIREGUARD_SERVER_IP}"
    echo "  Listen Port:       ${WIREGUARD_PORT}"
    echo "  Network:           ${WIREGUARD_SERVER_NETWORK}/${WIREGUARD_CIDR}"
    echo ""
    echo "  Use wireguard-manager.sh to add/remove clients"
    echo ""
    sleep 3
}

configure_wireguard_firewall() {
    log_info "Configuring firewall for WireGuard..."
    
    # Allow WireGuard port
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${WIREGUARD_PORT}/udp" comment "WireGuard VPN" || log_warning "Failed to add ufw rule"
    fi
    
    # Save iptables rules
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save || log_warning "Failed to save iptables rules"
    elif command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || log_warning "Failed to save iptables rules"
    fi
    
    log_success "Firewall configured"
}

install_wireguard_helpers() {
    log_info "Installing WireGuard helper scripts..."
    
    # Copy wireguard-manager.sh to PATH_FINISHED
    if [[ -f "${SCRIPT_DIR}/wireguard-manager.sh" ]]; then
        cp "${SCRIPT_DIR}/wireguard-manager.sh" "${PATH_FINISHED}/"
        chmod +x "${PATH_FINISHED}/wireguard-manager.sh"
        log_success "Installed wireguard-manager.sh"
    else
        # Download if not present
        if curl --tlsv1.3 -o "${PATH_FINISHED}/wireguard-manager.sh" \
            "https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/scripts/wireguard-manager.sh" 2>/dev/null; then
            chmod +x "${PATH_FINISHED}/wireguard-manager.sh"
            log_success "Downloaded wireguard-manager.sh"
        else
            log_warning "Could not install wireguard-manager.sh, will need manual client management"
        fi
    fi
}

# ============================================================================
# SECURITY & FINALIZATION
# ============================================================================

setup_fail2ban() {
    log_info "Configuring Fail2Ban with progressive banning..."
    
    # Create progressive banning configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban settings
bantime  = 1500        # 25 minutes (1500 seconds)
maxretry = 3           # 3 attempts before initial ban
findtime = 86400       # 24 hour window for attempts

# Email alerts (configure if desired)
destemail = root@localhost
sender = fail2ban@localhost
action = %(action_)s

# Enable sshd protection
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

# Pi-hole admin protection
[pihole]
enabled = true
port = http,https
filter = pihole
logpath = /var/log/pihole.log
maxretry = 3

# Recidivist jail - 7 day ban after 3 short bans in 90 days
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800       # 7 days
findtime = 7776000     # 90 day window
maxretry = 3           # After 3 short bans
action = %(action_mwl)s

# Permanent ban jail - forever after 2 recidive bans in 1 year
[recidive-permanent]
enabled = true
filter = recidive-permanent
logpath = /var/log/fail2ban.log
bantime = -1           # Permanent ban (-1 = forever)
findtime = 31536000    # 1 year window
maxretry = 2           # After 2 recidive bans
action = %(action_mwl)s
EOF
    log_success "Generated Fail2Ban jail configuration"
    
    # Create Pi-hole filter
    cat > /etc/fail2ban/filter.d/pihole.conf << 'EOF'
[Definition]
failregex = ^.* "(GET|POST|HEAD).* HTTP.*" 401 .*$
            ^.* "(GET|POST|HEAD).* HTTP.*" 403 .*$
ignoreregex =
EOF
    log_success "Generated Pi-hole Fail2Ban filter"
    
    # Create recidive-permanent filter (tracks recidive bans)
    cat > /etc/fail2ban/filter.d/recidive-permanent.conf << 'EOF'
[Definition]
failregex = ^%(__prefix_line)s\[recidive\] Ban <HOST>$
ignoreregex =
EOF
    log_success "Generated recidive-permanent Fail2Ban filter"
    
    # Restart Fail2Ban to apply configuration
    systemctl enable fail2ban
    if systemctl restart fail2ban; then
        log_success "Fail2Ban started with progressive banning"
        log_info "Ban progression: 3 attempts/24h → 25 min | 3 bans/90d → 7 days | 2 recidive/1y → permanent"
    else
        log_error "Failed to restart Fail2Ban"
    fi
}

configure_server_dns() {
    log_info "Configuring server to use itself for DNS..."
    
    # Unlink and relink resolv.conf
    unlink /etc/resolv.conf 2>/dev/null || true
    ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true
    systemctl restart systemd-resolved.service 2>/dev/null || true
    
    # Comment out existing nameservers and add localhost
    sed -i "s/^nameserver/#nameserver/g" /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 127.0.0.1" >> /etc/resolv.conf
    
    log_success "Server configured to use local Pi-hole DNS"
}

setup_unattended_upgrades() {
    log_info "Configuring unattended upgrades..."
    
    if apt-get install -y --no-install-recommends unattended-upgrades; then
        log_success "Unattended upgrades enabled"
    else
        log_warning "Failed to enable unattended upgrades"
    fi
}

harden_ssh() {
    log_info "Hardening SSH configuration..."
    
    local sshd_config="/etc/ssh/sshd_config"
    local backup="${sshd_config}.backup.$(date +%Y%m%d-%H%M%S)"
    
    # Backup original config
    cp "${sshd_config}" "${backup}" || {
        log_error "Failed to backup sshd_config"
        return 1
    }
    log_info "Backed up SSH config to ${backup}"
    
    # Check if AllowUsers already exists
    if grep -q "^AllowUsers" "${sshd_config}"; then
        # Append user if not already present
        if ! grep "^AllowUsers" "${sshd_config}" | grep -q "${REAL_USER}"; then
            sed -i "s/^AllowUsers.*/& ${REAL_USER}/" "${sshd_config}"
            log_success "Added ${REAL_USER} to existing AllowUsers"
        else
            log_info "${REAL_USER} already in AllowUsers"
        fi
    else
        # Add new AllowUsers line
        echo "" >> "${sshd_config}"
        echo "# Restrict SSH access to specific users" >> "${sshd_config}"
        echo "AllowUsers ${REAL_USER}" >> "${sshd_config}"
        log_success "Added AllowUsers ${REAL_USER} to SSH config"
    fi
    
    # Additional SSH hardening
    local changes_made=false
    
    # Disable root login
    if grep -q "^PermitRootLogin yes" "${sshd_config}"; then
        sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "${sshd_config}"
        changes_made=true
        log_info "Disabled root SSH login"
    fi
    
    # Disable password authentication (after MFA is set up, optional)
    # Uncommented for now to allow initial MFA setup
    # if grep -q "^PasswordAuthentication yes" "${sshd_config}"; then
    #     sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "${sshd_config}"
    #     log_info "Disabled password authentication (key-based only)"
    # fi
    
    # Test SSH config
    if sshd -t 2>/dev/null; then
        systemctl restart sshd || systemctl restart ssh || {
            log_error "Failed to restart SSH service"
            log_warning "Restoring backup config..."
            cp "${backup}" "${sshd_config}"
            systemctl restart sshd || systemctl restart ssh
            return 1
        }
        log_success "SSH configuration updated and service restarted"
    else
        log_error "SSH config test failed, restoring backup"
        cp "${backup}" "${sshd_config}"
        return 1
    fi
    
    log_warning "IMPORTANT: Test SSH access before closing this session!"
    sleep 3
}

setup_mfa() {
    [[ "${ENABLE_MFA}" != "yes" ]] && return 0
    
    log_info "Setting up Multi-Factor Authentication (Google Authenticator)..."
    
    # Install google-authenticator package
    if ! apt-get install -y libpam-google-authenticator; then
        log_error "Failed to install libpam-google-authenticator"
        return 1
    fi
    log_success "Installed libpam-google-authenticator"
    
    # User instructions - manual setup required
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          GOOGLE AUTHENTICATOR SETUP REQUIRED                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  The libpam-google-authenticator package has been installed."
    echo ""
    echo "  To enable MFA, you must manually complete these steps:"
    echo ""
    echo "  Step 1: Run this command as your user (not root):"
    echo ""
    echo "    google-authenticator"
    echo ""
    echo "  Step 2: Answer the prompts:"
    echo "    - Time-based tokens (TOTP): YES"
    echo "    - Update .google_authenticator file: YES"
    echo "    - Disallow multiple uses: YES"
    echo "    - Increase time window: NO (or YES if experiencing sync issues)"
    echo "    - Enable rate-limiting: YES"
    echo ""
    echo "  Step 3: Scan the QR code with your authenticator app"
    echo "          (Google Authenticator, Authy, Microsoft Authenticator, etc.)"
    echo ""
    echo "  Step 4: SAVE the emergency scratch codes somewhere safe!"
    echo ""
    echo "  Step 5: Configure PAM and SSH for 2FA:"
    echo "    Edit /etc/pam.d/sshd and add at the end:"
    echo "      auth required pam_google_authenticator.so"
    echo ""
    echo "    Edit /etc/ssh/sshd_config and ensure:"
    echo "      ChallengeResponseAuthentication yes"
    echo "      # Or on newer systems:"
    echo "      KbdInteractiveAuthentication yes"
    echo ""
    echo "    Then restart SSH:"
    echo "      sudo systemctl restart sshd"
    echo ""
    echo -e "${COLOR_YELLOW}  See: https://ubuntu.com/tutorials/configure-ssh-2fa${COLOR_RESET}"
    echo ""
    
    log_success "libpam-google-authenticator installed - manual configuration required"
}

cleanup_installation() {
    log_info "Cleaning up temporary files..."
    
    rm -rf "${PATH_TEMP}"/* 2>/dev/null || true
    apt-get autoremove -y || true
    apt-get clean || true
    
    log_success "Cleanup completed"
}

# ============================================================================
# MAIN INSTALLATION FLOW
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG_MODE=true
                log_info "Debug mode enabled"
                shift
                ;;
            --config=*)
                CONFIG_FILE="${1#*=}"
                shift
                ;;
            --repair)
                REPAIR_MODE=true
                log_info "Repair mode enabled - will skip completed steps"
                shift
                ;;
            --help)
                show_header
                echo "Usage: sudo bash install-pihole-vpn.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --debug          Enable debug output"
                echo "  --config=FILE    Use specified config file"
                echo "  --repair         Resume/repair failed installation (skips completed steps)"
                echo "  --help           Show this help message"
                echo ""
                echo "If no config file is specified, installer will run interactively."
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

main() {
    # Initialize
    show_header
    parse_arguments "$@"
    
    log "========================================"
    log "Pi-hole + VPN Installer v${VERSION}"
    log "Started: $(date --iso-8601=seconds)"
    log "========================================"
    
    # Pre-flight checks
    check_root
    detect_platform
    detect_network
    
    # Configuration
    if load_config_file; then
        show_config_summary
        
        # Validate and fix any issues
        echo ""
        read -p "Configuration looks good? [Y/n]: " config_ok
        if [[ ! "${config_ok,,}" =~ ^(y|yes|)$ ]]; then
            log_info "Entering interactive configuration mode..."
            prompt_configuration
        fi
    else
        prompt_configuration
    fi
    
    confirm_proceed
    
    # Detect real user (before any user-specific operations)
    detect_real_user
    
    # ========================================================================
    # PHASE 1: System Preparation
    # ========================================================================
    log_info "=== PHASE 1: System Preparation ==="
    
    if ! skip_if_complete "directories" "directory creation"; then
        create_directories && mark_step_complete "directories"
    fi
    
    if ! skip_if_complete "config_files" "configuration file generation"; then
        create_config_files && mark_step_complete "config_files"
    fi
    
    if ! skip_if_complete "system_update" "system update"; then
        system_update && mark_step_complete "system_update"
    fi
    
    if ! skip_if_complete "dependencies" "dependency installation"; then
        install_dependencies && mark_step_complete "dependencies"
    fi
    
    wait_for_user "System Preparation (updates & dependencies)" "System updates and dependencies installed. Ready to proceed?"
    
    # ========================================================================
    # PHASE 2: Security Configuration
    # ========================================================================
    log_info "=== PHASE 2: Security Configuration ==="
    
    if ! skip_if_complete "unattended_upgrades" "unattended upgrades"; then
        setup_unattended_upgrades && mark_step_complete "unattended_upgrades"
    fi
    
    if ! skip_if_complete "fail2ban" "Fail2Ban setup"; then
        setup_fail2ban && mark_step_complete "fail2ban"
    fi
    
    # SSH Hardening (before MFA so user can still login)
    if ! skip_if_complete "ssh_hardening" "SSH hardening"; then
        harden_ssh && mark_step_complete "ssh_hardening"
    fi
    
    wait_for_user "Security Configuration (Fail2Ban, SSH)" "Security hardening complete. Ready to proceed?"
    
    # ========================================================================
    # PHASE 3: GPG Key Setup
    # ========================================================================
    log_info "=== PHASE 3: GPG Key Setup ==="
    
    if ! skip_if_complete "gpg_download" "GPG public key download"; then
        download_public_gpg_keys && mark_step_complete "gpg_download"
    fi
    
    if ! skip_if_complete "gpg_key" "GPG key generation"; then
        generate_gpg_key && mark_step_complete "gpg_key"
    fi
    
    if ! skip_if_complete "gpg_import" "GPG key import"; then
        import_gpg_keys && mark_step_complete "gpg_import"
    fi
    
    wait_for_user "GPG Key Setup" "GPG keys configured. Ready to install Pi-hole?"
    
    # ========================================================================
    # PHASE 4: Pi-hole Installation (INTERACTIVE)
    # ========================================================================
    log_info "=== PHASE 4: Pi-hole Installation ==="
    echo ""
    echo -e "${COLOR_YELLOW}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}║           PI-HOLE INTERACTIVE INSTALLATION                   ║${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    echo "The Pi-hole installer will now run interactively."
    echo "Follow the prompts to complete Pi-hole setup."
    echo ""
    echo "IMPORTANT: When prompted for upstream DNS, select any option."
    echo "           We will configure Unbound as the DNS resolver next."
    echo ""
    read -p "Press ENTER to start the Pi-hole installer..."
    echo ""
    
    if ! skip_if_complete "pihole" "Pi-hole installation"; then
        install_pihole
        wait_for_user "Pi-hole Installation" "Is the Pi-hole installation FULLY COMPLETE?"
        mark_step_complete "pihole"
    fi
    
    # ========================================================================
    # PHASE 5: Unbound DNS Resolver
    # ========================================================================
    log_info "=== PHASE 5: Unbound DNS Resolver ==="
    
    if ! skip_if_complete "dns_provider" "DNS provider setup"; then
        install_unbound && mark_step_complete "dns_provider"
    fi
    
    wait_for_user "Unbound DNS Resolver" "Unbound installed and configured. Ready to proceed?"
    
    # ========================================================================
    # PHASE 6: Update Scripts & Cron Jobs
    # ========================================================================
    log_info "=== PHASE 6: Update Scripts & Cron Jobs ==="
    
    if ! skip_if_complete "update_scripts" "update scripts installation"; then
        install_update_scripts && mark_step_complete "update_scripts"
    fi
    
    if ! skip_if_complete "cron_jobs" "cron job setup"; then
        setup_cron_jobs && mark_step_complete "cron_jobs"
    fi
    
    wait_for_user "Update Scripts & Cron Jobs" "Scripts and cron jobs configured. Ready to proceed?"
    
    # ========================================================================
    # PHASE 7: WireGuard VPN (if requested)
    # ========================================================================
    if [[ "${INSTALL_VPN}" == "yes" ]]; then
        log_info "=== PHASE 7: WireGuard VPN ==="
        
        if ! skip_if_complete "wireguard" "WireGuard VPN"; then
            install_wireguard && mark_step_complete "wireguard"
        fi
        
        wait_for_user "WireGuard VPN" "WireGuard VPN installed. Ready to proceed?"
    else
        log_info "=== PHASE 7: WireGuard VPN (SKIPPED - not requested) ==="
    fi
    
    # ========================================================================
    # PHASE 8: Finalization
    # ========================================================================
    log_info "=== PHASE 8: Finalization ==="
    
    if ! skip_if_complete "dns_config" "server DNS configuration"; then
        configure_server_dns && mark_step_complete "dns_config"
    fi
    
    # MFA Setup (at the very end, requires user action)
    if ! skip_if_complete "mfa" "MFA setup"; then
        setup_mfa && mark_step_complete "mfa"
    fi
    
    if ! skip_if_complete "cleanup" "cleanup"; then
        cleanup_installation && mark_step_complete "cleanup"
    fi
    
    # Summary
    log "========================================"
    log "Installation completed: $(date --iso-8601=seconds)"
    log "========================================"
    
    # Clean up state file on successful completion
    rm -f "${STATE_FILE}"
    
    show_summary_report
    
    # Final instructions
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   NEXT STEPS                                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    local step=1
    
    echo "${step}. Set Pi-hole admin password:"
    echo "   sudo pihole setpassword"
    echo ""
    ((step++))
    
    if [[ "${INSTALL_VPN}" == "yes" ]]; then
        echo "${step}. Create WireGuard VPN clients:"
        echo "   Run: sudo bash ${PATH_FINISHED}/wireguard-manager.sh"
        echo ""
        ((step++))
    fi
    
    echo "${step}. Access Pi-hole admin interface:"
    echo "   http://${STATIC_IPV4}/admin"
    echo ""
    ((step++))
    
    echo "${step}. Review installation log:"
    echo "   ${LOG_FILE}"
    echo ""
    ((step++))
    
    echo "${step}. IMPORTANT - Test SSH access before closing this session:"
    echo "   SSH is configured for user: ${REAL_USER}"
    echo "   Open a NEW terminal and test SSH login before closing this session!"
    echo ""
    ((step++))
    
    echo "${step}. Reboot server to apply all changes:"
    echo "   sudo reboot"
    echo ""
}

# Run main function
main "$@"
