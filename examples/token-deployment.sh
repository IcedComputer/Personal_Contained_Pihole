#!/bin/bash
################################################################################
# GitHub Token Multi-Server Deployment Script
# File: token-deployment.sh
# Type: Utility Script
# Category: GitHub Authentication
# 
# Created: 2025-12-07
# Version: 1.0.0
#
# Description:
#   Deploy GitHub authentication token to multiple Pi-hole servers.
#   Supports parallel deployment with status tracking.
#   Useful for managing multiple Pi-hole instances.
#
# Usage:
#   1. Edit SERVER_LIST array with your server IPs
#   2. Set TOKEN variable or provide via argument
#   3. Run: bash token-deployment.sh [TOKEN]
#
# Examples:
#   bash token-deployment.sh
#   bash token-deployment.sh github_pat_XXXXXX
#   bash token-deployment.sh --servers 192.168.1.100,192.168.1.101
#
# Following Universal Constants:
#   UC-001: Code clarity over cleverness
#   UC-002: Meaningful naming conventions
#   UC-003: ISO 8601 date format
#   UC-004: Professional communication
#
################################################################################

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

# List of Pi-hole servers (edit this)
declare -a SERVER_LIST=(
    "192.168.1.100"    # Home Pi-hole
    "192.168.1.101"    # Backup Pi-hole
    # "10.0.0.10"      # Azure Pi-hole
    # Add more servers as needed
)

# SSH settings
SSH_USER="pi"                    # Default SSH user (change as needed)
SSH_PORT="22"                    # SSH port
SSH_KEY="${HOME}/.ssh/id_rsa"    # SSH key path

# Remote paths
REMOTE_TOKEN_FILE="/scripts/Finished/CONFIG/github_token.conf"
REMOTE_CONFIG_DIR="/scripts/Finished/CONFIG"

# Optional: Token expiration date (ISO 8601 format)
# Leave empty for "no expiration"
TOKEN_EXPIRY=""

# Colors
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_success() {
    echo -e "${COLOR_GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✓ $*${COLOR_RESET}"
}

log_error() {
    echo -e "${COLOR_RED}[$(date +'%Y-%m-%d %H:%M:%S')] ✗ ERROR: $*${COLOR_RESET}"
}

log_warning() {
    echo -e "${COLOR_YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠ WARNING: $*${COLOR_RESET}"
}

log_info() {
    echo -e "${COLOR_BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] ℹ INFO: $*${COLOR_RESET}"
}

show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     GitHub Token Multi-Server Deployment Script             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

validate_token() {
    local token="$1"
    
    # Check token format (github_pat_* or ghp_*)
    if [[ ! "$token" =~ ^(github_pat_[A-Za-z0-9_]{82}|ghp_[A-Za-z0-9]{36})$ ]]; then
        log_error "Invalid token format"
        log_info "Expected: github_pat_XXXX (93 chars) or ghp_XXXX (40 chars)"
        return 1
    fi
    
    return 0
}

check_ssh_access() {
    local server="$1"
    
    if ssh -i "$SSH_KEY" -p "$SSH_PORT" -o ConnectTimeout=5 -o BatchMode=yes \
        "${SSH_USER}@${server}" "echo test" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

deploy_token_to_server() {
    local server="$1"
    local token="$2"
    local expiry="${3:-}"
    
    log_info "Deploying to ${server}..."
    
    # Check SSH access
    if ! check_ssh_access "$server"; then
        log_error "Cannot connect to ${server} via SSH"
        return 1
    fi
    
    # Create CONFIG directory if needed
    ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${server}" \
        "sudo mkdir -p ${REMOTE_CONFIG_DIR} && sudo chmod 700 ${REMOTE_CONFIG_DIR}" || {
        log_error "Failed to create CONFIG directory on ${server}"
        return 1
    }
    
    # Deploy token
    ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${server}" \
        "echo '${token}' | sudo tee ${REMOTE_TOKEN_FILE} >/dev/null && \
         sudo chmod 600 ${REMOTE_TOKEN_FILE} && \
         sudo chown root:root ${REMOTE_TOKEN_FILE}" || {
        log_error "Failed to deploy token to ${server}"
        return 1
    }
    
    # Deploy expiry date if provided
    if [[ -n "$expiry" ]]; then
        ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${server}" \
            "echo '${expiry}' | sudo tee ${REMOTE_CONFIG_DIR}/github_token_expiry.conf >/dev/null && \
             sudo chmod 600 ${REMOTE_CONFIG_DIR}/github_token_expiry.conf && \
             sudo chown root:root ${REMOTE_CONFIG_DIR}/github_token_expiry.conf" || {
            log_warning "Failed to deploy expiry date to ${server}"
        }
    fi
    
    # Verify deployment
    if ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${server}" \
        "sudo test -f ${REMOTE_TOKEN_FILE}" >/dev/null 2>&1; then
        log_success "Successfully deployed to ${server}"
        return 0
    else
        log_error "Verification failed on ${server}"
        return 1
    fi
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

main() {
    show_header
    
    # Parse arguments
    local token="${1:-}"
    
    if [[ "$token" == "--servers" ]]; then
        IFS=',' read -ra SERVER_LIST <<< "${2:-}"
        token="${3:-}"
    fi
    
    # Get token if not provided
    if [[ -z "$token" ]]; then
        echo "Enter GitHub Personal Access Token:"
        read -s token
        echo ""
    fi
    
    # Validate token
    if ! validate_token "$token"; then
        exit 1
    fi
    
    log_success "Token format validated"
    
    # Optional: Get expiry date
    if [[ -z "$TOKEN_EXPIRY" ]]; then
        echo ""
        log_info "Enter token expiration date (YYYY-MM-DD) or press Enter for no expiration:"
        read TOKEN_EXPIRY
    fi
    
    # Show deployment plan
    echo ""
    log_info "Deployment Plan:"
    echo "  Servers: ${#SERVER_LIST[@]}"
    echo "  SSH User: ${SSH_USER}"
    echo "  SSH Key: ${SSH_KEY}"
    echo "  Token Expiry: ${TOKEN_EXPIRY:-No expiration}"
    echo ""
    
    for server in "${SERVER_LIST[@]}"; do
        echo "  • ${server}"
    done
    
    echo ""
    read -p "Proceed with deployment? [Y/n]: " confirm
    if [[ ! "${confirm,,}" =~ ^(y|yes|)$ ]]; then
        log_info "Deployment cancelled"
        exit 0
    fi
    
    # Deploy to all servers
    echo ""
    log_info "Starting deployment..."
    echo ""
    
    local success_count=0
    local fail_count=0
    declare -a failed_servers=()
    
    for server in "${SERVER_LIST[@]}"; do
        if deploy_token_to_server "$server" "$token" "$TOKEN_EXPIRY"; then
            ((success_count++))
        else
            ((fail_count++))
            failed_servers+=("$server")
        fi
    done
    
    # Summary
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  DEPLOYMENT SUMMARY                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "Total Servers: ${#SERVER_LIST[@]}"
    log_success "Successful: ${success_count}"
    
    if [[ $fail_count -gt 0 ]]; then
        log_error "Failed: ${fail_count}"
        echo ""
        log_warning "Failed servers:"
        for server in "${failed_servers[@]}"; do
            echo "  ✗ ${server}"
        done
        echo ""
        exit 1
    else
        echo ""
        log_success "All servers updated successfully!"
        echo ""
        log_info "Next steps:"
        echo "  1. Test authenticated downloads on each server"
        echo "  2. Run: sudo bash /scripts/Finished/updates.sh full-update"
        echo "  3. Verify no authentication errors in logs"
        echo ""
    fi
}

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

# Check if running as root (not needed, but warn if so)
if [[ $EUID -eq 0 ]]; then
    log_warning "Running as root. This script should be run as a normal user with SSH key access."
    log_warning "The script will use sudo on remote servers as needed."
fi

# Check SSH key exists
if [[ ! -f "$SSH_KEY" ]]; then
    log_error "SSH key not found: $SSH_KEY"
    log_info "Generate one with: ssh-keygen -t rsa -b 4096"
    exit 1
fi

# Check server list not empty
if [[ ${#SERVER_LIST[@]} -eq 0 ]]; then
    log_error "SERVER_LIST is empty. Edit the script and add your servers."
    exit 1
fi

# Run main function
main "$@"
