#!/bin/bash
################################################################################
# Pi-hole Configuration File
# File: rotate-github-token.sh
# Type: Maintenance Script
# Category: Security & Authentication
# Repository: Personal_Contained_Pihole/scripts/
# 
# Created: 2025-12-07
# Organized: 2025-12-07
# Last Modified: 2025-12-07
# Version: 1.0.0
#
# Description: 
#   GitHub token rotation script for VPN servers. Updates the stored GitHub
#   authentication token used for accessing private repository. Validates new
#   token before replacing old token to prevent service disruption.
#
# Usage:
#   sudo bash rotate-github-token.sh
#   sudo bash rotate-github-token.sh --token "github_pat_XXXXX"
#   sudo bash rotate-github-token.sh --help
#
################################################################################

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TOKEN_FILE="/scripts/Finished/CONFIG/github_token.conf"
readonly TOKEN_EXPIRY_FILE="/scripts/Finished/CONFIG/github_token_expiry.conf"
readonly BACKUP_DIR="/scripts/Finished/CONFIG/backups"
readonly REPO="IcedComputer/Personal_Contained_Pihole"

# Color codes for output
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_success() {
    printf "${COLOR_GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✓ %s${COLOR_RESET}\n" "$*"
}

log_error() {
    printf "${COLOR_RED}[$(date +'%Y-%m-%d %H:%M:%S')] ✗ ERROR: %s${COLOR_RESET}\n" "$*"
}

log_warning() {
    printf "${COLOR_YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠ WARNING: %s${COLOR_RESET}\n" "$*"
}

log_info() {
    printf "${COLOR_BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] ℹ %s${COLOR_RESET}\n" "$*"
}

show_header() {
    echo ""
    echo "=========================================="
    echo "  GitHub Token Rotation Tool"
    echo "  Version: 1.0.0"
    echo "=========================================="
    echo ""
}

show_help() {
    cat << EOF
GitHub Token Rotation Tool

USAGE:
    sudo bash rotate-github-token.sh [OPTIONS]

OPTIONS:
    --token TOKEN       Provide new token directly (non-interactive)
    --expiry DATE       Set token expiration date (YYYY-MM-DD)
    --no-backup         Skip backup of old token
    --help              Show this help message

DESCRIPTION:
    Safely rotates the GitHub authentication token used for accessing the
    private Personal_Contained_Pihole repository. Validates the new token
    before replacing the old one to prevent service disruption.

WORKFLOW:
    1. Validates current token (if exists)
    2. Prompts for new token (or uses --token option)
    3. Validates new token has correct permissions
    4. Backs up old token (unless --no-backup)
    5. Installs new token with secure permissions
    6. Tests download with new token
    7. Reports success or rolls back on failure

EXAMPLES:
    # Interactive mode (recommended)
    sudo bash rotate-github-token.sh

    # Non-interactive with token
    sudo bash rotate-github-token.sh --token "github_pat_XXXXX"

    # With expiration date
    sudo bash rotate-github-token.sh --expiry "2026-12-07"

SECURITY:
    - Token stored at: $TOKEN_FILE
    - Permissions: 600 (root read/write only)
    - Old tokens backed up to: $BACKUP_DIR
    - Tokens never logged or displayed

AFTER ROTATION:
    - Test with: sudo bash /scripts/Finished/updates.sh full-update
    - Revoke old token at: https://github.com/settings/tokens

EOF
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Usage: sudo bash $0"
        exit 1
    fi
}

validate_token_format() {
    local token="$1"
    
    if [[ -z "$token" ]]; then
        log_error "Token is empty"
        return 1
    fi
    
    # Check if token starts with expected prefix
    if [[ ! "$token" =~ ^(github_pat_|ghp_) ]]; then
        log_error "Invalid token format. Token should start with 'github_pat_' or 'ghp_'"
        return 1
    fi
    
    # Check token length (GitHub PATs are typically ~93 chars for fine-grained)
    local token_length=${#token}
    if [[ $token_length -lt 40 ]]; then
        log_error "Token appears too short (${token_length} chars). Expected 40+ characters."
        return 1
    fi
    
    return 0
}

validate_token_permissions() {
    local token="$1"
    
    log_info "Validating token has correct repository access..."
    
    # Test token by checking repository access
    local response
    local http_code
    
    response=$(curl -w "\n%{http_code}" -f -sS -H "Authorization: Bearer $token" \
        "https://api.github.com/repos/$REPO" 2>&1)
    
    http_code=$(echo "$response" | tail -n1)
    
    if [[ "$http_code" == "200" ]]; then
        log_success "Token validated successfully"
        
        # Parse repository info
        local repo_private=$(echo "$response" | grep -o '"private":[^,]*' | cut -d':' -f2 | tr -d ' ')
        if [[ "$repo_private" == "true" ]]; then
            log_info "Repository access confirmed (private repository)"
        else
            log_warning "Repository is public - token may not be necessary"
        fi
        
        return 0
    elif [[ "$http_code" == "401" ]]; then
        log_error "Token invalid or expired"
        return 1
    elif [[ "$http_code" == "404" ]]; then
        log_error "Token lacks access to repository: $REPO"
        log_error "Ensure token has 'Contents' read permission for this repository"
        return 1
    else
        log_error "Token validation failed with HTTP code: $http_code"
        return 1
    fi
}

backup_old_token() {
    if [[ ! -f "$TOKEN_FILE" ]]; then
        log_info "No existing token to backup"
        return 0
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    
    # Create timestamped backup
    local backup_file="${BACKUP_DIR}/github_token_$(date +'%Y%m%d_%H%M%S').conf.bak"
    cp "$TOKEN_FILE" "$backup_file"
    chmod 600 "$backup_file"
    
    log_success "Old token backed up to: $backup_file"
    
    # Also backup expiry file if exists
    if [[ -f "$TOKEN_EXPIRY_FILE" ]]; then
        local expiry_backup="${BACKUP_DIR}/github_token_expiry_$(date +'%Y%m%d_%H%M%S').conf.bak"
        cp "$TOKEN_EXPIRY_FILE" "$expiry_backup"
        chmod 600 "$expiry_backup"
        log_success "Old expiry date backed up"
    fi
}

install_new_token() {
    local token="$1"
    local expiry_date="${2:-}"
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$TOKEN_FILE")"
    
    # Write token
    echo "$token" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    chown root:root "$TOKEN_FILE"
    
    log_success "New token installed at: $TOKEN_FILE"
    
    # Write expiration date if provided
    if [[ -n "$expiry_date" ]]; then
        echo "$expiry_date" > "$TOKEN_EXPIRY_FILE"
        chmod 600 "$TOKEN_EXPIRY_FILE"
        chown root:root "$TOKEN_EXPIRY_FILE"
        log_success "Token expiration date set: $expiry_date"
    else
        # Remove expiry file if no date provided
        if [[ -f "$TOKEN_EXPIRY_FILE" ]]; then
            rm -f "$TOKEN_EXPIRY_FILE"
            log_info "Token expiration tracking removed (no expiration set)"
        fi
    fi
}

test_token_download() {
    local token="$1"
    local test_url="https://raw.githubusercontent.com/$REPO/master/README.md"
    local test_file="/tmp/github_token_test_$$"
    
    log_info "Testing authenticated download..."
    
    if curl -f -sS -H "Authorization: Bearer $token" -o "$test_file" "$test_url"; then
        rm -f "$test_file"
        log_success "Download test successful!"
        return 0
    else
        rm -f "$test_file"
        log_error "Download test failed"
        return 1
    fi
}

rollback_token() {
    log_warning "Rolling back to previous token..."
    
    # Find most recent backup
    local latest_backup=$(ls -t "$BACKUP_DIR"/github_token_*.conf.bak 2>/dev/null | head -n1)
    
    if [[ -n "$latest_backup" ]]; then
        cp "$latest_backup" "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        log_success "Rolled back to previous token"
        return 0
    else
        log_error "No backup found for rollback"
        return 1
    fi
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

rotate_token_interactive() {
    local new_token
    local expiry_date
    
    echo ""
    echo "=========================================="
    echo "  Interactive Token Rotation"
    echo "=========================================="
    echo ""
    
    # Show current token info (if exists)
    if [[ -f "$TOKEN_FILE" ]]; then
        log_info "Current token file exists: $TOKEN_FILE"
        if [[ -f "$TOKEN_EXPIRY_FILE" ]]; then
            local current_expiry=$(<"$TOKEN_EXPIRY_FILE")
            log_info "Current expiration: $current_expiry"
        else
            log_info "Current expiration: Not set (no expiration)"
        fi
        echo ""
    else
        log_info "No existing token found. This will be a new installation."
        echo ""
    fi
    
    # Instructions
    echo "To generate a new token:"
    echo "  1. Visit: https://github.com/settings/tokens?type=beta"
    echo "  2. Click 'Generate new token'"
    echo "  3. Configure:"
    echo "     - Name: pihole-vpn-servers-readonly"
    echo "     - Expiration: No expiration (or custom)"
    echo "     - Repository access: Only 'Personal_Contained_Pihole'"
    echo "     - Permissions: Contents (Read-only)"
    echo "  4. Copy the token (starts with 'github_pat_')"
    echo ""
    
    # Get new token
    read -rsp "Enter new GitHub token: " new_token
    echo ""
    
    if [[ -z "$new_token" ]]; then
        log_error "No token provided. Rotation cancelled."
        exit 1
    fi
    
    # Validate format
    if ! validate_token_format "$new_token"; then
        exit 1
    fi
    
    # Get expiration date (optional)
    echo ""
    read -rp "Enter token expiration date (YYYY-MM-DD, or press Enter for no expiration): " expiry_date
    
    # Validate date format if provided
    if [[ -n "$expiry_date" ]] && ! date -d "$expiry_date" &>/dev/null; then
        log_error "Invalid date format: $expiry_date"
        exit 1
    fi
    
    # Validate token permissions
    if ! validate_token_permissions "$new_token"; then
        log_error "Token validation failed. Rotation cancelled."
        exit 1
    fi
    
    # Backup old token
    if [[ "$NO_BACKUP" == "false" ]]; then
        backup_old_token
    fi
    
    # Install new token
    install_new_token "$new_token" "$expiry_date"
    
    # Test download
    if ! test_token_download "$new_token"; then
        log_error "Token rotation failed during download test"
        rollback_token
        exit 1
    fi
    
    # Success!
    echo ""
    log_success "Token rotation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Test updates: sudo bash /scripts/Finished/updates.sh full-update"
    echo "  2. Revoke old token at: https://github.com/settings/tokens"
    if [[ -n "$expiry_date" ]]; then
        echo "  3. Set calendar reminder to rotate before: $expiry_date"
    fi
    echo ""
}

rotate_token_noninteractive() {
    local new_token="$1"
    local expiry_date="${2:-}"
    
    log_info "Starting non-interactive token rotation..."
    
    # Validate format
    if ! validate_token_format "$new_token"; then
        exit 1
    fi
    
    # Validate permissions
    if ! validate_token_permissions "$new_token"; then
        exit 1
    fi
    
    # Backup old token
    if [[ "$NO_BACKUP" == "false" ]]; then
        backup_old_token
    fi
    
    # Install new token
    install_new_token "$new_token" "$expiry_date"
    
    # Test download
    if ! test_token_download "$new_token"; then
        log_error "Token rotation failed during download test"
        rollback_token
        exit 1
    fi
    
    log_success "Token rotation completed successfully!"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse arguments
    local token_arg=""
    local expiry_arg=""
    NO_BACKUP=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)
                token_arg="$2"
                shift 2
                ;;
            --expiry)
                expiry_arg="$2"
                shift 2
                ;;
            --no-backup)
                NO_BACKUP=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Pre-flight checks
    check_root
    show_header
    
    # Execute rotation
    if [[ -n "$token_arg" ]]; then
        # Non-interactive mode
        rotate_token_noninteractive "$token_arg" "$expiry_arg"
    else
        # Interactive mode
        rotate_token_interactive
    fi
}

main "$@"
