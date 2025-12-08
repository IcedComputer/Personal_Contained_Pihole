#!/bin/bash
################################################################################
# GitHub Authentication Helper Functions
# File: github_auth_helper.sh
# Created: 2025-12-07
# Version: 1.0.0
#
# Description:
#   Helper functions for authenticated access to private GitHub repositories.
#   Supports token-based authentication with secure storage and fallback.
#
# Usage:
#   source /scripts/Finished/github_auth_helper.sh
#   download_authenticated_file "URL" "destination"
#
################################################################################

readonly GITHUB_TOKEN_FILE="/scripts/Finished/CONFIG/github_token.conf"
readonly GITHUB_TOKEN_EXPIRY_FILE="/scripts/Finished/CONFIG/github_token_expiry.conf"

# Check if GitHub token exists and is readable
github_token_exists() {
    [[ -f "$GITHUB_TOKEN_FILE" ]] && [[ -r "$GITHUB_TOKEN_FILE" ]]
}

# Get GitHub token (returns empty string if not available)
get_github_token() {
    if github_token_exists; then
        # Read token and strip whitespace
        local token
        token=$(cat "$GITHUB_TOKEN_FILE" 2>/dev/null | tr -d '[:space:]')
        
        # Validate token format (github_pat_* or ghp_*)
        if [[ "$token" =~ ^(github_pat_|ghp_) ]]; then
            echo "$token"
            return 0
        fi
    fi
    echo ""
    return 1
}

# Check if token is approaching expiration
check_token_expiration() {
    if [[ ! -f "$GITHUB_TOKEN_EXPIRY_FILE" ]]; then
        return 0  # No expiry set, assume OK
    fi
    
    local expiry_date
    expiry_date=$(cat "$GITHUB_TOKEN_EXPIRY_FILE" 2>/dev/null)
    
    if [[ -z "$expiry_date" ]]; then
        return 0
    fi
    
    # Convert dates to seconds since epoch
    local expiry_seconds
    local now_seconds
    local days_until_expiry
    
    expiry_seconds=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
    now_seconds=$(date +%s)
    
    if [[ "$expiry_seconds" -eq 0 ]]; then
        return 0  # Invalid date format, skip check
    fi
    
    days_until_expiry=$(( (expiry_seconds - now_seconds) / 86400 ))
    
    if [[ $days_until_expiry -lt 0 ]]; then
        log_error "GitHub token has EXPIRED. Updates may fail."
        log_error "Generate new token: https://github.com/settings/tokens?type=beta"
        return 2
    elif [[ $days_until_expiry -lt 30 ]]; then
        log_warning "GitHub token expires in $days_until_expiry days. Consider renewing."
        return 1
    fi
    
    return 0
}

# Download file with GitHub authentication
# Usage: download_authenticated_file "URL" "destination_path"
download_authenticated_file() {
    local url="$1"
    local dest="$2"
    local token
    
    if [[ -z "$url" ]] || [[ -z "$dest" ]]; then
        log_error "download_authenticated_file: URL and destination required"
        return 1
    fi
    
    # Check token expiration (warning only, doesn't block)
    check_token_expiration
    
    # Try to get token
    token=$(get_github_token)
    
    # Construct curl command
    local curl_cmd="curl --tlsv1.3 -f -sS"
    
    if [[ -n "$token" ]]; then
        # Authenticated request using Authorization header
        verbose_log "Downloading with authentication: $(basename "$dest")"
        $curl_cmd -H "Authorization: Bearer $token" -o "$dest" "$url"
    else
        # Unauthenticated request (will fail for private repos)
        verbose_log "Downloading without authentication: $(basename "$dest")"
        log_warning "No GitHub token found. Private repository access may fail."
        $curl_cmd -o "$dest" "$url"
    fi
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        verbose_log "Downloaded: $(basename "$dest")"
        return 0
    else
        log_error "Failed to download: $url"
        
        if [[ -z "$token" ]]; then
            log_error "Hint: Configure GitHub token for private repository access"
            log_error "See: /docs/GITHUB_AUTH_SETUP.md"
        else
            log_error "Hint: Check if token has expired or lacks permissions"
        fi
        
        return 1
    fi
}

# Validate GitHub token has correct permissions
# Returns 0 if valid, 1 if invalid
validate_github_token() {
    local token="$1"
    local repo="${2:-IcedComputer/Personal_Contained_Pihole}"
    
    if [[ -z "$token" ]]; then
        return 1
    fi
    
    # Test token by checking repository access
    local response
    response=$(curl -f -sS -H "Authorization: Bearer $token" \
        "https://api.github.com/repos/$repo" 2>&1)
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "GitHub token validated successfully"
        return 0
    else
        if echo "$response" | grep -q "401"; then
            log_error "GitHub token invalid or expired"
        elif echo "$response" | grep -q "404"; then
            log_error "GitHub token lacks access to repository: $repo"
        else
            log_error "GitHub token validation failed: $response"
        fi
        return 1
    fi
}

# Setup GitHub token interactively
setup_github_token() {
    local token
    local expiry_date
    
    echo
    echo "=========================================="
    echo "  GitHub Private Repository Access Setup"
    echo "=========================================="
    echo
    echo "This installer requires access to a private GitHub repository."
    echo "You'll need a Fine-Grained Personal Access Token with:"
    echo "  - Repository: Personal_Contained_Pihole"
    echo "  - Permissions: Contents (Read-only)"
    echo
    echo "Generate token at: https://github.com/settings/tokens?type=beta"
    echo
    read -rp "Enter GitHub token (or press Enter to skip): " token
    
    if [[ -z "$token" ]]; then
        log_warning "Skipping GitHub token setup. Updates may not work for private repositories."
        return 1
    fi
    
    # Validate token
    log "Validating GitHub token..."
    if ! validate_github_token "$token"; then
        log_error "Token validation failed. Setup cancelled."
        return 1
    fi
    
    # Ask for expiration date (optional)
    echo
    read -rp "Enter token expiration date (YYYY-MM-DD, or press Enter to skip): " expiry_date
    
    # Store token securely
    mkdir -p "$(dirname "$GITHUB_TOKEN_FILE")"
    echo "$token" > "$GITHUB_TOKEN_FILE"
    chmod 600 "$GITHUB_TOKEN_FILE"
    chown root:root "$GITHUB_TOKEN_FILE"
    
    log_success "GitHub token stored securely at: $GITHUB_TOKEN_FILE"
    
    # Store expiration date if provided
    if [[ -n "$expiry_date" ]]; then
        echo "$expiry_date" > "$GITHUB_TOKEN_EXPIRY_FILE"
        chmod 600 "$GITHUB_TOKEN_EXPIRY_FILE"
        chown root:root "$GITHUB_TOKEN_EXPIRY_FILE"
        log_success "Token expiration date set: $expiry_date"
    fi
    
    # Test download
    echo
    log "Testing authenticated download..."
    local test_url="https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/README.md"
    local test_dest="/tmp/github_auth_test_$$"
    
    if download_authenticated_file "$test_url" "$test_dest"; then
        log_success "Authentication test successful!"
        rm -f "$test_dest"
        return 0
    else
        log_error "Authentication test failed"
        rm -f "$test_dest"
        return 1
    fi
}

# Export functions for use in other scripts
export -f github_token_exists
export -f get_github_token
export -f check_token_expiration
export -f download_authenticated_file
export -f validate_github_token
export -f setup_github_token
