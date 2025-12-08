#!/bin/bash
#
# Pi-hole Update Manager
# File: updates.sh
# Created: 2020-07-25
# Last Modified: 2025-12-07
# Version: 2.0.0
#
# Description: Automated update manager for Pi-hole configurations
#              Downloads and deploys adlists, regex rules, allow/block lists
#              Supports both Pi-hole v5 and v6 with GPG encryption
#
# Following Universal Constants:
# - UC-001: Code clarity over cleverness
# - UC-002: Meaningful naming conventions
# - UC-003: ISO 8601 date format
# - UC-004: Professional communication
#
# Usage: sudo bash updates.sh [COMMAND] [OPTIONS]
#
# Commands:
#   refresh              Update all script files from repository
#   full-update          Complete system and Pi-hole update (default)
#   allow-update         Update only allow/whitelist configurations
#   block-regex-update   Update only regex block lists
#   quick-update         Update Pi-hole configs without system upgrade
#   purge-and-update     Clear all Pi-hole lists and rebuild from scratch
#   help                 Show detailed help message
#
# Options:
#   --verbose            Enable verbose logging
#   --debug              Enable debug mode (includes verbose + error tracking)
#   --no-reboot          Skip automatic reboot check
#
# Examples:
#   sudo bash updates.sh full-update
#   sudo bash updates.sh allow-update --verbose
#   sudo bash updates.sh purge-and-update --no-reboot
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#======================================================================================
# CONFIGURATION
#======================================================================================

readonly FINISHED=/scripts/Finished
readonly TEMPDIR=/scripts/temp
readonly PIDIR=/etc/pihole
readonly CONFIG=/scripts/Finished/CONFIG
readonly GRAVITY_DB="/etc/pihole/gravity.db"
readonly LOGFILE=/var/log/pihole-updates.log

# Load configuration files
Type=$(<"$CONFIG/type.conf")
test_system=$(<"$CONFIG/test.conf") 
is_cloudflared=$(<"$CONFIG/dns_type.conf")
version=$(<"$CONFIG/ver.conf")

# GitHub base URLs
readonly GH_RAW="https://raw.githubusercontent.com/IcedComputer"
readonly REPO_BASE="${GH_RAW}/Personal_Contained_Pihole/master"
readonly REPO_BASE_BINARY="https://github.com/IcedComputer/Personal_Contained_Pihole/raw/refs/heads/main"

# Options
VERBOSE=0
NO_REBOOT=0
DEBUG=0

# Global error tracking
declare -a DOWNLOAD_ERRORS=()
declare -a GPG_ERRORS=()
declare -a SQL_ERRORS=()
declare -a DEPLOY_ERRORS=()

#======================================================================================
# UTILITY FUNCTIONS
#======================================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

log_success() {
    printf "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] ✓ %s\033[0m\n" "$*" | tee -a "$LOGFILE"
}

log_error() {
    printf "\033[1;31m[$(date +'%Y-%m-%d %H:%M:%S')] ✗ ERROR: %s\033[0m\n" "$*" | tee -a "$LOGFILE"
}

log_warning() {
    printf "\033[0;33m[$(date +'%Y-%m-%d %H:%M:%S')] ⚠ WARNING: %s\033[0m\n" "$*" | tee -a "$LOGFILE"
}

verbose_log() {
    [[ $VERBOSE -eq 1 ]] && log "$*"
}

debug_log() {
    if [[ $DEBUG -eq 1 ]]; then
        echo "[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
    fi
}

debug_success() {
    if [[ $DEBUG -eq 1 ]]; then
        printf "\033[0;32m[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] ✓ %s\033[0m\n" "$*" | tee -a "$LOGFILE"
    fi
}

debug_error() {
    if [[ $DEBUG -eq 1 ]]; then
        printf "\033[1;31m[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] ✗ %s\033[0m\n" "$*" | tee -a "$LOGFILE"
    fi
}

check_network() {
    debug_log "Checking network connectivity..."
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log "ERROR: No network connectivity detected"
        return 1
    fi
    if ! ping -c 1 raw.githubusercontent.com &> /dev/null; then
        log "ERROR: Cannot reach GitHub (raw.githubusercontent.com)"
        return 1
    fi
    debug_log "Network connectivity OK"
    return 0
}

check_gpg_keys() {
    debug_log "Checking GPG configuration..."
    
    if ! command -v gpg &> /dev/null; then
        log "ERROR: GPG is not installed"
        log "ERROR: Install with: apt-get install gnupg"
        return 1
    fi
    
    local key_count=$(gpg --list-keys 2>/dev/null | grep -c "^pub" || echo "0")
    debug_log "GPG public keys available: $key_count"
    
    local secret_key_count=$(gpg --list-secret-keys 2>/dev/null | grep -c "^sec" || echo "0")
    debug_log "GPG secret keys available: $secret_key_count"
    
    if [[ "$secret_key_count" -eq 0 ]]; then
        log "WARNING: No GPG secret keys found"
        log "WARNING: Encrypted file decryption will fail"
        log "WARNING: Import your private key with: gpg --import /path/to/private.key"
        return 1
    fi
    
    debug_log "GPG configuration OK"
    return 0
}

check_and_import_new_keys() {
    log "Checking for new GPG public keys..."
    debug_log "check_and_import_new_keys: Starting"
    
    local keys_cache_dir="$CONFIG/public-gpg-keys"
    mkdir -p "$keys_cache_dir"
    
    # Get list of .gpg files from GitHub repository
    debug_log "Fetching key list from GitHub..."
    
    # Try to get directory listing (GitHub API would be better, but this works)
    # We'll download each key and compare fingerprints
    local keys_to_check=(
        "encrypt.allow.gpg"
        "civic.allow.gpg"
        "financial.allow.gpg"
        "international.allow.gpg"
        "medical.allow.gpg"
        "tech.allow.gpg"
    )
    
    local imported_count=0
    local skipped_count=0
    local failed_count=0
    
    # Get currently imported key fingerprints
    local current_fingerprints=$(gpg --list-keys --fingerprint 2>/dev/null | grep -E "^[[:space:]]+Key fingerprint" | awk -F= '{print $2}' | tr -d ' ' || echo "")
    debug_log "Current GPG fingerprints in keyring: $(echo "$current_fingerprints" | wc -l) keys"
    
    # Check each potential key file
    for key_file in "${keys_to_check[@]}"; do
        local key_url="${REPO_BASE_BINARY}/installer/public-gpg-keys/${key_file}"
        local cache_path="$keys_cache_dir/${key_file}"
        
        debug_log "Checking key: $key_file"
        
        # Download key to cache
        if curl --tlsv1.3 --fail --location --connect-timeout 10 --max-time 30 \
            --silent -o "$cache_path" "$key_url" 2>/dev/null; then
            
            debug_success "Downloaded: $key_file"
            
            # Extract fingerprint from downloaded key (without importing)
            local new_fingerprint=$(gpg --with-colons --import-options show-only --import "$cache_path" 2>/dev/null | \
                grep "^fpr:" | cut -d: -f10 | head -n1)
            
            if [[ -z "$new_fingerprint" ]]; then
                log_warning "Could not extract fingerprint from $key_file"
                ((failed_count++))
                continue
            fi
            
            debug_log "Key fingerprint: $new_fingerprint"
            
            # Check if already imported
            if echo "$current_fingerprints" | grep -q "$new_fingerprint"; then
                debug_log "Key already imported: $key_file"
                ((skipped_count++))
            else
                # Import new key
                if gpg --import "$cache_path" 2>&1 | tee -a "$LOGFILE" >/dev/null; then
                    log_success "Imported new key: $key_file"
                    ((imported_count++))
                else
                    log_error "Failed to import: $key_file"
                    ((failed_count++))
                fi
            fi
        else
            # File doesn't exist on GitHub (not an error, just not available)
            debug_log "Key not found on GitHub: $key_file (this is normal if not using this key)"
        fi
    done
    
    # Summary
    if [[ $imported_count -gt 0 ]] || [[ $failed_count -gt 0 ]]; then
        log "GPG Key Update Summary:"
        log "  New keys imported: $imported_count"
        log "  Already imported: $skipped_count"
        if [[ $failed_count -gt 0 ]]; then
            log_warning "  Failed imports: $failed_count"
        fi
    else
        debug_log "No new GPG keys to import"
    fi
    
    debug_log "check_and_import_new_keys: Completed"
    return 0
}

print_banner() {
    local color="$1"
    local message="$2"
    
    case "$color" in
        green)
            printf '\033[0;32m%s\033[0m\n' "============================================"
            printf '\033[1;32m%s\033[0m\n' "$message"
            printf '\033[0;32m%s\033[0m\n' "============================================"
            ;;
        red)
            printf '\033[0;31m%s\033[0m\n' "============================================"
            printf '\033[1;31m%s\033[0m\n' "$message"
            printf '\033[0;31m%s\033[0m\n' "============================================"
            ;;
        yellow)
            printf '\033[0;33m%s\033[0m\n' "============================================"
            printf '\033[1;33m%s\033[0m\n' "$message"
            printf '\033[0;33m%s\033[0m\n' "============================================"
            ;;
    esac
}

show_error_summary() {
    local total_errors=0
    ((total_errors = ${#DOWNLOAD_ERRORS[@]} + ${#GPG_ERRORS[@]} + ${#SQL_ERRORS[@]} + ${#DEPLOY_ERRORS[@]}))
    
    if [[ $total_errors -eq 0 ]]; then
        print_banner green "✓ Update Completed Successfully - No Errors"
        return 0
    fi
    
    # Display big red error summary
    echo ""
    echo ""
    printf '\033[1;41;97m%s\033[0m\n' "╔══════════════════════════════════════════════════════════════════════════════╗"
    printf '\033[1;41;97m%s\033[0m\n' "║                                                                              ║"
    printf '\033[1;41;97m%s\033[0m\n' "║                        ⚠️  ERROR SUMMARY - ATTENTION REQUIRED ⚠️              ║"
    printf '\033[1;41;97m%s\033[0m\n' "║                                                                              ║"
    printf '\033[1;41;97m%s\033[0m\n' "║  Total Errors: $total_errors                                                        ║"
    printf '\033[1;41;97m%s\033[0m\n' "║                                                                              ║"
    printf '\033[1;41;97m%s\033[0m\n' "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [[ ${#DOWNLOAD_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "📥 DOWNLOAD FAILURES (${#DOWNLOAD_ERRORS[@]}):" 
        for error in "${DOWNLOAD_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#GPG_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "🔐 GPG DECRYPTION FAILURES (${#GPG_ERRORS[@]}):"
        for error in "${GPG_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#SQL_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "💾 DATABASE FAILURES (${#SQL_ERRORS[@]}):"
        for error in "${SQL_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#DEPLOY_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "📦 DEPLOYMENT FAILURES (${#DEPLOY_ERRORS[@]}):"
        for error in "${DEPLOY_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    printf '\033[1;33m%s\033[0m\n' "💡 RECOMMENDED ACTIONS:"
    printf '\033[0;33m%s\033[0m\n' "   1. Run with --debug flag for detailed diagnostics"
    printf '\033[0;33m%s\033[0m\n' "   2. Check network connectivity to GitHub"
    printf '\033[0;33m%s\033[0m\n' "   3. Review log file: $LOGFILE"
    printf '\033[0;33m%s\033[0m\n' "   4. Verify GPG keys are imported (for GPG errors)"
    printf '\033[0;33m%s\033[0m\n' "   5. Check disk space and permissions"
    echo ""
    
    return 1
}

download_file() {
    local url="$1"
    local output="$2"
    local retries=3
    local error_log="$TEMPDIR/curl_error_$$.log"
    
    debug_log "Starting download: $url"
    debug_log "Output destination: $output"
    
    for i in $(seq 1 $retries); do
        debug_log "Download attempt $i of $retries for: $url"
        
        if curl --tlsv1.3 --fail --location --connect-timeout 10 --max-time 60 \
            --show-error --silent -o "$output" "$url" 2>"$error_log"; then
            verbose_log "Downloaded: $url -> $output"
            debug_success "Downloaded: $url ($(stat -c%s "$output" 2>/dev/null || echo 'unknown') bytes)"
            rm -f "$error_log"
            return 0
        fi
        
        local error_msg=$(cat "$error_log" 2>/dev/null || echo "Unknown error")
        log_warning "Download attempt $i failed for: $url"
        debug_error "Download failed: $error_msg"
        debug_log "Waiting 3 seconds before retry..."
        sleep 3
    done
    
    log_error "Failed to download after $retries attempts"
    log_error "URL: $url"
    log_error "Output: $output"
    if [[ -f "$error_log" ]]; then
        log_error "$(cat "$error_log")"
        rm -f "$error_log"
    fi
    
    # Track error globally
    DOWNLOAD_ERRORS+=("DOWNLOAD FAILED: $url")
    
    return 1
}

download_gpg_file() {
    local url="$1"
    local output_base="$2"
    local gpg_error="$TEMPDIR/gpg_error_$$.log"
    
    debug_log "Downloading GPG file: $url"
    download_file "$url" "${output_base}.gpg" || return 1
    
    # Check if GPG file was actually downloaded and has content
    if [[ ! -f "${output_base}.gpg" ]]; then
        log "ERROR: GPG file was not downloaded: ${output_base}.gpg"
        return 1
    fi
    
    local gpg_size=$(stat -c%s "${output_base}.gpg" 2>/dev/null || echo "0")
    debug_log "Downloaded GPG file size: $gpg_size bytes"
    
    if [[ "$gpg_size" -eq 0 ]]; then
        log "ERROR: Downloaded GPG file is empty: ${output_base}.gpg"
        return 1
    fi
    
    debug_log "Decrypting: ${output_base}.gpg"
    debug_log "GPG command: gpg --batch --yes --decrypt ${output_base}.gpg"
    
    if ! gpg --batch --yes --decrypt "${output_base}.gpg" > "$output_base" 2>"$gpg_error"; then
        log_error "Failed to decrypt ${output_base}.gpg"
        log_error "GPG file size: $gpg_size bytes"
        if [[ -f "$gpg_error" ]]; then
            log_error "GPG output: $(cat "$gpg_error")"
            # Check for common GPG errors
            if grep -q "no secret key" "$gpg_error"; then
                log "ERROR: GPG key not found. You may need to import the decryption key."
                log "ERROR: Run: gpg --list-keys to see available keys"
            elif grep -q "decryption failed" "$gpg_error"; then
                log "ERROR: File may be corrupted or encrypted with different key"
            fi
        else
            log "ERROR: No GPG error output available"
        fi
        log "ERROR: Keeping ${output_base}.gpg for manual inspection"
        
        # Track error globally
        GPG_ERRORS+=("GPG DECRYPT FAILED: ${output_base}.gpg")
        
        return 1
    fi
    
    # Check if decrypted file has content
    local decrypted_size=$(stat -c%s "$output_base" 2>/dev/null || echo "0")
    debug_log "Decrypted file size: $decrypted_size bytes"
    
    if [[ "$decrypted_size" -eq 0 ]]; then
        log "ERROR: Decrypted file is empty: $output_base"
        return 1
    fi
    
    sed -i -e "s/\r//g" "$output_base"
    rm -f "${output_base}.gpg" "$gpg_error"
    verbose_log "Decrypted and cleaned: $output_base"
    debug_success "Decrypted: $output_base ($decrypted_size bytes)"
}

parallel_download() {
    local -n urls=$1
    local pids=()
    local pid_urls=()
    local failed=0
    
    debug_log "Starting ${#urls[@]} parallel downloads"
    
    for item in "${urls[@]}"; do
        IFS='|' read -r url output <<< "$item"
        debug_log "Queuing download: $url"
        download_file "$url" "$output" &
        local pid=$!
        pids+=("$pid")
        pid_urls[$pid]="$url|$output"
    done
    
    # Wait for all downloads to complete and track failures
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            IFS='|' read -r failed_url failed_output <<< "${pid_urls[$pid]}"
            log_error "Download failed for URL: $failed_url"
            log_error "Expected output: $failed_output"
            ((failed++))
        fi
    done
    
    if [[ $failed -gt 0 ]]; then
        log_warning "$failed out of ${#urls[@]} downloads failed"
        return 1
    fi
    
    debug_success "All ${#urls[@]} parallel downloads completed successfully"
    
    debug_log "All parallel downloads completed successfully"
    return 0
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - PI-HOLE VERSION 5
#======================================================================================

update_allow_regex_v5() {
    local file="$TEMPDIR/final.allow.regex.temp"
    
    debug_log "update_allow_regex_v5: Starting function"
    debug_log "update_allow_regex_v5: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No allow regex file found, skipping"
        debug_log "update_allow_regex_v5: File does not exist, skipping"
        return 0
    fi
    
    debug_log "update_allow_regex_v5: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow Regex List (v5)"
    
    local count=0
    local temp_sql="$TEMPDIR/allow_regex_insert.sql"
    debug_log "update_allow_regex_v5: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 2 = regex whitelist, enabled = 1
        # Escape single quotes for SQL
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (2, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow regex: $pattern"
    done < "$file"
    
    debug_log "update_allow_regex_v5: Queued $count regex patterns"
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_allow_regex_v5: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_regex_v5_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log "ERROR: Failed to insert allow regex"
        if [[ -f "$sql_error" ]]; then
            log "ERROR: SQL error: $(cat "$sql_error")"
            rm -f "$sql_error"
        fi
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    log_success "Added $count allow regex patterns via direct SQL (fast)"
    debug_success "update_allow_regex_v5: Completed successfully"
    print_banner yellow "Completed Allow Regex List"
}

update_allow_v5() {
    local file="$PIDIR/whitelist.txt"
    
    debug_log "update_allow_v5: Starting function"
    debug_log "update_allow_v5: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No whitelist file found, skipping"
        debug_log "update_allow_v5: File does not exist: $file"
        return 0
    fi
    
    debug_log "update_allow_v5: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow List (v5)"
    
    # Validate database exists
    if [[ ! -f "$GRAVITY_DB" ]]; then
        log "ERROR: Gravity database not found: $GRAVITY_DB"
        debug_log "update_allow_v5: Database missing, aborting"
        return 1
    fi
    debug_log "update_allow_v5: Database exists: $GRAVITY_DB"
    
    # Use direct SQL INSERT for massive performance improvement
    # This is 50-100x faster than calling pihole -w for each domain
    local count=0
    local temp_sql="$TEMPDIR/allow_insert.sql"
    debug_log "update_allow_v5: Creating SQL transaction file: $temp_sql"
    
    # Start SQL transaction
    echo "BEGIN TRANSACTION;" > "$temp_sql" || {
        log "ERROR: Failed to create SQL transaction file: $temp_sql"
        debug_log "update_allow_v5: Cannot write to temp directory"
        return 1
    }
    
    debug_log "update_allow_v5: Reading domains from $file"
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        # Type 0 = exact whitelist, enabled = 1
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (0, '${domain}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow domain: $domain"
    done < "$file"
    
    debug_log "update_allow_v5: Queued $count domains for insertion"
    echo "COMMIT;" >> "$temp_sql"
    
    local sql_size=$(stat -c%s "$temp_sql" 2>/dev/null || echo '0')
    debug_log "update_allow_v5: SQL file size: $sql_size bytes"
    debug_log "update_allow_v5: Executing SQL transaction"
    
    # Execute all inserts in one transaction
    local sql_error="$TEMPDIR/sql_error_v5_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log "ERROR: Failed to insert allow list"
        if [[ -f "$sql_error" ]]; then
            local error_msg=$(cat "$sql_error")
            log "ERROR: SQL error: $error_msg"
            SQL_ERRORS+=("SQL FAILED (v5 allow): $error_msg")
            rm -f "$sql_error"
        else
            SQL_ERRORS+=("SQL FAILED (v5 allow): Unknown error")
        fi
        debug_log "update_allow_v5: SQL execution failed, keeping $temp_sql for inspection"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    log_success "Added $count allow domains via direct SQL (fast)"
    debug_success "update_allow_v5: Completed successfully"
    print_banner yellow "Completed Allow List"
}

update_regex_v5() {
    local file="$PIDIR/regex.list"
    
    debug_log "update_regex_v5: Starting function"
    debug_log "update_regex_v5: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No regex block file found, skipping"
        debug_log "update_regex_v5: File does not exist, skipping"
        return 0
    fi
    
    debug_log "update_regex_v5: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Regex Block List (v5)"
    
    local count=0
    local temp_sql="$TEMPDIR/block_regex_insert.sql"
    debug_log "update_regex_v5: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 3 = regex blacklist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (3, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued block regex: $pattern"
    done < "$file"
    
    debug_log "update_regex_v5: Queued $count block regex patterns"
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_regex_v5: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_block_v5_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log "ERROR: Failed to insert block regex"
        if [[ -f "$sql_error" ]]; then
            log "ERROR: SQL error: $(cat "$sql_error")"
            rm -f "$sql_error"
        fi
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    log_success "Added $count block regex patterns via direct SQL (fast)"
    debug_success "update_regex_v5: Completed successfully"
    print_banner yellow "Completed Regex Block List"
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - PI-HOLE VERSION 6
#======================================================================================

update_allow_regex_v6() {
    local file="$TEMPDIR/final.allow.regex.temp"
    
    debug_log "update_allow_regex_v6: Starting function"
    debug_log "update_allow_regex_v6: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No allow regex file found, skipping"
        debug_log "update_allow_regex_v6: File does not exist, skipping"
        return 0
    fi
    
    debug_log "update_allow_regex_v6: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow Regex List (v6)"
    
    local count=0
    local temp_sql="$TEMPDIR/allow_regex_insert.sql"
    debug_log "update_allow_regex_v6: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 2 = regex whitelist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (2, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow regex: $pattern"
    done < "$file"
    
    debug_log "update_allow_regex_v6: Queued $count regex patterns"
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_allow_regex_v6: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_regex_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log "ERROR: Failed to insert allow regex"
        if [[ -f "$sql_error" ]]; then
            log "ERROR: SQL error: $(cat "$sql_error")"
            rm -f "$sql_error"
        fi
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    log_success "Added $count allow regex patterns via direct SQL (fast)"
    debug_success "update_allow_regex_v6: Completed successfully"
    print_banner yellow "Completed Allow Regex List"
}

update_allow_v6() {
    local file="$PIDIR/whitelist.txt"
    
    debug_log "update_allow_v6: Starting function"
    debug_log "update_allow_v6: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No whitelist file found, skipping"
        debug_log "update_allow_v6: File does not exist: $file"
        return 0
    fi
    
    debug_log "update_allow_v6: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow List (v6)"
    
    # Validate database exists
    if [[ ! -f "$GRAVITY_DB" ]]; then
        log "ERROR: Gravity database not found: $GRAVITY_DB"
        debug_log "update_allow_v6: Database missing, aborting"
        return 1
    fi
    debug_log "update_allow_v6: Database exists: $GRAVITY_DB"
    
    # Use direct SQL INSERT for massive performance improvement
    local count=0
    local temp_sql="$TEMPDIR/allow_insert.sql"
    debug_log "update_allow_v6: Creating SQL transaction file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql" || {
        log "ERROR: Failed to create SQL transaction file: $temp_sql"
        debug_log "update_allow_v6: Cannot write to temp directory"
        return 1
    }
    
    debug_log "update_allow_v6: Reading domains from $file"
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        # Type 0 = exact whitelist, enabled = 1
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (0, '${domain}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow domain: $domain"
    done < "$file"
    
    debug_log "update_allow_v6: Queued $count domains for insertion"
    echo "COMMIT;" >> "$temp_sql"
    
    local sql_size=$(stat -c%s "$temp_sql" 2>/dev/null || echo '0')
    debug_log "update_allow_v6: SQL file size: $sql_size bytes"
    debug_log "update_allow_v6: Executing SQL transaction"
    
    local sql_error="$TEMPDIR/sql_error_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log "ERROR: Failed to insert allow list"
        if [[ -f "$sql_error" ]]; then
            log "ERROR: SQL error: $(cat "$sql_error")"
            rm -f "$sql_error"
        fi
        debug_log "update_allow_v6: SQL execution failed, keeping $temp_sql for inspection"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    log_success "Added $count allow domains via direct SQL (fast)"
    debug_success "update_allow_v6: Completed successfully"
    print_banner yellow "Completed Allow List"
}

update_regex_v6() {
    local file="$PIDIR/regex.list"
    
    debug_log "update_regex_v6: Starting function"
    debug_log "update_regex_v6: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No regex block file found, skipping"
        debug_log "update_regex_v6: File does not exist, skipping"
        return 0
    fi
    
    debug_log "update_regex_v6: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Regex Block List (v6)"
    
    local count=0
    local temp_sql="$TEMPDIR/block_regex_insert.sql"
    debug_log "update_regex_v6: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 3 = regex blacklist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (3, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued block regex: $pattern"
    done < "$file"
    
    debug_log "update_regex_v6: Queued $count block regex patterns"
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_regex_v6: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_block_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log "ERROR: Failed to insert block regex"
        if [[ -f "$sql_error" ]]; then
            log "ERROR: SQL error: $(cat "$sql_error")"
            rm -f "$sql_error"
        fi
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    log_success "Added $count block regex patterns via direct SQL (fast)"
    debug_success "update_regex_v6: Completed successfully"
    print_banner yellow "Completed Regex Block List"
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - VERSION INDEPENDENT
#======================================================================================

update_adlists() {
    local file="$PIDIR/adlists.list"
    
    [[ ! -f "$file" ]] && { log "No adlists file found, skipping"; return 0; }
    
    print_banner green "Starting Adlist Database Update"
    
    # Clear existing adlist database
    sqlite3 "$GRAVITY_DB" "DELETE FROM adlist" 2>/dev/null || {
        log "ERROR: Failed to clear adlist database"
        return 1
    }
    
    # Format and prepare adlist
    grep -v '#' "$file" | grep "/" | sort | uniq > "$TEMPDIR/formatted_adlist.temp" || {
        log "WARNING: No valid adlists found"
        return 0
    }
    
    # Insert URLs into database
    local count=0
    local id=1
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        sqlite3 "$GRAVITY_DB" "INSERT INTO adlist (id, address, enabled) VALUES($id, '$url', 1)" 2>/dev/null || {
            log "WARNING: Failed to insert adlist: $url"
            continue
        }
        ((count++))
        ((id++))
        verbose_log "Added adlist: $url"
    done < "$TEMPDIR/formatted_adlist.temp"
    
    log "Added $count adlists to database"
    print_banner yellow "Completed Adlist Database Update"
}

#======================================================================================
# DATABASE UPDATE DISPATCHER FUNCTIONS
#======================================================================================

update_allow() {
    log "Updating allow lists..."
    debug_log "update_allow: Dispatching to version $version"
    case "$version" in
        5) 
            debug_log "update_allow: Calling update_allow_v5"
            update_allow_v5
            local result=$?
            debug_log "update_allow: update_allow_v5 returned: $result"
            return $result
            ;;
        6) 
            debug_log "update_allow: Calling update_allow_v6"
            update_allow_v6
            local result=$?
            debug_log "update_allow: update_allow_v6 returned: $result"
            return $result
            ;;
        *) 
            log "ERROR: Unknown Pi-hole version: $version"
            debug_log "update_allow: Invalid version detected"
            return 1
            ;;
    esac
}

update_allow_regex() {
    log "Updating allow regex..."
    debug_log "update_allow_regex: Dispatching to version $version"
    case "$version" in
        5) 
            debug_log "update_allow_regex: Calling update_allow_regex_v5"
            update_allow_regex_v5
            local result=$?
            debug_log "update_allow_regex: update_allow_regex_v5 returned: $result"
            return $result
            ;;
        6) 
            debug_log "update_allow_regex: Calling update_allow_regex_v6"
            update_allow_regex_v6
            local result=$?
            debug_log "update_allow_regex: update_allow_regex_v6 returned: $result"
            return $result
            ;;
        *) 
            log "ERROR: Unknown Pi-hole version: $version"
            debug_log "update_allow_regex: Invalid version detected"
            return 1
            ;;
    esac
}

update_block_regex() {
    log "Updating block regex..."
    debug_log "update_block_regex: Dispatching to version $version"
    case "$version" in
        5) 
            debug_log "update_block_regex: Calling update_regex_v5"
            update_regex_v5
            local result=$?
            debug_log "update_block_regex: update_regex_v5 returned: $result"
            return $result
            ;;
        6) 
            debug_log "update_block_regex: Calling update_regex_v6"
            update_regex_v6
            local result=$?
            debug_log "update_block_regex: update_regex_v6 returned: $result"
            return $result
            ;;
        *) 
            log "ERROR: Unknown Pi-hole version: $version"
            debug_log "update_block_regex: Invalid version detected"
            return 1
            ;;
    esac
}

#======================================================================================
# DATABASE UPDATE WRAPPER FUNCTIONS
#======================================================================================

update_pihole_database() {
    log "=== Starting full database update ==="
    log "Pi-hole version: $version"
    debug_log "update_pihole_database: Function called"
    debug_log "update_pihole_database: GRAVITY_DB=$GRAVITY_DB"
    debug_log "update_pihole_database: PIDIR=$PIDIR"
    debug_log "update_pihole_database: TEMPDIR=$TEMPDIR"
    
    debug_log "update_pihole_database: Step 1 - Calling update_allow"
    update_allow || {
        log "ERROR: update_allow failed"
        debug_log "update_pihole_database: update_allow returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 1 complete"
    
    debug_log "update_pihole_database: Step 2 - Calling update_allow_regex"
    update_allow_regex || {
        log "ERROR: update_allow_regex failed"
        debug_log "update_pihole_database: update_allow_regex returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 2 complete"
    
    debug_log "update_pihole_database: Step 3 - Calling update_adlists"
    update_adlists || {
        log "ERROR: update_adlists failed"
        debug_log "update_pihole_database: update_adlists returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 3 complete"
    
    debug_log "update_pihole_database: Step 4 - Calling update_block_regex"
    update_block_regex || {
        log "ERROR: update_block_regex failed"
        debug_log "update_pihole_database: update_block_regex returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 4 complete"
    
    log "=== Full database update completed ==="
    debug_log "update_pihole_database: All steps completed successfully"
}

update_pihole_database_allow_only() {
    log "=== Starting allow list database update ==="
    log "Pi-hole version: $version"
    
    update_allow
    update_allow_regex
    
    log "=== Allow list database update completed ==="
}

update_pihole_database_regex_only() {
    log "=== Starting regex block database update ==="
    log "Pi-hole version: $version"
    
    update_block_regex
    
    log "=== Regex block database update completed ==="
}

#======================================================================================
# CORE FUNCTIONS
#======================================================================================

system_update() {
    log "Starting system update..."
    apt-get update && apt-get dist-upgrade -y
    apt autoremove -y
    log "System update completed"
}

download_scripts() {
    log "Downloading configuration and scripts..."
    debug_log "download_scripts: Starting script downloads"
    
    local downloads=(
        "${REPO_BASE}/scripts/refresh.sh|$TEMPDIR/refresh.sh"
        "${REPO_BASE}/scripts/Research.sh|$TEMPDIR/Research.sh"
        "${REPO_BASE}/scripts/wireguard-manager.sh|$TEMPDIR/wireguard-manager.sh"
    )
    
    debug_log "download_scripts: Downloading ${#downloads[@]} files"
    if ! parallel_download downloads; then
        log_warning "Some script downloads failed, but continuing..."
        debug_log "download_scripts: parallel_download returned error, checking which files succeeded"
        
        # Log which files were successfully downloaded
        for item in "${downloads[@]}"; do
            IFS='|' read -r url output <<< "$item"
            if [[ -f "$output" ]]; then
                debug_success "download_scripts: $output exists"
            else
                log_warning "Failed to download: $output"
                debug_error "download_scripts: $output does not exist"
            fi
        done
    else
        debug_success "All ${#downloads[@]} scripts downloaded successfully"
    fi
    
    debug_log "download_scripts: Making scripts executable"
    chmod 755 $TEMPDIR/*.sh 2>/dev/null || true
    debug_log "download_scripts: Completed"
}

download_full_config() {
    log "Downloading full configuration..."
    
    # Download adlists
    download_file "${REPO_BASE}/lists/adlists/main.adlist.list" "$TEMPDIR/adlists.list" || {
        log "ERROR: Failed to download adlists"
        return 1
    }
    
    # Download regex lists in parallel
    local regex_files=(
        "${REPO_BASE}/lists/regex/main.regex|$TEMPDIR/main.regex"
        "${REPO_BASE}/lists/regex/oTLD.regex|$TEMPDIR/oTLD.regex"
        "${REPO_BASE}/lists/regex/uslocal.regex|$TEMPDIR/uslocal.regex"
    )
    parallel_download regex_files || {
        log "ERROR: Failed to download regex files"
        return 1
    }
    
    # Clean line endings
    sed -i -e "s/\r//g" $TEMPDIR/*.regex 2>/dev/null || true
    
    # Download encrypted country regex
    download_gpg_file "${REPO_BASE_BINARY}/lists/regex/country.regex.gpg" "$TEMPDIR/country.regex" || {
        log "ERROR: Failed to download/decrypt country.regex.gpg"
        log "ERROR: This is likely a GPG key issue"
        return 1
    }
}

download_security_config() {
    log "Downloading security configuration..."
    debug_log "download_security_config: Starting"
    
    if ! download_file "${REPO_BASE}/lists/adlists/security_basic_adlist.list" "$TEMPDIR/adlists.list"; then
        log_error "Failed to download security adlist"
        touch "$TEMPDIR/adlists.list" || {
            log_error "Cannot create adlists.list"
            return 1
        }
    fi
    
    local security_files=(
        "${REPO_BASE}/lists/regex/basic_security.regex|$TEMPDIR/basic_security.regex"
        "${REPO_BASE}/lists/regex/oTLD.regex|$TEMPDIR/oTLD.regex"
    )
    
    debug_log "download_security_config: Downloading ${#security_files[@]} regex files"
    if ! parallel_download security_files; then
        log_warning "Some security regex downloads failed, continuing..."
        debug_log "download_security_config: Checking which files succeeded"
    else
        debug_success "All ${#security_files[@]} security regex files downloaded successfully"
    fi
    
    sed -i -e "s/\r//g" $TEMPDIR/*.regex 2>/dev/null || true
    
    # Download encrypted files
    debug_log "download_security_config: Downloading encrypted regex files"
    if ! download_gpg_file "${REPO_BASE_BINARY}/lists/regex/basic_country.regex.gpg" "$TEMPDIR/basic_country.regex"; then
        log_warning "Failed to download basic_country.regex.gpg, creating empty file"
        touch "$TEMPDIR/basic_country.regex" || log_error "Cannot create basic_country.regex"
    fi
    
    if ! download_gpg_file "${REPO_BASE_BINARY}/lists/regex/encrypted.regex.gpg" "$TEMPDIR/encrypted.regex"; then
        log_warning "Failed to download encrypted.regex.gpg, creating empty file"
        touch "$TEMPDIR/encrypted.regex" || log_error "Cannot create encrypted.regex"
    fi
    
    debug_log "download_security_config: Completed"
}

download_test_lists() {
    [[ "$test_system" != "yes" ]] && { debug_log "Test system disabled, skipping test lists"; return 0; }
    
    log "Downloading test lists..."
    debug_log "download_test_lists: Starting"
    
    if ! download_file "${REPO_BASE}/lists/test-files/trial.adlist.list" "$TEMPDIR/adlists.list.trial.temp"; then
        log_warning "Failed to download trial.adlist.list, creating empty file"
        touch "$TEMPDIR/adlists.list.trial.temp" || {
            log_error "Cannot create trial.adlist.list"
            return 1
        }
    fi
    
    debug_log "download_test_lists: Merging trial adlists with main adlists"
    cat "$TEMPDIR/adlists.list.trial.temp" "$TEMPDIR/adlists.list" 2>/dev/null | \
        grep -v "##" | sort | uniq > "$TEMPDIR/adlists.list.temp" || {
        log_warning "Failed to merge adlists, using original"
        cp "$TEMPDIR/adlists.list" "$TEMPDIR/adlists.list.temp" 2>/dev/null
    }
    mv "$TEMPDIR/adlists.list.temp" "$TEMPDIR/adlists.list" || log_warning "Failed to update adlists.list"
    
    if ! download_file "${REPO_BASE}/lists/test-files/test.regex" "$TEMPDIR/test.regex"; then
        log_warning "Failed to download test.regex, creating empty file"
        touch "$TEMPDIR/test.regex" || log_error "Cannot create test.regex"
    fi
    
    if ! download_gpg_file "${REPO_BASE_BINARY}/lists/test-files/test.allow.gpg" "$TEMPDIR/test.allow.temp"; then
        log_warning "Failed to download test.allow.gpg, creating empty file"
        touch "$TEMPDIR/test.allow.temp" || log_error "Cannot create test.allow.temp"
    fi
    
    if ! download_gpg_file "${REPO_BASE_BINARY}/lists/test-files/test.block.encrypt.gpg" "$TEMPDIR/test.block.encrypt.temp"; then
        log_warning "Failed to download test.block.encrypt.gpg, creating empty file"
        touch "$TEMPDIR/test.block.encrypt.temp" || log_error "Cannot create test.block.encrypt.temp"
    fi
    
    debug_log "download_test_lists: Completed"
}

download_public_allowlists() {
    log "Downloading public allow lists..."
    debug_log "download_public_allowlists: Starting"
    
    local allow_files=(
        "${REPO_BASE}/lists/allow/basic.allow|$TEMPDIR/basic.allow.temp"
        "${REPO_BASE}/lists/allow/adlist.allow|$TEMPDIR/adlist.allow.temp"
    )
    
    debug_log "download_public_allowlists: Downloading ${#allow_files[@]} files"
    if ! parallel_download allow_files; then
        log_warning "Some allow list downloads failed"
        debug_log "download_public_allowlists: parallel_download returned error"
        
        # Check which files exist
        for item in "${allow_files[@]}"; do
            IFS='|' read -r url output <<< "$item"
            if [[ ! -f "$output" ]]; then
                log_warning "Missing file: $output"
                debug_log "download_public_allowlists: Creating empty placeholder for $output"
                touch "$output" || log_error "Cannot create $output"
            fi
        done
    else
        debug_success "All ${#allow_files[@]} allow lists downloaded successfully"
    fi
    
    # Add newlines and copy local config
    echo " " >> "$TEMPDIR/basic.allow.temp" 2>/dev/null || log "WARNING: Cannot append to basic.allow.temp"
    echo " " >> "$TEMPDIR/adlist.allow.temp" 2>/dev/null || log "WARNING: Cannot append to adlist.allow.temp"
    cp "$CONFIG/perm_allow.conf" "$TEMPDIR/perm.allow.temp" 2>/dev/null || {
        debug_log "download_public_allowlists: perm_allow.conf not found or cannot copy"
        touch "$TEMPDIR/perm.allow.temp" || log "WARNING: Cannot create perm.allow.temp"
    }
    debug_log "download_public_allowlists: Completed"
}

download_security_allowlists() {
    log "Downloading security allow lists..."
    debug_log "download_security_allowlists: Starting"
    
    if ! download_file "${REPO_BASE}/lists/allow/security_only.allow" "$TEMPDIR/security_only.allow.temp"; then
        log "WARNING: Failed to download security_only.allow, creating empty file"
        touch "$TEMPDIR/security_only.allow.temp" || log "ERROR: Cannot create security_only.allow.temp"
    fi
    
    debug_log "download_security_allowlists: Completed"
}

download_encrypted_allowlists() {
    log "Downloading encrypted allow lists..."
    debug_log "download_encrypted_allowlists: Starting"
    
    local encrypted_lists=(
        encrypt financial civic international medical tech
    )
    
    local pids=()
    for list in "${encrypted_lists[@]}"; do
        debug_log "download_encrypted_allowlists: Downloading ${list}.allow.gpg"
        (
            if ! download_gpg_file "${REPO_BASE_BINARY}/lists/allow/${list}.allow.gpg" "$TEMPDIR/${list}.allow.temp"; then
                log "WARNING: Failed to download ${list}.allow.gpg, creating empty file"
                touch "$TEMPDIR/${list}.allow.temp" 2>/dev/null
            fi
        ) &
        pids+=("$!")
    done
    
    debug_log "download_encrypted_allowlists: Waiting for ${#pids[@]} downloads to complete"
    for pid in "${pids[@]}"; do
        wait "$pid" || debug_log "download_encrypted_allowlists: A download process failed (non-fatal)"
    done
    
    debug_log "download_encrypted_allowlists: Completed"
}

download_regex_allowlists() {
    log "Downloading regex allow lists..."
    debug_log "download_regex_allowlists: Starting"
    
    if ! download_file "${REPO_BASE}/lists/allow/regex.allow" "$TEMPDIR/regex.allow.regex.temp"; then
        log "WARNING: Failed to download regex.allow, creating empty file"
        touch "$TEMPDIR/regex.allow.regex.temp" || log "ERROR: Cannot create regex.allow.regex.temp"
    fi
    
    if ! cp "$CONFIG/allow_wild.conf" "$TEMPDIR/allow_wild.allow.regex.temp" 2>/dev/null; then
        debug_log "download_regex_allowlists: allow_wild.conf not found, creating empty file"
        touch "$TEMPDIR/allow_wild.allow.regex.temp" || log "WARNING: Cannot create allow_wild.allow.regex.temp"
    fi
    
    if ! download_gpg_file "${REPO_BASE_BINARY}/lists/allow/encrypt.regex.allow.gpg" "$TEMPDIR/encrypt.regex.allow.regex.temp"; then
        log "WARNING: Failed to download/decrypt encrypt.regex.allow.gpg, creating empty file"
        touch "$TEMPDIR/encrypt.regex.allow.regex.temp" || log "ERROR: Cannot create encrypt.regex.allow.regex.temp"
    fi
    
    debug_log "download_regex_allowlists: Completed"
}

download_encrypted_blocklists() {
    log "Downloading encrypted block lists..."
    debug_log "download_encrypted_blocklists: Starting"
    
    local block_lists=(
        custom propaganda spam media
    )
    
    local pids=()
    for list in "${block_lists[@]}"; do
        debug_log "download_encrypted_blocklists: Downloading ${list}.block.encrypt.gpg"
        (
            if ! download_gpg_file "${REPO_BASE_BINARY}/lists/blocks/${list}.block.encrypt.gpg" "$TEMPDIR/${list}.block.encrypt.temp"; then
                log "WARNING: Failed to download ${list}.block.encrypt.gpg, creating empty file"
                touch "$TEMPDIR/${list}.block.encrypt.temp" 2>/dev/null
            fi
        ) &
        pids+=("$!")
    done
    
    debug_log "download_encrypted_blocklists: Waiting for ${#pids[@]} downloads to complete"
    for pid in "${pids[@]}"; do
        wait "$pid" || debug_log "download_encrypted_blocklists: A download process failed (non-fatal)"
    done
    
    debug_log "download_encrypted_blocklists: Completed"
}

assemble_and_deploy() {
    log "Assembling and deploying configurations..."
    
    # Assemble final files
    cat $TEMPDIR/*.allow.regex.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.regex.temp"
    
    cat $TEMPDIR/*.allow.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.temp"
    
    cat $TEMPDIR/*.regex 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/regex.list"
    
    cat $TEMPDIR/*.block.encrypt.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$CONFIG/encrypt.list"
    
    # Deploy files
    debug_log "assemble_and_deploy: Deploying configuration files"
    mv "$TEMPDIR/regex.list" "$PIDIR/regex.list" || {
        log "WARNING: Failed to deploy regex.list"
        DEPLOY_ERRORS+=("DEPLOY FAILED: regex.list to $PIDIR/regex.list")
    }
    mv "$TEMPDIR/final.allow.temp" "$PIDIR/whitelist.txt" || {
        log "WARNING: Failed to deploy whitelist.txt"
        DEPLOY_ERRORS+=("DEPLOY FAILED: whitelist.txt to $PIDIR/whitelist.txt")
    }
    mv "$TEMPDIR/adlists.list" "$PIDIR/adlists.list" || {
        log "WARNING: Failed to deploy adlists.list"
        DEPLOY_ERRORS+=("DEPLOY FAILED: adlists.list to $PIDIR/adlists.list")
    }
    
    # CFconfig is now generated locally during installation, not downloaded
    debug_log "assemble_and_deploy: CFconfig generation handled by installer"
    
    # Deploy all downloaded scripts
    local scripts=(
        "refresh.sh"
        "Research.sh"
        "wireguard-manager.sh"
    )
    
    debug_log "assemble_and_deploy: Deploying scripts to $FINISHED"
    for script in "${scripts[@]}"; do
        if [[ -f "$TEMPDIR/$script" ]]; then
            chmod 755 "$TEMPDIR/$script"
            if mv "$TEMPDIR/$script" "$FINISHED/$script" 2>/dev/null; then
                debug_success "assemble_and_deploy: Deployed $script"
            else
                log_warning "Failed to deploy $script"
            fi
        else
            debug_log "assemble_and_deploy: $script not found, skipping"
        fi
    done
    
    # Update database directly (integrated functionality)
    debug_log "assemble_and_deploy: Starting database update"
    update_pihole_database
    debug_log "assemble_and_deploy: Completed"
}

assemble_and_deploy_regex_only() {
    log "Assembling and deploying regex configurations..."
    
    # Assemble only regex block lists
    cat $TEMPDIR/*.regex 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/regex.list"
    
    # Deploy regex file
    mv "$TEMPDIR/regex.list" "$PIDIR/regex.list"
    
    # Update database with regex only (integrated functionality)
    update_pihole_database_regex_only
}

restart_services() {
    log "Restarting Pi-hole services..."
    
    killall -SIGHUP pihole-FTL 2>/dev/null || true
    pihole restartdns
    pihole -g
    
    if [[ "$is_cloudflared" == "cloudflared" ]]; then
        systemctl restart cloudflared
        log "Cloudflared restarted"
    fi
}

cleanup() {
    log "Cleaning up temporary files..."
    rm -f $TEMPDIR/*.regex $TEMPDIR/*.temp $TEMPDIR/*.gpg 2>/dev/null || true
}

purge_database() {
    log "Purging Pi-hole database..."
    
    # Clear adlists
    sqlite3 "$GRAVITY_DB" "DELETE FROM adlist" 2>/dev/null || {
        log "ERROR: Failed to clear adlist table"
        return 1
    }
    log "Cleared adlist table"
    
    if [[ "$version" == "5" ]]; then
        log "Purging Pi-hole v5 lists..."
        
        # Purge existing regex list
        pihole --regex --nuke 2>/dev/null || log "WARNING: Failed to nuke regex list"
        
        # Purge existing wildcard deny list
        pihole --wild --nuke 2>/dev/null || log "WARNING: Failed to nuke wildcard deny list"
        
        # Purge existing allow list
        pihole -w --nuke 2>/dev/null || log "WARNING: Failed to nuke allow list"
        
        # Purge existing allow list regex
        pihole --white-regex --nuke 2>/dev/null || log "WARNING: Failed to nuke allow regex"
        
        # Purge existing deny list
        pihole -b --nuke 2>/dev/null || log "WARNING: Failed to nuke deny list"
        
        # Purge existing wildcard allow list
        pihole --white-wild --nuke 2>/dev/null || log "WARNING: Failed to nuke wildcard allow"
        
        log "Pi-hole v5 database purged"
        
    elif [[ "$version" == "6" ]]; then
        log "Purging Pi-hole v6 lists..."
        
        # Clear domainlist table
        sqlite3 "$GRAVITY_DB" "DELETE FROM domainlist;" 2>/dev/null || {
            log "ERROR: Failed to clear domainlist table"
            return 1
        }
        
        log "Pi-hole v6 database purged (domainlist table cleared)"
    else
        log "ERROR: Unknown Pi-hole version: $version"
        return 1
    fi
    
    log "Database purge completed successfully"
}

#======================================================================================
# COMMAND FUNCTIONS
#======================================================================================

cmd_refresh() {
    log "=== Starting script refresh ==="
    download_scripts
    
    # Deploy all scripts to final location with correct permissions
    local scripts=(
        "refresh.sh"
        "Research.sh"
        "wireguard-manager.sh"
    )
    
    local deployed=0
    local failed=0
    
    for script in "${scripts[@]}"; do
        if [[ -f "$TEMPDIR/$script" ]]; then
            chmod 755 "$TEMPDIR/$script"
            if mv "$TEMPDIR/$script" "$FINISHED/$script" 2>/dev/null; then
                log_success "Installed: $script"
                ((deployed++))
            else
                log_error "Failed to install: $script"
                ((failed++))
            fi
        else
            log_warning "Not downloaded: $script (skipping)"
        fi
    done
    
    log "Script refresh completed: $deployed deployed, $failed failed"
    
    # Show error summary
    show_error_summary
}

cmd_full_update() {
    log "=== Starting full update ==="
    debug_log "cmd_full_update: Comprehensive update with all components"
    
    # Check and import new GPG keys
    check_and_import_new_keys || log_warning "GPG key check had issues"
    
    # System update
    system_update || log_warning "System update had issues"
    
    # Download scripts
    download_scripts || log_warning "Script download had issues"
    
    # Download configurations based on type
    if [[ "$Type" == "security" ]]; then
        download_security_config || log_warning "Security config download had issues"
        download_security_allowlists || log_warning "Security allowlist download had issues"
    else
        download_full_config || log_warning "Full config download had issues"
        download_test_lists || log_warning "Test list download had issues"
    fi
    
    # Download all allow and block lists (comprehensive)
    download_public_allowlists || log_warning "Public allowlist download had issues"
    download_regex_allowlists || log_warning "Regex allowlist download had issues"
    download_encrypted_allowlists || log_warning "Encrypted allowlist download had issues"
    download_encrypted_blocklists || log_warning "Encrypted blocklist download had issues"
    
    # Deploy and update database
    assemble_and_deploy || {
        log_error "Assembly and deployment failed"
        show_error_summary
        return 1
    }
    
    # Restart services
    restart_services || log_warning "Service restart had issues"
    
    # Cleanup
    cleanup
    
    log "=== Full update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_allow_update() {
    log "=== Starting allow list update ==="
    
    if [[ "$Type" == "security" ]]; then
        download_security_allowlists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    
    # Assemble allow lists
    cat $TEMPDIR/*.allow.regex.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.regex.temp"
    
    cat $TEMPDIR/*.allow.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.temp"
    
    # Deploy allow lists
    mv "$TEMPDIR/final.allow.temp" "$PIDIR/whitelist.txt"
    
    # Update database with allow lists only (integrated functionality)
    update_pihole_database_allow_only
    
    restart_services
    cleanup
    
    log "=== Allow list update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_quick_update() {
    log "=== Starting quick update (no system upgrade) ==="
    
    download_scripts
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
        download_security_allowlists
    else
        download_full_config
        download_test_lists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    download_encrypted_blocklists
    
    assemble_and_deploy
    restart_services
    cleanup
    
    log "=== Quick update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_purge_and_update() {
    log "=== Starting purge and full update ==="
    log "WARNING: This will clear all existing Pi-hole lists and rebuild from scratch"
    
    # Check and import new GPG keys first
    check_and_import_new_keys || log_warning "GPG key check had issues"
    
    # Purge existing database
    purge_database || {
        log "ERROR: Database purge failed, aborting update"
        return 1
    }
    
    # Run full update to repopulate
    log "Starting full update to repopulate database..."
    system_update
    download_scripts
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
        download_security_allowlists
    else
        download_full_config
        download_test_lists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    download_encrypted_blocklists
    
    assemble_and_deploy
    restart_services
    cleanup
    
    log "=== Purge and full update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_block_regex_update() {
    log "=== Starting block regex update ==="
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
    else
        download_full_config
        download_test_lists
    fi
    
    assemble_and_deploy_regex_only
    restart_services
    cleanup
    
    log "=== Block regex update completed ==="
    
    # Show error summary
    show_error_summary
}

show_help() {
    cat << 'EOF'
Pi-hole Update Script - Fully Integrated & Optimized Version

DESCRIPTION:
    Combines update/download functionality with database management in a single script.
    No separate database update script needed - all functionality is integrated.

USAGE:
    ./updates.sh [command] [options]

COMMANDS:
    refresh             Update all script files from repository
    full-update         Complete system and Pi-hole update (default)
    allow-update        Update only allow/whitelist configurations
    block-regex-update  Update only regex block lists
    quick-update        Update Pi-hole configs without system upgrade
    purge-and-update    Clear all Pi-hole lists and rebuild from scratch
    help                Show this help message

OPTIONS:
    --verbose       Enable verbose logging
    --debug         Enable debug mode (includes verbose + detailed error tracking)
    --no-reboot     Skip automatic reboot check

EXAMPLES:
    # Full update (default behavior)
    ./updates.sh full-update

    # Update only allow lists
    ./updates.sh allow-update

    # Update only block regex lists
    ./updates.sh block-regex-update

    # Purge all lists and rebuild (use when lists are corrupted)
    ./updates.sh purge-and-update

    # Refresh scripts with verbose output
    ./updates.sh refresh --verbose

CRON EXAMPLES:
    # Daily full update at 3 AM
    0 3 * * * /scripts/Finished/updates.sh full-update >> /var/log/pihole-cron.log 2>&1

    # Update allow lists every 6 hours
    0 */6 * * * /scripts/Finished/updates.sh allow-update

    # Update block regex lists every 4 hours
    0 */4 * * * /scripts/Finished/updates.sh block-regex-update

    # Refresh scripts weekly on Sunday at 2 AM
    0 2 * * 0 /scripts/Finished/updates.sh refresh

    # Quick update twice daily
    0 8,20 * * * /scripts/Finished/updates.sh quick-update

    # Monthly purge and rebuild (first Sunday at 4 AM)
    0 4 1-7 * 0 /scripts/Finished/updates.sh purge-and-update

NOTES:
    - Automatically detects Pi-hole version (5 or 6)
    - All database updates are handled internally
    - Logs to /var/log/pihole-updates.log

EOF
}

#======================================================================================
# MAIN EXECUTION
#======================================================================================

main() {
    # Parse options
    local command="${1:-full-update}"
    shift || true
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose)
                VERBOSE=1
                log "Verbose mode enabled"
                ;;
            --debug)
                DEBUG=1
                VERBOSE=1
                log "Debug mode enabled (includes verbose)"
                ;;
            --no-reboot)
                NO_REBOOT=1
                ;;
            *)
                log "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
    
    # Create temp directory if needed
    mkdir -p "$TEMPDIR"
    
    # Check network connectivity if downloading
    if [[ "$command" != "help" ]] && [[ "$command" != "--help" ]] && [[ "$command" != "-h" ]]; then
        check_network || {
            log "ERROR: Network check failed, cannot proceed with $command"
            exit 1
        }
        
        # Check GPG configuration for commands that need decryption
        if [[ "$command" == "full-update" ]] || [[ "$command" == "quick-update" ]] || [[ "$command" == "purge-and-update" ]]; then
            check_gpg_keys || {
                log "ERROR: GPG check failed - encrypted files cannot be decrypted"
                log "ERROR: Either import your GPG private key or skip encrypted files"
                exit 1
            }
        fi
    fi
    
    # Execute command
    case "$command" in
        refresh)
            cmd_refresh
            ;;
        full-update)
            cmd_full_update
            ;;
        allow-update)
            cmd_allow_update
            ;;
        block-regex-update)
            cmd_block_regex_update
            ;;
        quick-update)
            cmd_quick_update
            ;;
        purge-and-update)
            cmd_purge_and_update
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            log "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
