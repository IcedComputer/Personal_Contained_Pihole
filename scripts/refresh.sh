#!/bin/bash
#
# Script Refresh Manager
# File: refresh.sh
# Created: 2020-07-25
# Last Modified: 2025-12-07
# Version: 1.0.0
#
# Description: Updates management scripts from repository
#              Downloads latest versions of updates.sh and Research.sh
#              Ensures local scripts are current
#
# Following Universal Constants:
# - UC-001: Code clarity over cleverness
# - UC-002: Meaningful naming conventions
# - UC-003: ISO 8601 date format
# - UC-004: Professional communication
#
# Usage: sudo bash refresh.sh
#

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

readonly FINISHED=/scripts/Finished
readonly TEMPDIR=/scripts/temp
readonly REPO_BASE="https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master"

# ============================================================================
# FUNCTIONS
# ============================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_success() {
    printf "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] ✓ %s\033[0m\n" "$*"
}

log_error() {
    printf "\033[1;31m[$(date +'%Y-%m-%d %H:%M:%S')] ✗ ERROR: %s\033[0m\n" "$*"
}

# Download only updates.sh (updates.sh will handle all other scripts)
function download()
{
	log "Downloading updated updates.sh from repository..."
	
	# Download updates.sh
	curl --tlsv1.3 -f -o "$TEMPDIR/updates.sh" "$REPO_BASE/scripts/updates.sh" || {
		log_error "Failed to download updates.sh"
		return 1
	}
	log_success "Downloaded updates.sh"

}


# Install updates.sh only
function move()
{
	log "Installing updated script..."
	
	if [[ -f "$TEMPDIR/updates.sh" ]]; then
		chmod 755 "$TEMPDIR/updates.sh"
		mv "$TEMPDIR/updates.sh" "$FINISHED/updates.sh"
		log_success "Installed updates.sh"
	else
		log_error "updates.sh not found in temp directory"
		return 1
	fi
	
	log_success "Script refresh complete!"
	log ""
	log "Run 'sudo bash $FINISHED/updates.sh refresh' to update all other scripts"
}

# ============================================================================
# MAIN
# ============================================================================

download
move
