#!/bin/bash
#
# Pi-hole Log Research Tool
# File: Research.sh
# Created: 2020-07-25
# Last Modified: 2025-12-07
# Version: 2.0.0
#
# Description: Analyzes Pi-hole logs to categorize DNS queries and blocks
#              Generates reports on allowed, regex-blocked, and blocklist-blocked domains
#
# Following Universal Constants:
# - UC-001: Code clarity over cleverness
# - UC-002: Meaningful naming conventions
# - UC-003: ISO 8601 date format
# - UC-004: Professional communication
#
# Usage: sudo bash Research.sh
#
# Output Files (in /scripts/temp/):
#   dns_allowed_domains.txt      - Domains forwarded to upstream DNS
#   regex_blocked_domains.txt    - Domains blocked by regex rules (blacklist)
#   blocklist_blocked_domains.txt - Domains blocked by exact-match lists
#

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

readonly LOGFILE="/var/log/pihole.log"
readonly TEMPDIR="/scripts/temp"
readonly OUTPUT_DIR="${TEMPDIR}"

# Output files with descriptive names
readonly ALLOWED_FILE="${OUTPUT_DIR}/dns_allowed_domains.txt"
readonly REGEX_BLOCKED_FILE="${OUTPUT_DIR}/regex_blocked_domains.txt"
readonly BLOCKLIST_BLOCKED_FILE="${OUTPUT_DIR}/blocklist_blocked_domains.txt"

# Ensure temp directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Pi-hole DNS Research Analysis"
echo "=============================="
echo "Analyzing: ${LOGFILE}"
echo ""

# 1. Extract domains that received DNS responses (allowed/forwarded to upstream)
# These are queries that got actual IP addresses back, excluding CNAME/NODATA/HTTPS-only responses
echo "[1/3] Extracting domains allowed by Pi-hole (forwarded to upstream DNS)..."
grep -v "blocked" "${LOGFILE}" | \
    grep -v "CNAME" | \
    grep -v "NODATA" | \
    grep -v "HTTPS" | \
    grep -oP '(?<=reply\s)[^\s]+(?=\sis)' | \
    sort | uniq -c | sort -rn > "${ALLOWED_FILE}"

ALLOWED_COUNT=$(wc -l < "${ALLOWED_FILE}" 2>/dev/null || echo 0)
echo "   ✓ Found ${ALLOWED_COUNT} unique allowed domains"

# 2. Extract domains blocked by regex rules (blacklisted)
# These show as "blacklisted" in the logs
echo "[2/3] Extracting domains blocked by regex rules..."
grep "blacklisted" "${LOGFILE}" | \
    grep -oP '[^\s]+(?=\sis)' | \
    sort | uniq -c | sort -rn > "${REGEX_BLOCKED_FILE}"

REGEX_COUNT=$(wc -l < "${REGEX_BLOCKED_FILE}" 2>/dev/null || echo 0)
echo "   ✓ Found ${REGEX_COUNT} unique regex-blocked domains"

# 3. Extract domains blocked by exact-match blocklists
# These show as "blocked" (but not "blacklisted") in the logs
echo "[3/3] Extracting domains blocked by exact-match blocklists..."
grep "blocked" "${LOGFILE}" | \
    grep -v "blacklisted" | \
    grep -oP '[^\s]+(?=\sis)' | \
    sort | uniq -c | sort -rn > "${BLOCKLIST_BLOCKED_FILE}"

BLOCKLIST_COUNT=$(wc -l < "${BLOCKLIST_BLOCKED_FILE}" 2>/dev/null || echo 0)
echo "   ✓ Found ${BLOCKLIST_COUNT} unique blocklist-blocked domains"

# Summary
echo ""
echo "Analysis Complete!"
echo "=================="
echo "Results saved to:"
echo "  Allowed domains:    ${ALLOWED_FILE} (${ALLOWED_COUNT} unique)"
echo "  Regex blocked:      ${REGEX_BLOCKED_FILE} (${REGEX_COUNT} unique)"
echo "  Blocklist blocked:  ${BLOCKLIST_BLOCKED_FILE} (${BLOCKLIST_COUNT} unique)"
echo ""
echo "Note: Counts show number of requests per domain (sorted by frequency)"

