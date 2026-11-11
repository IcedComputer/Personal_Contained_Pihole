#!/bin/bash
#
# Pi-hole Log Research Tool
# File: Research.sh
# Created: 2020-07-25
# Last Modified: 2026-11-11
# Version: 2.0.1
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

readonly LOGFILE="/var/log/pihole/pihole.log"
readonly TEMPDIR="/scripts/temp"
readonly OUTPUT_DIR="${TEMPDIR}"

# Output files with descriptive names
readonly ALLOWED_FILE="${OUTPUT_DIR}/dns_allowed_domains.txt"
readonly REGEX_BLOCKED_FILE="${OUTPUT_DIR}/regex_blocked_domains.txt"
readonly BLOCKLIST_BLOCKED_FILE="${OUTPUT_DIR}/blocklist_blocked_domains.txt"

if [[ ! -f "${LOGFILE}" || ! -r "${LOGFILE}" ]]; then
    echo "ERROR: Cannot read Pi-hole query log: ${LOGFILE}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

extract_domains() {
    # awk treats zero matches as success but still reports input/read failures.
    awk -v category="$1" '
        category == "allowed" && /blocked|denied|CNAME|NODATA|HTTPS/ { next }
        category == "regex" && !/blacklisted|regex denied|regex blocked/ { next }
        category == "blocklist" && (!/blocked|denied/ || /blacklisted|regex/) { next }
        {
            for (i = 2; i < NF; i++) {
                if ($i == "is" && (category != "allowed" || (i > 2 && $(i-2) == "reply")))
                    print $(i-1)
            }
        }
    ' "${LOGFILE}" | sort | uniq -c | sort -rn
}

echo "Pi-hole DNS Research Analysis"
echo "=============================="
echo "Analyzing: ${LOGFILE}"
echo ""

echo "[1/3] Extracting domains allowed by Pi-hole (forwarded to upstream DNS)..."
extract_domains allowed > "${ALLOWED_FILE}"

ALLOWED_COUNT=$(wc -l < "${ALLOWED_FILE}")
echo "   ✓ Found ${ALLOWED_COUNT} unique allowed domains"

echo "[2/3] Extracting domains blocked by regex rules..."
extract_domains regex > "${REGEX_BLOCKED_FILE}"

REGEX_COUNT=$(wc -l < "${REGEX_BLOCKED_FILE}")
echo "   ✓ Found ${REGEX_COUNT} unique regex-blocked domains"

echo "[3/3] Extracting domains blocked by exact-match blocklists..."
extract_domains blocklist > "${BLOCKLIST_BLOCKED_FILE}"

BLOCKLIST_COUNT=$(wc -l < "${BLOCKLIST_BLOCKED_FILE}")
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
