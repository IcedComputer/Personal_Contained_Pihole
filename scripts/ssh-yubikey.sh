#!/bin/bash
#
# YubiKey SSH Authentication Manager
# File: ssh-yubikey.sh
# Created: 2026-11-11
# Last Modified: 2026-11-11
# Version: 1.0.0
#
# Description: Standalone FIDO2 SSH setup for Ubuntu Server and Raspberry Pi OS
#              Installs OpenSSH and generates client enrollment instructions
#              Supports public-key registration, staged enforcement, and recovery
#
#
# Usage: sudo bash ssh-yubikey.sh COMMAND --user USER [OPTIONS]
#
# Commands:
#   setup                 Install and configure additive FIDO2 SSH authentication
#   enroll                Register a client-generated FIDO2 public key
#   info                  Show enrollment instructions and key fingerprints
#   enforce               Require registered FIDO2 keys for the selected account
#   disable-enforcement   Restore the saved additive authentication policy
#
# Examples:
#   sudo bash ssh-yubikey.sh setup --user azureuser --host vm.example.com
#   sudo bash ssh-yubikey.sh enroll --user azureuser --public-key ~/yubikey.pub
#   sudo bash ssh-yubikey.sh enforce --user azureuser --confirm-tested
#

set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

SSH_CONFIG="/etc/ssh/sshd_config"
STATE_DIR="/etc/ssh/yubikey-ssh"
BACKUP_DIR="/var/backups/yubikey-ssh"
SSHD="/usr/sbin/sshd"
TARGET_USER=""
SERVER_HOST=""
SERVER_PORT=""
PUBLIC_KEY=""
CONFIRM_TESTED=0
TRANSACTION_ACTIVE=0
BACKUP=""
TEMP_FILES=()
SK_TYPES="sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"

log_info() { printf 'INFO: %s\n' "$*"; }
log_success() { printf 'SUCCESS: %s\n' "$*"; }
log_warning() { printf 'WARNING: %s\n' "$*" >&2; }
log_error() { printf 'ERROR: %s\n' "$*" >&2; }
die() {
    log_error "$*"
    exit 1
}

usage() {
    cat <<'EOF'
Usage: sudo bash ssh-yubikey.sh COMMAND --user USER [OPTIONS]

Commands:
  setup                 Install OpenSSH, enable FIDO2 login, write enrollment info.
                        Requires --host (the address clients actually connect to).
  enroll                Register one client-generated FIDO2 public key.
                        Requires --public-key FILE; accepts only a plain .pub key.
  info                  Show saved enrollment instructions and current key fingerprints.
  enforce               Require registered FIDO2 keys for this user only.
                        Requires --confirm-tested after a separate key-only SSH test.
  disable-enforcement   Restore this user's additive policy, keeping registered keys.

Options:
  --user USER           Existing non-root Linux login account.
  --host HOST           Public Azure DNS/IP or reachable Pi DNS/IP (setup only).
  --port PORT           Client-facing SSH port (setup only; default: detected port).
  --public-key FILE     Public key file already copied to the server (enroll only).
  --confirm-tested      Confirm a NEW key-only session and console recovery are tested.
  -h, --help            Show help.

Keep your current SSH session open. Generate keys on the CLIENT with the YubiKey
attached there, never on the server. Setup preserves existing authentication
requirements; enforcement deliberately replaces them for the selected user.
EOF
}

cleanup() {
    local status=$? file
    trap - EXIT
    if (( TRANSACTION_ACTIVE )); then
        log_error "SSH configuration change failed; restoring ${BACKUP}"
        if cp -p -- "${BACKUP}/sshd_config" "$SSH_CONFIG" &&
           { if [[ -f "${BACKUP}/user.conf" ]]; then
                 cp -p -- "${BACKUP}/user.conf" "$USER_CONFIG"
             else
                 rm -f -- "$USER_CONFIG"
             fi; } &&
           "$SSHD" -t &&
           systemctl reload ssh.service; then
            log_warning "Previous SSH configuration restored and reloaded."
        else
            log_error "Recovery failed. Keep this session open; restore ${BACKUP} from the console."
        fi
        status=1
    fi
    for file in "${TEMP_FILES[@]}"; do
        rm -f -- "$file"
    done
    exit "$status"
}

new_temp() {
    TEMP_FILE=$(mktemp "${STATE_DIR}/.tmp.XXXXXX")
    TEMP_FILES+=("$TEMP_FILE")
}

setting() {
    local key="$1"
    awk -v key="$key" '$1 == key { sub(/^[^[:space:]]+[[:space:]]+/, ""); print; exit }' <<< "$EFFECTIVE"
}

read_effective() {
    # Use the current connection when available so address/port Match rules apply.
    local client_ip="127.0.0.1" client_port="" server_ip="127.0.0.1" server_port="22"
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        read -r client_ip client_port server_ip server_port <<< "$SSH_CONNECTION"
    fi
    EFFECTIVE=$("$SSHD" -T -C "user=${TARGET_USER},host=${client_ip},addr=${client_ip},laddr=${server_ip},lport=${server_port}")
}

check_paths() {
    local path
    for path in "$SSH_CONFIG" "$STATE_DIR" "$BACKUP_DIR" "$USER_CONFIG" \
                "$ADDITIVE_CONFIG" "$KEYS_FILE" "$CONNECTION_FILE" "$REPORT"; do
        [[ ! -L "$path" ]] || die "Refusing symlinked managed path: ${path}"
    done
    [[ -f "$SSH_CONFIG" ]] || die "Missing regular SSH configuration: ${SSH_CONFIG}"
    install -d -o root -g root -m 755 "$STATE_DIR"
    install -d -o root -g root -m 700 "$BACKUP_DIR"
}

check_server() {
    [[ -x "$SSHD" ]] || die "OpenSSH server is missing. Run setup first."
    "$SSHD" -t || die "Existing sshd configuration is invalid; fix it before continuing."
    # The old directive name works on OpenSSH 8.2 as well as current releases.
    "$SSHD" -T -o "PubkeyAcceptedKeyTypes=${SK_TYPES}" >/dev/null ||
        die "OpenSSH 8.2+ with FIDO security-key support is required."
    systemctl is-active --quiet ssh.service ||
        die "ssh.service is not active. Start the standard OpenSSH service before continuing."
    read_effective
}

install_server() {
    [[ -f /etc/os-release ]] || die "Cannot identify this Linux distribution."
    # /etc/os-release is supplied by the OS, not by an enrollment file.
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian|raspbian) ;;
        *) die "Supported systems: Ubuntu Server, Debian, and Raspberry Pi OS." ;;
    esac
    command -v apt-get >/dev/null || die "apt-get is required."
    command -v systemctl >/dev/null || die "This script requires systemd and ssh.service."
    log_info "Installing distribution OpenSSH packages (no USB or PAM module is needed on the server)."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confold" \
        install -y openssh-server openssh-client
    systemctl enable ssh.service
    systemctl start ssh.service
}

write_policy() {
    local mode="$1" authorized_files algorithms type
    if [[ "$mode" == "additive" ]]; then
        authorized_files=$(setting authorizedkeysfile)
        [[ -n "$authorized_files" ]] || die "Cannot determine existing AuthorizedKeysFile."
        [[ "$authorized_files" != "none" ]] || authorized_files=""
        algorithms=$(setting pubkeyacceptedalgorithms)
        [[ -n "$algorithms" ]] || algorithms=$(setting pubkeyacceptedkeytypes)
        [[ -n "$algorithms" ]] || die "Cannot determine accepted public-key algorithms."
        for type in sk-ssh-ed25519@openssh.com sk-ecdsa-sha2-nistp256@openssh.com; do
            [[ ",${algorithms}," == *",${type},"* ]] || algorithms+=",${type}"
        done
        # Do not discard custom or Azure-provided authorized-key paths.
        cat <<EOF
# Managed by ssh-yubikey.sh: additive
Match User ${TARGET_USER}
    PubkeyAuthentication yes
    AuthorizedKeysFile ${authorized_files:+${authorized_files} }${KEYS_FILE}
    PubkeyAcceptedKeyTypes ${algorithms}
Match all
EOF
    else
        cat <<EOF
# Managed by ssh-yubikey.sh: enforced
Match User ${TARGET_USER}
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile ${KEYS_FILE}
    AuthorizedKeysCommand none
    PubkeyAcceptedKeyTypes ${SK_TYPES}
    PubkeyAuthOptions touch-required
Match all
EOF
    fi
}

verify_policy() {
    local mode="$1" files algorithms
    read_effective
    [[ "$(setting pubkeyauthentication)" == "yes" ]] ||
        die "An earlier Match rule prevents public-key authentication."
    files=$(setting authorizedkeysfile)
    [[ " $files " == *" ${KEYS_FILE} "* ]] ||
        die "An earlier Match rule prevents use of the managed key file."
    algorithms=$(setting pubkeyacceptedalgorithms)
    [[ -n "$algorithms" ]] || algorithms=$(setting pubkeyacceptedkeytypes)
    [[ ",${algorithms}," == *",sk-ssh-ed25519@openssh.com,"* &&
       ",${algorithms}," == *",sk-ecdsa-sha2-nistp256@openssh.com,"* ]] ||
        die "An earlier Match rule prevents FIDO2 public-key algorithms."
    [[ "$(setting pubkeyauthoptions)" != *"no-touch-required"* ]] ||
        die "Existing PubkeyAuthOptions disables the FIDO touch requirement."
    if [[ "$mode" == "enforced" ]]; then
        [[ "$files" == "$KEYS_FILE" &&
           "$(setting authenticationmethods)" == "publickey" &&
           "$(setting passwordauthentication)" == "no" &&
           "$(setting authorizedkeyscommand)" == "none" &&
           "$(setting pubkeyauthoptions)" == "touch-required" &&
           "$algorithms" == "$SK_TYPES" ]] ||
            die "Effective policy is not FIDO2-only; check earlier Match rules."
        if [[ "$(setting kbdinteractiveauthentication)" != "no" ]]; then
            die "An earlier Match rule still enables keyboard-interactive authentication."
        fi
    fi
}

apply_policy() {
    local candidate="$1" mode="$2" include="Include ${STATE_DIR}/*.conf"
    BACKUP=$(mktemp -d "${BACKUP_DIR}/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
    cp -p -- "$SSH_CONFIG" "${BACKUP}/sshd_config"
    if [[ -f "$USER_CONFIG" ]]; then
        cp -p -- "$USER_CONFIG" "${BACKUP}/user.conf"
    fi
    TRANSACTION_ACTIVE=1
    install -o root -g root -m 644 "$candidate" "$USER_CONFIG"
    if ! grep -Fxq "$include" "$SSH_CONFIG"; then
        # Appending avoids putting existing global directives inside a Match block.
        # Earlier conflicting Match rules are rejected by effective-policy validation.
        printf '\n# Managed YubiKey SSH policies\nMatch all\n%s\n' "$include" >> "$SSH_CONFIG"
    fi
    "$SSHD" -t || die "New SSH configuration is invalid."
    verify_policy "$mode"
    systemctl reload ssh.service || die "Could not reload ssh.service."
    systemctl is-active --quiet ssh.service || die "ssh.service is not active after reload."
    TRANSACTION_ACTIVE=0
    log_success "SSH policy applied. Configuration backup: ${BACKUP}"
}

normalize_keys() {
    local input="$1" single="$2" fingerprints count
    [[ -f "$input" && -r "$input" ]] || die "Cannot read public key file: ${input}"
    [[ "$(stat -c %s -- "$input")" -le 16384 ]] || die "Public key file exceeds 16 KiB."
    new_temp
    if ! awk -v single="$single" -v user="$TARGET_USER" '
        { sub(/\r$/, "") }
        NF {
            if (($1 != "sk-ssh-ed25519@openssh.com" &&
                 $1 != "sk-ecdsa-sha2-nistp256@openssh.com") ||
                $2 !~ /^[A-Za-z0-9+\/=]+$/) exit 1
            print $1, $2, user "-yubikey"
            count++
        }
        END { if (count == 0 || (single == 1 && count != 1)) exit 1 }
    ' "$input" > "$TEMP_FILE"; then
        die "Expected plain FIDO2 .pub key(s), without authorized_keys options or private-key data."
    fi
    if ! fingerprints=$(ssh-keygen -l -E sha256 -f "$TEMP_FILE"); then
        die "Invalid FIDO2 public-key encoding."
    fi
    count=$(wc -l < "$TEMP_FILE")
    if [[ "$(wc -l <<< "$fingerprints")" -ne "$count" ]] ||
       ! awk '$NF != "(ED25519-SK)" && $NF != "(ECDSA-SK)" { exit 1 }' <<< "$fingerprints"; then
        die "Key data does not contain only FIDO2 security keys."
    fi
    NORMALIZED_KEY_FILE="$TEMP_FILE"
}

enroll() {
    [[ -f "$USER_CONFIG" && -f "$ADDITIVE_CONFIG" ]] || die "Run setup for this user first."
    normalize_keys "$PUBLIC_KEY" 1
    local normalized="$NORMALIZED_KEY_FILE" type blob comment
    read -r type blob comment < "$normalized"
    if [[ -f "$KEYS_FILE" ]] &&
       awk -v type="$type" -v blob="$blob" '$1 == type && $2 == blob { found=1 } END { exit !found }' "$KEYS_FILE"; then
        log_info "This key is already registered; no changes made."
    else
        new_temp
        if [[ -f "$KEYS_FILE" ]]; then
            BACKUP=$(mktemp -d "${BACKUP_DIR}/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
            cp -p -- "$KEYS_FILE" "${BACKUP}/user.keys"
            cat "$KEYS_FILE" > "$TEMP_FILE"
            printf '\n' >> "$TEMP_FILE"
        fi
        cat "$normalized" >> "$TEMP_FILE"
        chown root:root "$TEMP_FILE"
        chmod 644 "$TEMP_FILE"
        mv -f -- "$TEMP_FILE" "$KEYS_FILE"
        log_success "FIDO2 public key registered. Existing keys were preserved."
    fi
    ssh-keygen -l -E sha256 -f "$KEYS_FILE"
    log_warning "Test a NEW SSH connection with only this key before enforcing."
}

validate_connection() {
    [[ "$SERVER_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] ||
        die "--host must be a DNS name or IP address, not a URL or SSH alias."
    [[ -n "$SERVER_PORT" ]] || return 0
    [[ "$SERVER_PORT" =~ ^[0-9]{1,5}$ ]] &&
        (( 10#$SERVER_PORT >= 1 && 10#$SERVER_PORT <= 65535 )) ||
        die "--port must be between 1 and 65535; specify it if port detection is ambiguous."
}

save_connection() {
    if [[ -z "$SERVER_PORT" ]]; then
        SERVER_PORT=$(setting port)
    fi
    [[ -n "$SERVER_PORT" ]] || die "Cannot detect the client-facing port; specify --port."
    validate_connection
    new_temp
    printf '%s\n%s\n' "$SERVER_HOST" "$SERVER_PORT" > "$TEMP_FILE"
    install -o root -g root -m 600 "$TEMP_FILE" "$CONNECTION_FILE"
}

write_report() {
    local connection scp_host
    [[ -f "$CONNECTION_FILE" ]] || die "Missing connection data. Run setup with --host."
    mapfile -t connection < "$CONNECTION_FILE"
    [[ "${#connection[@]}" -eq 2 ]] || die "Invalid saved connection data; re-run setup with --host."
    SERVER_HOST="${connection[0]}"
    SERVER_PORT="${connection[1]}"
    [[ -n "$SERVER_PORT" ]] || die "Missing saved connection port."
    validate_connection
    scp_host="$SERVER_HOST"
    [[ "$scp_host" != *:* ]] || scp_host="[${scp_host}]"
    new_temp
    cat > "$TEMP_FILE" <<EOF
YubiKey FIDO2 SSH enrollment
==========================
Server: ${SERVER_HOST}
Client-facing port: ${SERVER_PORT}
Linux account: ${TARGET_USER}
Managed public keys: ${KEYS_FILE}

1. On your CLIENT, install a FIDO-capable OpenSSH 8.2+ client and attach the
   YubiKey there. The server does not need the YubiKey, libpam-u2f or a USB device.
   Check: ssh -V
   Generate a NEW key (do not overwrite an existing identity):
     ssh-keygen -t ed25519-sk -f ~/.ssh/${TARGET_USER}_yubikey -C "${TARGET_USER}-yubikey"
   If your FIDO2 YubiKey does not support Ed25519, use -t ecdsa-sk instead.
   Keep the key-handle file safe and use a passphrase. Touch the YubiKey when asked.
   Optional PIN verification (OpenSSH 8.4+ client): add -O verify-required.

2. Verify the server host fingerprints below through a trusted channel, then
   copy ONLY the .pub file, using your existing SSH login:
     scp -P ${SERVER_PORT} ~/.ssh/${TARGET_USER}_yubikey.pub ${TARGET_USER}@${scp_host}:yubikey.pub
   On the SERVER, from the directory containing this script:
     sudo bash ssh-yubikey.sh enroll --user ${TARGET_USER} --public-key ~/yubikey.pub

3. Keep the existing session open. In a NEW CLIENT terminal, test ONLY the key:
     ssh -F none -p ${SERVER_PORT} -o ControlMaster=no -o ControlPath=none -o IdentityAgent=none -o IdentitiesOnly=yes -o PubkeyAcceptedKeyTypes=${SK_TYPES} -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -i ~/.ssh/${TARGET_USER}_yubikey ${TARGET_USER}@${SERVER_HOST}
   Check with -vv if needed: the authenticated key must be an ED25519-SK or
   ECDSA-SK key. This test ignores client configuration and accepts only SK key
   types. Add explicit proxy options if needed. Also confirm a NEW connection
   fails with the YubiKey unplugged. Test sudo and console recovery.
   For an account with existing MFA requirements, satisfy that policy first;
   setup does not remove it. Do not enforce until a FIDO2 login is verified.

4. Optional, on the SERVER after successful testing and backup-key enrollment:
     sudo bash ssh-yubikey.sh enforce --user ${TARGET_USER} --confirm-tested
   This disables other login methods/keys for THIS account, including existing
   password/TOTP authentication requirements. Other accounts are unchanged.
   It accepts only the registered FIDO key types, not SSH certificates.

Recovery from an OPEN session or Azure/Pi console, using this script:
     sudo bash ssh-yubikey.sh disable-enforcement --user ${TARGET_USER}
   This restores the saved additive policy, NOT passwords disabled elsewhere.
   Configuration backups: ${BACKUP_DIR}
   No Azure NSG, firewall, SSH port, PAM, or root-login settings are changed.
   Azure: use the reachable public DNS/IP; keep NSG SSH access restricted.
   Pi: use its LAN/VPN address. Never expose SSH to the Internet just to enroll.

No web registration, OTP secret, private key or YubiKey PIN belongs on the server.
Register a second physical key separately; keep a tested console recovery path.
EOF
    printf '\nCurrent SSH host-key fingerprints (verify through a trusted channel):\n' >> "$TEMP_FILE"
    local keyword host_key found=0
    while read -r keyword host_key; do
        [[ "$keyword" == "hostkey" ]] || continue
        [[ -f "${host_key}.pub" ]] || die "Missing configured SSH host public key: ${host_key}.pub"
        ssh-keygen -l -E sha256 -f "${host_key}.pub" >> "$TEMP_FILE"
        found=1
    done <<< "$EFFECTIVE"
    (( found )) || die "No SSH host public keys found."
    if [[ -s "$KEYS_FILE" ]]; then
        printf '\nRegistered FIDO2 public-key fingerprints:\n' >> "$TEMP_FILE"
        ssh-keygen -l -E sha256 -f "$KEYS_FILE" >> "$TEMP_FILE"
    fi
    install -o root -g root -m 644 "$TEMP_FILE" "$REPORT"
    cat "$REPORT"
    log_success "Enrollment instructions saved to ${REPORT}"
}

setup() {
    [[ -n "$SERVER_HOST" ]] || die "setup requires --host: specify the reachable Azure or Pi address."
    install_server
    check_paths
    check_server
    save_connection
    if [[ -f "$USER_CONFIG" ]]; then
        [[ -f "$ADDITIVE_CONFIG" ]] || die "Missing saved additive policy; recover it before re-running setup."
        log_info "Existing policy retained (setup never disables enforcement)."
    else
        new_temp
        write_policy additive > "$TEMP_FILE"
        install -o root -g root -m 644 "$TEMP_FILE" "$ADDITIVE_CONFIG"
        apply_policy "$ADDITIVE_CONFIG" additive
    fi
    write_report
}

enforce() {
    (( CONFIRM_TESTED )) || die "First test a new FIDO2-only login and console recovery; then pass --confirm-tested."
    [[ -f "$USER_CONFIG" && -f "$ADDITIVE_CONFIG" ]] || die "Run setup and enroll first."
    normalize_keys "$KEYS_FILE" 0
    new_temp
    write_policy enforced > "$TEMP_FILE"
    log_warning "Requiring registered hardware-backed keys for ${TARGET_USER}; keep this session open."
    apply_policy "$TEMP_FILE" enforced
}

disable_enforcement() {
    [[ -f "$ADDITIVE_CONFIG" ]] || die "No saved additive policy for ${TARGET_USER}."
    apply_policy "$ADDITIVE_CONFIG" additive
    log_success "Enforcement removed; original login requirements and registered FIDO2 keys retained."
}

main() {
    local command="${1:-}"
    [[ -n "$command" ]] || { usage; exit 1; }
    shift
    case "$command" in
        -h|--help) usage; return ;;
        setup|enroll|info|enforce|disable-enforcement) ;;
        *) usage; die "Unknown command: ${command}" ;;
    esac
    while (( $# )); do
        case "$1" in
            --user|--host|--port|--public-key)
                [[ $# -ge 2 && -n "$2" ]] || die "Missing value for $1."
                case "$1" in
                    --user) TARGET_USER="$2" ;;
                    --host) SERVER_HOST="$2" ;;
                    --port) SERVER_PORT="$2" ;;
                    --public-key) PUBLIC_KEY="$2" ;;
                esac
                shift 2 ;;
            --confirm-tested) CONFIRM_TESTED=1; shift ;;
            -h|--help) usage; return ;;
            *) die "Unknown option: $1" ;;
        esac
    done
    [[ $EUID -eq 0 ]] || die "Run this script as root (sudo)."
    [[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]*$ && "$TARGET_USER" != "root" ]] ||
        die "--user must name an existing non-root Linux account."
    id "$TARGET_USER" >/dev/null 2>&1 || die "Account does not exist: ${TARGET_USER}"
    [[ "$(id -u "$TARGET_USER")" != "0" ]] || die "The target account must not have UID 0."
    [[ "$command" == "setup" || ( -z "$SERVER_HOST" && -z "$SERVER_PORT" ) ]] ||
        die "--host and --port are setup-only options."
    [[ "$command" == "enroll" || -z "$PUBLIC_KEY" ]] || die "--public-key is enroll-only."
    [[ "$command" != "enroll" || -n "$PUBLIC_KEY" ]] || die "enroll requires --public-key FILE."
    [[ "$command" == "enforce" || "$CONFIRM_TESTED" == "0" ]] || die "--confirm-tested is enforce-only."
    if [[ "$command" == "setup" ]]; then
        validate_connection
    fi
    USER_CONFIG="${STATE_DIR}/${TARGET_USER}.conf"
    ADDITIVE_CONFIG="${STATE_DIR}/${TARGET_USER}.additive"
    KEYS_FILE="${STATE_DIR}/${TARGET_USER}.keys"
    CONNECTION_FILE="${STATE_DIR}/${TARGET_USER}.connection"
    REPORT="${STATE_DIR}/${TARGET_USER}-enrollment.txt"
    [[ ! -L "$STATE_DIR" ]] || die "Refusing symlinked state directory."
    install -d -o root -g root -m 755 "$STATE_DIR"
    [[ ! -L "${STATE_DIR}/.lock" ]] || die "Refusing symlinked lock file."
    exec 9>"${STATE_DIR}/.lock"
    flock -n 9 || die "Another YubiKey SSH setup is running."
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$command" == "setup" ]]; then
        setup
    else
        check_paths
        check_server
        case "$command" in
            enroll) enroll ;;
            info) write_report ;;
            enforce) enforce ;;
            disable-enforcement) disable_enforcement ;;
        esac
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
