#!/bin/bash
#
# YubiKey SSH Authentication Manager
# File: ssh-yubikey.sh
# Created: 2026-11-11
# Last Modified: 2026-11-11
# Version: 1.1.0
#
# Description: Standalone FIDO2 SSH setup for Ubuntu Server and Raspberry Pi OS
#              Installs OpenSSH and generates client enrollment instructions
#              Supports public-key registration, staged enforcement, and recovery
#
# Following Universal Constants:
# - UC-001: Code clarity over cleverness
# - UC-002: Meaningful naming conventions
# - UC-003: ISO 8601 date format
# - UC-004: Professional communication
#
# Usage: bash ssh-yubikey.sh COMMAND [OPTIONS]
#
# Commands:
#   setup                 Root: install OpenSSH and prepare a user's SSH access
#   configure             User: save connection details and enrollment instructions
#   enroll                Register a client-generated FIDO2 public key
#   info                  Show enrollment instructions and key fingerprints
#   enforce               Require registered FIDO2 keys for the selected account
#   disable-enforcement   Restore the saved additive authentication policy
#
# Examples:
#   sudo bash ssh-yubikey.sh setup
#   sudo bash ssh-yubikey.sh setup --user azureuser
#   bash ssh-yubikey.sh configure --host vm.example.com
#   bash ssh-yubikey.sh enroll --public-key ~/yubikey.pub
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
WORK_DIR="$STATE_DIR"

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
Usage: bash ssh-yubikey.sh COMMAND [OPTIONS]

Commands:
  setup                 ROOT: install OpenSSH and prepare a user's SSH access.
                        Uses the non-root sudo caller unless --user is supplied.
                        Prompts for the target account when run directly as root.
  configure             USER: save the server address and enrollment instructions.
                        Prompts for --host when omitted in an interactive shell.
  enroll                USER: register one client-generated FIDO2 public key.
                        Requires --public-key FILE; accepts only a plain .pub key.
  info                  USER: show enrollment instructions and key fingerprints.
  enforce               ROOT: require registered FIDO2 keys for --user USER only.
                        Requires --confirm-tested after a separate key-only SSH test.
  disable-enforcement   ROOT: restore --user USER's saved additive policy.

Options:
  --user USER           Target non-root SSH account for administrator commands.
                        User commands default to, and can only manage, their own account.
  --host HOST           Public Azure DNS/IP or reachable Pi DNS/IP (configure only).
  --port PORT           Client-facing port (configure only; default: detected port).
  --public-key FILE     Public key file already copied to the server (enroll only).
  --confirm-tested      Confirm a NEW key-only session and console recovery are tested.
  -h, --help            Show help.

Administrator: sudo bash ssh-yubikey.sh setup --user azureuser
Then, logged in as azureuser (WITHOUT sudo):
  bash ssh-yubikey.sh configure --host vm.example.com
  bash ssh-yubikey.sh enroll --public-key ~/yubikey.pub

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
           { if [[ -f "${BACKUP}/user.additive" ]]; then
                 cp -p -- "${BACKUP}/user.additive" "$ADDITIVE_CONFIG"
             else
                 rm -f -- "$ADDITIVE_CONFIG"
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
    TEMP_FILE=$(mktemp "${WORK_DIR}/.tmp.XXXXXX")
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
    for path in "$SSH_CONFIG" "$STATE_DIR" "${STATE_DIR}/users" "$BACKUP_DIR" \
                "$USER_CONFIG" "$ADDITIVE_CONFIG" "$SERVER_INFO" "$USER_DIR" \
                "$KEYS_FILE" "$LEGACY_KEYS_FILE"; do
        [[ ! -L "$path" ]] || die "Refusing symlinked managed path: ${path}"
    done
    [[ -f "$SSH_CONFIG" ]] || die "Missing regular SSH configuration: ${SSH_CONFIG}"
    install -d -o root -g root -m 755 "$STATE_DIR"
    install -d -o root -g root -m 755 "${STATE_DIR}/users"
    install -d -o root -g root -m 700 "$BACKUP_DIR"
}

check_user_state() {
    local path
    for path in "$STATE_DIR" "${STATE_DIR}/users" "$USER_DIR" "$USER_CONFIG" \
                "$SERVER_INFO" "$KEYS_FILE" "$CONNECTION_FILE" "$REPORT" \
                "$KEY_BACKUP_DIR" "${USER_DIR}/.lock"; do
        [[ ! -L "$path" ]] || die "Refusing symlinked managed path: ${path}"
    done
    [[ -d "$USER_DIR" && -O "$USER_DIR" && -w "$USER_DIR" &&
       -r "$USER_CONFIG" && -r "$SERVER_INFO" ]] ||
        die "An administrator must first run: sudo bash ssh-yubikey.sh setup --user ${TARGET_USER}"
    for path in "$USER_CONFIG" "$SERVER_INFO" "$KEYS_FILE" "$CONNECTION_FILE" "$REPORT"; do
        [[ ! -e "$path" || -f "$path" ]] || die "Expected a regular managed file: ${path}"
    done
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
    local candidate="$1" mode="$2" additive="${3:-}" include="Include ${STATE_DIR}/*.conf"
    BACKUP=$(mktemp -d "${BACKUP_DIR}/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
    cp -p -- "$SSH_CONFIG" "${BACKUP}/sshd_config"
    if [[ -f "$USER_CONFIG" ]]; then
        cp -p -- "$USER_CONFIG" "${BACKUP}/user.conf"
    fi
    if [[ -f "$ADDITIVE_CONFIG" ]]; then
        cp -p -- "$ADDITIVE_CONFIG" "${BACKUP}/user.additive"
    fi
    TRANSACTION_ACTIVE=1
    install -o root -g root -m 644 "$candidate" "$USER_CONFIG"
    if [[ -n "$additive" ]]; then
        install -o root -g root -m 644 "$additive" "$ADDITIVE_CONFIG"
    fi
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
            mkdir -p -- "$KEY_BACKUP_DIR"
            chmod 700 "$KEY_BACKUP_DIR"
            BACKUP=$(mktemp -d "${KEY_BACKUP_DIR}/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
            cp -p -- "$KEYS_FILE" "${BACKUP}/user.keys"
            cat "$KEYS_FILE" > "$TEMP_FILE"
            printf '\n' >> "$TEMP_FILE"
        fi
        cat "$normalized" >> "$TEMP_FILE"
        chmod 600 "$TEMP_FILE"
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
        SERVER_PORT="$DETECTED_PORT"
    fi
    [[ -n "$SERVER_PORT" ]] || die "Cannot detect the client-facing port; specify --port."
    validate_connection
    new_temp
    printf '%s\n%s\n' "$SERVER_HOST" "$SERVER_PORT" > "$TEMP_FILE"
    chmod 600 "$TEMP_FILE"
    mv -f -- "$TEMP_FILE" "$CONNECTION_FILE"
}

write_report() {
    local connection scp_host
    [[ -f "$CONNECTION_FILE" ]] || die "Missing connection data. Run configure --host HOST without sudo."
    mapfile -t connection < "$CONNECTION_FILE"
    [[ "${#connection[@]}" -eq 2 ]] || die "Invalid saved connection data; re-run configure --host HOST."
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
   On the SERVER, logged in as ${TARGET_USER}, WITHOUT sudo:
     bash ssh-yubikey.sh enroll --public-key ~/yubikey.pub

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
    tail -n +2 "$SERVER_INFO" >> "$TEMP_FILE"
    if [[ -s "$KEYS_FILE" ]]; then
        printf '\nRegistered FIDO2 public-key fingerprints:\n' >> "$TEMP_FILE"
        ssh-keygen -l -E sha256 -f "$KEYS_FILE" >> "$TEMP_FILE"
    fi
    chmod 600 "$TEMP_FILE"
    mv -f -- "$TEMP_FILE" "$REPORT"
    cat "$REPORT"
    log_success "Enrollment instructions saved to ${REPORT}"
}

setup() {
    install_server
    check_paths
    check_server
    install -d -o "$TARGET_USER" -g "$(id -gn "$TARGET_USER")" -m 700 "$USER_DIR"
    if [[ -f "$LEGACY_KEYS_FILE" ]]; then
        # Drop privileges before touching files in the user's writable directory.
        command -v runuser >/dev/null || die "runuser is required to migrate existing public keys."
        cat "$LEGACY_KEYS_FILE" | runuser -u "$TARGET_USER" -- bash -c '
            set -euo pipefail
            umask 077
            file="$1/keys"
            [[ ! -L "$file" ]] || { echo "ERROR: Refusing symlinked user keys" >&2; exit 1; }
            temp=$(mktemp "$1/.migration.XXXXXX")
            trap '\''rm -f -- "$temp"'\'' EXIT
            { if [[ -f "$file" ]]; then cat "$file"; printf "\n"; fi; cat; } |
                awk '\''NF && !seen[$0]++'\'' > "$temp"
            chmod 600 "$temp"
            mv -f -- "$temp" "$file"
        ' _ "$USER_DIR"
    fi
    if [[ -f "$USER_CONFIG" ]]; then
        [[ -f "$ADDITIVE_CONFIG" ]] || die "Missing saved additive policy; recover it before re-running setup."
        local active_candidate additive_candidate mode="additive"
        new_temp
        active_candidate="$TEMP_FILE"
        replace_legacy_key_path "$USER_CONFIG" > "$active_candidate"
        new_temp
        additive_candidate="$TEMP_FILE"
        replace_legacy_key_path "$ADDITIVE_CONFIG" > "$additive_candidate"
        if grep -Fxq "# Managed by ssh-yubikey.sh: enforced" "$USER_CONFIG"; then
            mode="enforced"
        fi
        apply_policy "$active_candidate" "$mode" "$additive_candidate"
        log_info "Existing authentication policy retained (setup never disables enforcement)."
    else
        new_temp
        write_policy additive > "$TEMP_FILE"
        apply_policy "$TEMP_FILE" additive "$TEMP_FILE"
    fi
    if [[ -f "$LEGACY_KEYS_FILE" ]]; then
        mv -- "$LEGACY_KEYS_FILE" "${BACKUP}/legacy.keys"
    fi
    save_server_info
    log_success "Server prepared for ${TARGET_USER}. Now log in as that user, WITHOUT sudo, and run:"
    printf '  bash ssh-yubikey.sh configure\n'
}

replace_legacy_key_path() {
    awk -v old="$LEGACY_KEYS_FILE" -v new="$KEYS_FILE" '
        $1 == "AuthorizedKeysFile" {
            for (i = 2; i <= NF; i++) if ($i == old) $i = new
        }
        { print }
    ' "$1"
}

save_server_info() {
    local keyword host_key found=0
    new_temp
    printf '%s\n' "$(setting port)" > "$TEMP_FILE"
    while read -r keyword host_key; do
        [[ "$keyword" == "hostkey" ]] || continue
        [[ -f "${host_key}.pub" ]] || die "Missing configured SSH host public key: ${host_key}.pub"
        ssh-keygen -l -E sha256 -f "${host_key}.pub" >> "$TEMP_FILE"
        found=1
    done <<< "$EFFECTIVE"
    (( found )) || die "No SSH host public keys found."
    install -o root -g root -m 644 "$TEMP_FILE" "$SERVER_INFO"
}

read_server_info() {
    IFS= read -r DETECTED_PORT < "$SERVER_INFO"
    [[ "$DETECTED_PORT" =~ ^[0-9]{1,5}$ ]] &&
        (( 10#$DETECTED_PORT >= 1 && 10#$DETECTED_PORT <= 65535 )) ||
        die "Invalid server metadata; ask the administrator to re-run setup."
    [[ "$(wc -l < "$SERVER_INFO")" -ge 2 ]] ||
        die "Missing server host fingerprints; ask the administrator to re-run setup."
}

configure() {
    if [[ -z "$SERVER_HOST" ]]; then
        prompt_setup_value "Server DNS name or IP reachable from your SSH client: " "--host HOST" SERVER_HOST
    fi
    save_connection
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

prompt_setup_value() {
    local prompt="$1" option="$2" variable="$3"
    [[ -t 0 ]] ||
        die "Non-interactive operation requires ${option}; provide it explicitly."
    read -r -p "$prompt" "$variable" ||
        die "Could not read setup input; specify ${option} explicitly."
}

select_target_user() {
    local command="$1"
    case "$command" in
        configure|enroll|info)
            local caller
            caller=$(id -un)
            [[ -z "$TARGET_USER" || "$TARGET_USER" == "$caller" ]] ||
                die "User commands can manage only your own account (${caller}), not ${TARGET_USER}."
            TARGET_USER="$caller"
            ;;
    esac
    if [[ -z "$TARGET_USER" && "$command" == "setup" ]]; then
        if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
            TARGET_USER="$SUDO_USER"
            log_info "Using sudo caller '${TARGET_USER}' as the SSH account; override with --user USER."
        else
            prompt_setup_value "Existing non-root SSH account to configure: " "--user USER" TARGET_USER
        fi
    fi
    [[ -n "$TARGET_USER" ]] ||
        die "--user USER is required. Run the script as root/sudo, but specify the non-root SSH login to configure."
    [[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]*$ && "$TARGET_USER" != "root" ]] ||
        die "--user must be a non-root SSH login (for example, azureuser), not the installer account. The script itself must run as root/sudo."
    id "$TARGET_USER" >/dev/null 2>&1 || die "Account does not exist: ${TARGET_USER}"
    [[ "$(id -u "$TARGET_USER")" != "0" ]] ||
        die "The SSH account selected by --user must not have UID 0. Keep running the installer as root/sudo."
}

check_command_role() {
    local command="$1" uid="$2"
    case "$command" in
        setup|enforce|disable-enforcement)
            [[ "$uid" -eq 0 ]] || die "${command} requires root privileges; run with sudo."
            ;;
        configure|enroll|info)
            [[ "$uid" -ne 0 ]] || die "Run ${command} as your regular SSH user WITHOUT sudo. Only setup and enforcement require root."
            ;;
    esac
}

main() {
    local command="${1:-}"
    [[ -n "$command" ]] || { usage; exit 1; }
    shift
    case "$command" in
        -h|--help) usage; return ;;
        setup|configure|enroll|info|enforce|disable-enforcement) ;;
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
    check_command_role "$command" "$EUID"
    select_target_user "$command"
    [[ "$command" == "configure" || ( -z "$SERVER_HOST" && -z "$SERVER_PORT" ) ]] ||
        die "--host and --port belong to configure, run as your regular user after root setup."
    [[ "$command" == "enroll" || -z "$PUBLIC_KEY" ]] || die "--public-key is enroll-only."
    [[ "$command" != "enroll" || -n "$PUBLIC_KEY" ]] || die "enroll requires --public-key FILE."
    [[ "$command" == "enforce" || "$CONFIRM_TESTED" == "0" ]] || die "--confirm-tested is enforce-only."
    USER_CONFIG="${STATE_DIR}/${TARGET_USER}.conf"
    ADDITIVE_CONFIG="${STATE_DIR}/${TARGET_USER}.additive"
    SERVER_INFO="${STATE_DIR}/${TARGET_USER}.server-info"
    LEGACY_KEYS_FILE="${STATE_DIR}/${TARGET_USER}.keys"
    USER_DIR="${STATE_DIR}/users/${TARGET_USER}"
    KEYS_FILE="${USER_DIR}/keys"
    CONNECTION_FILE="${USER_DIR}/connection"
    REPORT="${USER_DIR}/enrollment.txt"
    KEY_BACKUP_DIR="${USER_DIR}/backups"
    case "$command" in
        setup|enforce|disable-enforcement)
            [[ ! -L "$STATE_DIR" ]] || die "Refusing symlinked state directory."
            install -d -o root -g root -m 755 "$STATE_DIR"
            [[ ! -L "${STATE_DIR}/.lock" ]] || die "Refusing symlinked lock file."
            exec 9>"${STATE_DIR}/.lock"
            ;;
        *)
            check_user_state
            WORK_DIR="$USER_DIR"
            exec 9>"${USER_DIR}/.lock"
            ;;
    esac
    flock -n 9 || die "Another YubiKey SSH operation is running."
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    case "$command" in
        setup) setup ;;
        enforce|disable-enforcement)
            check_paths
            check_server
            if [[ "$command" == "enforce" ]]; then enforce; else disable_enforcement; fi
            ;;
        configure|enroll|info)
            read_server_info
            case "$command" in
                configure) configure ;;
                enroll) enroll ;;
                info) write_report ;;
            esac
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
