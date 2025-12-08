# AI Context Guide: Pi-hole + WireGuard VPN Project

**File:** AI-CONTEXT.md  
**Type:** Technical Documentation  
**Category:** Development Reference  
**Created:** 2025-12-07  
**Version:** 1.0.0

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Repository History & Evolution](#repository-history--evolution)
3. [Architecture & Design Philosophy](#architecture--design-philosophy)
4. [Core Components](#core-components)
5. [Script Interdependencies](#script-interdependencies)
6. [Update Mechanism Flow](#update-mechanism-flow)
7. [Configuration Management](#configuration-management)
8. [Network & Port Architecture](#network--port-architecture)
9. [Security Model](#security-model)
10. [File Structure & Permissions](#file-structure--permissions)
11. [Installation Profiles](#installation-profiles)
12. [Common Pitfalls & Gotchas](#common-pitfalls--gotchas)
13. [Testing & Validation](#testing--validation)
14. [Future Improvement Areas](#future-improvement-areas)
15. [Universal Constants](#universal-constants)

---

## Project Overview

### Purpose

Automated installer and maintenance system for Pi-hole DNS ad-blocker with optional WireGuard VPN. Designed for:
- **Raspberry Pi** deployments (home networks)
- **Azure VMs** (cloud-based DNS filtering)
- **Generic Linux** servers (Ubuntu/Debian-based)

### Key Value Propositions

1. **One-Command Installation** - From bare Linux to production Pi-hole in minutes
2. **Private Repository Support** - GitHub authentication for sensitive configurations
3. **Automated Maintenance** - Self-updating scripts with randomized cron schedules
4. **Security Hardening** - Progressive Fail2Ban, SSH hardening, MFA support
5. **Encrypted Lists** - GPG-based list encryption with automatic key management
6. **Multiple Profiles** - Full protection, security-only, or basic configurations

### Project Scale

- **Lines of Code:** ~5,500+ across all scripts
- **Configuration Files:** 200+ lines of templates
- **Documentation:** 1,500+ lines across 5 documents
- **List Management:** Handles 50+ blocklists, 100+ regex patterns
- **Supported Platforms:** 3 (Raspberry Pi, Azure, Generic Linux)

---

## Repository History & Evolution

### Original State (Pre-2025-12-07)

**Two Separate Repositories:**

1. **Personal-Pi-Hole-configs**
   - Purpose: Configuration files and lists
   - Contents: Blocklists, allowlists, regex patterns
   - Issue: No installer, manual deployment required

2. **Azure-Pihole-VPN-setup**
   - Purpose: Installation scripts for Azure VMs
   - Contents: Deployment scripts, installer
   - Issue: Azure-specific, not portable

**Problems:**
- Fragmented documentation
- Duplicate maintenance effort
- No unified update mechanism
- No private repository authentication
- Hardcoded URLs across multiple files

### Consolidation (2025-12-07)

**Merged into:** `Personal_Contained_Pihole`

**Changes Made:**
1. Combined all lists, scripts, and installer into single repo
2. Updated 100+ URL references across all files
3. Created unified installer (`install-pihole-vpn.sh`)
4. Streamlined update hierarchy (`refresh.sh` → `updates.sh` → all scripts)
5. Enhanced documentation (README, INSTALL)
6. Fixed critical port configuration bugs (566→5335, 555→5053)
7. Created comprehensive example configurations

**Result:** Single source of truth, easier maintenance, simpler deployment

---

## Architecture & Design Philosophy

### Core Principles

1. **Separation of Concerns**
   - Installer: One-time setup
   - Updates.sh: Ongoing maintenance
   - Auth Helper: Reusable authentication library
   - Each script has single, clear responsibility

2. **Fail-Safe Defaults**
   - Auto-detect platform when possible
   - Sensible defaults for all options
   - Backup configs before modification
   - Rollback capability on failures

3. **Idempotency**
   - Scripts can be run multiple times safely
   - Check before create/modify
   - Skip if already configured correctly

4. **Progressive Enhancement**
   - Basic installation works without optional features
   - VPN is optional (INSTALL_VPN="no")
   - MFA is optional (ENABLE_MFA="no")
   - GPG encryption is optional (place keys in installer/public-gpg-keys/)

5. **Security by Default**
   - Token files: 600 permissions (root-only)
   - CONFIG directory: 700 permissions
   - SSH: AllowUsers, root disabled
   - Fail2Ban: Enabled by default with progressive banning

### Design Patterns

**Bootstrap Pattern:**
- `refresh.sh` downloads only `updates.sh`
- `updates.sh` manages all other scripts
- Minimizes initial download, centralizes update logic

**Library Pattern:**
- Reusable functions across multiple scripts
- Single implementation, multiple consumers

**Validation Pattern:**
- Validate input before action
- Test configurations before applying
- Backup before destructive operations
- Provide rollback mechanisms

---

## Core Components

### 1. install-pihole-vpn.sh (1,702 lines)

**Purpose:** Primary installer for fresh systems

**Key Functions:**
- `detect_platform()` - Auto-detect Raspberry Pi, Azure, or generic Linux
- `detect_network()` - Find current IP address
- `load_config_file()` - Parse installer.conf for unattended installation
- `prompt_configuration()` - Interactive prompts if no config file
- `install_pihole()` - Pi-hole installation via official installer
- `install_unbound()` - Recursive DNS resolver (port 5335)
- `install_cloudflared()` - DNS over HTTPS proxy (port 5053)
- `install_wireguard()` - VPN server setup (port 51820)
- `setup_fail2ban()` - Progressive banning configuration
- `harden_ssh()` - SSH security hardening
- `install_update_scripts()` - Download all maintenance scripts


**Installation Flow:**
1. Parse arguments (`--debug`, `--config=FILE`, `--repair`)
2. Check root privileges
3. Detect platform and network
4. Load config or prompt interactively
5. Confirm settings with user
6. Create directory structure
7. Generate configuration files (type.conf, dns_type.conf, test.conf, ver.conf)
8. System update and dependencies
9. Security setup (unattended-upgrades, Fail2Ban, SSH)
10. GPG key generation and auto-import from installer/public-gpg-keys/
11. Pi-hole installation
12. DNS provider (Unbound or Cloudflared)
13. Update scripts installation
14. Cron job configuration
15. WireGuard VPN (optional) with dnsmasq addn-hosts configuration
16. MFA configuration (optional)
17. Final status summary

**Repair Mode:**
- Flag: `--repair`
- State file: `/var/log/pihole-vpn-install.state`
- Tracks completed steps, skips them on re-run
- Useful for interrupted or failed installations

**Critical Paths:**
```
/scripts/
  ├── temp/                    # Temporary downloads
  └── Finished/                # Deployed scripts
      ├── CONFIG/              # Configuration files (755 permissions)
      │   ├── type.conf                  (server type: "full"/"security"/"basic")
      │   ├── test.conf                  (test mode: "no"/"yes" - literal strings)
      │   ├── dns_type.conf              ("cloudflared"/"unbound" - literal strings)
      │   └── ver.conf                   (Pi-hole version: "6")
      └── *.sh                 # All management scripts (755)
```

### 2. updates.sh (1,758 lines)

**Purpose:** Central update manager for lists, scripts, and database

**Key Commands:**
- `full-update` - Everything (lists + scripts + database)
- `purge-and-update` - Clear database, rebuild from scratch
- `allow-update` - Allowlist only
- `block-regex-update` - Regex patterns only
- `quick-update` - Lists only, skip scripts
- `refresh` - Update all scripts (refresh.sh, Research.sh, etc.)
- `--setup-token` - Configure GitHub authentication

**Key Functions:**
- `download_file()` - Wrapper supporting authenticated/unauthenticated downloads
- `download_gpg_file()` - Download and decrypt GPG-encrypted files
- `parallel_download()` - Parallel download with fallback to sequential
- `download_scripts()` - Download all 5 management scripts
- `download_full_config()` - Full protection lists
- `download_security_config()` - Security-only lists
- `download_*_allowlists()` - Various allowlist sources
- `assemble_and_deploy()` - Merge lists, update database
- `update_pihole_database()` - Direct gravity.db manipulation
- `purge_database()` - Clear domainlist table
- `cmd_refresh()` - Deploy all scripts to /scripts/Finished/

**Script Management:**
Downloads and deploys these 3 scripts:
1. `refresh.sh` - Bootstrap updater
2. `Research.sh` - Query research tool
3. `wireguard-manager.sh` - VPN client manager

**Database Operations:**
- Direct SQLite manipulation of `/etc/pihole/gravity.db`
- Table: `domainlist` (domain, type, enabled, date_added, comment)
- Types: 0=allow, 1=block, 2=regex-allow, 3=regex-block
- Preserves Pi-hole's internal structure

**Configuration Files Read:**
- `/scripts/Finished/CONFIG/type.conf` - Server type ("full"/"security"/"basic")
- `/scripts/Finished/CONFIG/test.conf` - Test mode ("no" or "yes" - literal strings)
- `/scripts/Finished/CONFIG/dns_type.conf` - DNS provider ("cloudflared" or "unbound" - literal strings)
- `/scripts/Finished/CONFIG/ver.conf` - Pi-hole version ("6")

**CRITICAL:** Config files contain literal strings, NOT numeric values:
- dns_type.conf: "cloudflared" or "unbound" (NOT 0/1)
- test.conf: "no" or "yes" (NOT 0/1)
- Installer creates these files automatically with correct format
- Directory permissions: 755 (CONFIG dir), 644 (config files)

### 3. refresh.sh (111 lines)

**Purpose:** Bootstrap script - updates updates.sh only

**Design Rationale:**
- Minimal script that rarely changes
- Downloads the "real" updater (updates.sh)
- Creates update hierarchy: refresh.sh → updates.sh → everything else
- Users run this first, then `updates.sh refresh` for full script update

**Key Functions:**
- `download()` - Download updates.sh with authentication
- `move()` - Deploy updates.sh to /scripts/Finished/

**Simplification (2025-12-07):**
- Previously downloaded Research.sh too
- Now downloads only updates.sh
- Updates.sh handles all other script downloads

### 4. wireguard-manager.sh (870+ lines)

**Purpose:** Interactive VPN client management with hostname resolution

**Features:**
1. Add clients (generates config + QR code)
2. List clients with connection status
3. Remove clients
4. Show client configurations
5. Display QR codes for mobile setup
6. Revoke client access
7. Show VPN statistics
8. Restart WireGuard service
9. Backup configurations
10. Show file locations (NEW)

**Key Functions:**
- `add_client()` - Generate keys, create config, add to server, update hosts file
- `list_clients()` - Show all clients with status (connected/not in config)
- `remove_client()` - Remove from server config, hosts file, and cleanup
- `show_client_config()` - Display config for reimport
- `show_file_locations()` - Display all config file paths and status (NEW)
- `show_menu()` - Interactive TUI menu (10 options)

**VPN Network:**
- Server: 10.7.0.1/24 (hostname: wg-server)
- Clients: 10.7.0.2 - 10.7.0.254
- DNS: 10.7.0.1 (Pi-hole)
- Hostname Resolution: `/etc/wireguard/hosts` with dnsmasq addn-hosts

**Hostname Resolution:**
- Each client gets entry in `/etc/wireguard/hosts`
- Format: `10.7.0.X clientname`
- Dnsmasq config: `/etc/dnsmasq.d/02-pihole-wireguard.conf`
- Automatic updates when clients added/removed
- DNS service restarted after hosts file changes
- Port: Configurable (default 51820)

**Security:**
- Pre-shared keys for all clients
- Automatic IP assignment
- Config files: 600 permissions
- QR codes for mobile devices

### 5. Research.sh (Function TBD)

**Purpose:** Query research tool for Pi-hole

**Note:** Script exists in repository but exact functionality not fully documented in current analysis. Should be reviewed for:
- Query log analysis
- Domain research
- Blocking decision assistance
- Statistics gathering

---

## Script Interdependencies

### Dependency Graph

```
install-pihole-vpn.sh (one-time)
    ↓
    Downloads: updates.sh, refresh.sh, Research.sh, wireguard-manager.sh
    ↓
    Configures: Cron jobs → updates.sh purge-and-update

User runs: refresh.sh (as needed)
    ↓
    Downloads: updates.sh
    ↓
    Instructs user: Run "updates.sh refresh"

User runs: updates.sh refresh
    ↓
    Downloads: All scripts
    ↓
    Deploys: refresh.sh, Research.sh, wireguard-manager.sh

User runs: updates.sh full-update
    ↓
    Downloads: Lists, configs, scripts
    ↓
    Calls: assemble_and_deploy()
    ↓
    Updates: gravity.db
    ↓
    Restarts: pihole-FTL
```

### Source Chain

**No external sourcing required** - All scripts are self-contained

---

## Update Mechanism Flow

### Full Update Flow (updates.sh full-update)

1. **Pre-flight Checks**
   - Verify root privileges
   - Read configuration files (type.conf, test.conf, dns_type.conf)
   - Create temp directory

2. **Script Downloads** (parallel when possible)
   - refresh.sh
   - Research.sh
   - wireguard-manager.sh

3. **Configuration Downloads** (based on SERVER_TYPE)
   - **Full:** main.adlist.list, all regex files, encrypted lists
   - **Security:** security_basic_adlist.list, basic_security.regex, oTLD.regex
   - **Basic:** Minimal set

4. **Allowlist Downloads** (all types)
   - Public allowlists
   - Regex allowlists
   - Encrypted allowlists

5. **Assembly Phase** (assemble_and_deploy)
   - Merge all regex files → regex.list
   - Merge all allowlists → whitelist.txt
   - Clean line endings
   - Remove duplicates
   - Sort for consistency

6. **Deployment Phase**
   - Deploy regex.list → /etc/pihole/
   - Deploy whitelist.txt → /etc/pihole/
   - Deploy adlists.list → /etc/pihole/
   - Deploy scripts → /scripts/Finished/
   - Set permissions (755 for scripts)

7. **Database Update** (update_pihole_database)
   - Clear domainlist table
   - Insert allowlist domains (type=0)
   - Insert regex patterns (type=2 for allow, type=3 for block)
   - Mark all as enabled

8. **Service Restart**
   - `pihole restartdns reload-lists`
   - Verify FTL service running

9. **Post-Update**
   - Log completion
   - Check if reboot needed
   - Display summary

### Purge and Update Flow (purge-and-update)

Same as full-update, but adds:
- **Pre-Download:** `purge_database()` - Clear domainlist table completely
- **Reason:** Ensures clean state, removes orphaned entries

### Quick Update Flow (quick-update)

Skips:
- Script downloads
- Script deployment

Only:
- Download lists
- Update database
- Restart DNS

**Use Case:** Scheduled updates where scripts don't change often

---



## Configuration Management

### installer.conf.template Structure

**Required Fields:**
- `SERVER_TYPE` - full/security/basic
- `DNS_TYPE` - unbound/cloudflared
- `INSTALL_VPN` - yes/no

**Optional Fields:**
- `PLATFORM` - azure/rpi/other (auto-detected)
- `WIREGUARD_PORT` - Default 51820
- `STATIC_IPV4` - Auto-detected if not set
- `ENABLE_MFA` - yes/no, default no
- `REAL_USER` - Auto-detected from SUDO_USER
- `DEBUG_MODE` - true/false, default false

### Configuration Files (Runtime)

**Location:** `/scripts/Finished/CONFIG/`

**Files:**
- `type.conf` - full, security, or basic
- `test.conf` - true/false (test system flag)
- `dns_type.conf` - unbound or cloudflared
- `ver.conf` - Pi-hole version (5 or 6)
- `github_token.conf` - GitHub PAT (600 permissions)
- `github_token_expiry.conf` - Token expiration date (optional)

**Updates.sh Reads:**
```bash
Type=$(<"$CONFIG/type.conf")          # Determines which lists to download
test_system=$(<"$CONFIG/test.conf")   # Affects list selection
is_cloudflared=$(<"$CONFIG/dns_type.conf")
version=$(<"$CONFIG/ver.conf")        # Affects database operations
```

### Profile Behavior

**Full Protection (SERVER_TYPE="full"):**
- Downloads: main.adlist.list
- Regex: main.regex, oTLD.regex, uslocal.regex, country.regex.gpg
- Blocklists: All available
- Allowlists: All types (public, regex, encrypted)
- Best for: Home networks, maximum protection

**Security Only (SERVER_TYPE="security"):**
- Downloads: security_basic_adlist.list
- Regex: basic_security.regex, oTLD.regex
- Blocklists: Malware, phishing, tracking only
- Allowlists: Security-focused only
- Best for: Servers, business environments

**Basic (SERVER_TYPE="basic"):**
- Downloads: Minimal adlist
- Regex: Essential patterns only
- Blocklists: Core blocking only
- Allowlists: Minimal false positive fixes
- Best for: Testing, limited resources

---

## Network & Port Architecture

### Port Assignments

| Service | Port | Bind | Protocol | Purpose |
|---------|------|------|----------|---------|
| Pi-hole DNS | 53 | 0.0.0.0 | UDP/TCP | Public DNS queries |
| Pi-hole Web | 80 | 0.0.0.0 | TCP | Admin interface |
| SSH | 22 | 0.0.0.0 | TCP | Remote administration |
| Unbound | 5335 | 127.0.0.1 | UDP/TCP | Recursive DNS (localhost only) |
| Cloudflared | 5053 | 127.0.0.1 | UDP/TCP | DoH proxy (localhost only) |
| WireGuard | 51820 | 0.0.0.0 | UDP | VPN connections |

### DNS Resolution Chain

**Without VPN:**
```
Client Device
    ↓ (DNS query to Pi-hole IP:53)
Pi-hole (port 53)
    ↓ (Forward to localhost:5335 or localhost:5053)
Unbound (5335) OR Cloudflared (5053)
    ↓ (Upstream resolution)
Root DNS Servers OR Cloudflare 1.1.1.1
```

**With VPN:**
```
VPN Client (anywhere on internet)
    ↓ (WireGuard tunnel to server:51820)
WireGuard Server (10.7.0.1)
    ↓ (Client gets 10.7.0.2-254 IP, DNS=10.7.0.1)
Pi-hole (port 53, listening on VPN interface)
    ↓ (Forward to localhost:5335 or localhost:5053)
Unbound (5335) OR Cloudflared (5053)
    ↓ (Upstream resolution)
Root DNS Servers OR Cloudflare 1.1.1.1
```

### Network Isolation

**Public-Facing:**
- Port 53 (DNS) - Required for clients
- Port 80 (HTTP) - Admin interface (recommend VPN-only)
- Port 22 (SSH) - Hardened, key-based
- Port 51820 (WireGuard) - Encrypted tunnel

**Localhost-Only:**
- Port 5335 (Unbound) - Not accessible externally
- Port 5053 (Cloudflared) - Not accessible externally

**Security Benefit:**
- Upstream DNS resolvers isolated from network
- Only Pi-hole exposed as DNS endpoint
- Encrypted VPN provides secure admin access
- No need for "security through obscurity" on internal ports

### Critical Port Configuration Bugs (Fixed 2025-12-07)

**Bug 1: Unbound Port**
- **Was:** 566 (line 693 in install-pihole-vpn.sh)
- **Fixed:** 5335
- **Impact:** Would break Pi-hole → Unbound communication
- **Root Cause:** Typo or copy-paste error

**Bug 2: Cloudflared Port**
- **Was:** 555 (multiple locations in install-pihole-vpn.sh)
- **Fixed:** 5053
- **Impact:** Would break Pi-hole → Cloudflared communication
- **Locations Fixed:** 
  - Full/basic configuration (line ~866)
  - Security configuration (line ~884)
  - dnsmasq config (line ~920)

**Why These Were Bugs, Not Features:**
- Industry-standard ports expected by documentation
- Localhost-only binding already provides security
- Non-standard ports broke expected behavior
- No security benefit from obscurity on localhost

---

## Security Model

### Defense in Depth Layers

**Layer 1: Network Perimeter**
- Firewall rules (Azure NSG, iptables)
- Only necessary ports exposed
- VPN for admin access (recommended)

**Layer 2: Service Hardening**
- Pi-hole: Latest version, regular updates
- Unbound/Cloudflared: Localhost-only binding
- WireGuard: Modern cryptography (ChaCha20, Curve25519)

**Layer 3: SSH Security**
- AllowUsers: Specific user whitelist
- Root login disabled
- Password authentication optional (key-based recommended)
- Fail2Ban protection (see Layer 4)

**Layer 4: Progressive Banning (Fail2Ban)**
```
First Offense: 3 failed attempts within 10 min → 25 min ban
    ↓
Second Level: 3 short bans within 24 hours → 7 day ban
    ↓
Permanent Ban: 2 recidive bans within 7 days → Permanent ban (-1)
```

**Jails Configured:**
- `[sshd]` - SSH brute force protection
- `[pihole]` - Pi-hole admin interface (401/403 errors)
- `[recidive]` - Tracks repeat offenders
- `[recidive-permanent]` - Permanent ban for serial offenders

**Layer 5: File System Security**
- Token files: 600 (root:root)
- CONFIG directory: 700 (root:root)
- Scripts: 755 (executable by all, writable by root)
- WireGuard configs: 600/700

**Layer 6: Credential Management**
- GitHub tokens: Secured, no logging, expiration tracking
- GPG keys: Automatic import from installer/public-gpg-keys/, password-protected private keys
- WireGuard keys: Pre-shared keys for all clients

**Layer 6a: GPG Key Auto-Management**
- Public keys stored in GitHub repository: `installer/public-gpg-keys/*.gpg`
- Downloaded during installation to: `/scripts/Finished/CONFIG/public-gpg-keys/`
- Auto-imported during installation (no user prompts)
- Auto-checked and updated during `full-update` and `purge-and-update`
- Fingerprint-based comparison prevents duplicate imports
- Updates script checks GitHub for new keys automatically

**Layer 7: System Updates**
- Unattended-upgrades: Security patches automatic
- Cron jobs: Regular list updates
- Script refresh: Self-updating system

**Layer 8: Optional MFA**
- Google Authenticator for SSH
- TOTP-based second factor
- Requires post-install user configuration

### Security Through Obscurity (NOT USED)

**What We Don't Do:**
- ❌ Non-standard ports for localhost services (5335, 5053 are standard)
- ❌ Hide service banners (normal behavior maintained)
- ❌ Obfuscate file names or locations (standard paths)

**Why:**
- Localhost services already isolated by network binding
- Obscurity doesn't replace real security
- Standard configurations aid troubleshooting
- Community documentation assumes standard setup

### Threat Model

**Protected Against:**
- ✅ Brute force attacks (Fail2Ban)
- ✅ Unauthorized SSH access (AllowUsers, keys)
- ✅ DNS amplification attacks (rate limiting in Pi-hole)
- ✅ Man-in-the-middle on DNS (DoH with Cloudflared, DNSSEC with Unbound)
- ✅ Credential theft (600 permissions, root-only)
- ✅ Service exploitation (regular updates)

**Not Protected Against:**
- ❌ Physical access to server (full disk encryption not included)
- ❌ Compromised client devices (VPN provides secure tunnel, not endpoint security)
- ❌ Zero-day exploits (mitigated by updates, not prevented)
- ❌ Social engineering (user education required)

---

## File Structure & Permissions

### Directory Tree

```
/scripts/                                    (755, root:root)
├── temp/                                    (755, root:root)
│   └── (temporary downloads, cleaned after updates)
└── Finished/                                (755, root:root)
    ├── CONFIG/                              (700, root:root) ← CRITICAL
    │   ├── backups/                         (700, root:root)
    │   │   └── github_token_*.conf.bak      (600, root:root)
    │   ├── github_token.conf                (600, root:root) ← SENSITIVE
    │   ├── github_token_expiry.conf         (600, root:root)
    │   ├── type.conf                        (644, root:root)
    │   ├── test.conf                        (644, root:root)
    │   ├── dns_type.conf                    (644, root:root)
    │   ├── ver.conf                         (644, root:root)
    │   └── encrypt.list                     (644, root:root)
    ├── updates.sh                           (755, root:root)
    ├── refresh.sh                           (755, root:root)
    ├── Research.sh                          (755, root:root)

    ├── wireguard-manager.sh                 (755, root:root)
    ├── unbound_root_hints_update.sh         (755, root:root)
    ├── cloudflared                          (644, root:root)
    └── server-public-key.gpg                (644, root:root)

/etc/pihole/                                 (755, root:root)
├── gravity.db                               (644, pihole:pihole)
├── pihole-FTL.conf                          (644, root:root)
├── setupVars.conf                           (644, root:root)
├── adlists.list                             (644, root:root)
├── whitelist.txt                            (644, root:root)
└── regex.list                               (644, root:root)

/etc/wireguard/                              (700, root:root) ← CRITICAL
├── wg0.conf                                 (600, root:root) ← SENSITIVE
├── hosts                                    (644, root:root) ← VPN hostname mappings
├── clients/                                 (700, root:root)
│   └── *.conf                               (600, root:root) ← SENSITIVE
├── server-private.key                       (600, root:root) ← SENSITIVE
└── server-public.key                        (600, root:root)

/etc/dnsmasq.d/                              (755, root:root)
├── 01-pihole.conf                           (644, root:root)
├── 02-pihole-wireguard.conf                 (644, root:root) ← VPN DNS config
├── 50-cloudflared.conf                      (644, root:root)
├── 51-unbound.conf                          (644, root:root)
└── 99-edns.conf                             (644, root:root)

/var/log/                                    (755, root:root)
├── pihole-updates.log                       (644, root:root)
├── pihole-vpn-install.log                   (644, root:root)
└── pihole/                                  (755, pihole:pihole)
    └── FTL.log                              (644, pihole:pihole)
```

### Permission Rationale

**700 Directories:**
- `/scripts/Finished/CONFIG/` - Contains sensitive tokens
- `/etc/wireguard/` - Contains VPN private keys
- Reason: Only root should list directory contents

**600 Files:**
- `github_token.conf` - GitHub PAT
- `github_token_expiry.conf` - Token metadata
- WireGuard configs - VPN private keys
- Reason: Only root should read/write sensitive credentials

**755 Scripts:**
- All `.sh` files in `/scripts/Finished/`
- Reason: Executable by all, modifiable only by root

**644 Config Files:**
- Pi-hole configs, lists, non-sensitive settings
- Reason: Readable by all (Pi-hole runs as 'pihole' user)

### Permission Changes Made (2025-12-07)

**Fixed: CONFIG Directory**
- **Was:** 700 (root-only, blocked update scripts)
- **Now:** 755 (readable by scripts)
- **Location:** install-pihole-vpn.sh line 530
- **Reason:** Update scripts need to read type.conf, dns_type.conf, test.conf, ver.conf
- **Security:** Config files still 644, directory traversable for script access

**Added: WireGuard Hosts File**
- **File:** `/etc/wireguard/hosts` (644, root:root)
- **Purpose:** VPN client hostname-to-IP mappings
- **Format:** `10.7.0.X clientname` (one per line)
- **Integration:** Dnsmasq `addn-hosts=/etc/wireguard/hosts`
- **Maintenance:** Auto-updated by wireguard-manager.sh when adding/removing clients

### Permission Validation Commands

```bash
# Check CONFIG directory and token file
ls -la /scripts/Finished/CONFIG/
# Should show: drwx------ (700) for directory
# Should show: -rw------- (600) for github_token.conf

# Check WireGuard directory
ls -la /etc/wireguard/
# Should show: drwx------ (700) for directory
# Should show: -rw------- (600) for wg0.conf

# Check scripts
ls -la /scripts/Finished/*.sh
# Should show: -rwxr-xr-x (755) for all scripts
```

---

## Installation Profiles

### Full Protection Profile

**Use Case:** Home networks, maximum ad/tracker blocking

**SERVER_TYPE:** `full`

**Lists Downloaded:**
- `main.adlist.list` - Comprehensive blocklist sources
- `main.regex` - General regex patterns
- `oTLD.regex` - Obscure TLD blocking (.zip, .loan, etc.)
- `uslocal.regex` - US-specific patterns
- `country.regex.gpg` - Encrypted country-specific patterns
- All allowlists (public, regex, encrypted)
- All blocklists

**Characteristics:**
- Most comprehensive protection
- Highest chance of false positives
- Requires allowlist tuning for specific services
- Best with GPG key for encrypted lists

**Recommended DNS:** Unbound (maximum privacy)

**Example Config:** `examples/installer.conf.full`

### Security Only Profile

**Use Case:** Servers, business networks, minimal maintenance

**SERVER_TYPE:** `security`

**Lists Downloaded:**
- `security_basic_adlist.list` - Malware/phishing sources only
- `basic_security.regex` - Security-focused patterns
- `oTLD.regex` - Obscure TLD blocking
- Security allowlists only
- No encrypted lists (GPG_KEY_COUNT=0)

**Characteristics:**
- Focused on security threats only
- Minimal false positives
- Less aggressive ad blocking
- Lower maintenance
- Good for production servers

**Recommended DNS:** Cloudflared (speed + Cloudflare's malware filtering)

**Example Config:** `examples/installer.conf.security`

### Basic Profile

**Use Case:** Testing, limited resources, troubleshooting

**SERVER_TYPE:** `basic`

**Lists Downloaded:**
- Minimal adlist sources
- Essential regex patterns only
- oTLD.regex (obscure TLD protection)
- Minimal allowlists

**Characteristics:**
- Lightest footprint
- Fast updates
- Good for debugging false positives
- Baseline protection only

**Recommended DNS:** Either (both work well with basic lists)

**Example Config:** Not created yet (could add examples/installer.conf.basic)

---

## Common Pitfalls & Gotchas

### 1. Port Configuration Errors

**Symptom:** Pi-hole can't resolve DNS, all queries timeout

**Cause:** Incorrect Unbound/Cloudflared port in config

**Fix:**
- Unbound MUST be on port 5335
- Cloudflared MUST be on port 5053
- Check `/etc/unbound/unbound.conf.d/pi-hole.conf`
- Check `/etc/dnsmasq.d/50-cloudflared.conf` or `99-edns.conf`

**Prevention:** Use standard ports (fixed in 2025-12-07 update)

### 2. CONFIG Directory Permissions

**Symptom:** Token file readable by non-root users

**Cause:** CONFIG directory was 755 instead of 700

**Fix:**
```bash
sudo chmod 700 /scripts/Finished/CONFIG
sudo chmod 600 /scripts/Finished/CONFIG/github_token.conf
sudo chown root:root /scripts/Finished/CONFIG/github_token.conf
```

**Prevention:** Installer now sets 700 (fixed 2025-12-07)

### 3. Script Update Ordering

**Symptom:** Scripts don't update, or partial updates

**Cause:** Running wrong script or wrong order

**Correct Order:**
1. `refresh.sh` - Updates updates.sh only
2. `updates.sh refresh` - Updates all scripts
3. `updates.sh full-update` - Updates lists + database

**Wrong:**
- Running `refresh.sh` expecting all scripts to update (it only updates updates.sh)
- Running `updates.sh` directly from GitHub (should use refresh.sh first)

### 4. Database Schema Version Mismatch

**Symptom:** "Table domainlist doesn't exist" or schema errors

**Cause:** Pi-hole version changed (v5 → v6), database structure different

**Fix:**
- Check `/scripts/Finished/CONFIG/ver.conf`
- Should match actual Pi-hole version
- If mismatch, update manually: `echo "6" | sudo tee /scripts/Finished/CONFIG/ver.conf`
- Run `pihole -up` to update Pi-hole
- Run `updates.sh purge-and-update` to rebuild database

### 5. GPG Key Import Failures

**Symptom:** country.regex.gpg fails to decrypt

**Causes:**
- GPG key not available in installer/public-gpg-keys/
- Wrong key imported
- Key expired
- Insufficient permissions

**Debug:**
```bash
# List imported keys
gpg --list-keys

# Try manual decryption
gpg --decrypt /scripts/temp/country.regex.gpg

# Check if keys exist in repository
ls -la /path/to/pihole-installer/installer/public-gpg-keys/
```

**Fix:**
- Add correct .gpg public key file to installer/public-gpg-keys/
- Run installation or updates to auto-import
- Check key hasn't expired
- Verify key matches encrypted file's recipient

### 6. WireGuard Port Conflicts

**Symptom:** WireGuard fails to start, "address already in use"

**Cause:** Port 51820 already used by another service

**Fix:**
- Use different port in installer.conf: `WIREGUARD_PORT="51821"`
- Update firewall rules to match new port
- Regenerate client configs with new port

**Check:**
```bash
sudo netstat -tulpn | grep 51820
```

### 7. SSH Lockout After Hardening

**Symptom:** Can't SSH after installation completes

**Causes:**
- User not in AllowUsers list
- Root login disabled but no other user configured
- MFA enabled but not set up

**Prevention:**
- Test SSH in new terminal BEFORE closing installation session
- Ensure REAL_USER is correctly detected/configured
- Complete MFA setup if ENABLE_MFA="yes"

**Recovery:**
- Physical console access or cloud serial console
- Edit `/etc/ssh/sshd_config`
- Temporarily comment out AllowUsers
- Restart sshd: `systemctl restart sshd`

### 8. Cron Job Timing Issues

**Symptom:** Updates run at unexpected times or conflict

**Cause:** Randomized times can overlap

**Check:**
```bash
sudo crontab -l
```

**Fix:**
- Manually adjust times in crontab if needed
- Ensure purge-and-update runs before allow-update
- Stagger by at least 1 hour

---

## Testing & Validation

### Pre-Deployment Testing

**1. URL Validation**
```bash
# Check all GitHub URLs point to correct repository
grep -r "github\.com/IcedComputer" --include="*.sh" --include="*.md"
# Should only show: Personal_Contained_Pihole
# Should NOT show: Personal-Pi-Hole-configs, Azure-Pihole-VPN-setup
```

**2. Port Configuration**
```bash
# Check Unbound port
grep -A5 "port:" installer/install-pihole-vpn.sh
# Should show: port: 5335 (not 566)

# Check Cloudflared port
grep "port 5" installer/install-pihole-vpn.sh
# Should show: --port 5053 (not 555)
# Should show: server=127.0.0.1#5053 (not 555)
```

**3. Permission Settings**
```bash
# Check CONFIG directory permissions
grep -A2 "chmod.*PATH_CONFIG" installer/install-pihole-vpn.sh
# Should show: chmod 700 (not 755)

# Check token file permissions
grep "chmod.*github_token" scripts/*.sh
# Should show: chmod 600 (multiple locations)
```

**4. Script Dependencies**
```bash
# Check updates.sh downloads all required scripts
grep -A10 "download_scripts()" scripts/updates.sh
# Should include: refresh.sh, Research.sh, wireguard-manager.sh

# Check refresh.sh only downloads updates.sh
grep -A10 "download()" scripts/refresh.sh
# Should only show: updates.sh download
```

### Post-Installation Testing

**1. DNS Resolution**
```bash
# Test Pi-hole
dig @127.0.0.1 google.com
# Should return: IP address, query time <100ms

# Test blocking
dig @127.0.0.1 ads.google.com
# Should return: 0.0.0.0 or server IP (blocked)

# Test with known good domain
dig @127.0.0.1 example.com
# Should return: 93.184.216.34 (or similar)
```

**2. Service Status**
```bash
# Pi-hole FTL
systemctl status pihole-FTL
# Should show: active (running)

# Unbound (if using)
systemctl status unbound
# Should show: active (running)

# Cloudflared (if using)
systemctl status cloudflared
# Should show: active (running)

# WireGuard (if installed)
systemctl status wg-quick@wg0
# Should show: active (exited) [WireGuard is kernel-space]
sudo wg show
# Should show: interface wg0, listen port, peers
```

**3. Port Listening**
```bash
# Check all services listening on correct ports
sudo netstat -tulpn | grep -E ":(53|5335|5053|51820|22|80)"

# Expected:
# :53   - pihole-FTL (0.0.0.0)
# :5335 - unbound (127.0.0.1) [if using Unbound]
# :5053 - cloudflared (127.0.0.1) [if using Cloudflared]
# :51820 - (UDP) [if WireGuard installed]
# :22   - sshd (0.0.0.0)
# :80   - lighttpd (0.0.0.0)
```

**4. File Permissions**
```bash
# Check sensitive files
sudo ls -la /scripts/Finished/CONFIG/github_token.conf
# Expected: -rw------- (600) root root

sudo ls -ld /scripts/Finished/CONFIG
# Expected: drwx------ (700) root root

sudo ls -la /etc/wireguard/wg0.conf
# Expected: -rw------- (600) root root (if VPN installed)
```

**5. Authentication**
```bash
# Test GitHub authentication
sudo bash /scripts/Finished/updates.sh --help
# Should NOT show authentication warnings

# Check token file exists
sudo test -f /scripts/Finished/CONFIG/github_token.conf && echo "Token exists" || echo "Token missing"
```

**6. Cron Jobs**
```bash
# Check cron configured
sudo crontab -l
# Should show:
# - purge-and-update (daily around 3:30 AM)
# - allow-update (every 8 hours)
# - pihole updateGravity (before purge)
# Plus Cloudflared restart if using Cloudflared
```

**7. SSH Hardening**
```bash
# Check AllowUsers configured
sudo grep "^AllowUsers" /etc/ssh/sshd_config
# Should show: AllowUsers <username>

# Check root login disabled
sudo grep "^PermitRootLogin" /etc/ssh/sshd_config
# Should show: PermitRootLogin no
```

**8. Fail2Ban**
```bash
# Check Fail2Ban running
sudo systemctl status fail2ban
# Should show: active (running)

# Check jails enabled
sudo fail2ban-client status
# Should show: sshd, pihole, recidive, recidive-permanent

# Check ban times configured
sudo fail2ban-client get sshd bantime
# Should show: 1500 (25 minutes)
```

### Automated Testing Script (Future Enhancement)

```bash
#!/bin/bash
# test-installation.sh - Automated validation

echo "Testing DNS resolution..."
dig @127.0.0.1 google.com +short || echo "FAIL: DNS resolution"

echo "Testing blocking..."
[[ $(dig @127.0.0.1 ads.google.com +short) == "0.0.0.0" ]] || echo "FAIL: Blocking"

echo "Testing service status..."
systemctl is-active pihole-FTL || echo "FAIL: Pi-hole not running"

echo "Testing authentication..."
[[ -f /scripts/Finished/CONFIG/github_token.conf ]] || echo "WARN: Token not configured"

echo "Testing permissions..."
[[ $(stat -c %a /scripts/Finished/CONFIG) == "700" ]] || echo "FAIL: CONFIG permissions"
[[ $(stat -c %a /scripts/Finished/CONFIG/github_token.conf) == "600" ]] || echo "FAIL: Token permissions"

echo "Testing cron jobs..."
sudo crontab -l | grep -q "purge-and-update" || echo "FAIL: Cron not configured"

echo "All tests complete!"
```

---

## Future Improvement Areas

### High Priority

1. **Automated Testing Framework**
   - Unit tests for core functions
   - Integration tests for full installation
   - CI/CD pipeline for validation
   - Automated deployment testing on Azure/AWS

2. **Better Error Recovery**
   - Rollback mechanism for failed updates
   - Automatic retry with exponential backoff
   - Health checks before/after updates
   - Alert system for critical failures

3. **Configuration Validation**
   - Pre-flight check for installer.conf
   - Syntax validation before loading
   - Warn about common misconfigurations
   - Template generator/wizard

4. **Monitoring & Alerting**
   - Optional email notifications on failures
   - Integration with monitoring systems (Prometheus, Grafana)
   - Health dashboard
   - Performance metrics collection

### Medium Priority

5. **Multi-Architecture Support**
   - ARM64 (Raspberry Pi 4/5)
   - x86_64 (Intel/AMD)
   - Test on more distributions (Arch, Fedora)

6. **Backup & Restore**
   - Automated config backups
   - One-command restore
   - Migration tool for server changes
   - Cloud backup integration (S3, Azure Blob)

7. **Documentation Improvements**
   - Video tutorials
   - Troubleshooting decision tree
   - FAQ section
   - Architecture diagrams

8. **Performance Optimization**
   - Parallel list downloads (already partially implemented)
   - Database optimization for large lists
   - Memory usage profiling
   - Disk I/O optimization

### Low Priority (Nice to Have)

9. **Web UI for Management**
   - Alternative to SSH for script management
   - Visual cron job editor
   - Token rotation UI
   - VPN client management web interface

10. **Alternative VPN Options**
    - OpenVPN support (in addition to WireGuard)
    - Tailscale integration
    - ZeroTier option

11. **Advanced List Management**
    - Custom list editor
    - A/B testing for lists
    - Automatic false positive detection
    - Community list recommendations

12. **Multi-Server Management**
    - Central management console
    - Deploy configs to multiple servers
    - Synchronized updates across fleet
    - Load balancing support

### Code Quality Improvements

13. **Refactoring Opportunities**
    - Break large functions into smaller units
    - Reduce code duplication
    - Improve error handling consistency
    - Add more debug logging

14. **Security Enhancements**
    - Token encryption at rest (beyond 600 permissions)
    - Rotate tokens automatically before expiration
    - Two-factor authentication for token access
    - Audit logging for sensitive operations

15. **Bash Best Practices**
    - More shellcheck compliance
    - Consistent quoting styles
    - Better trap handlers for cleanup
    - Function-level documentation

---

## Universal Constants

These principles guide all development:

### UC-001: Code Clarity Over Cleverness

**Principle:** Readable, maintainable code > clever one-liners

**Examples:**
```bash
# Good: Clear and explicit
if [[ -f "$TOKEN_FILE" ]]; then
    token=$(cat "$TOKEN_FILE")
fi

# Avoid: Clever but obscure
token=$([ -f "$TOKEN_FILE" ] && cat "$TOKEN_FILE")
```

**Application:**
- Verbose error messages over cryptic codes
- Descriptive variable names over abbreviations
- Comments explain "why" not "what"
- Step-by-step logic over combined operations

### UC-002: Meaningful Naming Conventions

**Principle:** Names should be self-documenting

**Guidelines:**
- Functions: Verb phrases (`download_file`, `install_dependencies`, `configure_service`)
- Variables: Descriptive nouns (`TOKEN_FILE`, `REPO_BASE`, `SERVER_TYPE`)
- Constants: SCREAMING_SNAKE_CASE (`readonly COLOR_GREEN`)
- Files: Lowercase with hyphens (`wireguard-manager.sh`, `installer.conf.template`)

**Avoid:**
- Single-letter variables (except loop counters)
- Ambiguous abbreviations (`tmp` vs `TEMPDIR`)
- Generic names (`data`, `result`, `value`)

### UC-003: ISO 8601 Date Format

**Principle:** Always use YYYY-MM-DD HH:MM:SS format

**Usage:**
```bash
# Timestamps in logs
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

# File naming
backup_file="github_token_$(date +'%Y%m%d_%H%M%S').conf.bak"

# Human-readable dates
echo "Created: 2025-12-07"
```

**Benefits:**
- Sortable chronologically
- Unambiguous (no US vs EU confusion)
- International standard
- grep-friendly

### UC-004: Professional Communication

**Principle:** Clear, respectful, helpful messaging

**Examples:**
```bash
# Good: Informative and actionable
log_error "Failed to download updates.sh"
log_info "Check network connection and GitHub token"
log_info "See /var/log/pihole-updates.log for details"

# Avoid: Vague or unprofessional
echo "Download failed lol"
echo "Broken!!!"
echo "Something went wrong"
```

**Guidelines:**
- Use proper grammar and spelling
- Provide context with errors
- Suggest next steps
- Avoid slang, emoji (except in README for emphasis)
- Be respectful of user's time

**User-Facing Messages:**
- Status updates during installation
- Progress indicators for long operations
- Clear prompts for required input
- Confirmation of important actions

---

## End of AI Context Guide

**Last Updated:** 2025-12-07  
**Maintained By:** IcedComputer  
**For:** AI assistants working on Personal_Contained_Pihole project

This document should be updated when:
- Major architectural changes occur
- New scripts or components are added
- Security model changes
- Critical bugs are fixed that reveal design flaws
- Installation flow changes significantly

---

**Questions for AI Assistants:**

If you're an AI working on this project and encounter confusion:

1. **Architecture Questions:** Refer to "Core Components" and "Script Interdependencies"
2. **Security Questions:** Refer to "Security Model" and "File Structure & Permissions"
3. **Bug Investigation:** Check "Common Pitfalls & Gotchas"
4. **Testing:** Use "Testing & Validation" section
5. **Design Decisions:** Review "Architecture & Design Philosophy"
6. **Historical Context:** See "Repository History & Evolution"

**When Making Changes:**

1. ✅ Follow Universal Constants (UC-001 through UC-004)
2. ✅ Update this document if architecture changes
3. ✅ Test changes using validation procedures
4. ✅ Check for security implications
5. ✅ Verify no breaking changes to existing deployments
6. ✅ Update relevant documentation (README, INSTALL, etc.)
7. ✅ Add example configurations if introducing new features

**Red Flags to Watch For:**

- 🚩 Hardcoded tokens or credentials
- 🚩 World-readable sensitive files (should be 600)
- 🚩 Non-standard ports for localhost services (use 5335, 5053)
- 🚩 Duplicate code across multiple scripts
- 🚩 Missing error handling
- 🚩 Unclear variable names
- 🚩 Breaking changes to public APIs
- 🚩 Removing backup/rollback functionality

---

**Happy coding! Remember: Clarity, security, and maintainability are our priorities.** 🎯
