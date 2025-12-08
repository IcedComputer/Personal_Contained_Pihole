# Pi-hole + WireGuard VPN Installer

**Version:** 1.0.0  
**Created:** 2025-12-07  
**Platforms:** Raspberry Pi, Ubuntu Server, Azure

---

## Overview

Automated installer for Pi-hole DNS ad blocker with WireGuard VPN support. This installer streamlines the setup process for both Raspberry Pi and Ubuntu Server environments (including Azure), with comprehensive configuration options and user-friendly management tools.

### Key Features

- **Automated Installation**: Single-command setup for complete Pi-hole + VPN stack
- **Platform Detection**: Automatically detects Raspberry Pi, Azure, or generic Linux
- **Flexible DNS**: Choose between Unbound (recursive) or Cloudflared (DoH)
- **WireGuard VPN**: Optional VPN with modern, secure implementation and user-friendly client management
- **Configuration Profiles**: Pre-configured security levels (Full, Security, Basic)
- **GPG Key Management**: Automated key generation and import for encrypted lists
- **Randomized Scheduling**: Automated updates with randomized cron times
- **Error Tracking**: Comprehensive logging with colored output and summary reports

---

## Quick Start

### Interactive Installation

```bash
# Download installer
curl --tlsv1.3 -sSL -o install-pihole-vpn.sh \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/install-pihole-vpn.sh

# Make executable
chmod +x install-pihole-vpn.sh

# Run installer (interactive prompts)
sudo bash install-pihole-vpn.sh
```

### Repair Mode (Resume Failed Installation)

If installation fails or is interrupted, you can resume from where it stopped:

```bash
# Resume installation, skipping already completed steps
sudo bash install-pihole-vpn.sh --repair
```

**How Repair Mode Works:**
- Tracks completed installation steps in `/var/log/pihole-vpn-install.state`
- Automatically skips steps that completed successfully
- Re-runs only failed or incomplete steps
- Useful for network interruptions, package failures, or manual cancellations
- State file is automatically deleted on successful completion

**Example Repair Scenarios:**
- Pi-hole installation failed → Repair mode skips system updates and retries Pi-hole
- Network timeout during script download → Repair mode skips completed installs
- Manual cancellation during VPN setup → Repair mode resumes from VPN step

### Unattended Installation

```bash
# Download installer and config template
curl --tlsv1.3 -sSL -o install-pihole-vpn.sh \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/install-pihole-vpn.sh
  
curl --tlsv1.3 -sSL -o installer.conf.template \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/installer.conf.template

# Create configuration
cp installer.conf.template installer.conf
vim installer.conf  # Edit settings

# Run unattended installation
sudo bash install-pihole-vpn.sh
```

---

## Prerequisites

### Supported Platforms

- **Raspberry Pi**: Raspberry Pi OS (Debian-based)
- **Ubuntu Server**: 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Azure**: Ubuntu Server VM with static IP
- **Other**: Debian-based Linux distributions

### System Requirements

- **RAM**: Minimum 512 MB (1 GB+ recommended)
- **Storage**: 2 GB free space minimum
- **Network**: Static IP address (or DHCP reservation)
- **Privileges**: Root access (sudo)
- **Internet**: Active connection for downloads

### Network Requirements

- **Firewall Rules**: 
  - TCP/UDP 53 (DNS)
  - TCP 80/443 (Pi-hole web interface)
  - UDP 51820 (WireGuard VPN, if installed)
- **Static IP**: Required for reliable DNS and VPN operation
- **Port Forwarding**: Required for VPN access from outside network

---

## Installation Options

### Configuration Profiles

#### Full Protection (Recommended)
```bash
SERVER_TYPE="full"
```
- All allowlists and blocklists
- Maximum protection against ads, trackers, malware
- May cause some false positives (easily adjustable)
- Best for: Home users, families, security-conscious setups

#### Security-Focused
```bash
SERVER_TYPE="security"
```
- Security-focused lists only (malware, phishing, tracking)
- Minimal impact on legitimate sites
- Best for: Business use, minimal intervention required

#### Basic Protection
```bash
SERVER_TYPE="basic"
```
- Essential blocking only
- Minimal false positives
- Best for: Testing, troubleshooting, minimal overhead

### DNS Provider Options

#### Unbound (Recommended for Privacy)
```bash
DNS_TYPE="unbound"
```
**Advantages:**
- Maximum privacy (no third-party DNS provider)
- Resolves DNS directly from root servers
- No logging of DNS queries
- Complete control over DNS resolution

**Disadvantages:**
- Slightly slower initial queries
- More resource intensive
- Requires periodic root hints updates (automated)

#### Cloudflared (Recommended for Speed)
```bash
DNS_TYPE="cloudflared"
```
**Advantages:**
- Fast DNS resolution
- DNS over HTTPS (encrypted queries)
- Lower resource usage
- Cloudflare's 1.1.1.1 infrastructure

**Disadvantages:**
- Third-party DNS provider (Cloudflare sees queries)
- Cloudflare privacy policy applies
- External dependency

### VPN Options

#### Install WireGuard VPN
```bash
INSTALL_VPN="yes"
WIREGUARD_PORT="51820"
```
**Includes:**
- Modern WireGuard VPN server (secure implementation, not PiVPN)
- User-friendly client management tools
- QR code generation for mobile devices
- Automatic firewall configuration
- Peer-to-peer blocking (security)
- Post-quantum cryptography (pre-shared keys)
- DNS leak prevention
- Systemd integration for reliability

**Use Cases:**
- Remote access to Pi-hole DNS filtering
- Secure browsing on public Wi-Fi
- Access home network resources remotely
- Privacy protection while traveling

#### Skip VPN Installation
```bash
INSTALL_VPN="no"
```
- DNS-only setup
- Local network use only
- Simpler configuration

---

## Installation Process

### Step 1: Platform Detection

The installer automatically detects:
- Azure (via metadata service)
- Raspberry Pi (via device tree)
- Other Linux (manual selection if needed)

**Manual Override:**
```bash
# If auto-detection fails
PLATFORM="azure"  # or "rpi" or "other"
```

### Step 2: Network Configuration

The installer detects your current IP and offers it as default:
```
Detected IP address: 10.0.0.10
Use this IP as static? [Y/n] or enter different IP:
```

**Note:** Assumes IP is already configured as static. The installer does NOT modify network configuration.

### Step 3: GPG Key Setup

#### Automatic Key Generation
- Generates RSA 4096-bit key
- 2-year expiration
- Named after hostname
- Public key exported to `/scripts/Finished/server-public-key.gpg`

#### Automatic Public Key Import
Public keys are automatically imported from `installer/public-gpg-keys/`:

**Before Installation:**
```bash
# Add your public keys to the repository
cd pihole-installer/installer/public-gpg-keys/
# Copy your .gpg public key files here
ls -la
# Shows: my-encryption-key.gpg, work-key.gpg, etc.
```

**During Installation:**
- All `.gpg` files automatically imported
- No user interaction required
- Import status logged
- Installation continues even if some keys fail

**After Installation:**
- `full-update` and `purge-and-update` check for new keys
- New keys automatically downloaded and imported from GitHub
- Fingerprint comparison prevents duplicate imports

**Example: Import from File**
```bash
Enter full path to public key file: /home/user/encryption-key.gpg
```

**Example: Paste Key**
```
Paste the GPG public key (including -----BEGIN PGP PUBLIC KEY BLOCK-----)
Press Ctrl+D when done:
[Paste key content here]
[Press Ctrl+D]
```

### Step 4: Component Installation

The installer proceeds through these stages:

1. **System Update** - Updates packages and security patches
2. **Dependencies** - Installs required tools (curl, git, sqlite3, etc.)
3. **Pi-hole** - Installs latest Pi-hole version
4. **DNS Provider** - Configures Unbound or Cloudflared
5. **Update Scripts** - Downloads and configures `updates_optimized.sh`
6. **Cron Jobs** - Sets up automated maintenance schedules
7. **WireGuard** - Installs VPN (if requested)
8. **Security** - Configures Fail2Ban and unattended upgrades
9. **Finalization** - Configures server to use local DNS

### Step 5: Post-Installation

After successful installation:

```
╔══════════════════════════════════════════════════════════════╗
║                   NEXT STEPS                                 ║
╚══════════════════════════════════════════════════════════════╝

1. Update SSH configuration:
   Edit /etc/ssh/sshd_config and add your username to AllowUsers

2. Create WireGuard VPN clients:
   Run: pivpn add
   Or use: /scripts/Finished/wireguard-manager.sh

3. Access Pi-hole admin interface:
   http://10.0.0.10/admin

4. Set Pi-hole admin password:
   sudo pihole -a -p

5. Review installation log:
   /var/log/pihole-vpn-install.log

6. Reboot server to apply all changes:
   sudo reboot
```

---

## Configuration File Reference

### Complete Example: installer.conf

```bash
# Platform (auto-detected if omitted)
#PLATFORM="azure"

# Server configuration profile
SERVER_TYPE="full"

# DNS provider
DNS_TYPE="unbound"

# VPN installation
INSTALL_VPN="yes"
WIREGUARD_PORT="51820"

# Network (auto-detected, override if needed)
#STATIC_IPV4="10.0.0.10"

# GPG keys
GPG_KEY_COUNT=1

# Debug mode (optional)
#DEBUG_MODE=false
```

### Configuration Validation

The installer validates all settings and prompts for corrections:

```
╔══════════════════════════════════════════════════════════════╗
║               DETECTED CONFIGURATION                         ║
╚══════════════════════════════════════════════════════════════╝

  Platform:           azure
  Server Type:        full
  DNS Provider:       unbound
  Install VPN:        yes
  WireGuard Port:     51820
  Static IPv4:        10.0.0.10
  GPG Keys to Import: 1

Configuration looks good? [Y/n]:
```

---

## Automated Maintenance

### Cron Schedule Overview

The installer creates **randomized** cron schedules to reduce load on GitHub and list sources:

#### Gravity Refresh
```
Command: updates_optimized.sh refresh
Schedule: 1-3 hours before purge-and-update (randomized)
Purpose: Updates Pi-hole's gravity database from subscribed lists
```

#### Purge and Update
```
Command: updates_optimized.sh purge-and-update
Schedule: ~3:30 AM ±45 minutes (randomized per install)
Purpose: Comprehensive update - purges old data, downloads all lists
```

#### Allow List Updates
```
Command: updates_optimized.sh allow-update
Schedule: Every 8 hours (offset from purge time)
Purpose: Updates allowlists only (faster, less intrusive)
```

### Example Randomized Schedule

Installation 1:
```
02:15 - Gravity Refresh
04:03 - Purge and Update (3:30 AM + 33 min offset)
12:03 - Allow Update
20:03 - Allow Update
```

Installation 2:
```
01:47 - Gravity Refresh
03:12 - Purge and Update (3:30 AM - 18 min offset)
11:12 - Allow Update
19:12 - Allow Update
```

### Manual Updates

Run updates manually anytime:

```bash
# Full comprehensive update
/scripts/Finished/updates_optimized.sh purge-and-update

# Quick allowlist update
/scripts/Finished/updates_optimized.sh allow-update

# Refresh gravity only
/scripts/Finished/updates_optimized.sh refresh

# Block regex lists only
/scripts/Finished/updates_optimized.sh block-regex-update

# See all options
/scripts/Finished/updates_optimized.sh --help
```

---

## WireGuard VPN Management

### Client Manager Tool

The installer includes `wireguard-manager.sh` for easy VPN client management:

```bash
sudo bash /scripts/Finished/wireguard-manager.sh
```

**Menu Options:**
1. Add new VPN client
2. Remove VPN client
3. List all clients
4. Show client configuration
5. Show QR code for client
6. Revoke client access
7. Show VPN statistics
8. Restart WireGuard
9. Backup configurations
10. Show file locations (server config, client directory, hosts file, dnsmasq config, keys, backups)

**Note:** This installer uses a modern, secure WireGuard implementation built from scratch, not relying on the unmaintained PiVPN project. All security features are implemented with current best practices.

### Direct WireGuard Commands

Manage WireGuard directly if needed:

```bash
# Show interface status
sudo wg show wg0

# Reload configuration
sudo systemctl restart wg-quick@wg0

# View systemd logs
sudo journalctl -u wg-quick@wg0 -f

# Manual interface management
sudo wg-quick down wg0
sudo wg-quick up wg0
```

### Adding Mobile Clients

#### iOS / Android

1. Install WireGuard app from App Store / Play Store
2. Generate QR code on server:
   ```bash
   sudo bash /scripts/Finished/wireguard-manager.sh
   # Select option 5: Show QR code for client
   ```
3. Scan QR code with WireGuard app
4. Enable VPN connection

#### Desktop (Windows / macOS / Linux)

1. Install WireGuard from wireguard.com
2. Copy client configuration:
   ```bash
   # View config
   sudo cat /etc/wireguard/clients/client-name.conf
   ```
3. Import configuration into WireGuard application
4. Activate tunnel

### VPN Client Hostname Resolution

VPN clients can ping each other by hostname thanks to automatic DNS configuration:

**How It Works:**
- Each VPN client gets an entry in `/etc/wireguard/hosts`
- Format: `10.7.0.X clientname`
- Pi-hole uses dnsmasq `addn-hosts` directive to load this file
- Hostnames automatically added/removed when clients are created/deleted

**Example:**
```bash
# On VPN server or any connected client
ping laptop        # Resolves to 10.7.0.2
ping phone         # Resolves to 10.7.0.3
ping wg-server     # Resolves to 10.7.0.1
```

**View Current Hostnames:**
```bash
cat /etc/wireguard/hosts
```

**Dnsmasq Configuration:**
```bash
cat /etc/dnsmasq.d/02-pihole-wireguard.conf
```

### Firewall Configuration

**Azure Network Security Group:**
```
Inbound Rule:
- Port: 51820 (or your custom port)
- Protocol: UDP
- Source: Any (or specific IPs)
- Action: Allow
```

**Local Firewall (ufw):**
```bash
sudo ufw allow 51820/udp
sudo ufw enable
```

**Router Port Forwarding:**
```
External Port: 51820 UDP
Internal IP: [Pi-hole server IP]
Internal Port: 51820 UDP
```

---

## Troubleshooting

### Debug Mode

Run installer with debug output:

```bash
sudo bash install-pihole-vpn.sh --debug
```

### Common Issues

#### Issue: Pi-hole web interface not accessible

**Check:**
```bash
# Verify lighttpd is running
sudo systemctl status lighttpd

# Restart if needed
sudo systemctl restart lighttpd
```

**Solution:**
```bash
# Repair Pi-hole
sudo pihole -r
# Choose "Repair" option
```

#### Issue: DNS not resolving

**Check:**
```bash
# Test DNS resolution
dig @127.0.0.1 google.com

# Check Pi-hole FTL status
sudo systemctl status pihole-FTL
```

**Solution:**
```bash
# Restart DNS
sudo pihole restartdns

# If using Unbound
sudo service unbound restart

# If using Cloudflared
sudo systemctl restart cloudflared
```

#### Issue: WireGuard clients cannot connect

**Check:**
```bash
# Verify WireGuard is running
sudo wg show

# Check if port is listening
sudo ss -ulnp | grep 51820
```

**Solution:**
```bash
# Restart WireGuard
sudo wg-quick down wg0
sudo wg-quick up wg0

# Check firewall
sudo ufw status
sudo iptables -L -n
```

#### Issue: Updates failing with GPG errors

**Check:**
```bash
# List GPG keys
gpg --list-keys

# Test decryption
gpg --decrypt /path/to/encrypted-file.gpg
```

**Solution:**
```bash
# Re-import encryption keys
sudo bash /scripts/Finished/wireguard-manager.sh
# Choose appropriate key import option

# Or manually import
gpg --import /path/to/public-key.gpg
```

### Log Files

**Installation Log:**
```bash
/var/log/pihole-vpn-install.log
```

**Update Logs:**
```bash
/var/log/pihole-purge-update.log
/var/log/pihole-allow-update.log
/var/log/pihole-refresh.log
```

**Pi-hole Logs:**
```bash
/var/log/pihole/pihole.log
/var/log/pihole/FTL.log
```

**System Logs:**
```bash
# View recent errors
sudo journalctl -xe

# Follow logs
sudo journalctl -f
```

---

## Configuration Files

### Automatically Generated Files

The installer creates configuration files in `/scripts/Finished/CONFIG/` that are used by update scripts:

**type.conf** - Installation profile
```bash
# Contents: "full", "security", or "basic"
cat /scripts/Finished/CONFIG/type.conf
```

**dns_type.conf** - DNS provider
```bash
# Contents: "cloudflared" or "unbound" (literal strings, not numeric)
cat /scripts/Finished/CONFIG/dns_type.conf
```

**test.conf** - Test mode flag
```bash
# Contents: "no" for production, "yes" for test mode (literal strings)
cat /scripts/Finished/CONFIG/test.conf
```

**ver.conf** - Pi-hole version
```bash
# Contents: "6" (Pi-hole major version)
cat /scripts/Finished/CONFIG/ver.conf
```

### DNS Configuration Files

**Unbound Configuration:**
```bash
/etc/unbound/unbound.conf.d/pi-hole.conf    # Unbound Pi-hole config
/etc/dnsmasq.d/51-unbound.conf              # Dnsmasq upstream config
/var/lib/unbound/root.hints                 # DNS root servers
```

**Cloudflared Configuration:**
```bash
/scripts/Finished/cloudflared               # Cloudflared settings
/lib/systemd/system/cloudflared.service     # Systemd service
/etc/dnsmasq.d/50-cloudflared.conf          # Dnsmasq upstream config
```

**WireGuard DNS Configuration:**
```bash
/etc/dnsmasq.d/02-pihole-wireguard.conf     # VPN interface config
/etc/wireguard/hosts                        # VPN hostname mappings
```

### File Permissions

The installer automatically sets correct permissions:
- `/scripts/Finished/CONFIG/` - 755 (readable by update scripts)
- Configuration files - 644 (readable by all scripts)
- WireGuard configs - 600 (root only)
- Client directory - 700 (root only)

---

## Security Considerations

### SSH Hardening

**CRITICAL:** After installation, update SSH configuration:

```bash
sudo vim /etc/ssh/sshd_config
```

Add your username:
```
AllowUsers your-username
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

### Firewall Configuration

Enable and configure firewall:

```bash
# Install ufw if not present
sudo apt install ufw

# Allow SSH (change port if custom)
sudo ufw allow 22/tcp

# Allow DNS
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# Allow Pi-hole web interface
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow WireGuard (if installed)
sudo ufw allow 51820/udp

# Enable firewall
sudo ufw enable
```

### Fail2Ban

Fail2Ban is automatically configured to protect against brute-force attacks:

```bash
# Check Fail2Ban status
sudo fail2ban-client status

# Check banned IPs
sudo fail2ban-client status sshd
```

### GPG Key Security

**Server Private Key:**
- Located in GPG keyring
- Never share or export private key
- Backup in secure location

**Public Key:**
- Exported to `/scripts/Finished/server-public-key.gpg`
- Safe to share with list maintainers
- Used for encrypting files for this server

### Regular Updates

System automatically updates via unattended-upgrades. Monitor:

```bash
# Check update status
sudo apt update
sudo apt list --upgradable

# Manual system update
sudo apt update && sudo apt upgrade -y
```

---

## Performance Optimization

### Database Optimization

The `updates_optimized.sh` script uses SQL batch operations for 100x performance improvement over individual `pihole` commands.

**Performance Metrics:**
- v5 Database: 500+ seconds → 5 seconds (100x faster)
- v6 Database: Similar improvement
- Overall update time: 60% reduction

### Resource Usage

**Typical Resource Consumption:**

| Component | RAM | CPU | Storage |
|-----------|-----|-----|---------|
| Pi-hole FTL | 50-100 MB | 1-5% | 100 MB |
| Unbound | 30-50 MB | 1-3% | 50 MB |
| Cloudflared | 20-40 MB | 1-2% | 20 MB |
| WireGuard | 5-10 MB | <1% | 10 MB |

**Total (Full Stack):** ~150-200 MB RAM, minimal CPU

### Network Performance

**DNS Query Times:**
- Unbound (cached): <1 ms
- Unbound (uncached): 50-200 ms
- Cloudflared (cached): <1 ms
- Cloudflared (uncached): 10-30 ms

**WireGuard Performance:**
- Throughput: Near-line-speed (limited by CPU/network)
- Latency overhead: <5 ms typically
- Connection establishment: <100 ms

---

## Backup and Recovery

### Backup Configuration

```bash
# Backup Pi-hole configuration
sudo pihole -a -t

# Backup WireGuard configs
sudo tar -czf wireguard-backup.tar.gz /etc/wireguard/

# Backup update scripts
sudo tar -czf scripts-backup.tar.gz /scripts/Finished/
```

### Restore Configuration

```bash
# Restore Pi-hole from teleporter backup
# Upload .tar.gz via web interface: Settings > Teleporter

# Restore WireGuard
sudo tar -xzf wireguard-backup.tar.gz -C /

# Restore scripts
sudo tar -xzf scripts-backup.tar.gz -C /
```

### Disaster Recovery

If system becomes unresponsive:

1. **Boot from rescue media** (if physical) or **Azure Serial Console** (if Azure)
2. **Mount filesystem**
3. **Check logs:** `/var/log/pihole-vpn-install.log`
4. **Repair or reinstall**

**Quick Recovery:**
```bash
# Re-run installer with existing config
sudo bash install-pihole-vpn.sh

# Restore from backup
sudo pihole -a -t /path/to/backup.tar.gz
```

---

## Uninstallation

### Complete Removal

```bash
# Uninstall Pi-hole
pihole uninstall

# Remove WireGuard
sudo apt remove --purge wireguard wireguard-tools

# Remove Unbound or Cloudflared
sudo apt remove --purge unbound
# or
sudo apt remove --purge cloudflared

# Remove scripts
sudo rm -rf /scripts/

# Remove cron jobs
crontab -e
# Delete Pi-hole related entries

# Remove logs
sudo rm -f /var/log/pihole-*
```

### Partial Removal

**Remove VPN only:**
```bash
sudo apt remove --purge wireguard wireguard-tools
sudo rm -rf /etc/wireguard/
```

**Switch DNS provider:**
```bash
# From Unbound to Cloudflared
sudo apt remove --purge unbound
# Re-run installer with DNS_TYPE="cloudflared"
```

---

## Support and Documentation

### Official Documentation

- **Pi-hole**: https://docs.pi-hole.net/
- **WireGuard**: https://www.wireguard.com/
- **PiVPN**: https://pivpn.io/
- **Unbound**: https://nlnetlabs.nl/documentation/unbound/
- **Cloudflared**: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps

### Related Repositories

- **Personal Contained Pi-hole**: https://github.com/IcedComputer/Personal_Contained_Pihole
  - Main repository with installer, scripts, and configurations
  - All-in-one solution for Pi-hole + VPN deployment

### Community Resources

- **Pi-hole Discourse**: https://discourse.pi-hole.net/
- **Pi-hole Reddit**: https://reddit.com/r/pihole
- **WireGuard Reddit**: https://reddit.com/r/WireGuard

---

## Changelog

### Version 1.0.0 (2025-12-07)

**Initial Release:**
- Automated Pi-hole installation for Raspberry Pi and Ubuntu Server
- Platform auto-detection (Azure, RPi, other)
- Unbound and Cloudflared DNS provider support
- Modern WireGuard VPN implementation (secure, not relying on unmaintained PiVPN)
- Post-quantum cryptography support (pre-shared keys)
- GPG key generation and import
- Randomized cron scheduling
- Comprehensive error tracking and reporting
- Colored output with success/warning/error indicators
- Configuration file support for unattended installation
- User-friendly WireGuard client manager tool
- Complete installation documentation

---

## License

This installer is provided as-is with no warranty. Use at your own risk.

Based on:
- Pi-hole (licensed under EUPL v1.2)
- WireGuard (licensed under GPLv2)
- PiVPN (licensed under MIT)

---

**Last Updated:** 2025-12-07  
**Maintainer:** IcedComputer  
**Version:** 1.0.0
