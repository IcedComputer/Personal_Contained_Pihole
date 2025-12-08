# Pi-hole + WireGuard VPN Installer

**Version:** 1.0.0  
**Created:** 2025-12-07  
**Repository:** Personal_Contained_Pihole

---

## Overview

Automated installer for Pi-hole DNS ad-blocking with WireGuard VPN on Raspberry Pi, Ubuntu Server, and Azure VMs. Includes comprehensive security hardening, encrypted list support, and automated maintenance.

### Key Features

- ✅ **One-Command Installation** - Interactive or fully unattended setup
- ✅ **Multiple DNS Providers** - Choose Unbound (recursive) or Cloudflared (DoH)
- ✅ **WireGuard VPN** - Optional VPN with easy client management
- ✅ **Security Hardening** - SSH hardening, Fail2Ban with progressive banning, MFA support
- ✅ **Automated Updates** - Scheduled list updates and maintenance scripts
- ✅ **Encrypted Lists** - GPG-encrypted custom blocklists/allowlists
- ✅ **Multiple Profiles** - Full protection, security-only, or basic configurations

---

## Quick Start

### One-Line Installation

```bash
curl --tlsv1.3 -sSL https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/install-pihole-vpn.sh | sudo bash
```

### Interactive Installation (Step-by-Step)

```bash
# Download installer
curl --tlsv1.3 -sSL -o install-pihole-vpn.sh \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/install-pihole-vpn.sh

# Make executable and run
chmod +x install-pihole-vpn.sh
sudo bash install-pihole-vpn.sh
```

### Repair/Resume Failed Installation

If installation fails or is interrupted, resume from where it stopped:

```bash
# Resume installation, skipping completed steps
sudo bash install-pihole-vpn.sh --repair
```

The installer tracks completed steps in `/var/log/pihole-vpn-install.state` and only re-runs failed or incomplete steps.

### Unattended Installation

```bash
# Download installer and config template
curl --tlsv1.3 -sSL -o install-pihole-vpn.sh \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/install-pihole-vpn.sh
  
curl --tlsv1.3 -sSL -o installer.conf.template \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/installer/installer.conf.template

# Create and edit configuration
cp installer.conf.template installer.conf
vim installer.conf  # Configure your settings

# Run unattended installation
sudo bash install-pihole-vpn.sh
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](docs/INSTALL.md) | Complete installation guide with all options |
| [WIREGUARD-SECURITY.md](docs/WIREGUARD-SECURITY.md) | VPN security best practices and hardening |
| [AI-CONTEXT.md](docs/AI-CONTEXT.md) | Technical reference for AI assistants |
| [installer.conf.template](installer/installer.conf.template) | Configuration file reference |

---

## Repository Structure

```
Personal_Contained_Pihole/
├── installer/
│   ├── install-pihole-vpn.sh       # Main installer script
│   └── installer.conf.template      # Configuration template
├── scripts/
│   ├── updates.sh                   # Main update script (list management)
│   ├── refresh.sh                   # Bootstrap script (updates updates.sh)
│   ├── Research.sh                  # Pi-hole query research tool
│   └── wireguard-manager.sh         # VPN client management
├── lists/
│   ├── adlists/                     # Blocklist sources
│   ├── regex/                       # Regex filtering rules
│   ├── allow/                       # Domain allowlists
│   └── blocks/                      # Additional blocklists
└── docs/
    ├── INSTALL.md                   # Installation guide
    ├── AI-CONTEXT.md                # AI assistant context
    └── WIREGUARD-SECURITY.md        # VPN security guide
```

---

## System Requirements

### Supported Platforms

- **Raspberry Pi** - Raspberry Pi OS (Bookworm)
- **Ubuntu Server** - 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Azure VMs** - Ubuntu Server images
- **Generic Linux** - Debian-based distributions

### Minimum Hardware

- **CPU:** 1 core (2+ recommended)
- **RAM:** 512 MB (1 GB+ recommended)
- **Storage:** 4 GB free space
- **Network:** Internet connection for installation

### Software Requirements

- **OS:** Fresh or existing Linux installation
- **Access:** Root/sudo privileges
- **SSH:** Enabled with key-based authentication recommended

---

## Installation Profiles

### Full Protection (Recommended)

- All blocklists (malware, ads, tracking, telemetry)
- Comprehensive regex filters
- Encrypted country-specific lists
- Maximum protection, possible false positives

```bash
SERVER_TYPE="full"
```

### Security Only

- Malware and phishing protection
- Basic tracking prevention
- Minimal false positives
- Ideal for servers and business use

```bash
SERVER_TYPE="security"
```

### Basic

- Essential blocking only
- Minimal resource usage
- Good for testing or limited hardware

```bash
SERVER_TYPE="basic"
```

---

## DNS Provider Options

### Unbound (Recommended for Privacy)

- **Local recursive DNS resolver**
- **Port:** 5335 (localhost only)
- **Privacy:** Queries go directly to root DNS servers
- **No third-party logging**
- **Best for:** Maximum privacy

```bash
DNS_TYPE="unbound"
```

### Cloudflared (Recommended for Speed)

- **DNS over HTTPS (DoH)**
- **Port:** 5053 (localhost only)
- **Provider:** Cloudflare 1.1.1.1
- **Encrypted DNS queries**
- **Best for:** Speed and reliability

```bash
DNS_TYPE="cloudflared"
```

---

## Automated Maintenance

All maintenance scripts are automatically installed to `/scripts/Finished/`:

### Update Scripts

```bash
# Full update - All lists, scripts, and database
sudo bash /scripts/Finished/updates.sh full-update

# Purge and rebuild - Clear all lists and rebuild from scratch
sudo bash /scripts/Finished/updates.sh purge-and-update

# Allow list update only
sudo bash /scripts/Finished/updates.sh allow-update

# Regex update only
sudo bash /scripts/Finished/updates.sh block-regex-update

# Script refresh - Update all management scripts
sudo bash /scripts/Finished/updates.sh refresh

# Quick update - Lists only, no scripts
sudo bash /scripts/Finished/updates.sh quick-update
```

### Cron Jobs

Installer automatically configures randomized cron schedules:

- **Full Update:** ~3:30 AM ±45 minutes (daily)
- **Allow Update:** Every 8 hours
- **Gravity Refresh:** 1-3 hours before full update

Times are randomized per installation to reduce load on sources.

---

## WireGuard VPN Management

If you installed WireGuard (`INSTALL_VPN="yes"`), use the management script:

```bash
# Launch interactive VPN manager
sudo bash /scripts/Finished/wireguard-manager.sh
```

### VPN Manager Features

- ✅ Add new clients (QR code + config file)
- ✅ List all clients with status
- ✅ Remove clients
- ✅ Show client configurations
- ✅ Display QR codes for mobile setup
- ✅ Revoke client access
- ✅ Display connection statistics
- ✅ Restart WireGuard service
- ✅ Backup all configurations
- ✅ Show file locations (NEW)

### VPN Network

- **Server IP:** 10.7.0.1/24
- **Client Range:** 10.7.0.2 - 10.7.0.254
- **DNS:** Pi-hole (automatic for VPN clients)
- **Hostname Resolution:** VPN clients can ping each other by hostname
- **Hosts File:** `/etc/wireguard/hosts` (auto-managed)
- **Port:** 51820 UDP (configurable)

---

## Security Features

### Progressive Fail2Ban

- **First Ban:** 3 failed attempts → 25 minutes
- **Second Level:** 3 bans in 24 hours → 7 days
- **Permanent Ban:** 2 recidive bans → permanent

### SSH Hardening

- Root login disabled
- User-based access control (`AllowUsers`)
- Config backup and validation
- Optional MFA with Google Authenticator

### Unattended Security Updates

- Automatic security patches
- No manual intervention required
- System stays current with security fixes

---

## Troubleshooting

### Check Service Status

```bash
# Pi-hole FTL
sudo systemctl status pihole-FTL

# Unbound (if using Unbound)
sudo systemctl status unbound

# Cloudflared (if using Cloudflared)
sudo systemctl status cloudflared

# WireGuard (if installed)
sudo systemctl status wg-quick@wg0
```

### View Logs

```bash
# Pi-hole update logs
sudo tail -f /var/log/pihole-updates.log

# Installation log
sudo tail -f /var/log/pihole-vpn-install.log

# Pi-hole FTL log
sudo tail -f /var/log/pihole/FTL.log
```

### DNS Testing

```bash
# Test Pi-hole DNS
dig @127.0.0.1 google.com

# Test with known blocked domain
dig @127.0.0.1 ads.google.com

# Check upstream resolution
dig @127.0.0.1 example.com +trace
```

### Network Connectivity

```bash
# Verify Pi-hole is listening on port 53
sudo netstat -tulpn | grep :53

# Check Unbound/Cloudflared
sudo netstat -tulpn | grep -E "5335|5053"

# WireGuard status
sudo wg show
```

---

## Uninstallation

To completely remove Pi-hole and all components:

```bash
# Pi-hole uninstaller
pihole uninstall

# Remove directories
sudo rm -rf /scripts
sudo rm -rf /etc/wireguard

# Remove cron jobs
sudo crontab -r

# Optional: Remove packages
sudo apt-get remove --purge pihole-FTL cloudflared unbound wireguard fail2ban
```

---

## Support

### Documentation

- Full installation guide: [docs/INSTALL.md](docs/INSTALL.md)
- VPN security guide: [docs/WIREGUARD-SECURITY.md](docs/WIREGUARD-SECURITY.md)
- Technical reference: [docs/AI-CONTEXT.md](docs/AI-CONTEXT.md)

### Community Resources

- **Pi-hole Discourse:** https://discourse.pi-hole.net/
- **WireGuard Docs:** https://www.wireguard.com/
- **Unbound Wiki:** https://nlnetlabs.nl/documentation/unbound/

---

## License

This project consolidates and enhances multiple Pi-hole deployment tools into a single, maintainable repository.

**Created:** 2020-07-03  
**Organized:** 2025-12-07  
**Maintained by:** IcedComputer

---

## Changelog

### Version 1.0.0 (2025-12-07)

- ✅ Repository consolidation (Personal-Pi-Hole-configs + Azure-Pihole-VPN-setup)
- ✅ Comprehensive installer with interactive and unattended modes
- ✅ Repair mode for resuming failed installations (--repair flag)
- ✅ Automatic configuration file generation for update scripts
- ✅ Streamlined update process (refresh.sh → updates.sh → all scripts)
- ✅ Progressive Fail2Ban (25min → 7day → permanent)
- ✅ Enhanced documentation with step-by-step guides
- ✅ Config template with detailed examples
- ✅ WireGuard VPN with hostname resolution (addn-hosts)
- ✅ VPN client manager with 10 menu options including file locations
- ✅ Three installation profiles (full, security, basic)
- ✅ Two DNS providers (Unbound, Cloudflared)
- ✅ Security hardening (SSH, MFA, unattended-upgrades)
- ✅ Automated maintenance with randomized cron schedules
- ✅ TLS 1.3 enforcement for all downloads

---

## Following Universal Constants

- **UC-001:** Code clarity over cleverness
- **UC-002:** Meaningful naming conventions
- **UC-003:** ISO 8601 date format (YYYY-MM-DD)
- **UC-004:** Professional communication

---

**Happy Pi-holing! 🎯🔒**
