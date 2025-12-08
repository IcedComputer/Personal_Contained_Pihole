# WireGuard Security Implementation

**Version:** 1.0.0  
**Created:** 2025-12-07  
**Purpose:** Document security improvements over unmaintained PiVPN

---

## Why Not PiVPN?

PiVPN is no longer actively maintained (last commit 2023), which poses security risks:

- ❌ No security patches for new vulnerabilities
- ❌ Outdated cryptographic practices
- ❌ No support for modern WireGuard features
- ❌ Unclear long-term viability

## Our Modern Implementation

This installer implements WireGuard directly with current security best practices.

---

## Security Features

### 1. Post-Quantum Cryptography (Pre-shared Keys)

**What it is:**  
Pre-shared keys (PSK) add an additional symmetric encryption layer on top of WireGuard's public key cryptography.

**Why it matters:**  
Protects against future quantum computer attacks that could break current public key cryptography.

**Implementation:**
```bash
# Generated for each client
wg genpsk
```

Each client gets a unique PSK, stored in both server and client configs:
```ini
[Peer]
PublicKey = <public-key>
PresharedKey = <unique-psk>  # Post-quantum protection
```

**Security benefit:** Even if quantum computers break curve25519, the symmetric PSK remains secure.

---

### 2. Strong Key Generation

**Key Type:** Curve25519 (WireGuard default)  
**Key Strength:** 256-bit equivalent security

**Random Key Generation:**
```bash
# Private key (server and each client)
wg genkey  # Uses /dev/urandom for cryptographic randomness

# Public key (derived from private)
echo "<private-key>" | wg pubkey

# Pre-shared key (additional layer)
wg genpsk  # Uses /dev/urandom for cryptographic randomness
```

**Security improvements over PiVPN:**
- ✅ Modern key generation (not relying on potentially outdated OpenSSL)
- ✅ Direct use of WireGuard tools (maintained actively)
- ✅ Proper permissions (600) on all key files

---

### 3. Network Isolation (Peer-to-Peer Blocking)

**Configuration:**
```bash
# In server config PostUp:
iptables -I FORWARD -i wg0 -o wg0 -j REJECT --reject-with icmp-admin-prohibited
```

**What it does:**  
Prevents VPN clients from communicating with each other.

**Security benefit:**  
- Compromised client cannot attack other clients
- Limits lateral movement in security breach
- Enforces hub-and-spoke topology

**Example scenario:**
```
✅ Client A → Server → Internet  (allowed)
✅ Client A → Server → Pi-hole   (allowed)
❌ Client A → Client B           (blocked)
```

---

### 4. DNS Leak Prevention

**Client Configuration:**
```ini
[Interface]
DNS = 10.7.0.1  # Pi-hole server IP

[Peer]
AllowedIPs = 0.0.0.0/0, ::/0  # Route all traffic through VPN
```

**What it prevents:**  
- DNS queries leaking to ISP or public DNS
- Bypassing Pi-hole filtering when on VPN

**Additional hardening (optional):**
```ini
PostUp = resolvectl dns %i 10.7.0.1
PostUp = resolvectl domain %i ~.
```

This ensures system DNS respects VPN DNS settings.

---

### 5. Persistent Keepalive

**Configuration:**
```ini
[Peer]
PersistentKeepalive = 25  # seconds
```

**What it does:**  
Sends keepalive packets every 25 seconds.

**Security benefits:**
- Maintains NAT mappings (prevents connection drops)
- Detects dead peers quickly
- Prevents stale connections in firewall state tables

**Why 25 seconds?**  
- Long enough to minimize bandwidth waste
- Short enough to maintain NAT mappings (typical timeout: 30-60s)
- WireGuard recommended value

---

### 6. IP Forwarding with Strict Firewall Rules

**System Configuration:**
```bash
# Enable IPv4 forwarding
net.ipv4.ip_forward=1

# Enable IPv6 forwarding
net.ipv6.conf.all.forwarding=1
```

**Firewall Rules (iptables):**
```bash
# Allow forwarding from WireGuard interface
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT

# NAT for internet access
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Block peer-to-peer
PostUp = iptables -I FORWARD -i wg0 -o wg0 -j REJECT

# Cleanup on shutdown
PostDown = [reverse all rules]
```

**Security advantage:**  
Rules are interface-specific, minimizing attack surface.

---

### 7. Strict File Permissions

**Implementation:**
```bash
chmod 700 /etc/wireguard/           # Directory
chmod 600 /etc/wireguard/wg0.conf   # Server config
chmod 600 /etc/wireguard/clients/*  # Client configs
chmod 600 /etc/wireguard/*.key      # Key files
```

**Why it matters:**  
- Private keys are never readable by non-root users
- Prevents local privilege escalation via key theft
- Follows principle of least privilege

---

### 8. Automatic Client IP Assignment

**Safe IP Allocation:**
```bash
# Start from .2 (server is .1)
next_ip=2

# Check for conflicts
while grep -q "10.7.0.${next_ip}/32" /etc/wireguard/wg0.conf; do
    ((next_ip++))
    if [[ ${next_ip} -gt 254 ]]; then
        # Error: no available IPs
    fi
done
```

**Security benefits:**
- No IP conflicts (prevents routing issues)
- Predictable addressing (simplifies firewall rules)
- Automatic tracking in comments

---

### 9. Configuration Validation

**Client Name Validation:**
```bash
if [[ ! "${client_name}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    # Reject invalid names
fi
```

**Why it matters:**  
- Prevents command injection via filenames
- Avoids filesystem traversal attacks
- Ensures clean configuration files

---

### 10. Secure Public IP Detection

**Multi-source IP Detection:**
```bash
# Try multiple services (failover)
server_endpoint=$(curl -s --max-time 5 https://api.ipify.org || \
                  curl -s --max-time 5 https://icanhazip.com || \
                  curl -s --max-time 5 https://ifconfig.me)

# Prompt if all fail
if [[ -z "${server_endpoint}" ]]; then
    read -p "Enter server public IP: " server_endpoint
fi
```

**Security benefit:**  
- No single point of failure
- Timeout prevents hanging on dead services
- Manual fallback for air-gapped systems

---

## Comparison: PiVPN vs Our Implementation

| Feature | PiVPN | Our Implementation |
|---------|-------|-------------------|
| **Maintenance** | ❌ Unmaintained (2023) | ✅ Active, updatable |
| **Pre-shared Keys** | ❌ Not default | ✅ Always enabled |
| **Key Generation** | ⚠️ May use outdated tools | ✅ Direct WireGuard tools |
| **Peer Blocking** | ⚠️ Not always configured | ✅ Always enabled |
| **DNS Leak Prevention** | ⚠️ Basic | ✅ Enhanced with resolvectl |
| **File Permissions** | ✅ Good | ✅ Excellent (700/600) |
| **IP Assignment** | ✅ Works | ✅ Enhanced validation |
| **Systemd Integration** | ✅ Yes | ✅ Yes |
| **Backup on Removal** | ❌ No | ✅ Automatic |
| **Connection Status** | ⚠️ Basic | ✅ Enhanced (last handshake) |

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Pi-hole + VPN Server                    │
│                                                              │
│  ┌────────────┐         ┌──────────────┐                   │
│  │  Pi-hole   │←────────│  WireGuard   │                   │
│  │ 10.7.0.1   │  DNS    │  10.7.0.1    │                   │
│  └────────────┘         └──────────────┘                   │
│        ↓                        ↓                            │
│  ┌─────────────────────────────────────┐                   │
│  │    Upstream DNS (Unbound/CF)        │                   │
│  └─────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
                          ↕
              (Encrypted WireGuard Tunnel)
                          ↕
┌─────────────────────────────────────────────────────────────┐
│                      VPN Clients                             │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │  Client A  │  │  Client B  │  │  Client C  │           │
│  │ 10.7.0.2   │  │ 10.7.0.3   │  │ 10.7.0.4   │           │
│  └────────────┘  └────────────┘  └────────────┘           │
│         ↓              ↓              ↓                      │
│  All DNS queries → Pi-hole (ad-blocking + filtering)        │
│  All traffic → Encrypted via WireGuard                      │
│  Peer-to-peer communication → BLOCKED                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Examples

### Server Configuration (`/etc/wireguard/wg0.conf`)

```ini
# WireGuard Server Configuration
# Created: 2025-12-07T10:30:00-05:00

[Interface]
Address = 10.7.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# Forwarding and NAT rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -I FORWARD -i %i -o %i -j REJECT --reject-with icmp-admin-prohibited

PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o %i -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || true

# Client: mobile-phone (Created: 2025-12-07T10:35:00-05:00)
[Peer]
PublicKey = <client-public-key>
PresharedKey = <unique-psk-1>
AllowedIPs = 10.7.0.2/32

# Client: laptop (Created: 2025-12-07T10:40:00-05:00)
[Peer]
PublicKey = <client-public-key-2>
PresharedKey = <unique-psk-2>
AllowedIPs = 10.7.0.3/32
```

### Client Configuration (`/etc/wireguard/clients/mobile-phone.conf`)

```ini
# WireGuard Client Configuration: mobile-phone
# Created: 2025-12-07T10:35:00-05:00
# Server: vpn.example.com:51820

[Interface]
PrivateKey = <client-private-key>
Address = 10.7.0.2/32
DNS = 10.7.0.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = <unique-psk-1>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

---

## Security Best Practices

### 1. Regular Key Rotation

**Recommendation:** Rotate client keys every 6-12 months.

```bash
# Remove old client
sudo bash /scripts/Finished/wireguard-manager.sh
# Select: Remove VPN client

# Add new client with same name
sudo bash /scripts/Finished/wireguard-manager.sh
# Select: Add new VPN client
```

### 2. Monitor Connection Logs

```bash
# View WireGuard logs
sudo journalctl -u wg-quick@wg0 -f

# Check active connections
sudo wg show wg0

# View handshake times
sudo wg show wg0 latest-handshakes
```

### 3. Firewall Hardening

```bash
# Only allow specific ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 53/tcp    # DNS
sudo ufw allow 53/udp
sudo ufw allow 80/tcp    # Pi-hole web
sudo ufw allow 443/tcp
sudo ufw allow 51820/udp # WireGuard
sudo ufw enable
```

### 4. Audit Client List Regularly

```bash
# List all configured clients
sudo bash /scripts/Finished/wireguard-manager.sh
# Select: List all clients

# Remove unused clients immediately
```

### 5. Backup Configurations

```bash
# Automatic backup via manager
sudo bash /scripts/Finished/wireguard-manager.sh
# Select: Backup configurations

# Manual backup
sudo tar -czf wireguard-backup-$(date +%Y%m%d).tar.gz /etc/wireguard/
```

---

## Troubleshooting Security Issues

### Issue: Client can reach other clients

**Check:**
```bash
sudo iptables -L FORWARD -v -n | grep wg0
```

**Fix:**
```bash
# Re-add peer blocking rule
sudo iptables -I FORWARD -i wg0 -o wg0 -j REJECT --reject-with icmp-admin-prohibited

# Save rules
sudo netfilter-persistent save
```

### Issue: DNS leaking outside VPN

**Check:**
```bash
# On client, while connected:
dig google.com
nslookup google.com
```

**Fix:**  
Ensure client config has:
```ini
DNS = 10.7.0.1
AllowedIPs = 0.0.0.0/0, ::/0
```

### Issue: Weak keys detected

**Fix:**  
Regenerate all keys:
```bash
# Remove and re-add all clients
# Server key rotation requires full reconfiguration
```

---

## Performance vs Security

| Setting | Performance Impact | Security Benefit |
|---------|-------------------|------------------|
| Pre-shared Keys | Negligible | High (post-quantum) |
| PersistentKeepalive | ~1KB/minute | Medium (connection stability) |
| Peer Blocking | None | High (lateral movement) |
| DNS via Pi-hole | None | High (ad blocking + privacy) |
| Full Tunnel (0.0.0.0/0) | High (all traffic) | Maximum (complete protection) |

**Recommendation:** Use all security features. Performance impact is minimal on modern hardware.

---

## Compliance Notes

### GDPR / Privacy

- ✅ No logs stored by default
- ✅ DNS queries only logged by Pi-hole (configurable)
- ✅ Client configs stored locally (not cloud)
- ✅ No third-party analytics

### Industry Standards

- ✅ Follows WireGuard official best practices
- ✅ Uses NIST-recommended cryptography (Curve25519)
- ✅ Implements defense-in-depth (multiple security layers)
- ✅ Regular security updates via system package manager

---

## Future Security Improvements

Planned enhancements:

1. **Certificate-based authentication** (in addition to keys)
2. **Two-factor authentication** for client provisioning
3. **Automated security audits** (scheduled scans)
4. **Intrusion detection** integration (Fail2Ban rules)
5. **Geographic IP blocking** (optional)

---

## Additional Resources

- **WireGuard Official Documentation:** https://www.wireguard.com/
- **WireGuard Cryptography:** https://www.wireguard.com/protocol/
- **NIST Post-Quantum Crypto:** https://csrc.nist.gov/projects/post-quantum-cryptography
- **Linux Kernel WireGuard:** https://git.zx2c4.com/wireguard-linux/

---

**Last Updated:** 2025-12-07  
**Maintainer:** IcedComputer  
**Version:** 1.0.0
