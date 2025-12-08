# GitHub Private Repository Authentication Setup

## Overview
This document explains how to configure secure access to the private `Personal_Contained_Pihole` repository for automated updates on VPN servers.

## Security Model

### Authentication Method: Fine-Grained Personal Access Token (PAT)

**Why PAT over Deploy Keys:**
- Simpler to manage across multiple servers
- Can use same token for all VPN servers
- Easier to rotate when needed
- Works seamlessly with `curl` downloads (no git required)
- Fine-grained tokens scope to single repository only

**Security Features:**
- Token stored in protected configuration file (root-only readable)
- Token never logged or displayed
- Token scope limited to read-only, single repository
- Token expiration reminder system
- Fallback to public URLs if token invalid

---

## Setup Instructions

### Step 1: Create Fine-Grained Personal Access Token

1. Go to GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens
2. Click "Generate new token"
3. Configure:
   - **Name**: `pihole-vpn-servers-readonly`
   - **Expiration**: **No expiration** (recommended for automated servers)
     - Alternative: Custom (up to 1 year max)
     - ⚠️ Tokens can be revoked anytime if compromised
   - **Repository access**: "Only select repositories" → `Personal_Contained_Pihole`
   - **Permissions**: Repository permissions → Contents → **Read-only**
4. Generate and copy the token (starts with `github_pat_`)
5. **Save token securely** - You cannot view it again after leaving the page!

### Step 2: Deploy Token to VPN Servers

**During Installation:**
The installer will prompt for the GitHub token and store it securely:
```
Enter GitHub token (or press Enter to skip): github_pat_YOUR_TOKEN_HERE
Enter token expiration date (YYYY-MM-DD, or press Enter to skip): [Enter]
```

**Manual Deployment (Existing Servers):**

*Option 1 - Interactive (Recommended):*
```bash
ssh root@vpn-server.com
sudo bash /scripts/Finished/updates.sh --setup-token
# Follow prompts to enter token
```

*Option 2 - Direct Command:*
```bash
# Create secure token file
sudo mkdir -p /scripts/Finished/CONFIG
sudo touch /scripts/Finished/CONFIG/github_token.conf
sudo chmod 600 /scripts/Finished/CONFIG/github_token.conf
sudo chown root:root /scripts/Finished/CONFIG/github_token.conf

# Add token (replace YOUR_TOKEN_HERE)
echo "YOUR_TOKEN_HERE" | sudo tee /scripts/Finished/CONFIG/github_token.conf > /dev/null
```

*Option 3 - Remote Deployment (All Servers at Once):*
```bash
# From your work machine
TOKEN="github_pat_YOUR_TOKEN"
SERVERS=("vpn1.example.com" "vpn2.example.com" "vpn3.example.com")

for server in "${SERVERS[@]}"; do
    ssh root@$server "mkdir -p /scripts/Finished/CONFIG && \
        echo '$TOKEN' > /scripts/Finished/CONFIG/github_token.conf && \
        chmod 600 /scripts/Finished/CONFIG/github_token.conf"
done
```

**Verify:**
```bash
# Test token works
TOKEN=$(sudo cat /scripts/Finished/CONFIG/github_token.conf)
curl -f -H "Authorization: Bearer $TOKEN" \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/README.md
```

### Step 3: Token Rotation

**When to Rotate:**
- Token approaching expiration (automated reminder 30 days before)
- Suspected compromise
- Regular security audit (annually)

**How to Rotate:**
1. Generate new token with same permissions
2. Update token on all VPN servers:
   ```bash
   echo "NEW_TOKEN" | sudo tee /scripts/Finished/CONFIG/github_token.conf > /dev/null
   ```
3. Test updates work: `sudo bash /scripts/Finished/updates.sh full-update`
4. Revoke old token in GitHub

---

## Technical Implementation

### Token Storage
- **Location**: `/scripts/Finished/CONFIG/github_token.conf`
- **Permissions**: `600` (root read/write only)
- **Owner**: `root:root`
- **Format**: Single line, token only, no whitespace

### URL Construction
```bash
# Without token (public repos)
https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/file

# With token (private repos)
curl -H "Authorization: Bearer $TOKEN" \
  https://raw.githubusercontent.com/IcedComputer/Personal_Contained_Pihole/master/file
```

### Fallback Strategy
1. Try authenticated download with token
2. If token missing/invalid, log warning
3. Attempt unauthenticated download (fails for private repo)
4. Report error with instructions

### Security Considerations

**What's Protected:**
- Token never exposed in process lists (`ps aux`)
- Token never written to logs
- Token not passed as URL parameter (uses Authorization header)
- Token file readable only by root

**What to Monitor:**
- Failed authentication attempts (check `/var/log/pihole-updates.log`)
- Token expiration warnings
- Unauthorized access to token file (intrusion detection)

---

## Automation Features

### Installer Integration
The installer automatically:
1. Prompts for GitHub token (optional, can skip)
2. Validates token has correct permissions
3. Stores token securely
4. Configures all scripts to use token
5. Tests download of sample file

### Token Expiration Monitoring
The `updates.sh` script checks token expiration:
- 30 days before: Warning in logs
- 7 days before: Email alert to admin (if configured)
- Expired: Error message with renewal instructions

### Multi-Server Management
For managing tokens across multiple VPN servers:

```bash
# deploy-token.sh (example script)
#!/bin/bash
TOKEN="your_token_here"
SERVERS=("vpn1.example.com" "vpn2.example.com" "vpn3.example.com")

for server in "${SERVERS[@]}"; do
    echo "Deploying token to $server..."
    ssh root@$server "echo '$TOKEN' > /scripts/Finished/CONFIG/github_token.conf && chmod 600 /scripts/Finished/CONFIG/github_token.conf"
done
```

---

## Troubleshooting

### Token Not Working
```bash
# Verify token exists
sudo cat /scripts/Finished/CONFIG/github_token.conf

# Test token manually
TOKEN=$(sudo cat /scripts/Finished/CONFIG/github_token.conf)
curl -I -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/repos/IcedComputer/Personal_Contained_Pihole

# Expected: HTTP/2 200 (success)
# If 401: Token invalid/expired
# If 404: Token doesn't have repo access
```

### Permission Denied
```bash
# Fix token file permissions
sudo chmod 600 /scripts/Finished/CONFIG/github_token.conf
sudo chown root:root /scripts/Finished/CONFIG/github_token.conf
```

### Scripts Not Using Token
```bash
# Verify scripts have been updated
grep -r "github_token" /scripts/Finished/
# Should show: updates.sh, refresh.sh referencing token file
```

---

## Alternative: Work Account Collaboration

Since you mentioned collaboration between work and personal accounts:

### Option: Add Work Account as Collaborator
1. Repository Settings → Collaborators → Add `jugiammo-work`
2. Work account accepts invitation
3. Work account can now push/pull from work machine
4. VPN servers still use token for automated access

**Benefits:**
- Work account has full read/write access
- Can push changes from work machine
- Separate audit trail for work vs automated server updates
- Token still used for automated server-side operations

---

## Security Checklist

- [ ] Token generated with minimal permissions (read-only, single repo)
- [ ] Token stored in `/scripts/Finished/CONFIG/github_token.conf`
- [ ] Token file permissions set to 600
- [ ] Token file owned by root:root
- [ ] Token tested on all VPN servers
- [ ] Token expiration date recorded (1 year from creation)
- [ ] Calendar reminder set for token renewal (11 months)
- [ ] Backup token generation procedure documented
- [ ] All VPN servers logging authentication status
- [ ] Token never committed to git repository

---

## Quick Reference

**Create Token:** GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens

**Deploy Token:**
```bash
echo "TOKEN" | sudo tee /scripts/Finished/CONFIG/github_token.conf > /dev/null
sudo chmod 600 /scripts/Finished/CONFIG/github_token.conf
```

**Test Token:**
```bash
sudo bash /scripts/Finished/updates.sh full-update
```

**Rotate Token:**
1. Generate new token
2. Update all servers
3. Test updates work
4. Revoke old token
