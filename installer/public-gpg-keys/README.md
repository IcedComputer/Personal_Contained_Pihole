# Public GPG Keys

This directory contains public GPG keys that will be automatically imported during Pi-hole installation.

## Purpose

These public keys are used to decrypt encrypted list files (`.gpg` files) such as:
- Encrypted allowlists
- Encrypted blocklists
- Encrypted regex rules

## Usage

### Adding a Public Key

1. Export your public key:
   ```bash
   gpg --export --armor your-email@example.com > mykey.gpg
   ```

2. Copy the `.gpg` file to this directory:
   ```bash
   cp mykey.gpg installer/public-gpg-keys/
   ```

3. Commit and push to repository (public keys are safe to share)

### During Installation

- The installer automatically imports ALL `.gpg` files from this directory
- No user interaction required
- Each key import is logged (success/failure)
- Installation continues even if some keys fail to import

### After Installation

- The update script (`updates.sh`) checks for new keys during:
  - `full-update` command
  - `purge-and-update` command
- New keys are automatically downloaded and imported
- Keys are cached in `/scripts/Finished/CONFIG/public-gpg-keys/`

## File Requirements

- **Format**: GPG public key files only
- **Extension**: `.gpg` (required)
- **Content**: ASCII-armored or binary GPG public keys
- **Naming**: Any descriptive name (e.g., `personal-key.gpg`, `work-key.gpg`)

## Security Notes

- ✅ Public keys are SAFE to store in version control
- ✅ Public keys can be freely distributed
- ❌ Never store private keys in this directory
- ❌ Never commit private keys to the repository

## Example

If you have encrypted lists that require key `0x1234ABCD`:

```bash
# Export public key
gpg --export --armor 0x1234ABCD > installer/public-gpg-keys/my-encryption-key.gpg

# Commit to repo
git add installer/public-gpg-keys/my-encryption-key.gpg
git commit -m "Add public GPG key for encrypted lists"
git push
```

During installation or updates, this key will be automatically imported and used to decrypt your encrypted list files.

## Verification

To verify which keys are currently imported on the server:

```bash
gpg --list-keys
```

To see key fingerprints:

```bash
gpg --list-keys --fingerprint
```
