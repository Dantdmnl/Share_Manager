# Migration Guide: AES to DPAPI Encryption

## Overview

Share Manager v2.0.0+ uses **Windows DPAPI** (Data Protection API) for credential encryption instead of the legacy AES-with-key.bin approach. This provides better security by tying encryption to your Windows user account and machine.

## What Changed

### Before (v1.x)
- Credentials stored in `cred.txt` (2 lines: username, encrypted password)
- Encryption used a symmetric AES key stored in `key.bin`
- Anyone with access to both files could potentially decrypt

### After (v2.0.0+)
- Credentials stored in `creds.json` (structured JSON with multiple users)
- Encryption uses Windows DPAPI (no key file needed)
- Only your Windows user account on this machine can decrypt
- Supports multiple usernames/credentials for different shares

## Migration Process (Automatic)

**You don't need to do anything!** Migration happens automatically:

1. **First Launch**: When you run v2.0.0+ for the first time, the script detects legacy files:
   - `cred.txt` → Automatically migrated to `creds.json` with DPAPI encryption
   - `key.bin` → Kept for backward compatibility during transition

2. **First Credential Use**: When retrieving credentials:
   - Legacy AES-encrypted entries are decrypted using `key.bin`
   - Immediately re-encrypted with DPAPI and saved
   - Entry is marked with `"EncryptionType": "DPAPI"`

3. **New Credentials**: All newly saved credentials use DPAPI only

## File Structure

### Legacy (v1.x)
```
%APPDATA%\Share_Manager\
├── config.json          # Single share config
├── cred.txt             # Single credential (2 lines)
└── key.bin              # AES encryption key
```

### Modern (v2.0.0+)
```
%APPDATA%\Share_Manager\
├── shares.json          # Multi-share config
├── creds.json           # Multi-credential store (DPAPI)
├── config.json          # Legacy (auto-migrated on first run)
├── cred.txt             # Legacy (auto-migrated on first use)
└── key.bin              # Legacy (kept for transition period)
```

## creds.json Structure

```json
{
  "Entries": [
    {
      "Username": "user1",
      "Encrypted": "01000000d08c9d...",
      "EncryptionType": "DPAPI"
    },
    {
      "Username": "user2",
      "Encrypted": "01000000d08c9d...",
      "EncryptionType": "DPAPI"
    }
  ]
}
```

## Security Improvements

| Aspect | Legacy (AES + key.bin) | Modern (DPAPI) |
|--------|------------------------|----------------|
| Key Storage | Separate file (key.bin) | Windows manages internally |
| Portability | Can copy files between machines | Tied to user+machine |
| Key Compromise | If attacker gets both files | Requires OS-level breach |
| User Separation | Same key for all users | Per-user keys managed by Windows |
| Best Practice | ❌ Symmetric key in file | ✅ OS-managed encryption |

## What Happens to Old Files

**Automatic Cleanup** (v2.0.0+):
- **config.json**: Auto-migrated to shares.json format. Backup created as `config.json.v1.backup`, original removed.
- **cred.txt**: Auto-migrated to creds.json on first use. Backup created as `cred.txt.v1.backup`, original removed.
- **key.bin**: Kept permanently for backward compatibility (allows decrypting any remaining legacy credentials).

**Backups are created before deletion**, so you can always restore if needed. The backup files (*.v1.backup) can be safely deleted once you've confirmed everything works.

## Manual Migration (Optional)

If you want to force migration immediately:

1. Launch Share Manager v2.0.0+
2. Go to Credentials menu (K)
3. Select "Save/Update Credentials" for each username
4. Re-enter password for each
5. This forces re-encryption with DPAPI

## Verification

After migration, check `creds.json`:
- All entries should have `"EncryptionType": "DPAPI"`
- Encrypted strings start with `01000000d08c9d...` (DPAPI marker)

## Persistent Mapping (Logon Script)

The startup script (`Share_Manager_AutoMap.ps1`) supports both:
- **DPAPI** entries (modern)
- **AES** entries (legacy, uses key.bin if present)

This ensures your shares reconnect at logon even during migration.

## Rollback (Not Recommended)

If you need to revert to v1.x:
1. Restore `config.json.v1.backup` to `config.json`
2. Delete `shares.json` and `creds.json`
3. Keep `cred.txt` and `key.bin`

**Warning**: You'll lose multi-share support and DPAPI encryption.

## FAQ

**Q: Can I use Share Manager on multiple machines?**  
A: Yes, but credentials won't transfer (DPAPI is per-user/per-machine). Export/import your `shares.json` config, then re-enter credentials on each machine.

**Q: What if I change my Windows password?**  
A: DPAPI credentials remain accessible. Windows handles password changes automatically.

**Q: Can I delete key.bin now?**  
A: Wait until all credentials show `"EncryptionType": "DPAPI"` in `creds.json`, then it's safe to delete.

**Q: Is this more secure?**  
A: Yes. DPAPI ties encryption to your Windows identity, eliminating the symmetric key file attack vector.

## Support

- See [GDPR-COMPLIANCE.md](GDPR-COMPLIANCE.md) for data handling details
- Open an issue on GitHub with "Migration" in the title for migration-specific questions
- Include your Share Manager version (visible in menus/title bars)
