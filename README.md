# VaultCrypt

**English** · [Română](README.ro.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [Português](README.pt.md) · [Deutsch](README.de.md) · [Magyar](README.hu.md)

**Version:** 3.0.1 · **Last updated:** 2026-10-27

**Status:** experimental · **Offline:** complete

Interface languages: **Română, English, Français, Italiano, Español, Português (PT), Deutsch, Magyar**

**Live / demo:** https://chiuta.github.io/VaultCrypt/

![VaultCrypt — screenshot](screenshot.en.png)

In-browser encryption/decryption of files and text, in a single `index.html` (8 languages), plus a password generator and checksums.

## How it works (from the code)
- Key derived from the password with PBKDF2-HMAC-SHA-256 (600,000 / 1,000,000 iterations; default "High" = 600,000; the last level used when sealing is remembered locally in `localStorage`, key `vaultcrypt.sec`), random 16-byte salt.
- AES-256-GCM encryption (Web Crypto) with a random 12-byte IV; the container header (39 bytes) is authenticated as additional data.
- `.vault` format (magic `VCRYPT`, version 1/2) or a text "armored" block for messages.
- Generated passwords use `crypto.getRandomValues`. Checksums: SHA-256/384/512 and SHA-1 (SHA-1 is weak; use it only to verify file integrity, not for security).

## Cryptographic details and file format (read from the code, 3.0.1)

> **Not independently audited.** The scheme below is documented exactly as the current code implements it. It is a description, not a security guarantee, and it has not been reviewed by an outside cryptographer.

**Key derivation (KDF)**
- Algorithm: **PBKDF2** with HMAC-SHA-256 (Web Crypto `deriveKey`). **Argon2 / scrypt are not used.**
- Iterations: **600,000** ("High", default) or **1,000,000** ("Paranoid"). The count is stored in the container header; when opening, values from 1 to 10,000,000 are accepted (anything else is refused to avoid a crafted header freezing the browser). Older containers may carry lower counts (e.g. 310,000) and still open.
- Salt: 16 random bytes (`crypto.getRandomValues`), new for every container.
- Passphrase: the UTF-8 bytes of the text exactly as typed, **without Unicode normalization** (the `.fff.json` backup, a separate feature, does normalize to NFC). Minimum 4 characters; below 12 the app warns and asks for an explicit "Seal anyway".
- Derived key: AES-256, non-extractable.

**Encryption**
- **AES-256-GCM** (Web Crypto), random 12-byte IV, 128-bit authentication tag (the Web Crypto default; the code does not set `tagLength`).
- Additional authenticated data (AAD): the whole 39-byte cleartext header, so changing the iteration count, salt or IV makes decryption fail.
- A wrong passphrase and a damaged or tampered file give the same GCM failure; the app cannot tell them apart.

**`.vault` container layout (version 2; the same bytes are used for the armored text block)**

| Bytes | Content |
|---|---|
| 0-5 | magic `VCRYPT` (`56 43 52 59 50 54`) |
| 6 | version (`2`; version `1` containers are still read) |
| 7-10 | PBKDF2 iterations, unsigned 32-bit big-endian |
| 11-26 | salt, 16 bytes |
| 27-38 | IV, 12 bytes |
| 39+ | AES-GCM ciphertext followed by the 16-byte tag |

Plaintext before encryption (v2): `file count` (uint16 BE), then for each file `name length` (uint16 BE), `name` (UTF-8), `data length` (uint32 BE), `data`. Limits in the format: 65,535 files, 65,535 bytes per name, under 4 GiB per file; the app itself stops at about 400 MB per operation. Version 1: a single file, `name length` (uint16 BE) + `name` + data. For a text message the single entry has an empty name.

**Armored text block**: `-----BEGIN VAULTCRYPT MESSAGE-----`, the container in Base64 wrapped at 64 characters, `-----END VAULTCRYPT MESSAGE-----`.

**What the container does not hide**: its size (the ciphertext length reveals the plaintext length; there is no padding), the iteration count, and the fact that it is a VaultCrypt container (magic bytes). File names and the number of files are inside the encrypted part. There is no compression, no key file and no recovery.

**Recovery shares (Shamir, tab "Shares")**: split only the passphrase (or another short secret, up to 1024 bytes), they do not change the container format. Shamir (k, n) over GF(2^8) with the AES polynomial 0x11B, fresh random coefficients from `crypto.getRandomValues`, n up to 16, x = 1..n. The secret is padded to a multiple of 64 bytes and a 4-byte check tag (SHA-256 of `"VCS1"` plus the padded part) is shared with it. Share text: `VCS1:` + Base32 groups (also as a QR code), with a CRC that only detects typos. Shares are **not encrypted**: anyone holding k of them can rebuild the secret.

**Encrypted backup of app data (`.fff.json`, fff-kit)**: PBKDF2-HMAC-SHA-256 with 600,000 iterations (accepted on import: 100,000 to 5,000,000), 16-byte salt, AES-256-GCM with a 12-byte IV, AAD `fff-bundle-enc|1|<app slug>`, passphrase normalized to NFC, minimum 12 characters. JSON envelope: `format`, `schema`, `app`, `kdf`, `iter`, `salt`, `iv`, `ct` (Base64).

**Planned / not done**: an independent security audit (needs an outside expert) and an Argon2 option (it would change the format and is not implemented; a new format version would be needed).

## Warnings
- **Not independently audited.** Code written by a single author, with no external security audit; do not use it as the sole protection for critical data.
- **Lost password = lost data.** There is no recovery. Keep backups and store the password in a safe place.
- The password stays in the browser's memory for the duration of the session; a compromised device (malware, extensions) defeats the protection.

## Data and privacy
No network requests: the page has a CSP with `connect-src 'self'`, and `fetch`/`XMLHttpRequest`/`sendBeacon` are blocked in the code ("Privacy audit" log in the page). No telemetry, no external fonts or scripts. Checked in the audit: 0 external requests on load. The only external links are those in the footer and in the "About" window (they open only on click).

## Limitations
Files are read entirely into memory (several times over during encryption): practical limit 400 MB per operation (tested: 380 MB OK, ≈860 MB freezes the tab). For larger files, use a desktop tool.

The CSP no longer allows `'unsafe-inline'` for scripts: the page's single script is authorized by a SHA-256 hash in the CSP meta tag (the hash must be recomputed after any change to the script), and inline handlers have been replaced with event delegation. Inline styles remain allowed. Large files are processed entirely in memory.

## License
MIT, per the header of `index.html`; see `LICENSE`.

Audit: 2026-10-10

## History / Changelog

### 2.2.5 — 2026-10-22
- fff-kit 1.1.4: touch targets and minimum text size; touch targets/text fixed

### 2.2.4 — 2026-10-22
- fff-kit 1.1.2: PBKDF2 600,000 iterations, anti-clickjacking protection.

### 2.2.3 — 2026-10-22
- Security: passphrases shorter than 12 characters are no longer accepted silently: the app shows a warning (translated into all 8 languages) and requires an explicit "Seal anyway" confirmation. The absolute minimum stays at 4 characters.

### 2.2.2 — 2026-10-22
- the language selector's accessibility label and the "additional authenticated data" (AAD) term in the About section are now translated into all languages.

### 2.2.1 — 2026-10-22
- Title, meta tags, security warning in the footer and aria-labels now follow the interface language; the fff-kit panel description is localized.

### 2.1.0 — 2026-10-14
- Data backup and labelling (fff-kit).

### 12 October 2026 (v2.0.4)
- 2.0.4 — 2026-10-12: the version and the date of the last update are shown in the app

### 11 October 2026 (v2.0.3)
- Large files: really tested (Chromium, offline) — 120 MB and 380 MB are sealed and unsealed identically (≈5 s each at 310,000 iterations), but at ≈860 MB the tab freezes on download. That is why, from 150 MB, a "large data" note appears during the operation, and above 400 MB the app refuses with a clear message (instead of freezing the tab); memory errors get their own message, in all 6 languages. The limit also applies to unsealing.
- Version v2.0.3 in the footer.

### 11 October 2026 (v2.0.2)
- Live "passwords match / do not match yet" indicator below the confirmation field (`role=status`) and a Caps Lock warning on the password fields, in all 6 languages; Ctrl/Cmd+Enter for the action already existed. Tested offline with CSP active: 0 errors, axe 0.

### 11 October 2026 (v2.0.1)
- A modified/truncated armored block (invalid base64, but with the markers present) now shows a separate integrity message ("damaged or incomplete"), in all 6 languages, instead of "valid armored block not found"; a modification that keeps the base64 valid still gives "wrong password or tampered container".
- CSP: removed `'unsafe-inline'` from `script-src` (SHA-256 hash for the single script); the 26 inline handlers were replaced with event delegation; tested with CSP active.
- Content is wrapped in `<main>` (axe: 0 violations); the default "High" level is documented explicitly (remembering the last level explains a possible "Balanced" on reopening).
- Version v2.0.2 in the footer.
