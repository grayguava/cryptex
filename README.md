## What ByteSeal is for

ByteSeal exists to do **one thing**:

> **Take a file, encrypt it with a password, and return a single encrypted container.**

You might use ByteSeal to:

- encrypt files before storing them in untrusted locations
- move files between devices without exposing contents
- keep a simple, offline encryption workflow
- inspect or experiment with client-side cryptography in the browser

There is no ecosystem, sync, or automation layer.

---

## What ByteSeal can do

- Encrypt any file into a single encrypted container (`.byts`)
- Decrypt `.byts` containers back to the original file
- Preserve original filename and MIME type inside encrypted metadata
- Run fully offline after initial page load

---

## What ByteSeal does **not** do

- No password recovery
- No cloud storage
- No key management
- No multi-file archives
- No protection against a compromised system

If the password is lost, the data is unrecoverable.  
This is intentional.

---

## Technical overview

- **Key derivation:** PBKDF2 (SHA-256, 250k iterations)
- **Encryption:** AES-256-GCM
- **Randomness:** `crypto.getRandomValues`
- **Environment:** Browser (Web Crypto API)
- **Execution model:** Client-side only

---

## Container format (ByteSeal v1)

```
[ Plain header ]

- magic: "BYTESEAL" (8 bytes)
- version: 0x01
- salt: 16 bytes 
- iv: 12 bytes 

[ Encrypted payload (AES-256-GCM) ]

- metadata length (uint32, big-endian)
- metadata JSON (filename, MIME type)
- raw file bytes
```


All metadata is encrypted.  
Encrypted output filenames are intentionally opaque and random.

---

## Filenames and metadata

- Output container filenames do **not** reveal the original filename
- Original filename and MIME type are stored **inside encrypted metadata**
- Filenames are restored only after successful decryption

This prevents metadata leakage from encrypted containers.

---

## Threat model

ByteSeal is designed to protect against:

- cloud storage inspection
- curious servers
- accidental file exposure
- untrusted networks

ByteSeal does **not** protect against:

- malware on the user’s device
- keyloggers
- compromised browsers or operating systems
- weak or reused passwords

ByteSeal assumes the execution environment is trusted.

---

## Limitations

- Files are processed fully in memory  
  (browser memory limits apply)
- Very large files may fail on low-memory devices
- Rendering decrypted files depends on external viewers

---

## Design

ByteSeal is intentionally:

- small
- explicit
- offline-first
- scope-limited
- boring

It avoids feature creep, background services, and hidden behavior.

---

## License

MIT