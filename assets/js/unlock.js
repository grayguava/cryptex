/*
  ByteSeal v1.0 — Unlock

  Container header:
  [ 8  bytes ] magic
  [ 1  byte  ] version
  [ 16 bytes ] salt
  [ 12 bytes ] iv
  [ n bytes  ] AES-GCM encrypted payload

  Payload (after decrypt):
  [ 4 bytes ] metadata length (uint32, big-endian)
  [ n bytes ] metadata JSON (utf-8)
  [ m bytes ] file bytes
*/

class CryptoAuthError extends Error {
  constructor() {
    super("Incorrect password or corrupted file");
    this.name = "CryptoAuthError";
  }
}


import { FORMATS } from "./version.js";

// =====================
// Constants
// =====================
const MAGIC_LEN = 8;
const VERSION_LEN = 1;
const SALT_LEN = 16;
const IV_LEN = 12;

const HEADER_LEN = MAGIC_LEN + VERSION_LEN + SALT_LEN + IV_LEN;
const PBKDF2_ITERS = 250000;

// =====================
// DOM
// =====================
const form = document.getElementById("form");
const fileInput = document.getElementById("file");
const fileNameEl = document.getElementById("fileName");
const passwordInput = document.getElementById("password");
const status = document.getElementById("status");
const unlockBtn = document.getElementById("unlockBtn");

// =====================
// Helpers
// =====================
if (fileInput && fileNameEl) {
  fileInput.addEventListener("change", () => {
    fileNameEl.textContent =
      fileInput.files.length ? fileInput.files[0].name : "No file chosen";
  });
}

function setStatus(msg, isError = false) {
  status.textContent = msg;
  status.style.color = isError ? "#a33" : "#222";
}

/*
  IMPORTANT:
  Binary format detection MUST be byte-wise.
  Do NOT decode magic as text — mobile browsers will break it.
*/
function detectFormat(buf) {
  for (const fmt of Object.values(FORMATS)) {
    const magicBytes = new TextEncoder().encode(fmt.magic);

    let match = true;
    for (let i = 0; i < MAGIC_LEN; i++) {
      if (buf[i] !== magicBytes[i]) {
        match = false;
        break;
      }
    }

    if (match) return fmt;
  }

  throw new Error("Unknown container format");
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

// =====================
// Main
// =====================
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  setStatus("");

  const file = fileInput.files[0];
  if (!file) return setStatus("No file selected", true);

  const password = passwordInput.value;
  if (!password) return setStatus("Password required", true);

  unlockBtn.disabled = true;

  try {
    setStatus("Reading container…");
    const buf = new Uint8Array(await file.arrayBuffer());
    if (buf.length < HEADER_LEN) throw new Error("Invalid container");

    setStatus("Detecting format…");
    const format = detectFormat(buf);

    const version = buf[MAGIC_LEN];
    if (version !== format.version)
      throw new Error(`Unsupported ${format.label}`);

    const saltOff = MAGIC_LEN + VERSION_LEN;
    const ivOff = saltOff + SALT_LEN;
    const ctOff = ivOff + IV_LEN;

    const salt = buf.slice(saltOff, saltOff + SALT_LEN);
    const iv = buf.slice(ivOff, ivOff + IV_LEN);
    const ct = buf.slice(ctOff);

    setStatus("Deriving key…");
    const key = await deriveKey(password, salt.buffer);

    setStatus("Decrypting…");
    let plaintext;

try {
  plaintext = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
  );
} catch {
  throw new CryptoAuthError();
}


    if (plaintext.length < 4)
  throw new Error("Decrypted payload is invalid");

const view = new DataView(plaintext.buffer);
const metaLen = view.getUint32(0, false);

if (metaLen <= 0 || metaLen > plaintext.length - 4)
  throw new Error("Decrypted metadata is corrupted");

    
    const metaJson = new TextDecoder("utf-8", { fatal: true }).decode(
      plaintext.slice(4, 4 + metaLen)
    );
    const meta = JSON.parse(metaJson);

    const fileBytes = plaintext.slice(4 + metaLen);

    setStatus("Restoring file…");
    const blob = new Blob([fileBytes], { type: meta.type });

    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = meta.name;
    a.click();
    URL.revokeObjectURL(a.href);

    setStatus(`File restored (${format.label})`);
    
  } catch (err) {
  if (err instanceof CryptoAuthError) {
    setStatus("Wrong password or file was modified", true);
  } else {
    setStatus(err.message || "Decryption failed", true);
  }
}

  
  finally {
    unlockBtn.disabled = false;
  }
});
