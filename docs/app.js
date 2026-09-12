// CryptoVault Interactive Cryptographic Deck & Tools

document.addEventListener("DOMContentLoaded", () => {
  initDeckTabs();
  initWebCryptoInspector();
  initPasswordStudio();
  initCopyButtons();
});

// 1. Deck Tab Switching
function initDeckTabs() {
  const tabButtons = document.querySelectorAll(".deck-tab-button");
  const tabPanes = document.querySelectorAll(".tab-pane");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.tab;
      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add("active");
      }
    });
  });
}

// 2. Buffer <-> Hex helpers
function bufToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

function secureChoice(chars) {
  const value = new Uint32Array(1);
  window.crypto.getRandomValues(value);
  return chars[value[0] % chars.length];
}

// Global active state for encryption demo
let activeCipherState = null;

// 3. WebCrypto AEAD Inspector
function initWebCryptoInspector() {
  const secretInput = document.getElementById("field-secret");
  const passInput = document.getElementById("field-pass");
  const btnRun = document.getElementById("btn-run-aead");
  const btnTamper = document.getElementById("btn-tamper-tag");
  const btnVerify = document.getElementById("btn-verify-aead");

  const hexSalt = document.getElementById("hex-salt");
  const hexNonce = document.getElementById("hex-nonce");
  const hexTag = document.getElementById("hex-tag");
  const hexCiphertext = document.getElementById("hex-ct");
  const statusBadge = document.getElementById("status-badge");

  if (!btnRun) return;

  btnRun.addEventListener("click", async () => {
    const secret = secretInput.value.trim();
    const passphrase = passInput.value;

    if (!secret || !passphrase) {
      alert("Please provide both a secret and a master passphrase.");
      return;
    }

    try {
      const enc = new TextEncoder();
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const nonce = window.crypto.getRandomValues(new Uint8Array(12));

      // Derive AES-GCM 256-bit key from passphrase using PBKDF2-SHA256
      const baseKey = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      const aesKey = await window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      // Authenticated Encryption with AES-256-GCM
      // Associated data binds the service context (metadata authentication)
      const aad = enc.encode("crypto-vault:demo-session");
      const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        aesKey,
        enc.encode(secret)
      );

      const encryptedBytes = new Uint8Array(encryptedBuffer);
      // In WebCrypto AES-GCM, the last 16 bytes are the authentication tag
      const tagBytes = encryptedBytes.slice(-16);
      const ctBytes = encryptedBytes.slice(0, -16);

      activeCipherState = {
        salt,
        nonce,
        aad,
        fullCiphertext: encryptedBytes,
        originalSecret: secret
      };

      hexSalt.textContent = bufToHex(salt);
      hexNonce.textContent = bufToHex(nonce);
      hexTag.textContent = bufToHex(tagBytes);
      hexCiphertext.textContent = bufToHex(ctBytes);

      statusBadge.className = "status-badge-inline status-neutral";
      statusBadge.textContent = "Pipeline executed cleanly. Ready to verify or simulate bit-flip attack.";

      btnTamper.disabled = false;
      btnVerify.disabled = false;

    } catch (err) {
      statusBadge.className = "status-badge-inline status-danger";
      statusBadge.textContent = "Encryption Error: " + err.message;
    }
  });

  // Tamper: Injects a single bit flip into the AEAD Authentication Tag
  btnTamper.addEventListener("click", () => {
    if (!activeCipherState) return;

    // Flip 1 bit in the authentication tag (last byte)
    const ct = activeCipherState.fullCiphertext;
    ct[ct.length - 1] ^= 0x01;

    // Update display tag
    const tamperedTag = ct.slice(-16);
    hexTag.textContent = bufToHex(tamperedTag) + " (TAMPERED)";
    hexTag.style.color = "var(--accent-rose)";

    statusBadge.className = "status-badge-inline status-danger";
    statusBadge.textContent = "1-Bit Tamper Injected into Tag. Click 'Verify & Decrypt' to observe AEAD rejection.";
  });

  // Decrypt and Verify
  btnVerify.addEventListener("click", async () => {
    if (!activeCipherState) return;

    const passphrase = passInput.value;
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    try {
      const baseKey = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      const aesKey = await window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: activeCipherState.salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: activeCipherState.nonce, additionalData: activeCipherState.aad },
        aesKey,
        activeCipherState.fullCiphertext
      );

      const plaintext = dec.decode(decrypted);
      statusBadge.className = "status-badge-inline status-success";
      statusBadge.textContent = "AUTHENTICATED: Decrypted plaintext = \"" + plaintext + "\" (Tag Validated)";
      hexTag.style.color = "var(--text-1)";

    } catch (err) {
      statusBadge.className = "status-badge-inline status-danger";
      statusBadge.textContent = "AUTHENTICATION FAILED: GCM Tag Verification Mismatch! Modified data rejected.";
    }
  });
}

// 4. Precision Password Studio
function initPasswordStudio() {
  const slider = document.getElementById("slider-pass-len");
  const lenDisplay = document.getElementById("display-pass-len");
  const chkUpper = document.getElementById("opt-upper");
  const chkLower = document.getElementById("opt-lower");
  const chkNum = document.getElementById("opt-num");
  const chkSym = document.getElementById("opt-sym");
  const btnGen = document.getElementById("btn-generate-password");
  const outputField = document.getElementById("field-generated-password");
  const entropyLabel = document.getElementById("label-entropy-bits");
  const strengthRating = document.getElementById("label-strength-rating");
  const meterBar = document.getElementById("meter-bar-fill");

  if (!btnGen) return;

  slider.addEventListener("input", () => {
    lenDisplay.textContent = slider.value;
    generate();
  });

  [chkUpper, chkLower, chkNum, chkSym].forEach(chk => {
    chk.addEventListener("change", generate);
  });

  btnGen.addEventListener("click", generate);

  function generate() {
    const len = parseInt(slider.value, 10);
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let pool = "";
    let guaranteed = [];

    if (chkUpper.checked) {
      pool += upper;
      guaranteed.push(secureChoice(upper));
    }
    if (chkLower.checked) {
      pool += lower;
      guaranteed.push(secureChoice(lower));
    }
    if (chkNum.checked) {
      pool += digits;
      guaranteed.push(secureChoice(digits));
    }
    if (chkSym.checked) {
      pool += symbols;
      guaranteed.push(secureChoice(symbols));
    }

    if (!pool) {
      pool = lower + digits;
      guaranteed = ["x", "9"];
    }

    let chars = [...guaranteed];
    const randVals = new Uint32Array(len);
    window.crypto.getRandomValues(randVals);

    for (let i = chars.length; i < len; i++) {
      chars.push(pool[randVals[i] % pool.length]);
    }

    // Cryptographic Fisher-Yates shuffle
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randVals[i] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    const pass = chars.join("");
    outputField.value = pass;

    // Calculate Shannon entropy: H = L * log2(N)
    const entropy = Math.round(len * Math.log2(pool.length));
    entropyLabel.textContent = `${entropy} bits`;

    let color = "#ef4444";
    let pct = 20;
    let label = "Vulnerable";

    if (entropy > 45) { color = "#f97316"; pct = 45; label = "Weak"; }
    if (entropy > 65) { color = "#fbbf24"; pct = 70; label = "Good"; }
    if (entropy > 85) { color = "#10b981"; pct = 90; label = "Hardened"; }
    if (entropy > 105) { color = "#38bdf8"; pct = 100; label = "Military Grade"; }

    meterBar.style.width = pct + "%";
    meterBar.style.backgroundColor = color;
    strengthRating.textContent = label;
    strengthRating.style.color = color;
  }

  generate();
}

// 5. Copy Buttons & Toasts
function initCopyButtons() {
  document.querySelectorAll("[data-copy-target]").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.copyTarget;
      const targetEl = document.getElementById(targetId);
      if (!targetEl) return;

      const text = targetEl.value || targetEl.textContent;
      navigator.clipboard.writeText(text).then(() => {
        const originalHtml = btn.innerHTML;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied`;
        btn.classList.add("copied");

        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.classList.remove("copied");
        }, 2000);
      });
    });
  });
}
