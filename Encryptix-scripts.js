/* =============================
   Mobile Menu Toggle
   ============================= */
const menuToggle = document.querySelector('.menu-toggle');
const siteNav = document.querySelector('.site-nav');
if (menuToggle) {
  menuToggle.addEventListener('click', () => {
    siteNav.classList.toggle('open');
  });
}

/* =============================
   Progress Bar Helper
   ============================= */
function animateProgress(barId) {
  const bar = document.getElementById(barId);
  if (!bar) return;
  bar.style.width = '0%';
  setTimeout(() => { bar.style.width = '100%'; }, 50);
  setTimeout(() => { bar.style.width = '0%'; }, 1500);
}

/* =============================
   SYMMETRIC (Caesar Cipher)
   ============================= */
const symEncryptBtn = document.getElementById('sym-encrypt');
const symDecryptBtn = document.getElementById('sym-decrypt');

function caesarEncrypt(str, key) {
  return str.replace(/[a-z]/gi, (c) => {
    const base = c === c.toUpperCase() ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + key) % 26 + base);
  });
}
function caesarDecrypt(str, key) {
  return caesarEncrypt(str, 26 - key);
}

if (symEncryptBtn) {
  symEncryptBtn.addEventListener('click', () => {
    const text = document.getElementById('sym-text').value;
    const key = parseInt(document.getElementById('sym-key').value);
    if (!text || isNaN(key)) return alert('Enter text and a key (1-25)');
    animateProgress('sym-progress');
    document.getElementById('sym-result').textContent = caesarEncrypt(text, key);
  });
}
if (symDecryptBtn) {
  symDecryptBtn.addEventListener('click', () => {
    const text = document.getElementById('sym-text').value;
    const key = parseInt(document.getElementById('sym-key').value);
    if (!text || isNaN(key)) return alert('Enter text and a key (1-25)');
    animateProgress('sym-progress');
    document.getElementById('sym-result').textContent = caesarDecrypt(text, key);
  });
}

/* ============================================================================
   ASYMMETRIC ENCRYPTION DEMO (RSA-OAEP)
   Simple "encrypt then decrypt" walk-through for non technical users
   ============================================================================ */

if (document.getElementById("asym-text")) {
  const $ = (id) => document.getElementById(id);

  const textInput   = $("asym-text");
  const stepsOutput = $("asym-steps");
  const runBtn      = $("asym-run");

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let publicKey = null;
  let privateKey = null;

  function showSteps(text, ok = false, error = false) {
    stepsOutput.textContent = text;
    stepsOutput.style.whiteSpace = "pre-wrap";
    if (error) {
      stepsOutput.style.color = "#8a0000";
    } else if (ok) {
      stepsOutput.style.color = "#116611";
    } else {
      stepsOutput.style.color = "inherit";
    }
  }

  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  async function ensureKeyPair() {
    // Reuse keys if already generated so the user can run the demo again
    if (publicKey && privateKey) return;

    const pair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    publicKey = pair.publicKey;
    privateKey = pair.privateKey;
  }

  runBtn.addEventListener("click", async () => {
    try {
      const message =
        textInput.value.trim() ||
        "Sample message from a shelter to a vet clinic";

      showSteps("Running demo...");

      // Step 1 – generate or reuse the key pair
      await ensureKeyPair();

      // Step 2 – encrypt the message with the public key
      const plainBytes = encoder.encode(message);
      const cipherBytes = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        plainBytes
      );
      const cipherB64 = bufToBase64(cipherBytes);

      // Truncate encrypted text to 20 characters for display
      const truncatedCipher =
        cipherB64.length > 20 ? cipherB64.slice(0, 20) + "..." : cipherB64;

      // Step 3 – decrypt with the private key
      const decryptedBytes = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        cipherBytes
      );
      const decryptedMessage = decoder.decode(decryptedBytes);

      const explanation =
        "Step 1  Plain message typed by the user:\n" +
        "  " + message + "\n\n" +
        "Step 2  Encrypted message (Truncated to the first 20 characters for tidiness):\n" +
        "  " + truncatedCipher + "\n\n" +
        "Step 3  Same message decrypted again with the private key:\n" +
        "  " + decryptedMessage + "\n\n" +
        "Summary  Anyone with the public key can encrypt, but only the server that holds\n" +
        "the private key can turn this encrypted message back into readable text.";

      showSteps(explanation, true);
    } catch (err) {
      console.error(err);
      showSteps(
        "Something went wrong while running the demo. Please dont ask where we have no idea",
        false,
        true
      );
    }
  });
}

/* =============================
   HASHING (SHA-256 with VERIFY)
   ============================= */
let lastHash = "";
const hashBtn = document.getElementById('hash-generate');
const hashVerifyBtn = document.getElementById('hash-verify');

if (hashBtn) {
  hashBtn.addEventListener('click', async () => {
    const txt = document.getElementById('hash-input').value;
    if (!txt) return alert('Enter text to hash');
    animateProgress('hash-progress');
    const data = new TextEncoder().encode(txt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    lastHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('hash-result').textContent = lastHash;
  });
}

if (hashVerifyBtn) {
  hashVerifyBtn.addEventListener('click', async () => {
    if (!lastHash) return alert('Generate a hash first');
    const txt = document.getElementById('hash-input').value;
    if (!txt) return alert('Enter text to verify');
    const data = new TextEncoder().encode(txt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    animateProgress('hash-progress');
    if (hashHex === lastHash) {
      document.getElementById('hash-result').textContent = "✅ Match: Text produces the same hash.";
    } else {
      document.getElementById('hash-result').textContent = "❌ No match: Text does not match the stored hash.";
    }
  });
}

/* =============================
   HYBRID (AES + RSA with Decrypt)
   ============================= */
const hybridEncryptBtn = document.getElementById('hybrid-run');
const hybridDecryptBtn = document.getElementById('hybrid-decrypt');
let hybridStore = {cipher: null, iv: null, wrappedKey: null, rsaKeys: null};

if (hybridEncryptBtn) {
  hybridEncryptBtn.addEventListener('click', async () => {
    const txt = document.getElementById('hybrid-text').value;
    if (!txt) return alert('Enter text');
    animateProgress('hybrid-progress');

    // Generate AES key
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt","decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(txt);
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc);

    // Generate RSA keypair
    const rsaKeys = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 1024, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
      true, ["encrypt","decrypt"]
    );
    const rawAes = await crypto.subtle.exportKey("raw", aesKey);
    const wrappedKey = await crypto.subtle.encrypt({name:"RSA-OAEP"}, rsaKeys.publicKey, rawAes);

    hybridStore = {cipher, iv, wrappedKey, rsaKeys};

    document.getElementById('hybrid-result').textContent =
      `Hybrid done: AES message encrypted & key wrapped with RSA. You can now decrypt.`;
  });
}

if (hybridDecryptBtn) {
  hybridDecryptBtn.addEventListener('click', async () => {
    if (!hybridStore.cipher || !hybridStore.rsaKeys) return alert('Run the hybrid encryption first');
    animateProgress('hybrid-progress');

    // Unwrap AES key
    const rawKey = await crypto.subtle.decrypt({name:"RSA-OAEP"}, hybridStore.rsaKeys.privateKey, hybridStore.wrappedKey);
    const aesKey = await crypto.subtle.importKey("raw", rawKey, {name:"AES-GCM"}, false, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt({name:"AES-GCM", iv: hybridStore.iv}, aesKey, hybridStore.cipher);

    document.getElementById('hybrid-result').textContent = `Decrypted: ${new TextDecoder().decode(decrypted)}`;
  });
}

/* =============================
   RESET
   ============================= */
const resetBtn = document.getElementById('reset-btn');
if (resetBtn) {
  resetBtn.addEventListener('click', () => {
    ['sym-text','sym-key','asym-text','hash-input','hybrid-text'].forEach(id=>{
      const el=document.getElementById(id); if(el) el.value='';
    });
    ['sym-result','asym-result','hash-result','hybrid-result','asym-keys'].forEach(id=>{
      const el=document.getElementById(id); if(el) el.textContent='';
    });
    ['sym-progress','asym-progress','hash-progress','hybrid-progress'].forEach(id=>{
      const el=document.getElementById(id); if(el) el.style.width='0%';
    });
    lastHash = "";
    hybridStore = {cipher: null, iv: null, wrappedKey: null, rsaKeys: null};
  });
}
