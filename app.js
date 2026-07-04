/* =========================================================
   1. CONFIG — paste your deployed Apps Script Web App URL here
   ========================================================= */
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzRhFtK4E7biBnnaTPfz78QuwnWL2kxuJUbbjmFPK298fPokPe_2sZDNtrc7k_Mi91q/exec";

/* A fixed salt for the WebAuthn PRF extension. It does not need to be
   secret — it just needs to be the same every time so the same
   fingerprint produces the same derived key on this device. */
const PRF_SALT = new TextEncoder().encode("fp-login-site-v1");

/* =========================================================
   2. Small helpers
   ========================================================= */
const $ = (id) => document.getElementById(id);

function showMsg(text, type = "ok") {
  const el = $("msg");
  el.textContent = text;
  el.className = `msg show ${type}`;
}
function clearMsg() {
  $("msg").className = "msg";
}

function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64ToBuf(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bufToB64(bytes.buffer);
}

/* Calls the Apps Script backend. Uses text/plain to avoid a CORS
   preflight request, which Apps Script Web Apps don't handle. */
async function callServer(action, payload) {
  const res = await fetch(APPS_SCRIPT_URL, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action, ...payload }),
  });
  return res.json();
}

/* =========================================================
   3. WebAuthn PRF: turn a fingerprint into an AES key
   ========================================================= */
async function deriveAesKeyFromPrf(prfBytes) {
  const baseKey = await crypto.subtle.importKey(
    "raw", prfBytes, "HKDF", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: PRF_SALT },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptWithKey(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv: bufToB64(iv), ct: bufToB64(ct) };
}
async function decryptWithKey(key, ivB64, ctB64) {
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64ToBuf(ctB64));
  return new TextDecoder().decode(pt);
}

function deviceStoreKey(username) {
  return `fpdevice_${username.toLowerCase()}`;
}

/* Create a new platform (fingerprint) credential for this device and
   register it against the currently logged-in account. */
async function enableFingerprint(username) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: "Access Panel" },
      user: { id: userId, name: username, displayName: username },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
      extensions: { prf: {} },
      timeout: 60000,
    },
  });

  const prfSupported = credential.getClientExtensionResults().prf?.enabled;
  if (!prfSupported) {
    throw new Error("This device/browser doesn't support secure fingerprint unlock (WebAuthn PRF). Try Chrome or Edge on a device with Windows Hello / Touch ID.");
  }

  // Immediately do a get() to pull out the PRF secret tied to this credential.
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: credential.rawId, type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });

  const prfResult = assertion.getClientExtensionResults().prf?.results?.first;
  if (!prfResult) throw new Error("Could not derive a key from this fingerprint sensor.");

  const key = await deriveAesKeyFromPrf(prfResult);
  const deviceToken = randomToken();
  const { iv, ct } = await encryptWithKey(key, deviceToken);
  const credentialId = bufToB64(credential.rawId);

  const result = await callServer("registerDevice", { username, credentialId, deviceToken });
  if (!result.success) throw new Error(result.error || "Server rejected device registration.");

  localStorage.setItem(deviceStoreKey(username), JSON.stringify({ credentialId, iv, ct }));
}

/* Use an existing fingerprint credential on this device to unlock the
   locally-stored device token, then confirm it with the server. */
async function loginWithFingerprint(username) {
  const raw = localStorage.getItem(deviceStoreKey(username));
  if (!raw) throw new Error("No fingerprint sign-in set up for this account on this device.");
  const { credentialId, iv, ct } = JSON.parse(raw);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: b64ToBuf(credentialId), type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });

  const prfResult = assertion.getClientExtensionResults().prf?.results?.first;
  if (!prfResult) throw new Error("Fingerprint check didn't return a usable key.");

  const key = await deriveAesKeyFromPrf(prfResult);
  const deviceToken = await decryptWithKey(key, iv, ct);

  const result = await callServer("verifyDevice", { username, deviceToken });
  if (!result.success) throw new Error(result.error || "Server could not verify this device.");
  return true;
}

/* =========================================================
   4. UI wiring
   ========================================================= */
let currentUser = null;

function setLoggedIn(username) {
  currentUser = username;
  $("authArea").classList.add("hidden");
  $("sessionArea").classList.remove("hidden");
  $("whoAmI").textContent = username;

  const hasDevice = !!localStorage.getItem(deviceStoreKey(username));
  $("enableFpBtn").classList.toggle("hidden", hasDevice);
}

function setLoggedOut() {
  currentUser = null;
  $("authArea").classList.remove("hidden");
  $("sessionArea").classList.add("hidden");
  $("loginForm").reset();
  $("registerForm").reset();
}

// Tabs
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const isLogin = tab.dataset.tab === "login";
    $("loginForm").classList.toggle("hidden", !isLogin);
    $("registerForm").classList.toggle("hidden", isLogin);
    clearMsg();
  });
});

// Show the fingerprint option as soon as a recognized username is typed
$("loginUser").addEventListener("input", (e) => {
  const username = e.target.value.trim();
  const known = username && localStorage.getItem(deviceStoreKey(username));
  $("fingerprintArea").classList.toggle("hidden", !known);
  if (known) $("fpLabel").textContent = `Sign in as ${username}`;
});

// Register
$("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMsg();
  const username = $("regUser").value.trim();
  const password = $("regPass").value;
  try {
    const result = await callServer("register", { username, password });
    if (!result.success) return showMsg(result.error || "Registration failed.", "err");
    showMsg("Account created. You can log in now.", "ok");
    document.querySelector('.tab[data-tab="login"]').click();
    $("loginUser").value = username;
  } catch (err) {
    showMsg("Couldn't reach the server. Check the Apps Script URL in app.js.", "err");
  }
});

// Login
$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMsg();
  const username = $("loginUser").value.trim();
  const password = $("loginPass").value;
  try {
    const result = await callServer("login", { username, password });
    if (!result.success) return showMsg(result.error || "Incorrect username or password.", "err");
    setLoggedIn(username);
  } catch (err) {
    showMsg("Couldn't reach the server. Check the Apps Script URL in app.js.", "err");
  }
});

// Fingerprint login
$("fingerprintBtn").addEventListener("click", async () => {
  const username = $("loginUser").value.trim();
  if (!username) return showMsg("Type your username first.", "err");
  clearMsg();
  $("scanIcon").classList.add("scanning");
  try {
    await loginWithFingerprint(username);
    setLoggedIn(username);
  } catch (err) {
    showMsg(err.message, "err");
  } finally {
    $("scanIcon").classList.remove("scanning");
  }
});

// Enable fingerprint (from the session view)
$("enableFpBtn").addEventListener("click", async () => {
  clearMsg();
  try {
    await enableFingerprint(currentUser);
    showMsg("Fingerprint sign-in enabled on this device.", "ok");
    $("enableFpBtn").classList.add("hidden");
  } catch (err) {
    showMsg(err.message, "err");
  }
});

// Logout
$("logoutBtn").addEventListener("click", () => {
  setLoggedOut();
});
