/**
 * @file popup/pairing.js
 * @description Popup-side pairing UI logic for the Beam Chrome extension.
 *
 * This module drives the QR display, PIN countdown, SAS emoji verification,
 * and device-naming steps of the pairing ceremony.  It is intentionally free
 * of DOM bootstrapping — callers provide the container/canvas elements so that
 * the functions are independently testable and easy to embed in any popup view.
 *
 * Message flow (simplified):
 *   popup → background → offscreen: MSG.START_PAIRING
 *   offscreen → popup            : MSG.PAIRING_QR_DATA  (QR payload)
 *   offscreen → popup            : MSG.PAIRING_SAS      (emoji array)
 *   popup → offscreen            : MSG.PAIRING_CONFIRM_SAS
 *   popup → offscreen            : MSG.PAIRING_SET_DEVICE_NAME
 *   offscreen → popup            : MSG.PAIRING_COMPLETE
 *
 * @module popup/pairing
 */

import { MSG } from '../shared/message-types.js';

// ---------------------------------------------------------------------------
// QR initiation
// ---------------------------------------------------------------------------

/**
 * Ask the offscreen transfer-engine to begin a pairing ceremony and return
 * the QR payload data.
 *
 * Sends MSG.START_PAIRING to the runtime (routed by the service worker to the
 * offscreen document) and resolves with the `payload` field of the response.
 *
 * @returns {Promise<{
 *   deviceId: string,
 *   ed25519Pk: number[],
 *   x25519Pk: number[],
 *   relayUrl: string
 * } | undefined>} QR payload, or undefined if the offscreen document did not
 *   respond (e.g. it was not yet initialised).
 */
export async function startPairing() {
  // Check if keys already exist in storage
  let stored = await chrome.storage.local.get(['deviceId', 'deviceKeys']);

  if (stored.deviceId && stored.deviceId.length >= 16 && stored.deviceKeys?.ed25519?.pk) {
    console.log('[Beam] Using stored keys. deviceId:', stored.deviceId);
    return _buildQrData(stored);
  }

  // No keys — generate them here in the popup using Web Crypto API.
  // Web Crypto Ed25519 (Chrome 113+) and X25519 (Chrome 133+) are instant,
  // no WASM needed, and the popup has chrome.storage.local access.
  // The offscreen document can't access chrome.storage directly, so the
  // popup is the right place to generate and store keys.
  console.log('[Beam] Generating keys via Web Crypto...');

  try {
    // Ed25519 keypair
    const ed25519Key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const ed25519PkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ed25519Key.publicKey));
    const ed25519SkPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed25519Key.privateKey));

    // X25519 keypair
    const x25519Key = await crypto.subtle.generateKey('X25519', true, ['deriveBits']);
    const x25519PkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', x25519Key.publicKey));
    const x25519SkPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', x25519Key.privateKey));

    // Derive deviceId: base64url(SHA-256(ed25519Pk)[0:16])
    const hashBuffer = await crypto.subtle.digest('SHA-256', ed25519PkRaw);
    const idBytes = new Uint8Array(hashBuffer).slice(0, 16);
    const deviceId = btoa(String.fromCharCode(...idBytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // Store keys — public as raw arrays, private as PKCS8 arrays
    await chrome.storage.local.set({
      deviceId,
      deviceKeys: {
        x25519:  { pk: Array.from(x25519PkRaw),  sk: Array.from(x25519SkPkcs8) },
        ed25519: { pk: Array.from(ed25519PkRaw), sk: Array.from(ed25519SkPkcs8) },
      },
    });

    console.log('[Beam] Keys generated and stored. deviceId:', deviceId, 'length:', deviceId.length);

    return {
      deviceId,
      ed25519Pk: Array.from(ed25519PkRaw),
      x25519Pk: Array.from(x25519PkRaw),
      relayUrl: 'wss://zaptransfer-relay.fly.dev',
    };
  } catch (err) {
    console.error('[Beam] Web Crypto keygen failed:', err);
    return null;
  }
}

/**
 * Build the QR data object from chrome.storage.local values.
 *
 * @param {{ deviceId: string, deviceKeys: object }} stored
 * @returns {{ deviceId: string, ed25519Pk: number[], x25519Pk: number[], relayUrl: string }}
 */
function _buildQrData(stored) {
  return {
    deviceId:   stored.deviceId,
    ed25519Pk:  stored.deviceKeys.ed25519.pk,  // Array of numbers (from offscreen libsodium)
    x25519Pk:   stored.deviceKeys.x25519.pk,   // Array of numbers (from offscreen libsodium)
    relayUrl:   'wss://zaptransfer-relay.fly.dev',
  };
}

// ---------------------------------------------------------------------------
// QR rendering
// ---------------------------------------------------------------------------

/**
 * Render a QR code into `canvas` using the qrcode-generator library
 * (exposed as the global `qrcode` function by qr.js loaded in popup.html).
 *
 * The QR payload is a compact JSON object containing the version tag, device
 * identity, both public keys (base64), and the relay URL so that the Android
 * companion app can establish a pairing WebSocket without a side-channel.
 *
 * QR payload schema:
 * ```json
 * { "v": 1, "did": "<deviceId>", "epk": "<ed25519PkBase64>",
 *   "xpk": "<x25519PkBase64>", "relay": "<relayUrl>" }
 * ```
 *
 * If the `qrcode` global is absent (e.g. in unit-test environments where the
 * library is not loaded) the function is a no-op and logs a warning.
 *
 * @param {HTMLElement} canvas - Container element to receive the SVG tag.
 * @param {{
 *   deviceId: string,
 *   ed25519Pk: number[] | Uint8Array,
 *   x25519Pk:  number[] | Uint8Array,
 *   relayUrl:  string
 * }} data - QR payload values returned by startPairing().
 */
export function renderQR(canvas, data) {
  const qrPayload = JSON.stringify({
    v:     1,
    did:   data.deviceId,
    epk:   arrayToBase64(data.ed25519Pk),
    xpk:   arrayToBase64(data.x25519Pk),
    relay: data.relayUrl,
  });

  // qrcode-generator is loaded as a <script> tag in popup.html and exposes
  // a global `qrcode` constructor function.  Guard so the module can be
  // imported in environments where that script is absent.
  if (typeof qrcode === 'undefined') {
    console.warn('[Beam] qrcode-generator not available; QR will not render.');
    return;
  }

  // Error-correction level 'M' (~15 %) gives a good balance between payload
  // capacity and scan robustness.  Type 0 = auto-select minimum version.
  const qr = qrcode(0, 'M'); // eslint-disable-line no-undef
  qr.addData(qrPayload);
  qr.make();
  // cellSize=4, margin=0 — the popup CSS handles padding around the code.
  canvas.innerHTML = qr.createSvgTag(4, 0);
}

// ---------------------------------------------------------------------------
// PIN generation and countdown
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random 8-digit PIN string.
 *
 * The PIN provides a weak secondary channel that the Android app can use to
 * confirm it scanned the correct QR code before the SAS step is reached.
 * It is NOT a security-critical secret — the SAS emoji step provides the
 * binding guarantee.
 *
 * Pad with leading zeros so the display width is always exactly 8 characters.
 *
 * @returns {string} Zero-padded 8-digit PIN, e.g. "00731842".
 */
export function generatePIN() {
  // Math.random() is sufficient here; the PIN is purely informational.
  const pin = String(Math.floor(Math.random() * 100_000_000)).padStart(8, '0');
  return pin;
}

/**
 * Start a live countdown timer and update `element.textContent` every second.
 *
 * When the countdown reaches zero the interval is cleared and `onExpire` is
 * called (if provided) so the caller can disable the PIN and prompt the user
 * to refresh.
 *
 * @param {HTMLElement}  element  - Element whose textContent is updated each tick.
 * @param {number}       [seconds=60] - Initial countdown value in seconds.
 * @param {Function}     [onExpire]   - Optional callback fired when the timer hits 0.
 * @returns {number} The interval ID (pass to clearInterval to cancel early).
 */
export function startPINCountdown(element, seconds = 60, onExpire) {
  let remaining = seconds;

  const timer = setInterval(() => {
    remaining--;
    element.textContent = `${remaining}s`;

    if (remaining <= 0) {
      clearInterval(timer);
      if (typeof onExpire === 'function') onExpire();
    }
  }, 1000);

  return timer;
}

// ---------------------------------------------------------------------------
// SAS emoji display
// ---------------------------------------------------------------------------

/**
 * Render the Short Authentication String (SAS) emoji array into `container`.
 *
 * Each emoji is wrapped in a `.sas-emoji` div with an inner `.emoji` span so
 * CSS can style the grid layout independently from the font sizing.
 *
 * @param {HTMLElement} container - Parent element to receive the emoji markup.
 * @param {string[]}    emojis    - Array of 4 emoji strings from crypto.sasToEmoji().
 */
export function displaySAS(container, emojis) {
  container.innerHTML = emojis
    .map(e => `<div class="sas-emoji"><span class="emoji">${e}</span></div>`)
    .join('');
}

// ---------------------------------------------------------------------------
// Device naming form
// ---------------------------------------------------------------------------

/**
 * Build and insert a device-naming form into `container`.
 *
 * The form contains:
 *   - A text input pre-filled with `suggestedName` (max 30 chars).
 *   - An icon picker row with four device-type buttons (laptop, desktop, phone,
 *     tablet).  The first button is selected by default; clicking another
 *     transfers the `selected` CSS class.
 *   - A primary "Done" button, disabled until the name input is non-empty.
 *
 * When the user clicks "Done", `onSubmit({ name, icon })` is called with the
 * trimmed name and the currently-selected icon slug.
 *
 * @param {HTMLElement} container      - Parent element to receive the form markup.
 * @param {string}      suggestedName  - Pre-filled value for the name input.
 * @param {Function}    onSubmit       - Callback: ({ name: string, icon: string }) => void
 */
export function createNamingForm(container, suggestedName, onSubmit) {
  // Sanitise suggestedName to avoid XSS via attribute injection.
  const safeName = (suggestedName || '').replace(/"/g, '&quot;').replace(/</g, '&lt;');

  container.innerHTML = `
    <div class="naming-form">
      <label for="device-name">Name this device</label>
      <input type="text" id="device-name" value="${safeName}"
             placeholder="e.g., Work Laptop" maxlength="30" autocomplete="off">
      <div class="icon-picker" id="icon-picker">
        <button type="button" data-icon="laptop"  class="icon-btn selected">💻</button>
        <button type="button" data-icon="desktop" class="icon-btn">🖥️</button>
        <button type="button" data-icon="phone"   class="icon-btn">📱</button>
        <button type="button" data-icon="tablet"  class="icon-btn">📟</button>
      </div>
      <button id="naming-done" type="button" class="primary-btn" disabled>Done</button>
    </div>
  `;

  const nameInput    = container.querySelector('#device-name');
  const doneBtn      = container.querySelector('#naming-done');
  const iconBtns     = container.querySelectorAll('.icon-btn');
  let   selectedIcon = 'laptop';

  // Enable the Done button whenever the name field has non-whitespace content.
  nameInput.addEventListener('input', () => {
    doneBtn.disabled = nameInput.value.trim().length === 0;
  });

  // Transfer the `selected` class on icon button click.
  iconBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      iconBtns.forEach(b => b.classList.remove('selected'));
      btn.classList.add('selected');
      selectedIcon = btn.dataset.icon;
    });
  });

  // Fire the caller-provided callback with the final name and icon.
  doneBtn.addEventListener('click', () => {
    onSubmit({ name: nameInput.value.trim(), icon: selectedIcon });
  });

  // Enable immediately if a non-empty name was pre-filled.
  doneBtn.disabled = nameInput.value.trim().length === 0;
}

// ---------------------------------------------------------------------------
// SAS emoji table — 256 entries, MUST match Android's SAS_EMOJI_TABLE exactly
// ---------------------------------------------------------------------------

/**
 * 256-emoji lookup table for Short Authentication String display.
 * Sourced from PairingViewModel.kt (spec section 4.4.2).
 * Each index maps to one emoji; 4 emoji are shown per pairing (8 bytes of
 * HKDF output, 2 bytes per emoji, big-endian uint16 mod 256).
 *
 * DO NOT modify this table without updating the Android companion app.
 *
 * @type {ReadonlyArray<string>}
 */
const SAS_EMOJI_TABLE = Object.freeze([
  "\u{1F600}", "\u{1F602}", "\u{1F60D}", "\u{1F923}", "\u{1F60A}", "\u{1F60E}", "\u{1F929}", "\u{1F634}",
  "\u{1F973}", "\u{1F608}", "\u{1F916}", "\u{1F47B}", "\u{1F480}", "\u{1F383}", "\u{1F648}", "\u{1F649}",
  "\u{1F64A}", "\u{1F436}", "\u{1F431}", "\u{1F42D}", "\u{1F439}", "\u{1F430}", "\u{1F98A}", "\u{1F43B}",
  "\u{1F43C}", "\u{1F428}", "\u{1F42F}", "\u{1F981}", "\u{1F42E}", "\u{1F437}", "\u{1F438}", "\u{1F435}",
  "\u{1F414}", "\u{1F427}", "\u{1F426}", "\u{1F424}", "\u{1F986}", "\u{1F985}", "\u{1F989}", "\u{1F987}",
  "\u{1F43A}", "\u{1F417}", "\u{1F434}", "\u{1F984}", "\u{1F41D}", "\u{1F41B}", "\u{1F98B}", "\u{1F40C}",
  "\u{1F41E}", "\u{1F41C}", "\u{1F99F}", "\u{1F997}", "\u{1F982}", "\u{1F422}", "\u{1F40D}", "\u{1F98E}",
  "\u{1F996}", "\u{1F995}", "\u{1F419}", "\u{1F991}", "\u{1F990}", "\u{1F99E}", "\u{1F980}", "\u{1F421}",
  "\u{1F420}", "\u{1F41F}", "\u{1F42C}", "\u{1F433}", "\u{1F40B}", "\u{1F988}", "\u{1F40A}", "\u{1F405}",
  "\u{1F406}", "\u{1F993}", "\u{1F98D}", "\u{1F9A7}", "\u{1F9A3}", "\u{1F418}", "\u{1F99B}", "\u{1F98F}",
  "\u{1F42A}", "\u{1F42B}", "\u{1F992}", "\u{1F998}", "\u{1F9AC}", "\u{1F403}", "\u{1F402}", "\u{1F404}",
  "\u{1F40E}", "\u{1F416}", "\u{1F40F}", "\u{1F411}", "\u{1F999}", "\u{1F410}", "\u{1F98C}", "\u{1F415}",
  "\u{1F429}", "\u{1F9AE}", "\u{1F408}", "\u{1F413}", "\u{1F983}", "\u{1F9A4}", "\u{1F99A}", "\u{1F99C}",
  "\u{1F9A2}", "\u{1F9A9}", "\u{1F54A}", "\u{1F407}", "\u{1F99D}", "\u{1F9A8}", "\u{1F9A1}", "\u{1F9AB}",
  "\u{1F9A6}", "\u{1F9A5}", "\u{1F401}", "\u{1F400}", "\u{1F43F}", "\u{1F994}", "\u{1F335}", "\u{1F332}",
  "\u{1F333}", "\u{1F334}", "\u{1F331}", "\u{1F33F}", "\u{2618}",  "\u{1F340}", "\u{1F38D}", "\u{1F38B}",
  "\u{1F343}", "\u{1F342}", "\u{1F341}", "\u{1F344}", "\u{1F33E}", "\u{1F490}", "\u{1F337}", "\u{1F339}",
  "\u{1F940}", "\u{1F33A}", "\u{1F338}", "\u{1F33C}", "\u{1F33B}", "\u{1F31E}", "\u{1F31D}", "\u{1F31B}",
  "\u{1F31C}", "\u{1F31A}", "\u{1F315}", "\u{1F316}", "\u{1F317}", "\u{1F318}", "\u{1F311}", "\u{1F312}",
  "\u{1F313}", "\u{1F314}", "\u{1F319}", "\u{1F31F}", "\u{2B50}",  "\u{1F320}", "\u{1F30C}", "\u{2601}",
  "\u{26C5}",  "\u{1F324}", "\u{1F308}", "\u{26A1}",  "\u{2744}",  "\u{1F525}", "\u{1F4A7}", "\u{1F30A}",
  "\u{1F34F}", "\u{1F34E}", "\u{1F350}", "\u{1F34A}", "\u{1F34B}", "\u{1F34C}", "\u{1F349}", "\u{1F347}",
  "\u{1F353}", "\u{1FAD0}", "\u{1F348}", "\u{1F352}", "\u{1F351}", "\u{1F96D}", "\u{1F34D}", "\u{1F965}",
  "\u{1F95D}", "\u{1F345}", "\u{1F346}", "\u{1F951}", "\u{1F966}", "\u{1F96C}", "\u{1F952}", "\u{1F336}",
  "\u{1FAD1}", "\u{1F9C4}", "\u{1F9C5}", "\u{1F954}", "\u{1F360}", "\u{1F950}", "\u{1F96F}", "\u{1F35E}",
  "\u{1F956}", "\u{1F968}", "\u{1F9C0}", "\u{1F95A}", "\u{1F373}", "\u{1F9C8}", "\u{1F95E}", "\u{1F9C7}",
  "\u{1F953}", "\u{1F969}", "\u{1F357}", "\u{1F356}", "\u{1F9B4}", "\u{1F32D}", "\u{1F354}", "\u{1F35F}",
  "\u{1F355}", "\u{1F32E}", "\u{1F32F}", "\u{1FAD4}", "\u{1F959}", "\u{1F9C6}", "\u{1F95A}", "\u{1F37F}",
  "\u{1F9C2}", "\u{1F96B}", "\u{1F371}", "\u{1F358}", "\u{1F359}", "\u{1F35A}", "\u{1F35B}", "\u{1F35C}",
  "\u{1F35D}", "\u{1F360}", "\u{1F362}", "\u{1F363}", "\u{1F364}", "\u{1F365}", "\u{1F96E}", "\u{1F361}",
  "\u{1F95F}", "\u{1F9AA}", "\u{1F366}", "\u{1F367}", "\u{1F368}", "\u{1F369}", "\u{1F36A}", "\u{1F382}",
  "\u{1F370}", "\u{1F9C1}", "\u{1F967}", "\u{1F36B}", "\u{1F36C}", "\u{1F36D}", "\u{1F36E}", "\u{1F36F}",
]);

// ---------------------------------------------------------------------------
// Relay connection for pairing ceremony (delegated to service worker)
// ---------------------------------------------------------------------------

/**
 * Tell the service worker to connect to the relay and listen for a pairing
 * request from the Android device.
 *
 * The WebSocket connection lives in the service worker so it survives the
 * popup closing when the user switches to their phone to scan the QR code.
 *
 * When the pairing request arrives:
 *   - If the popup is open: SW sends PAIRING_REQUEST_RECEIVED directly.
 *   - If the popup is closed: SW stores data in chrome.storage.session.
 *     When the popup reopens, it polls storage and picks it up.
 *
 * Once the raw pairing-request message is received (by either path), ECDH
 * and SAS derivation happen here in the popup using Web Crypto.
 *
 * @param {string} deviceId - Our device ID (displayed in QR, used as rendezvous).
 * @returns {Promise<{emojis: string[], peerId: string, peerKeys: {ed25519Pk: number[], x25519Pk: number[]}, sharedSecret: number[]}>}
 * @throws {Error} On timeout, auth failure, or crypto failure.
 */
export async function waitForPairingRequest(deviceId) {
  const stored = await chrome.storage.local.get(['deviceKeys']);

  if (!stored.deviceKeys) {
    throw new Error('Device keys not found in storage. Call startPairing() first.');
  }

  // Tell the service worker to open the relay WebSocket and authenticate.
  const result = await chrome.runtime.sendMessage({
    type: 'START_PAIRING_LISTENER',
    payload: {
      deviceId,
      ed25519Sk: stored.deviceKeys.ed25519.sk,
      ed25519Pk: stored.deviceKeys.ed25519.pk,
    },
  });

  if (!result?.ok) {
    throw new Error('SW relay failed: ' + (result?.error || 'no response'));
  }
  console.log('[Beam] SW relay listening for pairing');

  // Wait for the pairing request — two delivery paths:
  //   1. Direct message from SW (popup is open when request arrives).
  //   2. Poll chrome.storage.session (popup was closed and reopened).
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      chrome.runtime.onMessage.removeListener(listener);
      clearInterval(pollTimer);
      chrome.runtime.sendMessage({ type: 'STOP_PAIRING_LISTENER' });
      reject(new Error('Pairing request timeout (60s)'));
    }, 60_000);

    /**
     * Process the raw pairing-request message: ECDH + HKDF -> SAS emoji.
     * @param {object} msg - The pairing-request relay message.
     */
    const handlePairingRequest = async (msg) => {
      clearTimeout(timeout);
      try {
        const derivedResult = await deriveSasFromRequest(msg, stored.deviceKeys);
        resolve(derivedResult);
      } catch (err) {
        reject(err);
      }
    };

    // Path 1: Direct message from SW while popup is open.
    const listener = (msg) => {
      if (msg.type === 'PAIRING_REQUEST_RECEIVED') {
        chrome.runtime.onMessage.removeListener(listener);
        clearInterval(pollTimer);
        handlePairingRequest(msg.payload);
      }
    };
    chrome.runtime.onMessage.addListener(listener);

    // Path 2: Poll session storage (popup may have been closed and reopened).
    const pollTimer = setInterval(async () => {
      const s = await chrome.storage.session.get('pendingPairingRequest');
      if (s.pendingPairingRequest) {
        clearInterval(pollTimer);
        chrome.runtime.onMessage.removeListener(listener);
        // Clear to prevent double-processing.
        await chrome.storage.session.remove('pendingPairingRequest');
        handlePairingRequest(s.pendingPairingRequest);
      }
    }, 500);
  });
}

/**
 * Perform X25519 ECDH key exchange and derive the SAS emoji from a raw
 * pairing-request message.
 *
 * @param {object}  msg        - The relay pairing-request message (contains ed25519Pk, x25519Pk).
 * @param {object}  deviceKeys - Our device keys from chrome.storage.local.
 * @returns {Promise<{emojis: string[], peerId: string, peerKeys: {ed25519Pk: number[], x25519Pk: number[]}, sharedSecret: number[]}>}
 */
async function deriveSasFromRequest(msg, deviceKeys) {
  const peerId = msg.fromDeviceId || msg.deviceId;
  console.log('[Beam] Deriving SAS for PAIRING_REQUEST from', peerId);

  const peerX25519PkRaw = base64ToBytes(msg.x25519Pk);
  const peerEd25519PkRaw = base64ToBytes(msg.ed25519Pk);

  // X25519 ECDH: derive 256-bit shared secret
  const x25519PrivateKey = await crypto.subtle.importKey(
    'pkcs8',
    new Uint8Array(deviceKeys.x25519.sk).buffer,
    'X25519',
    false,
    ['deriveBits'],
  );
  const peerX25519Pk = await crypto.subtle.importKey(
    'raw',
    peerX25519PkRaw.buffer,
    'X25519',
    false,
    [],
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: peerX25519Pk },
    x25519PrivateKey,
    256,
  );
  const sharedSecret = new Uint8Array(sharedBits);

  // SAS derivation (spec section 4.4.2):
  //   salt = chrome_ed25519_pk (32B) || android_ed25519_pk (32B)
  // Android does: salt = payload.ed25519Pk + ourKeys.ed25519Pk
  //   where payload.ed25519Pk = chrome's pk (from QR), ourKeys = android's pk.
  // Chrome must use the same order: our_pk || peer_pk.
  const ourEd25519Pk = new Uint8Array(deviceKeys.ed25519.pk);
  const salt = new Uint8Array(ourEd25519Pk.length + peerEd25519PkRaw.length);
  salt.set(ourEd25519Pk);
  salt.set(peerEd25519PkRaw, ourEd25519Pk.length);

  // HKDF-SHA256(ikm=sharedSecret, salt=salt, info="zaptransfer-sas-v1", len=8)
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits'],
  );
  const sasBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: new TextEncoder().encode('zaptransfer-sas-v1'),
    },
    hkdfKey,
    64, // 8 bytes = 64 bits
  );
  const sasBytes = new Uint8Array(sasBits);

  // Map 8 SAS bytes to 4 emoji (2 bytes per emoji, big-endian uint16 mod 256)
  const emojis = sasToEmoji(sasBytes);

  return {
    emojis,
    peerId,
    peerKeys: {
      ed25519Pk: Array.from(peerEd25519PkRaw),
      x25519Pk: Array.from(peerX25519PkRaw),
    },
    sharedSecret: Array.from(sharedSecret),
  };
}

/**
 * Send PAIRING_ACK back to Android after the user confirms the SAS emoji match,
 * then save the paired device to chrome.storage.local.
 *
 * The ACK is sent through the service worker's relay WebSocket connection
 * (which may still be open from the startPairingListener call).
 *
 * @param {string} peerId - The Android device's ID.
 * @param {{ed25519Pk: number[], x25519Pk: number[]}} peerKeys - Android's public keys.
 * @param {string} deviceId - Our (Chrome) device ID.
 * @returns {Promise<void>}
 */
export async function confirmPairing(peerId, peerKeys, deviceId) {
  // Send acknowledgement to Android via the SW's relay WebSocket.
  const stored = await chrome.storage.local.get(['deviceKeys']);
  await chrome.runtime.sendMessage({
    type: 'SEND_PAIRING_MESSAGE',
    payload: {
      type:           'pairing-ack',
      targetDeviceId: peerId,
      rendezvousId:   deviceId,
      deviceId:       deviceId,
      ed25519Pk:      bytesToBase64(new Uint8Array(stored.deviceKeys.ed25519.pk)),
      x25519Pk:       bytesToBase64(new Uint8Array(stored.deviceKeys.x25519.pk)),
    },
  });

  // Save paired device to storage
  const existing = await chrome.storage.local.get(['pairedDevices']);
  const devices = existing.pairedDevices || [];
  devices.push({
    deviceId:        peerId,
    name:            'Android Device', // User will rename in the naming step
    icon:            'phone',
    ed25519PublicKey: peerKeys.ed25519Pk,
    x25519PublicKey:  peerKeys.x25519Pk,
    pairedAt:        Date.now(),
  });
  await chrome.storage.local.set({ pairedDevices: devices });

  // Tell SW to close the pairing relay connection.
  chrome.runtime.sendMessage({ type: 'STOP_PAIRING_LISTENER' });
}

/**
 * Cancel the pairing ceremony and tell the service worker to close
 * its relay WebSocket. Called when the user cancels pairing or navigates away.
 */
export function cancelPairingRelay() {
  chrome.runtime.sendMessage({ type: 'STOP_PAIRING_LISTENER' });
}

/**
 * Convert 8 raw SAS bytes to 4 emoji using the SAS_EMOJI_TABLE.
 *
 * Each pair of bytes is treated as a big-endian uint16, then taken modulo 256
 * to index into the 256-entry table. This matches the Android deriveSasEmoji().
 *
 * @param {Uint8Array} sasBytes - Exactly 8 bytes of HKDF-derived SAS material.
 * @returns {string[]} Array of 4 emoji strings.
 */
function sasToEmoji(sasBytes) {
  if (sasBytes.length !== 8) {
    throw new Error(`SAS bytes must be 8, got ${sasBytes.length}`);
  }

  const emojis = [];
  for (let i = 0; i < 4; i++) {
    const high = sasBytes[i * 2];
    const low = sasBytes[i * 2 + 1];
    const index = ((high << 8) | low) % 256;
    emojis.push(SAS_EMOJI_TABLE[index]);
  }
  return emojis;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Encode a byte array (Uint8Array or plain number[]) to a standard base64
 * string for embedding in the QR payload JSON.
 *
 * The spread-into-String.fromCharCode approach is safe here because the
 * longest input is a 32-byte public key, well within the call-stack limit.
 *
 * @param {Uint8Array | number[]} arr - Byte array to encode.
 * @returns {string} Base64-encoded string.
 */
function arrayToBase64(arr) {
  if (arr instanceof Uint8Array) {
    return btoa(String.fromCharCode(...arr));
  }
  return btoa(String.fromCharCode(...new Uint8Array(arr)));
}

/**
 * Decode a standard base64 string to a Uint8Array.
 *
 * @param {string} b64 - Base64-encoded string.
 * @returns {Uint8Array}
 */
function base64ToBytes(b64) {
  return new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
}

/**
 * Encode a Uint8Array to a standard base64 string.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
