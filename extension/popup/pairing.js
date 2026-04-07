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
  // Read keys from storage first
  const stored = await chrome.storage.local.get(['deviceId', 'deviceKeys']);

  let deviceId = stored.deviceId;
  let ed25519Pk = stored.deviceKeys?.ed25519?.pk;
  let x25519Pk = stored.deviceKeys?.x25519?.pk;

  // If keys exist and deviceId is valid, use them
  if (deviceId && deviceId.length >= 16 && ed25519Pk && x25519Pk) {
    console.log('[Beam] Using stored keys. deviceId:', deviceId);
    return { deviceId, ed25519Pk, x25519Pk, relayUrl: 'wss://zaptransfer-relay.fly.dev' };
  }

  // Keys missing — generate using Web Crypto API (instant, no WASM)
  console.log('[Beam] Generating fresh keys via Web Crypto...');

  try {
    // Generate Ed25519 keypair (Chrome 113+)
    const ed25519Key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const ed25519PkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ed25519Key.publicKey));
    const ed25519SkPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed25519Key.privateKey));

    // Generate X25519 keypair (Chrome 133+)
    const x25519Key = await crypto.subtle.generateKey('X25519', true, ['deriveBits']);
    const x25519PkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', x25519Key.publicKey));
    const x25519SkPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', x25519Key.privateKey));

    // Derive deviceId: base64url(SHA-256(ed25519Pk)[0:16])
    const hashBuffer = await crypto.subtle.digest('SHA-256', ed25519PkRaw);
    const idBytes = new Uint8Array(hashBuffer).slice(0, 16);
    deviceId = btoa(String.fromCharCode(...idBytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    ed25519Pk = Array.from(ed25519PkRaw);
    x25519Pk = Array.from(x25519PkRaw);

    // Persist keys to storage
    // Note: We store the raw public keys as arrays.
    // Private keys are stored in PKCS8 format for later import by libsodium in the offscreen doc.
    await chrome.storage.local.set({
      deviceId,
      deviceKeys: {
        x25519:  { pk: Array.from(x25519PkRaw),  sk: Array.from(x25519SkPkcs8) },
        ed25519: { pk: Array.from(ed25519PkRaw), sk: Array.from(ed25519SkPkcs8) },
      },
    });

    console.log('[Beam] Keys generated. deviceId:', deviceId, 'length:', deviceId.length);
    return { deviceId, ed25519Pk, x25519Pk, relayUrl: 'wss://zaptransfer-relay.fly.dev' };
  } catch (err) {
    console.error('[Beam] Web Crypto key generation failed:', err);
    // Ed25519/X25519 might not be supported — fall back to random bytes for QR display
    // (pairing won't fully work but at least the UI won't be broken)
    return _fallbackKeyGen();
  }
}

/** Last-resort fallback using getRandomValues — produces displayable QR but can't do real crypto */
async function _fallbackKeyGen() {
  console.warn('[Beam] Using random fallback keys (crypto not fully functional)');
  const ed25519Pk = crypto.getRandomValues(new Uint8Array(32));
  const x25519Pk = crypto.getRandomValues(new Uint8Array(32));
  const hashBuffer = await crypto.subtle.digest('SHA-256', ed25519Pk);
  const idBytes = new Uint8Array(hashBuffer).slice(0, 16);
  const deviceId = btoa(String.fromCharCode(...idBytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  await chrome.storage.local.set({
    deviceId,
    deviceKeys: {
      x25519:  { pk: Array.from(x25519Pk),  sk: Array.from(crypto.getRandomValues(new Uint8Array(32))) },
      ed25519: { pk: Array.from(ed25519Pk), sk: Array.from(crypto.getRandomValues(new Uint8Array(64))) },
    },
  });

  return { deviceId, ed25519Pk: Array.from(ed25519Pk), x25519Pk: Array.from(x25519Pk), relayUrl: 'wss://zaptransfer-relay.fly.dev' };
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
