/**
 * @file popup/popup.js
 * @description Main controller for the Beam extension popup.
 *
 * Responsibilities:
 *   - Boot: load devices, transfer history, and clipboard history from storage.
 *   - Device list: render online/offline indicators, select a target device.
 *   - File transfer: drag-and-drop, click-to-browse, clipboard, screenshot, tab URL.
 *   - Pairing flow: QR display, PIN countdown, SAS emoji confirmation, device naming.
 *   - Real-time updates: storage change listener + chrome.runtime.onMessage listener.
 *   - Active transfer progress bars.
 *   - Toast notifications for transient status messages.
 *
 * Security notes:
 *   - All user-supplied strings pass through escapeHtml() before being written
 *     to innerHTML.  The only exceptions are emoji characters from the emoji
 *     icon map which are hard-coded literals and therefore safe.
 *   - File names, device names, and clipboard content are all escaped.
 *
 * @module popup/popup
 */

import { MSG } from '../shared/message-types.js';
import {
  startPairing,
  renderQR,
  generatePIN,
  startPINCountdown,
  displaySAS,
  createNamingForm,
  waitForPairingRequest,
  confirmPairing,
  cancelPairingRelay,
} from './pairing.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

import * as beamIcon from './beam-icons.js';

/** Maps icon slug -> Lucide SVG (16px, inherits currentColor). */
const ICON_MAP = Object.freeze({
  laptop:  beamIcon.laptop(),
  desktop: beamIcon.monitor(),
  phone:   beamIcon.smartphone(),
  tablet:  beamIcon.tablet(),
});

/** Maximum number of active transfer cards shown simultaneously. */
const MAX_ACTIVE_SHOWN = 5;

/** Duration (ms) before a toast auto-dismisses. */
const TOAST_DURATION_MS = 3000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** @type {Array<{deviceId: string, name: string, icon: string, isOnline: boolean}>} */
let currentDevices = [];

/**
 * The device ID that will receive the next manual file / clipboard / screenshot
 * send.  Defaults to the first online device; updates on card click.
 * @type {string|null}
 */
let selectedDeviceId = null;

/**
 * Active in-progress transfers keyed by transferId.
 * @type {Map<string, {transferId: string, fileName: string, bytesTransferred: number, totalBytes: number}>}
 */
const activeTransfers = new Map();

/** Handle returned by setInterval for the PIN countdown. */
let pinTimerHandle = null;

/** Toast dismiss timeout handle. */
let toastHandle = null;

/**
 * Pending pairing result from the relay (emojis, peerId, peerKeys, sharedSecret).
 * Populated by waitForPairingRequest(), consumed by the SAS confirm handler.
 * @type {{emojis: string[], peerId: string, peerKeys: object, sharedSecret: number[]}|null}
 */
let pendingPairing = null;

/**
 * The deviceId used for the current pairing session.
 * Needed by confirmPairing() to send the ACK.
 * @type {string|null}
 */
let pairingDeviceId = null;

// ---------------------------------------------------------------------------
// DOM references (resolved after DOMContentLoaded)
// ---------------------------------------------------------------------------

/**
 * Lazily resolved DOM elements.  All getters throw a descriptive error if the
 * element is missing so misconfigured HTML surfaces immediately during dev.
 *
 * @param {string} id
 * @returns {HTMLElement}
 */
function el(id) {
  const node = document.getElementById(id);
  if (!node) throw new Error(`[Beam popup] Missing element #${id}`);
  return node;
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  await loadDevices();
  await loadTransferHistory();
  await loadClipboardHistory();
  await loadReceivedFile();
  await consumeAutoCopyPending();
  setupEventListeners();
  listenForStorageChanges();
  startKeepalive();
});

/**
 * Check for and consume any pending auto-copy clipboard content.
 *
 * When the service worker receives clipboard content with auto-copy ON,
 * it cannot write to the clipboard from the SW context. Instead it sets
 * an autoCopyPending key in session storage. When the popup opens, we
 * consume it and write to the clipboard.
 *
 * @returns {Promise<void>}
 */
async function consumeAutoCopyPending() {
  try {
    const stored = await chrome.storage.session.get('autoCopyPending');
    if (stored?.autoCopyPending) {
      await navigator.clipboard.writeText(stored.autoCopyPending);
      await chrome.storage.session.remove('autoCopyPending');
    }
  } catch {
    // Clipboard write may fail if popup is not focused; ignore silently.
  }
}

// ---------------------------------------------------------------------------
// Storage loaders
// ---------------------------------------------------------------------------

/**
 * Load paired devices from persistent storage and current online presence from
 * session storage, then render the device list.
 *
 * Storage schema:
 *   chrome.storage.local  → pairedDevices: [{deviceId, name, icon}, ...]
 *   chrome.storage.session → devicePresence: {[deviceId]: {isOnline: boolean}}
 *
 * @returns {Promise<void>}
 */
async function loadDevices() {
  const [localData, sessionData] = await Promise.all([
    chrome.storage.local.get('pairedDevices'),
    chrome.storage.session.get('devicePresence').catch(() => ({})),
  ]);

  // Presence defaults to OFFLINE until the relay confirms a peer-online
  // message for each device. The relay broadcasts peer-online for any
  // already-registered peers when we join, so initial state populates
  // quickly after the signalling client connects.
  const presence = sessionData?.devicePresence || {};
  currentDevices = (localData?.pairedDevices ?? []).map(d => ({
    ...d,
    isOnline: presence[d.deviceId]?.isOnline === true,
  }));

  renderDevices();
}

/**
 * Load completed/failed transfer records from session storage and render them
 * in the Recent section.
 *
 * Schema: chrome.storage.session → transferHistory: [{transferId, fileName,
 *   fileSize, direction, status, timestamp, targetDeviceName?}]
 *
 * @returns {Promise<void>}
 */
async function loadTransferHistory() {
  const stored = await chrome.storage.session.get('transferHistory').catch(() => ({}));
  renderTransferHistory(stored?.transferHistory ?? []);
}

/**
 * Load clipboard history entries from session storage.
 *
 * Schema: chrome.storage.session → clipboardHistory: [{id, content, timestamp}]
 *
 * @returns {Promise<void>}
 */
async function loadClipboardHistory() {
  // Load from both keys — 'receivedClipboard' (from background-relay.js) and legacy 'clipboardHistory'
  const stored = await chrome.storage.session.get(['receivedClipboard', 'clipboardHistory']).catch(() => ({}));
  const items = stored?.receivedClipboard ?? stored?.clipboardHistory ?? [];
  renderClipboardHistory(items);
}

/**
 * Load the most recently received file from session storage and render a
 * download banner in the popup if one exists.
 *
 * Schema: chrome.storage.session -> receivedFile: {fileName, fileSize, mimeType,
 *   fromDeviceId, data (base64), timestamp}
 *
 * @returns {Promise<void>}
 */
async function loadReceivedFile() {
  const stored = await chrome.storage.session.get('receivedFile').catch(() => ({}));
  renderReceivedFile(stored?.receivedFile ?? null);
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/**
 * Re-render the device list (or show the empty state when no devices exist).
 * Preserves the currently selected device across re-renders.
 */
function renderDevices() {
  const list  = el('device-list');
  const empty = el('empty-state');
  const dz    = el('drop-zone');

  if (currentDevices.length === 0) {
    list.classList.add('hidden');
    empty.classList.remove('hidden');
    dz.classList.add('disabled');
    setQuickActionsDisabled(true);
    return;
  }

  empty.classList.add('hidden');
  list.classList.remove('hidden');

  // Re-select the first online device if current selection went offline or is unset.
  if (!selectedDeviceId || !currentDevices.find(d => d.deviceId === selectedDeviceId && d.isOnline)) {
    const firstOnline = currentDevices.find(d => d.isOnline);
    selectedDeviceId = firstOnline?.deviceId ?? null;
  }

  const hasOnline = currentDevices.some(d => d.isOnline);
  dz.classList.toggle('disabled', !hasOnline);
  setQuickActionsDisabled(!hasOnline);

  list.innerHTML = currentDevices
    .map(d => deviceCardHTML(d))
    .join('');

  // Mark the currently selected card.
  if (selectedDeviceId) {
    list.querySelector(`[data-id="${CSS.escape(selectedDeviceId)}"]`)
        ?.classList.add('selected');
  }

  // Attach click handlers via event delegation on the list container.
  list.onclick = handleDeviceListClick;
}

/**
 * Build the inner HTML for a single device card.
 * All user-provided text is escaped.
 *
 * @param {{deviceId: string, name: string, icon: string, isOnline: boolean}} d
 * @returns {string}
 */
function deviceCardHTML(d) {
  const icon       = ICON_MAP[d.icon] ?? '💻';
  const statusClass = d.isOnline ? 'online' : 'offline';
  const statusDot  = d.isOnline ? 'green' : 'gray';
  const statusText = d.isOnline ? 'Online' : 'Offline';
  const sendBtn    = d.isOnline
    ? `<div class="device-actions">
         <button class="send-file-btn" data-id="${escapeAttr(d.deviceId)}"
                 aria-label="Send file to ${escapeAttr(d.name)}">Send</button>
       </div>`
    : '';

  return `
    <div class="device-card ${statusClass}" data-id="${escapeAttr(d.deviceId)}"
         role="button" tabindex="0" aria-label="${escapeAttr(d.name)}, ${statusText}">
      <div class="device-icon" aria-hidden="true">${icon}</div>
      <div class="device-info">
        <div class="device-name">${escapeHtml(d.name)}</div>
        <div class="device-status">
          <span class="status-dot ${statusDot}"></span>
          ${statusText}
        </div>
      </div>
      ${sendBtn}
    </div>
  `;
}

/**
 * Re-render the active transfer progress bars.
 * Called whenever activeTransfers map changes.
 */
function renderActiveTransfers() {
  const section = el('active-transfers');
  if (activeTransfers.size === 0) {
    section.innerHTML = '';
    return;
  }

  const items = [...activeTransfers.values()].slice(0, MAX_ACTIVE_SHOWN);
  section.innerHTML = items.map(t => {
    const pct  = t.totalBytes > 0
      ? Math.round((t.bytesTransferred / t.totalBytes) * 100)
      : 0;
    const speed = t.speedBps ? ` — ${formatBytes(t.speedBps)}/s` : '';
    return `
      <div class="transfer-card" data-transfer="${escapeAttr(t.transferId)}">
        <div class="transfer-card-header">
          <span class="transfer-filename">${escapeHtml(t.fileName)}</span>
          <span class="transfer-meta">${pct}%${speed}</span>
        </div>
        <div class="progress-bar-wrap">
          <div class="progress-bar" style="width:${pct}%"></div>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Render the recent transfer history list.
 *
 * @param {Array<{transferId: string, fileName: string, fileSize: number,
 *   direction: string, status: string, timestamp: number, targetDeviceName?: string}>} history
 */
function renderTransferHistory(history) {
  const list    = el('transfer-list');
  const section = el('recent-transfers');

  if (!history.length) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  list.innerHTML = history.map(item => {
    const icon       = item.direction === 'in' ? beamIcon.arrow_down() : beamIcon.arrow_up();
    const statusCls  = item.status === 'complete' ? 'ok' : 'fail';
    const statusText = item.status === 'complete' ? '✓' : '✗';
    const meta       = [
      formatBytes(item.fileSize),
      item.targetDeviceName ? escapeHtml(item.targetDeviceName) : null,
      formatRelativeTime(item.timestamp),
    ].filter(Boolean).join(' · ');

    return `
      <div class="history-item">
        <div class="history-item-icon" aria-hidden="true">${icon}</div>
        <div class="history-item-body">
          <div class="history-item-name">${escapeHtml(item.fileName)}</div>
          <div class="history-item-meta">${meta}</div>
        </div>
        <span class="history-item-status ${statusCls}" aria-label="${item.status}">${statusText}</span>
      </div>
    `;
  }).join('');
}

/**
 * Render the clipboard history list with per-item "Resend" copy buttons.
 *
 * @param {Array<{id: string, content: string, timestamp: number}>} history
 */
function renderClipboardHistory(history) {
  const list    = el('clipboard-list');
  const section = el('clipboard-section');
  const count   = el('clipboard-count');

  if (!history.length) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  count.textContent = String(history.length);

  list.innerHTML = history.map(item => {
    const preview = escapeHtml(item.content.slice(0, 80)) +
                    (item.content.length > 80 ? '…' : '');
    const from = item.fromDeviceId ? `From device` : '';
    const time = formatRelativeTime(item.timestamp);
    return `
      <div class="history-item">
        <div class="history-item-icon" aria-hidden="true">${beamIcon.clipboard()}</div>
        <div class="history-item-body">
          <div class="history-item-name">${preview}</div>
          <div class="history-item-meta">${from} ${time}</div>
        </div>
        <button class="copy-clip-btn"
                data-content="${escapeAttr(item.content)}"
                aria-label="Copy to clipboard"
                style="padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text-primary);cursor:pointer;font-size:12px;">Copy</button>
      </div>
    `;
  }).join('');

  // Delegate resend clicks.
  list.onclick = handleClipboardResend;
}

/**
 * Render or hide the received-file download banner.
 *
 * When a file has been received, shows the file name, size, and a Download
 * button. Clicking Download creates a blob URL and triggers a browser download.
 * A Dismiss button removes the banner and clears session storage.
 *
 * @param {{fileName: string, fileSize: number, mimeType: string, data: string, timestamp: number}|null} file
 */
function renderReceivedFile(file) {
  const section = document.getElementById('received-file-section');
  if (!section) return;

  if (!file) {
    section.classList.add('hidden');
    section.innerHTML = '';
    return;
  }

  section.classList.remove('hidden');
  section.innerHTML = `
    <h4 class="section-title">Received File</h4>
    <div class="history-item" style="align-items:center">
      <div class="history-item-icon" aria-hidden="true">${beamIcon.pkg()}</div>
      <div class="history-item-body">
        <div class="history-item-name">${escapeHtml(file.fileName)}</div>
        <div class="history-item-meta">${formatBytes(file.fileSize)} &middot; ${formatRelativeTime(file.timestamp)}</div>
      </div>
      <button id="btn-download-file"
              style="padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:var(--primary);color:#fff;cursor:pointer;font-size:12px;margin-right:4px;">Download</button>
      <button id="btn-dismiss-file"
              style="padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text-primary);cursor:pointer;font-size:12px;">Dismiss</button>
    </div>
  `;

  // Download handler: decode base64, create blob URL, trigger download.
  document.getElementById('btn-download-file')?.addEventListener('click', () => {
    try {
      const binaryStr = atob(file.data);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: file.mimeType });
      const url  = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href     = url;
      a.download = file.fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast('Download started!', 'success');
    } catch (err) {
      showToast('Download failed: ' + err.message, 'error');
    }
  });

  // Dismiss handler: clear the received file from session storage.
  document.getElementById('btn-dismiss-file')?.addEventListener('click', async () => {
    await chrome.storage.session.remove('receivedFile');
    section.classList.add('hidden');
    section.innerHTML = '';
  });
}

// ---------------------------------------------------------------------------
// View navigation
// ---------------------------------------------------------------------------

/**
 * Switch to a named view, hiding all others.
 * Valid names: 'main' | 'pairing' | 'sas' | 'naming'
 *
 * @param {'main'|'pairing'|'sas'|'naming'} name
 */
function showView(name) {
  const ids = ['view-main', 'view-pairing', 'view-sas', 'view-naming', 'view-settings'];
  ids.forEach(id => document.getElementById(id)?.classList.add('hidden'));
  document.getElementById(`view-${name}`)?.classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Pairing flow
// ---------------------------------------------------------------------------

/**
 * Initiate the pairing ceremony: generate keys via Web Crypto, render the QR
 * code, show the PIN with countdown, then connect to the relay and wait for
 * the Android device's PAIRING_REQUEST.
 *
 * The entire pairing flow now runs in the popup (no offscreen dependency):
 *   1. startPairing() generates Ed25519/X25519 keys and stores them.
 *   2. QR is rendered so the Android app can scan it.
 *   3. waitForPairingRequest() connects to the relay, authenticates, registers
 *      the deviceId as rendezvous, and waits for the Android's pairing-request.
 *   4. On receipt: X25519 ECDH + HKDF derives SAS emoji for verification.
 *   5. User confirms SAS match -> confirmPairing() sends ACK and saves device.
 */
async function showPairingView() {
  // Clear any previous PIN timer and pending pairing state.
  if (pinTimerHandle) {
    clearInterval(pinTimerHandle);
    pinTimerHandle = null;
  }
  pendingPairing = null;
  pairingDeviceId = null;

  // Clear stale pairing data from previous failed attempts.
  await chrome.storage.session.remove('pendingPairingRequest').catch(() => {});
  // Stop any existing SW relay listener from a previous attempt.
  chrome.runtime.sendMessage({ type: 'STOP_PAIRING_LISTENER' }).catch(() => {});

  showView('pairing');

  // Reset QR container to placeholder state while waiting for data.
  const qrContainer = el('qr-container');
  qrContainer.innerHTML = `
    <div id="qr-placeholder" class="qr-placeholder">
      <div class="qr-spinner"></div>
      <span>Generating&hellip;</span>
    </div>
  `;

  let qrData;
  try {
    qrData = await startPairing();
    console.log('[Beam popup] startPairing returned:', JSON.stringify(qrData));
  } catch (err) {
    console.error('[Beam popup] startPairing failed:', err);
    showToast('Could not start pairing. Is the extension background running?', 'error');
    showView('main');
    return;
  }

  if (!qrData) {
    console.error('[Beam popup] qrData is null/undefined — key generation failed');
    showToast('Pairing service unavailable. Try again in a moment.', 'error');
    showView('main');
    return;
  }

  console.log('[Beam popup] deviceId:', qrData.deviceId, 'length:', qrData.deviceId?.length);
  pairingDeviceId = qrData.deviceId;

  // Render QR code into the container element.
  qrContainer.innerHTML = ''; // clear placeholder
  renderQR(qrContainer, qrData);

  // Generate and display PIN.
  const pin       = generatePIN();
  const pinEl     = el('pin-code');
  const timerEl   = el('pin-timer');

  // Format PIN as XXXX XXXX for readability.
  pinEl.textContent  = pin.slice(0, 4) + ' ' + pin.slice(4);
  timerEl.textContent = '60s';

  pinTimerHandle = startPINCountdown(timerEl, 60, () => {
    // PIN expired — grey out and prompt refresh.
    pinEl.textContent   = '—— ——';
    timerEl.textContent = 'Expired';
    showToast('PIN expired. Click Pair to generate a new code.');
  });

  // ── Connect to relay and wait for Android's PAIRING_REQUEST ──────────────
  // This runs concurrently with the PIN countdown. When Android scans the QR
  // and sends its pairing-request via the relay, we derive the SAS emoji and
  // transition to the verification view.
  try {
    const result = await waitForPairingRequest(qrData.deviceId);
    pendingPairing = result;

    // Clear the PIN timer — we no longer need it.
    if (pinTimerHandle) {
      clearInterval(pinTimerHandle);
      pinTimerHandle = null;
    }

    // Show SAS verification view with derived emoji
    displaySAS(el('sas-emojis'), result.emojis);
    showView('sas');
  } catch (err) {
    console.error('[Beam popup] waitForPairingRequest failed:', err);
    // Clean up stale pairing state.
    await chrome.storage.session.remove('pendingPairingRequest').catch(() => {});
    chrome.runtime.sendMessage({ type: 'STOP_PAIRING_LISTENER' }).catch(() => {});
    // Only show error if we are still on the pairing view (user may have cancelled)
    if (!document.getElementById('view-pairing')?.classList.contains('hidden')) {
      showToast('Pairing timed out. Try again.', 'error');
      showView('main');
    }
  }
}

/**
 * The user confirmed the SAS emoji match.
 *
 * Sends PAIRING_ACK to Android via the relay, saves the paired device to
 * storage, then transitions to the device naming view.
 */
async function confirmSAS() {
  if (!pendingPairing || !pairingDeviceId) {
    console.error('[Beam popup] confirmSAS called without pending pairing data');
    showToast('Pairing state lost. Please try again.', 'error');
    showView('main');
    return;
  }

  try {
    await confirmPairing(
      pendingPairing.peerId,
      pendingPairing.peerKeys,
      pairingDeviceId,
    );
  } catch (err) {
    console.error('[Beam popup] confirmPairing failed:', err);
    showToast('Could not complete pairing: ' + err.message, 'error');
    showView('main');
    pendingPairing = null;
    pairingDeviceId = null;
    return;
  }

  // Clear PIN timer if still running.
  if (pinTimerHandle) {
    clearInterval(pinTimerHandle);
    pinTimerHandle = null;
  }

  // Show the device naming view.
  showView('naming');
  const suggestedName = 'Android Device';
  createNamingForm(el('naming-container'), suggestedName, async ({ name, icon }) => {
    // Update the paired device entry with the user-chosen name and icon.
    try {
      const stored = await chrome.storage.local.get(['pairedDevices']);
      const devices = stored.pairedDevices || [];
      const entry = devices.find(d => d.deviceId === pendingPairing.peerId);
      if (entry) {
        entry.name = name;
        entry.icon = icon;
        await chrome.storage.local.set({ pairedDevices: devices });
      }
    } catch (err) {
      console.error('[Beam popup] Failed to update device name:', err);
    }

    pendingPairing = null;
    pairingDeviceId = null;

    await loadDevices();
    showView('main');
    showToast(`"${escapeHtml(name)}" paired successfully!`, 'success');
  });
}

/**
 * The user clicked Cancel on the SAS view — abort the pairing ceremony.
 * Disconnects the relay and clears pending state.
 */
function cancelSAS() {
  cancelPairingRelay();
  pendingPairing = null;
  pairingDeviceId = null;
  showView('main');
  showToast('Pairing cancelled.');
}

// ---------------------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------------------

/** Wire up all static event listeners after DOM is ready. */
function setupEventListeners() {
  // Header: Pair button
  document.getElementById('btn-pair')?.addEventListener('click', showPairingView);

  // Empty state: Pair first device button
  document.getElementById('btn-pair-first')?.addEventListener('click', showPairingView);

  // Header: Settings — open settings view
  document.getElementById('btn-settings')?.addEventListener('click', showSettingsView);

  // Settings view: Back button
  document.getElementById('settings-back')?.addEventListener('click', () => {
    showView('main');
  });

  // Settings view: auto-save checkboxes on change
  document.getElementById('setting-auto-copy')?.addEventListener('change', saveSettings);
  document.getElementById('setting-auto-save')?.addEventListener('change', saveSettings);

  // Settings view: device name on blur
  document.getElementById('setting-device-name')?.addEventListener('blur', saveSettings);

  // Pairing view: Cancel — disconnect relay and return to main.
  document.getElementById('btn-pairing-cancel')?.addEventListener('click', () => {
    if (pinTimerHandle) { clearInterval(pinTimerHandle); pinTimerHandle = null; }
    cancelPairingRelay();
    pendingPairing = null;
    pairingDeviceId = null;
    showView('main');
  });

  // SAS view buttons
  document.getElementById('sas-confirm')?.addEventListener('click', confirmSAS);
  document.getElementById('sas-cancel')?.addEventListener('click', cancelSAS);

  // Drop zone
  const dropZone  = el('drop-zone');
  const fileInput = el('file-input');

  dropZone.addEventListener('click', () => {
    if (!selectedDeviceId) { showToast('Select a device first.', 'error'); return; }
    fileInput.click();
  });

  dropZone.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      dropZone.click();
    }
  });

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', handleFileDrop);
  fileInput.addEventListener('change', handleFileSelect);

  // Quick actions
  document.getElementById('btn-clipboard')?.addEventListener('click', sendClipboard);
  document.getElementById('btn-screenshot')?.addEventListener('click', sendScreenshot);
  document.getElementById('btn-tab-url')?.addEventListener('click', sendTabUrl);

  // Runtime messages (pairing events, transfer progress, presence changes)
  chrome.runtime.onMessage.addListener(handleMessage);
}

// ---------------------------------------------------------------------------
// Storage change listener
// ---------------------------------------------------------------------------

/**
 * Listen for chrome.storage changes so the device list and history sections
 * stay in sync when the background SW mutates storage while the popup is open.
 */
function listenForStorageChanges() {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.pairedDevices) {
      loadDevices();
    }
    if (area === 'session') {
      if (changes.devicePresence)    loadDevices();
      if (changes.transferHistory)   loadTransferHistory();
      if (changes.clipboardHistory || changes.receivedClipboard) loadClipboardHistory();
      if (changes.receivedFile) loadReceivedFile();
    }
  });
}

// ---------------------------------------------------------------------------
// SW keepalive
// ---------------------------------------------------------------------------

/**
 * Send a periodic keepalive ping to the service worker while the popup is open
 * so Chrome does not suspend it mid-transfer.
 * Frequency: every 20 s (well under Chrome's 30 s idle threshold).
 */
function startKeepalive() {
  setInterval(() => {
    chrome.runtime.sendMessage({ type: MSG.KEEPALIVE_PING }).catch(() => {
      // SW may be temporarily suspended; ignore the error — the next ping will
      // wake it via chrome.alarms.
    });
  }, 20_000);
}

// ---------------------------------------------------------------------------
// Runtime message handler
// ---------------------------------------------------------------------------

/**
 * Handle inbound messages from the service worker / offscreen document.
 *
 * @param {{type: string, payload?: object}} msg
 */
function handleMessage(msg) {
  switch (msg.type) {

    // ── Pairing ──────────────────────────────────────────────────────────────
    case MSG.PAIRING_QR_DATA:
      // Background is forwarding QR data; render it now.
      if (msg.payload?.qrData) {
        const qrContainer = document.getElementById('qr-container');
        if (qrContainer) renderQR(qrContainer, msg.payload.qrData);
      }
      break;

    case MSG.PAIRING_SAS: {
      // SAS emojis arrived — switch to SAS verification view.
      showView('sas');
      // The offscreen sends { emojis, peerId } while the legacy path
      // may use { sas }.  Handle both shapes.
      const rawEmojis = msg.payload?.emojis ?? msg.payload?.sas;
      if (rawEmojis) {
        const emojis = Array.isArray(rawEmojis)
          ? rawEmojis
          : rawEmojis.split(/\s+/);
        displaySAS(el('sas-emojis'), emojis);
      }
      break;
    }

    case MSG.PAIRING_COMPLETE: {
      // Pairing done — clear PIN timer, show naming form.
      if (pinTimerHandle) { clearInterval(pinTimerHandle); pinTimerHandle = null; }
      showView('naming');

      const suggested = msg.payload?.name ?? 'My Device';
      createNamingForm(el('naming-container'), suggested, async ({ name, icon }) => {
        try {
          await chrome.runtime.sendMessage({
            type:    MSG.PAIRING_SET_DEVICE_NAME,
            payload: { name, icon },
          });
        } catch (err) {
          console.error('[Beam popup] PAIRING_SET_DEVICE_NAME failed:', err);
        }
        await loadDevices();
        showView('main');
        showToast(`"${escapeHtml(name)}" paired successfully!`, 'success');
      });
      break;
    }

    // ── Transfer progress ────────────────────────────────────────────────────
    case MSG.TRANSFER_PROGRESS: {
      const { transferId, fileName, bytesTransferred, totalBytes, speedBps } = msg.payload ?? {};
      if (transferId) {
        activeTransfers.set(transferId, { transferId, fileName, bytesTransferred, totalBytes, speedBps });
        renderActiveTransfers();
      }
      break;
    }

    case MSG.TRANSFER_COMPLETE: {
      const { transferId, fileName } = msg.payload ?? {};
      if (transferId) activeTransfers.delete(transferId);
      renderActiveTransfers();
      showToast(`Sent "${escapeHtml(fileName ?? 'file')}" successfully.`, 'success');
      // Reload history so the new record appears.
      loadTransferHistory();
      break;
    }

    case MSG.TRANSFER_FAILED: {
      const { transferId, reason } = msg.payload ?? {};
      if (transferId) activeTransfers.delete(transferId);
      renderActiveTransfers();
      showToast(`Transfer failed: ${escapeHtml(reason ?? 'unknown error')}`, 'error');
      loadTransferHistory();
      break;
    }

    // ── Incoming transfer request ────────────────────────────────────────────
    case MSG.INCOMING_TRANSFER: {
      const { fromDeviceName, fileName, fileSize } = msg.payload ?? {};
      showToast(
        `Receiving "${escapeHtml(fileName ?? 'file')}" (${formatBytes(fileSize)}) from ${escapeHtml(fromDeviceName ?? 'device')}…`
      );
      break;
    }

    // ── Auto-copy clipboard from SW ────────────────────────────────────────
    case 'AUTO_COPY_CLIPBOARD': {
      const autoCopyContent = msg.payload?.content;
      if (autoCopyContent) {
        navigator.clipboard.writeText(autoCopyContent).then(() => {
          chrome.storage.session.remove('autoCopyPending');
        }).catch(() => {
          // Will be consumed next time popup opens via consumeAutoCopyPending.
        });
      }
      break;
    }

    // ── Presence ─────────────────────────────────────────────────────────────
    case MSG.DEVICE_PRESENCE_CHANGED:
      // Merge single-device presence update without a full storage reload.
      if (msg.payload?.deviceId) {
        const { deviceId, online } = msg.payload;
        currentDevices = currentDevices.map(d =>
          d.deviceId === deviceId ? { ...d, isOnline: !!online } : d
        );
        renderDevices();
      }
      break;
  }
}

// ---------------------------------------------------------------------------
// File transfers
// ---------------------------------------------------------------------------

/**
 * Handle a drop event on the drop zone.
 *
 * @param {DragEvent} e
 */
async function handleFileDrop(e) {
  e.preventDefault();
  el('drop-zone').classList.remove('drag-over');

  if (!selectedDeviceId) {
    showToast('Select an online device first.', 'error');
    return;
  }

  const files = Array.from(e.dataTransfer?.files ?? []);
  if (!files.length) return;

  for (const file of files) {
    await sendFile(file);
  }
}

/**
 * Handle a file selection from the hidden <input type="file">.
 *
 * @param {Event} e
 */
async function handleFileSelect(e) {
  if (!selectedDeviceId) {
    showToast('Select an online device first.', 'error');
    return;
  }

  const files = Array.from(e.target.files ?? []);
  // Reset so the same file can be re-selected next time.
  e.target.value = '';

  for (const file of files) {
    await sendFile(file);
  }
}

/**
 * Read a File object, encode as base64, and send via the relay binary channel.
 *
 * The file data is sent as a base64 string to the service worker because
 * ArrayBuffer is not serialisable across chrome.runtime.sendMessage.
 * The SW decodes it and streams binary chunks through the relay WebSocket.
 *
 * @param {File} file
 * @returns {Promise<void>}
 */
async function sendFile(file) {
  if (!selectedDeviceId) return;

  const targetId = selectedDeviceId;

  // Look up the paired device to get the rendezvousId for relay routing.
  const stored = await chrome.storage.local.get(['pairedDevices', 'deviceId']);
  const pairedDevice = (stored.pairedDevices || []).find(d => d.deviceId === targetId);
  const rendezvousId = pairedDevice?.rendezvousId || stored.deviceId;

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch (err) {
    showToast(`Could not read "${escapeHtml(file.name)}": ${err.message}`, 'error');
    return;
  }

  // Convert to base64 for serialisation across the message channel.
  // Process in 32KB slices to avoid call-stack overflow on large files.
  const bytes = new Uint8Array(buffer);
  let base64 = '';
  const SLICE = 32768;
  for (let i = 0; i < bytes.length; i += SLICE) {
    base64 += String.fromCharCode.apply(null, bytes.subarray(i, i + SLICE));
  }
  base64 = btoa(base64);

  chrome.runtime.sendMessage({
    type: 'SEND_FILE',
    payload: {
      fileName:       file.name,
      fileSize:       file.size,
      mimeType:       file.type || 'application/octet-stream',
      data:           base64,
      targetDeviceId: targetId,
      rendezvousId,
    },
  }).then(resp => {
    if (resp?.ok) {
      showToast('Sending ' + escapeHtml(file.name) + '...', 'success');
    } else {
      showToast('Send failed: relay not connected.', 'error');
    }
  }).catch(err => {
    showToast(`Could not send file: ${err.message}`, 'error');
  });
}

/**
 * Read the system clipboard and send its text content to the selected device.
 * Requires the clipboard-read permission (granted via activeTab in MV3).
 *
 * @returns {Promise<void>}
 */
async function sendClipboard() {
  const targetId = selectedDeviceId || currentDevices[0]?.deviceId;
  if (!targetId) {
    showToast('No paired device.', 'error');
    return;
  }
  selectedDeviceId = targetId;

  let text;
  try {
    text = await navigator.clipboard.readText();
  } catch {
    showToast('Clipboard access denied. Check browser permissions.', 'error');
    return;
  }

  if (!text.trim()) {
    showToast('Clipboard is empty.');
    return;
  }

  // Look up the paired device to get its rendezvousId (Chrome's deviceId)
  // for relay routing.
  const stored = await chrome.storage.local.get(['pairedDevices', 'deviceId']);
  const pairedDevice = (stored.pairedDevices || []).find(d => d.deviceId === selectedDeviceId);
  const rendezvousId = pairedDevice?.rendezvousId || stored.deviceId;

  // Send via the SW's relay WebSocket (clipboard-transfer wire message).
  chrome.runtime.sendMessage({
    type: 'SEND_CLIPBOARD',
    payload: {
      content:        text,
      targetDeviceId: selectedDeviceId,
      rendezvousId,
    },
  }).then(resp => {
    if (resp?.ok) {
      showToast('Clipboard sent!', 'success');
    } else {
      showToast('Send failed: relay not connected.', 'error');
    }
  }).catch(err => showToast(`Send failed: ${err.message}`, 'error'));
}

/**
 * Capture the visible area of the active tab and send it to the selected device.
 *
 * chrome.tabs.captureVisibleTab requires the activeTab permission and must be
 * called from a user gesture in the popup context.
 *
 * @returns {Promise<void>}
 */
async function sendScreenshot() {
  if (!selectedDeviceId) {
    showToast('Select an online device first.', 'error');
    return;
  }

  let dataUrl;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
  } catch (err) {
    showToast(`Screenshot failed: ${err.message}`, 'error');
    return;
  }

  // Convert data URL to byte array for the offscreen document.
  const base64    = dataUrl.split(',')[1];
  const binaryStr = atob(base64);
  const bytes     = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);

  const now = new Date();
  const fileName = `screenshot-${now.toISOString().slice(0, 19).replace(/:/g, '-')}.png`;

  chrome.runtime.sendMessage({
    type:    MSG.INITIATE_TRANSFER,
    payload: {
      type:           'file',
      targetDeviceId: selectedDeviceId,
      data:           Array.from(bytes),
      fileName,
      mimeType:       'image/png',
      fileSize:       bytes.length,
    },
  }).catch(err => showToast(`Send failed: ${err.message}`, 'error'));

  showToast('Screenshot sent!', 'success');
}

/**
 * Read the URL of the currently active tab and send it as a clipboard/link
 * transfer to the selected device.
 *
 * @returns {Promise<void>}
 */
async function sendTabUrl() {
  if (!selectedDeviceId) {
    showToast('Select an online device first.', 'error');
    return;
  }

  let url;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    url = tab?.url;
  } catch (err) {
    showToast(`Could not read tab URL: ${err.message}`, 'error');
    return;
  }

  if (!url || url.startsWith('chrome://')) {
    showToast('Cannot send this URL (restricted page).', 'error');
    return;
  }

  chrome.runtime.sendMessage({
    type:    MSG.INITIATE_TRANSFER,
    payload: {
      type:           'clipboard',
      targetDeviceId: selectedDeviceId,
      content:        url,
    },
  }).catch(err => showToast(`Send failed: ${err.message}`, 'error'));

  showToast('Tab URL sent!', 'success');
}

// ---------------------------------------------------------------------------
// Click delegation handlers
// ---------------------------------------------------------------------------

/**
 * Handle clicks in the device list:
 *   - Clicking a .device-card selects it as the transfer target.
 *   - Clicking a .send-file-btn triggers the file picker immediately.
 *
 * @param {MouseEvent} e
 */
function handleDeviceListClick(e) {
  // Send button
  const sendBtn = e.target.closest('.send-file-btn');
  if (sendBtn) {
    e.stopPropagation();
    selectedDeviceId = sendBtn.dataset.id;
    el('file-input').click();
    return;
  }

  // Card selection
  const card = e.target.closest('.device-card');
  if (!card || card.classList.contains('offline')) return;

  // Update selection
  el('device-list')
    .querySelectorAll('.device-card')
    .forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  selectedDeviceId = card.dataset.id;
}

/**
 * Handle clicks on clipboard "Resend" buttons.
 *
 * @param {MouseEvent} e
 */
function handleClipboardResend(e) {
  // Handle Copy button
  const copyBtn = e.target.closest('.copy-clip-btn');
  if (copyBtn) {
    const content = copyBtn.dataset.content;
    if (content) {
      navigator.clipboard.writeText(content).then(() => {
        copyBtn.textContent = '✓';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      }).catch(() => {
        // Fallback: select text in a textarea
        const ta = document.createElement('textarea');
        ta.value = content;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        copyBtn.textContent = '✓';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    }
    return;
  }

  // Handle Resend button (legacy)
  const btn = e.target.closest('.resend-clip-btn');
  if (!btn || !selectedDeviceId) return;

  const content = btn.dataset.content;
  if (!content) return;

  chrome.runtime.sendMessage({
    type:    MSG.INITIATE_TRANSFER,
    payload: {
      type:           'clipboard',
      targetDeviceId: selectedDeviceId,
      content,
    },
  }).catch(err => showToast(`Resend failed: ${err.message}`, 'error'));

  showToast('Clipboard item resent!', 'success');
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * Load settings from chrome.storage.local, populate the settings form, render
 * the paired devices list, and switch to the settings view.
 *
 * Settings schema in chrome.storage.local:
 *   settings: { autoCopy: boolean, autoSave: boolean, deviceName: string }
 *
 * @returns {Promise<void>}
 */
async function showSettingsView() {
  const stored = await chrome.storage.local.get(['settings', 'pairedDevices']);
  const settings = stored.settings ?? { autoCopy: true, autoSave: false, deviceName: 'Chrome' };
  const devices = stored.pairedDevices ?? [];

  // Populate form controls
  const autoCopyEl = document.getElementById('setting-auto-copy');
  const autoSaveEl = document.getElementById('setting-auto-save');
  const nameEl = document.getElementById('setting-device-name');

  if (autoCopyEl) autoCopyEl.checked = settings.autoCopy !== false;
  if (autoSaveEl) autoSaveEl.checked = !!settings.autoSave;
  if (nameEl) nameEl.value = settings.deviceName || 'Chrome';

  // Render paired devices list
  renderSettingsPairedDevices(devices);

  showView('settings');
}

/**
 * Read current form values and persist them to chrome.storage.local.
 *
 * Called on checkbox change and device name blur so settings auto-save
 * without requiring a "Save" button.
 *
 * @returns {Promise<void>}
 */
async function saveSettings() {
  const autoCopy = document.getElementById('setting-auto-copy')?.checked ?? true;
  const autoSave = document.getElementById('setting-auto-save')?.checked ?? false;
  const deviceName = (document.getElementById('setting-device-name')?.value || 'Chrome').trim().slice(0, 30) || 'Chrome';

  await chrome.storage.local.set({
    settings: { autoCopy, autoSave, deviceName },
  });
}

/**
 * Render the list of paired devices inside the settings view with unpair buttons.
 *
 * @param {Array<{deviceId: string, name: string, icon: string}>} devices
 */
function renderSettingsPairedDevices(devices) {
  const container = document.getElementById('settings-paired-devices');
  if (!container) return;

  if (!devices.length) {
    container.innerHTML = '<div class="empty-list-msg">No paired devices</div>';
    return;
  }

  container.innerHTML = devices.map(d => {
    const icon = ICON_MAP[d.icon] ?? beamIcon.laptop();
    return `
      <div class="setting-device-row" data-id="${escapeAttr(d.deviceId)}">
        <span class="setting-device-icon">${icon}</span>
        <span class="setting-device-name">${escapeHtml(d.name)}</span>
        <button class="unpair-btn" data-id="${escapeAttr(d.deviceId)}"
                aria-label="Unpair ${escapeAttr(d.name)}">Unpair</button>
      </div>
    `;
  }).join('');

  // Wire unpair buttons via event delegation
  container.onclick = async (e) => {
    const btn = e.target.closest('.unpair-btn');
    if (!btn) return;

    const deviceId = btn.dataset.id;
    if (!deviceId) return;

    // Confirm before unpairing
    if (!confirm(`Unpair this device? It will no longer be able to transfer files.`)) return;

    // Remove from pairedDevices array
    const stored = await chrome.storage.local.get('pairedDevices');
    const updatedDevices = (stored.pairedDevices ?? []).filter(d => d.deviceId !== deviceId);
    await chrome.storage.local.set({ pairedDevices: updatedDevices });

    // Re-render the list and update main view
    renderSettingsPairedDevices(updatedDevices);
    await loadDevices();
    showToast('Device unpaired.', 'success');
  };
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Enable or disable all quick-action buttons as a group.
 *
 * @param {boolean} disabled
 */
function setQuickActionsDisabled(disabled) {
  ['btn-clipboard', 'btn-screenshot', 'btn-tab-url'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = disabled;
  });
}

/**
 * Show a transient toast notification at the top of the popup.
 * Auto-dismisses after TOAST_DURATION_MS milliseconds.
 *
 * @param {string} message - Plain text or already-escaped HTML.
 * @param {'success'|'error'|''} [type='']
 */
function showToast(message, type = '') {
  const toast = el('toast');
  toast.textContent = message;           // textContent is XSS-safe
  toast.className   = `toast ${type}`.trim();
  toast.classList.remove('hidden');

  if (toastHandle) clearTimeout(toastHandle);
  toastHandle = setTimeout(() => {
    toast.classList.add('hidden');
  }, TOAST_DURATION_MS);
}

/**
 * Escape a string for safe insertion as HTML text content.
 * Converts the five HTML special characters to named entities.
 *
 * @param {string} s
 * @returns {string}
 */
function escapeHtml(s) {
  if (typeof s !== 'string') return '';
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escape a string for safe insertion inside an HTML attribute value.
 * Equivalent to escapeHtml for our use cases (attribute values are quoted).
 *
 * @param {string} s
 * @returns {string}
 */
function escapeAttr(s) {
  return escapeHtml(s);
}

/**
 * Format a byte count as a human-readable string (e.g. "1.4 MB").
 *
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
  if (!bytes || bytes < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i     = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
  const value = bytes / (1024 ** i);
  return `${i === 0 ? value : value.toFixed(1)} ${units[i]}`;
}

/**
 * Format a Unix timestamp as a short relative-time string (e.g. "2m ago").
 *
 * @param {number} timestamp - Unix timestamp in milliseconds.
 * @returns {string}
 */
function formatRelativeTime(timestamp) {
  if (!timestamp) return '';
  const diff = Date.now() - timestamp;
  if (diff < 60_000)       return 'just now';
  if (diff < 3_600_000)    return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000)   return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}
