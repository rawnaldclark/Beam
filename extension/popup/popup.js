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

// ---------------------------------------------------------------------------
// Phase 2c — Inline transfer state tracking
// ---------------------------------------------------------------------------

/**
 * Active transfers indexed by deviceId for inline device-row visualisation.
 * Each entry holds the transfer metadata needed to render the ring-progress
 * indicator, success hold, or failure state directly inside the device row.
 *
 * @type {Map<string, {
 *   percent: number,
 *   fileName: string,
 *   bytesTransferred: number,
 *   bytesTotal: number,
 *   direction: 'out'|'in',
 *   transferId: string,
 *   state: 'progress'|'success'|'failed',
 *   error?: string,
 *   targetDeviceId: string,
 *   sendPayload?: object
 * }>}
 */
const activeTransfersByDevice = new Map();

/** Circumference of the ring-progress circle (r=6). */
const RING_CIRCUMFERENCE = 2 * Math.PI * 6; // 37.699

/** Duration (ms) the success state holds before fading back to idle. */
const SUCCESS_HOLD_MS = 600;

/** Duration (ms) for the crossfade from ring to check icon. */
const CROSSFADE_MS = 120;

/** Duration (ms) for the fade-back to idle after success hold. */
const FADE_BACK_MS = 180;

/** Timeout handles for success-hold per deviceId, so we can cancel on re-send. */
const successTimers = new Map();

/** Whether the relay-error banner is currently visible. */
let relayErrorActive = false;

/** Interval handle for the relay-error countdown. */
let relayCountdownHandle = null;

/**
 * Cached transfer history for the unified activity list (Phase 2a).
 * @type {Array<{transferId: string, fileName: string, fileSize: number, direction: string, status: string, timestamp: number, targetDeviceName?: string}>}
 */
let cachedTransferHistory = [];

/**
 * Cached clipboard history for the unified activity list (Phase 2a).
 * @type {Array<{id: string, content: string, timestamp: number, fromDeviceId?: string}>}
 */
let cachedClipboardHistory = [];

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
  populateIdentityStrip();
  setupEventListeners();
  listenForStorageChanges();
  startKeepalive();

  // Retry device load after a short delay to catch the cold-start timing
  // race: on browser restart or extension reload, the SW may still be
  // connecting to the relay when the popup first renders. The initial
  // loadDevices() reads empty devicePresence from session storage and
  // shows all devices offline. By the time this retry fires, the SW has
  // usually completed auth + received peer-online + written to session
  // storage, so the second loadDevices() picks up the correct state.
  //
  // The storage.onChanged listener handles updates AFTER this window,
  // but this retry covers the gap between popup-open and listener-ready.
  setTimeout(loadDevices, 1500);
  setTimeout(loadDevices, 4000);
});

/**
 * Populate the identity strip with the device's own name and relay status.
 *
 * Reads the device name from chrome.storage.local settings. The relay status
 * dot defaults to online (green) — the service worker heartbeat manages the
 * actual connection state. A future Phase 2b pass will wire up real-time
 * relay status updates.
 *
 * @returns {Promise<void>}
 */
async function populateIdentityStrip() {
  try {
    const stored = await chrome.storage.local.get(['settings', 'deviceId']);
    const alias  = stored.settings?.deviceName || 'Chrome';
    const aliasEl = document.getElementById('identity-alias');
    if (aliasEl) aliasEl.textContent = alias;
  } catch {
    // Non-critical — identity strip shows empty alias if storage read fails.
  }

  // Relay status dot: default to online. The SW manages relay connectivity
  // and will send RELAY_STATUS messages in a future phase.
  const dot = document.getElementById('relay-status-dot');
  if (dot) dot.classList.remove('disconnected');
}

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

  // Phase 2c: if we have paired devices but presence is empty (relay WS closed),
  // show the error banner. Empty presence + paired devices = relay unreachable.
  if (currentDevices.length > 0 && Object.keys(presence).length === 0) {
    const hasAnyOnline = currentDevices.some(d => d.isOnline);
    if (!hasAnyOnline) {
      // Check if this is a genuine relay disconnect (not just startup timing).
      // We use a short delay so the relay has time to populate presence on
      // initial popup open. The banner only shows if still empty after 1.5s.
      setTimeout(() => {
        const anyOnline = currentDevices.some(d => d.isOnline);
        if (!anyOnline && currentDevices.length > 0) {
          showRelayErrorBanner();
        }
      }, 1500);
    }
  }

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
 *
 * Phase 2a: uses flat 36px device-row items instead of bordered cards.
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
    .map(d => deviceRowHTML(d))
    .join('');

  // Attach click handlers via event delegation on the list container.
  list.onclick = handleDeviceListClick;

  // Phase 4: stagger-enter animation for device rows (max 3 rows staggered).
  const rows = list.querySelectorAll('.device-row');
  rows.forEach((row, i) => {
    if (i < 3) {
      row.style.animationDelay = `${i * 30}ms`;
      row.classList.add('stagger-enter');
      row.addEventListener('animationend', () => {
        row.classList.remove('stagger-enter');
        row.style.animationDelay = '';
      }, { once: true });
    }
  });
}

/**
 * Build the inner HTML for a single device row (Phase 2a flat 36px row).
 * Phase 2c: if an active transfer exists for this device, the row morphs to
 * show inline ring-progress, success, or failure state.
 *
 * All user-provided text is escaped.
 *
 * @param {{deviceId: string, name: string, icon: string, isOnline: boolean}} d
 * @returns {string}
 */
function deviceRowHTML(d) {
  const statusClass   = d.isOnline ? 'online' : 'offline';
  const selectedClass = d.deviceId === selectedDeviceId ? 'selected' : '';
  const icon          = ICON_MAP[d.icon] ?? beamIcon.laptop();

  // Phase 2c: check for active transfer state on this device.
  const xfer = activeTransfersByDevice.get(d.deviceId);

  if (xfer && xfer.state === 'progress') {
    return deviceRowTransferHTML(d, xfer, statusClass, selectedClass, icon);
  }

  if (xfer && xfer.state === 'success') {
    return deviceRowSuccessHTML(d, xfer, statusClass, selectedClass);
  }

  if (xfer && xfer.state === 'failed') {
    return deviceRowFailedHTML(d, xfer, statusClass, selectedClass, icon);
  }

  // Default idle state.
  const dotClass = d.isOnline ? 'dot-online' : 'dot-offline';
  const trailing = relayErrorActive ? 'unavailable'
                 : d.isOnline       ? 'send'
                 :                    'offline';

  return `
    <div class="device-row ${statusClass} ${selectedClass}" data-id="${escapeAttr(d.deviceId)}"
         role="button" tabindex="0" aria-label="${escapeAttr(d.name)}, ${statusClass}">
      <span class="row-dot ${dotClass}"></span>
      <span class="row-icon" aria-hidden="true">${icon}</span>
      <span class="row-name">${escapeHtml(d.name)}</span>
      <span class="row-trailing">${trailing}</span>
    </div>
  `;
}

/**
 * Build a device row in the "transferring" state with an inline ring-progress SVG.
 *
 * @param {object} d  - Device object
 * @param {object} xfer - Transfer state from activeTransfersByDevice
 * @param {string} statusClass
 * @param {string} selectedClass
 * @param {string} icon - Device icon SVG
 * @returns {string}
 */
function deviceRowTransferHTML(d, xfer, statusClass, selectedClass, icon) {
  const pct    = Math.min(100, Math.max(0, xfer.percent));
  const offset = RING_CIRCUMFERENCE * (1 - pct / 100);

  const ring = `
    <svg class="ring-progress" width="16" height="16" viewBox="0 0 16 16">
      <circle cx="8" cy="8" r="6" fill="none" stroke="var(--beam-border-subtle, var(--border))" stroke-width="1.5"/>
      <circle cx="8" cy="8" r="6" fill="none" stroke="var(--beam-accent, var(--primary))" stroke-width="1.5"
              stroke-dasharray="${RING_CIRCUMFERENCE.toFixed(3)}" stroke-dashoffset="${offset.toFixed(3)}"
              stroke-linecap="round" transform="rotate(-90 8 8)"/>
    </svg>`;

  // Trailing: filename + bytes progress for outgoing, filename + "in" for incoming.
  let trailingContent;
  if (xfer.direction === 'in') {
    trailingContent = `
      <span class="xfer-filename">${escapeHtml(truncateFilename(xfer.fileName, 18))}</span>
      <span class="xfer-bytes">in</span>`;
  } else {
    const transferred = formatBytes(xfer.bytesTransferred);
    const total       = formatBytes(xfer.bytesTotal);
    trailingContent = `
      <span class="xfer-filename">${escapeHtml(truncateFilename(xfer.fileName, 18))}</span>
      <span class="xfer-bytes">${transferred}/${total}</span>`;
  }

  return `
    <div class="device-row transferring ${statusClass} ${selectedClass}" data-id="${escapeAttr(d.deviceId)}"
         role="button" tabindex="0" aria-label="${escapeAttr(d.name)}, transferring ${pct}%">
      <span class="row-ring">${ring}</span>
      <span class="row-name">${escapeHtml(d.name)}</span>
      <span class="row-trailing row-trailing-xfer">${trailingContent}</span>
    </div>
  `;
}

/**
 * Build a device row in the "success" state (check-circle icon, green flash).
 *
 * @param {object} d
 * @param {object} xfer
 * @param {string} statusClass
 * @param {string} selectedClass
 * @returns {string}
 */
function deviceRowSuccessHTML(d, xfer, statusClass, selectedClass) {
  // Inline check-circle SVG (16px) since beam-icons.js has a placeholder.
  const checkCircle = `<svg class="state-icon success-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`;

  const sizeStr = formatBytes(xfer.bytesTotal);

  return `
    <div class="device-row transfer-success ${statusClass} ${selectedClass}" data-id="${escapeAttr(d.deviceId)}"
         role="button" tabindex="0" aria-label="${escapeAttr(d.name)}, transfer complete">
      <span class="row-state-icon">${checkCircle}</span>
      <span class="row-name">${escapeHtml(d.name)}</span>
      <span class="row-trailing row-trailing-done">
        <span class="xfer-verb">sent</span>
        <span class="xfer-filename">${escapeHtml(truncateFilename(xfer.fileName, 16))}</span>
        <span class="xfer-bytes">${sizeStr}</span>
      </span>
    </div>
  `;
}

/**
 * Build a device row in the "failed" state (x-circle icon, red background, retry chip).
 *
 * @param {object} d
 * @param {object} xfer
 * @param {string} statusClass
 * @param {string} selectedClass
 * @param {string} icon
 * @returns {string}
 */
function deviceRowFailedHTML(d, xfer, statusClass, selectedClass, icon) {
  // Inline x-circle SVG (16px) since beam-icons.js has a placeholder.
  const xCircle = `<svg class="state-icon danger-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>`;

  const errorMsg = escapeHtml(xfer.error || 'Transfer failed');

  return `
    <div class="device-row transfer-failed ${statusClass} ${selectedClass}" data-id="${escapeAttr(d.deviceId)}"
         role="button" tabindex="0" aria-label="${escapeAttr(d.name)}, transfer failed">
      <span class="row-state-icon">${xCircle}</span>
      <span class="row-name">${escapeHtml(d.name)}</span>
      <span class="row-trailing row-trailing-error">
        <span class="xfer-error-msg">${errorMsg}</span>
        <span class="retry-chip" data-retry-device="${escapeAttr(d.deviceId)}">retry</span>
      </span>
    </div>
  `;
}

/**
 * Truncate a filename to maxLen characters, preserving the extension.
 *
 * @param {string} name
 * @param {number} maxLen
 * @returns {string}
 */
function truncateFilename(name, maxLen) {
  if (!name || name.length <= maxLen) return name || '';
  const dotIdx = name.lastIndexOf('.');
  if (dotIdx > 0 && name.length - dotIdx <= 6) {
    // Preserve extension (up to 5 chars + dot).
    const ext  = name.slice(dotIdx);
    const base = name.slice(0, maxLen - ext.length - 1);
    return base + '\u2026' + ext;
  }
  return name.slice(0, maxLen - 1) + '\u2026';
}

/**
 * Re-render the active transfer progress bars.
 *
 * Phase 2c: the old separate progress-bar section is replaced by inline
 * device-row states. This function now hides the legacy section and
 * triggers a device list re-render so the inline states are visible.
 */
function renderActiveTransfers() {
  // Hide the legacy active-transfers section (Phase 2c replacement).
  const section = document.getElementById('active-transfers');
  if (section) section.innerHTML = '';

  // Re-render device rows so inline transfer states are reflected.
  renderDeviceRowsOnly();
}

/**
 * Re-render ONLY the device rows without resetting selection or re-running
 * the full renderDevices() logic. This avoids selection flicker during
 * live transfer progress updates.
 */
function renderDeviceRowsOnly() {
  const list = document.getElementById('device-list');
  if (!list) return;

  list.innerHTML = currentDevices
    .map(d => deviceRowHTML(d))
    .join('');

  // Re-attach click handler (event delegation on the list container).
  list.onclick = handleDeviceListClick;
}

/**
 * Cache transfer history and trigger a unified activity list re-render.
 *
 * @param {Array<{transferId: string, fileName: string, fileSize: number,
 *   direction: string, status: string, timestamp: number, targetDeviceName?: string}>} history
 */
function renderTransferHistory(history) {
  cachedTransferHistory = history;
  renderActivityList();
}

/**
 * Cache clipboard history and trigger a unified activity list re-render.
 *
 * @param {Array<{id: string, content: string, timestamp: number}>} history
 */
function renderClipboardHistory(history) {
  cachedClipboardHistory = history;
  renderActivityList();
}

/**
 * Unified activity list renderer (Phase 2a).
 *
 * Merges transfer history and clipboard history into a single time-sorted
 * list of flat 36px activity-row items, capped at 8 visible rows.
 * Renders into #activity-list.
 */
function renderActivityList() {
  const list = document.getElementById('activity-list');
  if (!list) return;

  // Build unified activity entries from both sources.
  /** @type {Array<{type: string, html: string, timestamp: number}>} */
  const entries = [];

  // Transfer history entries
  for (const item of cachedTransferHistory) {
    const icon     = item.direction === 'in' ? beamIcon.arrow_down() : beamIcon.arrow_up();
    const sizeMeta = formatBytes(item.fileSize);
    const device   = item.targetDeviceName ? escapeHtml(item.targetDeviceName) : '';
    const time     = formatRelativeTime(item.timestamp);

    entries.push({
      type: 'transfer',
      timestamp: item.timestamp,
      html: `
        <div class="activity-row">
          <span class="row-icon" aria-hidden="true">${icon}</span>
          <span class="row-name">${escapeHtml(item.fileName)}</span>
          <span class="row-meta">${sizeMeta}</span>
          ${device ? `<span class="row-meta">${device}</span>` : ''}
          <span class="row-meta">${time}</span>
        </div>
      `,
    });
  }

  // Clipboard history entries
  for (const item of cachedClipboardHistory) {
    const preview = escapeHtml(item.content.slice(0, 40)) +
                    (item.content.length > 40 ? '...' : '');
    const time    = formatRelativeTime(item.timestamp);

    entries.push({
      type: 'clipboard',
      timestamp: item.timestamp,
      html: `
        <div class="activity-row" data-clip-content="${escapeAttr(item.content)}">
          <span class="row-icon" aria-hidden="true">${beamIcon.clipboard()}</span>
          <span class="row-name">${preview}</span>
          <span class="row-meta">${time}</span>
        </div>
      `,
    });
  }

  // Sort by most recent first, cap at 8.
  entries.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  const visible = entries.slice(0, 8);

  if (visible.length === 0) {
    list.innerHTML = '<div class="activity-empty">Nothing sent yet. Paste or drop to start.</div>';
  } else {
    list.innerHTML = visible.map(e => e.html).join('');
  }

  // Delegate clipboard copy on click.
  list.onclick = handleActivityListClick;
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

      showToast('Download started.', 'success');
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
/** Tracks the last active view name so we can determine slide direction. */
let _lastViewName = 'main';

function showView(name) {
  const ids = ['view-main', 'view-pairing', 'view-sas', 'view-naming', 'view-settings'];
  ids.forEach(id => document.getElementById(id)?.classList.add('hidden'));

  const newView = document.getElementById(`view-${name}`);
  if (!newView) return;
  newView.classList.remove('hidden');

  // Phase 4: apply slide-in animation class based on direction.
  const isReturning = name === 'main' && _lastViewName !== 'main';
  const isEntering  = name !== 'main' && _lastViewName === 'main';
  newView.classList.remove('entering', 'returning');
  if (isEntering) {
    newView.classList.add('entering');
  } else if (isReturning) {
    newView.classList.add('returning');
  }
  _lastViewName = name;

  // Phase 4: focus management — move focus to the first interactive element
  // in the newly visible view after the animation frame settles.
  setTimeout(() => {
    newView.querySelector('button, [tabindex="0"], input')?.focus();
  }, 50);

  // Phase 3a: manage the shortcut footer based on active view.
  // Secondary views show a minimal "esc back" footer; main shows the full footer.
  const footer = document.getElementById('shortcut-footer');
  if (!footer) return;

  if (name === 'main') {
    footer.classList.remove('hidden');
    footer.innerHTML = `
      <span class="shortcut-chip">&#x23CE; send</span>
      <span class="shortcut-chip">&#x2191;&#x2193; select</span>
      <span class="shortcut-chip">/ filter</span>
      <span class="shortcut-chip">p pair</span>
      <span class="shortcut-chip">, settings</span>
    `;
  } else {
    footer.classList.remove('hidden');
    footer.innerHTML = '<span class="shortcut-chip">esc back</span>';
  }
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
    showToast('Could not start pairing — background service unavailable.', 'error');
    showView('main');
    return;
  }

  if (!qrData) {
    console.error('[Beam popup] qrData is null/undefined — key generation failed');
    showToast('Pairing service unavailable, try again in a moment.', 'error');
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
      showToast('Pairing timed out, try again.', 'error');
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
    showToast('Pairing state lost, try again.', 'error');
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
    showToast(`"${escapeHtml(name)}" paired successfully.`, 'success');
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
  // Empty state: Pair first device button
  document.getElementById('btn-pair-first')?.addEventListener('click', showPairingView);

  // Header: Settings — open settings view
  document.getElementById('btn-settings')?.addEventListener('click', showSettingsView);

  // Phase 3a: Back rows for all secondary views (using view-back pattern)
  document.getElementById('settings-back')?.addEventListener('click', () => {
    showView('main');
  });
  document.getElementById('pairing-back')?.addEventListener('click', () => {
    if (pinTimerHandle) { clearInterval(pinTimerHandle); pinTimerHandle = null; }
    cancelPairingRelay();
    pendingPairing = null;
    pairingDeviceId = null;
    showView('main');
  });
  document.getElementById('sas-back')?.addEventListener('click', cancelSAS);
  document.getElementById('naming-back')?.addEventListener('click', () => {
    showView('main');
  });

  // Phase 3a: Settings toggle switches
  document.getElementById('toggle-auto-copy')?.addEventListener('click', () => {
    const tog = document.getElementById('toggle-auto-copy');
    if (!tog) return;
    tog.classList.toggle('on');
    tog.setAttribute('aria-checked', tog.classList.contains('on') ? 'true' : 'false');
    saveSettings();
  });
  document.getElementById('toggle-auto-save')?.addEventListener('click', () => {
    const tog = document.getElementById('toggle-auto-save');
    if (!tog) return;
    tog.classList.toggle('on');
    tog.setAttribute('aria-checked', tog.classList.contains('on') ? 'true' : 'false');
    saveSettings();
  });

  // Phase 3a: Toggle keyboard accessibility (Enter/Space)
  document.querySelectorAll('.beam-toggle').forEach(tog => {
    tog.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        tog.click();
      }
    });
  });

  // Phase 3a: Device name inline edit
  document.getElementById('settings-edit-name')?.addEventListener('click', () => {
    const displayRow = document.getElementById('settings-device-name-row');
    const editRow    = document.getElementById('settings-device-name-edit-row');
    const input      = document.getElementById('setting-device-name');
    if (!displayRow || !editRow || !input) return;

    // Copy current display value into the input
    const displayEl = document.getElementById('settings-device-name-display');
    if (displayEl) input.value = displayEl.textContent;

    displayRow.classList.add('hidden');
    editRow.classList.remove('hidden');
    input.focus();
    input.select();
  });

  // Device name: save on blur or Enter
  const nameInput = document.getElementById('setting-device-name');
  if (nameInput) {
    nameInput.addEventListener('blur', () => {
      commitDeviceNameEdit();
    });
    nameInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        nameInput.blur();
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        // Revert and close
        const displayRow = document.getElementById('settings-device-name-row');
        const editRow    = document.getElementById('settings-device-name-edit-row');
        if (displayRow) displayRow.classList.remove('hidden');
        if (editRow) editRow.classList.add('hidden');
      }
    });
  }

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

  // Shortcut footer: delegate clicks on chips (Phase 2a)
  document.getElementById('shortcut-footer')?.addEventListener('click', handleShortcutClick);

  // Runtime messages (pairing events, transfer progress, presence changes)
  chrome.runtime.onMessage.addListener(handleMessage);
}

/**
 * Handle clicks on shortcut chips in the footer (Phase 2a).
 * Maps chip text content to actions.
 *
 * @param {MouseEvent} e
 */
function handleShortcutClick(e) {
  const chip = e.target.closest('.shortcut-chip');
  if (!chip) return;

  const text = chip.textContent.trim().toLowerCase();
  if (text.includes('pair')) {
    showPairingView();
  } else if (text.includes('settings')) {
    showSettingsView();
  }
  // 'send' and 'select' chips are informational labels for keyboard shortcuts
  // which will be wired in Phase 2b.
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
        showToast(`"${escapeHtml(name)}" paired successfully.`, 'success');
      });
      break;
    }

    // ── Transfer progress (Phase 2c: inline device-row states) ──────────────
    case MSG.TRANSFER_PROGRESS: {
      const { transferId, fileName, bytesTransferred, totalBytes, speedBps, targetDeviceId } = msg.payload ?? {};
      if (transferId) {
        activeTransfers.set(transferId, { transferId, fileName, bytesTransferred, totalBytes, speedBps });

        // Phase 2c: feed into per-device transfer map for inline rendering.
        const deviceId = targetDeviceId || resolveDeviceIdFromTransfer(transferId);
        if (deviceId) {
          const pct = totalBytes > 0 ? Math.round((bytesTransferred / totalBytes) * 100) : 0;
          activeTransfersByDevice.set(deviceId, {
            percent: pct,
            fileName: fileName || 'file',
            bytesTransferred: bytesTransferred || 0,
            bytesTotal: totalBytes || 0,
            direction: 'out',
            transferId,
            state: 'progress',
            targetDeviceId: deviceId,
          });
        }
        renderActiveTransfers();
      }
      break;
    }

    case MSG.TRANSFER_COMPLETE: {
      const { transferId, fileName, fileSize, targetDeviceId } = msg.payload ?? {};
      if (transferId) activeTransfers.delete(transferId);

      // Phase 2c: transition to success state on the device row.
      const deviceId = targetDeviceId || resolveDeviceIdFromTransfer(transferId);
      if (deviceId) {
        handleTransferSuccess(deviceId, transferId, fileName, fileSize);
      } else {
        // Fallback: no device mapping, just clear and toast.
        renderActiveTransfers();
        showToast(`Sent "${escapeHtml(fileName ?? 'file')}" successfully.`, 'success');
      }
      loadTransferHistory();
      break;
    }

    case MSG.TRANSFER_FAILED: {
      const { transferId, reason, targetDeviceId } = msg.payload ?? {};
      if (transferId) activeTransfers.delete(transferId);

      // Phase 2c: transition to failed state on the device row.
      const deviceId = targetDeviceId || resolveDeviceIdFromTransfer(transferId);
      if (deviceId) {
        handleTransferFailure(deviceId, transferId, reason);
      } else {
        renderActiveTransfers();
        showToast(`Transfer failed: ${escapeHtml(reason ?? 'unknown error')}`, 'error');
      }
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
      // Phase 2c: detect relay reset (WS close) vs individual device presence.
      if (msg.payload?.reset) {
        // Relay WS closed — all devices go offline, show error banner.
        currentDevices = currentDevices.map(d => ({ ...d, isOnline: false }));
        showRelayErrorBanner();
        renderDevices();
      } else if (msg.payload?.deviceId) {
        const { deviceId, online } = msg.payload;
        currentDevices = currentDevices.map(d =>
          d.deviceId === deviceId ? { ...d, isOnline: !!online } : d
        );

        // If any device comes back online, hide the relay error banner.
        if (online && relayErrorActive) {
          hideRelayErrorBanner();
        }
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

  // Phase 2c: start mock progress animation on the device row while the real
  // transfer is dispatched. If the SW sends TRANSFER_PROGRESS with a
  // targetDeviceId, the mock will be overridden by real data. If not, the
  // mock provides a smooth 0->100% animation as a visual placeholder.
  startMockTransferProgress(targetId, file.name, file.size);

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
    if (!resp?.ok) {
      // Send was rejected — transition device row to failed state.
      handleTransferFailure(targetId, 'send-' + Date.now(), 'relay not connected');
    }
  }).catch(err => {
    handleTransferFailure(targetId, 'send-' + Date.now(), err.message);
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
      showToast('Clipboard sent.', 'success');
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

  showToast('Screenshot sent.', 'success');
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

  showToast('Tab URL sent.', 'success');
}

// ---------------------------------------------------------------------------
// Click delegation handlers
// ---------------------------------------------------------------------------

/**
 * Handle clicks in the device list (Phase 2a + 2c):
 *   - Clicking a .device-row selects it as the transfer target.
 *   - Clicking the trailing "send" text on an online row opens the file picker.
 *   - Phase 2c: clicking a .retry-chip retries the failed transfer.
 *
 * @param {MouseEvent} e
 */
function handleDeviceListClick(e) {
  // Phase 2c: retry chip click.
  const retryChip = e.target.closest('.retry-chip[data-retry-device]');
  if (retryChip) {
    const deviceId = retryChip.dataset.retryDevice;
    if (deviceId) retryTransfer(deviceId);
    return;
  }

  // Row selection
  const row = e.target.closest('.device-row');
  if (!row) return;

  // Phase 2c: don't allow interaction on failed rows except via retry.
  if (row.classList.contains('transfer-failed')) return;

  // Don't allow clicking offline rows.
  if (row.classList.contains('offline')) return;

  // If user clicked the "send" trailing text, open file picker.
  const trailing = e.target.closest('.row-trailing');
  if (trailing && row.dataset.id && !row.classList.contains('transferring') && !row.classList.contains('transfer-success')) {
    selectedDeviceId = row.dataset.id;
    el('file-input').click();
    // Still select the row visually below.
  }

  // Update selection
  el('device-list')
    .querySelectorAll('.device-row')
    .forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  selectedDeviceId = row.dataset.id;
}

/**
 * Handle clicks in the unified activity list (Phase 2a).
 * Clipboard activity rows can be clicked to copy content.
 *
 * @param {MouseEvent} e
 */
function handleActivityListClick(e) {
  const row = e.target.closest('.activity-row[data-clip-content]');
  if (!row) return;

  const content = row.dataset.clipContent;
  if (!content) return;

  navigator.clipboard.writeText(content).then(() => {
    showToast('Copied to clipboard.', 'success');
  }).catch(() => {
    showToast('Could not copy to clipboard.', 'error');
  });
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

  showToast('Clipboard item resent.', 'success');
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

  // Phase 3a: populate toggle switches instead of checkboxes
  const autoCopyToggle = document.getElementById('toggle-auto-copy');
  const autoSaveToggle = document.getElementById('toggle-auto-save');
  const nameDisplay    = document.getElementById('settings-device-name-display');
  const nameInput      = document.getElementById('setting-device-name');

  if (autoCopyToggle) {
    autoCopyToggle.classList.toggle('on', settings.autoCopy !== false);
    autoCopyToggle.setAttribute('aria-checked', settings.autoCopy !== false ? 'true' : 'false');
  }
  if (autoSaveToggle) {
    autoSaveToggle.classList.toggle('on', !!settings.autoSave);
    autoSaveToggle.setAttribute('aria-checked', settings.autoSave ? 'true' : 'false');
  }
  if (nameDisplay) nameDisplay.textContent = settings.deviceName || 'Chrome';
  if (nameInput)   nameInput.value = settings.deviceName || 'Chrome';

  // Reset to display mode (hide inline edit if open)
  const displayRow = document.getElementById('settings-device-name-row');
  const editRow    = document.getElementById('settings-device-name-edit-row');
  if (displayRow) displayRow.classList.remove('hidden');
  if (editRow)    editRow.classList.add('hidden');

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
  // Phase 3a: read from toggle switches instead of checkboxes
  const autoCopy   = document.getElementById('toggle-auto-copy')?.classList.contains('on') ?? true;
  const autoSave   = document.getElementById('toggle-auto-save')?.classList.contains('on') ?? false;
  const deviceName = (document.getElementById('settings-device-name-display')?.textContent || 'Chrome').trim().slice(0, 30) || 'Chrome';

  await chrome.storage.local.set({
    settings: { autoCopy, autoSave, deviceName },
  });
}

/**
 * Commit the inline device name edit: update display, save settings, and
 * switch back to display mode.
 */
function commitDeviceNameEdit() {
  const input      = document.getElementById('setting-device-name');
  const displayEl  = document.getElementById('settings-device-name-display');
  const displayRow = document.getElementById('settings-device-name-row');
  const editRow    = document.getElementById('settings-device-name-edit-row');
  if (!input) return;

  const newName = (input.value || 'Chrome').trim().slice(0, 30) || 'Chrome';
  if (displayEl) displayEl.textContent = newName;

  // Switch back to display mode
  if (displayRow) displayRow.classList.remove('hidden');
  if (editRow)    editRow.classList.add('hidden');

  // Persist
  saveSettings();

  // Update the identity strip alias
  const aliasEl = document.getElementById('identity-alias');
  if (aliasEl) aliasEl.textContent = newName;
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
      <div class="settings-device-row" data-id="${escapeAttr(d.deviceId)}">
        <span class="settings-device-icon">${icon}</span>
        <span class="settings-device-name">${escapeHtml(d.name)}</span>
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
// Phase 2c — Transfer state transitions
// ---------------------------------------------------------------------------

/**
 * Resolve a deviceId from a transferId by searching the activeTransfersByDevice map.
 * Returns null if no mapping is found.
 *
 * @param {string} transferId
 * @returns {string|null}
 */
function resolveDeviceIdFromTransfer(transferId) {
  for (const [deviceId, xfer] of activeTransfersByDevice) {
    if (xfer.transferId === transferId) return deviceId;
  }
  return null;
}

/**
 * Transition a device row to the success state, hold for 600ms, then fade back.
 *
 * @param {string} deviceId
 * @param {string} transferId
 * @param {string} [fileName]
 * @param {number} [fileSize]
 */
function handleTransferSuccess(deviceId, transferId, fileName, fileSize) {
  // Cancel any pending success timer for this device.
  if (successTimers.has(deviceId)) {
    clearTimeout(successTimers.get(deviceId));
    successTimers.delete(deviceId);
  }

  const existing = activeTransfersByDevice.get(deviceId);

  // Set to 100% progress first (ring fills).
  activeTransfersByDevice.set(deviceId, {
    percent: 100,
    fileName: fileName || existing?.fileName || 'file',
    bytesTransferred: fileSize || existing?.bytesTotal || 0,
    bytesTotal: fileSize || existing?.bytesTotal || 0,
    direction: existing?.direction || 'out',
    transferId,
    state: 'success',
    targetDeviceId: deviceId,
  });

  renderDeviceRowsOnly();

  // After SUCCESS_HOLD_MS, fade back to idle and add to activity list.
  const timer = setTimeout(() => {
    successTimers.delete(deviceId);
    activeTransfersByDevice.delete(deviceId);
    renderDeviceRowsOnly();
  }, SUCCESS_HOLD_MS);

  successTimers.set(deviceId, timer);
}

/**
 * Transition a device row to the failed state with retry option.
 *
 * @param {string} deviceId
 * @param {string} transferId
 * @param {string} [reason]
 */
function handleTransferFailure(deviceId, transferId, reason) {
  const existing = activeTransfersByDevice.get(deviceId);

  activeTransfersByDevice.set(deviceId, {
    percent: existing?.percent || 0,
    fileName: existing?.fileName || 'file',
    bytesTransferred: existing?.bytesTransferred || 0,
    bytesTotal: existing?.bytesTotal || 0,
    direction: existing?.direction || 'out',
    transferId,
    state: 'failed',
    error: reason || 'Transfer failed',
    targetDeviceId: deviceId,
    sendPayload: existing?.sendPayload || null,
  });

  renderDeviceRowsOnly();
}

/**
 * Retry a failed transfer for a given device.
 * Clears the error state and re-triggers the send.
 *
 * @param {string} deviceId
 */
function retryTransfer(deviceId) {
  const xfer = activeTransfersByDevice.get(deviceId);
  if (!xfer || xfer.state !== 'failed') return;

  // Clear the failed state.
  activeTransfersByDevice.delete(deviceId);
  renderDeviceRowsOnly();

  // Re-trigger: select the device and open the file picker.
  // If the original sendPayload was stored, we could re-send automatically,
  // but for safety we prompt the user to re-select the file.
  selectedDeviceId = deviceId;
  updateSelection(deviceId);
  el('file-input').click();
}

// ---------------------------------------------------------------------------
// Phase 2c — Mock transfer progress (for testing without real SW data)
// ---------------------------------------------------------------------------

/**
 * Start a mock 3-second transfer animation on the given device.
 * Used when the real transfer data flow doesn't include targetDeviceId
 * or when testing the UI without a connected relay.
 *
 * @param {string} deviceId
 * @param {string} fileName
 * @param {number} fileSize
 */
function startMockTransferProgress(deviceId, fileName, fileSize) {
  const transferId = 'mock-' + Date.now();
  const duration   = 3000; // 3 seconds
  const startTime  = Date.now();

  activeTransfersByDevice.set(deviceId, {
    percent: 0,
    fileName,
    bytesTransferred: 0,
    bytesTotal: fileSize,
    direction: 'out',
    transferId,
    state: 'progress',
    targetDeviceId: deviceId,
  });

  renderDeviceRowsOnly();

  const interval = setInterval(() => {
    const elapsed = Date.now() - startTime;
    const pct     = Math.min(100, Math.round((elapsed / duration) * 100));
    const bytes   = Math.round((pct / 100) * fileSize);

    const entry = activeTransfersByDevice.get(deviceId);
    if (!entry || entry.transferId !== transferId) {
      clearInterval(interval);
      return;
    }

    entry.percent = pct;
    entry.bytesTransferred = bytes;
    renderDeviceRowsOnly();

    if (pct >= 100) {
      clearInterval(interval);
      handleTransferSuccess(deviceId, transferId, fileName, fileSize);
    }
  }, 50);
}

// ---------------------------------------------------------------------------
// Phase 2c — Relay error banner
// ---------------------------------------------------------------------------

/**
 * Show the surface-wide relay error banner at the top of #main-list.
 * Dims all device rows and makes them non-interactive.
 */
function showRelayErrorBanner() {
  if (relayErrorActive) return;
  relayErrorActive = true;

  const mainList = document.getElementById('main-list');
  if (!mainList) return;

  mainList.classList.add('relay-error');

  // Build the banner element.
  let banner = document.getElementById('error-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'error-banner';
    banner.className = 'error-banner';

    // Inline x-circle SVG for the error icon.
    const xCircleSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>`;

    banner.innerHTML = `
      <span class="error-icon">${xCircleSvg}</span>
      <span class="error-message">relay unreachable. retrying in <span id="error-countdown">5</span>s.</span>
      <button class="retry-chip" id="error-retry">retry</button>
    `;

    mainList.insertBefore(banner, mainList.firstChild);

    // Wire retry button.
    document.getElementById('error-retry')?.addEventListener('click', () => {
      // Attempt immediate reconnect via the SW.
      chrome.runtime.sendMessage({ type: 'RELAY_RECONNECT' }).catch(() => {});
      const countdown = document.getElementById('error-countdown');
      if (countdown) countdown.textContent = '...';
    });
  }

  // Start countdown (5 seconds, auto-decrement).
  let remaining = 5;
  const countdown = document.getElementById('error-countdown');
  if (countdown) countdown.textContent = String(remaining);

  if (relayCountdownHandle) clearInterval(relayCountdownHandle);
  relayCountdownHandle = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      remaining = 5; // Reset: relay auto-reconnect typically fires every 5s.
    }
    const el = document.getElementById('error-countdown');
    if (el) el.textContent = String(remaining);
  }, 1000);

  renderDeviceRowsOnly();
}

/**
 * Hide the relay error banner and restore device rows to interactive state.
 */
function hideRelayErrorBanner() {
  if (!relayErrorActive) return;
  relayErrorActive = false;

  if (relayCountdownHandle) {
    clearInterval(relayCountdownHandle);
    relayCountdownHandle = null;
  }

  const mainList = document.getElementById('main-list');
  if (mainList) mainList.classList.remove('relay-error');

  const banner = document.getElementById('error-banner');
  if (banner) banner.remove();

  renderDeviceRowsOnly();
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

// ---------------------------------------------------------------------------
// Phase 2b — Selection model
// ---------------------------------------------------------------------------

/**
 * Update the selected device visually and in state.
 * Removes `.selected` from all device rows, applies it to the row matching
 * newDeviceId, and scrolls that row into view.
 *
 * @param {string|null} newDeviceId
 */
function updateSelection(newDeviceId) {
  selectedDeviceId = newDeviceId;

  const rows = document.querySelectorAll('#device-list .device-row');
  rows.forEach(r => r.classList.remove('selected'));

  if (!newDeviceId) return;

  const target = document.querySelector(`#device-list .device-row[data-id="${CSS.escape(newDeviceId)}"]`);
  if (target) {
    target.classList.add('selected');
    target.scrollIntoView({ block: 'nearest' });
  }
}

/**
 * Get the ordered list of visible online device IDs from the DOM.
 * During filter mode, only non-hidden rows are included.
 *
 * @returns {string[]}
 */
function getOnlineDeviceIds() {
  const rows = document.querySelectorAll('#device-list .device-row:not(.offline)');
  const ids = [];
  for (const row of rows) {
    // Skip rows hidden by the filter (display:none).
    if (row.offsetParent === null && row.style.display === 'none') continue;
    if (row.dataset.id) ids.push(row.dataset.id);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// Phase 2b — Filter state machine
// ---------------------------------------------------------------------------

/** Whether the device filter bar is currently active. */
let filterActive = false;

/** The device selection before the filter was activated, to restore on cancel. */
let preFilterSelection = null;

/**
 * Activate the filter bar: insert the filter-bar element above the device
 * section header, focus the input, and add `.filter-active` to #main-list.
 */
function activateFilter() {
  if (filterActive) return;
  filterActive = true;
  preFilterSelection = selectedDeviceId;

  const mainList = document.getElementById('main-list');
  if (!mainList) return;

  // Build and insert filter bar at the top of #main-list.
  const bar = document.createElement('div');
  bar.id = 'filter-bar';
  bar.innerHTML = `
    <span class="filter-prefix">/</span>
    <input type="text" id="filter-input" placeholder="Filter devices" autocomplete="off" aria-label="Filter devices">
    <span class="filter-hint">esc</span>
  `;
  mainList.insertBefore(bar, mainList.firstChild);
  mainList.classList.add('filter-active');

  const input = document.getElementById('filter-input');
  if (input) {
    input.focus();
    input.addEventListener('input', handleFilterInput);
  }
}

/**
 * Deactivate the filter bar: remove the element, restore device list visibility,
 * restore the prior selection, and remove `.filter-active`.
 */
function deactivateFilter() {
  if (!filterActive) return;
  filterActive = false;

  const bar = document.getElementById('filter-bar');
  if (bar) bar.remove();

  const mainList = document.getElementById('main-list');
  if (mainList) mainList.classList.remove('filter-active');

  // Restore all device rows to visible.
  const rows = document.querySelectorAll('#device-list .device-row');
  rows.forEach(r => { r.style.display = ''; });

  // Restore the Devices section header to its original text.
  const header = document.querySelector('#main-list .section-header');
  if (header) header.textContent = 'Devices';

  // Restore prior selection.
  updateSelection(preFilterSelection);
  preFilterSelection = null;
}

/**
 * Handle input events on the filter text field.
 * Filters device rows by prefix+substring match on device alias (case-insensitive).
 * Updates the Devices section header with a count, and auto-selects the first match.
 *
 * @param {Event} e
 */
function handleFilterInput(e) {
  const query = (e.target.value || '').toLowerCase();
  const rows = document.querySelectorAll('#device-list .device-row');
  let visibleCount = 0;
  const totalCount = rows.length;
  let firstVisibleId = null;

  rows.forEach(r => {
    const name = (r.querySelector('.row-name')?.textContent || '').toLowerCase();
    const matches = !query || name.includes(query);
    r.style.display = matches ? '' : 'none';
    if (matches) {
      visibleCount++;
      if (!firstVisibleId) firstVisibleId = r.dataset.id;
    }
  });

  // Update section header with count.
  const header = document.querySelector('#main-list .section-header');
  if (header) {
    header.textContent = query
      ? `Devices ${visibleCount} of ${totalCount}`
      : 'Devices';
  }

  // Auto-select the first visible online device.
  const onlineIds = getOnlineDeviceIds();
  if (onlineIds.length > 0) {
    updateSelection(onlineIds[0]);
  } else if (firstVisibleId) {
    updateSelection(firstVisibleId);
  } else {
    updateSelection(null);
  }
}

// ---------------------------------------------------------------------------
// Phase 2b — Global keyboard handler
// ---------------------------------------------------------------------------

/**
 * Returns the name of the currently visible view.
 * @returns {'main'|'pairing'|'sas'|'naming'|'settings'}
 */
function currentView() {
  const views = ['main', 'pairing', 'sas', 'naming', 'settings'];
  for (const v of views) {
    const el = document.getElementById(`view-${v}`);
    if (el && !el.classList.contains('hidden')) return v;
  }
  return 'main';
}

/**
 * Global keydown handler implementing Raycast/Linear-style keyboard navigation.
 * Attached to `document` in setupEventListeners().
 *
 * @param {KeyboardEvent} e
 */
function handleGlobalKeydown(e) {
  const tag = e.target.tagName;
  const isInputFocused = tag === 'INPUT' || tag === 'TEXTAREA';

  // Escape always works, even when an input is focused.
  if (e.key === 'Escape') {
    e.preventDefault();

    // If filter is active, clear it first.
    if (filterActive) {
      deactivateFilter();
      return;
    }

    // Phase 2c: if the selected device has a failed transfer, dismiss the error.
    if (selectedDeviceId && activeTransfersByDevice.has(selectedDeviceId)) {
      const xfer = activeTransfersByDevice.get(selectedDeviceId);
      if (xfer && xfer.state === 'failed') {
        activeTransfersByDevice.delete(selectedDeviceId);
        renderDeviceRowsOnly();
        return;
      }
    }

    // If on a non-main view, return to main.
    const view = currentView();
    if (view !== 'main') {
      // Clean up pairing state if leaving pairing view.
      if (view === 'pairing') {
        if (pinTimerHandle) { clearInterval(pinTimerHandle); pinTimerHandle = null; }
        cancelPairingRelay();
        pendingPairing = null;
        pairingDeviceId = null;
      }
      showView('main');
      return;
    }

    // On main view with nothing else active — close popup.
    window.close();
    return;
  }

  // All other shortcuts are suppressed when a text input is focused.
  if (isInputFocused) return;

  // Only handle shortcuts when on main view (except Escape handled above).
  const view = currentView();

  switch (e.key) {
    case 'ArrowDown':
    case 'ArrowUp': {
      if (view !== 'main') return;
      e.preventDefault();

      const ids = getOnlineDeviceIds();
      if (ids.length === 0) return;

      const currentIndex = ids.indexOf(selectedDeviceId);
      let nextIndex;

      if (e.key === 'ArrowDown') {
        nextIndex = currentIndex < 0 ? 0 : (currentIndex + 1) % ids.length;
      } else {
        nextIndex = currentIndex <= 0 ? ids.length - 1 : currentIndex - 1;
      }

      updateSelection(ids[nextIndex]);
      break;
    }

    case 'Enter': {
      if (view !== 'main') return;
      e.preventDefault();

      // In filter mode, commit to the top filtered result and deactivate.
      if (filterActive) {
        const ids = getOnlineDeviceIds();
        if (ids.length > 0) {
          updateSelection(ids[0]);
          preFilterSelection = ids[0]; // so deactivate restores to this
        }
        deactivateFilter();
        // Fall through to trigger the device click behavior below.
      }

      if (!selectedDeviceId) return;

      // Phase 2c: if the selected device has a failed transfer, retry it.
      const xferState = activeTransfersByDevice.get(selectedDeviceId);
      if (xferState && xferState.state === 'failed') {
        retryTransfer(selectedDeviceId);
        return;
      }

      // Check if the selected device is online.
      const device = currentDevices.find(d => d.deviceId === selectedDeviceId);
      if (!device || !device.isOnline) return;

      // Simulate the device row click — trigger file picker (same as clicking
      // the row's trailing "send" text). This is the existing send trigger.
      const row = document.querySelector(
        `#device-list .device-row[data-id="${CSS.escape(selectedDeviceId)}"]`
      );
      if (row) {
        // Pulse to indicate "ready to send" — if there's no staged content,
        // this gives visual feedback that Enter was registered.
        row.classList.add('pulse');
        setTimeout(() => row.classList.remove('pulse'), 300);

        // Trigger the file picker as the send action.
        el('file-input').click();
      }
      break;
    }

    case '/': {
      if (view !== 'main') return;
      e.preventDefault();
      activateFilter();
      break;
    }

    case 'p': {
      if (view !== 'main') return;
      e.preventDefault();
      showPairingView();
      break;
    }

    case ',': {
      if (view !== 'main') return;
      e.preventDefault();
      showSettingsView();
      break;
    }
  }
}

// Attach the global keyboard handler.
document.addEventListener('keydown', handleGlobalKeydown);
