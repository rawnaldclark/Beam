/**
 * @file background.js
 * @description Beam service worker — thin dispatcher that owns Chrome APIs and
 * delegates all heavy work (crypto, WebRTC, WebSocket) to the offscreen document.
 *
 * Responsibilities:
 *   - Keep the service worker alive via a Chrome alarm (alarms survive worker
 *     suspension; sending a ping to the offscreen document re-activates it).
 *   - Route chrome.runtime messages between the popup and the offscreen doc.
 *   - Own context menus (requires service-worker context to register/update).
 *   - Own chrome.notifications (requires service-worker context).
 *   - Own keyboard shortcuts (chrome.commands API).
 *   - Fetch images on behalf of the offscreen doc (cross-origin fetches are
 *     permitted in the service worker but not in the offscreen document).
 *
 * Design notes:
 *   - The service worker is intentionally "thin": it contains no crypto, no
 *     connection state, and no transfer logic.  All of that lives in the
 *     offscreen document (transfer-engine.js), which persists as long as the
 *     alarm keeps it alive.
 *   - Chrome alarms fire at most once per minute (Chrome's minimum period is
 *     1 minute for Manifest V3 service workers).  We clamp the computed period
 *     to at least 1 minute even though KEEPALIVE_INTERVAL_MS is shorter, so
 *     the alarm itself acts as a "wake-up" signal rather than a precise timer.
 *   - Context menu item IDs use prefixes to disambiguate action type:
 *       img_{deviceId}   — send image
 *       link_{deviceId}  — send link
 *       text_{deviceId}  — send selected text
 */

import { MSG }                  from './shared/message-types.js';
import { KEEPALIVE_INTERVAL_MS } from './shared/constants.js';
import { startPairingListener, stopPairingListener, sendPairingMessage, sendBinary } from './background-relay.js';

// ---------------------------------------------------------------------------
// Badge state — tracks a pending "failure" clear so we can dismiss it on the
// next meaningful interaction rather than on a fixed timer.
// ---------------------------------------------------------------------------

/**
 * When the badge shows an error indicator ("!") we record the notification ID
 * so that the next INITIATE_TRANSFER or context-menu click can clear it.
 *
 * @type {boolean}
 */
let badgeShowingFailure = false;

// ---------------------------------------------------------------------------
// Service worker lifecycle
// ---------------------------------------------------------------------------

/**
 * On install: register the keepalive alarm so the offscreen document is
 * never left dormant for longer than one Chrome alarm period (~1 minute).
 */
chrome.runtime.onInstalled.addListener(() => {
  const periodInMinutes = Math.max(1, KEEPALIVE_INTERVAL_MS / 60_000);
  chrome.alarms.create('keepalive', { periodInMinutes });
  autoStartRelayIfPaired();
});

/**
 * On browser startup: ensure the offscreen document is running so the
 * extension is ready before the user interacts with the popup.
 */
chrome.runtime.onStartup.addListener(() => {
  ensureOffscreen();
  autoStartRelayIfPaired();
});

// Auto-start on SW initialization (fires every time SW wakes up)
autoStartRelayIfPaired();

/**
 * If the user has previously paired, automatically start the relay listener
 * so incoming messages (clipboard, files) work without the user opening the popup.
 */
async function autoStartRelayIfPaired() {
  try {
    const stored = await chrome.storage.local.get(['deviceId', 'deviceKeys', 'pairedDevices']);
    if (!stored.deviceId || !stored.deviceKeys?.ed25519?.sk || !stored.pairedDevices?.length) {
      return; // Not paired yet
    }
    console.log('[Beam SW] Auto-starting relay listener for paired session');
    await startPairingListener(
      stored.deviceId,
      stored.deviceKeys.ed25519.sk,
      stored.deviceKeys.ed25519.pk
    );
  } catch (err) {
    console.error('[Beam SW] Auto-start relay failed:', err);
  }
}

// ---------------------------------------------------------------------------
// Alarm handler — keepalive ping
// ---------------------------------------------------------------------------

/**
 * When the keepalive alarm fires, ping the offscreen document.  If the ping
 * fails (offscreen document not running), recreate it.
 */
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'keepalive') return;

  try {
    await chrome.runtime.sendMessage({ type: MSG.KEEPALIVE_PING });
  } catch {
    // Offscreen document is not running (e.g. after a browser restart).
    await ensureOffscreen();
  }
});

// ---------------------------------------------------------------------------
// Message router
// ---------------------------------------------------------------------------

/**
 * Route messages from the popup and offscreen document.
 *
 * Returns `true` from the listener only when we call sendResponse
 * asynchronously (required by Chrome's message-passing contract).
 *
 * @param {object}   msg        - Message object with at least a `type` field.
 * @param {object}   sender     - MessageSender (unused here but kept for clarity).
 * @param {Function} sendResponse - Callback to send a reply.
 * @returns {boolean} true if sendResponse will be called asynchronously.
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {

    // ── Badge update ────────────────────────────────────────────────────────
    case MSG.UPDATE_BADGE:
      handleBadgeUpdate(msg.payload);
      break;

    // ── Desktop notification ────────────────────────────────────────────────
    case MSG.SEND_NOTIFICATION:
      createNotification(msg.payload);
      break;

    // ── Device presence — rebuild context menus ─────────────────────────────
    case MSG.DEVICE_PRESENCE_CHANGED:
      rebuildContextMenus(msg.payload.devices ?? []);
      break;

    // ── Storage relay for offscreen document (which can't access chrome.storage) ──
    case 'STORAGE_GET':
      chrome.storage.local.get(msg.payload.keys).then(data => {
        sendResponse({ data });
      });
      return true; // async

    case 'STORAGE_SET':
      chrome.storage.local.set(msg.payload.data).then(() => {
        sendResponse({ ok: true });
      });
      return true; // async

    // ── Image fetch — must happen in SW (cross-origin fetch allowed here) ───
    case MSG.FETCH_IMAGE:
      fetchImageForOffscreen(msg.payload.url)
        .then(data  => sendResponse({ type: MSG.IMAGE_FETCHED, payload: { data } }))
        .catch(err  => sendResponse({ type: MSG.IMAGE_FETCHED, payload: { error: err.message } }));
      return true; // async sendResponse

    // ── Pairing relay (runs in SW so it survives popup close) ────────────────
    case 'START_PAIRING_LISTENER': {
      console.log('[Beam SW] START_PAIRING_LISTENER received, deviceId:', msg.payload?.deviceId);
      const { deviceId, ed25519Sk, ed25519Pk } = msg.payload;
      startPairingListener(deviceId, ed25519Sk, ed25519Pk)
        .then(() => {
          console.log('[Beam SW] Pairing listener started successfully');
          sendResponse({ ok: true });
        })
        .catch(err => {
          console.error('[Beam SW] Pairing listener failed:', err.message);
          sendResponse({ ok: false, error: err.message });
        });
      return true; // async sendResponse
    }

    case 'STOP_PAIRING_LISTENER':
      stopPairingListener();
      break;

    case 'SEND_PAIRING_MESSAGE':
      sendPairingMessage(msg.payload);
      break;

    // ── File transfer via relay binary channel ──────────────────────────────
    case 'SEND_FILE': {
      const transferId = sendFileViaRelay(msg.payload);
      sendResponse({ ok: true, transferId });
      return true;
    }

    // ── Clipboard transfer via relay WebSocket ─────────────────────────────
    case 'SEND_CLIPBOARD': {
      const { content, targetDeviceId, rendezvousId } = msg.payload;
      sendPairingMessage({
        type: 'clipboard-transfer',
        targetDeviceId,
        rendezvousId,
        content,
      });
      sendResponse({ ok: true });
      break;
    }

    // ── All other messages — forward to offscreen document ─────────────────
    default: {
      // Messages like START_PAIRING, GET_DEVICE_LIST, PAIRING_CONFIRM_SAS, etc.
      // are handled by the offscreen document. The popup can't talk to it directly
      // so we forward: ensure offscreen exists, re-send with a _forwarded flag
      // so our own listener ignores the echo, and pipe the response back.
      if (msg._forwarded) return false; // ignore our own re-broadcast
      ensureOffscreen().then(async () => {
        try {
          const response = await chrome.runtime.sendMessage({ ...msg, _forwarded: true });
          sendResponse(response);
        } catch {
          sendResponse(null);
        }
      });
      return true; // async sendResponse
    }

  }
});

// ---------------------------------------------------------------------------
// Context menu clicks
// ---------------------------------------------------------------------------

/**
 * Handle a context menu click by sending the selected content to the target
 * device via the working SEND_CLIPBOARD / SEND_FILE relay paths.
 *
 * Menu item IDs are formatted as "{prefix}_{deviceId}" where prefix is one of
 * "img", "link", or "text".  We parse the prefix to determine what content
 * type to send and dispatch directly through sendPairingMessage/sendFileViaRelay.
 *
 * @param {chrome.contextMenus.OnClickData} info - Click metadata.
 * @param {chrome.tabs.Tab}                 tab  - The tab in which the click occurred.
 */
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  // Clear any lingering failure badge when the user initiates a new transfer.
  badgeShowingFailure = false;
  clearBadge();

  // Parse menu item ID: "img_{deviceId}" / "link_{deviceId}" / "text_{deviceId}"
  const menuId = String(info.menuItemId);
  const match  = menuId.match(/^(img|link|text)_(.+)$/);
  if (!match) return;

  const [, type, deviceId] = match;

  // Look up our own deviceId — this is the rendezvousId both sides registered
  // during pairing, and the SW uses it as the from-identity for outgoing msgs.
  const { deviceId: ownDeviceId } = await chrome.storage.local.get('deviceId');
  if (!ownDeviceId) {
    console.error('[Beam SW] Cannot send: no deviceId stored');
    return;
  }
  const rendezvousId = ownDeviceId;

  if (type === 'link') {
    sendPairingMessage({
      type:           'clipboard-transfer',
      targetDeviceId: deviceId,
      rendezvousId,
      content:        info.linkUrl,
    });
    notifySent('Link sent');
    return;
  }

  if (type === 'text') {
    sendPairingMessage({
      type:           'clipboard-transfer',
      targetDeviceId: deviceId,
      rendezvousId,
      content:        info.selectionText,
    });
    notifySent('Text sent');
    return;
  }

  if (type === 'img') {
    try {
      const imageData = await fetchImageForOffscreen(info.srcUrl);

      // Convert the plain-array byte data to base64 (SEND_FILE expects base64).
      const bytes = new Uint8Array(imageData.data);
      let binStr  = '';
      const SLICE = 32768;
      for (let i = 0; i < bytes.length; i += SLICE) {
        binStr += String.fromCharCode.apply(null, bytes.subarray(i, i + SLICE));
      }
      const base64 = btoa(binStr);

      // Derive a filename from the image URL pathname.
      let fileName = 'image.jpg';
      try {
        const urlPath = new URL(info.srcUrl).pathname;
        const last    = urlPath.split('/').pop();
        if (last) fileName = last;
      } catch { /* fallback default */ }

      sendFileViaRelay({
        fileName,
        fileSize:       imageData.size,
        mimeType:       imageData.mimeType || 'image/jpeg',
        data:           base64,
        targetDeviceId: deviceId,
        rendezvousId,
      });
      notifySent('Image sending…');
    } catch (err) {
      console.error('[Beam SW] Image fetch failed:', err);
      chrome.notifications.create('beam-err-' + Date.now(), {
        type:    'basic',
        iconUrl: 'icons/icon-128.png',
        title:   'Beam',
        message: 'Failed to fetch image: ' + err.message,
      });
    }
  }
});

/**
 * Show a transient "sent" notification after a context-menu or shortcut action.
 *
 * @param {string} message - Short user-facing message for the notification body.
 */
function notifySent(message) {
  chrome.notifications.create('beam-sent-' + Date.now(), {
    type:    'basic',
    iconUrl: 'icons/icon-128.png',
    title:   'Beam',
    message,
  });
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

/**
 * Handle keyboard commands declared in manifest.json's `commands` section.
 *
 * "send-clipboard"     — read the active tab's clipboard and send to the first
 *                        online paired device via the working relay path.
 * "open-device-picker" — open the extension popup for manual device selection.
 *
 * @param {string} command - Command name as declared in the manifest.
 */
chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'send-clipboard') {
    badgeShowingFailure = false;
    clearBadge();

    const target = await findTargetDevice();
    if (!target) {
      chrome.notifications.create('beam-err-' + Date.now(), {
        type:    'basic',
        iconUrl: 'icons/icon-128.png',
        title:   'Beam',
        message: 'No paired device to send to',
      });
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      // Inject a small snippet into the active tab to read the clipboard;
      // the service worker has no DOM, so navigator.clipboard is unavailable here.
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func:   async () => {
          try {
            return await navigator.clipboard.readText();
          } catch {
            return null;
          }
        },
      });

      const text = result?.result;
      if (!text) {
        chrome.notifications.create('beam-err-' + Date.now(), {
          type:    'basic',
          iconUrl: 'icons/icon-128.png',
          title:   'Beam',
          message: 'Clipboard is empty or permission denied',
        });
        return;
      }

      sendPairingMessage({
        type:           'clipboard-transfer',
        targetDeviceId: target.deviceId,
        rendezvousId:   target.rendezvousId,
        content:        text,
      });

      chrome.notifications.create('beam-sent-' + Date.now(), {
        type:    'basic',
        iconUrl: 'icons/icon-128.png',
        title:   'Beam',
        message: `Clipboard sent to ${target.name}`,
      });
    } catch (err) {
      console.error('[Beam SW] Clipboard read failed:', err);
      chrome.notifications.create('beam-err-' + Date.now(), {
        type:    'basic',
        iconUrl: 'icons/icon-128.png',
        title:   'Beam',
        message: 'Failed to read clipboard: ' + err.message,
      });
    }
    return;
  }

  if (command === 'open-device-picker') {
    // chrome.action.openPopup() is available in Chrome 127+.  Fall back to a
    // notification that guides the user to click the extension icon when the
    // API is absent (e.g. older Chrome or a non-active-tab context).
    if (typeof chrome.action.openPopup === 'function') {
      try {
        await chrome.action.openPopup();
      } catch {
        // openPopup can throw if the active window isn't a normal browser
        // window (e.g. a devtools window).  Show the fallback notification.
        showOpenPopupFallbackNotification();
      }
    } else {
      showOpenPopupFallbackNotification();
    }
  }
});

// ---------------------------------------------------------------------------
// Notification button clicks
// ---------------------------------------------------------------------------

/**
 * Forward notification button clicks to the offscreen document so it can
 * act on user responses (e.g. "Open" / "Save" on an incoming file, or
 * "Retry" on a failed transfer).
 *
 * The type string "NOTIFICATION_ACTION" is intentionally not in the MSG
 * freeze object because it is a SW-internal routing concern; the offscreen
 * document and popup each handle it by matching this literal string.
 *
 * @param {string} notifId     - The notification ID (same as the transfer ID
 *                               embedded by createNotification).
 * @param {number} buttonIndex - Zero-based index of the clicked button.
 */
chrome.notifications.onButtonClicked.addListener((notifId, buttonIndex) => {
  chrome.runtime.sendMessage({
    type:    'NOTIFICATION_ACTION',
    payload: { notifId, buttonIndex },
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create the offscreen document if it does not already exist.
 *
 * The offscreen document hosts the transfer engine (WebRTC, WebSocket,
 * crypto).  Chrome only allows one offscreen document per extension; the
 * `hasDocument` check prevents "already exists" errors on repeated calls.
 *
 * @returns {Promise<void>}
 */
async function ensureOffscreen() {
  // chrome.offscreen.hasDocument is available in Chrome 116+.
  if (await chrome.offscreen.hasDocument?.()) return;

  try {
    await chrome.offscreen.createDocument({
      url:           'offscreen/transfer-engine.html',
      reasons:       ['WORKERS'],
      justification: 'WebRTC data channels and WebSocket connections for file transfer',
    });
  } catch {
    // Document was created by a concurrent call — safe to ignore.
  }
}

/**
 * Build (or rebuild) the right-click context menus based on the current list
 * of online paired devices.
 *
 * Three menu items are created per online device — one each for image, link,
 * and text selection contexts.  If no devices are online a single disabled
 * placeholder item is shown.
 *
 * @param {Array<{deviceId: string, name: string, isOnline: boolean}>} devices
 *   All known paired devices (online and offline).
 */
function rebuildContextMenus(devices) {
  chrome.contextMenus.removeAll(() => {
    const onlineDevices = devices.filter(d => d.isOnline);

    if (onlineDevices.length === 0) {
      chrome.contextMenus.create({
        id:       'beam-none',
        title:    'No devices online',
        enabled:  false,
        contexts: ['all'],
      });
      return;
    }

    for (const device of onlineDevices) {
      // Image context menu — shown on right-click of an image element.
      chrome.contextMenus.create({
        id:       `img_${device.deviceId}`,
        title:    `Send image to ${device.name}`,
        contexts: ['image'],
      });

      // Link context menu — shown on right-click of a hyperlink.
      chrome.contextMenus.create({
        id:       `link_${device.deviceId}`,
        title:    `Send link to ${device.name}`,
        contexts: ['link'],
      });

      // Selection context menu — shown when text is selected.
      chrome.contextMenus.create({
        id:       `text_${device.deviceId}`,
        title:    `Send text to ${device.name}`,
        contexts: ['selection'],
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Badge helpers
// ---------------------------------------------------------------------------

/**
 * Handle a structured badge-update request.
 *
 * Recognised `status` values:
 *   "progress"  — transfer in flight.  `percent` (0-100) is required.
 *                 Shows e.g. "47%" with a blue background.
 *   "complete"  — transfer succeeded.  Shows a checkmark with green
 *                 background; auto-clears after 3 seconds.
 *   "failure"   — transfer failed.  Shows "!" with a red background.
 *                 Remains until the user triggers the next transfer.
 *   "clear"     — unconditionally clear the badge (e.g. on idle).
 *
 * Legacy payloads that pass raw `text` / `color` fields directly are still
 * accepted for backwards compatibility.
 *
 * @param {{ status?: string, percent?: number, text?: string, color?: string }} payload
 */
function handleBadgeUpdate(payload) {
  const { status, percent } = payload;

  switch (status) {
    case 'progress': {
      // Clamp to 0-100 and format as an integer percentage string.
      const pct = Math.max(0, Math.min(100, Math.round(percent ?? 0)));
      badgeShowingFailure = false;
      chrome.action.setBadgeBackgroundColor({ color: '#4285F4' }); // Google blue
      chrome.action.setBadgeText({ text: `${pct}%` });
      break;
    }

    case 'complete': {
      badgeShowingFailure = false;
      chrome.action.setBadgeBackgroundColor({ color: '#22c55e' }); // Tailwind green-500
      chrome.action.setBadgeText({ text: '\u2713' }); // Unicode checkmark ✓

      // Auto-clear after 3 seconds so the badge does not persist indefinitely.
      setTimeout(clearBadge, 3_000);
      break;
    }

    case 'failure': {
      badgeShowingFailure = true;
      chrome.action.setBadgeBackgroundColor({ color: '#EA4335' }); // Google red
      chrome.action.setBadgeText({ text: '!' });
      break;
    }

    case 'clear': {
      clearBadge();
      break;
    }

    default: {
      // Legacy path: caller supplies raw text/color.
      badgeShowingFailure = false;
      chrome.action.setBadgeText({ text: payload.text ?? '' });
      chrome.action.setBadgeBackgroundColor({ color: payload.color ?? '#4285F4' });
    }
  }
}

/**
 * Remove the badge text and reset failure state.
 */
function clearBadge() {
  badgeShowingFailure = false;
  chrome.action.setBadgeText({ text: '' });
}

// ---------------------------------------------------------------------------
// Notification helpers
// ---------------------------------------------------------------------------

/**
 * Create a Chrome notification from a structured payload.
 *
 * Recognised `kind` values:
 *   "send-complete"      — outgoing transfer finished.
 *   "receive-complete"   — incoming transfer finished; offers Open / Save.
 *   "clipboard-received" — remote clipboard content arrived; shows preview.
 *   "transfer-failed"    — transfer failed; offers a Retry button.
 *
 * Legacy payloads without a `kind` field fall back to using the raw
 * `title` / `message` / `buttons` fields directly.
 *
 * @param {{
 *   kind?: string,
 *   id?: string,
 *   title?: string,
 *   message?: string,
 *   buttons?: Array<{title: string}>,
 *   fileName?: string,
 *   deviceName?: string,
 *   preview?: string,
 * }} payload
 */
function createNotification(payload) {
  const { kind } = payload;

  /** @type {string} */
  let title;
  /** @type {string} */
  let message;
  /** @type {Array<{title: string}>} */
  let buttons = [];

  switch (kind) {
    case 'send-complete':
      title   = 'Transfer complete';
      message = `Sent ${payload.fileName ?? 'file'} to ${payload.deviceName ?? 'device'}`;
      break;

    case 'receive-complete':
      title   = `${payload.deviceName ?? 'Device'} sent you a file`;
      message = payload.fileName ?? 'Unknown file';
      buttons = [{ title: 'Open' }, { title: 'Save' }];
      break;

    case 'clipboard-received': {
      title   = `Clipboard from ${payload.deviceName ?? 'device'}`;
      // Show up to 100 chars of the clipboard content as a preview.
      const preview = payload.preview ?? '';
      message = preview.length > 100 ? `${preview.slice(0, 97)}...` : preview;
      break;
    }

    case 'transfer-failed':
      title   = `Transfer to ${payload.deviceName ?? 'device'} failed`;
      message = payload.fileName ? `Could not send ${payload.fileName}` : 'Transfer did not complete';
      buttons = [{ title: 'Retry' }];
      break;

    default:
      // Legacy path: caller supplies raw title / message / buttons.
      title   = payload.title   ?? 'Beam';
      message = payload.message ?? '';
      buttons = payload.buttons ?? [];
  }

  chrome.notifications.create(payload.id ?? '', {
    type:    'basic',
    iconUrl: 'icons/icon-128.png',
    title,
    message,
    buttons,
  });
}

/**
 * Show a fallback notification when chrome.action.openPopup() is unavailable
 * or throws (e.g. non-standard window context).  Guides the user to open the
 * extension popup manually.
 */
function showOpenPopupFallbackNotification() {
  chrome.notifications.create('beam-open-popup', {
    type:    'basic',
    iconUrl: 'icons/icon-128.png',
    title:   'Beam',
    message: 'Click the Beam icon in the toolbar to open the device picker.',
  });
}

// ---------------------------------------------------------------------------
// Target device selection + file relay helpers
// ---------------------------------------------------------------------------

/**
 * Find the first online paired device, or fall back to the first paired device
 * if none are currently online.  Returns null when there are no paired devices.
 *
 * @returns {Promise<{deviceId: string, name: string, rendezvousId: string}|null>}
 *   Selected target device with the rendezvousId (our own deviceId) both sides
 *   registered during pairing, or null if no paired devices exist.
 */
async function findTargetDevice() {
  const [localData, sessionData] = await Promise.all([
    chrome.storage.local.get(['pairedDevices', 'deviceId']),
    chrome.storage.session.get('devicePresence'),
  ]);

  const devices     = localData?.pairedDevices || [];
  const presence    = sessionData?.devicePresence || {};
  const ownDeviceId = localData?.deviceId;

  const online   = devices.find(d => presence[d.deviceId]?.isOnline === true);
  const fallback = devices[0];
  const target   = online || fallback;

  if (!target) return null;

  return {
    deviceId:     target.deviceId,
    name:         target.name,
    // rendezvousId is Chrome's own deviceId — both sides registered it during pairing.
    rendezvousId: ownDeviceId,
  };
}

/**
 * Send a file via the pairing relay binary channel.
 *
 * Emits file-offer + relay-bind, waits briefly for the receiver to bind, then
 * streams base64-decoded bytes as chunked binary frames, finishing with
 * file-complete + relay-release.
 *
 * Shared between the SEND_FILE message handler (popup path) and the context
 * menu image handler so both code paths go through identical logic.
 *
 * @param {{
 *   fileName: string,
 *   fileSize: number,
 *   mimeType: string,
 *   data: string,                // base64-encoded file bytes
 *   targetDeviceId: string,
 *   rendezvousId: string,
 * }} payload
 * @returns {string} The generated transferId for this transfer.
 */
function sendFileViaRelay(payload) {
  const { fileName, fileSize, mimeType, data, targetDeviceId, rendezvousId } = payload;
  const transferId = 'tf-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);

  // Send file-offer + relay-bind, then wait for file-accept before sending data.
  sendPairingMessage({ type: 'file-offer', targetDeviceId, rendezvousId, fileName, fileSize, mimeType, transferId });
  sendPairingMessage({ type: 'relay-bind', transferId, targetDeviceId, rendezvousId });

  const _sendFileData = () => {
    const binaryStr = atob(data);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);

    const CHUNK_SIZE = 200 * 1024;
    let offset = 0;

    // Send chunks with small delays to avoid overwhelming the relay.
    function sendNextChunk() {
      if (offset >= bytes.length) {
        // All chunks sent — send file-complete + release after a brief pause.
        setTimeout(() => {
          sendPairingMessage({ type: 'file-complete', targetDeviceId, rendezvousId, transferId });
          sendPairingMessage({ type: 'relay-release', transferId });
          console.log('[Beam SW] File send complete:', fileName);
        }, 200);
        return;
      }
      const end = Math.min(offset + CHUNK_SIZE, bytes.length);
      sendBinary(bytes.slice(offset, end).buffer);
      offset = end;
      // 50ms between chunks — gives relay time to forward.
      setTimeout(sendNextChunk, 50);
    }
    sendNextChunk();
  };

  // Wait 2 seconds for receiver to bind, then start sending.
  // The receiver auto-assembles when bytesReceived >= fileSize.
  setTimeout(_sendFileData, 2000);

  return transferId;
}

// ---------------------------------------------------------------------------

/**
 * Fetch an image URL in the service worker context and return a transferable
 * representation for the offscreen document.
 *
 * Service workers may fetch cross-origin resources that are blocked by
 * Content Security Policy in other extension contexts.
 *
 * @param {string} url - The image URL to fetch.
 * @returns {Promise<{data: number[], mimeType: string, size: number}>}
 *   `data` is the raw bytes as a plain Array (JSON-serialisable).
 * @throws {Error} If the network request fails or the response is not OK.
 */
async function fetchImageForOffscreen(url) {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Fetch failed: ${response.status} ${response.statusText}`);
  }

  const blob   = await response.blob();
  const buffer = await blob.arrayBuffer();

  return {
    // Plain Array is JSON-serialisable; the offscreen doc reconstructs a Uint8Array.
    data:     Array.from(new Uint8Array(buffer)),
    mimeType: blob.type,
    size:     buffer.byteLength,
  };
}
