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

// ---------------------------------------------------------------------------
// Service worker lifecycle
// ---------------------------------------------------------------------------

/**
 * On install: register the keepalive alarm so the offscreen document is
 * never left dormant for longer than one Chrome alarm period (~1 minute).
 */
chrome.runtime.onInstalled.addListener(() => {
  // Chrome requires a minimum alarm period of 1 minute for MV3 service workers.
  // KEEPALIVE_INTERVAL_MS (25 s) is shorter than that, so we clamp to 1 minute.
  const periodInMinutes = Math.max(1, KEEPALIVE_INTERVAL_MS / 60_000);
  chrome.alarms.create('keepalive', { periodInMinutes });
});

/**
 * On browser startup: ensure the offscreen document is running so the
 * extension is ready before the user interacts with the popup.
 */
chrome.runtime.onStartup.addListener(ensureOffscreen);

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
      chrome.action.setBadgeText({ text: msg.payload.text ?? '' });
      chrome.action.setBadgeBackgroundColor({ color: msg.payload.color ?? '#4285F4' });
      break;

    // ── Desktop notification ────────────────────────────────────────────────
    case MSG.SEND_NOTIFICATION:
      chrome.notifications.create(msg.payload.id ?? '', {
        type:    'basic',
        iconUrl: 'icons/icon-128.png',
        title:   msg.payload.title,
        message: msg.payload.message,
        buttons: msg.payload.buttons ?? [],
      });
      break;

    // ── Device presence — rebuild context menus ─────────────────────────────
    case MSG.DEVICE_PRESENCE_CHANGED:
      rebuildContextMenus(msg.payload.devices ?? []);
      break;

    // ── Image fetch — must happen in SW (cross-origin fetch allowed here) ───
    case MSG.FETCH_IMAGE:
      fetchImageForOffscreen(msg.payload.url)
        .then(data  => sendResponse({ type: MSG.IMAGE_FETCHED, payload: { data } }))
        .catch(err  => sendResponse({ type: MSG.IMAGE_FETCHED, payload: { error: err.message } }));
      return true; // async sendResponse

  }
  // Synchronous path — no async sendResponse needed.
  return false;
});

// ---------------------------------------------------------------------------
// Context menu clicks
// ---------------------------------------------------------------------------

/**
 * Dispatch a context menu click to the offscreen transfer engine.
 *
 * Menu item IDs are formatted as "{prefix}_{deviceId}" where prefix is one of
 * "img", "link", or "text".  We parse the prefix to determine what content
 * type to send and build the payload from the ContextMenuInfo fields.
 *
 * @param {chrome.contextMenus.OnClickData} info - Click metadata.
 * @param {chrome.tabs.Tab}                 tab  - The tab in which the click occurred.
 */
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  await ensureOffscreen();

  // Parse prefix from menu item ID: "img_{deviceId}", "link_{deviceId}", "text_{deviceId}"
  const separatorIdx  = info.menuItemId.indexOf('_');
  const prefix        = info.menuItemId.slice(0, separatorIdx);
  const targetDeviceId = info.menuItemId.slice(separatorIdx + 1);

  /** @type {object} */
  const payload = { targetDeviceId };

  if (prefix === 'img' && info.srcUrl) {
    payload.type = 'image';
    payload.url  = info.srcUrl;
  } else if (prefix === 'link' && info.linkUrl) {
    payload.type    = 'link';
    payload.content = info.linkUrl;
  } else if (prefix === 'text' && info.selectionText) {
    payload.type    = 'text';
    payload.content = info.selectionText;
  }

  chrome.runtime.sendMessage({ type: MSG.INITIATE_TRANSFER, payload });
});

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

/**
 * Handle keyboard commands declared in manifest.json's `commands` section.
 *
 * "send-clipboard" — initiate a transfer of the current clipboard contents
 *                    to the last-used device.
 *
 * @param {string} command - Command name as declared in the manifest.
 */
chrome.commands.onCommand.addListener(async (command) => {
  await ensureOffscreen();

  if (command === 'send-clipboard') {
    chrome.runtime.sendMessage({
      type:    MSG.INITIATE_TRANSFER,
      payload: { type: 'clipboard', targetDevice: 'last-used' },
    });
  }
});

// ---------------------------------------------------------------------------
// Notification button clicks
// ---------------------------------------------------------------------------

/**
 * Forward notification button clicks to the offscreen document so it can
 * act on user responses (e.g. "Accept" / "Decline" on an incoming transfer).
 *
 * @param {string} notifId    - The notification ID.
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
