/**
 * @file shared/transfer-history.js
 * @description Read/write helpers for the persisted transfer-history list
 *   (chrome.storage.session → `transferHistory`).
 *
 * Schema (Task 12):
 *
 *   {
 *     transferId:        string,
 *     deviceId:          string,            // remote peer
 *     direction:         'out' | 'in',
 *     fileName:          string,
 *     fileSize:          number,
 *     mimeType?:         string,
 *     status:            'completed' | 'failed',
 *     timestamp:         number,            // ms since epoch (sentAt for
 *                                           // completed; failedAt for failed)
 *     reason?:           string,            // failure code, e.g.
 *                                           // 'PEER_UNREACHABLE'. Only set
 *                                           // when status === 'failed'.
 *     targetDeviceName?: string,
 *   }
 *
 * Backwards compatibility: legacy entries written by earlier builds may lack a
 * `status` field. {@link normalizeHistoryEntries} backfills them as
 * `'completed'` at read time so the popup branch on `status === 'failed'`
 * stays sound. We do NOT migrate stored data — the backfill is purely a
 * read-side default.
 *
 * @module shared/transfer-history
 */

import { MAX_TRANSFER_HISTORY } from './constants.js';

/**
 * Storage key in chrome.storage.session that holds the transfer history.
 */
export const TRANSFER_HISTORY_KEY = 'transferHistory';

/**
 * Read-side backfill: any legacy entry without a `status` field is treated
 * as `'completed'`. Returns a new array; does not mutate inputs.
 *
 * @param {Array<object>} entries - Raw entries as loaded from storage.
 * @returns {Array<object>} Entries with `status` guaranteed to be a string.
 */
export function normalizeHistoryEntries(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.map((e) => {
    if (e && typeof e === 'object' && typeof e.status !== 'string') {
      return { ...e, status: 'completed' };
    }
    return e;
  });
}

/**
 * Module-scope serialisation queue. {@link appendHistoryEntry} chains every
 * call onto this promise so concurrent invocations cannot race the
 * read-modify-write against `chrome.storage.session`. Without this, a user
 * mass-firing failed sends (e.g. a peer that just went unreachable) would see
 * one entry per pair-of-overlapping-appends silently lost — the second `set`
 * clobbers the first because both `get`s read the same pre-write list.
 *
 * Failures inside one append must not poison the queue, so we trap them.
 * Callers receive their own promise from {@link appendHistoryEntry}, so they
 * still see the rejection — only the chain's continuation is shielded.
 *
 * @type {Promise<unknown>}
 */
let _writeQueue = Promise.resolve();

/**
 * Append a new history entry to chrome.storage.session and trim the list to
 * {@link MAX_TRANSFER_HISTORY} most-recent items.
 *
 * Newest entries are stored first (the popup activity list sorts by timestamp
 * but the cap preserves recency). Returns the persisted list for convenience.
 *
 * Concurrent calls are serialised via a module-scope promise chain — see
 * {@link _writeQueue}.
 *
 * The caller is expected to provide a fully-formed entry; this helper does
 * not synthesise timestamps or transferIds — keeping write-site responsibility
 * explicit makes it easy to test the SW path without time-mocking the helper.
 *
 * @param {object} entry - History entry conforming to the schema above.
 * @param {{
 *   storage?: { get: Function, set: Function },
 *   max?: number,
 * }} [opts] - DI seam for tests; defaults to `chrome.storage.session` and
 *   {@link MAX_TRANSFER_HISTORY}.
 * @returns {Promise<Array<object>>} The persisted (capped) list.
 */
export function appendHistoryEntry(entry, opts = {}) {
  const result = _writeQueue.then(() => _doAppend(entry, opts));
  // Swallow rejections on the queue's continuation so one failed write does
  // not break every subsequent caller. The current caller still sees the
  // rejection on `result`.
  _writeQueue = result.catch(() => {});
  return result;
}

async function _doAppend(entry, opts) {
  const storage = opts.storage || chrome.storage.session;
  const max = typeof opts.max === 'number' ? opts.max : MAX_TRANSFER_HISTORY;

  const stored = await storage.get(TRANSFER_HISTORY_KEY);
  const existing = Array.isArray(stored?.[TRANSFER_HISTORY_KEY])
    ? stored[TRANSFER_HISTORY_KEY]
    : [];

  // Newest-first; cap at `max`. Use a fresh array to avoid mutating the
  // caller's reference when storage returns a live object (test stubs).
  const next = [entry, ...existing].slice(0, max);
  await storage.set({ [TRANSFER_HISTORY_KEY]: next });
  return next;
}

/**
 * Build a `status:'failed'` history entry for the SW SEND_FILE failure path.
 *
 * @param {{
 *   transferId?: string,
 *   deviceId: string,
 *   fileName: string,
 *   fileSize: number,
 *   mimeType?: string,
 *   reason: string,
 *   failedAt?: number,
 * }} fields
 * @returns {object} A history entry ready to pass to {@link appendHistoryEntry}.
 */
export function buildFailedEntry(fields) {
  const now = typeof fields.failedAt === 'number' ? fields.failedAt : Date.now();
  return {
    transferId: fields.transferId || `failed-${now}`,
    deviceId:   fields.deviceId,
    direction:  'out',
    fileName:   fields.fileName,
    fileSize:   fields.fileSize,
    mimeType:   fields.mimeType,
    status:     'failed',
    timestamp:  now,
    reason:     fields.reason,
  };
}
