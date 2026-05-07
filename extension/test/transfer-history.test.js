/**
 * @file transfer-history.test.js
 * @description Tests for Task 12 — persisted transfer-history schema with
 *   `status:'completed'|'failed'` and the read-side backfill for legacy
 *   entries that pre-date the field. Also covers the broadcast-coalesce
 *   follow-up from Task 10 review (3 rapid observable emissions → 1
 *   chrome.runtime.sendMessage call).
 *
 * Run:  node --test test/transfer-history.test.js
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { installChromeStub, chromeStub } from './_helpers/chrome-stubs.js';

// Install the chrome stub before importing modules that touch chrome.*.
installChromeStub();

// eslint-disable-next-line import/first
const transferHistory = await import('../shared/transfer-history.js');
// eslint-disable-next-line import/first
const wiring = await import('../connection/connection-authority-wiring.js');

const {
  appendHistoryEntry,
  buildFailedEntry,
  normalizeHistoryEntries,
  TRANSFER_HISTORY_KEY,
} = transferHistory;
const {
  ensureConnectionAuthority,
  installPopupBroadcaster,
  _resetConnectionAuthority,
} = wiring;

// ─── Reader: legacy backfill ─────────────────────────────────────────────────

describe('normalizeHistoryEntries: legacy backfill', () => {
  it('treats entries without a status field as status:completed', () => {
    const out = normalizeHistoryEntries([
      { transferId: 'a', fileName: 'a.txt', fileSize: 10, timestamp: 1 },
      { transferId: 'b', fileName: 'b.txt', fileSize: 20, timestamp: 2 },
    ]);
    assert.equal(out.length, 2);
    assert.equal(out[0].status, 'completed');
    assert.equal(out[1].status, 'completed');
  });

  it('preserves an explicit status:failed', () => {
    const out = normalizeHistoryEntries([
      { transferId: 'x', fileName: 'x.txt', fileSize: 1, timestamp: 1,
        status: 'failed', reason: 'PEER_UNREACHABLE' },
    ]);
    assert.equal(out[0].status, 'failed');
    assert.equal(out[0].reason, 'PEER_UNREACHABLE');
  });

  it('preserves an explicit status:completed', () => {
    const out = normalizeHistoryEntries([
      { transferId: 'y', fileName: 'y.txt', fileSize: 1, timestamp: 1,
        status: 'completed' },
    ]);
    assert.equal(out[0].status, 'completed');
  });

  it('returns [] for non-array inputs (defensive)', () => {
    assert.deepEqual(normalizeHistoryEntries(null), []);
    assert.deepEqual(normalizeHistoryEntries(undefined), []);
    assert.deepEqual(normalizeHistoryEntries('garbage'), []);
  });

  it('does not mutate the input entries', () => {
    const input = [{ transferId: 'a', fileName: 'a.txt', fileSize: 10 }];
    normalizeHistoryEntries(input);
    assert.equal(input[0].status, undefined,
      'reader-side default must not write back to the input array');
  });
});

// ─── Writer: buildFailedEntry + appendHistoryEntry ──────────────────────────

describe('buildFailedEntry', () => {
  it('produces a status:failed entry with the failure metadata', () => {
    const entry = buildFailedEntry({
      deviceId: 'peer-1',
      fileName: 'photo.jpg',
      fileSize: 12345,
      mimeType: 'image/jpeg',
      reason:   'PEER_UNREACHABLE',
      failedAt: 1700000000000,
    });
    assert.equal(entry.status, 'failed');
    assert.equal(entry.deviceId, 'peer-1');
    assert.equal(entry.fileName, 'photo.jpg');
    assert.equal(entry.fileSize, 12345);
    assert.equal(entry.mimeType, 'image/jpeg');
    assert.equal(entry.reason, 'PEER_UNREACHABLE');
    assert.equal(entry.timestamp, 1700000000000);
    assert.equal(entry.direction, 'out');
  });

  it('synthesises a transferId when not supplied', () => {
    const entry = buildFailedEntry({
      deviceId: 'peer-1', fileName: 'x', fileSize: 1, reason: 'PEER_UNREACHABLE',
      failedAt: 42,
    });
    assert.match(entry.transferId, /failed-/);
  });

  it('honours a caller-supplied transferId', () => {
    const entry = buildFailedEntry({
      transferId: 'custom-id',
      deviceId: 'peer-1', fileName: 'x', fileSize: 1, reason: 'PEER_UNREACHABLE',
    });
    assert.equal(entry.transferId, 'custom-id');
  });
});

describe('appendHistoryEntry: persistence', () => {
  beforeEach(() => {
    chromeStub._reset();
  });

  it('writes a single entry to chrome.storage.session', async () => {
    const entry = buildFailedEntry({
      deviceId: 'peer-A', fileName: 'a.txt', fileSize: 1,
      reason: 'PEER_UNREACHABLE', failedAt: 100,
    });
    await appendHistoryEntry(entry);

    const stored = await chrome.storage.session.get(TRANSFER_HISTORY_KEY);
    assert.equal(stored[TRANSFER_HISTORY_KEY].length, 1);
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].status, 'failed');
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].reason, 'PEER_UNREACHABLE');
  });

  it('places newest entries first', async () => {
    await appendHistoryEntry(buildFailedEntry({
      deviceId: 'peer-A', fileName: 'first.txt', fileSize: 1,
      reason: 'PEER_UNREACHABLE', failedAt: 100,
    }));
    await appendHistoryEntry(buildFailedEntry({
      deviceId: 'peer-A', fileName: 'second.txt', fileSize: 2,
      reason: 'PEER_UNREACHABLE', failedAt: 200,
    }));

    const stored = await chrome.storage.session.get(TRANSFER_HISTORY_KEY);
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].fileName, 'second.txt',
      'most recent write must be at index 0');
    assert.equal(stored[TRANSFER_HISTORY_KEY][1].fileName, 'first.txt');
  });

  it('caps the list at the supplied max', async () => {
    for (let i = 0; i < 5; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await appendHistoryEntry(buildFailedEntry({
        deviceId: 'peer-A', fileName: `f${i}.txt`, fileSize: i,
        reason: 'PEER_UNREACHABLE', failedAt: i,
      }), { max: 3 });
    }
    const stored = await chrome.storage.session.get(TRANSFER_HISTORY_KEY);
    assert.equal(stored[TRANSFER_HISTORY_KEY].length, 3);
    // Most recent kept; oldest two evicted.
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].fileName, 'f4.txt');
    assert.equal(stored[TRANSFER_HISTORY_KEY][2].fileName, 'f2.txt');
  });

  it('serialises concurrent appends so no entry is lost to a read-modify-write race', async () => {
    // Without the module-scope queue, two `appendHistoryEntry` calls that
    // both `await storage.get(...)` before either calls `set(...)` would
    // each compute `[entry, ...sameOldList]` and the second `set` would
    // clobber the first — silently losing one entry. Real-world trigger:
    // user mass-fires sends to a peer that just went unreachable; each
    // failure schedules an append and they overlap on the SW microtask
    // queue.
    const N = 8;
    const writes = [];
    for (let i = 0; i < N; i += 1) {
      writes.push(appendHistoryEntry(buildFailedEntry({
        deviceId: 'peer-A', fileName: `f${i}.txt`, fileSize: i,
        reason: 'PEER_UNREACHABLE', failedAt: 1000 + i,
      }), { max: 100 }));
    }
    await Promise.all(writes);

    const stored = await chrome.storage.session.get(TRANSFER_HISTORY_KEY);
    assert.equal(stored[TRANSFER_HISTORY_KEY].length, N,
      `every concurrent append must be persisted (got ${stored[TRANSFER_HISTORY_KEY].length}, expected ${N})`);
    // The last write (newest) sits at index 0; the first (oldest) sits at index N-1.
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].fileName, `f${N - 1}.txt`);
    assert.equal(stored[TRANSFER_HISTORY_KEY][N - 1].fileName, 'f0.txt');
  });

  it('preserves a previously-stored completed entry alongside a failed write', async () => {
    // Simulate a prior completed entry in storage (no `status` field — legacy).
    await chrome.storage.session.set({
      [TRANSFER_HISTORY_KEY]: [
        { transferId: 'old-1', fileName: 'old.txt', fileSize: 99, timestamp: 50 },
      ],
    });

    await appendHistoryEntry(buildFailedEntry({
      deviceId: 'peer-A', fileName: 'new.txt', fileSize: 1,
      reason: 'PEER_UNREACHABLE', failedAt: 100,
    }));

    const stored = await chrome.storage.session.get(TRANSFER_HISTORY_KEY);
    assert.equal(stored[TRANSFER_HISTORY_KEY].length, 2);
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].fileName, 'new.txt');
    assert.equal(stored[TRANSFER_HISTORY_KEY][0].status, 'failed');
    // Legacy entry survives untouched (no status field — backfill is read-only).
    assert.equal(stored[TRANSFER_HISTORY_KEY][1].fileName, 'old.txt');
    assert.equal(stored[TRANSFER_HISTORY_KEY][1].status, undefined);
  });
});

// ─── Coalesce: 3 emissions → 1 broadcast ────────────────────────────────────

describe('installPopupBroadcaster: coalesce (Task 10 follow-up b)', () => {
  beforeEach(() => {
    chromeStub._reset();
    _resetConnectionAuthority();
  });

  it('coalesces concurrent observable emissions into a single broadcast', async () => {
    const auth = ensureConnectionAuthority({
      sendJson: () => {},
      ownDeviceId: 'self',
    });
    installPopupBroadcaster();

    // Subscribing replays current values synchronously and schedules ONE
    // microtask broadcast. Drain it so we measure only the post-install
    // batch below.
    chromeStub._runtimeLog.length = 0;
    await new Promise((resolve) => queueMicrotask(resolve));
    // After draining the install-time microtask, the log holds at most one
    // broadcast; clear it for a clean baseline.
    chromeStub._runtimeLog.length = 0;

    // Fire three near-simultaneous changes (selfState, peerHealth, surrender).
    // We poke the underlying Observables directly via `.next()` — that's the
    // production code path the authority itself uses. We avoid mutating the
    // authority's reducers because we just want to verify the broadcaster's
    // coalesce, not exercise full state machinery.
    const next1 = new Map(auth.peerHealth.value);
    next1.set('peer-1', 'HEALTHY');
    auth.peerHealth.next(next1);

    const next2 = new Map(auth.peerHealth.value);
    next2.set('peer-2', 'STALE');
    auth.peerHealth.next(next2);

    if (auth.surrenderedToUser) {
      auth.surrenderedToUser.next(true);
    }

    // Drain the microtask queue.
    await new Promise((resolve) => queueMicrotask(resolve));

    const broadcasts = chromeStub._runtimeLog
      .filter((m) => m?.type === 'CONNECTION_STATE_CHANGED');
    assert.equal(broadcasts.length, 1,
      `expected exactly 1 coalesced broadcast, got ${broadcasts.length}`);

    // The single broadcast carries the LATEST snapshot (latest peerHealth +
    // surrender flag), not a stale interim value.
    const payload = broadcasts[0].payload;
    assert.equal(payload.peerHealth['peer-1'], 'HEALTHY');
    assert.equal(payload.peerHealth['peer-2'], 'STALE');
    if (auth.surrenderedToUser) {
      assert.equal(payload.surrenderedToUser, true);
    }
  });

  it('schedules a fresh broadcast for emissions in a later microtask turn', async () => {
    const auth = ensureConnectionAuthority({
      sendJson: () => {},
      ownDeviceId: 'self',
    });
    installPopupBroadcaster();

    // Drain the install-time broadcast.
    await new Promise((resolve) => queueMicrotask(resolve));
    chromeStub._runtimeLog.length = 0;

    // Turn 1.
    const t1 = new Map(auth.peerHealth.value);
    t1.set('peer-1', 'HEALTHY');
    auth.peerHealth.next(t1);
    await new Promise((resolve) => queueMicrotask(resolve));

    // Turn 2 — should yield its own broadcast.
    const t2 = new Map(auth.peerHealth.value);
    t2.set('peer-1', 'STALE');
    auth.peerHealth.next(t2);
    await new Promise((resolve) => queueMicrotask(resolve));

    const broadcasts = chromeStub._runtimeLog
      .filter((m) => m?.type === 'CONNECTION_STATE_CHANGED');
    assert.equal(broadcasts.length, 2,
      'each microtask turn should produce its own coalesced broadcast');
  });
});
