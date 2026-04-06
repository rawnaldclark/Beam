/**
 * @file transfer-manager.test.js
 * @description Unit tests for ChunkSizer and FlowController from transfer-manager.js.
 *
 * Runs with:  node --test test/transfer-manager.test.js
 *
 * Coverage:
 *   ChunkSizer:
 *     1. Starts at tier 3 (DEFAULT_CHUNK_TIER — 64 KB)
 *     2. Increases tier after 8 consecutive good ACKs
 *     3. Decreases tier on RTT spike (latest RTT > 2× rolling average)
 *     4. Respects minimum tier (tier 0)
 *     5. Respects maximum tier (last index in CHUNK_TIERS)
 *   FlowController:
 *     6. Starts with window = WINDOW_INITIAL (4)
 *     7. canSend() returns false when inFlight >= window
 *     8. Additive increase after a full window worth of ACKs
 *     9. Multiplicative decrease (halve) on loss
 *    10. Respects minimum window (WINDOW_MIN = 2)
 *    11. Respects maximum window (relay cap WINDOW_MAX_RELAY = 8)
 *    12. Respects maximum window (direct cap WINDOW_MAX_DIRECT = 64)
 *
 * Design notes:
 *   - ChunkSizer._adapt() is triggered internally by recordAck(); we drive it
 *     by feeding crafted RTT measurements.
 *   - "Good" ACK: rttMs well below any spike threshold (all equal so avg == value).
 *   - "Spike" ACK: rttMs set to strictly more than 2× the rolling average.
 *   - Tests do NOT exercise TransferManager directly (requires browser crypto APIs
 *     and a WebSocket); that is an integration concern covered at runtime.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { ChunkSizer, FlowController } from '../offscreen/transfer-manager.js';
import * as C from '../shared/constants.js';

// ═══════════════════════════════════════════════════════════════════════════
// Helper utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Feed `count` identical "good" ACKs (low, consistent RTT) into a ChunkSizer.
 * Each ACK uses rttMs = 50 and chunkSize = current sizer.size, which keeps
 * the rolling average stable and well below the spike threshold.
 *
 * @param {ChunkSizer} sizer - The ChunkSizer instance to feed.
 * @param {number}     count - Number of ACKs to feed.
 */
function feedGoodAcks(sizer, count) {
  for (let i = 0; i < count; i++) {
    sizer.recordAck(50, sizer.size);
  }
}

/**
 * Feed `count` good ACKs then one spike ACK whose rttMs is strictly more
 * than 2× the rolling average to trigger the decrease branch.
 *
 * The spike RTT is computed as rollingAvg * 3 (safely above the 2× threshold).
 *
 * @param {ChunkSizer} sizer - The ChunkSizer instance to feed.
 * @param {number}     goodCount - Number of good ACKs before the spike.
 */
function feedSpikeAck(sizer, goodCount) {
  feedGoodAcks(sizer, goodCount);
  // Rolling average after uniform good ACKs is 50 ms; spike needs > 100 ms.
  sizer.recordAck(200, sizer.size); // 200 > 50 * 2 = 100
}

// ═══════════════════════════════════════════════════════════════════════════
// ChunkSizer tests
// ═══════════════════════════════════════════════════════════════════════════

describe('ChunkSizer', () => {

  // ── Test 1: initial tier ──────────────────────────────────────────────────
  it('starts at tier DEFAULT_CHUNK_TIER (3 → 64 KB)', () => {
    const sizer = new ChunkSizer();
    assert.strictEqual(sizer.tier, C.DEFAULT_CHUNK_TIER,
      `expected tier ${C.DEFAULT_CHUNK_TIER}, got ${sizer.tier}`);
  });

  it('initial size matches CHUNK_TIERS[DEFAULT_CHUNK_TIER]', () => {
    const sizer = new ChunkSizer();
    const expectedSize = C.CHUNK_TIERS[C.DEFAULT_CHUNK_TIER]; // 65 536
    assert.strictEqual(sizer.size, expectedSize,
      `expected ${expectedSize} bytes, got ${sizer.size}`);
  });

  // ── Test 2: tier increase after 8 good ACKs ───────────────────────────────
  it('increases tier by 1 after 8 consecutive loss-free, spike-free ACKs', () => {
    const sizer = new ChunkSizer();
    const startTier = sizer.tier;
    feedGoodAcks(sizer, 8);
    assert.strictEqual(sizer.tier, startTier + 1,
      `expected tier ${startTier + 1}, got ${sizer.tier}`);
  });

  it('size reflects increased tier after promotion', () => {
    const sizer = new ChunkSizer();
    const expectedSize = C.CHUNK_TIERS[sizer.tier + 1];
    feedGoodAcks(sizer, 8);
    assert.strictEqual(sizer.size, expectedSize);
  });

  it('does not increase tier after only 7 good ACKs', () => {
    const sizer = new ChunkSizer();
    const startTier = sizer.tier;
    feedGoodAcks(sizer, 7);
    assert.strictEqual(sizer.tier, startTier,
      'tier should not increase before 8 full ACKs');
  });

  it('resets measurement window after tier increase', () => {
    // After an increase, the window is cleared; the next ACK should NOT
    // immediately re-trigger an increase.
    const sizer = new ChunkSizer();
    feedGoodAcks(sizer, 8); // promotes to tier 4
    const tierAfterPromotion = sizer.tier;
    feedGoodAcks(sizer, 1); // only 1 ACK in new window — no second promotion
    assert.strictEqual(sizer.tier, tierAfterPromotion,
      'tier should not double-increase with only 1 ACK after reset');
  });

  // ── Test 3: tier decrease on RTT spike ────────────────────────────────────
  it('decreases tier by 1 when RTT spike detected after ≥4 measurements', () => {
    const sizer = new ChunkSizer();
    const startTier = sizer.tier;
    // Feed 4 good ACKs (establishes a stable rolling average of 50 ms),
    // then one spike ACK > 2× that average.
    feedGoodAcks(sizer, 4);
    sizer.recordAck(200, sizer.size); // spike: 200 > 50 * 2
    assert.strictEqual(sizer.tier, startTier - 1,
      `expected tier ${startTier - 1} after spike, got ${sizer.tier}`);
  });

  it('does not decrease tier on spike when fewer than 4 measurements total', () => {
    const sizer = new ChunkSizer();
    const startTier = sizer.tier;
    // 2 good ACKs + 1 spike = 3 measurements total, which is below the
    // required minimum of 4 for the demotion check.
    feedGoodAcks(sizer, 2);
    sizer.recordAck(200, sizer.size); // 3rd measurement — below threshold
    assert.strictEqual(sizer.tier, startTier,
      'tier should not decrease with fewer than 4 total measurements');
  });

  it('resets measurement window after tier decrease', () => {
    const sizer = new ChunkSizer();
    feedGoodAcks(sizer, 4);
    sizer.recordAck(200, sizer.size); // triggers decrease, clears window
    const tierAfterDecrease = sizer.tier;
    // One more good ACK: window has only 1 entry — no second decrease.
    sizer.recordAck(50, sizer.size);
    assert.strictEqual(sizer.tier, tierAfterDecrease,
      'tier should not double-decrease with 1 ACK after window reset');
  });

  // ── Test 4: minimum tier ──────────────────────────────────────────────────
  it('does not decrease below tier 0 (8 KB minimum)', () => {
    const sizer = new ChunkSizer();
    // Drive tier to 0 by repeatedly forcing spikes.
    // Default tier is 3; we need 3 decreases minimum.
    for (let i = 0; i < 10; i++) {
      feedGoodAcks(sizer, 4);
      sizer.recordAck(200, sizer.size);
    }
    assert.strictEqual(sizer.tier, 0,
      `tier should be clamped at 0, got ${sizer.tier}`);
    assert.strictEqual(sizer.size, C.CHUNK_TIERS[0]);
  });

  // ── Test 5: maximum tier ──────────────────────────────────────────────────
  it('does not increase beyond the last CHUNK_TIERS index', () => {
    const maxTier = C.CHUNK_TIERS.length - 1;
    const sizer = new ChunkSizer();

    // Drive tier to maximum by repeatedly sending 8 good ACKs.
    // Each cycle of 8 ACKs promotes by 1 tier.
    for (let i = 0; i < maxTier + 5; i++) {
      feedGoodAcks(sizer, 8);
    }

    assert.strictEqual(sizer.tier, maxTier,
      `tier should be clamped at ${maxTier}, got ${sizer.tier}`);
    assert.strictEqual(sizer.size, C.CHUNK_TIERS[maxTier]);
  });

});

// ═══════════════════════════════════════════════════════════════════════════
// FlowController tests
// ═══════════════════════════════════════════════════════════════════════════

describe('FlowController', () => {

  // ── Test 6: initial window ────────────────────────────────────────────────
  it('starts with window = WINDOW_INITIAL (4)', () => {
    const fc = new FlowController('relay');
    assert.strictEqual(fc.window, C.WINDOW_INITIAL);
  });

  it('starts with inFlight = 0', () => {
    const fc = new FlowController('relay');
    assert.strictEqual(fc.inFlight, 0);
  });

  it('canSend() returns true when inFlight < window', () => {
    const fc = new FlowController('relay');
    assert.strictEqual(fc.canSend(), true);
  });

  // ── Test 7: canSend blocks when window full ───────────────────────────────
  it('canSend() returns false when inFlight == window', () => {
    const fc = new FlowController('relay');
    // Fill the window exactly.
    for (let i = 0; i < fc.window; i++) {
      fc.onSend();
    }
    assert.strictEqual(fc.canSend(), false);
  });

  it('canSend() returns true again after an ACK drains one slot', () => {
    const fc = new FlowController('relay');
    for (let i = 0; i < fc.window; i++) {
      fc.onSend();
    }
    fc.onAck(); // drain one slot
    assert.strictEqual(fc.canSend(), true);
  });

  it('onSend() increments inFlight', () => {
    const fc = new FlowController('relay');
    fc.onSend();
    assert.strictEqual(fc.inFlight, 1);
    fc.onSend();
    assert.strictEqual(fc.inFlight, 2);
  });

  it('onAck() decrements inFlight', () => {
    const fc = new FlowController('relay');
    fc.onSend();
    fc.onSend();
    fc.onAck();
    assert.strictEqual(fc.inFlight, 1);
  });

  // ── Test 8: additive increase after full window ACKed ─────────────────────
  it('window increases by 1 after a full window of ACKs (AIMD additive)', () => {
    const fc = new FlowController('direct'); // use direct for headroom
    const initialWindow = fc.window; // 4
    // Send and ACK a full window's worth to trigger the increase.
    for (let i = 0; i < initialWindow; i++) {
      fc.onSend();
    }
    for (let i = 0; i < initialWindow; i++) {
      fc.onAck();
    }
    assert.strictEqual(fc.window, initialWindow + 1,
      `expected window ${initialWindow + 1}, got ${fc.window}`);
  });

  it('window does not increase before a full window has been ACKed', () => {
    const fc = new FlowController('direct');
    const initialWindow = fc.window;
    // ACK one less than a full window.
    for (let i = 0; i < initialWindow; i++) {
      fc.onSend();
    }
    for (let i = 0; i < initialWindow - 1; i++) {
      fc.onAck();
    }
    assert.strictEqual(fc.window, initialWindow,
      'window should not increase prematurely');
  });

  it('resets ACK counter after each window increase', () => {
    // Two consecutive full-window cycles should yield two increments.
    const fc = new FlowController('direct');
    const initial = fc.window; // 4

    // First full window cycle.
    for (let i = 0; i < initial; i++) fc.onSend();
    for (let i = 0; i < initial; i++) fc.onAck();
    assert.strictEqual(fc.window, initial + 1); // 5

    // Second full window cycle (now window = 5).
    const afterFirst = fc.window;
    for (let i = 0; i < afterFirst; i++) fc.onSend();
    for (let i = 0; i < afterFirst; i++) fc.onAck();
    assert.strictEqual(fc.window, initial + 2); // 6
  });

  // ── Test 9: multiplicative decrease on loss ───────────────────────────────
  it('halves the window on loss (AIMD multiplicative decrease)', () => {
    const fc = new FlowController('direct');
    // Grow window to 8 first.
    for (let cycle = 0; cycle < 4; cycle++) {
      const w = fc.window;
      for (let i = 0; i < w; i++) fc.onSend();
      for (let i = 0; i < w; i++) fc.onAck();
    }
    const preWindow = fc.window; // should be 8
    fc.onLoss();
    assert.strictEqual(fc.window, Math.max(Math.floor(preWindow / 2), C.WINDOW_MIN),
      `expected ${Math.max(Math.floor(preWindow / 2), C.WINDOW_MIN)}, got ${fc.window}`);
  });

  it('onLoss() resets the ACK-since-increase counter', () => {
    const fc = new FlowController('direct');
    const initial = fc.window;
    // ACK half a window (not yet a full window but sets up partial state).
    for (let i = 0; i < Math.floor(initial / 2); i++) fc.onSend();
    for (let i = 0; i < Math.floor(initial / 2); i++) fc.onAck();
    fc.onLoss();
    // After loss, we need a fresh full window of ACKs to increment.
    // Only provide half — window should NOT increase.
    const windowAfterLoss = fc.window;
    for (let i = 0; i < Math.floor(windowAfterLoss / 2); i++) fc.onSend();
    for (let i = 0; i < Math.floor(windowAfterLoss / 2); i++) fc.onAck();
    assert.strictEqual(fc.window, windowAfterLoss,
      'window should not increase when ACK counter was reset by loss');
  });

  // ── Test 10: minimum window ───────────────────────────────────────────────
  it('does not decrease window below WINDOW_MIN (2) on repeated loss', () => {
    const fc = new FlowController('relay');
    // Hammer with losses.
    for (let i = 0; i < 20; i++) {
      fc.onLoss();
    }
    assert.strictEqual(fc.window, C.WINDOW_MIN,
      `window should be clamped at ${C.WINDOW_MIN}, got ${fc.window}`);
  });

  // ── Test 11: relay maximum window ────────────────────────────────────────
  it('relay mode caps window at WINDOW_MAX_RELAY (8)', () => {
    const fc = new FlowController('relay');
    // Drive the window upward through many full-window ACK cycles.
    for (let cycle = 0; cycle < 20; cycle++) {
      const w = fc.window;
      for (let i = 0; i < w; i++) fc.onSend();
      for (let i = 0; i < w; i++) fc.onAck();
    }
    assert.strictEqual(fc.window, C.WINDOW_MAX_RELAY,
      `relay window should cap at ${C.WINDOW_MAX_RELAY}, got ${fc.window}`);
  });

  // ── Test 12: direct maximum window ───────────────────────────────────────
  it('direct mode caps window at WINDOW_MAX_DIRECT (64)', () => {
    const fc = new FlowController('direct');
    // Drive to maximum via many full-window ACK cycles.
    for (let cycle = 0; cycle < 100; cycle++) {
      const w = fc.window;
      for (let i = 0; i < w; i++) fc.onSend();
      for (let i = 0; i < w; i++) fc.onAck();
    }
    assert.strictEqual(fc.window, C.WINDOW_MAX_DIRECT,
      `direct window should cap at ${C.WINDOW_MAX_DIRECT}, got ${fc.window}`);
  });

  it('direct mode maxWindow is distinct from relay maxWindow', () => {
    const relay  = new FlowController('relay');
    const direct = new FlowController('direct');
    assert.notStrictEqual(relay.maxWindow, direct.maxWindow);
    assert.strictEqual(relay.maxWindow,  C.WINDOW_MAX_RELAY);
    assert.strictEqual(direct.maxWindow, C.WINDOW_MAX_DIRECT);
  });

});
