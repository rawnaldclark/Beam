/**
 * @file connection-authority-wiring.test.js
 * @description Locks the singleton contract for connection-authority-wiring.js.
 *
 * Run:  node --test test/connection-authority-wiring.test.js
 *
 * Verifies:
 *   - ensureConnectionAuthority constructs once, returns the same instance
 *     on subsequent calls (hooks on later calls are ignored).
 *   - getConnectionAuthority returns null until ensureConnectionAuthority
 *     has been called, and the same instance afterwards.
 *   - _resetConnectionAuthority clears the singleton so a fresh ensure
 *     yields a new instance.
 *
 * This is observational wiring; the rest of the authority's behaviour is
 * covered by connection-authority.test.js.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  ensureConnectionAuthority,
  getConnectionAuthority,
  _resetConnectionAuthority,
} from '../connection/connection-authority-wiring.js';
import { ConnectionAuthority } from '../connection/connection-authority.js';

function makeHooks(ownDeviceId = 'test-device') {
  return {
    sendJson: () => {},
    ownDeviceId,
  };
}

describe('connection-authority-wiring singleton', () => {
  beforeEach(() => {
    _resetConnectionAuthority();
  });

  it('returns null from getConnectionAuthority before ensure is called', () => {
    assert.equal(getConnectionAuthority(), null);
  });

  it('ensureConnectionAuthority constructs a ConnectionAuthority on first call', () => {
    const auth = ensureConnectionAuthority(makeHooks());
    assert.ok(auth instanceof ConnectionAuthority);
  });

  it('returns the same instance on subsequent calls (singleton)', () => {
    const a = ensureConnectionAuthority(makeHooks('first'));
    const b = ensureConnectionAuthority(makeHooks('second'));
    assert.strictEqual(a, b, 'same singleton instance must be returned');
  });

  it('getConnectionAuthority returns the constructed instance after ensure', () => {
    const a = ensureConnectionAuthority(makeHooks());
    assert.strictEqual(getConnectionAuthority(), a);
  });

  it('_resetConnectionAuthority clears the singleton so a fresh ensure constructs anew', () => {
    const a = ensureConnectionAuthority(makeHooks());
    _resetConnectionAuthority();
    assert.equal(getConnectionAuthority(), null);
    const b = ensureConnectionAuthority(makeHooks());
    assert.notStrictEqual(a, b, 'after reset, ensure must construct a new instance');
  });
});
