/**
 * @file rendezvous.test.js
 * @description Tests for the shared rendezvous-set helper. Mirrors the
 *   Android `RendezvousIdsTest.kt` test-for-test.
 *
 *   Invariant: every register-rendezvous frame must carry the COMPLETE
 *   membership set — this device's OWN deviceId (so its own-id-keyed
 *   peer-pings route) PLUS every paired peer's deviceId (so it is a member
 *   of each peer's room). The relay's presence.register REPLACES the set on
 *   every call, so a partial set silently breaks routing.
 *
 * Run:  node --test test/rendezvous.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { computeRendezvousIds } from '../shared/rendezvous.js';

const OWN = 'OWNdeviceId0000000000A';
const PEER_A = 'PEERaaaaaaaaaaaaaaaaaA';
const PEER_B = 'PEERbbbbbbbbbbbbbbbbbB';

describe('computeRendezvousIds', () => {
  it('always includes the own deviceId', () => {
    assert.ok(computeRendezvousIds(OWN, [PEER_A]).includes(OWN));
  });

  it('includes all paired peer ids', () => {
    const ids = computeRendezvousIds(OWN, [PEER_A, PEER_B]);
    assert.ok(ids.includes(PEER_A));
    assert.ok(ids.includes(PEER_B));
  });

  it('yields own-only when there are no peers', () => {
    assert.deepEqual(computeRendezvousIds(OWN, []), [OWN]);
  });

  it('does not duplicate own when it already appears in peers', () => {
    const ids = computeRendezvousIds(OWN, [PEER_A, OWN]);
    assert.equal(ids.filter((id) => id === OWN).length, 1);
    assert.ok(ids.includes(PEER_A));
  });

  it('dedupes repeated peers', () => {
    const ids = computeRendezvousIds(OWN, [PEER_A, PEER_A, PEER_B]);
    assert.equal(ids.filter((id) => id === PEER_A).length, 1);
    assert.equal(ids.filter((id) => id === PEER_B).length, 1);
  });

  it('filters out falsy peer ids (legacy records)', () => {
    const ids = computeRendezvousIds(OWN, [PEER_A, undefined, '', null]);
    assert.deepEqual(ids, [OWN, PEER_A]);
  });
});
