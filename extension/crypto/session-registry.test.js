// Beam E2E encryption — unit tests for session-registry.js.
//
// These run in the same browser harness as beam-crypto.test.js
// (beam-crypto.test.html -> bootstrap -> runTests).

import {
  SessionRegistry,
  STATE,
  ERROR_CODES,
} from './session-registry.js';
import {
  generateEphemeral,
  x25519PublicKey,
  toHex,
} from './beam-crypto.js';

// -- tiny harness shared contract: { name, passed, detail } entries -----------

function makeRecorder() {
  const results = [];
  const record = (name, passed, detail) => {
    results.push({ name, passed, detail });
  };
  const check = (name, cond, detail) => record(name, !!cond, detail);
  return { results, record, check };
}

// In-memory storage stub that mirrors our SessionRegistry storage contract.
function memoryStorage() {
  const m = new Map();
  return {
    _map: m,
    async get(k) { return m.get(k); },
    async set(k, v) { m.set(k, v); },
    async remove(k) { m.delete(k); },
  };
}

// Synthesize a static identity keypair for a "party".
async function makeIdentity() {
  const { sk, pk } = await generateEphemeral();
  // x25519 keypair from libsodium is already usable as a static identity here.
  return { sk, pk: await x25519PublicKey(sk) }; // re-derive pk for symmetry
}

// ---------------------------------------------------------------------------

export async function runSessionRegistryTests() {
  const { results, check, record } = makeRecorder();

  const alice = await makeIdentity();
  const bob = await makeIdentity();

  // -------------------------------------------------------------------------
  // 1. Happy path: initiator → responder → active on both sides.
  // -------------------------------------------------------------------------
  {
    const tA = Date.now();
    let nowA = tA;
    const regA = new SessionRegistry({
      ourStaticSk: alice.sk,
      ourStaticPk: alice.pk,
      now: () => nowA,
      storage: memoryStorage(),
    });
    const regB = new SessionRegistry({
      ourStaticSk: bob.sk,
      ourStaticPk: bob.pk,
      now: () => nowA,
      storage: memoryStorage(),
    });

    const { wireMessage: initMsg, transferIdHex } = await regA.startInit({
      peerId: 'bob',
      peerStaticPk: bob.pk,
      kind: 'clipboard',
    });
    check('startInit: produces transfer-init message', initMsg.type === 'transfer-init');
    check('startInit: version 1', initMsg.v === 1);
    check('startInit: kind clipboard', initMsg.kind === 'clipboard');
    check(
      'startInit: registers pending session',
      regA.getByTransferId(regA._sessions.get(transferIdHex).transferId)?.state ===
        STATE.AWAITING_ACCEPT,
    );

    const { session: sessionB, wireMessage: acceptMsg } = await regB.onInit({
      peerId: 'alice',
      peerStaticPk: alice.pk,
      wireMessage: initMsg,
    });
    check('onInit: produces transfer-accept message', acceptMsg.type === 'transfer-accept');
    check('onInit: responder state is ACTIVE', sessionB.state === STATE.ACTIVE);
    check(
      'onInit: transcript is 32 bytes',
      sessionB.transcript && sessionB.transcript.byteLength === 32,
    );

    const sessionA = await regA.onAccept({
      peerId: 'bob',
      wireMessage: acceptMsg,
    });
    check('onAccept: initiator state is ACTIVE', sessionA.state === STATE.ACTIVE);

    // Most important: both sides derived the SAME session/chunk/meta key.
    check(
      'session keys match (sessionKey)',
      toHex(sessionA.sessionKey) === toHex(sessionB.sessionKey),
      `A=${toHex(sessionA.sessionKey).slice(0, 16)}… B=${toHex(sessionB.sessionKey).slice(0, 16)}…`,
    );
    check(
      'session keys match (chunkKey)',
      toHex(sessionA.chunkKey) === toHex(sessionB.chunkKey),
    );
    check(
      'session keys match (metaKey)',
      toHex(sessionA.metaKey) === toHex(sessionB.metaKey),
    );
    check(
      'transcripts match',
      toHex(sessionA.transcript) === toHex(sessionB.transcript),
    );

    // Ephemerals wiped after derivation.
    check('initiator ephSk wiped', sessionA.ephSk === null);

    await regA.destroy(sessionA.transferId);
    await regB.destroy(sessionB.transferId);
    check('destroyed: A registry empty', regA.size() === 0);
    check('destroyed: B registry empty', regB.size() === 0);
  }

  // -------------------------------------------------------------------------
  // 2. Version mismatch on init → VERSION error.
  // -------------------------------------------------------------------------
  {
    const regB = new SessionRegistry({
      ourStaticSk: bob.sk,
      ourStaticPk: bob.pk,
      storage: memoryStorage(),
    });
    let err = null;
    try {
      await regB.onInit({
        peerId: 'alice',
        peerStaticPk: alice.pk,
        wireMessage: {
          type: 'transfer-init',
          v: 99,
          transferId: 'AAAAAAAAAAAAAAAAAAAAAA',
          kind: 'clipboard',
          ephPkA: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
      });
    } catch (e) {
      err = e;
    }
    check('version mismatch throws', err !== null);
    check('version mismatch error code', err && err.code === ERROR_CODES.VERSION);
  }

  // -------------------------------------------------------------------------
  // 3. Duplicate transferId on responder → DUPLICATE error.
  // -------------------------------------------------------------------------
  {
    const regA = new SessionRegistry({
      ourStaticSk: alice.sk,
      ourStaticPk: alice.pk,
      storage: memoryStorage(),
    });
    const regB = new SessionRegistry({
      ourStaticSk: bob.sk,
      ourStaticPk: bob.pk,
      storage: memoryStorage(),
    });
    const { wireMessage: init1 } = await regA.startInit({
      peerId: 'bob',
      peerStaticPk: bob.pk,
      kind: 'clipboard',
    });
    await regB.onInit({
      peerId: 'alice',
      peerStaticPk: alice.pk,
      wireMessage: init1,
    });
    let err = null;
    try {
      await regB.onInit({
        peerId: 'alice',
        peerStaticPk: alice.pk,
        wireMessage: init1,
      });
    } catch (e) {
      err = e;
    }
    check('duplicate transferId throws', err !== null);
    check('duplicate transferId code', err && err.code === ERROR_CODES.DUPLICATE);
  }

  // -------------------------------------------------------------------------
  // 4. Handshake timeout via sweep.
  // -------------------------------------------------------------------------
  {
    let t = 0;
    const regA = new SessionRegistry({
      ourStaticSk: alice.sk,
      ourStaticPk: alice.pk,
      now: () => t,
      options: { ...SessionRegistry.prototype.constructor ? {} : {}, HANDSHAKE_TIMEOUT_MS: 1000 },
      storage: memoryStorage(),
    });
    t = 1000;
    const { transferIdHex } = await regA.startInit({
      peerId: 'bob',
      peerStaticPk: bob.pk,
      kind: 'file',
    });
    check('pending session exists', regA.size() === 1);
    t = 1000 + 1500; // past timeout
    await regA.sweep();
    check('sweep reaped timed-out session', regA.size() === 0);
    check(
      'sweep removed storage entry',
      (await regA._storage.get('beam:pending-hs:' + transferIdHex)) == null,
    );
  }

  // -------------------------------------------------------------------------
  // 5. Per-peer rate limit.
  // -------------------------------------------------------------------------
  {
    const regA = new SessionRegistry({
      ourStaticSk: alice.sk,
      ourStaticPk: alice.pk,
      options: { MAX_PENDING_PER_PEER: 2, MAX_GLOBAL_PER_SECOND: 1000 },
      storage: memoryStorage(),
    });
    await regA.startInit({ peerId: 'bob', peerStaticPk: bob.pk, kind: 'clipboard' });
    await regA.startInit({ peerId: 'bob', peerStaticPk: bob.pk, kind: 'clipboard' });
    let err = null;
    try {
      await regA.startInit({ peerId: 'bob', peerStaticPk: bob.pk, kind: 'clipboard' });
    } catch (e) {
      err = e;
    }
    check('per-peer rate limit enforced', err && err.code === ERROR_CODES.RATE_LIMIT);
  }

  // -------------------------------------------------------------------------
  // 6. Global rate limit.
  // -------------------------------------------------------------------------
  {
    let t = 1_000_000;
    const regA = new SessionRegistry({
      ourStaticSk: alice.sk,
      ourStaticPk: alice.pk,
      options: { MAX_PENDING_PER_PEER: 999, MAX_GLOBAL_PER_SECOND: 3 },
      now: () => t,
      storage: memoryStorage(),
    });
    for (let i = 0; i < 3; i += 1) {
      await regA.startInit({ peerId: `peer${i}`, peerStaticPk: bob.pk, kind: 'clipboard' });
    }
    let err = null;
    try {
      await regA.startInit({ peerId: 'overflow', peerStaticPk: bob.pk, kind: 'clipboard' });
    } catch (e) {
      err = e;
    }
    check('global rate limit enforced', err && err.code === ERROR_CODES.RATE_LIMIT);
    // Advance past the 1s window; allowed again.
    t += 1500;
    let ok = false;
    try {
      await regA.startInit({ peerId: 'peer-late', peerStaticPk: bob.pk, kind: 'clipboard' });
      ok = true;
    } catch (_) {
      ok = false;
    }
    check('global rate limit clears after 1s window', ok);
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  return results;
}
