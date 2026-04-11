import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { MSG, validate } from '../src/protocol.js';

describe('protocol constants', () => {
  it('defines all required message types', () => {
    assert.equal(MSG.CHALLENGE, 'challenge');
    assert.equal(MSG.AUTH, 'auth');
    assert.equal(MSG.AUTH_OK, 'auth-ok');
    assert.equal(MSG.AUTH_FAIL, 'auth-fail');
    assert.equal(MSG.REGISTER_RENDEZVOUS, 'register-rendezvous');
    assert.equal(MSG.PEER_ONLINE, 'peer-online');
    assert.equal(MSG.PEER_OFFLINE, 'peer-offline');
    assert.equal(MSG.SDP_OFFER, 'sdp-offer');
    assert.equal(MSG.SDP_ANSWER, 'sdp-answer');
    assert.equal(MSG.ICE_CANDIDATE, 'ice-candidate');
    assert.equal(MSG.RELAY_BIND, 'relay-bind');
    assert.equal(MSG.RELAY_RELEASE, 'relay-release');
    assert.equal(MSG.RELAY_DATA, 'relay-data');
    assert.equal(MSG.RECONNECT, 'reconnect');
    assert.equal(MSG.ERROR, 'error');
    assert.equal(MSG.PING, 'ping');
    assert.equal(MSG.PONG, 'pong');
  });
});

describe('validate()', () => {
  it('rejects non-object input', () => { const r = validate('hello'); assert.equal(r.valid, false); assert.match(r.error, /must be an object/i); });
  it('rejects missing type field', () => { const r = validate({ foo: 1 }); assert.equal(r.valid, false); assert.match(r.error, /missing.*type/i); });
  it('rejects unknown type', () => { const r = validate({ type: 'unknown-garbage' }); assert.equal(r.valid, false); assert.match(r.error, /unknown.*type/i); });
  it('accepts valid ping', () => { const r = validate({ type: 'ping' }); assert.equal(r.valid, true); });
  it('rejects auth missing required fields', () => { const r = validate({ type: 'auth' }); assert.equal(r.valid, false); assert.match(r.error, /deviceId/i); });
  it('accepts valid auth message', () => { const r = validate({ type: 'auth', deviceId: 'abc123', publicKey: 'AAAA', signature: 'BBBB', timestamp: Date.now() }); assert.equal(r.valid, true); });
  it('rejects sdp-offer missing rendezvousId', () => { const r = validate({ type: 'sdp-offer', targetDeviceId: 'd1', sdp: '...' }); assert.equal(r.valid, false); });
  it('accepts valid sdp-offer', () => { const r = validate({ type: 'sdp-offer', targetDeviceId: 'd1', rendezvousId: 'rv1', sdp: 'v=0...' }); assert.equal(r.valid, true); });
  it('rejects relay-bind missing transferId', () => { const r = validate({ type: 'relay-bind', targetDeviceId: 'd1' }); assert.equal(r.valid, false); });
  it('accepts valid relay-bind', () => { const r = validate({ type: 'relay-bind', transferId: 'tf-1', targetDeviceId: 'd1', rendezvousId: 'rv1' }); assert.equal(r.valid, true); });
  it('rejects register-rendezvous missing rendezvousIds', () => { const r = validate({ type: 'register-rendezvous' }); assert.equal(r.valid, false); });
  it('accepts valid register-rendezvous', () => { const r = validate({ type: 'register-rendezvous', rendezvousIds: ['rv1', 'rv2'] }); assert.equal(r.valid, true); });
  it('rejects reconnect missing required fields', () => { const r = validate({ type: 'reconnect' }); assert.equal(r.valid, false); });
  it('accepts valid reconnect', () => { const r = validate({ type: 'reconnect', deviceId: 'd1', publicKey: 'AAAA', signature: 'BBBB', timestamp: Date.now() }); assert.equal(r.valid, true); });
  it('rejects messages exceeding max text size (64KB)', () => { const r = validate({ type: 'sdp-offer', targetDeviceId: 'd1', rendezvousId: 'rv1', sdp: 'x'.repeat(65 * 1024) }); assert.equal(r.valid, false); assert.match(r.error, /too large/i); });

  // Beam E2E handshake envelope validation
  it('accepts valid transfer-init', () => {
    const r = validate({ type: 'transfer-init', v: 1, rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't', kind: 'clipboard', ephPkA: 'pk', salt: 's' });
    assert.equal(r.valid, true);
  });
  it('rejects transfer-init with invalid kind', () => {
    const r = validate({ type: 'transfer-init', v: 1, rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't', kind: 'bogus', ephPkA: 'pk', salt: 's' });
    assert.equal(r.valid, false);
    assert.match(r.error, /kind/);
  });
  it('rejects transfer-init missing ephPkA', () => {
    const r = validate({ type: 'transfer-init', v: 1, rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't', kind: 'file', salt: 's' });
    assert.equal(r.valid, false);
    assert.match(r.error, /ephPkA/);
  });
  it('rejects transfer-init with non-numeric version', () => {
    const r = validate({ type: 'transfer-init', v: 'one', rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't', kind: 'clipboard', ephPkA: 'pk', salt: 's' });
    assert.equal(r.valid, false);
    assert.match(r.error, /\bv\b/);
  });
  it('accepts valid transfer-accept', () => {
    const r = validate({ type: 'transfer-accept', v: 1, rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't', ephPkB: 'pk' });
    assert.equal(r.valid, true);
  });
  it('rejects transfer-accept missing ephPkB', () => {
    const r = validate({ type: 'transfer-accept', v: 1, rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't' });
    assert.equal(r.valid, false);
    assert.match(r.error, /ephPkB/);
  });
  it('accepts valid transfer-reject', () => {
    const r = validate({ type: 'transfer-reject', rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't', errorCode: 'TIMEOUT' });
    assert.equal(r.valid, true);
  });
  it('rejects transfer-reject missing errorCode', () => {
    const r = validate({ type: 'transfer-reject', rendezvousId: 'rv1', targetDeviceId: 'd1', transferId: 't' });
    assert.equal(r.valid, false);
    assert.match(r.error, /errorCode/);
  });
});
