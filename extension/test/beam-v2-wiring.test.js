/**
 * @file beam-v2-wiring.test.js
 * @description Locks the contract for the popup-progress wiring added in
 * Task 10.5: the wiring layer must translate the transport's bare
 * `(transferIdHex, percent)` events into the popup's full
 * `MSG.TRANSFER_PROGRESS` shape, using metadata seeded by the new
 * `onSendStart` hook, and must clean up that metadata on completion +
 * `_resetTransportSingleton`.
 *
 * Run:  node --test test/beam-v2-wiring.test.js
 *
 * The test reaches into `transport._hooks` (private-by-convention) to invoke
 * onSendStart/onProgress directly. That is the cheapest seam — the
 * alternative (driving `transport.sendFile()` end-to-end) requires a fully
 * fixtured chrome.storage.local with deviceKeys + a paired peer, which buys
 * no extra coverage of the wiring contract this file is meant to lock.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { installChromeStub, chromeStub } from './_helpers/chrome-stubs.js';

// Install the chrome stub BEFORE importing the wiring module — it touches
// `chrome.runtime` at import time via getConnectionAuthority resolution.
installChromeStub();

const {
  ensureTransport,
  _resetTransportSingleton,
  _getOutboundMetaForTest,
} = await import('../crypto/beam-v2-wiring.js');

function makeTransportArgs() {
  return {
    sendBinary: () => true,
    sendJson:   () => {},
    onClipboardReceived: async () => {},
    onFileReceived:      async () => {},
  };
}

function getProgressMessages() {
  return chromeStub._runtimeLog.filter((m) => m?.type === 'transfer-progress');
}

function getCompleteMessages() {
  return chromeStub._runtimeLog.filter((m) => m?.type === 'transfer-complete');
}

describe('beam-v2-wiring outbound progress (Task 10.5)', () => {
  beforeEach(() => {
    _resetTransportSingleton();
    chromeStub._reset();
  });

  it('seeds outbound metadata when onSendStart fires for a file', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('aabbcc', {
      kind:           'file',
      targetDeviceId: 'peer-1',
      fileName:       'doc.pdf',
      fileSize:       2048,
      mimeType:       'application/pdf',
      totalChunks:    4,
    });
    const meta = _getOutboundMetaForTest().get('aabbcc');
    assert.ok(meta, 'metadata entry must exist after onSendStart');
    assert.equal(meta.targetDeviceId, 'peer-1');
    assert.equal(meta.fileName, 'doc.pdf');
    assert.equal(meta.totalBytes, 2048);
  });

  it('does NOT seed metadata for clipboard sends (no streaming progress)', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('ccdd', {
      kind:           'clipboard',
      targetDeviceId: 'peer-1',
      fileSize:       42,
    });
    assert.equal(_getOutboundMetaForTest().has('ccdd'), false);
  });

  it('translates onProgress(transferIdHex, percent) into MSG.TRANSFER_PROGRESS with all six fields', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('deadbeef', {
      kind:           'file',
      targetDeviceId: 'peer-A',
      fileName:       'movie.mp4',
      fileSize:       1000,
      mimeType:       'video/mp4',
      totalChunks:    2,
    });

    transport._hooks.onProgress('deadbeef', 50);

    const msgs = getProgressMessages();
    assert.equal(msgs.length, 1, 'exactly one progress message must be emitted');
    const { type, payload } = msgs[0];
    assert.equal(type, 'transfer-progress');
    assert.equal(payload.transferId,       'deadbeef');
    assert.equal(payload.fileName,         'movie.mp4');
    assert.equal(payload.bytesTransferred, 500);
    assert.equal(payload.totalBytes,       1000);
    assert.equal(payload.targetDeviceId,   'peer-A');
    assert.equal(typeof payload.speedBps,  'number');
  });

  it('drops onProgress events for ids that were never seeded (no metadata leak)', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onProgress('unseeded-id', 25);
    assert.equal(getProgressMessages().length, 0);
  });

  it('clears the metadata entry when onProgress reports 100%', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('ff00', {
      kind: 'file', targetDeviceId: 'peer-B',
      fileName: 'x.bin', fileSize: 16, mimeType: 'application/octet-stream', totalChunks: 1,
    });
    assert.equal(_getOutboundMetaForTest().has('ff00'), true);
    transport._hooks.onProgress('ff00', 100);
    assert.equal(_getOutboundMetaForTest().has('ff00'), false,
      'metadata entry must be removed once the transfer reaches 100%');
  });

  it('emits MSG.TRANSFER_COMPLETE at 100% so the popup transitions to the success state', () => {
    // Without this emission the device row stays at 100% indefinitely
    // (popup.js's success-fade handler keys off TRANSFER_COMPLETE, not the
    // 100% progress tick).
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('cafef00d', {
      kind: 'file', targetDeviceId: 'peer-Z',
      fileName: 'final.zip', fileSize: 1234,
      mimeType: 'application/zip', totalChunks: 3,
    });
    transport._hooks.onProgress('cafef00d', 50);  // mid-flight, no complete
    assert.equal(getCompleteMessages().length, 0, 'no TRANSFER_COMPLETE before 100%');

    transport._hooks.onProgress('cafef00d', 100);
    const completes = getCompleteMessages();
    assert.equal(completes.length, 1, 'exactly one TRANSFER_COMPLETE at 100%');
    assert.deepEqual(completes[0].payload, {
      transferId:     'cafef00d',
      fileName:       'final.zip',
      fileSize:       1234,
      targetDeviceId: 'peer-Z',
    }, 'TRANSFER_COMPLETE payload matches popup.js destructure shape');

    // A second 100% tick (defensive — the loop only fires once, but if a
    // future change ever double-emits, we must not re-emit COMPLETE either).
    transport._hooks.onProgress('cafef00d', 100);
    assert.equal(getCompleteMessages().length, 1,
      'TRANSFER_COMPLETE is only emitted once even if 100% repeats');
  });

  it('clears the metadata entry when onSendError fires for that id', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('1111', {
      kind: 'file', targetDeviceId: 'peer-C',
      fileName: 'y.bin', fileSize: 8, mimeType: 'application/octet-stream', totalChunks: 1,
    });
    transport._hooks.onSendError?.('1111', 'NO_TRANSPORT');
    assert.equal(_getOutboundMetaForTest().has('1111'), false,
      'send-error must release the metadata slot so a retry can re-seed it');
  });

  it('_resetTransportSingleton clears the metadata map alongside the transport', () => {
    const transport = ensureTransport(makeTransportArgs());
    transport._hooks.onSendStart('2222', {
      kind: 'file', targetDeviceId: 'peer-D',
      fileName: 'z.bin', fileSize: 4, mimeType: 'application/octet-stream', totalChunks: 1,
    });
    assert.equal(_getOutboundMetaForTest().size, 1);
    _resetTransportSingleton();
    assert.equal(_getOutboundMetaForTest().size, 0,
      'Rung-3 reset must drop every per-transfer metadata entry');
  });
});
