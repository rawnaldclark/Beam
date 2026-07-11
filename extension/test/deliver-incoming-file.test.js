/**
 * @file deliver-incoming-file.test.js
 * @description Coverage for deliverIncomingFile's auto-save / manual-save UX.
 *
 * Regression target: the receiver called chrome.downloads.download() but the
 * manifest never granted "downloads", so chrome.downloads was undefined, the
 * download threw into a catch that only logged, and the "File Saved"
 * notification fired unconditionally anyway — the user saw success while the
 * bytes were silently discarded. These tests pin: (1) success only claims
 * "File Saved" on an actual successful download, (2) a failed download falls
 * back to the manual-save stash so the file is never lost, (3) the manifest
 * declares the permission the code depends on.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installChromeStub, chromeStub } from './_helpers/chrome-stubs.js';

// chrome.* must exist before background-relay.js evaluates.
installChromeStub();
const { deliverIncomingFile } = await import('../background-relay.js');

/** Redirect chrome.notifications.create into a captured array. */
function captureNotifications() {
  const notes = [];
  chromeStub.notifications.create = (_id, opts) => { notes.push(opts); };
  return notes;
}

const FILE = {
  bytes:        new Uint8Array([1, 2, 3]),
  fileName:     'a.txt',
  fileSize:     3,
  mimeType:     'text/plain',
  fromDeviceId: 'dev-1',
};

describe('deliverIncomingFile', () => {
  beforeEach(() => {
    chromeStub._reset();
    // Restore the default (successful) download between tests.
    chromeStub.downloads.download = async () => 1;
  });

  it('auto-save success: notifies "File Saved" and does not stash for manual save', async () => {
    await chromeStub.storage.local.set({ settings: { autoSave: true } });
    const notes = captureNotifications();

    await deliverIncomingFile(FILE);

    assert.ok(notes.some((n) => n.title === 'File Saved'), 'must notify File Saved on success');
    const s = await chromeStub.storage.session.get('receivedFile');
    assert.equal(s.receivedFile, undefined, 'no manual-save stash when auto-save succeeded');
  });

  it('auto-save failure: does NOT claim "File Saved" and stashes bytes so the file is not lost', async () => {
    await chromeStub.storage.local.set({ settings: { autoSave: true } });
    chromeStub.downloads.download = async () => { throw new Error('missing downloads permission'); };
    const notes = captureNotifications();

    await deliverIncomingFile(FILE);

    assert.ok(!notes.some((n) => n.title === 'File Saved'),
      'must not falsely claim File Saved when the download failed');
    const s = await chromeStub.storage.session.get('receivedFile');
    assert.ok(s.receivedFile, 'file must be stashed for manual save so it is not silently lost');
    assert.equal(s.receivedFile.fileName, 'a.txt');
  });

  it('auto-save off: stashes bytes for manual save and notifies "File Received"', async () => {
    await chromeStub.storage.local.set({ settings: { autoSave: false } });
    const notes = captureNotifications();

    await deliverIncomingFile(FILE);

    const s = await chromeStub.storage.session.get('receivedFile');
    assert.ok(s.receivedFile, 'manual-save path stores the file');
    assert.ok(notes.some((n) => n.title === 'File Received'));
  });
});

describe('manifest permissions', () => {
  it('declares "downloads" (deliverIncomingFile calls chrome.downloads.download)', () => {
    const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
    assert.ok(
      Array.isArray(manifest.permissions) && manifest.permissions.includes('downloads'),
      'manifest.permissions must include "downloads" or chrome.downloads is undefined at runtime',
    );
  });
});
