/**
 * @file beam-errors.js
 * @description User-facing messages for Beam transport error codes.
 *
 * The transport raises errors with a string `code` (e.g. NO_PEER, NO_KEY,
 * SIZE_MISMATCH). The popup / SW notification surface looks up the
 * canonical message here so we never let raw enum strings reach the UI.
 */

const MESSAGES = Object.freeze({
  // Transport-layer
  NO_PEER:        'That device is not paired.',
  NO_KEY:         'Pairing key missing — re-pair this device to refresh keys.',
  NO_TRANSPORT:   'Not connected to the relay. Reload the extension and try again.',
  SIZE_MISMATCH:  'File size mismatch — transfer aborted to protect the file.',
  TOO_BIG:        'File is too large (limit: 500 MB).',
  TOO_MANY_CHUNKS: 'File has too many chunks for a single transfer.',
  // Receiver / completion
  PARTIAL:        "The peer didn't deliver every chunk. Ask them to retry.",
  PEER_FAILED:    'The peer reported a transfer failure.',
  // Codec / framing
  NO_KEY_OR_DECRYPT_FAIL: 'Decryption failed — the keys may be out of sync. Re-pair the device.',
  CLIPBOARD_NOT_FINAL:    'Malformed clipboard frame received.',
  FRAME0_NO_META:         'Malformed transfer header received.',
  BAD_META:               'Malformed transfer metadata received.',
  BAD_TOTAL_CHUNKS:       'Invalid chunk count in transfer metadata.',
  BAD_FILE_SIZE:          'Invalid file size in transfer metadata.',
  BAD_FILENAME:           'Invalid file name in transfer metadata.',
  BAD_MIME:               'Invalid MIME type in transfer metadata.',
  INDEX_OUT_OF_RANGE:     'Out-of-range chunk received — transfer aborted.',
  INTERNAL:               'Something went wrong. Please try again.',
});

/** Look up a user-facing string for a transport error code. */
export function beamErrorMessage(code) {
  return MESSAGES[code] || MESSAGES.INTERNAL;
}
