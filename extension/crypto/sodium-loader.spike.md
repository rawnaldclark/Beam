# libsodium in MV3 Service Worker — Spike Result

**Date:** 2026-04-10
**Outcome:** ✅ **PRIMARY ESM PATH WORKS** — no fallback required.

## Setup

- `extension/lib/sodium-esm/libsodium-sumo.mjs` — copied from `node_modules/libsodium-sumo/dist/modules-sumo-esm/libsodium-sumo.mjs`
- `extension/lib/sodium-esm/libsodium-wrappers.mjs` — copied from `node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs`, with the bare-specifier `import e from "libsodium-sumo"` rewritten to `import e from "./libsodium-sumo.mjs"` so the SW ES module loader can resolve it.
- `extension/crypto/sodium-loader.js` — exports `loadSodium()` which statically imports the wrapper and awaits `sodium.ready`.
- Manifest: `background.type = "module"` (already set) + CSP `script-src 'self' 'wasm-unsafe-eval'` (already set).

## Probe

```js
import { loadSodium } from './crypto/sodium-loader.js';
const sodium = await loadSodium();
const sk = new Uint8Array(32); sk[0] = 1;
const pk = sodium.crypto_scalarmult_base(sk);
// expected: 2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74
```

## Observed (Chrome service worker DevTools console)

```
[beam-crypto-spike] calling loadSodium()...
[beam-crypto-spike] OK  crypto_scalarmult_base(1) = 2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74
[beam-crypto-spike] AEAD fn present: true
```

The X25519 output is byte-correct (standard libsodium test value for the scalar `{01 00 00 ... 00}`). `crypto_aead_xchacha20poly1305_ietf_encrypt` is present on the loaded module.

## Decision

- **Keep `sodium-loader.js` as the static ESM loader.** No offscreen proxy is needed for crypto.
- All subsequent tasks (Chrome `beam-crypto.js`, handshake, integration) can assume that `import { loadSodium } from './crypto/sodium-loader.js'` resolves to a fully-initialized sumo module inside the SW.
- The existing offscreen document (transfer-engine.html) stays in place for non-crypto responsibilities but is no longer on the crypto critical path.

## Cleanup

The temporary `[beam-crypto-spike]` probe added to `background.js` at the top of the file is removed in the same commit as this file.
