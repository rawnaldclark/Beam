// External bootstrap for beam-crypto.test.html — MV3 CSP forbids inline <script>.
// Beam v2 codec tests live in `test/beam-v2.test.js` (Node) and the Kotlin
// side in `BeamV2Test.kt`; the in-browser harness now only verifies the
// shared crypto primitives.
import { runTests } from './beam-crypto.test.js';

const summaryEl = document.getElementById('summary');
const resultsEl = document.getElementById('results');

(async () => {
  try {
    // Suite 1: byte-exact crypto vectors.
    const vectorsOut = await runTests();

    const all = [
      { group: 'crypto vectors', results: vectorsOut.results },
    ];

    let total = 0;
    let passed = 0;
    const lines = [];
    for (const suite of all) {
      lines.push(`<b>── ${suite.group} ──</b>`);
      for (const r of suite.results) {
        total += 1;
        if (r.passed) passed += 1;
        const cls = r.passed ? 'pass' : 'fail';
        const label = r.passed ? 'PASS' : 'FAIL';
        const detail = r.detail ? `  — ${r.detail}` : '';
        lines.push(`<span class="${cls}">${label}</span>  ${r.name}${detail}`);
      }
    }
    const failed = total - passed;

    resultsEl.innerHTML = lines.join('\n');
    summaryEl.textContent = `${passed}/${total} passed (${failed} failed)`;
    summaryEl.className = failed === 0 ? 'pass' : 'fail';
  } catch (err) {
    summaryEl.textContent = `ERROR: ${err && err.message ? err.message : err}`;
    summaryEl.className = 'fail';
    resultsEl.textContent = err && err.stack ? err.stack : String(err);
  }
})();
