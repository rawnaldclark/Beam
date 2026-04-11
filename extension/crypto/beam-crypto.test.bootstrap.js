// External bootstrap for beam-crypto.test.html — MV3 CSP forbids inline <script>.
import { runTests } from './beam-crypto.test.js';
import { runSessionRegistryTests } from './session-registry.test.js';

const summaryEl = document.getElementById('summary');
const resultsEl = document.getElementById('results');

(async () => {
  try {
    // Suite 1: byte-exact crypto vectors.
    const vectorsOut = await runTests();
    // Suite 2: session registry state machine.
    const regResults = await runSessionRegistryTests();

    const all = [
      { group: 'crypto vectors', results: vectorsOut.results },
      { group: 'session registry', results: regResults },
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
