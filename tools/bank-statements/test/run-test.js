'use strict';
// End-to-end test: run download-statements.js against the mock bank and check the files it saves.
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { start, MONTH_NAMES } = require('./mock-server');

const MONTHS = 24;
const outDir = path.join(__dirname, 'out');
const profile = path.join(__dirname, 'profile');

(async () => {
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.rmSync(profile, { recursive: true, force: true });
  const { srv, port, statements } = await start(0);
  const now = new Date();
  const cutoff = new Date(now.getFullYear(), now.getMonth() - MONTHS, 1);
  const expected = statements.filter((s) => new Date(s.y, s.m - 1, s.d) >= cutoff);
  const notExpected = statements.filter((s) => new Date(s.y, s.m - 1, s.d) < cutoff);

  const args = [path.join(__dirname, '..', 'download-statements.js'), '--url', `http://127.0.0.1:${port}/`, '--name', 'MockBank', '--out', outDir, '--profile', profile, '--months', String(MONTHS), '--headless', '--login-timeout', '2'];
  console.log('> node', args.join(' '));
  const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
  let log = '';
  child.stdout.on('data', (d) => { process.stdout.write(d); log += d; });
  child.stderr.on('data', (d) => { process.stderr.write(d); log += d; });
  const code = await new Promise((r) => child.on('close', r));
  srv.close();

  const problems = [];
  if (code !== 0) problems.push(`script exited with code ${code}`);
  for (const s of expected) {
    const f = path.join(outDir, String(s.y), `${MONTH_NAMES[s.m - 1]} ${s.d}.pdf`);
    if (!fs.existsSync(f)) { problems.push(`missing ${s.y}/${MONTH_NAMES[s.m - 1]} ${s.d}.pdf`); continue; }
    const buf = fs.readFileSync(f);
    const tag = `STATEMENT ${s.y}-${String(s.m).padStart(2, '0')}`;
    if (buf.slice(0, 4).toString() !== '%PDF') problems.push(`${f} is not a PDF`);
    else if (!buf.toString('latin1').includes(tag)) problems.push(`${f} has the wrong content (expected ${tag})`);
  }
  for (const s of notExpected) {
    const f = path.join(outDir, String(s.y), `${MONTH_NAMES[s.m - 1]} ${s.d}.pdf`);
    if (fs.existsSync(f)) problems.push(`downloaded out-of-range statement ${s.y}/${MONTH_NAMES[s.m - 1]} ${s.d}.pdf`);
  }
  const all = fs.existsSync(outDir) ? fs.readdirSync(outDir, { recursive: true }).filter((f) => f.endsWith('.pdf') || f.endsWith('.csv')) : [];
  const extras = all.filter((f) => !/^\d{4}[\\/][A-Z][a-z]+ \d{1,2}\.pdf$/.test(f));
  if (extras.length) problems.push(`unexpected files: ${extras.join(', ')}`);
  if (/transactions/i.test(log.split('Statements list found')[1] || '')) problems.push('the transactions link was treated as a statement');

  console.log(`\nexpected ${expected.length} statements, saved ${all.length} files`);
  if (problems.length) { console.log('TEST FAILED'); problems.forEach((p) => console.log(' - ' + p)); process.exit(1); }
  console.log('TEST PASSED');
})();
