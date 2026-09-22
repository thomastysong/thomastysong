#!/usr/bin/env node
'use strict';

const USAGE = `
download-statements.js

Saves the last N months of card statements (PDF) from a bank's online
"Statements" page. You log in yourself in the browser window that opens;
the script never sees, asks for, or stores your password or 2FA code.
Once the list of statements is on screen, the script takes over: it walks
the year selector, finds each statement's download/view control, clicks
it, and saves the PDF as  <out>/<Year>/<Month Day>.pdf  (e.g. 2026/August 12.pdf).

Usage:
  node download-statements.js capitalone
  node download-statements.js citi
  node download-statements.js --url "https://.../Statements" --name MyBank

Options:
  --months N          how far back to go (default 24)
  --out DIR           where to save (default ~/Downloads/Statements/<Name>)
  --drive             save into Google Drive for desktop instead:
                      <My Drive>/<drive-folder>/<Name>/  (auto-detected)
  --drive-folder P    folder inside My Drive to use with --drive (default "Statements")
  --url URL           page to open first (defaults to the bank's home page)
  --name NAME         bank/card name used for the folder (default from preset)
  --dry-run           log in and list what would be downloaded, click nothing
  --profile DIR       browser profile dir (default ~/.bank-statements-browser-profile)
  --login-timeout M   minutes to wait for you to log in (default 20)
  --headless          no visible window (only useful for automated tests)
`;


const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

function loadPlaywright() {
  try {
    return require('playwright').chromium;
  } catch (e) {
    console.error('Playwright is not installed. In this folder run:  npm install   and try again.');
    process.exit(1);
  }
}

const PRESETS = {
  capitalone: {
    name: 'CapitalOne',
    url: 'https://myaccounts.capitalone.com/',
    hint: 'Sign in, open the card, then click "Statements".',
  },
  citi: {
    name: 'Citi',
    url: 'https://online.citi.com/',
    hint: 'Sign in, open the card, then open "Statements" (sometimes under "Statements & Documents").',
  },
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage() {
  console.log(USAGE.trim());
}

function expandHome(p) {
  return p && p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p;
}

// Where Google Drive for desktop mirrors "My Drive" on this computer.
function findDriveDesktopRoot() {
  const home = os.homedir();
  const cands = [];
  if (process.platform === 'darwin') {
    const cs = path.join(home, 'Library', 'CloudStorage');
    try {
      for (const d of fs.readdirSync(cs)) if (d.startsWith('GoogleDrive-')) cands.push(path.join(cs, d, 'My Drive'));
    } catch (e) { /* no CloudStorage dir */ }
    cands.push(path.join(home, 'Google Drive', 'My Drive'), '/Volumes/GoogleDrive/My Drive', path.join(home, 'Google Drive'));
  } else if (process.platform === 'win32') {
    for (let c = 67; c <= 90; c++) cands.push(`${String.fromCharCode(c)}:\\My Drive`);
    cands.push(path.join(home, 'Google Drive', 'My Drive'), path.join(home, 'Google Drive'));
  } else {
    cands.push(path.join(home, 'Google Drive', 'My Drive'), path.join(home, 'GoogleDrive', 'My Drive'));
  }
  if (process.env.GOOGLE_DRIVE_ROOT) cands.unshift(expandHome(process.env.GOOGLE_DRIVE_ROOT));
  return cands.find((p) => { try { return fs.statSync(p).isDirectory(); } catch (e) { return false; } }) || null;
}

function parseArgs(argv) {
  const o = { months: 24, dryRun: false, headless: false, url: null, name: null, out: null, profile: null, loginTimeoutMin: 20, drive: false, driveFolder: 'Statements' };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) { console.error(`Missing value for ${a}`); process.exit(2); }
      return argv[++i];
    };
    if (a === '--months') o.months = parseInt(next(), 10);
    else if (a === '--out') o.out = next();
    else if (a === '--url') o.url = next();
    else if (a === '--name') o.name = next();
    else if (a === '--profile') o.profile = next();
    else if (a === '--login-timeout') o.loginTimeoutMin = parseInt(next(), 10);
    else if (a === '--drive') o.drive = true;
    else if (a === '--drive-folder') o.driveFolder = next();
    else if (a === '--dry-run') o.dryRun = true;
    else if (a === '--headless') o.headless = true;
    else if (a === '--help' || a === '-h') { usage(); process.exit(0); }
    else if (a.startsWith('--')) { console.error(`Unknown option ${a}\n`); usage(); process.exit(2); }
    else rest.push(a);
  }
  const presetKey = rest[0] && rest[0].toLowerCase();
  const preset = presetKey ? PRESETS[presetKey] : null;
  if (presetKey && !preset) {
    console.error(`Unknown bank "${rest[0]}". Known presets: ${Object.keys(PRESETS).join(', ')} — or pass --url.`);
    process.exit(2);
  }
  if (!preset && !o.url) { usage(); process.exit(2); }
  if (!Number.isFinite(o.months) || o.months < 1) { console.error('--months must be a positive whole number'); process.exit(2); }
  if (!Number.isFinite(o.loginTimeoutMin) || o.loginTimeoutMin < 1) { console.error('--login-timeout must be a positive whole number'); process.exit(2); }
  o.name = (o.name || (preset ? preset.name : 'Bank')).replace(/[^\w.-]+/g, '');
  o.url = o.url || preset.url;
  o.hint = preset ? preset.hint : 'Sign in and open the Statements page.';
  if (o.out) {
    o.out = expandHome(o.out);
  } else if (o.drive) {
    const root = findDriveDesktopRoot();
    if (!root) {
      console.error('Could not find a Google Drive for desktop folder on this computer.');
      console.error('Install Google Drive for desktop (https://www.google.com/drive/download/) and sign in, or pass --out <folder>');
      console.error('and drag the folder into Google Drive afterwards.');
      process.exit(2);
    }
    o.out = path.join(root, ...o.driveFolder.split(/[\\/]+/).filter(Boolean), o.name);
  } else {
    o.out = path.join(os.homedir(), 'Downloads', 'Statements', o.name);
  }
  o.profile = expandHome(o.profile) || path.join(os.homedir(), '.bank-statements-browser-profile');
  return o;
}

// ---------------------------------------------------------------------------
// In-page scanners. These run INSIDE the browser via page.evaluate, so they
// must be self-contained (no references to variables outside the function).
// ---------------------------------------------------------------------------

function scanForStatements() {
  const MONTH_RE = '(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)';
  const DATE_RE = new RegExp(
    '\\b' + MONTH_RE + '\\.?\\s+(?:(\\d{1,2})(?:st|nd|rd|th)?,?\\s+)?(\\d{4})\\b' +
    '|\\b(\\d{1,2})/(\\d{1,2})/(\\d{4}|\\d{2})\\b' +
    '|\\b(\\d{4})-(\\d{2})-(\\d{2})\\b',
    'gi'
  );
  const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  const LABEL_RE = /\bdownload\b|\.pdf\b|\bpdf\b|\bview\b|\bopen\b|\bsave\b|\bstatement\b/i;

  function datesIn(text) {
    const out = [];
    let m;
    DATE_RE.lastIndex = 0;
    while ((m = DATE_RE.exec(text))) {
      if (m[1]) out.push({ y: +m[3], m: MONTHS.indexOf(m[1].slice(0, 3).toLowerCase()) + 1, d: m[2] ? +m[2] : null });
      else if (m[4]) { let y = +m[6]; if (y < 100) y += 2000; out.push({ y, m: +m[4], d: +m[5] }); }
      else out.push({ y: +m[7], m: +m[8], d: +m[9] });
    }
    return out.filter((x) => x.m >= 1 && x.m <= 12 && x.y > 1990 && x.y < 2100 && (x.d === null || (x.d >= 1 && x.d <= 31)));
  }

  function visible(el) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== 'hidden' && s.display !== 'none';
  }

  function textOf(el) {
    return (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
  }

  function labelOf(el) {
    const parts = [textOf(el), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('href'), el.getAttribute('download'), el.getAttribute('value')];
    el.querySelectorAll('img[alt], svg title, [aria-label], [title]').forEach((c) => {
      parts.push(c.getAttribute('alt'), c.getAttribute('aria-label'), c.getAttribute('title'), c.tagName === 'title' ? c.textContent : '');
    });
    return parts.filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
  }

  function scoreOf(label) {
    if (/\bdownload\b|\.pdf\b|\bpdf\b|\bsave\b/i.test(label)) return 3;
    if (/\bstatement\b/i.test(label)) return 2;
    return 1;
  }

  document.querySelectorAll('[data-stmt-idx]').forEach((e) => e.removeAttribute('data-stmt-idx'));
  document.querySelectorAll('[data-stmt-cand]').forEach((e) => e.removeAttribute('data-stmt-cand'));

  const controls = [];
  document.querySelectorAll('a, button, [role="button"], [role="link"], input[type="button"], input[type="submit"]').forEach((el) => {
    if (!visible(el)) return;
    const label = labelOf(el);
    if (!LABEL_RE.test(label)) return;
    if (el.parentElement && el.parentElement.closest('[data-stmt-cand]')) return; // nested control inside a control
    el.setAttribute('data-stmt-cand', '1');
    controls.push({ el, label });
  });

  // For each control, find the "row" it belongs to: the nearest ancestor whose
  // text contains a date, provided that ancestor is small (few controls, little
  // text). The LAST date in the row is used — for "Jul 16 – Aug 15, 2026" that
  // is the closing date, which is what names a statement.
  const results = [];
  controls.forEach(({ el, label }, i) => {
    let node = el;
    let date = null;
    let rowText = '';
    for (let depth = 0; node && depth < 10; depth++, node = node.parentElement) {
      if (node.querySelectorAll('[data-stmt-cand]').length > 3) break;
      const t = depth === 0 ? label : textOf(node);
      if (t.length > 600) break;
      const dates = datesIn(t);
      if (dates.length) { date = dates[dates.length - 1]; rowText = t; break; }
    }
    if (!date) return;
    el.setAttribute('data-stmt-idx', String(i));
    results.push({
      idx: i,
      y: date.y, m: date.m, d: date.d,
      label: label.slice(0, 160),
      row: rowText.slice(0, 160),
      href: el.getAttribute('href') || '',
      score: scoreOf(label),
    });
  });
  document.querySelectorAll('[data-stmt-cand]').forEach((e) => e.removeAttribute('data-stmt-cand'));
  return results;
}

function scanForYearControls({ minYear, maxYear }) {
  document.querySelectorAll('[data-stmt-year]').forEach((e) => e.removeAttribute('data-stmt-year'));
  document.querySelectorAll('[data-stmt-year-select]').forEach((e) => e.removeAttribute('data-stmt-year-select'));

  function visible(el) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== 'hidden' && s.display !== 'none';
  }

  const result = { selects: [], clickables: [] };
  let n = 0;
  document.querySelectorAll('select').forEach((sel) => {
    const years = Array.from(sel.options)
      .map((o) => ({ value: o.value, year: +((o.textContent.match(/\b(\d{4})\b/) || [])[1]) }))
      .filter((o) => o.year >= minYear && o.year <= maxYear);
    if (years.length && visible(sel)) {
      sel.setAttribute('data-stmt-year-select', String(n));
      result.selects.push({ idx: n++, years });
    }
  });

  document.querySelectorAll('a, button, [role="button"], [role="tab"], [role="option"], [role="menuitem"], [role="radio"], li, label, span, div, p, td').forEach((el) => {
    if (el.children.length > 2) return;
    const t = (el.innerText || el.textContent || '').trim();
    const m = t.match(/^(?:FY\s*)?(\d{4})$/);
    if (!m) return;
    const y = +m[1];
    if (y < minYear || y > maxYear) return;
    if (!visible(el)) return;
    if (el.parentElement && el.parentElement.closest('[data-stmt-year]')) return;
    el.setAttribute('data-stmt-year', String(y));
    result.clickables.push({ year: y });
  });
  return result;
}

// ---------------------------------------------------------------------------
// PDF capture: downloads, inline PDF responses, and blob: popups all end up
// in the same queue so the caller can "click, then wait for one PDF".
// ---------------------------------------------------------------------------

function makeCapturer(context) {
  const waiters = [];
  const strays = [];
  const seen = new Set();

  function deliver(item) {
    const hash = crypto.createHash('sha1').update(item.buf).digest('hex');
    if (seen.has(hash)) return;
    seen.add(hash);
    item.hash = hash;
    const w = waiters.shift();
    if (w) w.resolve(item);
    else strays.push(item);
  }

  function isPdf(buf) {
    return buf && buf.length > 4 && buf.slice(0, 4).toString() === '%PDF';
  }

  function attach(p) {
    p.on('download', async (dl) => {
      try {
        const tmp = await dl.path();
        if (!tmp) return;
        const buf = fs.readFileSync(tmp);
        if (isPdf(buf)) deliver({ buf, name: dl.suggestedFilename(), source: 'download' });
      } catch (e) { /* cancelled or failed download */ }
    });
  }

  context.pages().forEach(attach);
  context.on('page', async (p) => {
    attach(p);
    try {
      await p.waitForLoadState('domcontentloaded', { timeout: 8000 }).catch(() => {});
      const u = p.url();
      if (u.startsWith('blob:')) {
        const b64 = await p.evaluate(async (blobUrl) => {
          const r = await fetch(blobUrl);
          const bytes = new Uint8Array(await r.arrayBuffer());
          let s = '';
          for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
          return btoa(s);
        }, u);
        const buf = Buffer.from(b64, 'base64');
        if (isPdf(buf)) deliver({ buf, name: 'statement.pdf', source: 'blob' });
      }
    } catch (e) { /* not a blob PDF we can read */ }
  });

  context.on('response', async (r) => {
    try {
      const h = r.headers();
      const ct = (h['content-type'] || '').toLowerCase();
      const cd = h['content-disposition'] || '';
      const url = r.url();
      if (!(ct.includes('application/pdf') || /\.pdf/i.test(cd) || /\.pdf(\?|#|$)/i.test(url))) return;
      let buf = await r.body();
      if (!isPdf(buf)) {
        // Chrome's PDF viewer swallowed the bytes; fetch the same URL again with the browser's cookies.
        if (!ct.includes('application/pdf') || r.request().method() !== 'GET') return;
        const again = await context.request.get(url, { timeout: 20000 }).catch(() => null);
        if (!again) return;
        buf = await again.body();
        if (!isPdf(buf)) return;
      }
      const cdName = (cd.match(/filename\*?=(?:utf-8'')?"?([^";]+)/i) || [])[1];
      let urlName = '';
      try { urlName = path.basename(new URL(url).pathname); } catch (e) { /* ignore */ }
      deliver({ buf, name: cdName || urlName || 'statement.pdf', source: 'response' });
    } catch (e) { /* body unavailable (e.g. it became a download) */ }
  });

  function waitForPdf(ms) {
    return new Promise((resolve) => {
      const w = { resolve };
      waiters.push(w);
      setTimeout(() => {
        const i = waiters.indexOf(w);
        if (i >= 0) { waiters.splice(i, 1); resolve(null); }
      }, ms);
    });
  }

  return { waitForPdf, strays };
}

// ---------------------------------------------------------------------------
// Page driving helpers
// ---------------------------------------------------------------------------

const MONTH_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

function statementFileName(c) {
  return c.d ? `${MONTH_NAMES[c.m - 1]} ${c.d}.pdf` : `${MONTH_NAMES[c.m - 1]}.pdf`;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function settle(page) {
  await page.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
  await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
  await sleep(700);
}

async function safeEvaluate(page, fn, arg) {
  try { return await page.evaluate(fn, arg); } catch (e) { return null; }
}

async function expandAll(page) {
  for (let i = 0; i < 12; i++) {
    const btn = page
      .locator('a, button, [role="button"]')
      .filter({ hasText: /^\s*((show|load)\s+(more|all|older)|view\s+(more|older)\s+statements?)\b/i })
      .first();
    if (!(await btn.count()) || !(await btn.isVisible().catch(() => false))) break;
    await btn.click({ timeout: 3000 }).catch(() => {});
    await settle(page);
  }
  await safeEvaluate(page, () => window.scrollTo(0, document.body.scrollHeight));
  await sleep(400);
  await safeEvaluate(page, () => window.scrollTo(0, 0));
}

async function selectYear(page, year, range) {
  let ctl = await safeEvaluate(page, scanForYearControls, range);
  if (!ctl) return false;
  if (ctl.selects.length) {
    const s = ctl.selects.find((x) => x.years.some((y) => y.year === year));
    if (!s) return false;
    const opt = s.years.find((y) => y.year === year);
    await page.locator(`[data-stmt-year-select="${s.idx}"]`).first().selectOption(opt.value);
    await settle(page);
    return true;
  }
  if (!ctl.clickables.some((c) => c.year === year)) {
    // Probably a closed custom dropdown: click its trigger and look again.
    const trigger = page.locator('[data-stmt-year], [aria-haspopup="listbox"], [aria-haspopup="menu"], [aria-haspopup="true"]').first();
    if (await trigger.count()) {
      await trigger.click({ timeout: 3000 }).catch(() => {});
      await sleep(700);
      ctl = await safeEvaluate(page, scanForYearControls, range);
    }
  }
  if (ctl && ctl.clickables.some((c) => c.year === year)) {
    await page.locator(`[data-stmt-year="${year}"]`).first().click({ timeout: 5000 });
    await settle(page);
    return true;
  }
  return false;
}

async function closeExtraPages(context, keep) {
  for (const p of context.pages()) {
    if (p !== keep) await p.close().catch(() => {});
  }
}

async function findCandidate(page, key) {
  const found = (await safeEvaluate(page, scanForStatements)) || [];
  return found
    .map((c) => ({ ...c, key: `${c.y}-${String(c.m).padStart(2, '0')}` }))
    .filter((c) => c.key === key)
    .sort((a, b) => b.score - a.score)[0] || null;
}

async function clickAndCapture(context, page, cap, cand) {
  let loc = page.locator(`[data-stmt-idx="${cand.idx}"]`).first();
  if ((await loc.count()) === 0) {
    // The list re-rendered since we scanned; find the control again.
    const again = await findCandidate(page, cand.key);
    if (!again) return null;
    loc = page.locator(`[data-stmt-idx="${again.idx}"]`).first();
  }
  const listingUrl = page.url();
  await loc.scrollIntoViewIfNeeded().catch(() => {});
  const wait = cap.waitForPdf(25000);
  try {
    await loc.click({ timeout: 5000 });
  } catch (e) {
    await loc.click({ timeout: 5000, force: true }).catch(() => {});
  }
  const item = await wait;
  await sleep(300);
  if (page.url() !== listingUrl && !page.isClosed()) {
    // The click navigated the main tab (e.g. to an inline PDF). Go back.
    await page.goBack({ timeout: 10000 }).catch(() => {});
    await settle(page);
  }
  await closeExtraPages(context, page);
  return item;
}

async function waitForStatements(context, page, opts) {
  const deadline = Date.now() + opts.loginTimeoutMin * 60 * 1000;
  let lastHint = 0;
  console.log(`\nA browser window is open. ${opts.hint}`);
  console.log('Waiting until a list of statements is visible… (Ctrl+C to abort)');
  while (Date.now() < deadline) {
    for (const p of context.pages()) {
      if (p.isClosed()) continue;
      const found = await safeEvaluate(p, scanForStatements);
      if (found && found.length) return p;
    }
    if (Date.now() - lastHint > 30000) {
      lastHint = Date.now();
      console.log(`  … still waiting (${Math.round((deadline - Date.now()) / 60000)} min left). ${opts.hint}`);
    }
    if (context.pages().every((p) => p.isClosed())) throw new Error('The browser window was closed.');
    await sleep(2000);
  }
  throw new Error(`Gave up after ${opts.loginTimeoutMin} minutes without seeing a statements list.`);
}

// Chrome normally renders PDFs in its built-in viewer, which hides the bytes
// from us. This profile preference makes it download them instead.
function preferPdfDownloads(profileDir) {
  const prefFile = path.join(profileDir, 'Default', 'Preferences');
  let prefs = {};
  try { prefs = JSON.parse(fs.readFileSync(prefFile, 'utf8')); } catch (e) { /* new profile */ }
  prefs.plugins = Object.assign({}, prefs.plugins, { always_open_pdf_externally: true });
  prefs.download = Object.assign({}, prefs.download, { prompt_for_download: false });
  fs.mkdirSync(path.dirname(prefFile), { recursive: true });
  fs.writeFileSync(prefFile, JSON.stringify(prefs));
}

async function launchBrowser(opts) {
  const chromium = loadPlaywright();
  fs.mkdirSync(opts.profile, { recursive: true });
  preferPdfDownloads(opts.profile);
  const base = {
    headless: opts.headless,
    acceptDownloads: true,
    viewport: opts.headless ? { width: 1280, height: 900 } : null,
    args: ['--disable-blink-features=AutomationControlled'],
    ignoreDefaultArgs: ['--enable-automation'],
  };
  const attempts = process.env.BROWSER_PATH
    ? [{ executablePath: process.env.BROWSER_PATH }]
    : [{ channel: 'chrome' }, { channel: 'msedge' }, {}];
  let lastErr = null;
  for (const a of attempts) {
    try {
      return await chromium.launchPersistentContext(opts.profile, { ...base, ...a });
    } catch (e) {
      lastErr = e;
    }
  }
  console.error('Could not start a browser. Install Google Chrome, or run:  npx playwright install chromium');
  console.error(lastErr && lastErr.message);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  fs.mkdirSync(opts.out, { recursive: true });

  const now = new Date();
  const cutoff = new Date(now.getFullYear(), now.getMonth() - opts.months, 1);
  const range = { minYear: cutoff.getFullYear(), maxYear: now.getFullYear() };
  const inWindow = (c) => {
    const dt = new Date(c.y, c.m - 1, c.d || 1);
    return dt >= cutoff && dt <= new Date(now.getFullYear(), now.getMonth() + 1, 28);
  };

  console.log(`${opts.name}: statements from ${cutoff.getFullYear()}-${String(cutoff.getMonth() + 1).padStart(2, '0')} onward (${opts.months} months)`);
  console.log(`Saving to: ${opts.out}${opts.dryRun ? '   [DRY RUN — nothing will be clicked or saved]' : ''}`);

  const context = await launchBrowser(opts);
  const cap = makeCapturer(context);
  const shutdown = async () => { await context.close().catch(() => {}); process.exit(130); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  let page = context.pages()[0] || (await context.newPage());
  await page.goto(opts.url, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch((e) => {
    console.warn(`Could not open ${opts.url} automatically (${e.message.split('\n')[0]}). Navigate there yourself in the window.`);
  });

  page = await waitForStatements(context, page, opts);
  console.log(`\nStatements list found at ${page.url()}\n`);

  const done = new Set();
  const failures = [];
  let saved = 0;
  let skippedExisting = 0;

  async function harvestAndDownload(label) {
    await expandAll(page);
    const found = (await safeEvaluate(page, scanForStatements)) || [];
    const byKey = new Map();
    for (const c of found) {
      if (!inWindow(c)) continue;
      const key = `${c.y}-${String(c.m).padStart(2, '0')}`;
      const prev = byKey.get(key);
      if (!prev || c.score > prev.score) byKey.set(key, { ...c, key });
    }
    const cands = [...byKey.values()].filter((c) => !done.has(c.key)).sort((a, b) => (a.key < b.key ? 1 : -1));
    console.log(`[${label}] ${found.length} statement control(s) on page, ${cands.length} new in range`);
    for (const c of cands) {
      const fileName = statementFileName(c);
      const file = path.join(opts.out, String(c.y), fileName);
      if (fs.existsSync(file) || fs.existsSync(path.join(opts.out, fileName))) {
        console.log(`  = ${c.key}  already saved, skipping`);
        done.add(c.key); skippedExisting++;
        continue;
      }
      if (opts.dryRun) {
        console.log(`  ~ ${c.key}  would click "${c.label.slice(0, 60)}"  (row: ${c.row.slice(0, 70)})`);
        done.add(c.key);
        continue;
      }
      process.stdout.write(`  ↓ ${c.key}  clicking "${c.label.slice(0, 40)}" … `);
      const item = await clickAndCapture(context, page, cap, c);
      if (!item) {
        console.log('no PDF received within 25s');
        failures.push(c.key);
        continue;
      }
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, item.buf);
      console.log(`saved ${c.y}/${fileName} (${Math.round(item.buf.length / 1024)} KB, via ${item.source})`);
      done.add(c.key); saved++;
    }
  }

  const first = (await safeEvaluate(page, scanForYearControls, range)) || { selects: [], clickables: [] };
  const hasYearControls = first.selects.length > 0 || first.clickables.length > 0;

  if (!hasYearControls) {
    await harvestAndDownload('all years');
  } else {
    for (let y = range.maxYear; y >= range.minYear; y--) {
      const ok = await selectYear(page, y, range);
      if (!ok) { console.log(`[${y}] no year control found for ${y}, skipping`); continue; }
      await harvestAndDownload(String(y));
    }
  }

  // Anything that arrived without a matching click (e.g. two PDFs from one click).
  for (const s of cap.strays) {
    const safe = (s.name || 'statement.pdf').replace(/[^\w.-]+/g, '_');
    const file = path.join(opts.out, `unmatched-${s.hash.slice(0, 8)}-${safe}`);
    if (!opts.dryRun) { fs.writeFileSync(file, s.buf); console.log(`  + extra PDF saved as ${path.basename(file)}`); }
  }

  const expected = [];
  for (let d = new Date(cutoff); d < now; d.setMonth(d.getMonth() + 1)) {
    expected.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`);
  }
  const missing = expected.filter((k) => !done.has(k));

  console.log('\nSummary');
  console.log(`  saved now:        ${saved}`);
  console.log(`  already had:      ${skippedExisting}`);
  console.log(`  failed:           ${failures.length}${failures.length ? '  (' + failures.join(', ') + ')' : ''}`);
  if (missing.length) console.log(`  months not seen:  ${missing.join(', ')}  (may not exist, or the page hides them)`);
  console.log(`  folder:           ${opts.out}`);

  await context.close().catch(() => {});
  process.exit(failures.length ? 1 : 0);
}

main().catch(async (e) => {
  console.error(`\nError: ${e.message}`);
  process.exit(1);
});
