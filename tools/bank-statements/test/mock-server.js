'use strict';
// A fake bank "Statements" page used to test download-statements.js without a real bank.
// It shows a sign-in screen for 1.5s, then a statements list with a year <select>,
// a "Show more" button, rows using two different download mechanisms, and one
// unrelated "Download transactions" link that must be ignored.
const http = require('http');

const MONTH_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

function makePdf(label) {
  const content = `BT /F1 24 Tf 72 720 Td (${label}) Tj ET`;
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = '%PDF-1.4\n';
  const offs = [];
  objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => String(o).padStart(10, '0') + ' 00000 n \n').join('');
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

// Statements exist for the last 4 calendar years, up to last month.
function availableStatements(now) {
  const list = [];
  for (let y = now.getFullYear() - 3; y <= now.getFullYear(); y++) {
    const lastM = y === now.getFullYear() ? now.getMonth() : 12; // getMonth() is 0-based, so this is "last month"
    for (let m = 1; m <= lastM; m++) list.push({ y, m, d: 10 + (m % 3) });
  }
  return list;
}

function page(now) {
  const stmts = availableStatements(now);
  return `<!doctype html><html><head><title>Mock Bank</title></head><body>
<div id="login"><h1>Sign in</h1><input placeholder="username"><input type="password" placeholder="password"><button>Sign in</button></div>
<div id="app" hidden>
  <nav><a href="/">Accounts</a> <a href="/statements">Statements &amp; Documents</a></nav>
  <h1>Statements</h1>
  <label>Statement year <select id="year"></select></label>
  <div id="list"></div>
  <button id="more" hidden>Show more</button>
  <p><a href="/transactions.csv" download>Download transactions</a></p>
</div>
<script>
const MONTH_NAMES = ${JSON.stringify(MONTH_NAMES)};
const STMTS = ${JSON.stringify(stmts)};
const years = [...new Set(STMTS.map(s => s.y))].sort((a, b) => b - a);
let shownAll = false;
setTimeout(() => { document.getElementById('login').hidden = true; document.getElementById('app').hidden = false; init(); }, 1500);
function init() {
  const sel = document.getElementById('year');
  years.forEach(y => { const o = document.createElement('option'); o.textContent = y; o.value = y; sel.appendChild(o); });
  sel.onchange = () => { shownAll = false; render(); };
  document.getElementById('more').onclick = () => { shownAll = true; render(); };
  render();
}
function render() {
  const y = +document.getElementById('year').value;
  const rows = STMTS.filter(s => s.y === y).sort((a, b) => b.m - a.m).map(s => {
    const mm = String(s.m).padStart(2, '0');
    const label = MONTH_NAMES[s.m - 1] + ' ' + s.d + ', ' + s.y;
    const prev = MONTH_NAMES[(s.m + 10) % 12] + ' ' + (s.d + 1);
    const ctl = s.m % 2 === 0
      ? '<a href="/pdf/' + y + '-' + mm + '.pdf" download>Download</a>'
      : '<button aria-label="View statement" onclick="window.open(\\'/pdf/' + y + '-' + mm + '.pdf\\', \\'_blank\\')">View</button>';
    return '<div class="row"><span>' + prev + ' - ' + label + '</span> <span>$' + (100 + s.m) + '.00</span> ' + ctl + '</div>';
  });
  const vis = shownAll ? rows : rows.slice(0, 6);
  document.getElementById('list').innerHTML = vis.join('');
  document.getElementById('more').hidden = shownAll || rows.length <= 6;
}
</script></body></html>`;
}

function start(port = 0) {
  return new Promise((resolve) => {
    const now = new Date();
    const srv = http.createServer((req, res) => {
      const m = req.url.match(/^\/pdf\/(\d{4})-(\d{2})\.pdf$/);
      if (m) {
        res.writeHead(200, { 'content-type': 'application/pdf', 'content-disposition': `inline; filename="statement-${m[1]}-${m[2]}.pdf"` });
        res.end(makePdf(`STATEMENT ${m[1]}-${m[2]}`));
        return;
      }
      if (req.url.startsWith('/transactions.csv')) {
        res.writeHead(200, { 'content-type': 'text/csv' });
        res.end('date,amount\n');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(page(now));
    });
    srv.listen(port, '127.0.0.1', () => resolve({ srv, port: srv.address().port, statements: availableStatements(now) }));
  });
}

module.exports = { start, MONTH_NAMES };
if (require.main === module) start(8765).then(({ port }) => console.log(`mock bank on http://127.0.0.1:${port}/`));
