// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
// https://github.com/sv102/mcp-gate
//
// MCP Gate — automated screenshot tool for documentation
// Captures all WebUI pages via Playwright headless browser
// and generates an HTML gallery for preview.
//
// Usage: node screenshots.js [options]
//
//   --url       Base URL of MCP Gate     (env MCPGATE_URL, default http://localhost:8000)
//   --password  Admin password            (env MCPGATE_PASSWORD, prompted if not set)
//   --output    Output directory           (default ./screenshots)
//   --width     Viewport width             (default 1440)
//   --height    Viewport height            (default 900)
//   --clean     Remove old PNGs first      (default, use --no-clean to keep)
//   --full-page All pages with full scroll (default: only guide)
//   --delay     Ms to wait after load      (default 800)
//   --no-gallery  Skip HTML gallery generation
//   --help      Show help
//
// Examples:
//   node screenshots.js --url http://192.168.0.103:8090
//   node screenshots.js --width 1920 --height 1080 --full-page
//   MCPGATE_PASSWORD=xxx node screenshots.js --url http://host:8000
//

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// ── Page registry ──────────────────────────────────────────────
const PAGES = [
  { name: '01_login',        path: '/login',        noAuth: true,  title: 'Login',          desc: 'Authentication page with password form' },
  { name: '02_dashboard',    path: '/dashboard',                    title: 'Dashboard',      desc: 'Overview: hosts, agents, recent activity, pending approvals' },
  { name: '03_hosts',        path: '/hosts',                        title: 'Hosts',          desc: 'SSH host management — add, configure, assign command sets' },
  { name: '04_agents',       path: '/agents',                       title: 'Agents',         desc: 'AI agent configuration — API keys, permissions, rate limits' },
  { name: '05_command_sets', path: '/command-sets',                  title: 'Command Sets',   desc: 'Allow/deny command groups with pattern matching' },
  { name: '06_console',      path: '/console',                      title: 'Console',        desc: 'Interactive SSH terminal — execute commands on hosts' },
  { name: '07_audit',        path: '/audit',                        title: 'Audit Log',      desc: 'Full history of all executed commands with filters' },
  { name: '08_approvals',    path: '/approvals',                    title: 'Approvals',      desc: 'Pending command approvals queue (pessimistic mode)' },
  { name: '09_secrets',      path: '/secrets',                      title: 'Secrets',        desc: 'Encrypted secret storage — inject into commands securely' },
  { name: '10_alerts',       path: '/alerts',                       title: 'Alerts',         desc: 'Notification rules — Telegram and SMTP alerts' },
  { name: '11_settings',     path: '/settings',                     title: 'Settings',       desc: 'Instance configuration — auth, SSH, notifications' },
  { name: '12_appearance',   path: '/appearance',                   title: 'Appearance',     desc: 'Theme editor — colors, background, glass effects' },
  { name: '13_guide',        path: '/guide',        fullPage: true, title: 'Guide',          desc: 'Built-in setup and usage guide' },
  { name: '14_about',        path: '/about',                        title: 'About',          desc: 'System info — version, stats, diagnostics' },
];

// ── Argument parsing ───────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    url:      process.env.MCPGATE_URL || 'http://localhost:8000',
    password: process.env.MCPGATE_PASSWORD || '',
    output:   './screenshots',
    width:    1440,
    height:   900,
    clean:    true,
    fullPage: false,
    delay:    800,
    gallery:  true,
  };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':         opts.url = args[++i]; break;
      case '--password':    opts.password = args[++i]; break;
      case '--output':      opts.output = args[++i]; break;
      case '--width':       opts.width = parseInt(args[++i], 10); break;
      case '--height':      opts.height = parseInt(args[++i], 10); break;
      case '--clean':       opts.clean = true; break;
      case '--no-clean':    opts.clean = false; break;
      case '--full-page':   opts.fullPage = true; break;
      case '--delay':       opts.delay = parseInt(args[++i], 10); break;
      case '--no-gallery':  opts.gallery = false; break;
      case '--help': case '-h':
        const src = fs.readFileSync(__filename, 'utf8');
        const help = src.match(/\/\/ Usage:[\s\S]*?\/\/\n/);
        if (help) console.log(help[0].replace(/^\/\/ ?/gm, ''));
        process.exit(0);
    }
  }
  return opts;
}

// ── Prompt password ────────────────────────────────────────────
async function promptPassword() {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      const rl = readline.createInterface({ input: process.stdin });
      rl.question('', (a) => { rl.close(); resolve(a); });
      return;
    }
    process.stderr.write('MCP Gate password: ');
    const raw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.resume();
    let pw = '';
    const onData = (ch) => {
      const c = ch.toString();
      if (c === '\n' || c === '\r') {
        process.stdin.setRawMode(raw);
        process.stdin.removeListener('data', onData);
        process.stdin.pause();
        process.stderr.write('\n');
        resolve(pw);
      } else if (c === '\u007f' || c === '\b') {
        pw = pw.slice(0, -1);
      } else if (c === '\u0003') {
        process.exit(1);
      } else {
        pw += c;
      }
    };
    process.stdin.on('data', onData);
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── HTML Gallery Generator ─────────────────────────────────────
function generateGallery(outDir, files, opts) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const items = files.map(f => {
    const pg = PAGES.find(p => f.startsWith(p.name));
    const sz = fs.statSync(path.join(outDir, f)).size;
    return {
      file: f,
      title: pg ? pg.title : f.replace('.png', ''),
      desc: pg ? pg.desc : '',
      size: `${(sz / 1024).toFixed(0)} KB`,
    };
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Gate — Screenshots</title>
<style>
  :root { --bg: #0f1117; --card: #1a1d27; --border: #2a2d37; --text: #e0e0e0;
          --text2: #888; --accent: #818cf8; --accent-dim: #5558c0; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg);
         color: var(--text); min-height: 100vh; }
  .header { text-align: center; padding: 40px 20px 20px; }
  .header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
  .header h1 span { color: var(--accent); }
  .header .meta { font-size: 13px; color: var(--text2); }
  .header .meta b { color: var(--text); font-weight: 500; }
  .controls { display: flex; justify-content: center; gap: 8px; padding: 16px 20px;
              flex-wrap: wrap; }
  .controls button { background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); padding: 8px 16px; font-size: 13px;
    cursor: pointer; transition: .15s; }
  .controls button:hover, .controls button.active { background: var(--accent-dim);
    border-color: var(--accent); }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
          gap: 20px; padding: 20px 40px 60px; max-width: 1800px; margin: 0 auto; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px;
          overflow: hidden; transition: transform .15s, box-shadow .15s; cursor: pointer; }
  .card:hover { transform: translateY(-4px);
                box-shadow: 0 8px 32px rgba(129,140,248,0.15); }
  .card img { width: 100%; display: block; border-bottom: 1px solid var(--border); }
  .card .info { padding: 14px 16px; }
  .card .info h3 { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
  .card .info p { font-size: 12px; color: var(--text2); line-height: 1.4; }
  .card .info .badge { display: inline-block; font-size: 11px; color: var(--accent);
    background: rgba(129,140,248,0.1); padding: 2px 8px; border-radius: 4px;
    margin-top: 6px; }
  /* Lightbox */
  .lb { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.92);
        z-index: 100; align-items: center; justify-content: center; flex-direction: column; }
  .lb.open { display: flex; }
  .lb img { max-width: 95vw; max-height: 85vh; border-radius: 8px;
            box-shadow: 0 0 60px rgba(0,0,0,0.5); }
  .lb .caption { color: var(--text); font-size: 16px; font-weight: 600; margin-top: 16px; }
  .lb .sub { color: var(--text2); font-size: 13px; margin-top: 4px; }
  .lb .nav { position: absolute; top: 50%; transform: translateY(-50%);
             font-size: 40px; color: #fff; cursor: pointer; padding: 20px;
             user-select: none; opacity: 0.6; transition: .15s; }
  .lb .nav:hover { opacity: 1; }
  .lb .nav.prev { left: 10px; }
  .lb .nav.next { right: 10px; }
  .lb .close { position: absolute; top: 20px; right: 30px; font-size: 32px;
               color: #fff; cursor: pointer; opacity: 0.6; transition: .15s; }
  .lb .close:hover { opacity: 1; }
  .lb .counter { position: absolute; top: 24px; left: 30px; color: var(--text2);
                 font-size: 14px; }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr; padding: 12px; } }
</style>
</head>
<body>

<div class="header">
  <h1>🔐 <span>MCP Gate</span> — Screenshots</h1>
  <p class="meta">
    <b>${items.length}</b> pages &nbsp;·&nbsp;
    <b>${opts.width}×${opts.height}</b> viewport &nbsp;·&nbsp;
    captured <b>${ts}</b>
  </p>
</div>

<div class="controls">
  <button class="active" onclick="filter('all')">All (${items.length})</button>
  <button onclick="filter('core')">Core</button>
  <button onclick="filter('security')">Security</button>
  <button onclick="filter('config')">Config</button>
</div>

<div class="grid" id="grid">
${items.map((item, i) => {
  const tags = [];
  if (['02_dashboard','03_hosts','04_agents','05_command_sets'].includes(item.file.replace('.png','')))
    tags.push('core');
  if (['01_login','07_audit','08_approvals','09_secrets','10_alerts'].includes(item.file.replace('.png','')))
    tags.push('security');
  if (['11_settings','12_appearance','13_guide','14_about'].includes(item.file.replace('.png','')))
    tags.push('config');
  if (['06_console'].includes(item.file.replace('.png','')))
    tags.push('core');
  return `  <div class="card" data-tags="${tags.join(',')}" onclick="openLb(${i})">
    <img src="${item.file}" alt="${item.title}" loading="lazy">
    <div class="info">
      <h3>${item.title}</h3>
      <p>${item.desc}</p>
      <span class="badge">${item.size}</span>
    </div>
  </div>`;
}).join('\n')}
</div>

<div class="lb" id="lb">
  <span class="close" onclick="closeLb()">&times;</span>
  <span class="counter" id="lbCounter"></span>
  <span class="nav prev" onclick="navLb(-1)">&#8249;</span>
  <span class="nav next" onclick="navLb(1)">&#8250;</span>
  <img id="lbImg" src="" alt="">
  <div class="caption" id="lbCaption"></div>
  <div class="sub" id="lbSub"></div>
</div>

<script>
const items = ${JSON.stringify(items)};
let current = 0;

function openLb(i) {
  current = i;
  renderLb();
  document.getElementById('lb').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeLb() {
  document.getElementById('lb').classList.remove('open');
  document.body.style.overflow = '';
}
function navLb(d) {
  current = (current + d + items.length) % items.length;
  renderLb();
}
function renderLb() {
  document.getElementById('lbImg').src = items[current].file;
  document.getElementById('lbCaption').textContent = items[current].title;
  document.getElementById('lbSub').textContent = items[current].desc;
  document.getElementById('lbCounter').textContent = (current+1) + ' / ' + items.length;
}
document.addEventListener('keydown', e => {
  if (!document.getElementById('lb').classList.contains('open')) return;
  if (e.key === 'Escape') closeLb();
  if (e.key === 'ArrowLeft') navLb(-1);
  if (e.key === 'ArrowRight') navLb(1);
});

function filter(tag) {
  document.querySelectorAll('.controls button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.card').forEach(c => {
    const tags = c.dataset.tags;
    c.style.display = (tag === 'all' || tags.includes(tag)) ? '' : 'none';
  });
}
</script>
</body>
</html>`;

  const galleryPath = path.join(outDir, 'index.html');
  fs.writeFileSync(galleryPath, html);
  return galleryPath;
}

// ── Main ───────────────────────────────────────────────────────
async function main() {
  const opts = parseArgs();

  if (!opts.password) {
    opts.password = await promptPassword();
  }
  if (!opts.password) {
    console.error('Error: password is required');
    process.exit(1);
  }

  const outDir = path.resolve(opts.output);
  fs.mkdirSync(outDir, { recursive: true });

  // Clean
  if (opts.clean) {
    const old = fs.readdirSync(outDir).filter(f => f.endsWith('.png') || f === 'index.html');
    if (old.length > 0) {
      old.forEach(f => fs.unlinkSync(path.join(outDir, f)));
      console.log(`Cleaned ${old.length} old files\n`);
    }
  }

  const viewport = { width: opts.width, height: opts.height };
  console.log('MCP Gate Screenshot Tool');
  console.log(`  URL:      ${opts.url}`);
  console.log(`  Output:   ${outDir}`);
  console.log(`  Viewport: ${viewport.width}×${viewport.height}`);
  console.log(`  Pages:    ${PAGES.length}`);
  console.log(`  Clean:    ${opts.clean}`);
  console.log('');

  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();
  let captured = 0;

  // Login page
  console.log(`[1/${PAGES.length}] Login`);
  await page.goto(`${opts.url}/login`, { waitUntil: 'networkidle' });
  await sleep(opts.delay);
  await page.screenshot({ path: path.join(outDir, '01_login.png') });
  console.log('  ✓');
  captured++;

  // Auth via API
  console.log('\nAuthenticating...');
  const resp = await page.evaluate(async (pw) => {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw })
    });
    return { status: r.status, body: await r.text() };
  }, opts.password);

  if (resp.status !== 200) {
    console.error(`Login failed (${resp.status}): ${resp.body}`);
    await browser.close();
    process.exit(1);
  }
  console.log('  ✓ OK\n');

  // Pages
  let idx = 2;
  for (const pg of PAGES) {
    if (pg.noAuth) continue;
    console.log(`[${idx}/${PAGES.length}] ${pg.title}`);
    try {
      await page.goto(`${opts.url}${pg.path}`, { waitUntil: 'networkidle', timeout: 15000 });
      await sleep(opts.delay);
      const doFull = opts.fullPage || pg.fullPage;
      await page.screenshot({ path: path.join(outDir, `${pg.name}.png`), fullPage: !!doFull });
      console.log('  ✓');
      captured++;
    } catch (err) {
      console.error(`  ✗ ${err.message}`);
    }
    idx++;
  }

  await browser.close();

  // Gallery
  const files = fs.readdirSync(outDir).filter(f => f.endsWith('.png')).sort();
  let totalBytes = 0;

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`${captured}/${PAGES.length} screenshots captured:\n`);
  files.forEach(f => {
    const sz = fs.statSync(path.join(outDir, f)).size;
    totalBytes += sz;
    console.log(`  ${f.padEnd(28)} ${(sz / 1024).toFixed(0).padStart(5)} KB`);
  });
  console.log(`\n  Total: ${(totalBytes / 1024 / 1024).toFixed(1)} MB`);

  if (opts.gallery && files.length > 0) {
    const gp = generateGallery(outDir, files, opts);
    console.log(`\n  Gallery: ${gp}`);
    console.log('  Open in browser to preview all screenshots');
  }
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
