/* =========================================================
   CLAUD Pro Panel — mobile-first frontend
   - Real-time terminal (Socket.IO + polling fallback)
   - Live CPU/RAM/Disk stats
   - Process manager, AI fixer, backups, auto-restart
   - Bottom-nav tabs, swipe-to-close, skeleton loading
   All rendered inside a floating bottom sheet — the existing
   dashboard markup is untouched.
   ========================================================= */
(function () {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const html = (strings, ...vals) => {
    const t = document.createElement('template');
    t.innerHTML = String.raw(strings, ...vals).trim();
    return t.content.firstElementChild;
  };
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Minimal ANSI → HTML (colors + reset). Enough for python coloured tracebacks.
  const ANSI = {
    30: 'color:#6b7280', 31: 'color:#ff4d5e', 32: 'color:#22e07a',
    33: 'color:#ffb020', 34: 'color:#7ec8ff', 35: 'color:#c084fc',
    36: 'color:#00e5ff', 37: 'color:#e5e7eb', 90: 'color:#4b5563',
    91: 'color:#ff8ba0', 92: 'color:#7ff0b0', 93: 'color:#ffd166',
    94: 'color:#93c5fd', 95: 'color:#e0b1ff', 96: 'color:#88f7ff',
    1: 'font-weight:700', 4: 'text-decoration:underline'
  };
  function ansiToHtml(text) {
    text = esc(text);
    let open = 0, out = '';
    text = text.replace(/\x1b\[([0-9;]*)m/g, (_, codes) => {
      let seg = '';
      const parts = codes.split(';').filter(Boolean);
      if (parts.length === 0 || parts.includes('0')) {
        seg += '</span>'.repeat(open); open = 0; return seg;
      }
      const styles = parts.map(p => ANSI[+p]).filter(Boolean).join(';');
      if (styles) { open++; seg += `<span style="${styles}">`; }
      return seg;
    });
    out = text + '</span>'.repeat(open);
    // Highlight common tokens
    out = out.replace(/(Traceback[^<]*)/g, '<span class="err">$1</span>')
             .replace(/((?:^|\n)[^\n]*Error:[^\n]*)/g, '<span class="err">$1</span>')
             .replace(/((?:^|\n)\[[^\]]+\] \[INFO\][^\n]*)/g, '<span class="info">$1</span>')
             .replace(/((?:^|\n)\[[^\]]+\] \[CMD\][^\n]*)/g, '<span class="hl">$1</span>');
    return out;
  }

  // Detect current server folder from existing dashboard state.
  function detectFolder() {
    // Try common globals used by existing dashboard.html
    if (window.currentFolder) return window.currentFolder;
    if (window.activeFolder) return window.activeFolder;
    if (window.selectedFolder) return window.selectedFolder;
    // Fallback: read data attribute anywhere on the page
    const el = document.querySelector('[data-server-folder]');
    if (el) return el.getAttribute('data-server-folder');
    // Fallback: URL query
    const p = new URLSearchParams(location.search);
    return p.get('folder') || p.get('server') || '';
  }

  // CSRF from any existing input the app renders
  function csrfToken() {
    const el = document.querySelector('input[name="csrf_token"]');
    return el ? el.value : (window.CSRF_TOKEN || '');
  }

  async function api(path, opts = {}) {
    opts.headers = Object.assign({ 'X-CSRF-Token': csrfToken() }, opts.headers || {});
    if (opts.json !== undefined) {
      opts.body = JSON.stringify(opts.json);
      opts.headers['Content-Type'] = 'application/json';
      delete opts.json;
    }
    const r = await fetch(path, opts);
    if (r.status === 204) return {};
    try { return await r.json(); } catch { return {}; }
  }

  // ─── Socket.IO (with polling fallback) ─────────────────
  let socket = null;
  function ensureSocket(cb) {
    if (socket) return cb(socket);
    if (typeof io === 'undefined') {
      const s = document.createElement('script');
      s.src = 'https://cdn.socket.io/4.7.5/socket.io.min.js';
      s.onload = () => { socket = io({ transports: ['websocket', 'polling'] }); cb(socket); };
      s.onerror = () => cb(null); // still render terminal in polling-only mode
      document.head.appendChild(s);
    } else {
      socket = io({ transports: ['websocket', 'polling'] });
      cb(socket);
    }
  }

  // ─── Panel scaffold ────────────────────────────────────
  const TABS = [
    { id: 'stats', label: 'Live',    icon: 'fa-gauge-high' },
    { id: 'term',  label: 'Console', icon: 'fa-terminal' },
    { id: 'proc',  label: 'Procs',   icon: 'fa-microchip' },
    { id: 'ai',    label: 'AI Fix',  icon: 'fa-wand-magic-sparkles' },
    { id: 'more',  label: 'More',    icon: 'fa-toolbox' }
  ];

  function buildSheet() {
    const sheet = html`
      <div class="pp-sheet" id="pp-sheet" role="dialog" aria-modal="true" aria-label="Pro Panel">
        <div class="pp-sheet-inner">
          <div class="pp-grabber"></div>
          <div class="pp-header">
            <div class="pp-title"><span class="pp-dot"></span> Pro Panel <span class="pp-muted" id="pp-folder"></span></div>
            <button class="pp-close" id="pp-close" aria-label="Close"><i class="fas fa-xmark"></i></button>
          </div>
          <div class="pp-tabs" id="pp-tabs"></div>
          <div class="pp-body" id="pp-body"></div>
        </div>
      </div>`;
    document.body.appendChild(sheet);

    const tabs = $('#pp-tabs');
    TABS.forEach((t, i) => {
      const b = html`<button class="pp-tab ${i===0?'active':''}" data-tab="${t.id}">
        <i class="fas ${t.icon}"></i><span>${t.label}</span></button>`;
      b.addEventListener('click', () => selectTab(t.id));
      tabs.appendChild(b);
    });

    $('#pp-close').addEventListener('click', closePanel);
    sheet.addEventListener('click', (e) => { if (e.target === sheet) closePanel(); });

    // Swipe-down to dismiss
    let startY = null;
    sheet.addEventListener('touchstart', (e) => { startY = e.touches[0].clientY; }, { passive: true });
    sheet.addEventListener('touchmove', (e) => {
      if (startY == null) return;
      const dy = e.touches[0].clientY - startY;
      if (dy > 90) { closePanel(); startY = null; }
    }, { passive: true });
  }

  function buildFab() {
    const fab = html`<button class="pp-fab" id="pp-fab" aria-label="Open Pro Panel">
      <i class="fas fa-bolt"></i></button>`;
    fab.addEventListener('click', openPanel);
    document.body.appendChild(fab);
  }

  function openPanel() {
    const folder = detectFolder();
    if (!folder) {
      // If no server context, still open with stats-only view
      $('#pp-folder').textContent = '(no server selected)';
    } else {
      $('#pp-folder').textContent = '· ' + folder;
    }
    $('#pp-sheet').classList.add('open');
    selectTab('stats');
    ensureSocket((s) => {
      if (!s || !folder) return;
      s.emit('term:subscribe', { folder });
      s.emit('stats:subscribe', { folder });
    });
  }
  function closePanel() {
    $('#pp-sheet').classList.remove('open');
    stopStatsPolling();
    stopTermPolling();
  }

  // ─── Tab renderers ─────────────────────────────────────
  let currentTab = null;
  function selectTab(id) {
    currentTab = id;
    $$('.pp-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === id));
    const body = $('#pp-body');
    body.innerHTML = '';
    if (id === 'stats') renderStats(body);
    else if (id === 'term') renderTerm(body);
    else if (id === 'proc') renderProc(body);
    else if (id === 'ai')   renderAI(body);
    else if (id === 'more') renderMore(body);
  }

  // ── Stats tab
  let statsTimer = null;
  function stopStatsPolling() { if (statsTimer) { clearInterval(statsTimer); statsTimer = null; } }
  function renderStats(body) {
    body.appendChild(html`
      <div class="pp-card">
        <h4>Server <span class="pp-pill" id="pp-status">…</span></h4>
        <div class="pp-stat-grid">
          <div class="pp-stat"><div class="k">CPU</div><div class="v" id="pp-s-cpu">–<small>%</small></div><div class="pp-bar"><i id="pp-b-cpu" style="width:0"></i></div></div>
          <div class="pp-stat"><div class="k">RAM</div><div class="v" id="pp-s-ram">–<small>MB</small></div><div class="pp-bar"><i id="pp-b-ram" style="width:0"></i></div></div>
          <div class="pp-stat"><div class="k">Threads</div><div class="v" id="pp-s-th">–</div></div>
          <div class="pp-stat"><div class="k">Uptime</div><div class="v" id="pp-s-up">–</div></div>
        </div>
      </div>
      <div class="pp-card">
        <h4>System</h4>
        <div class="pp-stat-grid">
          <div class="pp-stat"><div class="k">System CPU</div><div class="v" id="pp-ss-cpu">–<small>%</small></div><div class="pp-bar"><i id="pp-bb-cpu" style="width:0"></i></div></div>
          <div class="pp-stat"><div class="k">System RAM</div><div class="v" id="pp-ss-ram">–<small>%</small></div><div class="pp-bar"><i id="pp-bb-ram" style="width:0"></i></div></div>
          <div class="pp-stat"><div class="k">Disk</div><div class="v" id="pp-ss-disk">–<small>%</small></div><div class="pp-bar"><i id="pp-bb-disk" style="width:0"></i></div></div>
          <div class="pp-stat"><div class="k">Network ↑↓ MB</div><div class="v" id="pp-ss-net">– / –</div></div>
        </div>
      </div>
      <div class="pp-card">
        <h4>Quick actions</h4>
        <div class="pp-term-toolbar">
          <button class="pp-btn primary" data-act="start"><i class="fas fa-play"></i> Start</button>
          <button class="pp-btn" data-act="restart"><i class="fas fa-rotate"></i> Restart</button>
          <button class="pp-btn danger" data-act="stop"><i class="fas fa-stop"></i> Stop</button>
          <button class="pp-btn danger" id="pp-killall"><i class="fas fa-skull"></i> Kill</button>
        </div>
      </div>`);

    body.querySelectorAll('[data-act]').forEach(b => b.addEventListener('click', async () => {
      const f = detectFolder(); if (!f) return;
      b.disabled = true;
      await api(`/server/action/${f}/${b.dataset.act}`, { method: 'POST' });
      b.disabled = false;
    }));
    $('#pp-killall').addEventListener('click', async () => {
      const f = detectFolder(); if (!f) return;
      const r = await api(`/server/processes/${f}`);
      if (r.root_pid) await api(`/server/kill-pid/${f}`, { method: 'POST', json: { pid: r.root_pid } });
    });

    ensureSocket((s) => {
      if (s) s.on('stats:data', applyStats);
    });
    // Also poll as fallback
    tickStats();
    statsTimer = setInterval(tickStats, 3000);
  }
  async function tickStats() {
    const f = detectFolder(); if (!f) return;
    const d = await api(`/server/stats/${f}`).catch(() => null);
    if (!d) return;
    applyStats({
      online: d.online, cpu: parseFloat(d.cpu||0), ram_mb: parseFloat(d.ram||0),
      threads: parseInt(d.threads||0,10), uptime_s: null,
      sys: {
        cpu: parseFloat(d.sys_cpu||0), ram_pct: parseFloat(d.sys_ram_pct||0),
        disk_pct: parseFloat(d.sys_disk_pct||0),
        net_sent_mb: parseFloat(d.net_sent||0), net_recv_mb: parseFloat(d.net_recv||0)
      }, _uptime_txt: d.uptime
    });
  }
  function applyStats(p) {
    if (currentTab !== 'stats') return;
    const set = (id, v) => { const el = $('#'+id); if (el) el.innerHTML = v; };
    const bar = (id, pct) => { const el = $('#'+id); if (el) el.style.width = Math.min(100, pct||0) + '%'; };
    const status = $('#pp-status'); if (status) {
      status.textContent = p.online ? 'Online' : 'Offline';
      status.className = 'pp-pill ' + (p.online ? 'on' : 'off');
    }
    set('pp-s-cpu', `${(p.cpu||0).toFixed(1)}<small>%</small>`); bar('pp-b-cpu', p.cpu||0);
    set('pp-s-ram', `${(p.ram_mb||0).toFixed(1)}<small>MB</small>`); bar('pp-b-ram', Math.min(100, (p.ram_mb||0)/5));
    set('pp-s-th', p.threads ?? '–');
    let up = p._uptime_txt;
    if (!up && p.uptime_s != null) {
      const s = p.uptime_s; const h=Math.floor(s/3600), m=Math.floor(s%3600/60), sec=s%60;
      up = (h?h+'h ':'') + (m?m+'m ':'') + sec+'s';
    }
    set('pp-s-up', up || (p.online ? 'Online' : 'Offline'));
    if (p.sys) {
      set('pp-ss-cpu', `${(p.sys.cpu||0).toFixed(1)}<small>%</small>`); bar('pp-bb-cpu', p.sys.cpu);
      set('pp-ss-ram', `${(p.sys.ram_pct||0).toFixed(1)}<small>%</small>`); bar('pp-bb-ram', p.sys.ram_pct);
      set('pp-ss-disk', `${(p.sys.disk_pct||0).toFixed(1)}<small>%</small>`); bar('pp-bb-disk', p.sys.disk_pct);
      set('pp-ss-net', `${(p.sys.net_sent_mb||0).toFixed(1)} / ${(p.sys.net_recv_mb||0).toFixed(1)}`);
    }
  }

  // ── Terminal tab
  let autoScroll = true, termPollTimer = null, termOffset = 0, cmdHistory = [], histIdx = -1;
  function stopTermPolling() { if (termPollTimer) { clearInterval(termPollTimer); termPollTimer = null; } }
  function renderTerm(body) {
    body.appendChild(html`
      <div class="pp-card pp-term-wrap">
        <div class="pp-term-toolbar">
          <input class="pp-input" id="pp-term-search" placeholder="Search logs…" style="flex:1; min-width:120px;"/>
          <button class="pp-btn small" id="pp-term-clear"><i class="fas fa-eraser"></i></button>
          <button class="pp-btn small" id="pp-term-dl"><i class="fas fa-download"></i></button>
          <button class="pp-btn small" id="pp-term-scroll" title="Auto-scroll"><i class="fas fa-angles-down"></i></button>
          <button class="pp-btn small" id="pp-term-full"><i class="fas fa-expand"></i></button>
        </div>
        <div class="pp-term" id="pp-term" tabindex="0"></div>
        <div class="pp-input-row">
          <input class="pp-input" id="pp-cmd" placeholder="$ command  (Enter to run · ↑/↓ history)" autocomplete="off"/>
          <button class="pp-btn primary" id="pp-cmd-run"><i class="fas fa-paper-plane"></i></button>
        </div>
      </div>
      <div id="pp-diag-inline"></div>`);

    termOffset = 0;
    const term = $('#pp-term');
    const search = $('#pp-term-search');

    $('#pp-term-clear').addEventListener('click', () => term.innerHTML = '');
    $('#pp-term-dl').addEventListener('click', () => {
      const f = detectFolder(); if (!f) return;
      const blob = new Blob([term.innerText], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${f}-console.log`; a.click();
    });
    $('#pp-term-scroll').addEventListener('click', (e) => {
      autoScroll = !autoScroll;
      e.currentTarget.style.color = autoScroll ? 'var(--pp-cyan)' : 'var(--pp-dim)';
    });
    $('#pp-term-full').addEventListener('click', () => term.classList.toggle('full'));

    search.addEventListener('input', () => {
      const q = search.value.toLowerCase();
      $$('#pp-term span[data-line]').forEach(el => {
        el.style.display = !q || el.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });

    const cmd = $('#pp-cmd');
    cmd.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { runCmd(cmd.value); cmd.value = ''; }
      else if (e.key === 'ArrowUp') { if (histIdx < cmdHistory.length - 1) { histIdx++; cmd.value = cmdHistory[cmdHistory.length-1-histIdx] || ''; } e.preventDefault(); }
      else if (e.key === 'ArrowDown') { if (histIdx > 0) { histIdx--; cmd.value = cmdHistory[cmdHistory.length-1-histIdx] || ''; } else { histIdx=-1; cmd.value=''; } e.preventDefault(); }
    });
    $('#pp-cmd-run').addEventListener('click', () => { runCmd(cmd.value); cmd.value=''; });

    // Live via socket + fallback polling
    ensureSocket((s) => {
      if (s) {
        s.on('term:data', (p) => { if (p.folder === detectFolder()) appendChunk(p.chunk); });
        s.on('term:diagnosis', (p) => { if (p.folder === detectFolder()) inlineDiag(p.diagnosis); });
      }
    });
    // Prime with existing log, then keep polling as safety net.
    (async () => {
      const f = detectFolder(); if (!f) return;
      const r = await api(`/server/log/${f}?offset=0`);
      if (r && r.log) { appendChunk(r.log); termOffset = r.offset || 0; }
    })();
    termPollTimer = setInterval(async () => {
      const f = detectFolder(); if (!f) return;
      const r = await api(`/server/log/${f}?offset=${termOffset}`);
      if (r && r.log) { appendChunk(r.log); termOffset = r.offset || termOffset; }
    }, 2500);
  }
  function appendChunk(chunk) {
    const term = $('#pp-term'); if (!term) return;
    const wrap = document.createElement('span');
    wrap.setAttribute('data-line', '1');
    wrap.innerHTML = ansiToHtml(chunk);
    term.appendChild(wrap);
    // Prune to last ~500 KB of DOM to stay fast on mobile
    while (term.childNodes.length > 400) term.removeChild(term.firstChild);
    if (autoScroll) term.scrollTop = term.scrollHeight;
  }
  async function runCmd(cmd) {
    cmd = (cmd || '').trim(); if (!cmd) return;
    const f = detectFolder(); if (!f) return;
    cmdHistory.push(cmd); histIdx = -1;
    appendChunk(`\n\x1b[36m$ ${cmd}\x1b[0m\n`);
    const r = await api(`/server/command/${f}`, { method: 'POST', json: { command: cmd } });
    if (r && r.output) appendChunk(r.output + '\n');
  }
  function inlineDiag(d) {
    const box = $('#pp-diag-inline'); if (!box) return;
    box.innerHTML = ''; box.appendChild(renderDiagCard(d));
  }

  // ── Processes tab
  function renderProc(body) {
    body.appendChild(html`
      <div class="pp-card">
        <h4>Processes <button class="pp-btn small" id="pp-proc-refresh"><i class="fas fa-rotate"></i></button></h4>
        <div id="pp-proc-wrap"><div class="pp-skel"></div><div class="pp-skel"></div><div class="pp-skel"></div></div>
      </div>`);
    $('#pp-proc-refresh').addEventListener('click', loadProc);
    loadProc();
  }
  async function loadProc() {
    const f = detectFolder(); if (!f) return;
    const r = await api(`/server/processes/${f}`);
    const wrap = $('#pp-proc-wrap'); if (!wrap) return;
    if (!r.processes || !r.processes.length) {
      wrap.innerHTML = '<div class="pp-muted">No running processes.</div>'; return;
    }
    const tbl = html`<table class="pp-proc"><thead><tr><th>PID</th><th>Name</th><th>CPU</th><th>RAM</th><th>Thr</th><th></th></tr></thead><tbody></tbody></table>`;
    r.processes.forEach(p => {
      const tr = html`<tr>
        <td class="n">${p.pid}</td><td>${esc(p.name)}</td>
        <td>${p.cpu.toFixed(1)}%</td><td>${p.ram_mb} MB</td><td>${p.threads}</td>
        <td><button class="pp-btn small danger" data-pid="${p.pid}"><i class="fas fa-xmark"></i></button></td>
      </tr>`;
      tr.querySelector('button').addEventListener('click', async (e) => {
        const pid = e.currentTarget.dataset.pid;
        await api(`/server/kill-pid/${f}`, { method: 'POST', json: { pid: +pid } });
        loadProc();
      });
      tbl.querySelector('tbody').appendChild(tr);
    });
    wrap.innerHTML = ''; wrap.appendChild(tbl);
  }

  // ── AI tab
  function renderDiagCard(d) {
    const card = html`
      <div class="pp-diag">
        <span class="conf">${d.confidence||0}% confidence</span>
        <span class="badge err">${esc(d.type||'Error')}</span>
        <div class="t">${esc(d.title||'')}</div>
        <div class="e">${esc(d.explanation||'')}</div>
        <div class="e" style="margin-top:6px"><b>Fix:</b> ${esc(d.fix||'')}</div>
        ${d.command ? `<div class="cmd"><span>${esc(d.command)}</span>
          <span style="display:flex;gap:4px;flex-shrink:0">
            <button class="pp-btn small" data-copy="${esc(d.command)}"><i class="fas fa-copy"></i></button>
            <button class="pp-btn small primary" data-install="${esc(d.command)}"><i class="fas fa-download"></i></button>
          </span></div>` : ''}
      </div>`;
    card.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => {
      navigator.clipboard?.writeText(b.dataset.copy);
      b.innerHTML = '<i class="fas fa-check"></i>';
      setTimeout(() => b.innerHTML = '<i class="fas fa-copy"></i>', 1200);
    }));
    card.querySelectorAll('[data-install]').forEach(b => b.addEventListener('click', async () => {
      const cmd = b.dataset.install || '';
      const m = cmd.match(/pip install(?: --user)? +([^\s].*)$/);
      if (!m) return;
      const f = detectFolder(); if (!f) return;
      b.disabled = true; b.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
      const res = await api(`/server/install/${f}`, { method: 'POST', json: { package: m[1] } });
      b.disabled = false;
      b.innerHTML = res.status === 'success' ? '<i class="fas fa-check"></i>' : '<i class="fas fa-triangle-exclamation"></i>';
    }));
    return card;
  }
  function renderAI(body) {
    body.appendChild(html`
      <div class="pp-card">
        <h4>AI Auto-Fix <button class="pp-btn small" id="pp-ai-refresh"><i class="fas fa-rotate"></i> Scan</button></h4>
        <div id="pp-ai-wrap"><div class="pp-skel"></div><div class="pp-skel"></div></div>
      </div>`);
    $('#pp-ai-refresh').addEventListener('click', loadAI);
    loadAI();
  }
  async function loadAI() {
    const f = detectFolder(); const wrap = $('#pp-ai-wrap'); if (!f || !wrap) return;
    wrap.innerHTML = '<div class="pp-skel"></div><div class="pp-skel"></div>';
    const r = await api(`/ai/analyze/${f}`);
    wrap.innerHTML = '';
    if (!r.findings || !r.findings.length) {
      wrap.appendChild(html`<div class="pp-diag ok"><span class="badge">Clean</span>
        <div class="t">No known errors detected</div>
        <div class="e">Console output looks healthy. Rerun the scan after your next crash.</div></div>`);
      return;
    }
    r.findings.forEach(d => wrap.appendChild(renderDiagCard(d)));
    if (r.missing_packages && r.missing_packages.length) {
      const cmd = `pip install --user ${r.missing_packages.join(' ')}`;
      wrap.appendChild(html`<div class="pp-diag">
        <span class="badge">Bulk install</span>
        <div class="t">Missing requirements</div>
        <div class="e">Install everything the log flagged in one shot.</div>
        <div class="cmd"><span>${esc(cmd)}</span>
          <button class="pp-btn small primary" id="pp-ai-bulk"><i class="fas fa-download"></i></button>
        </div></div>`);
      $('#pp-ai-bulk').addEventListener('click', async (e) => {
        e.currentTarget.disabled = true;
        for (const p of r.missing_packages) {
          await api(`/server/install/${detectFolder()}`, { method: 'POST', json: { package: p } });
        }
        loadAI();
      });
    }
  }

  // ── More tab (backups, clone, auto-restart, etc.)
  function renderMore(body) {
    body.appendChild(html`
      <div class="pp-card">
        <h4>Auto-restart on crash</h4>
        <div class="pp-row">
          <div><div>Restart automatically when the process exits with an error.</div>
            <div class="pp-muted" id="pp-ar-status">Loading…</div></div>
          <div class="pp-switch" id="pp-ar-toggle"></div>
        </div>
      </div>
      <div class="pp-card">
        <h4>Backups <button class="pp-btn small primary" id="pp-bk-new"><i class="fas fa-floppy-disk"></i> Create</button></h4>
        <ul class="pp-list" id="pp-bk-list"><li class="pp-muted">Loading…</li></ul>
      </div>
      <div class="pp-card">
        <h4>Server</h4>
        <div class="pp-term-toolbar">
          <button class="pp-btn" id="pp-clone"><i class="fas fa-clone"></i> Clone server</button>
          <a class="pp-btn" id="pp-dl-all" href="#"><i class="fas fa-file-zipper"></i> Download all</a>
        </div>
      </div>
      <div class="pp-card">
        <h4>Session</h4>
        <div class="pp-muted">Session auto-locks after 60 minutes of inactivity. Rate limit: 120 req/min.</div>
      </div>`);

    const f = detectFolder();
    // Auto-restart
    (async () => {
      if (!f) return;
      const s = await api(`/server/autorestart/${f}`);
      $('#pp-ar-toggle').classList.toggle('on', !!s.enabled);
      $('#pp-ar-status').textContent = s.enabled ? 'Enabled' : 'Disabled';
    })();
    $('#pp-ar-toggle').addEventListener('click', async (e) => {
      const on = !e.currentTarget.classList.contains('on');
      await api(`/server/autorestart/${f}`, { method: 'POST', json: { enabled: on } });
      e.currentTarget.classList.toggle('on', on);
      $('#pp-ar-status').textContent = on ? 'Enabled' : 'Disabled';
    });

    // Backups
    async function loadBk() {
      const list = $('#pp-bk-list');
      const r = await api(`/server/backups/${f}`);
      list.innerHTML = '';
      if (!r.backups || !r.backups.length) {
        list.appendChild(html`<li class="pp-muted">No backups yet.</li>`); return;
      }
      r.backups.forEach(b => {
        const li = html`<li>
          <div><div>${esc(b.name)}</div><div class="meta">${b.size_human} · ${b.modified}</div></div>
          <div class="actions">
            <a class="pp-btn small" href="/server/backup-download/${f}/${encodeURIComponent(b.name)}"><i class="fas fa-download"></i></a>
            <button class="pp-btn small" data-r="${esc(b.name)}"><i class="fas fa-rotate-left"></i></button>
            <button class="pp-btn small danger" data-d="${esc(b.name)}"><i class="fas fa-trash"></i></button>
          </div></li>`;
        li.querySelector('[data-r]').addEventListener('click', async () => {
          if (!confirm('Restore this backup? Existing files with the same name will be overwritten.')) return;
          await api(`/server/backup-restore/${f}`, { method: 'POST', json: { name: b.name } });
          alert('Restored.');
        });
        li.querySelector('[data-d]').addEventListener('click', async () => {
          if (!confirm('Delete backup?')) return;
          await api(`/server/backup-delete/${f}`, { method: 'POST', json: { name: b.name } });
          loadBk();
        });
        list.appendChild(li);
      });
    }
    $('#pp-bk-new').addEventListener('click', async (e) => {
      e.currentTarget.disabled = true;
      await api(`/server/backup/${f}`, { method: 'POST' });
      e.currentTarget.disabled = false; loadBk();
    });
    if (f) loadBk();

    $('#pp-clone').addEventListener('click', async () => {
      if (!confirm('Create a clone of this server?')) return;
      const r = await api(`/server/clone/${f}`, { method: 'POST' });
      alert(r.status === 'ok' ? `Cloned as ${r.name}` : (r.msg || 'Failed'));
    });
    $('#pp-dl-all').href = `/files/download-folder/${f}?path=&name=`;
  }

  // ─── Boot ──────────────────────────────────────────────
  function boot() {
    if (document.getElementById('pp-fab')) return;
    document.body.setAttribute('data-pp-amoled', '1');
    buildSheet();
    buildFab();
    // Keyboard shortcut: press "P" to open panel
    document.addEventListener('keydown', (e) => {
      if (e.key === 'P' && !/input|textarea/i.test((e.target||{}).tagName || '')) openPanel();
      if (e.key === 'Escape') closePanel();
    });
    // Expose for existing code
    window.ProPanel = { open: openPanel, close: closePanel, api };
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
