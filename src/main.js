'use strict';

const invoke = () => window.__TAURI__.core.invoke;
const listen = () => window.__TAURI__.event.listen;

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
    if (btn.dataset.tab === 'netscan') initNetScan();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// HOST CHECK TAB
// ══════════════════════════════════════════════════════════════════════════════

const hostInput    = document.getElementById('host-input');
const checkBtn     = document.getElementById('check-btn');
const results      = document.getElementById('results');
const updownStatus = document.getElementById('updown-status');
const updownLabel  = document.getElementById('updown-label');
const latencyVal   = document.getElementById('latency-val');
const pingVal      = document.getElementById('ping-val');
const macVal       = document.getElementById('mac-val');
const rootWarning  = document.getElementById('root-warning');
const dnsBadge     = document.getElementById('dns-badge');
const dnsBody      = document.getElementById('dns-body');
const sslBadge     = document.getElementById('ssl-badge');
const sslBody      = document.getElementById('ssl-body');
const portGrid     = document.getElementById('port-grid');
const portsSummary = document.getElementById('ports-summary');
const KEY_PORTS    = [22, 80, 443];

let state = { dnsOk: null, portsOpen: 0 };
let debounceTimer = null;

function setBadge(el, status, label) {
  el.className = 'badge ' + status;
  el.textContent = label;
}

function setLoading() {
  state = { dnsOk: null, portsOpen: 0 };
  updownStatus.className = 'summary-status pending';
  updownLabel.textContent = 'checking…';
  latencyVal.className = 'summary-val'; latencyVal.textContent = '…';
  pingVal.className = 'summary-val';    pingVal.textContent = '…';
  macVal.className = 'summary-val';     macVal.textContent = '…';
  rootWarning.classList.add('hidden');
  setBadge(dnsBadge, 'pending', '…');
  dnsBody.innerHTML = '<div class="spinner"></div>';
  setBadge(sslBadge, 'pending', '…');
  sslBody.innerHTML = '<div class="spinner"></div>';
  portGrid.innerHTML = '<div class="spinner"></div>';
  portsSummary.textContent = 'scanning 20 common ports…';
  KEY_PORTS.forEach(port => {
    const el = document.getElementById(`kp-${port}`);
    el.className = 'key-port pending';
    el.querySelector('.kp-status').textContent = '…';
  });
}

function updateUpDown() {
  if (state.dnsOk === null) return;
  const up = state.dnsOk && state.portsOpen > 0;
  updownStatus.className = 'summary-status ' + (up ? 'up' : 'down');
  updownLabel.textContent = up ? 'UP' : 'DOWN';
}

function renderDns(r) {
  if (r.error) {
    setBadge(dnsBadge, 'danger', 'DANGER');
    dnsBody.innerHTML = `<span class="dns-error">${r.error}</span>`;
    state.dnsOk = false;
  } else {
    setBadge(dnsBadge, 'ok', 'OK');
    dnsBody.innerHTML = r.addresses.map(ip => `<div class="dns-ip">${ip}</div>`).join('');
    state.dnsOk = true;
  }
  updateUpDown();
}

function renderSsl(r) {
  if (r.error) {
    setBadge(sslBadge, 'danger', 'DANGER');
    sslBody.innerHTML = `<span class="ssl-error">${r.error}</span>`;
    return;
  }
  const d = r.days_remaining;
  const sc = (!r.valid || d === null || d < 0) ? 'danger' : d <= 30 ? 'warn' : 'ok';
  setBadge(sslBadge, sc, sc === 'danger' ? 'EXPIRED' : sc === 'warn' ? 'WARN' : 'OK');
  const daysLabel = d === null ? '?' : d < 0 ? `expired ${Math.abs(d)}d ago` : `${d} days remaining`;
  sslBody.innerHTML = `
    <div class="ssl-row"><span class="ssl-label">Status</span>
      <span class="ssl-value ${sc}">${r.valid ? 'Valid' : 'Invalid / Expired'}</span></div>
    <div class="ssl-row"><span class="ssl-label">Expires</span>
      <span class="ssl-value ${sc}">${daysLabel}</span></div>
    ${r.subject ? `<div class="ssl-row"><span class="ssl-label">Subject</span>
      <span class="ssl-value normal">${r.subject}</span></div>` : ''}
    ${r.issuer  ? `<div class="ssl-row"><span class="ssl-label">Issuer</span>
      <span class="ssl-value normal">${r.issuer}</span></div>`  : ''}
    ${r.expires ? `<div class="ssl-row"><span class="ssl-label">Not after</span>
      <span class="ssl-value normal">${r.expires}</span></div>` : ''}`;
}

function renderPorts(ports) {
  KEY_PORTS.forEach(port => {
    const entry = ports.find(p => p.port === port);
    const el = document.getElementById(`kp-${port}`);
    if (!entry) return;
    el.className = 'key-port ' + (entry.open ? 'ok' : 'danger');
    el.querySelector('.kp-status').textContent = entry.open ? 'Open' : 'Closed';
  });
  state.portsOpen = ports.filter(p => p.open).length;
  updateUpDown();
  portsSummary.textContent = `${state.portsOpen} open / ${ports.length} scanned`;
  portGrid.innerHTML = ports.map(p => `
    <div class="port-pill ${p.open ? 'open' : 'closed'}">
      <span class="dot"></span>
      <span class="port-num">${p.port}</span>
      <span class="port-svc">${p.service}</span>
    </div>`).join('');
}

function renderLatency(r) {
  if (r.ms !== null && r.ms !== undefined) {
    latencyVal.className = 'summary-val ' + (r.ms < 50 ? 'ok' : r.ms < 200 ? 'warn' : 'danger');
    latencyVal.textContent = `${r.ms}ms (port ${r.port})`;
  } else {
    latencyVal.className = 'summary-val danger';
    latencyVal.textContent = 'unreachable';
  }
}

function renderPing(r) {
  if (r.requires_root) {
    pingVal.className = 'summary-val warn';
    pingVal.textContent = 'requires root';
    rootWarning.classList.remove('hidden');
    return;
  }
  if (!r.success || r.avg_ms === null || r.avg_ms === undefined) {
    pingVal.className = 'summary-val danger';
    pingVal.textContent = r.packet_loss === 100 ? '100% loss' : 'failed';
    return;
  }
  pingVal.className = 'summary-val ' + (r.avg_ms < 50 ? 'ok' : r.avg_ms < 200 ? 'warn' : 'danger');
  const loss = r.packet_loss != null ? ` · ${r.packet_loss}% loss` : '';
  pingVal.textContent = `${r.avg_ms.toFixed(1)}ms${loss}`;
}

function renderMac(r) {
  if (r.mac) {
    macVal.className = 'summary-val ok';
    macVal.textContent = r.mac;
  } else {
    macVal.className = 'summary-val muted';
    macVal.textContent = r.is_local ? 'not in ARP' : 'remote host';
  }
}

async function runChecks(host) {
  if (!host) { hostInput.focus(); return; }
  checkBtn.disabled = true;
  results.classList.remove('hidden');
  setLoading();
  const inv = invoke();
  await Promise.all([
    inv('check_dns',     { host }).then(renderDns)    .catch(e => renderDns({ error: String(e) })),
    inv('check_ssl',     { host }).then(renderSsl)    .catch(e => renderSsl({ error: String(e) })),
    inv('check_ports',   { host }).then(renderPorts)  .catch(e => { portGrid.innerHTML = `<span class="dns-error">${e}</span>`; }),
    inv('check_latency', { host }).then(renderLatency).catch(() => { latencyVal.textContent = 'error'; }),
    inv('check_ping',    { host }).then(renderPing)   .catch(() => { pingVal.textContent = 'error'; }),
    inv('check_mac',     { host }).then(renderMac)    .catch(() => { macVal.textContent = 'error'; }),
  ]);
  checkBtn.disabled = false;
}

// Debounce: auto-scan 800ms after user stops typing
hostInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  const host = hostInput.value.trim();
  if (!host) return;
  debounceTimer = setTimeout(() => runChecks(host), 800);
});

checkBtn.addEventListener('click', () => runChecks(hostInput.value.trim()));
hostInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') { clearTimeout(debounceTimer); runChecks(hostInput.value.trim()); }
});

// ══════════════════════════════════════════════════════════════════════════════
// NETWORK SCAN TAB
// ══════════════════════════════════════════════════════════════════════════════

const subnetSelector = document.getElementById('subnet-selector');
const scanBtn        = document.getElementById('scan-btn');
const progressWrap   = document.getElementById('progress-wrap');
const progressBar    = document.getElementById('progress-bar');
const progressLabel  = document.getElementById('progress-label');
const netscanCard    = document.getElementById('netscan-card');
const netscanSummary = document.getElementById('netscan-summary');
const netscanTbody   = document.getElementById('netscan-tbody');

let unlistenProgress = null;
let unlistenFound    = null;
let unlistenComplete = null;
let netScanInitialized = false;
let foundCount = 0;

async function initNetScan() {
  if (netScanInitialized) return;
  netScanInitialized = true;

  const subnets = await invoke()('get_subnets', {}).catch(() => []);

  if (!subnets.length) {
    subnetSelector.innerHTML = '<span class="subnet-loading" style="color:var(--danger)">No network interfaces found</span>';
    return;
  }

  subnetSelector.innerHTML = subnets.map((s, i) => `
    <input type="radio" class="subnet-radio" name="subnet" id="sn-${i}"
      value="${i}" data-ip="${s.local_ip}" data-prefix="${s.prefix_len}" ${i === 0 ? 'checked' : ''}>
    <label class="subnet-label" for="sn-${i}">
      ${s.local_ip}/${s.prefix_len}
      <span class="subnet-iface">${s.interface} · ${s.scan_count} hosts</span>
    </label>
  `).join('');

  scanBtn.disabled = false;
}

function getSelectedSubnet() {
  const checked = document.querySelector('input[name="subnet"]:checked');
  if (!checked) return null;
  return { localIp: checked.dataset.ip, prefixLen: parseInt(checked.dataset.prefix) };
}

async function startNetScan() {
  const subnet = getSelectedSubnet();
  if (!subnet) return;

  // Cleanup previous listeners
  if (unlistenProgress) { unlistenProgress(); unlistenProgress = null; }
  if (unlistenFound)    { unlistenFound();    unlistenFound = null; }
  if (unlistenComplete) { unlistenComplete(); unlistenComplete = null; }

  scanBtn.disabled = true;
  foundCount = 0;
  netscanTbody.innerHTML = '';
  netscanCard.style.display = 'block';
  netscanSummary.textContent = 'scanning…';
  progressWrap.classList.remove('hidden');
  progressBar.style.width = '0%';
  progressLabel.textContent = '0 / ?';

  const lst = listen();

  unlistenProgress = await lst('scan-progress', ({ payload: p }) => {
    const pct = Math.round((p.scanned / p.total) * 100);
    progressBar.style.width = pct + '%';
    progressLabel.textContent = `${p.scanned} / ${p.total}`;
  });

  unlistenFound = await lst('host-found', ({ payload: host }) => {
    foundCount++;
    netscanSummary.textContent = `${foundCount} host${foundCount !== 1 ? 's' : ''} found`;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td-ip">${host.ip}</td>
      <td class="td-host ${host.hostname ? '' : 'td-none'}">${host.hostname || '—'}</td>
      <td class="td-mac  ${host.mac      ? '' : 'td-none'}">${host.mac      || '—'}</td>`;
    netscanTbody.appendChild(tr);
  });

  unlistenComplete = await lst('scan-complete', ({ payload: total }) => {
    progressBar.style.width = '100%';
    progressLabel.textContent = `Done — ${total} IPs scanned`;
    netscanSummary.textContent = `${foundCount} host${foundCount !== 1 ? 's' : ''} found`;
    scanBtn.disabled = false;
    if (unlistenProgress) { unlistenProgress(); unlistenProgress = null; }
    if (unlistenFound)    { unlistenFound();    unlistenFound = null; }
    if (unlistenComplete) { unlistenComplete(); unlistenComplete = null; }
  });

  invoke()('scan_network', {
    localIp: subnet.localIp,
    prefixLen: subnet.prefixLen,
  }).catch(e => {
    netscanSummary.textContent = 'Error: ' + e;
    scanBtn.disabled = false;
  });
}

scanBtn.addEventListener('click', startNetScan);

// ══════════════════════════════════════════════════════════════════════════════
// TRACEROUTE TAB
// ══════════════════════════════════════════════════════════════════════════════

const trInput  = document.getElementById('tr-input');
const trBtn    = document.getElementById('tr-btn');
const trCard   = document.getElementById('tr-card');
const trOutput = document.getElementById('tr-output');
const trSummary= document.getElementById('tr-summary');

let unlistenTrLine = null;
let unlistenTrDone = null;
let trHopCount = 0;

function parseTrLine(line) {
  // Try to extract hop number, IP and RTT from traceroute output
  // e.g.: " 1  192.168.1.1 (router.local)  2.123 ms  2.234 ms  2.345 ms"
  // e.g.: " 2  * * *"
  const trimmed = line.trim();
  const hopMatch = trimmed.match(/^(\d+)\s+(.*)/);
  if (!hopMatch) return null;

  const n = hopMatch[1];
  const rest = hopMatch[2];

  if (rest.trim() === '* * *' || rest.trim() === '*') {
    return { n, ip: null, rtt: null, timeout: true };
  }

  // Extract IP (possibly with hostname in parens)
  const ipMatch = rest.match(/(\d+\.\d+\.\d+\.\d+)/);
  const ip = ipMatch ? ipMatch[1] : rest.split(/\s+/)[0];

  // Extract first RTT
  const rttMatch = rest.match(/([\d.]+)\s*ms/);
  const rtt = rttMatch ? rttMatch[1] + ' ms' : null;

  return { n, ip, rtt, timeout: false };
}

async function runTraceroute() {
  const host = trInput.value.trim();
  if (!host) { trInput.focus(); return; }

  if (unlistenTrLine) { unlistenTrLine(); unlistenTrLine = null; }
  if (unlistenTrDone) { unlistenTrDone(); unlistenTrDone = null; }

  trBtn.disabled = true;
  trCard.classList.remove('hidden');
  trOutput.innerHTML = '';
  trSummary.textContent = 'tracing…';
  trHopCount = 0;

  const lst = listen();

  unlistenTrLine = await lst('traceroute-line', ({ payload: line }) => {
    const parsed = parseTrLine(line);
    if (parsed) {
      trHopCount++;
      const div = document.createElement('div');
      if (parsed.timeout) {
        div.className = 'tr-hop';
        div.innerHTML = `<span class="tr-n">${parsed.n}</span><span class="tr-star">* * *</span><span class="tr-rtt">timeout</span>`;
      } else {
        div.className = 'tr-hop';
        div.innerHTML = `<span class="tr-n">${parsed.n}</span><span class="tr-ip">${parsed.ip || '?'}</span><span class="tr-rtt">${parsed.rtt || '?'}</span>`;
      }
      trOutput.appendChild(div);
      trOutput.scrollTop = trOutput.scrollHeight;
    } else if (line.trim() && !line.startsWith('traceroute to') && !line.startsWith('tracepath to')) {
      // Show non-hop lines (header etc.) as raw
      const div = document.createElement('div');
      div.className = 'tr-raw';
      div.textContent = line;
      trOutput.appendChild(div);
    }
  });

  unlistenTrDone = await lst('traceroute-done', () => {
    trSummary.textContent = `${trHopCount} hops`;
    trBtn.disabled = false;
    if (unlistenTrLine) { unlistenTrLine(); unlistenTrLine = null; }
    if (unlistenTrDone) { unlistenTrDone(); unlistenTrDone = null; }
  });

  invoke()('run_traceroute', { host }).catch(e => {
    trSummary.textContent = 'Error: ' + e;
    trBtn.disabled = false;
  });
}

trBtn.addEventListener('click', runTraceroute);
trInput.addEventListener('keydown', e => { if (e.key === 'Enter') runTraceroute(); });

// ══════════════════════════════════════════════════════════════════════════════
// DNS RECORDS TAB
// ══════════════════════════════════════════════════════════════════════════════

const dnsRecInput   = document.getElementById('dns-rec-input');
const dnsRecBtn     = document.getElementById('dns-rec-btn');
const dnsRecResults = document.getElementById('dns-rec-results');

function renderRecords(elId, records) {
  const el = document.getElementById(elId);
  if (!records || records.length === 0) {
    el.innerHTML = '<span class="rec-empty">none</span>';
  } else {
    el.innerHTML = records.map(r => `<div class="rec-entry">${r}</div>`).join('');
  }
}

async function runDnsRecords() {
  const host = dnsRecInput.value.trim();
  if (!host) { dnsRecInput.focus(); return; }

  dnsRecBtn.disabled = true;
  dnsRecResults.classList.remove('hidden');
  ['rec-a','rec-cname','rec-mx','rec-ns','rec-txt'].forEach(id => {
    document.getElementById(id).innerHTML = '<div class="spinner"></div>';
  });

  const result = await invoke()('check_dns_records', { host }).catch(e => ({ error: String(e) }));

  if (result.error) {
    ['rec-a','rec-cname','rec-mx','rec-ns','rec-txt'].forEach(id => {
      document.getElementById(id).innerHTML = `<span class="dns-error">${result.error}</span>`;
    });
  } else {
    renderRecords('rec-a',     result.a);
    renderRecords('rec-cname', result.cname);
    renderRecords('rec-mx',    result.mx);
    renderRecords('rec-ns',    result.ns);
    renderRecords('rec-txt',   result.txt);
  }
  dnsRecBtn.disabled = false;
}

dnsRecBtn.addEventListener('click', runDnsRecords);
dnsRecInput.addEventListener('keydown', e => { if (e.key === 'Enter') runDnsRecords(); });

// ══════════════════════════════════════════════════════════════════════════════
// HTTP CHECK TAB
// ══════════════════════════════════════════════════════════════════════════════

const httpInput        = document.getElementById('http-input');
const httpBtn          = document.getElementById('http-btn');
const httpResults      = document.getElementById('http-results');
const httpStatusBox    = document.getElementById('http-status-box');
const httpStatusLabel  = document.getElementById('http-status-label');
const httpTime         = document.getElementById('http-time');
const httpFinalUrl     = document.getElementById('http-final-url');
const httpRedirectsCard= document.getElementById('http-redirects-card');
const httpRedirects    = document.getElementById('http-redirects');
const httpHeaders      = document.getElementById('http-headers');
const httpHeadersCount = document.getElementById('http-headers-count');

function statusClass(code) {
  if (code >= 200 && code < 300) return 'ok';
  if (code >= 300 && code < 400) return 'warn';
  return 'danger';
}

async function runHttpCheck() {
  const url = httpInput.value.trim();
  if (!url) { httpInput.focus(); return; }

  httpBtn.disabled = true;
  httpResults.classList.remove('hidden');
  httpStatusBox.className = 'summary-status pending';
  httpStatusLabel.textContent = '…';
  httpTime.textContent = '…';
  httpFinalUrl.textContent = '…';
  httpRedirectsCard.classList.add('hidden');
  httpRedirects.innerHTML = '';
  httpHeaders.innerHTML = '<div class="spinner"></div>';
  httpHeadersCount.textContent = '—';

  const result = await invoke()('check_http', { url }).catch(e => ({ error: String(e), status: 0, redirects: [], headers: [], response_ms: 0, final_url: url }));

  const sc = result.error ? 'danger' : statusClass(result.status);
  httpStatusBox.className = 'summary-status ' + sc;
  httpStatusLabel.textContent = result.error ? 'Error' : `HTTP ${result.status}`;
  httpTime.textContent = result.response_ms + 'ms';
  httpFinalUrl.textContent = result.final_url || url;

  if (result.redirects && result.redirects.length > 0) {
    httpRedirectsCard.classList.remove('hidden');
    httpRedirects.innerHTML = result.redirects.map(r => `
      <div class="http-redirect">
        <span class="http-redirect-status">${r.status}</span>
        <span class="http-arrow">→</span>
        <span class="http-redirect-url">${r.url}</span>
      </div>`).join('');
  }

  if (result.error) {
    httpHeaders.innerHTML = `<span class="dns-error">${result.error}</span>`;
  } else {
    httpHeadersCount.textContent = result.headers.length + ' headers';
    httpHeaders.innerHTML = result.headers.map(([k, v]) => `
      <div class="http-header-row">
        <span class="http-hk">${k}</span>
        <span class="http-hv">${v}</span>
      </div>`).join('');
  }

  httpBtn.disabled = false;
}

httpBtn.addEventListener('click', runHttpCheck);
httpInput.addEventListener('keydown', e => { if (e.key === 'Enter') runHttpCheck(); });

// ══════════════════════════════════════════════════════════════════════════════
// WHOIS TAB
// ══════════════════════════════════════════════════════════════════════════════

const whoisInput  = document.getElementById('whois-input');
const whoisBtn    = document.getElementById('whois-btn');
const whoisCard   = document.getElementById('whois-card');
const whoisOutput = document.getElementById('whois-output');
const whoisHost   = document.getElementById('whois-host');

async function runWhois() {
  const host = whoisInput.value.trim();
  if (!host) { whoisInput.focus(); return; }

  whoisBtn.disabled = true;
  whoisCard.classList.remove('hidden');
  whoisHost.textContent = host;
  whoisOutput.textContent = 'Loading…';

  const result = await invoke()('check_whois', { host }).catch(e => ({ error: String(e), raw: '' }));

  if (result.error) {
    whoisOutput.textContent = result.error;
  } else {
    // Lightly highlight key fields
    whoisOutput.innerHTML = result.raw
      .split('\n')
      .map(line => {
        const el = document.createElement('span');
        el.textContent = line + '\n';
        if (/^(Registrar|Expir|Creat|Updated|Name Server|Organisation|OrgName|country|netname)/i.test(line.trim())) {
          el.style.color = 'var(--accent)';
        }
        return el.outerHTML;
      })
      .join('');
  }

  whoisBtn.disabled = false;
}

whoisBtn.addEventListener('click', runWhois);
whoisInput.addEventListener('keydown', e => { if (e.key === 'Enter') runWhois(); });

// ══════════════════════════════════════════════════════════════════════════════
// PING TAB
// ══════════════════════════════════════════════════════════════════════════════

const pingHostInput   = document.getElementById('ping-host-input');
const pingCountSelect = document.getElementById('ping-count-select');
const pingStartBtn    = document.getElementById('ping-start-btn');
const pingStopBtn     = document.getElementById('ping-stop-btn');
const pingCard        = document.getElementById('ping-card');
const pingOutput      = document.getElementById('ping-output');
const pingStats       = document.getElementById('ping-stats');
const pingRootWarning = document.getElementById('ping-root-warning');

let unlistenPingLine = null;
let unlistenPingDone = null;
let pingReplyCount   = 0;
let pingTotalCount   = 0;

async function startPing() {
  const host  = pingHostInput.value.trim();
  if (!host) { pingHostInput.focus(); return; }

  const count = parseInt(pingCountSelect.value);

  if (unlistenPingLine) { unlistenPingLine(); unlistenPingLine = null; }
  if (unlistenPingDone) { unlistenPingDone(); unlistenPingDone = null; }

  pingStartBtn.disabled = true;
  pingStopBtn.disabled  = false;
  pingRootWarning.classList.add('hidden');
  pingCard.classList.remove('hidden');
  pingOutput.innerHTML  = '';
  pingStats.textContent = count > 0 ? `0 / ${count}` : 'running…';
  pingReplyCount = 0;
  pingTotalCount = 0;

  const lst = listen();

  unlistenPingLine = await lst('ping-line', ({ payload: p }) => {
    if (p.requires_root) {
      pingRootWarning.classList.remove('hidden');
      pingStats.textContent = 'requires root';
      return;
    }
    pingTotalCount++;
    if (p.is_reply) pingReplyCount++;

    const div = document.createElement('div');
    div.className = 'ping-line' +
      (p.is_reply   ? ' reply'   : '') +
      (p.is_timeout ? ' timeout' : '') +
      (p.is_stats   ? ' stats'   : '') +
      (p.requires_root ? ' root' : '');
    div.textContent = p.line;
    pingOutput.appendChild(div);
    pingOutput.scrollTop = pingOutput.scrollHeight;

    if (!p.is_stats && count > 0) {
      pingStats.textContent = `${pingReplyCount} / ${count} replies`;
    }
  });

  unlistenPingDone = await lst('ping-done', () => {
    pingStartBtn.disabled = false;
    pingStopBtn.disabled  = true;
    pingStats.textContent = `done — ${pingReplyCount} replies`;
    if (unlistenPingLine) { unlistenPingLine(); unlistenPingLine = null; }
    if (unlistenPingDone) { unlistenPingDone(); unlistenPingDone = null; }
  });

  invoke()('run_ping', { host, count }).catch(e => {
    pingStats.textContent = 'Error: ' + e;
    pingStartBtn.disabled = false;
    pingStopBtn.disabled  = true;
  });
}

// Stop just disables the button; the ping process ends naturally or on window close.
// For a real stop we'd need a kill command — for now the count option handles it.
pingStopBtn.addEventListener('click', () => {
  pingStopBtn.disabled = true;
  pingStartBtn.disabled = false;
  pingStats.textContent += ' (stopped)';
  if (unlistenPingLine) { unlistenPingLine(); unlistenPingLine = null; }
  if (unlistenPingDone) { unlistenPingDone(); unlistenPingDone = null; }
});

pingStartBtn.addEventListener('click', startPing);
pingHostInput.addEventListener('keydown', e => { if (e.key === 'Enter') startPing(); });
