ultMsg').className = 'bad';
  }
}
// MailSleuth frontend — part 3: dashboard, history, DNS/IP, local AI, admin, logs, init.
Object.assign(I18N.en, {
  authservLabel: 'Authentication server', authHeaderLabel: 'Authentication-Results header',
  geoLabel: 'Geolocation', geoUnavailable: 'Geolocation unavailable.', regionLabel: 'Region', accuracyLabel: 'Accuracy',
  timezoneLabel: 'Timezone', dnsSourceNative: 'Native DNS', resolverLabel: 'Resolvers', authRecords: 'Authentication records',
  warningsLabel: 'Warnings', durationLabel: 'Duration', keyUsed: 'Key used', keyNotUsed: 'No key', informationLabel: 'Information',
  transcriptLabel: 'Transcript', rawLabel: 'Raw', reportingNameServer: 'Reporting nameserver'
});
Object.assign(I18N.vi, {
  authservLabel: 'Máy chủ xác thực', authHeaderLabel: 'Header Authentication-Results',
  geoLabel: 'Định vị', geoUnavailable: 'Không có dữ liệu định vị.', regionLabel: 'Vùng', accuracyLabel: 'Độ chính xác',
  timezoneLabel: 'Múi giờ', dnsSourceNative: 'DNS gốc', resolverLabel: 'Bộ phân giải', authRecords: 'Bản ghi xác thực',
  warningsLabel: 'Cảnh báo', durationLabel: 'Thời lượng', keyUsed: 'Có dùng key', keyNotUsed: 'Không dùng key', informationLabel: 'Thông tin',
  transcriptLabel: 'Bản ghi', rawLabel: 'Dữ liệu gốc', reportingNameServer: 'Nameserver báo cáo'
});

// ---------------------------------------------------------------------------
// dashboard
// ---------------------------------------------------------------------------
async function loadDashboard() {
  try {
    const r = await api('/api/cases?limit=500');
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return;
    const cases = Array.isArray(j.cases) ? j.cases : [];
    let msgs = 0, bad = 0, warn = 0, ok = 0;
    for (const c of cases) {
      msgs += Number(c.count) || 0;
      if (c.verdict === 'malicious_or_phishing') bad++;
      else if (c.verdict === 'suspicious') warn++;
      else if (c.verdict === 'clean') ok++;
    }
    if ($('dashCases')) $('dashCases').textContent = String(cases.length);
    if ($('dashMessages')) $('dashMessages').textContent = String(msgs);
    if ($('dashBad')) $('dashBad').textContent = String(bad);
    if ($('dashWarn')) $('dashWarn').textContent = String(warn);
    if ($('dashOk')) $('dashOk').textContent = String(ok);
  } catch {}
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------
function renderHistory(cases) {
  const out = $('histOut');
  if (!out) return;
  out.textContent = '';
  if (!cases.length) { out.append(el('p', 'hint', t('historyEmpty'))); return; }
  const table = el('table', 'datatable historytable');
  const htr = el('tr');
  [t('historyWhen'), t('historyFile'), t('historyAnalyst'), t('historyMessages'), t('historyVerdict'), t('historyScore'), ''].forEach(x => htr.append(el('th', '', x)));
  table.append(htr);
  for (const c of cases) {
    const tr = el('tr');
    tr.append(el('td', '', fmtDate(c.ts)), el('td', '', c.file || '—'), el('td', '', c.user || '—'),
      el('td', '', String(c.count ?? '—')), el('td', '', verdictText(c.verdict) || '—'), el('td', '', String(c.score ?? '—')));
    const td = el('td');
    const b = el('button', 'ghost', t('historyOpen'));
    b.type = 'button';
    b.onclick = () => openHistoryCase(c.id);
    td.append(b);
    tr.append(td);
    table.append(tr);
  }
  out.append(table);
}

async function loadHistory(force = false) {
  if (histLoading || (histLoaded && !force)) return;
  histLoading = true;
  $('histMsg').textContent = '';
  try {
    const r = await api('/api/cases?limit=100&q=' + encodeURIComponent($('histQ').value.trim()));
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!r.ok) { $('histMsg').textContent = t('logsLoadFailed'); return; }
    histCases = Array.isArray(j.cases) ? j.cases : [];
    histLoaded = true;
    renderHistory(histCases);
  } catch (e) {
    $('histMsg').textContent = t('errNetwork') + e.message;
  } finally { histLoading = false; }
}

async function openHistoryCase(id) {
  $('histMsg').textContent = '';
  try {
    const r = await api(`/api/report/${id}?format=json`);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(apiCode(j) || r.status);
    if (!j.custody) j.custody = { caseId: id, original: j.caseMeta?.file || '', sha256: j.caseMeta?.sha256 || '', utc: j.caseMeta?.ts || '' };
    lastResults = [j];
    currentIdx = 0;
    resTab = 'overview';
    last = j;
    renderCurrentResult();
    switchTab('tabResults');
  } catch (e) {
    $('histMsg').textContent = t('reportFailed') + e.message;
  }
}

// ---------------------------------------------------------------------------
// DNS / IP
// ---------------------------------------------------------------------------
function card(title) {
  const s = el('section', 'toolcard');
  if (title) s.append(el('h4', '', title));
  return s;
}
function listCard(title, values) {
  if (!values?.length) return null;
  const s = card(title);
  const ul = el('ul');
  values.forEach(v => ul.append(el('li', '', typeof v === 'object' ? JSON.stringify(v) : v)));
  s.append(ul);
  return s;
}
function geoCard(geo, ptrNames, status, confidence) {
  const s = card(t('geoLabel'));
  if (!geo) {
    s.append(el('p', 'hint', t('geoUnavailable')));
    if (status) s.append(el('p', 'summary', `GeoLite2: City=${status.city ? 'yes' : 'no'}, ASN=${status.asn ? 'yes' : 'no'}, Country=${status.country ? 'yes' : 'no'}`));
    return s;
  }
  const dl = el('dl', 'kv');
  addKV(dl, t('countryLabel'), geo.countryIso ? `${geo.country || ''} (${geo.countryIso})` : geo.country);
  addKV(dl, t('cityLabel'), geo.city);
  addKV(dl, t('regionLabel'), (geo.subdivisions || []).join(', '));
  addKV(dl, t('asnLabel'), geo.asn);
  addKV(dl, t('organizationLabel'), geo.organization);
  if (geo.location?.latitude != null) {
    addKV(dl, t('coordinatesLabel'), `${geo.location.latitude}, ${geo.location.longitude}`);
    addKV(dl, t('accuracyLabel'), geo.location.accuracyRadiusKm != null ? `${geo.location.accuracyRadiusKm} km` : null);
    addKV(dl, t('timezoneLabel'), geo.location.timeZone);
  }
  addKV(dl, t('ptrLabel'), (ptrNames || []).join(', '));
  if (confidence != null) addKV(dl, t('confidenceLabel'), Math.round(Number(confidence)) + '%');
  s.append(dl, el('p', 'hint', t('approxLabel')));
  return s;
}
function renderNativeDNS(d) {
  const box = el('div', 'toolresult');
  const head = el('div', 'toolhead');
  head.append(badge(t('dnsSourceNative'), 'ok'), el('strong', '', `${d.domain} · ${d.type}`));
  box.append(head);
  if (d.resolver?.length) box.append(el('p', 'summary', `${t('resolverLabel')}: ${d.resolver.join(', ')}`));
  const r = d.records || {};
  for (const key of ['a', 'aaaa', 'ns', 'cname', 'ptr']) {
    const c = listCard(key.toUpperCase(), r[key]);
    if (c) box.append(c);
  }
  if (r.mx?.length) {
    const s = card('MX');
    const table = el('table', 'datatable');
    const tr = el('tr');
    tr.append(el('th', '', '#'), el('th', '', 'MX'));
    table.append(tr);
    r.mx.forEach(x => { const row = el('tr'); row.append(el('td', '', x.priority), el('td', '', x.exchange)); table.append(row); });
    s.append(table); box.append(s);
  }
  if (r.txt?.length) {
    const s = card('TXT');
    const ul = el('ul');
    r.txt.forEach(x => ul.append(el('li', '', x)));
    s.append(ul); box.append(s);
  }
  if (r.soa) {
    const s = card('SOA');
    const dl = el('dl', 'kv');
    for (const [k, v] of Object.entries(r.soa)) addKV(dl, k, typeof v === 'object' ? JSON.stringify(v) : v);
    s.append(dl); box.append(s);
  }
  if (d.auth) {
    const s = card(t('authRecords'));
    for (const key of ['spf', 'dmarc', 'dkim']) {
      const a = d.auth[key] || {};
      const row = el('div', 'authrow');
      row.append(badge(key.toUpperCase(), a.found ? 'ok' : 'warn'));
      if (a.found) {
        if (key === 'spf') row.append(el('span', '', `${a.raw || ''}${a.all ? ' · all=' + a.all : ''}${a.includes?.length ? ' · include=' + a.includes.join(', ') : ''}`));
        else if (key === 'dmarc') row.append(el('span', '', `${a.raw || ''}${a.policy ? ' · p=' + a.policy : ''}`));
        else row.append(el('span', '', `${a.raw || ''}${a.selector ? ' · s=' + a.selector : ''}${a.hasPublicKey ? ' · p=yes' : ' · p=no'}`));
      } else row.append(el('span', 'summary', t('notFoundLabel')));
      s.append(row);
    }
    box.append(s);
  }
  if (d.geo) box.append(geoCard(d.geo, [], d.geoStatus));
  if (d.errors?.length) {
    const s = card(t('warningsLabel'));
    const ul = el('ul');
    d.errors.forEach(e => ul.append(el('li', '', `${e.type || ''} ${e.code || ''}: ${e.message || ''}`)));
    s.append(ul); box.append(s);
  }
  return box;
}
function paintDns(_source, data) {
  $('dnsOut').textContent = '';
  $('dnsOut').append(renderNativeDNS(data));
}
function paintIp(j) {
  const box = el('div', 'toolresult');
  const head = el('div', 'toolhead');
  head.append(badge('IP', 'ok'), el('strong', '', j.ip), el('span', 'summary', fmtDate(j.at)));
  box.append(head, geoCard(j.geo, j.ptr?.names, j.geoStatus, j.confidence));
  if (j.ptr?.errors?.length) {
    const s = card(t('warningsLabel'));
    const ul = el('ul');
    j.ptr.errors.forEach(e => ul.append(el('li', '', `${e.code}: ${e.message}`)));
    s.append(ul); box.append(s);
  }
  $('ipOut').textContent = '';
  $('ipOut').append(box);
}
async function lookupDns() {
  $('dnsMsg').textContent = '';
  $('dnsOut').textContent = '';
  const domain = $('dnsDomain').value.trim();
  if (!domain) return;
  const btn = $('dnsGo');
  btn.disabled = true;
  try {
    const body = { domain, type: $('dnsType').value };
    if (body.type === 'dkim') body.selector = $('dnsSelector').value.trim();
    const r = await api('/api/dns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('dnsMsg').textContent = errText(apiCode(j) || r.status); return; }
    lastDns = { source: 'native', data: j };
    paintDns('native', j);
  } catch (e) { $('dnsMsg').textContent = t('errNetwork') + e.message; }
  finally { btn.disabled = false; }
}
async function lookupIp() {
  $('ipMsg').textContent = '';
  $('ipOut').textContent = '';
  const ip = $('ipAddr').value.trim();
  if (!ip) return;
  const btn = $('ipGo');
  btn.disabled = true;
  try {
    const r = await api('/api/ip', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('ipMsg').textContent = errText(apiCode(j) || r.status); return; }
    lastIp = j;
    paintIp(j);
  } catch (e) { $('ipMsg').textContent = t('errNetwork') + e.message; }
  finally { btn.disabled = false; }
}

// ---------------------------------------------------------------------------
// local AI settings
// ---------------------------------------------------------------------------
async function loadTrustStatus() {
  try {
    const r = await api('/api/settings/llm');
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('trustState').textContent = t('trustLoadFailed'); return; }
    $('llmBase').value = j.base || '';
    $('llmModel').value = j.model || '';
    $('llmKey').value = j.hasKey ? '••••••••' : '';
    $('llmEnabled').checked = !!j.enabled;
    $('trustState').textContent = `${t('trustStateOn')}: ${j.enabled ? t('trustEnabled') : t('trustDisabled')} · ${j.base || ''} · ${j.local ? 'local' : 'remote'}`;
  } catch { $('trustState').textContent = t('trustLoadFailed'); }
}
async function saveTrust() {
  $('trustMsg').textContent = t('saving');
  const body = {
    base: $('llmBase').value.trim(),
    model: $('llmModel').value.trim(),
    enabled: $('llmEnabled').checked
  };
  const k = $('llmKey').value.trim();
  if (k && k !== '••••••••') body.key = k;
  try {
    const r = await api('/api/settings/llm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('trustMsg').textContent = errText(apiCode(j) || r.status); return; }
    $('trustMsg').textContent = t('trustSaved');
    await loadTrustStatus();
  } catch (e) { $('trustMsg').textContent = t('errNetwork') + e.message; }
}
async function testTrust() {
  $('trustMsg').textContent = t('saving');
  try {
    const r = await api('/api/settings/llm/test', { method: 'POST' });
    const j = await r.json().catch(() => ({}));
    $('trustMsg').textContent = j.ok ? t('trustTestOk') : t('trustTestFail') + ' ' + (j.error || '');
  } catch (e) { $('trustMsg').textContent = t('trustTestFail') + ' ' + e.message; }
}
async function clearTrustKey() {
  try {
    const r = await api('/api/settings/llm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: '' }) });
    if (r.ok) { $('llmKey').value = ''; $('trustMsg').textContent = t('trustRemoved'); }
  } catch (e) { $('trustMsg').textContent = t('errNetwork') + e.message; }
}

// ---------------------------------------------------------------------------
// administration
// ---------------------------------------------------------------------------
async function loadAdmin(force = true) {
  if (role !== 'admin') return;
  if (adminLoaded && !force) return;
  $('adminMsg').textContent = t('adminMsg');
  try {
    const [sr, ur] = await Promise.all([api('/api/admin/stats'), api('/api/admin/users')]);
    const sj = await sr.json().catch(() => ({}));
    const uj = await ur.json().catch(() => ({}));
    if (sr.status === 401 || ur.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!sr.ok || !ur.ok) { $('adminMsg').textContent = t('adminLoadFailed'); return; }
    adminUsers = Array.isArray(uj.users) ? uj.users : [];
    adminLoaded = true;
    $('adminMsg').textContent = '';
    renderAdminStats(sj);
    renderAdminUsers();
  } catch (e) { $('adminMsg').textContent = t('errNetwork') + e.message; }
}
function renderAdminStats(s) {
  const box = $('adminStats');
  if (!box) return;
  box.textContent = '';
  for (const [label, v] of [[t('adminUsers'), s.users], [t('roleAdmin'), s.admins], [t('dashCases'), s.cases],
    ['URL imports', s.urlImports], ['Evidence bytes', fSize(s.evidenceBytes || 0)], ['Map', s.map], ['Offline', s.offline ? 'yes' : 'no']]) {
    box.append(el('span', 'statLabel', label), el('b', 'statVal', String(v ?? '—')));
  }
}
function renderAdminUsers() {
  const box = $('adminUsers');
  if (!box) return;
  box.textContent = '';
  if (!adminUsers.length) { box.append(el('p', 'hint', t('adminUsersEmpty'))); return; }
  const table = el('table', 'datatable');
  const htr = el('tr');
  [t('adminUid'), t('username'), t('profileRole'), t('adminPhone'), t('adminStatus'), t('adminLastLogin'), t('adminActions')].forEach(x => htr.append(el('th', '', x)));
  table.append(htr);
  for (const u of adminUsers) {
    const self = u.uid === uid;
    const tr = el('tr');
    tr.append(el('td', 'hashcell', u.uid || ''), el('td', '', u.user || ''), el('td', '', u.role || ''),
      el('td', '', u.phone || '—'), el('td', '', u.disabled ? 'disabled' : 'active'),
      el('td', '', fmtDate(u.lastLogin)));
    const td = el('td', 'actioncell');
    const reset = el('button', 'ghost', t('adminReset'));
    reset.type = 'button';
    reset.onclick = async () => {
      const pw = prompt(t('adminResetPrompt'));
      if (!pw) return;
      const r = await api(`/api/admin/users/${u.uid}/reset`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pass: pw }) });
      const j = await r.json().catch(() => ({}));
      $('adminMsg').textContent = r.ok ? t('adminResetOk') + (j.recovery ? ' ' + j.recovery : '') : errText(apiCode(j) || r.status);
      $('adminMsg').className = r.ok ? 'ok' : 'bad';
      await loadAdmin(true);
    };
    const dis = el('button', 'ghost', u.disabled ? t('adminEnable') : t('adminDisable'));
    dis.type = 'button';
    dis.disabled = self;
    dis.title = self ? t('adminSelf') : '';
    dis.onclick = async () => {
      const r = await api(`/api/admin/users/${u.uid}/disable`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ disabled: !u.disabled }) });
      const j = await r.json().catch(() => ({}));
      $('adminMsg').textContent = r.ok ? (u.disabled ? t('adminEnabledOk') : t('adminDisabledOk')) : errText(apiCode(j) || r.status);
      $('adminMsg').className = r.ok ? 'ok' : 'bad';
      await loadAdmin(true);
    };
    const roleBtn = el('button', 'ghost', t('adminRole'));
    roleBtn.type = 'button';
    roleBtn.disabled = self;
    roleBtn.onclick = async () => {
      const nr = u.role === 'admin' ? 'analyst' : 'admin';
      const r = await api(`/api/admin/users/${u.uid}/role`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: nr }) });
      const j = await r.json().catch(() => ({}));
      $('adminMsg').textContent = r.ok ? t('adminRoleOk') : errText(apiCode(j) || r.status);
      $('adminMsg').className = r.ok ? 'ok' : 'bad';
      await loadAdmin(true);
    };
    const ren = el('button', 'ghost', t('adminRename'));
    ren.type = 'button';
    ren.onclick = async () => {
      const r = await api(`/api/admin/users/${u.uid}/rename-token`, { method: 'POST' });
      const j = await r.json().catch(() => ({}));
      if (r.ok) {
        $('adminMsg').textContent = `${t('adminRenameOk')} ${j.token} (${fmtDate(j.expires)})`;
        $('adminMsg').className = 'ok';
        try { await navigator.clipboard.writeText(j.token); } catch {}
      } else {
        $('adminMsg').textContent = errText(apiCode(j) || r.status);
        $('adminMsg').className = 'bad';
      }
    };
    td.append(reset, dis, roleBtn, ren);
    tr.append(td);
    table.append(tr);
  }
  box.append(table);
}
async function createAccount() {
  $('acMsg').textContent = '';
  $('acKey').hidden = true;
  const body = {
    user: $('acUser').value.trim(),
    phone: $('acPhone').value.trim(),
    pass: $('acPass').value,
    role: $('acRole').value,
    cccd: $('acCccd').value.trim()
  };
  if (body.role === 'admin' && !body.cccd) { $('acMsg').textContent = t('adminNoCccd'); return; }
  const btn = $('acGo');
  btn.disabled = true;
  try {
    const r = await api('/api/admin/users', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('acMsg').textContent = errText(apiCode(j) || r.status); return; }
    const key = j.key || j.recovery || '';
    $('acMsg').textContent = t('adminCreated');
    $('acMsg').className = 'ok';
    $('acKey').textContent = `${t('adminKeyOnce')}: ${key}`;
    $('acKey').hidden = false;
    $('acUser').value = ''; $('acPhone').value = ''; $('acPass').value = ''; $('acCccd').value = '';
    await loadAdmin(true);
  } catch (e) { $('acMsg').textContent = t('errNetwork') + e.message; }
  finally { btn.disabled = false; }
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------
function renderLogs() {
  const logsOut = $('logsOut'), sessionsOut = $('sessionsOut');
  if (!logsOut || !sessionsOut) return;
  logsOut.textContent = ''; sessionsOut.textContent = '';
  if (!logsData.length) logsOut.append(el('p', 'hint', t('logsEmpty')));
  else {
    const table = el('table', 'datatable');
    const htr = el('tr');
    [t('historyWhen'), t('sessionUser'), 'Action', 'Detail', t('durationMs')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    for (const x of logsData) {
      const tr = el('tr');
      tr.append(el('td', '', fmtDate(x.ts)), el('td', '', x.user || '—'), el('td', '', x.action || ''), el('td', '', x.detail || ''), el('td', '', x.ms ?? '—'));
      table.append(tr);
    }
    logsOut.append(table);
  }
  if (!sessionsData.length) sessionsOut.append(el('p', 'hint', t('sessionsEmpty')));
  else {
    const table = el('table', 'datatable');
    const htr = el('tr');
    [t('historyWhen'), t('sessionUser'), t('sessionRole'), t('reasonLabel'), t('durationMs'), t('signatureLabel'), t('previousLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    for (const x of sessionsData) {
      const tr = el('tr');
      tr.append(el('td', '', fmtDate(x.ended)), el('td', '', x.user || '—'), el('td', '', x.role || '—'),
        el('td', '', x.reason || ''), el('td', '', x.started && x.ended ? x.ended - x.started : '—'),
        el('td', 'hashcell', x.sha256 || ''), el('td', 'hashcell', x.prev_hash || '—'));
      table.append(tr);
    }
    sessionsOut.append(table);
  }
}
async function loadLogs(force = false) {
  if (logsLoading || (logsLoaded && !force)) return;
  logsLoading = true;
  $('logsMsg').textContent = '';
  try {
    const [a, b] = await Promise.all([api('/api/admin/logs'), api('/api/admin/sessions')]);
    const ja = await a.json().catch(() => []), jb = await b.json().catch(() => []);
    if (a.status === 401 || b.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!a.ok || !b.ok) { $('logsMsg').textContent = t('logsLoadFailed'); return; }
    logsData = Array.isArray(ja) ? ja : [];
    sessionsData = Array.isArray(jb) ? jb : [];
    logsLoaded = true;
    renderLogs();
  } catch (e) {
    $('logsMsg').textContent = t('errNetwork') + e.message;
  } finally { logsLoading = false; }
}

// ---------------------------------------------------------------------------
// language
// ---------------------------------------------------------------------------
function applyLang() {
  document.documentElement.lang = lang;
  document.title = t('title');
  document.querySelectorAll('[data-i18n]').forEach(x => { x.textContent = t(x.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(x => { x.placeholder = t(x.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-aria]').forEach(x => { x.setAttribute('aria-label', t(x.dataset.i18nAria)); });
  document.querySelectorAll('[data-i18n-g]').forEach(x => { try { x.label = t(x.dataset.i18nG); } catch {} });
  if ($('lang')) $('lang').value = lang;
  const flag = $('langFlag');
  if (flag) flag.className = 'flag-icon ' + lang;
  applyTheme(document.documentElement.dataset.theme === 'dark');
  renderWho();
  if (lastDns) paintDns(lastDns.source, lastDns.data);
  if (lastIp) paintIp(lastIp);
  if (profileData) renderProfile();
  if (sessionExpires) renderSessionTimer();
  if (logsLoaded) renderLogs();
  if (histLoaded) renderHistory(histCases);
  if (adminLoaded) { renderAdminUsers(); loadAdmin(false); }
  renderPick();
  if (lastResults.length) renderCurrentResult();
}

// ---------------------------------------------------------------------------
// file picking / drag & drop
// ---------------------------------------------------------------------------
$('f').onchange = () => { addFiles($('f').files); $('f').value = ''; };
$('fdir').onchange = () => { addFiles($('fdir').files); $('fdir').value = ''; };
$('fclear').onclick = () => { picked = []; pfRejected = []; renderPick(); };
if ($('fbtn')) $('fbtn').onclick = () => $('f').click();
if ($('fdirBtn')) $('fdirBtn').onclick = () => $('fdir').click();

async function entryFiles(entry, out, depth = 0) {
  if (!entry || depth > 8 || out.length > 2000) return;
  if (entry.isFile) {
    await new Promise(r => entry.file(f => { out.push({ f, path: (entry.fullPath || '/' + f.name).replace(/^\//, '') }); r(); }, r));
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    let batch;
    do {
      batch = await new Promise(r => reader.readEntries(r, r));
      for (const e of batch) await entryFiles(e, out, depth + 1);
    } while (batch.length);
  }
}
{
  const dz = $('drop');
  const over = e => { e.preventDefault(); dz.classList.add('over'); };
  dz.addEventListener('dragover', over);
  dz.addEventListener('dragenter', over);
  dz.addEventListener('dragleave', e => { if (!dz.contains(e.relatedTarget)) dz.classList.remove('over'); });
  dz.addEventListener('drop', async e => {
    e.preventDefault();
    dz.classList.remove('over');
    const dt = e.dataTransfer;
    if (!dt) return;
    const entries = Array.from(dt.items || []).map(i => i.webkitGetAsEntry?.()).filter(Boolean);
    if (entries.length) {
      const out = [];
      for (const en of entries) await entryFiles(en, out);
      if (out.length) { addItems(out); return; }
    }
    addFiles(dt.files);
  });
}

// URL import drop zone on the results pane
{
  const pane = $('paneResults');
  pane.addEventListener('dragover', e => { e.preventDefault(); pane.classList.add('over'); });
  pane.addEventListener('dragleave', () => pane.classList.remove('over'));
  pane.addEventListener('drop', e => {
    e.preventDefault();
    pane.classList.remove('over');
    const files = Array.from(e.dataTransfer?.files || []).filter(f => /\.(csv|json|xml|txt)$/i.test(f.name));
    if (files.length) importUrls(files);
  });
}

// ---------------------------------------------------------------------------
// run controls
// ---------------------------------------------------------------------------
$('run').onclick = startAnalysis;
$('btnPause').onclick = () => {
  if (!job || job.stopped || job.cancelled) return;
  job.paused = !job.paused;
  setRunState(t(job.paused ? 'runPausing' : 'runResuming'), job.paused ? 'warn' : '');
  syncRunButtons();
};
$('btnStop').onclick = () => {
  if (!job || job.stopped || job.cancelled) return;
  job.stopped = true;
  job.paused = false;
  setRunState(t('runStopping'), 'warn');
  try { job.ac?.abort(); } catch {}
  syncRunButtons();
};
$('btnCancel').onclick = () => {
  if (!job || job.cancelled) return;
  job.cancelled = true;
  job.paused = false;
  setRunState(t('runCancelled'), 'bad');
  try { job.ac?.abort(); } catch {}
  syncRunButtons();
};

// ---------------------------------------------------------------------------
// report / URL buttons
// ---------------------------------------------------------------------------
$('repHtml').onclick = reportHtml;
$('repPdf').onclick = reportPdf;
$('repCsv').onclick = reportCsv;
$('repBundle').onclick = reportBundle;
$('repVerify').onclick = verifySignature;
$('urlCsv').onclick = exportUrlCsv;
$('urlImportBtn').onclick = () => $('urlImportFile').click();
$('urlImportDirBtn').onclick = () => $('urlImportDir').click();
$('urlImportFile').onchange = () => { importUrls($('urlImportFile').files); $('urlImportFile').value = ''; };
$('urlImportDir').onchange = () => { importUrls($('urlImportDir').files); $('urlImportDir').value = ''; };
$('graphBtn').onclick = () => { resTab = 'graph'; renderCurrentResult(); };

// dashboard platform cards
for (const [id, p] of [['platWin', 'windows'], ['platLin', 'linux']]) {
  const b = $(id);
  if (b) b.onclick = () => {
    $('platform').value = p;
    try { localStorage.setItem('platform', p); } catch {}
    switchTab('tabAnalysis');
    $('drop').classList.add('over');
    setTimeout(() => $('drop').classList.remove('over'), 600);
  };
}
$('platform').onchange = () => { try { localStorage.setItem('platform', $('platform').value); } catch {} };

// ---------------------------------------------------------------------------
// auth bindings
// ---------------------------------------------------------------------------
$('go').onclick = login;
$('ngo').onclick = register;
$('rgo').onclick = recover;
for (const id of ['u', 'p']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
for (const id of ['nu', 'nphone', 'np', 'np2']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') register(); });
for (const id of ['ru', 'rk', 'rp']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') recover(); });
$('showReg').onclick = e => { e.preventDefault(); showAuth('reg'); $('nu').focus(); };
$('showLogin').onclick = e => { e.preventDefault(); showAuth('login'); $('u').focus(); };
$('recBack').onclick = e => { e.preventDefault(); showAuth('login'); };
$('forgot').onclick = e => { e.preventDefault(); showAuth('rec'); $('ru').focus(); };
$('keycopy').onclick = async () => {
  try { await navigator.clipboard.writeText($('keyval').textContent); $('keymsg').textContent = t('copied'); }
  catch { $('keymsg').textContent = t('copyFailed'); }
};
$('keyok').onclick = () => { $('keybox').hidden = true; };
$('logout').onclick = async () => { try { await api('/api/logout', { method: 'POST' }); } catch {} location.reload(); };
$('pgo').onclick = changePassword;
$('rnGo').onclick = renameAccount;
$('avatarUpload').onclick = uploadAvatar;
$('avatarFile').onchange = uploadAvatar;

// ---------------------------------------------------------------------------
// other bindings
// ---------------------------------------------------------------------------
$('dnsGo').onclick = lookupDns;
$('ipGo').onclick = lookupIp;
$('dnsType').onchange = () => { $('dnsDkimRow').hidden = $('dnsType').value !== 'dkim'; };
for (const id of ['dnsDomain', 'dnsSelector']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') lookupDns(); });
$('ipAddr').addEventListener('keydown', e => { if (e.key === 'Enter') lookupIp(); });
$('histGo').onclick = () => loadHistory(true);
$('histRefresh').onclick = () => loadHistory(true);
$('histQ').addEventListener('keydown', e => { if (e.key === 'Enter') loadHistory(true); });
$('logsRefresh').onclick = () => loadLogs(true);
$('trustSave').onclick = saveTrust;
$('trustTest').onclick = testTrust;
$('trustClear').onclick = clearTrustKey;
$('adminRefresh').onclick = () => loadAdmin(true);
$('acGo').onclick = createAccount;
$('acRole').onchange = () => { $('acCccd').hidden = $('acRole').value !== 'admin'; };
$('acRole').onchange();
$('lang').onchange = () => {
  lang = $('lang').value === 'vi' ? 'vi' : 'en';
  try { localStorage.setItem('lang', lang); } catch {}
  applyLang();
};
$('themeBtn').onclick = () => applyTheme(document.documentElement.dataset.theme !== 'dark');

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------
initTheme();
applyLang();
(async () => {
  try {
    const r = await fetch('/api/me');
    if (r.ok) enterApp(await r.json());
  } catch {}
})();
