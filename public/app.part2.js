// MailSleuth frontend — part 2: analysis streaming, results, message viewer, URL intel, graph.
let picked = []; // {f, path}
let pfRejected = []; // {path, size, reason}
let job = null; // {paused, stopped, cancelled, ac, done, failed}
let resTab = 'overview';
let currentIdx = 0;

const OK_EXT = /\.(eml|emlx|mht|mhtml|msg|mbox|mbx|txt)$/i;
const PICK_FILE_MAX = 80 * 1024 * 1024;
const PICK_TOTAL_MAX = 2000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function addFiles(fileList, prefix = '') {
  const items = Array.from(fileList || []).map(f => ({
    f,
    path: prefix ? prefix.replace(/\/+$/, '') + '/' + f.name
      : (typeof f.__path === 'string' && f.__path ? f.__path : (f.webkitRelativePath || f.name))
  }));
  addItems(items);
}

function addItems(items) {
  const rejected = [];
  const seen = new Set(picked.map(x => x.path + '|' + x.f.size + '|' + x.f.lastModified));
  for (const { f, path } of items) {
    const reason = !OK_EXT.test(f.name) ? 'pfBadExt'
      : f.size === 0 ? 'pfEmpty'
        : f.size > PICK_FILE_MAX ? 'pfTooLarge' : null;
    if (reason) { rejected.push({ path, size: f.size, reason }); continue; }
    const key = path + '|' + f.size + '|' + f.lastModified;
    if (seen.has(key)) { rejected.push({ path, size: f.size, reason: 'pfDupe' }); continue; }
    seen.add(key);
    picked.push({ f, path });
  }
  pfRejected = rejected;
  renderPick();
}

function renderPick() {
  const list = $('flist');
  if (!list) return;
  list.textContent = '';
  const total = picked.reduce((s, x) => s + x.f.size, 0);
  const skipped = pfRejected.filter(x => x.reason !== 'pfDupe').length;
  const dupes = pfRejected.length - skipped;
  let msg = picked.length ? `${picked.length} ${t('pickFiles')} · ${fSize(total)}` : t('pickNone');
  if (skipped) msg += ` · ${skipped} ${t('pickSkipped')}`;
  if (dupes) msg += ` · ${dupes} ${t('pickDup')}`;
  if (picked.length > PICK_TOTAL_MAX) msg += ` · ${t('pickLimit')}`;
  if (picked.length && !pfRejected.length) msg += ` · ✓ ${t('pfReady')}`;
  $('pickMsg').textContent = msg;
  picked.forEach((x, i) => {
    const li = el('li', 'filerow');
    li.append(el('span', 'fname', x.path), el('span', 'fsize', fSize(x.f.size)));
    const rm = el('button', 'ghost', '×');
    rm.type = 'button';
    rm.title = t('pickRemove');
    rm.setAttribute('aria-label', t('pickRemove') + ': ' + x.path);
    rm.onclick = () => { picked.splice(i, 1); renderPick(); };
    li.append(rm);
    list.append(li);
  });
  const pf = $('preflight');
  if (pf) {
    const pl = $('pfList');
    pl.textContent = '';
    if (pfRejected.length) {
      pf.hidden = false;
      $('pfMsg').textContent = `${pfRejected.length} ${t('pfRejected')}`;
      for (const x of pfRejected) {
        const li = el('li', 'filerow pfbad');
        li.append(el('span', 'fname', x.path), el('span', 'fsize', fSize(x.size || 0)));
        li.append(el('span', 'pfreason', t(x.reason)));
        pl.append(li);
      }
    } else pf.hidden = true;
  }
  syncRunButtons();
}

function syncRunButtons() {
  if (!$('run')) return;
  const running = !!job;
  $('run').disabled = running || !picked.length || picked.length > PICK_TOTAL_MAX;
  const p = $('btnPause'), s = $('btnStop'), c = $('btnCancel');
  if (p) { p.disabled = !running || (job && (job.stopped || job.cancelled)); p.textContent = t(job && job.paused ? 'resume' : 'pause'); }
  if (s) s.disabled = !running || !!(job && (job.stopped || job.cancelled));
  if (c) c.disabled = !running || !!(job && job.cancelled);
}

async function waitIfPaused() {
  if (!job || !job.paused) return;
  setRunState(t('runPaused'), 'warn');
  while (job && job.paused && !job.stopped && !job.cancelled) await sleep(150);
  if (job && !job.stopped && !job.cancelled) setRunState(t('runRunning'));
}

function setLive(title, l1, l2, l3, pct, running = true) {
  const box = $('live');
  if (!box) return;
  box.hidden = false;
  $('liveTitle').textContent = title || '';
  $('liveL1').textContent = l1 || '';
  $('liveL2').textContent = l2 || '';
  $('liveL3').textContent = l3 || '';
  const v = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
  $('progPct').textContent = v + '%';
  const amp = $('ampBar');
  if (amp) {
    amp.setAttribute('aria-valuenow', String(v));
    amp.classList.toggle('running', !!running);
    const bars = [...amp.children];
    bars.forEach((b, i) => {
      const phase = (v / 7) + i * 0.75;
      const h = 18 + 78 * Math.abs(Math.sin(phase));
      b.style.height = h.toFixed(0) + '%';
      b.classList.toggle('lit', (i + 1) / bars.length <= v / 100);
    });
  }
}
function hideLive() { const x = $('live'); if (x) x.hidden = true; }

class StreamError extends Error {
  constructor(code, detail = '') { super(code || 'parse'); this.code = code || 'parse'; this.detail = detail; }
}

async function streamOne(item, idx, total, basePct) {
  const fd = new FormData();
  fd.append('file', item.f, item.f.name);
  fd.append('platform', $('platform').value || 'auto');
  fd.append('lang', lang);
  const ac = new AbortController();
  job.ac = ac;
  const pctFor = p => Math.min(99.5, basePct + (p / 100) * (100 / total));
  setLive(`${t('liveTitle')} ${idx + 1}/${total}`,
    `${t('liveFile')}: ${item.path}`,
    `${t('liveStage')}: ${t('stepUpload')}`,
    `${fSize(item.f.size)}`, pctFor(2), true);
  const r = await fetch('/api/analyze/stream', { method: 'POST', body: fd, headers: { 'x-csrf': csrf }, signal: ac.signal });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new StreamError(apiCode(j) || (r.status === 401 ? 'auth' : 'upload'));
  }
  if (!r.body) throw new StreamError('parse');
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let result = null;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let ev;
      try { ev = JSON.parse(line); } catch { continue; }
      const p = pctFor(Number(ev.pct) || 0);
      if (ev.type === 'stage') {
        const stage = ev.stage === 'receive' ? t('stepUpload') : t('stepProcess');
        const detail = ev.bytes != null ? `${fSize(ev.bytes)}` : '';
        setLive(`${t('liveTitle')} ${idx + 1}/${total}`,
          `${t('liveFile')}: ${ev.file || item.path}`,
          `${t('liveStage')}: ${stage}`, detail, p, true);
      } else if (ev.type === 'result') {
        result = ev.result;
        const rr = result || {};
        setLive(`${t('liveTitle')} ${idx + 1}/${total}`,
          `${t('liveFile')}: ${rr.custody?.original || item.path}`,
          `${t('liveStage')}: ${String(rr.format || '').toUpperCase()} × ${rr.count || 0}`,
          `${t('verdict')}: ${verdictText(rr.verdict)} · ${rr.score}/100 · ${rr.client?.label || ''}`,
          p, false);
      } else if (ev.type === 'error') {
        throw new StreamError(ev.error || 'parse', ev.detail || '');
      }
    }
  }
  if (!result) throw new StreamError('parse');
  return result;
}

async function startAnalysis() {
  if (job) return;
  const files = picked.slice();
  if (!files.length) { $('out').textContent = t('noFile'); return; }
  if (files.length > PICK_TOTAL_MAX) { $('out').textContent = t('pickLimit'); return; }
  $('out').textContent = '';
  $('resultsOut').textContent = '';
  last = null; lastResults = []; lastErrors = [];
  job = { paused: false, stopped: false, cancelled: false, ac: null, done: [], failed: null };
  syncRunButtons();
  setRunState(t('runRunning'));
  setLive(t('liveTitle'), t('stepValidate'), '', '', 0, true);
  const results = [], errors = [];
  let netErr = '';
  try {
    for (let i = 0; i < files.length; i++) {
      await waitIfPaused();
      if (!job || job.cancelled || job.stopped) break;
      const basePct = (i / files.length) * 100;
      try {
        const r = await streamOne(files[i], i, files.length, basePct);
        results.push(r);
        if (job) job.done.push(files[i]);
      } catch (e) {
        if (e && e.name === 'AbortError' && (!job || job.cancelled || job.stopped)) break;
        if (e instanceof StreamError && e.code === 'auth') {
          leaveApp(); $('err').textContent = t('e_auth'); return;
        }
        const code = (e && e.code) || 'parse';
        const detail = (e && e.detail) || (e && e.message) || '';
        errors.push({ file: files[i].path, error: code, detail });
        if (job) job.failed = { file: files[i].path, code, detail };
        break;
      }
    }
  } catch (e) {
    netErr = t('errNetwork') + (e && e.message ? e.message : String(e));
  }
  const wasCancelled = !!(job && job.cancelled);
  const wasStopped = !!(job && job.stopped);
  const done = job ? job.done.slice() : [];
  const failed = job ? job.failed : null;
  job = null;
  syncRunButtons();

  if (wasCancelled) {
    last = null; lastResults = []; lastErrors = [];
    $('resultsOut').textContent = '';
    hideLive();
    setRunState(t('runCancelled'), 'bad');
    return;
  }

  // Finished files leave the picker so a resume continues exactly at the
  // failing/remaining file instead of re-analyzing everything.
  if (done.length) {
    const doneKeys = new Set(done.map(x => x.path + '|' + x.f.size + '|' + x.f.lastModified));
    picked = picked.filter(x => !doneKeys.has(x.path + '|' + x.f.size + '|' + x.f.lastModified));
    renderPick();
  }

  if (results.length) {
    lastResults = results;
    lastErrors = errors;
    currentIdx = 0;
    resTab = 'overview';
    last = results.reduce((a, b) => (b.score > a.score || (b.score === a.score && a.verdict === 'clean' && b.verdict !== 'clean')) ? b : a);
    histLoaded = false;
    renderCurrentResult();
    switchTab('tabResults');
    loadDashboard();
  }

  if (failed) {
    const msg = `${t('uploadErrors')}: ${failed.file} — ${errText(failed.code)}${failed.detail ? ' (' + failed.detail + ')' : ''}. ${t('runStopping')}`;
    setRunState(msg, 'bad');
    if (!results.length) {
      const box = el('div', 'f s3');
      box.append(el('strong', '', t('uploadErrors')));
      box.append(el('div', '', `${failed.file}: ${errText(failed.code)}${failed.detail ? ' — ' + failed.detail : ''}`));
      $('out').append(box);
    }
  } else if (netErr) {
    setRunState(netErr, 'bad');
  } else if (wasStopped) {
    setRunState(`${t('runStopped')} ${results.length}/${files.length}`, 'warn');
  } else if (errors.length) {
    setRunState(t('uploadErrors'), 'bad');
  } else {
    setRunState('');
  }
  if (!results.length && !failed) {
    if (errors.length) {
      const box = el('div', 'f s3');
      box.append(el('strong', '', t('uploadErrors')));
      errors.forEach(e => box.append(el('div', '', `${e.file}: ${errText(e.error)}${e.detail ? ' — ' + e.detail : ''}`)));
      $('out').append(box);
    } else if (wasStopped) {
      $('out').textContent = t('runStoppedNoResults');
    } else if (!netErr) {
      $('out').textContent = errText('upload');
    }
  }
  hideLive();
}

// ---------------------------------------------------------------------------
// results rendering
// ---------------------------------------------------------------------------
const bodyCache = new Map();
const verdictClass = v => v === 'malicious_or_phishing' ? 'malicious' : v === 'suspicious' ? 'suspicious' : 'clean';
const verdictGlow = v => v === 'malicious_or_phishing' ? 'glow-red' : v === 'suspicious' ? 'glow-yellow' : v === 'clean' ? '' : 'glow-blue';
const platformIcon = p => p === 'linux' ? '🐧' : '🪟';
const clientIcon = key => {
  const k = String(key || '').toLowerCase();
  if (k.includes('outlook') || k.includes('exchange')) return '🪟';
  if (k.includes('thunderbird')) return '🦅';
  if (k.includes('apple')) return '🍎';
  if (k.includes('gmail')) return '✉️';
  if (k.includes('maildir') || k.includes('mbox')) return '🐧';
  return '✉️';
};
const currentCase = () => (lastResults[currentIdx]?.custody?.caseId) || '';

function renderCurrentResult() {
  const out = $('resultsOut');
  if (!out) return;
  const r = lastResults[currentIdx];
  if (!r) {
    $('resultCase').textContent = t('noResult');
    out.textContent = '';
    return;
  }
  $('resultCase').textContent = '';
  if (lastResults.length > 1) {
    const sel = el('select', 'caseSel');
    lastResults.forEach((x, i) => {
      const o = el('option', '', `${i + 1}. ${x.custody?.original || ''} — ${verdictText(x.verdict)}`);
      o.value = String(i);
      o.selected = i === currentIdx;
      sel.append(o);
    });
    sel.onchange = () => { currentIdx = Number(sel.value) || 0; resTab = 'overview'; renderCurrentResult(); };
    $('resultCase').append(sel);
  }
  $('resultCase').append(el('span', '', ` ${t('caseLabel')}: ${r.custody?.caseId || ''} · ${t('shaLabel')} ${r.custody?.sha256 || ''}`));
  out.textContent = '';

  const strip = el('div', 'clientTabs');
  const first = el('button', 'clientTab active');
  first.type = 'button';
  first.append(el('span', 'clientIco', platformIcon(r.platform)),
    el('span', '', ` ${r.client?.label || r.format || ''} `),
    badge(`${String(r.format || '').toUpperCase()} × ${r.count || 0}`, 'ok'));
  first.title = t('clientLabel');
  strip.append(first);
  strip.append(el('span', 'clientMeta', `${t('platformLabel')}: ${r.platform || 'auto'} · ${t('verdict')}: ${verdictText(r.verdict)} · ${r.score}/100`));
  out.append(strip);

  const tabs = el('div', 'subtabs');
  for (const [key, label] of [['overview', t('resOverview')], ['messages', t('resMessages')], ['urls', t('resUrls')], ['graph', t('resGraph')]]) {
    const b = el('button', 'subtab' + (resTab === key ? ' active' : ''), label);
    b.type = 'button';
    b.onclick = () => { resTab = key; renderCurrentResult(); };
    tabs.append(b);
  }
  out.append(tabs);
  const body = el('div', 'resBody');
  out.append(body);
  if (resTab === 'messages') renderMessages(body, r);
  else if (resTab === 'urls') renderUrls(body, r);
  else if (resTab === 'graph') renderGraph(body, r);
  else renderOverview(body, r);
}

function renderOverview(out, r) {
  const cls = verdictClass(r.verdict);
  const banner = el('div', `verdictBanner ${cls} ${verdictGlow(r.verdict)}`);
  banner.append(el('strong', '', `${t('verdict')}: ${verdictText(r.verdict)}`),
    el('span', '', ` · ${t('score')}: ${r.score}/100`),
    el('span', 'bannerMeta', ` · ${r.format?.toUpperCase()} × ${r.count}${r.truncated ? '+' : ''} · ${r.client?.label || ''}`));
  out.append(banner);

  const stats = el('div', 'statRow');
  for (const [n, label] of [[r.count || 0, t('messagesLabel')], [(r.attachments || []).length, t('attachments')],
    [(r.findings || []).length, t('findings')], [(r.urls || []).length, 'URL'], [(r.originIPs || []).length, 'IP']]) {
    const c = el('div', 'statCard');
    c.append(el('b', '', String(n)), el('span', '', label));
    stats.append(c);
  }
  out.append(stats);

  const meta = el('dl', 'kv');
  addKV(meta, t('custodyLabel'), `${r.custody?.caseId || ''} · ${fmtDate(r.custody?.utc)}`);
  addKV(meta, t('shaLabel'), r.custody?.sha256);
  addKV(meta, t('signatureLabel'), r.signature?.sha256);
  addKV(meta, t('formatLabel'), `${r.format} · ${r.platform}`);
  addKV(meta, t('clientLabel'), r.client?.label);
  out.append(meta);

  renderForensics(out, r);
  renderThreats(out, r);
  renderEnrichment(out, r);

  const fh = el('h4', '', `${t('findings')} (${(r.findings || []).length})`);
  out.append(fh);
  if (!r.findings?.length) {
    out.append(el('div', 'f s0', t('noFindings')));
  } else {
    for (const f of r.findings.slice(0, 300)) {
      const d = el('div', 'f s' + (f.sev ?? 0) + (f.weight === 0 ? ' info' : ''));
      d.textContent = `${r.count > 1 ? '#' + ((f.m ?? 0) + 1) + ' ' : ''}${f.type || ''}: ${f.evidence || ''}`;
      out.append(d);
    }
    if (r.findings.length > 300) out.append(el('p', 'hint', t('shown')));
  }

  if (r.attachments?.length) {
    const det = el('details');
    det.append(el('summary', '', `${t('attachments')} (${r.attachments.length})`));
    const ul = el('ul', 'att');
    for (const a of r.attachments.slice(0, 200)) {
      const li = el('li', '', `${a.m !== undefined ? '#' + (a.m + 1) + ' ' : ''}${a.name} — ${a.size} B — ${a.sha256}${a.magic && a.magic !== 'unknown' ? ' — ' + a.magic : ''}`);
      if (a.verdict && a.verdict !== 'clean') {
        li.append(' — ', badge(assessText(a.verdict), a.verdict === 'malicious' ? 'bad' : 'warn'));
        if (a.reasons?.length) li.title = a.reasons.join('; ');
      }
      ul.append(li);
    }
    det.append(ul);
    out.append(det);
  }
}

function renderAuthDetails(auth) {
  const box = el('div', 'authbox');
  if (!auth?.headerFound) {
    box.append(el('p', 'hint', t('missing')));
    return box;
  }
  const dl = el('dl', 'kv');
  addKV(dl, t('authservLabel') || 'Authentication server', auth.authservId);
  addKV(dl, t('statusLabel'), auth.overall);
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const x = auth[k] || {};
    addKV(dl, k.toUpperCase(), x.result || 'none');
    addKV(dl, `${k.toUpperCase()} domain`, x.domain);
    if (k === 'dkim') addKV(dl, t('selectorLabel'), x.selector);
    if (k === 'dmarc') addKV(dl, t('policy'), x.policy);
    if (k === 'spf' || k === 'dkim') addKV(dl, `${k.toUpperCase()} ${t('alignmentLabel')}`, auth.alignment?.[k] === true ? t('yesLabel') : auth.alignment?.[k] === false ? t('noLabel') : t('unknownLabel'));
  }
  const up = auth.upstream || {};
  if (up.raw) {
    addKV(dl, t('upstreamLabel'), up.authserv || '—');
    addKV(dl, t('upstreamSpf'), up.spf || '—');
    addKV(dl, t('upstreamDkim'), up.dkim || '—');
    addKV(dl, t('upstreamDmarc'), up.dmarc || '—');
  }
  const sigs = auth.dkimSignatures || [];
  if (sigs.length > 1) addKV(dl, t('dkimSignaturesLabel'), sigs.map(s => `${s.domain || '?'}/${s.selector || '?'}=${s.result || '?'}`).join(', '));
  box.append(dl);
  if (auth.raw) {
    const det = el('details');
    det.append(el('summary', '', t('authHeaderLabel') || 'Authentication-Results header'), el('pre', 'rawtext', auth.raw));
    box.append(det);
  }
  return box;
}

const authKind = result => {
  const r = String(result || '').toLowerCase();
  if (r === 'pass') return 'ok';
  if (['none', 'neutral', 'softfail'].includes(r)) return 'warn';
  return r ? 'bad' : 'warn';
};
const authLine = auth => {
  const wrap = el('span', 'authbadges');
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const r = auth?.[k]?.result;
    wrap.append(badge(`${k.toUpperCase()} ${r || 'none'}`, authKind(r)));
  }
  return wrap;
};

async function openMessage(caseId, index, msg, container) {
  if (container.dataset.loaded) return;
  container.dataset.loaded = '1';
  container.textContent = '…';
  try {
    const key = caseId + ':' + index;
    let data = bodyCache.get(key);
    if (!data) {
      const r = await api(`/api/case/${caseId}/message/${index}`);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(apiCode(j) || r.status);
      data = j;
      bodyCache.set(key, data);
    }
    container.textContent = '';
    const md = el('dl', 'kv');
    addKV(md, t('fromLabel'), msg.fromName ? `${msg.fromName} <${msg.from || ''}>` : msg.from);
    addKV(md, t('toLabel'), (msg.to || []).join(', '));
    addKV(md, t('replyToLabel'), msg.replyTo);
    addKV(md, t('returnPathLabel'), msg.returnPath);
    addKV(md, t('dateLabel'), fmtDate(msg.date));
    addKV(md, t('messageIdLabel'), msg.messageId);
    addKV(md, t('originIps'), (msg.originIPs || []).join(', '));
    addKV(md, t('statusLabel'), `${verdictText(msg.verdict)} · ${msg.score}/100`);
    container.append(el('h4', '', t('authLabel')), authLine(msg.auth), renderAuthDetails(msg.auth), md);
    if (data.headers) {
      const det = el('details');
      det.append(el('summary', '', 'Raw headers'), el('pre', 'rawtext', data.headers));
      container.append(det);
    }
    if (data.text) container.append(el('h4', '', t('bodyText')), el('pre', 'mailtext', data.text));
    if (data.html) {
      container.append(el('h4', '', t('bodyHtml')), el('p', 'hint', t('htmlBlocked')));
      const frame = el('iframe', 'mailhtml');
      frame.setAttribute('sandbox', '');
      frame.setAttribute('referrerpolicy', 'no-referrer');
      frame.title = t('bodyHtml');
      frame.srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><style>body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:.75rem;color:#111;word-break:break-word}pre{white-space:pre-wrap}table{border-collapse:collapse}td,th{border:1px solid #999;padding:.25rem}</style></head><body>${data.html}</body></html>`;
      container.append(frame);
    }
    if (!data.text && !data.html) container.append(el('p', 'hint', t('bodyEmpty')));
    if (data.truncated) container.append(el('p', 'hint', t('bodyTruncated')));
    if (data.omitted) container.append(el('p', 'hint', t('bodyOmitted')));
  } catch (e) {
    container.dataset.loaded = '';
    container.textContent = t('contentLoadFailed') + ' ' + e.message;
  }
}

function renderMessages(out, r) {
  if (!r?.messages?.length) return;
  out.append(el('h4', '', `${t('messagesLabel')} (${r.messages.length})`));
  const list = el('div', 'msglist');
  r.messages.slice(0, 200).forEach((m, i) => {
    const det = el('details', 'msg');
    const sum = el('summary');
    sum.append(
      el('span', 'msgnum', '#' + (i + 1)),
      el('strong', 'msgsubject', m.subject || '(no subject)'),
      el('span', 'msgfrom', m.fromName ? `${m.fromName} <${m.from || ''}>` : (m.from || '—')),
      el('span', 'msgdate', fmtDate(m.date)),
      el('span', 'msgscore', `${verdictText(m.verdict)} · ${m.score}/100`),
      authLine(m.auth)
    );
    det.append(sum);
    const box = el('div', 'msgbody', '…');
    det.append(box);
    det.addEventListener('toggle', () => { if (det.open) openMessage(r.custody.caseId, i, m, box); });
    list.append(det);
  });
  out.append(list);
  if (r.messages.length > 200) out.append(el('p', 'hint', t('showFirstMessages')));
}

function renderForensics(out, r) {
  if (!out || !r) return;
  const auth = r.auth || {};
  const hdr = r.headerAnalysis || {};
  const rt = r.routing || {};
  if (!auth.spf && !auth.dmarc && !rt.hopCount && !hdr.receivedCount) return;
  const sec = el('section', 'toolcard');
  const head = el('div', 'toolhead');
  head.append(el('h5', '', t('forensics')));
  const badges = el('span', '');
  for (const [label, a] of [['SPF', auth.spf], ['DKIM', auth.dkim], ['DMARC', auth.dmarc]]) {
    const res = a?.result || 'none';
    const kind = res === 'pass' ? 'ok' : (res === 'fail' ? 'bad' : (res === 'not_run' ? 'warn' : ''));
    badges.append(badge(`${label}: ${res}${res === 'fail' && a?.policy ? ' (p=' + a.policy + ')' : ''}`, kind), ' ');
  }
  head.append(badges);
  sec.append(head);
  const dl = el('dl', 'kv');
  if (auth.envDomain || auth.clientIp) addKV(dl, t('authEnvelope'), `${auth.envDomain || '—'} · ${auth.clientIp || '—'}`);
  if (hdr.receivedCount != null) addKV(dl, t('receivedCount'), String(hdr.receivedCount));
  if (rt.hopCount) addKV(dl, t('totalTransit'), `${rt.totalDelayMs || 0} ms`);
  if (dl.childElementCount) sec.append(dl);
  const checks = (hdr.checks || []).concat(rt.anomalies || []);
  if (checks.length) {
    const det = el('details');
    det.append(el('summary', '', `${t('headerChecks')} (${checks.length})`));
    for (const f of checks.slice(0, 60)) det.append(el('div', 'f s' + (f.sev ?? 0) + (f.weight === 0 ? ' info' : ''), `${f.id || ''} ${f.type || ''}: ${f.evidence || ''}`));
    sec.append(det);
  }
  if (rt.hops?.length) {
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', t('hopFrom'), 'By', 'With', t('gatewayLabel'), t('hopDelay'), t('hopTime')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    for (const h of rt.hops.slice(0, 40)) {
      const tr = el('tr');
      tr.append(el('td', '', '#' + h.idx),
        el('td', '', `${h.from || '—'}${h.ip ? ' (' + h.ip + ')' : ''}`),
        el('td', '', h.by || '—'), el('td', '', h.with || '—'), el('td', '', h.gateway || '—'),
        el('td', '', h.delayMs != null ? h.delayMs + ' ms' : '—'), el('td', '', h.ts || '—'));
      table.append(tr);
    }
    sec.append(table);
  }
  out.append(sec);
}

function renderThreats(out, r) {
  if (!out || !r) return;
  const urls = r.urls || [], atts = r.attachments || [], ioc = r.ioc || { counts: {} };
  if (!urls.length && !atts.length) return;
  const sec = el('section', 'toolcard');
  const head = el('div', 'toolhead');
  head.append(el('h5', '', t('threats')));
  const c = ioc.counts || {};
  if (Object.keys(c).length) head.append(badge(t('iocCount') + ': ' + Object.entries(c).map(([k, v]) => k + ' ' + v).join(', '), 'warn'));
  sec.append(head);
  if (urls.length) {
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', t('urlLabel'), t('hostLabel'), t('riskLabel'), t('reasonsLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    urls.slice(0, 60).forEach((u, i) => {
      const tr = el('tr');
      if (u.verdict === 'malicious') tr.className = 'rowbad'; else if (u.verdict === 'suspicious') tr.className = 'rowwarn';
      tr.append(el('td', '', String(i + 1)),
        el('td', '', (u.url || '').length > 80 ? u.url.slice(0, 80) + '…' : u.url),
        el('td', '', u.host || '—'),
        el('td', '', `${u.risk ?? '—'}% — ${assessText(u.verdict)}`),
        el('td', '', (u.reasons || []).join('; ') || '—'));
      table.append(tr);
    });
    sec.append(table);
  }
  out.append(sec);
}

function renderEnrichment(out, r) {
  const dnsEntries = Object.entries(r?.dns || {});
  if (dnsEntries.length) {
    out.append(el('h4', '', t('senderDns')), el('p', 'hint', t('dnsExplain')));
    for (const [domain, d] of dnsEntries) {
      const s = el('section', 'toolcard');
      const head = el('div', 'toolhead');
      head.append(el('h5', '', domain));
      if (d.assessment) head.append(badge(assessText(d.assessment.verdict), d.assessment.verdict === 'authentic' ? 'ok' : d.assessment.verdict === 'spoofed' ? 'bad' : 'warn'));
      s.append(head);
      const dl = el('dl', 'kv');
      const spf = d.auth?.spf, dmarc = d.auth?.dmarc;
      addKV(dl, 'SPF', spf?.found ? `${spf.raw || (spf.records || []).join(' / ')}${spf.all ? ' · all=' + spf.all : ''}` : t('notFoundLabel'));
      addKV(dl, 'DMARC', dmarc?.found ? `${dmarc.raw || 'found'}${dmarc.policy ? ' · p=' + dmarc.policy : ''}` : t('notFoundLabel'));
      addKV(dl, 'MX', (d.records?.mx || []).map(x => `${x.priority} ${x.exchange}`).join(', ') || t('noRecords'));
      if (d.assessment?.reasons?.length) addKV(dl, t('assessLabel'), d.assessment.reasons.join('; '));
      if (d.errors?.length) addKV(dl, 'Warnings', d.errors.map(e => `${e.code}: ${e.message}`).join('; '));
      s.append(dl);
      out.append(s);
    }
  }
  const ipEntries = r?.ipInfo || [];
  if (ipEntries.length) {
    out.append(el('h4', '', t('ipIntelligence')), el('p', 'hint', t('ipExplain')));
    const located = ipEntries.filter(x => x.geo?.location?.latitude != null && x.geo.location.longitude != null);
    if (located.length) {
      const img = el('img', 'ipmap');
      img.src = '/api/map?ips=' + encodeURIComponent(located.map(x => x.ip).join(','));
      img.alt = t('mapTitle');
      img.loading = 'lazy';
      out.append(img);
    }
    const locatedPct = ipEntries.length ? Math.round(located.length / ipEntries.length * 100) : 0;
    out.append(el('p', 'summary', `${t('locatedSummary')}: ${located.length}/${ipEntries.length} (${locatedPct}%)`));
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', 'IP', t('coordinatesLabel'), t('countryLabel'), t('cityLabel'), t('asnLabel'), t('organizationLabel'), t('ptrLabel'), t('serverTypeLabel'), t('assessLabel'), t('confidenceLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    ipEntries.forEach((x, n) => {
      const loc = x.geo?.location;
      const tr = el('tr');
      const conf = x.confidence != null ? Math.round(Number(x.confidence)) : null;
      tr.append(
        el('td', '', String(n + 1)), el('td', '', x.ip),
        el('td', '', loc?.latitude != null ? `${loc.latitude}, ${loc.longitude}` : '—'),
        el('td', '', x.geo?.countryIso ? `${x.geo.country || ''} (${x.geo.countryIso})` : (x.geo?.country || '—')),
        el('td', '', x.geo?.city || '—'), el('td', '', x.geo?.asn ? `AS${x.geo.asn}` : '—'),
        el('td', '', x.geo?.organization || '—'), el('td', '', (x.ptr || []).join(', ') || '—'),
        el('td', '', x.server ? `${serverText(x.server.key)}${x.server.evidence ? ' — ' + x.server.evidence : ''}` : '—'),
        el('td', '', x.assessment ? `${assessText(x.assessment.verdict)}${x.assessment.reasons?.length ? ' — ' + x.assessment.reasons.join('; ') : ''}` : '—'),
        el('td', conf == null ? '' : (conf >= 70 ? 'confhi' : conf >= 40 ? 'confmed' : 'conflo'), conf == null ? '—' : conf + '%')
      );
      table.append(tr);
    });
    out.append(table, el('p', 'hint', t('approxLabel')));
  }
}

// ---------------------------------------------------------------------------
// URLs by target
// ---------------------------------------------------------------------------
function localGroups(r) {
  const msgs = r.messages || [];
  const groups = {};
  for (const u of (r.urls || [])) {
    const m = u.m;
    const key = Number.isInteger(m) ? 'm' + m : 'file';
    if (!groups[key]) {
      const msg = Number.isInteger(m) && m >= 0 && m < msgs.length ? msgs[m] : {};
      groups[key] = { key, index: Number.isInteger(m) ? m : null, subject: msg.subject || u.target || t('fileLevel'), from: msg.from || '', urls: [] };
    }
    groups[key].urls.push(u);
  }
  return Object.values(groups);
}

async function renderUrls(out, r) {
  const cid = r.custody.caseId;
  let groups = localGroups(r);
  try {
    const resp = await api(`/api/case/${cid}/urls?lang=${lang}`);
    if (resp.ok) {
      const j = await resp.json();
      if (Array.isArray(j.groups)) groups = j.groups;
    }
  } catch {}
  out.append(el('h4', '', `${t('urlsByTarget')} (${groups.reduce((n, g) => n + (g.urls?.length || 0), 0)})`));
  if (!groups.length) {
    out.append(el('p', 'hint', '—'));
  }
  for (const g of groups) {
    const sec = el('section', 'toolcard');
    const head = el('div', 'toolhead');
    head.append(el('h5', '', g.subject || t('fileLevel')));
    if (g.from) head.append(el('span', 'summary', g.from));
    head.append(badge(`${g.urls.length} ${t('groupTotal')}`, 'warn'));
    sec.append(head);
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', t('urlLabel'), t('hostLabel'), t('riskLabel'), t('reasonsLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    g.urls.forEach((u, i) => {
      const tr = el('tr');
      if (u.verdict === 'malicious') tr.className = 'rowbad'; else if (u.verdict === 'suspicious') tr.className = 'rowwarn';
      tr.append(el('td', '', String(i + 1)),
        el('td', '', (u.url || '').length > 90 ? u.url.slice(0, 90) + '…' : u.url),
        el('td', '', u.host || '—'),
        el('td', '', `${u.risk ?? '—'}% — ${assessText(u.verdict)}`),
        el('td', '', (u.reasons || []).join('; ') || '—'));
      table.append(tr);
    });
    sec.append(table);
    out.append(sec);
  }
  if (r.urlImports?.length) {
    out.append(el('h4', '', 'Imports'));
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', 'ID', t('historyWhen'), 'Source', 'Count', t('importMerged')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    r.urlImports.forEach((x, i) => {
      const tr = el('tr');
      tr.append(el('td', '', String(i + 1)), el('td', '', x.id), el('td', '', fmtDate(x.ts)),
        el('td', '', (x.summary?.sources || x.source || '') + ''), el('td', '', String(x.count || '')), el('td', '', String(x.merged ?? '')));
      table.append(tr);
    });
    out.append(table);
  }
}

async function renderGraph(out, r) {
  const cid = r.custody.caseId;
  out.append(el('h4', '', t('resGraph')));
  const img = el('img', 'graphimg');
  img.alt = t('resGraph');
  img.src = `/api/case/${cid}/graph.svg?lang=${lang}&t=${Date.now()}`;
  out.append(img);
  const s = r.graph || {};
  out.append(el('p', 'summary', `${s.nodes || 0} nodes · ${s.edges || 0} edges`));
}

// ---------------------------------------------------------------------------
// report / URL import actions
// ---------------------------------------------------------------------------
async function reportHtml() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/report/${cid}?lang=${lang}`);
    await saveBlob(blob, `${cid}-report-${lang}.html`, 'text/html');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function reportPdf() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/report/${cid}.pdf?lang=${lang}`);
    await saveBlob(blob, `${cid}-report-${lang}.pdf`, 'application/pdf');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function reportCsv() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/report/${cid}.csv?lang=${lang}&kind=summary`);
    await saveBlob(blob, `${cid}-report-${lang}.csv`, 'text/csv');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function reportBundle() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const files = [];
    files.push({ name: `${cid}-report-${lang}.pdf`, mime: 'application/pdf', blob: await blobFrom(`/api/report/${cid}.pdf?lang=${lang}`) });
    files.push({ name: `${cid}-urls-${lang}.csv`, mime: 'text/csv', blob: await blobFrom(`/api/case/${cid}/urls.csv?lang=${lang}`) });
    files.push({ name: `${cid}-report-${lang}.csv`, mime: 'text/csv', blob: await blobFrom(`/api/report/${cid}.csv?lang=${lang}&kind=summary`) });
    files.push({ name: `${cid}-report-${lang}.html`, mime: 'text/html', blob: await blobFrom(`/api/report/${cid}?lang=${lang}`) });
    const svg = await blobFrom(`/api/case/${cid}/graph.svg?lang=${lang}`);
    files.push({ name: `${cid}-graph.svg`, mime: 'image/svg+xml', blob: svg });
    await saveMany(files);
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('exportFail') + e.message; }
}
async function verifySignature() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const r = await api(`/api/report/${cid}/verify`);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(apiCode(j) || r.status);
    $('resultMsg').textContent = j.match ? t('verifyOk') : t('verifyBad');
    $('resultMsg').className = j.match ? 'ok' : 'bad';
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function exportUrlCsv() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/case/${cid}/urls.csv?lang=${lang}`);
    await saveBlob(blob, `${cid}-urls-${lang}.csv`, 'text/csv');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('exportFail') + e.message; }
}
async function importUrls(fileList) {
  const cid = currentCase();
  const files = Array.from(fileList || []);
  if (!files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append('files', f, f.name);
  if (cid) fd.append('case_id', cid);
  try {
    const r = await api('/api/urls/import', { method: 'POST', body: fd });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(apiCode(j) || r.status);
    $('resultMsg').textContent = `${t('importOk')} ${j.summary?.total ?? 0} URL · ${j.merged ?? 0} ${t('importMerged')}`;
    $('resultMsg').className = 'ok';
    if (cid) {
      const resp = await api(`/api/report/${cid}?format=json`);
      if (resp.ok) {
        lastResults[currentIdx] = await resp.json();
        resTab = 'urls';
        renderCurrentResult();
      }
    }
  } catch (e) {
    $('resultMsg').textContent = t('importFail') + ' ' + e.message;
    $('res