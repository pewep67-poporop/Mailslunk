import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';

const BASE = 'http://127.0.0.1:8100';
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const PORT = 9334;
const TMP = process.env.TEMP + '\\opencode';
const FILES = TMP + '\\ui-files-' + Date.now();
const PROFILE = TMP + '\\edgeui-' + Date.now();

let p = 0, f = 0;
const ok = (n, c, e = '') => { c ? (p++, console.log('  PASS  ' + n)) : (f++, console.log('  FAIL  ' + n + (e ? ' :: ' + e : ''))); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

mkdirSync(FILES, { recursive: true });
const write = (name, size) => { writeFileSync(FILES + '\\' + name, Buffer.alloc(size, 0x61)); return FILES + '\\' + name; };
const eml = 'From: a@b.c\r\nSubject: t\r\n\r\nhello';
const valid = [];
for (let i = 0; i < 11; i++) { const pth = FILES + '\\m' + i + '.eml'; writeFileSync(pth, eml); valid.push(pth); }
const okFile = write('ok1.eml', 64);
const badExt = write('notes.exe', 64);
const pst = write('mail.pst', 64);
const empty = write('empty.eml', 0);
const big = write('big.eml', 25 * 1024 * 1024 + 1);

async function waitHttp(url, tries = 120) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(url); if (r.ok) return await r.json(); } catch {}
    await sleep(150);
  }
  throw new Error('no devtools at ' + url);
}

const edge = spawn(EDGE, [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--disable-extensions', '--remote-debugging-port=' + PORT, '--user-data-dir=' + PROFILE, 'about:blank'
], { stdio: 'ignore' });

const version = await waitHttp(`http://127.0.0.1:${PORT}/json/version`);
ok('edge devtools up', !!version.webSocketDebuggerUrl);

const created = await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(BASE + '/')}`, { method: 'PUT' }).then(r => r.json());
const cdp = await new Promise((res, rej) => {
  const ws = new WebSocket(created.webSocketDebuggerUrl);
  let id = 0; const pend = new Map();
  ws.onopen = () => res({
    ws,
    send(method, params = {}) { return new Promise((r2, j2) => { const i = ++id; pend.set(i, { r2, j2 }); ws.send(JSON.stringify({ id: i, method, params })); }); }
  });
  ws.onerror = rej;
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { const { r2, j2 } = pend.get(m.id); pend.delete(m.id); m.error ? j2(new Error(JSON.stringify(m.error))) : r2(m.result); }
  };
});
await cdp.send('Runtime.enable');
await cdp.send('Page.enable');
await cdp.send('DOM.enable');

async function ev(expr) {
  const r = await cdp.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || JSON.stringify(r.exceptionDetails));
  return r.result.value;
}
async function until(expr, ms = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await ev(expr)) return true; await sleep(120); }
  return false;
}
async function setFiles(paths) {
  const r = await cdp.send('Runtime.evaluate', { expression: `document.getElementById('f')`, returnByValue: false });
  await cdp.send('DOM.setFileInputFiles', { files: paths, objectId: r.result.objectId });
  await sleep(250);
}
const ui = () => ev(`({
  pick: document.getElementById('pickMsg').textContent,
  pfRows: [...document.querySelectorAll('#pfList li')].map(li => li.textContent),
  pfHidden: document.getElementById('preflight').hidden,
  runDisabled: document.getElementById('run').disabled,
  pauseDisabled: document.getElementById('btnPause').disabled,
  stopDisabled: document.getElementById('btnStop').disabled,
  cancelDisabled: document.getElementById('btnCancel').disabled,
  pauseLabel: document.getElementById('btnPause').textContent,
  state: document.getElementById('runState').textContent,
  stateHidden: document.getElementById('runState').hidden,
  blocks: document.querySelectorAll('#out > .caseblock').length,
  single: !!document.querySelector('#out > h3'),
  outLen: document.getElementById('out').textContent.length,
  progHidden: document.getElementById('progBarWrap').hidden,
  pct: document.getElementById('progPct').textContent
})`);

ok('page loaded', await until(`document.getElementById('login') && document.getElementById('run') && document.getElementById('pickMsg') && document.getElementById('pickMsg').textContent.length > 0`, 20000));

const logged = await ev(`(async () => {
  document.getElementById('u').value = 'admin';
  document.getElementById('p').value = 'TestSmoke-123456';
  document.getElementById('go').click();
  for (let i = 0; i < 120; i++) { if (!document.getElementById('app').hidden) return true; await new Promise(r => setTimeout(r, 100)); }
  return false;
})()`);
ok('login via UI', logged === true, await ev(`document.getElementById('err').textContent`));

// ---------- A. preflight ----------
await ev(`document.getElementById('fclear').click()`);
await setFiles([okFile, badExt, pst, empty, big]);
const a = await ui();
ok('preflight keeps 2 valid files (eml + pst)', /^2 file\(s\) selected/.test(a.pick), a.pick);
ok('preflight lists 3 rejected files', a.pfRows.length === 3 && a.pfHidden === false, JSON.stringify(a.pfRows));
ok('reasons shown: ext / empty / >25MB',
  a.pfRows.some(x => /unsupported extension/.test(x)) &&
  a.pfRows.some(x => /empty file/.test(x)) &&
  a.pfRows.some(x => /25 MB/.test(x)), JSON.stringify(a.pfRows));
ok('PST no longer rejected', !a.pfRows.some(x => /PST\/OST/.test(x)), JSON.stringify(a.pfRows));
ok('PST kept in the valid list', await ev(`[...document.querySelectorAll('#flist .fname')].some(x => /mail\\.pst$/.test(x.textContent))`));
ok('analyze enabled with valid files', a.runDisabled === false, a.pick);
ok('pause/stop/cancel disabled when idle', a.pauseDisabled && a.stopDisabled && a.cancelDisabled, JSON.stringify(a));

await setFiles([okFile]); // same file again -> duplicate
const dup = await ui();
ok('duplicate rejected as pfDupe', dup.pfRows.some(x => /duplicate/.test(x)) && /^2 file\(s\) selected/.test(dup.pick), JSON.stringify(dup.pfRows));

await ev(`document.getElementById('fclear').click()`);
await setFiles([badExt]);
const none = await ui();
ok('all-invalid list leaves zero files', /No files selected/.test(none.pick), none.pick);
ok('analyze disabled when no valid files', none.runDisabled === true, none.pick);

// ---------- fetch delay harness (module uses the global fetch) ----------
await ev(`(() => {
  window.__origFetch = window.__origFetch || window.fetch;
  window.__delayFor = () => 0;
  window.__calls = 0;
  window.fetch = async (u, o) => {
    if (String(u).includes('/api/analyze')) {
      window.__calls++;
      const d = window.__delayFor(window.__calls);
      if (d) await new Promise(r => setTimeout(r, d));
    }
    return window.__origFetch(u, o);
  };
  return true;
})()`);

// ---------- B. pause / resume ----------
await ev(`document.getElementById('fclear').click()`);
await setFiles(valid);
ok('11 valid files selected', /^11 file\(s\) selected/.test((await ui()).pick), (await ui()).pick);
await ev(`window.__delayFor = () => 1200; window.__calls = 0`);
await ev(`document.getElementById('run').click()`);
ok('run started (buttons enabled)', await until(`!document.getElementById('btnPause').disabled && !document.getElementById('btnStop').disabled`));
await ev(`document.getElementById('btnPause').click()`);
const p1 = await ui();
ok('pause click flips label to Resume', p1.pauseLabel === 'Resume', p1.pauseLabel);
ok('pause click shows pausing message', /Pausing/.test(p1.state), p1.state);
ok('pause reaches the batch boundary', await until(`/Paused/.test(document.getElementById('runState').textContent)`, 10000));
const p2 = await ui();
const callsWhilePaused = await ev(`window.__calls`);
ok('no next batch starts while paused', callsWhilePaused === 1, 'calls=' + callsWhilePaused);
ok('analyze disabled while running', p2.runDisabled === true, String(p2.runDisabled));
ok('progress is not complete while paused', p2.pct !== '100%', p2.pct);
await ev(`document.getElementById('btnPause').click()`);
ok('resume finishes the run', await until(`document.getElementById('btnPause').disabled && !document.getElementById('run').disabled`, 30000));
const done = await ui();
ok('all 11 results rendered after resume', done.blocks === 11, 'blocks=' + done.blocks);
ok('run state cleared after success', done.state === '' && done.stateHidden === true, JSON.stringify({ s: done.state, h: done.stateHidden }));
ok('pause label back to Pause', done.pauseLabel === 'Pause', done.pauseLabel);

// ---------- B2. message detail body (M8) ----------
const opened = await ev(`(() => { const d = document.querySelector('#out .msg'); if (!d) return false; const s = d.querySelector('summary'); if (!s) return false; s.click(); return true; })()`);
ok('message details opened', opened === true);
const bodyLoaded = await until(`(() => { const p = document.querySelector('#out .msg pre.mailtext'); return !!p && (p.textContent || '').length > 0; })()`, 15000);
ok('message body loaded from API', bodyLoaded);
const bodyErr = await ev(`(() => { const b = document.querySelector('#out .msg .msgbody'); return b ? (b.textContent || '') : ''; })()`);
ok('no content-load error in message body', !/could not load|không tải được/i.test(bodyErr), bodyErr.slice(0, 120));

// ---------- C. stop keeps partial results ----------
await ev(`document.getElementById('fclear').click()`);
await setFiles(valid);
await ev(`window.__delayFor = n => n === 1 ? 200 : 5000; window.__calls = 0`);
await ev(`document.getElementById('run').click()`);
ok('second run starts two batches', await until(`window.__calls >= 2`, 10000));
await ev(`document.getElementById('btnStop').click()`);
ok('stop returns to idle', await until(`!document.getElementById('run').disabled && document.getElementById('btnPause').disabled`, 12000));
const st = await ui();
ok('stop keeps the first finished batch (10 blocks)', st.blocks === 10, 'blocks=' + st.blocks);
ok('stop reports partial 10/11', /Stopped/.test(st.state) && st.state.includes('10/11'), st.state);
ok('stop keeps result output visible', st.outLen > 0, 'outLen=' + st.outLen);
ok('stop re-enables analyze', st.runDisabled === false, String(st.runDisabled));

// ---------- D. cancel discards results ----------
await ev(`document.getElementById('fclear').click()`);
await setFiles(valid);
await ev(`window.__delayFor = () => 5000; window.__calls = 0`);
await ev(`document.getElementById('run').click()`);
ok('third run started', await until(`window.__calls >= 1 && !document.getElementById('btnCancel').disabled`, 8000));
await ev(`document.getElementById('btnCancel').click()`);
ok('cancel returns to idle', await until(`!document.getElementById('run').disabled && document.getElementById('btnPause').disabled`, 10000));
const ca = await ui();
ok('cancel discards results (no blocks)', ca.blocks === 0 && !ca.single, 'blocks=' + ca.blocks);
ok('cancel clears output', ca.outLen === 0, 'outLen=' + ca.outLen);
ok('cancel shows cancelled message', /cancelled|discarded/i.test(ca.state), ca.state);
ok('cancel hides progress bar', ca.progHidden === true, String(ca.progHidden));
ok('cancel re-enables analyze', ca.runDisabled === false, String(ca.runDisabled));

// ---------- E. i18n label ----------
await ev(`(() => { const s = document.getElementById('lang'); s.value = 'vi'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
await sleep(300);
const vi = await ui();
ok('Vietnamese: pause label localized', vi.pauseLabel === 'Tạm dừng', vi.pauseLabel);
await ev(`document.getElementById('fclear').click()`);
await setFiles([badExt]);
const viPf = await ev(`({ msg: document.getElementById('pfMsg').textContent, hidden: document.getElementById('preflight').hidden, reason: document.querySelector('#pfList .pfreason')?.textContent || '' })`);
ok('Vietnamese: preflight text + reason localized',
  viPf.hidden === false && /tệp bị kiểm tra trước loại bỏ/.test(viPf.msg) && /phần mở rộng không hỗ trợ/.test(viPf.reason), JSON.stringify(viPf));
await ev(`document.getElementById('fclear').click()`);
await ev(`(() => { const s = document.getElementById('lang'); s.value = 'en'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);

console.log(`\n${p}/${p + f} PASS`);
try { cdp.ws.close(); } catch {}
try { edge.kill(); } catch {}
try { rmSync(PROFILE, { recursive: true, force: true }); } catch {}
try { rmSync(FILES, { recursive: true, force: true }); } catch {}
process.exit(f ? 1 : 0);
