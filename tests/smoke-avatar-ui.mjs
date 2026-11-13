import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = 'http://127.0.0.1:8100';
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const PORT = 9336;
const TMP = process.env.TEMP + '\\opencode';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const FILES = TMP + '\\av-files-' + Date.now();
const PROFILE = TMP + '\\edgeav-' + Date.now();

let p = 0, f = 0;
const ok = (n, c, e = '') => { c ? (p++, console.log('  PASS  ' + n)) : (f++, console.log('  FAIL  ' + n + (e ? ' :: ' + e : ''))); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

mkdirSync(FILES, { recursive: true });
// real 64x64 PNG (red/yellow/blue quadrants) — used as the uploaded avatar
const PNG = readFileSync(HERE + '\\real-avatar.png');
const png = FILES + '\\me.png';
writeFileSync(png, PNG);
const notImage = FILES + '\\fake.png';
writeFileSync(notImage, Buffer.from('this is not an image'));

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
  let id = 0; const pend = new Map(); const logs = []; const failed = []; const net = [];
  ws.onopen = () => res({
    ws, logs, failed, net,
    send(method, params = {}) { return new Promise((r2, j2) => { const i = ++id; pend.set(i, { r2, j2 }); ws.send(JSON.stringify({ id: i, method, params })); }); }
  });
  ws.onerror = rej;
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') logs.push(JSON.stringify(m.params.args?.map(a => a.value || a.description)));
    if (m.method === 'Network.loadingFailed') failed.push(m.params.errorText);
    if (m.method === 'Network.responseReceived') { cdp.net.push(m.params.response.status + ' ' + m.params.response.url); if (m.params.response.status >= 400) failed.push(m.params.response.status + ' ' + m.params.response.url); }
    if (m.id && pend.has(m.id)) { const { r2, j2 } = pend.get(m.id); pend.delete(m.id); m.error ? j2(new Error(JSON.stringify(m.error))) : r2(m.result); }
  };
});
await cdp.send('Runtime.enable');
await cdp.send('Page.enable');
await cdp.send('DOM.enable');
await cdp.send('Network.enable');

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
async function setFile(id, path) {
  const r = await cdp.send('Runtime.evaluate', { expression: `document.getElementById('${id}')`, returnByValue: false });
  await cdp.send('DOM.setFileInputFiles', { files: [path], objectId: r.result.objectId });
  await sleep(200);
}
const avState = () => ev(`(() => {
  const sm = document.getElementById('avatarSm'), big = document.getElementById('avatarBig');
  const g = e => e ? { hidden: e.hidden, src: e.getAttribute('src') || '', disp: getComputedStyle(e).display,
                       w: e.naturalWidth, h: e.naturalHeight, cw: e.clientWidth, ch: e.clientHeight } : null;
  return { sm: g(sm), big: g(big), msg: (document.getElementById('avatarMsg')?.textContent || ''),
           meta: (document.getElementById('profileMeta')?.textContent || ''),
           barHidden: document.getElementById('accountBar')?.hidden,
           smRect: sm ? JSON.stringify(sm.getBoundingClientRect()) : 'none' };
})()`);

ok('page loaded', await until(`document.getElementById('login') && document.getElementById('run') && document.getElementById('pickMsg') && document.getElementById('pickMsg').textContent.length > 0`, 25000));

const logged = await ev(`(async () => {
  document.getElementById('u').value = 'admin';
  document.getElementById('p').value = 'TestSmoke-123456';
  document.getElementById('go').click();
  for (let i = 0; i < 120; i++) { if (!document.getElementById('app').hidden) return true; await new Promise(r => setTimeout(r, 100)); }
  return false;
})()`);
ok('login via UI', logged === true, await ev(`document.getElementById('err').textContent`) + ' | appHidden=' + await ev(`document.getElementById('app').hidden`) + ' | net=' + JSON.stringify(cdp.net));

await sleep(800);
const before = await avState();
// either no avatar yet (hidden) or an avatar that is already displayed
ok('avatar state consistent before upload',
  (before.sm?.hidden === true && !before.sm?.src) || (before.sm?.hidden === false && before.sm?.w > 0),
  JSON.stringify(before.sm));

// upload a valid PNG
await setFile('avatarFile', png);
await ev(`document.getElementById('avatarUpload').click()`);
ok('avatar upload shows ok message', await until(`/updated|cập nhật/i.test(document.getElementById('avatarMsg').textContent)`, 15000),
  await ev(`document.getElementById('avatarMsg').textContent`));
await sleep(600);
const after = await avState();
ok('small avatar visible', after.sm?.hidden === false && after.sm?.disp !== 'none', JSON.stringify(after.sm));
ok('big avatar visible', after.big?.hidden === false && after.big?.disp !== 'none', JSON.stringify(after.big));
ok('avatar src points to API', /\/api\/profile\/avatar/.test(after.sm?.src || ''), after.sm?.src);
ok('avatar image actually loaded (naturalWidth>0)', after.sm?.w > 0 && after.big?.w > 0, JSON.stringify(after.sm));
ok('avatar has rendered size', (after.sm?.cw || 0) > 0 && (after.sm?.ch || 0) > 0, JSON.stringify(after.sm));
ok('profile meta rendered', /admin/.test(after.meta || ''), after.meta);
ok('no failed network requests', cdp.failed.filter(x => !/favicon|\/api\/me/.test(x)).length === 0, JSON.stringify(cdp.failed));
ok('no console errors', cdp.logs.length === 0, JSON.stringify(cdp.logs));

// invalid file -> friendly error, avatar must not break
await setFile('avatarFile', notImage);
await ev(`document.getElementById('avatarUpload').click()`);
await sleep(800);
const bad = await avState();
ok('invalid image rejected with message', /invalid|không hợp lệ|only png/i.test(bad.msg || ''), bad.msg);
ok('avatar still displayed after rejected upload', bad.sm?.hidden === false && bad.sm?.w > 0, JSON.stringify(bad.sm));

// reload -> avatar still shown (persisted)
await ev(`location.reload()`);
await sleep(1500);
ok('app after reload', await until(`document.getElementById('app') && !document.getElementById('app').hidden`, 20000));
await sleep(800);
const re = await avState();
ok('avatar persisted after reload', re.sm?.hidden === false && re.sm?.w > 0, JSON.stringify(re.sm));

// ---------- monogram fallback for a fresh account (no avatar) ----------
await fetch(BASE + '/api/register', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ user: 'tester1', pass: 'TestSmoke-123456' })
});
await ev(`(async () => {
  document.getElementById('logout') ? document.getElementById('logout').click() : null;
  document.getElementById('u').value = 'tester1';
  document.getElementById('p').value = 'TestSmoke-123456';
  document.getElementById('go').click();
  for (let i = 0; i < 120; i++) { if (!document.getElementById('app').hidden) return true; await new Promise(r => setTimeout(r, 100)); }
  return false;
})()`);
await sleep(1200);
const mono = await ev(`(() => {
  const sm = document.getElementById('avatarSmMono'), big = document.getElementById('avatarBigMono');
  const img = document.getElementById('avatarSm');
  return { smHidden: sm?.hidden, smText: sm?.textContent, smDisp: sm ? getComputedStyle(sm).display : 'none',
           bigHidden: big?.hidden, bigText: big?.textContent, imgHidden: img?.hidden };
})()`);
ok('monogram shown when no avatar', mono.smHidden === false && mono.smText === 'T' && mono.smDisp !== 'none', JSON.stringify(mono));
ok('no empty image box for the monogram account', mono.imgHidden === true, JSON.stringify(mono));
ok('big monogram shown', mono.bigHidden === false && mono.bigText === 'T', JSON.stringify(mono));

// error mapping: posting without a session must not say "Only PNG or JPEG"
const badResp = await fetch(BASE + '/api/profile/avatar', { method: 'POST', body: new FormData() });
const badBody = await badResp.json().catch(() => ({}));
ok('unauthenticated avatar upload -> 401 auth', badResp.status === 401 && badBody.error === 'auth', badResp.status + ' ' + JSON.stringify(badBody));
const nf = await fetch(BASE + '/api/nope');
const nfBody = await nf.json().catch(() => ({}));
ok('unknown route -> flat not_found', nf.status === 404 && nfBody.error === 'not_found', nf.status + ' ' + JSON.stringify(nfBody));

console.log(`\n${p}/${p + f} PASS`);
try { cdp.ws.close(); } catch {}
try { edge.kill(); } catch {}
try { rmSync(PROFILE, { recursive: true, force: true }); } catch {}
try { rmSync(FILES, { recursive: true, force: true }); } catch {}
process.exit(f ? 1 : 0);
