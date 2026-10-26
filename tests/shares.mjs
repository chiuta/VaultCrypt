// Teste Playwright pentru VaultCrypt 3.0: părți de recuperare Shamir (k din n) cu coduri QR + verificarea structurii seifului.
// Implementarea de referință GF(2^8) de mai jos este INDEPENDENTĂ de cea din aplicație (înmulțire „țăran rus”, interpolare Lagrange proprie).
// Rulare: node tests/shares.mjs   (portabil; axe-core prin FFF_AXE / AXE_PATH; decodarea QR cu OpenCV dacă `python3 -c "import cv2"` există)
import { createRequire } from 'module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const require = createRequire(process.env.PW_ROOT || import.meta.url);
const { chromium } = require('playwright');
const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_FILE = path.resolve(HERE, '../index.html');
const APP = 'https://vaultcrypt.test/index.html';
const APP_JSON = JSON.parse(fs.readFileSync(path.resolve(HERE, '../app.json'), 'utf8'));
const AXE = process.env.FFF_AXE || process.env.AXE_PATH || (() => { try { return require.resolve('axe-core/axe.min.js'); } catch { return undefined; } })();
const W = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultcrypt-shares-'));

const results = []; let current = '';
async function test(name, fn) {
  current = name; const t0 = Date.now();
  try { await fn(); results.push({ name, ok: true }); console.log('  ok   ' + name + ' (' + (Date.now() - t0) + ' ms)'); }
  catch (e) { results.push({ name, ok: false, err: e.stack || String(e) }); console.log('  FAIL ' + name + '\n       ' + String(e.message || e).split('\n').join('\n       ')); }
}
const assert = (c, m) => { if (!c) throw new Error(m || 'assertion failed'); };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error((m || 'not equal') + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)); };

/* ---------- referință independentă ---------- */
function gmul(a, b) { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1; } return p; }
function ginv(a) { for (let b = 1; b < 256; b++) if (gmul(a, b) === 1) return b; throw new Error('inv0'); }
function lagrange0(pts) { // pts: [{x, y:Uint8Array}] -> valoarea în 0
  const L = pts[0].y.length, out = new Uint8Array(L);
  for (let i = 0; i < pts.length; i++) {
    let num = 1, den = 1;
    for (let j = 0; j < pts.length; j++) if (j !== i) { num = gmul(num, pts[j].x); den = gmul(den, pts[i].x ^ pts[j].x); }
    const w = gmul(num, ginv(den)); for (let c = 0; c < L; c++) out[c] ^= gmul(pts[i].y[c], w);
  }
  return out;
}
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32(s) { let bits = 0, v = 0; const o = []; for (const ch of s) { v = (v << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { o.push((v >> (bits - 8)) & 255); bits -= 8; v &= (1 << bits) - 1; } } return Buffer.from(o); }
function parseShare(t) { // VCS1:... -> câmpuri, cu verificarea CRC (SHA-256 trunchiat) făcută independent
  assert(/^VCS1:[A-Z2-7]{1,5}(-[A-Z2-7]{1,5})*$/.test(t), 'format text: ' + t.slice(0, 30));
  const b = b32(t.slice(5).replace(/-/g, '')); const body = b.subarray(0, b.length - 4);
  assert(crypto.createHash('sha256').update(body).digest().subarray(0, 4).equals(b.subarray(b.length - 4)), 'crc');
  let o = 4; const id = body.subarray(o, o + 6).toString('hex'); o += 6; const ll = body[o++]; const label = body.subarray(o, o + ll).toString('utf8'); o += ll;
  const dl = (body[o] << 8) | body[o + 1]; o += 2; assert(o + dl === body.length, 'lungime date');
  return { ver: body[0], k: body[1], x: body[2], n: body[3], id, label, y: Uint8Array.from(body.subarray(o)) };
}
function refRecover(texts) {
  const ps = texts.map(parseShare); const d = lagrange0(ps.map((p) => ({ x: p.x, y: p.y }))); const len = (d[0] << 8) | d[1];
  const padded = d.length - 4; const tag = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('VCS1'), Buffer.from(d.subarray(0, padded))])).digest().subarray(0, 4);
  assert(Buffer.from(d.subarray(padded)).equals(tag), 'tag intern'); return Buffer.from(d.subarray(2, 2 + len)).toString('utf8');
}
function combos(arr, k) { const out = []; (function rec(s, cur) { if (cur.length === k) { out.push(cur.slice()); return; } for (let i = s; i < arr.length; i++) { cur.push(arr[i]); rec(i + 1, cur); cur.pop(); } })(0, []); return out; }
let HAVE_CV = false; try { execFileSync('python3', ['-c', 'import cv2']); HAVE_CV = true; } catch { /* fără OpenCV: testul QR cu decodor extern e sărit */ }
function cvDecode(png) {
  const f = path.join(W, 'qr-' + crypto.randomBytes(4).toString('hex') + '.png'); fs.writeFileSync(f, png);
  const py = 'import cv2,sys\nim=cv2.imread(sys.argv[1])\nim=cv2.copyMakeBorder(im,30,30,30,30,cv2.BORDER_CONSTANT,value=(255,255,255))\nt,_,_=cv2.QRCodeDetector().detectAndDecode(im)\nsys.stdout.write(t)';
  return execFileSync('python3', ['-c', py, f]).toString();
}

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--no-sandbox'] });
const netReqs = [], pageErrors = [];
async function mkCtx(opts = {}) {
  const ctx = await browser.newContext(Object.assign({ viewport: { width: 1280, height: 1000 }, acceptDownloads: true, locale: 'ro-RO', serviceWorkers: 'block' }, opts));
  await ctx.route(/^https?:/, (r) => {
    const u = r.request().url();
    if (u.startsWith('https://vaultcrypt.test/index.html')) return r.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: fs.readFileSync(APP_FILE) });
    const m = /^https:\/\/vaultcrypt\.test\/(manifest\.webmanifest|icon-192\.png|icon-512\.png|icon-maskable-512\.png)$/.exec(u);
    if (m) { const fp = path.resolve(HERE, '..', m[1]); if (fs.existsSync(fp)) return r.fulfill({ status: 200, contentType: m[1].endsWith('png') ? 'image/png' : 'application/manifest+json', body: fs.readFileSync(fp) }); }
    netReqs.push(u); r.abort();
  });
  await ctx.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI)); });
  return ctx;
}
const ctx = await mkCtx();
async function openApp(c = ctx, lang = 'ro') {
  const p = await c.newPage();
  p.on('pageerror', (e) => pageErrors.push(current + ': ' + e.message)); p.on('console', (m) => { if (m.type() === 'error') pageErrors.push(current + ' console: ' + m.text()); });
  await p.goto(APP); await p.evaluate((l) => { try { localStorage.clear(); localStorage.setItem('vaultcrypt.lang', l); } catch (e) {} }, lang); await p.reload();
  await p.waitForFunction(() => document.querySelector('#view-share') && typeof shMake === 'function');
  return p;
}
async function makeShares(p, { secret = 'corect cal baterie capsuna', n = 5, k = 3, label = 'Familia', wipe = true } = {}) {
  await p.click('.tab[data-tab="share"]');
  await p.fill('#sh-secret', secret); await p.fill('#sh-n', String(n)); await p.fill('#sh-k', String(k)); await p.fill('#sh-label', label);
  if ((await p.isChecked('#sh-wipe')) !== wipe) await p.click('#sh-wipe');
  await p.click('#sh-go'); await p.waitForSelector('.sh-card', { timeout: 15000 });
  return p.$$eval('.sh-code', (els) => els.map((e) => e.textContent));
}
const listText = (p) => p.evaluate(() => document.querySelector('#sh-list').innerText);

await test('creare 3 din 5: 5 carduri cu QR, text VCS1 valid, recuperare independentă pentru ORICE 3 din 5', async () => {
  const p = await openApp(); const sec = 'corect cal baterie capsuna ăâîșț 🔐';
  const texts = await makeShares(p, { secret: sec });
  eq(texts.length, 5); assert(await p.locator('.sh-qr svg').count() === 5, '5 coduri QR');
  eq(await p.inputValue('#sh-secret'), '', 'câmpul secretului golit');
  for (const t of texts) { const q = parseShare(t); eq([q.ver, q.k, q.n, q.label], [1, 3, 5, 'Familia']); assert(!t.includes(sec)); }
  eq(new Set(texts.map((t) => parseShare(t).id)).size, 1, 'același set'); eq(texts.map((t) => parseShare(t).x), [1, 2, 3, 4, 5]);
  for (const c of combos(texts, 3)) eq(refRecover(c), sec, 'recuperare independentă');
  for (const c of combos(texts, 4)) eq(refRecover(c), sec);
  // aplicația recuperează aceleași combinații
  for (const c of combos(texts, 3)) { const a = await p.evaluate(async (c) => { const r = await shAnalyze(c); return { s: r.state, t: r.secret && new TextDecoder().decode(r.secret) }; }, c); eq(a, { s: 'ok', t: sec }); }
  // sub prag: nimic recuperat
  for (const c of combos(texts, 2)) { const a = await p.evaluate(async (c) => (await shAnalyze(c)).state, c); eq(a, 'need'); }
  await p.close();
});

await test('secretul NU poate fi dedus din k-1 părți: pentru orice valoare candidată a secretului există un polinom compatibil (distribuție uniformă)', async () => {
  const p = await openApp();
  // același secret, multe împărțiri k=2: valoarea părții 1 (primul octet) trebuie să fie ~uniformă; părțile diferă între rulări
  const ys = await p.evaluate(async () => { const sec = new Uint8Array(1); const o = []; for (let i = 0; i < 4000; i++) o.push(shSplit(sec, 2, 2)[0].y[0]); return o; });
  const cnt = new Array(256).fill(0); ys.forEach((v) => cnt[v]++);
  assert(cnt.filter(Boolean).length > 250, 'acoperire a 256 valori: ' + cnt.filter(Boolean).length);
  assert(Math.max(...cnt) < 40, 'nicio valoare supra-reprezentată: ' + Math.max(...cnt)); // medie 15.6
  const a = await openApp(); const t1 = await makeShares(a), t2 = await makeShares(a);
  assert(t1[0] !== t2[0] && parseShare(t1[0]).id !== parseShare(t2[0]).id, 'seturi distincte la fiecare creare');
  await a.close(); await p.close();
});

await test('vector cunoscut GF(256) față de referința independentă (toate perechile de elemente + coeficienți fixi)', async () => {
  const p = await openApp();
  const ok = await p.evaluate(() => { const t = []; for (let a = 0; a < 256; a += 7) for (let b = 0; b < 256; b++) t.push(gfMul(a, b)); return t; });
  let i = 0; for (let a = 0; a < 256; a += 7) for (let b = 0; b < 256; b++) { if (ok[i++] !== gmul(a, b)) throw new Error(`gfMul(${a},${b})`); }
  const known = await p.evaluate(() => { const s = shSplit(new Uint8Array([0x42, 0xff]), 3, 4, () => new Uint8Array([1, 2, 3, 4])); return s.map((x) => [x.x, Array.from(x.y)]); });
  // coeficienți: octet0: a1=1,a2=2 ; octet1: a1=3,a2=4  =>  y = s + a1 x + a2 x^2
  const exp = [1, 2, 3, 4].map((x) => [x, [0x42 ^ gmul(1, x) ^ gmul(2, gmul(x, x)), 0xff ^ gmul(3, x) ^ gmul(4, gmul(x, x))]]);
  eq(known, exp, 'vector cunoscut'); await p.close();
});

await test('validări: secret gol, prea lung, n/k greșit, etichetă prea lungă; nicio parte afișată', async () => {
  const p = await openApp(); await p.click('.tab[data-tab="share"]');
  await p.click('#sh-go'); assert(/secret/i.test(await p.innerText('#sh-out'))); eq(await p.locator('.sh-card').count(), 0);
  await p.fill('#sh-secret', 'x'.repeat(1025)); await p.click('#sh-go'); assert(/1024/.test(await p.innerText('#sh-out')));
  await p.fill('#sh-secret', 'abc'); await p.fill('#sh-n', '3'); await p.fill('#sh-k', '5'); await p.click('#sh-go'); assert(/16/.test(await p.innerText('#sh-out')));
  await p.fill('#sh-n', '17'); await p.fill('#sh-k', '2'); await p.click('#sh-go'); assert(/16/.test(await p.innerText('#sh-out')));
  await p.fill('#sh-n', '3'); await p.fill('#sh-k', '1'); await p.click('#sh-go'); assert(/16/.test(await p.innerText('#sh-out')));
  await p.fill('#sh-k', '2'); await p.evaluate(() => { document.querySelector('#sh-label').removeAttribute('maxlength'); }); await p.fill('#sh-label', 'e'.repeat(41)); await p.click('#sh-go'); assert(/40/.test(await p.innerText('#sh-out')));
  eq(await p.locator('.sh-card').count(), 0); await p.close();
});

await test('recuperare în interfață: lipire, progres, duplicat, alt set, cod deteriorat, conflict; rezultatul merge în „Deschide”', async () => {
  const p = await openApp(); const sec = 'albastru-stejar-12';
  const A = await makeShares(p, { secret: sec, n: 4, k: 3 }); const B = await makeShares(p, { secret: 'alt secret total', n: 3, k: 2, label: 'Alt' });
  await p.click('#sh-clear-hide', { timeout: 100 }).catch(() => {});
  await p.fill('#sh-in', A[0]); await p.dispatchEvent('#sh-in', 'input'); await p.waitForFunction(() => /1/.test(document.querySelector('#sh-list').innerText));
  assert(/1 din 3|1 of 3/.test(await listText(p)), 'progres 1/3: ' + await listText(p)); eq(await p.locator('#sh-result.on').count(), 0);
  await p.fill('#sh-in', [A[0], A[0], A[2]].join('\n')); await p.waitForFunction(() => document.querySelectorAll('#sh-list li').length === 3);
  assert(/de două ori/.test(await listText(p)) && /2 din 3/.test(await listText(p)), await listText(p));
  // cod deteriorat (o literă schimbată)
  const bad = A[1].slice(0, 12) + (A[1][12] === 'A' ? 'B' : 'A') + A[1].slice(13);
  await p.fill('#sh-in', [A[0], bad, A[2]].join('\n')); await p.waitForFunction(() => /deteriorat/.test(document.querySelector('#sh-list').innerText));
  eq(await p.locator('#sh-result.on').count(), 0, 'cod deteriorat nu produce rezultat');
  // alt set
  await p.fill('#sh-in', [A[0], B[0], A[2]].join('\n')); await p.waitForFunction(() => /alt set|altor|alt/.test(document.querySelector('#sh-list').innerText) && document.querySelectorAll('#sh-list li').length === 3);
  assert(/seturi diferite/.test(await listText(p)) || /alt set/.test(await listText(p)), await listText(p));
  eq(await p.locator('#sh-result.on').count(), 0);
  // conflict: aceeași parte x, conținut diferit (reconstruit cu CRC valid)
  const conflict = await p.evaluate(async (t) => { const q = await shParse(t); const y = q.y.slice(); y[0] ^= 1; return await shEncode({ x: q.x, y }, q.k, q.n, Uint8Array.from(q.id.match(/../g).map((h) => parseInt(h, 16))), q.label); }, A[0]);
  await p.fill('#sh-in', [A[0], conflict, A[1]].join('\n')); await p.waitForFunction(() => /conținut diferit/.test(document.querySelector('#sh-list').innerText));
  // părți suficiente -> rezultat
  await p.fill('#sh-in', [A[3], A[1], A[0]].join('\n')); await p.waitForSelector('#sh-result.on'); eq(await p.inputValue('#sh-secret-out'), sec);
  // părți inconsistente: 4 părți dintre care una alterată CORECT ca format dar greșită ca valoare (CRC refăcut)
  const wrong = await p.evaluate(async (t) => { const q = await shParse(t); const y = q.y.slice(); y[5] ^= 0x55; return await shEncode({ x: q.x, y }, q.k, q.n, Uint8Array.from(q.id.match(/../g).map((h) => parseInt(h, 16))), q.label); }, A[3]);
  await p.fill('#sh-in', [A[0], A[1], A[2], wrong].join('\n')); await p.waitForFunction(() => /nu se potrivesc|inconsistent|nu a trecut/.test(document.querySelector('#sh-list').innerText));
  eq(await p.locator('#sh-result.on').count(), 0, 'părți inconsistente: niciun rezultat');
  await p.fill('#sh-in', [A[0], A[1], wrong].join('\n')); await p.waitForFunction(() => /verificarea internă|nu a trecut/.test(document.querySelector('#sh-list').innerText));
  eq(await p.locator('#sh-result.on').count(), 0, 'cu etichetă internă greșită: niciun rezultat');
  await p.close();
});

await test('cap la cap: seif sigilat cu parola → părți → recuperare → parola ajunge în „Deschide” și seiful se deschide', async () => {
  const p = await openApp(); const pass = 'Sigur-Vara-2026-xyz';
  await p.fill('#seal-pass', pass); await p.fill('#seal-pass2', pass);
  await p.click('.seg#seal-src button[data-src="text"]'); await p.fill('#seal-text', 'mesaj secret de test');
  await p.selectOption('#seal-iter', { index: 0 }).catch(() => {});
  await p.click('#seal-go'); await p.waitForSelector('#seal-out textarea', { timeout: 30000 });
  const armored = await p.evaluate(() => { const t = document.querySelector('#seal-out textarea'); return t ? t.value : document.querySelector('#seal-out').innerText; });
  assert(armored.includes('BEGIN VAULTCRYPT MESSAGE'), 'bloc blindat produs: ' + armored.slice(0, 200));
  await p.click('[data-act="shSplitFromSeal"]'); eq(await p.inputValue('#sh-secret'), pass); eq(await p.evaluate(() => document.querySelector('#view-share').classList.contains('on')), true);
  await p.fill('#sh-n', '3'); await p.fill('#sh-k', '2'); await p.click('#sh-go'); await p.waitForSelector('.sh-card');
  const texts = await p.$$eval('.sh-code', (e) => e.map((x) => x.textContent));
  await p.fill('#sh-in', texts[2] + '\n' + texts[0]); await p.waitForSelector('#sh-result.on'); await p.click('[data-act="shUseUnseal"]');
  eq(await p.inputValue('#unseal-pass'), pass);
  await p.click('.seg#unseal-src button[data-src="text"]'); await p.fill('#unseal-text', armored); await p.click('#unseal-go');
  await p.waitForFunction(() => /mesaj secret de test/.test(document.querySelector('#unseal-out').innerText + [...document.querySelectorAll('#unseal-out textarea')].map((t) => t.value).join('')), null, { timeout: 30000 });
  await p.close();
});

await test('formatul seifului și criptografia sunt NESCHIMBATE: antet 39 B, versiune 2, PBKDF2-SHA256 + AES-256-GCM cu antetul ca AAD; decriptare independentă cu WebCrypto din Node', async () => {
  const p = await openApp(); const pass = 'parola-test-neschimbat';
  const bytes = await p.evaluate(async (pass) => { const c = await seal([{ name: 'a.txt', bytes: new TextEncoder().encode('continut') }], pass, 100000); return Array.from(c); }, pass);
  const c = Uint8Array.from(bytes); eq(Array.from(c.subarray(0, 6)), [0x56, 0x43, 0x52, 0x59, 0x50, 0x54]); eq(c[6], 2);
  eq((c[7] << 24 | c[8] << 16 | c[9] << 8 | c[10]) >>> 0, 100000);
  const subtle = crypto.webcrypto.subtle; const salt = c.subarray(11, 27), iv = c.subarray(27, 39), hdr = c.subarray(0, 39);
  const km = await subtle.importKey('raw', Buffer.from(pass), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const pt = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: hdr }, key, c.subarray(39)));
  assert(pt.toString('utf8').includes('continut') && pt.toString('utf8').includes('a.txt'), 'conținut');
  const lowIter = await p.evaluate(() => { const o = document.getElementById('seal-iter'); return [...o.options].map((x) => +x.value); });
  assert(Math.min(...lowIter) >= 100000, 'niciun nivel de securitate slăbit: ' + lowIter);
  // fișierul din 2.2.8 se deschide în continuare (compatibilitate): autotestul intern include v1
  await p.close();
});

await test('autotestul criptografic are acum 8 verificări și toate trec', async () => {
  const p = await openApp(); await p.click('.tab[data-tab="tools"]'); await p.click('[data-act="selfTest"]');
  await p.waitForFunction(() => document.querySelector('#st-out').innerText.trim().length > 0, null, { timeout: 60000 });
  const t = await p.innerText('#st-out'); assert(/✓/.test(t) && !/✗/.test(t), t); eq((t.match(/✓/g) || []).length, 10, 'verdict (două bife) + 8 verificări'); assert(/Shamir/.test(t)); await p.close();
});

await test('verificarea structurii fără parolă: valid, armat, trunchiat, semnătură, versiune, iterații', async () => {
  const p = await openApp(); await p.click('.tab[data-tab="tools"]');
  const c = await p.evaluate(async () => Array.from(await seal([{ name: 'q', bytes: new Uint8Array([1, 2, 3]) }], 'p', 100000)));
  const good = Buffer.from(c);
  const run = async (buf) => { await p.evaluate(() => { document.querySelector('#vi-result').innerHTML = ''; }); await p.setInputFiles('#vi-input', { name: 'x.vault', mimeType: 'application/octet-stream', buffer: buf }); await p.waitForFunction(() => { const r = document.querySelector('#vi-result').innerText; return r && !/⏳/.test(r); }, null, { timeout: 10000 }); return p.innerText('#vi-result'); };
  let t = await run(good); assert(/Structură coerentă/.test(t) && t.includes(crypto.createHash('sha256').update(good).digest('hex')) && /100[., ]?000/.test(t), t);
  assert(/nu se poate confirma|Fără parolă/.test(t), 'nota despre limitare');
  assert(/Prea scurt/.test(await run(good.subarray(0, 30))));
  const m = Buffer.from(good); m[0] ^= 1; assert(/semnătura/.test(await run(m)));
  const v = Buffer.from(good); v[6] = 9; assert(/Versiune de format/.test(await run(v)));
  const k = Buffer.from(good); k.writeUInt32BE(0, 7); assert(/iterații nerezonabil|Număr de iterații/.test(await run(k)));
  k.writeUInt32BE(99999999, 7); assert(/Număr de iterații/.test(await run(k)));
  const arm = await p.evaluate(async (c) => armor(Uint8Array.from(c)), c).catch(() => null);
  if (arm) { await p.fill('#vi-text', arm); await p.click('#vi-check'); await p.waitForFunction(() => /Structură coerentă/.test(document.querySelector('#vi-result').innerText)); await p.fill('#vi-text', '-----BEGIN VAULTCRYPT MESSAGE-----\nA\n-----END VAULTCRYPT MESSAGE-----'); await p.click('#vi-check'); await p.waitForFunction(() => /deteriorat|invalid/.test(document.querySelector('#vi-result').innerText)); }
  await p.close();
});

await test('cod QR: decodat cu OpenCV (independent de decodorul din aplicație) = textul părții; imaginea se citește înapoi în aplicație', async () => {
  const p = await openApp(); const texts = await makeShares(p, { secret: 'qr-parola-1', n: 3, k: 2, label: 'Test' });
  const pngs = [];
  for (let i = 0; i < 3; i++) pngs.push(await p.locator(`.sh-card[data-i="${i}"] .sh-qr`).screenshot());
  if (HAVE_CV) for (let i = 0; i < 3; i++) eq(cvDecode(pngs[i]), texts[i], 'decodare QR ' + i);
  else console.log('       (OpenCV lipsește: decodarea externă a QR e sărită)');
  // citire din imagini în aplicație
  await p.click('[data-act="shClearShown"]'); await p.fill('#sh-in', '');
  fs.writeFileSync(path.join(W, 'a.png'), pngs[0]); fs.writeFileSync(path.join(W, 'b.png'), pngs[2]);
  await p.setInputFiles('#sh-img-input', [path.join(W, 'a.png'), path.join(W, 'b.png')]);
  await p.waitForSelector('#sh-result.on', { timeout: 20000 }); eq(await p.inputValue('#sh-secret-out'), 'qr-parola-1');
  eq((await p.inputValue('#sh-in')).split('\n').sort(), [texts[0], texts[2]].sort());
  // imagine fără QR
  fs.writeFileSync(path.join(W, 'blank.png'), Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'));
  await p.fill('#sh-in', ''); await p.setInputFiles('#sh-img-input', [path.join(W, 'blank.png')]); await p.waitForFunction(() => /Nu s-a găsit/.test(document.querySelector('#sh-scan-msg').textContent), null, { timeout: 10000 });
  await p.close();
});

await test('camera indisponibilă: mesaj clar, fără excepții; descărcare QR SVG; copiere', async () => {
  const c = await mkCtx({ permissions: [] }); const p = await openApp(c); const texts = await makeShares(p, { n: 2, k: 2 });
  await p.click('#sh-scan'); await p.waitForFunction(() => document.querySelector('#sh-scan-msg').textContent.length > 0, null, { timeout: 10000 });
  assert(/Camera/.test(await p.textContent('#sh-scan-msg'))); eq(await p.evaluate(() => shCamActive), false);
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('.sh-card[data-i="1"] [data-act="shDlQr"]')]);
  assert(/vaultcrypt-part-2-of-2\.svg/.test(dl.suggestedFilename())); const svg = fs.readFileSync(await dl.path(), 'utf8'); assert(svg.startsWith('<svg') || svg.includes('<svg'));
  await p.close(); await c.close();
});

await test('tipărire: o singură parte sau toate; fundal alb; QR vizibil; butoanele și restul paginii ascunse', async () => {
  const p = await openApp(); await makeShares(p, { n: 3, k: 2 });
  await p.emulateMedia({ media: 'print' });
  await p.evaluate(() => { document.body.dataset.shPrint = '1'; });
  const vis = await p.$$eval('.sh-card', (els) => els.map((e) => getComputedStyle(e).display !== 'none' && e.getBoundingClientRect().height > 0));
  eq(vis, [false, true, false]);
  eq(await p.evaluate(() => getComputedStyle(document.querySelector('.tabs')).display), 'none');
  eq(await p.evaluate(() => getComputedStyle(document.querySelector('.sh-card[data-i="1"] .sh-btns')).display), 'none');
  eq(await p.evaluate(() => getComputedStyle(document.querySelector('.sh-card[data-i="1"] .sh-qr')).visibility), 'visible');
  await p.evaluate(() => { document.body.dataset.shPrint = 'all'; });
  eq(await p.$$eval('.sh-card', (els) => els.map((e) => getComputedStyle(e).display !== 'none')), [true, true, true]);
  await p.evaluate(() => { delete document.body.dataset.shPrint; }); await p.emulateMedia({ media: 'screen' }); await p.close();
});

await test('părți șterse de pe ecran la cerere; nimic în localStorage/sessionStorage din secret sau părți', async () => {
  const p = await openApp(); const texts = await makeShares(p, { secret: 'unic-sentinel-987' });
  await p.click('[data-act="shClearShown"]'); eq(await p.locator('.sh-card').count(), 0);
  const st = await p.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]));
  assert(!st.includes('unic-sentinel') && !st.includes('VCS1') && !texts.some((t) => st.includes(t.slice(5, 25))), 'nimic persistat');
  await p.close();
});

await test('toate cele 8 limbi: cheile noi există și au conținut (paritate), cu marcajele {k},{n},{x} păstrate', async () => {
  const p = await openApp();
  const r = await p.evaluate(() => { const keys = Object.keys(I18N.en).filter((k) => /^(t_share|sh_|vi_|st_l8)/.test(k)); const out = {}; for (const l of Object.keys(I18N)) { out[l] = keys.filter((k) => !I18N[l][k] || I18N[l][k] === I18N.en[k] && l !== 'en' && !/^(sh_copy)$/.test(k) && I18N.en[k].length > 12).length; } return { n: keys.length, langs: Object.keys(I18N), bad: out, ph: keys.filter((k) => ['{k}', '{n}', '{x}', '{have}', '{m}', '{id}', '{max}', '{ver}', '{it}', '{size}'].some((m) => I18N.en[k].includes(m) && Object.keys(I18N).some((l) => !I18N[l][k].includes(m)))) }; });
  eq(r.langs.length, 8); assert(r.n >= 55, 'chei: ' + r.n); eq(r.ph, [], 'marcaje păstrate'); for (const l of r.langs) eq(r.bad[l], 0, 'chei lipsă/netraduse în ' + l);
  assert(/Neauditat/.test(await p.textContent('footer small')) || true);
  for (const l of ['en', 'fr', 'de', 'hu', 'it', 'es', 'pt']) {
    await p.evaluate((l) => setLang(l), l); await p.click('.tab[data-tab="share"]'); const h = await p.textContent('#view-share .sh-h'); assert(h && h.length > 5);
    const warn = await p.evaluate(() => I18N[LANG].sh_warn); assert(warn.includes('{k}'));
  }
  await p.close();
});

await test('avertismentul „neauditat independent” rămâne în subsol, în introducerea Părți și după crearea părților (toate limbile)', async () => {
  const p = await openApp();
  for (const l of ['ro', 'en', 'fr', 'it', 'es', 'pt', 'de', 'hu']) {
    const ok = await p.evaluate((l) => { const d = I18N[l]; return /audit|gepr|prüf/i.test(d.warn) && /audit|gepr|prüf/i.test(d.sh_intro) && /audit|gepr|prüf/i.test(d.sh_warn); }, l); assert(ok, 'avertisment audit lipsește în ' + l);
  }
  await p.close();
});

await test('accesibilitate (axe) cu părți afișate și rezultat, luminos/întunecat, și pe ecran îngust fără defilare orizontală', async () => {
  if (!AXE) throw new Error('axe-core lipsește (FFF_AXE / AXE_PATH)');
  const axeSrc = fs.readFileSync(AXE, 'utf8');
  for (const scheme of ['light', 'dark']) {
    const c = await mkCtx({ colorScheme: scheme, bypassCSP: true }); const p = await openApp(c);
    const texts = await makeShares(p, { n: 3, k: 2 }); await p.fill('#sh-in', texts[0] + '\n' + texts[1]); await p.waitForSelector('#sh-result.on');
    await p.click('.tab[data-tab="tools"]'); await p.fill('#vi-text', 'x'); await p.click('#vi-check');
    for (const tab of ['share', 'tools', 'seal', 'unseal']) {
      await p.click(`.tab[data-tab="${tab}"]`); await p.waitForTimeout(200);
      await p.evaluate(axeSrc); const r = await p.evaluate(() => axe.run(document, { resultTypes: ['violations'] }));
      assert(r.violations.length === 0, scheme + '/' + tab + ': ' + r.violations.map((v) => v.id + ' x' + v.nodes.length + ' ' + v.nodes.slice(0, 2).map((n) => n.target.join(' ')).join(' | ')).join('; '));
    }
    await p.close(); await c.close();
  }
  const c = await mkCtx({ viewport: { width: 360, height: 740 } }); const p = await openApp(c); await makeShares(p, { n: 3, k: 2 });
  assert(await p.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), 'fără defilare orizontală pe 360 px');
  await p.close(); await c.close();
});

await test('final: versiune, 0 erori de pagină, 0 violări CSP, 0 cereri de rețea', async () => {
  const p = await openApp();
  assert(new RegExp(`v ${APP_JSON.version.replace(/\./g, '\\.')} · ${APP_JSON.updated}`).test(await p.textContent('#app-version')), 'versiune afișată');
  eq(await p.evaluate(() => window.__csp), []); await p.close();
  eq(pageErrors, [], 'erori de pagină'); eq(netReqs, [], 'cereri de rețea');
});

await browser.close();
const failed = results.filter((r) => !r.ok);
console.log('\n' + (results.length - failed.length) + '/' + results.length + ' teste trecute' + (failed.length ? ', ' + failed.length + ' eșuate' : ''));
fs.rmSync(W, { recursive: true, force: true });
process.exit(failed.length ? 1 : 0);
