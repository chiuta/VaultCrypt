// Teste Playwright (interfață) pentru revizuirea criptografică 2026-10-28 (Claude, AI) — NU sunt un audit independent.
// Rulare: PW_ROOT=/calea/node_modules/ CHROMIUM_PATH=/calea/chrome node tests/cripto-ui.mjs   (VC_INDEX=… pentru alt index.html)
// Acoperă: o singură derivare de cheie la Ctrl+Enter repetat (seal/unseal), parola slabă confirmată nu rămâne în memorie,
// niciun secret în localStorage/sessionStorage/cookie/IndexedDB/Cache, fișiere malformate prin interfață (fără blocaj/erori de pagină).
import { createRequire } from 'module';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_FILE = process.env.VC_INDEX || path.resolve(HERE, '../index.html');
const APP = 'https://vaultcrypt.test/index.html';
let chromium;
try { chromium = createRequire(process.env.PW_ROOT || import.meta.url)('playwright').chromium; } catch { console.log('omis: Playwright indisponibil (PW_ROOT)'); process.exit(0); }
const results = []; let current = '';
async function test(name, fn) { current = name; const t0 = Date.now(); try { await fn(); results.push({ name, ok: true }); console.log('  ok   ' + name + ' (' + (Date.now() - t0) + ' ms)'); } catch (e) { results.push({ name, ok: false }); console.log('  FAIL ' + name + '\n       ' + String(e.message || e).split('\n').join('\n       ')); } }
const assert = (c, m) => { if (!c) throw new Error(m || 'assertion failed'); };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error((m || 'not equal') + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)); };
const fx = JSON.parse(fs.readFileSync(path.resolve(HERE, 'fixtures-compat.json'), 'utf8'));
const mkV = (pl, pass = 'pw-test-ui') => { const iter = 1000, salt = crypto.randomBytes(16), iv = crypto.randomBytes(12), h = Buffer.alloc(39); Buffer.from('VCRYPT').copy(h, 0); h[6] = 2; h.writeUInt32BE(iter, 7); salt.copy(h, 11); iv.copy(h, 27); const c = crypto.createCipheriv('aes-256-gcm', crypto.pbkdf2Sync(pass, salt, iter, 32, 'sha256'), iv); c.setAAD(h); return Buffer.concat([h, c.update(Buffer.from(pl)), c.final(), c.getAuthTag()]); };

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--no-sandbox'] });
const netReqs = [], pageErrors = [];
const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 }, acceptDownloads: true, serviceWorkers: 'block' });
await ctx.route(/^https?:/, (r) => { const u = r.request().url(); if (u.startsWith(APP)) return r.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: fs.readFileSync(APP_FILE) });
  const m = /^https:\/\/vaultcrypt\.test\/(manifest\.webmanifest|icon-192\.png|icon-512\.png|icon-maskable-512\.png)$/.exec(u); const fp = m && path.resolve(HERE, '..', m[1]);
  if (fp && fs.existsSync(fp)) return r.fulfill({ status: 200, contentType: m[1].endsWith('png') ? 'image/png' : 'application/manifest+json', body: fs.readFileSync(fp) });
  netReqs.push(u); r.abort(); });
await ctx.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI)); });
async function openApp() { const p = await ctx.newPage(); p.on('pageerror', (e) => pageErrors.push(current + ': ' + e.message)); await p.goto(APP); await p.waitForFunction(() => typeof doSeal === 'function'); return p; }
const SLOW = 700; /* întârzie seal()/unseal() ca să existe o fereastră în care a doua apăsare e posibilă */
const countCalls = (p) => p.evaluate((d) => { window.__calls = { seal: 0, unseal: 0 }; const s = window.seal, u = window.unseal; window.seal = async (...a) => { window.__calls.seal++; await new Promise((r) => setTimeout(r, d)); return s(...a); }; window.unseal = async (...a) => { window.__calls.unseal++; await new Promise((r) => setTimeout(r, d)); return u(...a); }; }, SLOW);

await test('Ctrl+Enter repetat în timpul sigilării pornește o singură derivare', async () => {
  const p = await openApp(); await countCalls(p);
  await p.click('.tab[data-tab="seal"]'); await p.click('[data-src="text"]'); await p.fill('#seal-text', 'salut');
  await p.fill('#seal-pass', 'parola-foarte-lunga-1'); await p.fill('#seal-pass2', 'parola-foarte-lunga-1');
  await p.click('#seal-go'); await p.keyboard.press('Control+Enter'); await p.keyboard.press('Control+Enter'); await p.keyboard.press('Control+Enter');
  await p.waitForSelector('#seal-out textarea', { timeout: 30000 }); await p.waitForTimeout(1500);
  eq(await p.evaluate(() => window.__calls.seal), 1, 'apeluri seal()'); assert(!(await p.isDisabled('#seal-go')), 'butonul reactivat la final'); await p.close();
});

await test('Ctrl+Enter repetat în timpul deschiderii pornește o singură derivare; după final se poate relua', async () => {
  const p = await openApp(); await countCalls(p); const f = fx.items[0];
  await p.click('.tab[data-tab="unseal"]'); await p.click('#view-unseal [data-src="text"]'); await p.fill('#unseal-text', f.armored); await p.fill('#unseal-pass', f.pass);
  await p.click('#unseal-go'); await p.keyboard.press('Control+Enter'); await p.keyboard.press('Control+Enter');
  await p.waitForSelector('#unseal-out textarea', { timeout: 30000 }); await p.waitForTimeout(1500);
  eq(await p.evaluate(() => window.__calls.unseal), 1, 'apeluri unseal()'); eq(await p.inputValue('#unseal-out textarea'), f.expect[0].text);
  await p.keyboard.press('Control+Enter'); await p.waitForTimeout(2500); eq(await p.evaluate(() => window.__calls.unseal), 2, 'o a doua deschidere, după final, e permisă'); await p.close();
});

await test('parola slabă confirmată („Sigilează oricum”) funcționează, dar nu rămâne reținută în memorie', async () => {
  const p = await openApp(); await p.click('.tab[data-tab="seal"]'); await p.click('[data-src="text"]'); await p.fill('#seal-text', 'x');
  await p.fill('#seal-pass', 'abcd'); await p.fill('#seal-pass2', 'abcd'); await p.click('#seal-go');
  await p.waitForSelector('#seal-out button'); assert(!(await p.isVisible('#seal-out textarea')), 'încă nu s-a sigilat fără confirmare');
  await p.click('#seal-out button'); await p.waitForSelector('#seal-out textarea', { timeout: 30000 });
  eq(await p.evaluate(() => weakAckPass), null, 'weakAckPass trebuie golit'); 
  await p.click('#seal-go'); await p.waitForSelector('#seal-out button'); assert(!(await p.isVisible('#seal-out textarea')), 'a doua sigilare cu aceeași parolă slabă cere din nou confirmarea');
  await p.close();
});

await test('nicio parolă/text în clar în localStorage, sessionStorage, cookie, IndexedDB sau Cache după sigilare și deschidere', async () => {
  const p = await openApp(); const PW = 'Parola-Unica-ZXQ-7731-ț', PT = 'TEXT-IN-CLAR-UNIC-QQ-4412';
  await p.click('.tab[data-tab="seal"]'); await p.click('[data-src="text"]'); await p.fill('#seal-text', PT); await p.fill('#seal-pass', PW); await p.fill('#seal-pass2', PW);
  await p.click('#seal-go'); await p.waitForSelector('#seal-out textarea', { timeout: 30000 }); const arm = await p.inputValue('#seal-out textarea');
  await p.click('.tab[data-tab="unseal"]'); await p.click('#view-unseal [data-src="text"]'); await p.fill('#unseal-text', arm); await p.fill('#unseal-pass', PW); await p.click('#unseal-go'); await p.waitForSelector('#unseal-out textarea', { timeout: 30000 });
  await p.click('.tab[data-tab="share"]'); await p.fill('#sh-secret', PW); await p.fill('#sh-n', '3'); await p.fill('#sh-k', '2'); await p.click('#sh-go'); await p.waitForSelector('.sh-card');
  const dump = await p.evaluate(async () => { const o = { ls: {}, ss: {}, cookie: document.cookie, idb: [], caches: [] }; for (let i = 0; i < localStorage.length; i++) o.ls[localStorage.key(i)] = localStorage.getItem(localStorage.key(i)); for (let i = 0; i < sessionStorage.length; i++) o.ss[sessionStorage.key(i)] = sessionStorage.getItem(sessionStorage.key(i)); try { o.idb = (await indexedDB.databases()).map((d) => d.name); } catch (e) {} try { o.caches = await caches.keys(); } catch (e) {} return o; });
  const s = JSON.stringify(dump); assert(!s.includes(PW) && !s.includes(PT) && !s.includes(arm.slice(40, 80)), 'secret găsit în stocare: ' + s.slice(0, 300));
  assert(Object.keys(dump.ls).every((k) => /^(vaultcrypt\.|fff\.vaultcrypt\.)/.test(k)), 'chei neașteptate: ' + Object.keys(dump.ls)); await p.close();
});

await test('fișiere malformate prin interfață: eroare clară, fără blocaj, butonul rămâne utilizabil, fără erori de pagină', async () => {
  const nm = [...Buffer.from('x.txt')];
  const cases = {
    'autentic dar trunchiat (count=65535)': mkV([255, 255]),
    'autentic, lungime de date peste capăt': mkV([0, 1, 0, nm.length, ...nm, 255, 255, 255, 255, 1]),
    'magic corect, rest gunoi': Buffer.concat([Buffer.from('VCRYPT'), Buffer.from([2, 0, 0, 3, 232]), crypto.randomBytes(80)]),
    'iterații 0xFFFFFFFF': Buffer.concat([Buffer.from('VCRYPT'), Buffer.from([2, 255, 255, 255, 255]), crypto.randomBytes(80)]),
    'v3 cu m uriaș': Buffer.concat([Buffer.from('VCRYPT'), Buffer.from([3, 0, 0, 0, 3]), crypto.randomBytes(32), Buffer.from([0x7f, 255, 255, 255, 1]), crypto.randomBytes(40)]),
    'doar magic': Buffer.from('VCRYPT'), 'nu e seif': Buffer.from('salut lume'),
  };
  const p = await openApp(); await p.click('.tab[data-tab="unseal"]');
  for (const [n, buf] of Object.entries(cases)) {
    await p.setInputFiles('#unseal-file-input', { name: 'm.vault', mimeType: 'application/octet-stream', buffer: buf }); await p.fill('#unseal-pass', 'pw-test-ui');
    await p.click('#unseal-go'); await p.waitForSelector('#unseal-out .status.bad', { timeout: 20000 });
    assert(!(await p.isDisabled('#unseal-go')), 'buton blocat după: ' + n); assert((await p.locator('#unseal-out .filechip').count()) === 0, 'fișiere fantomă afișate: ' + n); await p.fill('#unseal-pass', '');
  }
  await p.close();
});

await test('fișiere 3.1.0 (v2 și v3) se deschid prin interfață și textul se afișează corect', async () => {
  const p = await openApp(); await p.click('.tab[data-tab="unseal"]');
  for (const f of fx.items.filter((x) => x.armored)) {
    await p.click('#view-unseal [data-src="text"]'); await p.fill('#unseal-text', f.armored); await p.fill('#unseal-pass', f.pass); await p.click('#unseal-go');
    await p.waitForSelector('#unseal-out textarea', { timeout: 40000 }); eq(await p.inputValue('#unseal-out textarea'), f.expect[0].text, f.label);
  }
  const m = fx.items.find((x) => !x.armored && x.expect.length === 2);
  await p.click('#view-unseal [data-src="file"]'); await p.setInputFiles('#unseal-file-input', { name: 'b.vault', mimeType: 'application/octet-stream', buffer: Buffer.from(m.b64, 'base64') }); await p.fill('#unseal-pass', m.pass); await p.click('#unseal-go');
  await p.waitForSelector('#unseal-out .filechip', { timeout: 40000 }); eq(await p.locator('#unseal-out .filechip .nm').allTextContents(), m.expect.map((e) => e.name)); await p.close();
});

await test('final: 0 erori de pagină, 0 violări CSP, 0 cereri de rețea', async () => {
  const p = await openApp(); eq(await p.evaluate(() => window.__csp), []); await p.close();
  eq(pageErrors, [], 'erori de pagină'); eq(netReqs, [], 'cereri de rețea');
});

await browser.close();
const failed = results.filter((r) => !r.ok);
console.log('\n' + (results.length - failed.length) + '/' + results.length + ' teste trecute' + (failed.length ? ', ' + failed.length + ' eșuate' : ''));
process.exit(failed.length ? 1 : 0);
