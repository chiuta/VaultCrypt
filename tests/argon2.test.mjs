// Teste pentru Argon2id/BLAKE2b din VaultCrypt 3.1 — fără browser: extrage blocul dintre marcatori din index.html.
// Rulare: node tests/argon2.test.mjs
// Vectori: RFC 9106 §5.1–5.3 (Argon2d, Argon2i, Argon2id; p=4, m=32, t=3, secret și date asociate); BLAKE2b comparat cu Node (crypto 'blake2b512').
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.resolve(HERE, '../index.html'), 'utf8');
const a = html.indexOf('/*ARGON2-BEGIN*/'), b = html.indexOf('/*ARGON2-END*/');
if (a < 0 || b < 0) throw new Error('markerii ARGON2 lipsesc din index.html');
const Argon2 = new Function(html.slice(a, b) + '\nreturn Argon2;')();
const hex = u => Buffer.from(u).toString('hex');
let fail = 0;
const ok = (name, cond, extra) => { console.log((cond ? '  ok   ' : '  FAIL ') + name + (cond ? '' : '  ' + (extra || ''))); if (!cond) fail++; };
const rep = (n, len) => new Uint8Array(len).fill(n);

// BLAKE2b-512 / -256 vs Node, lungimi de la limita blocului (0, 1, 127, 128, 129, 255, 256, 1000)
for (const n of [0, 1, 3, 127, 128, 129, 255, 256, 1000]) {
  const d = crypto.randomBytes(n);
  ok('BLAKE2b-512 n=' + n, hex(Argon2.blake2b(d, 64)) === crypto.createHash('blake2b512').update(d).digest('hex'));
}
ok('BLAKE2b-256("") valoare cunoscută', hex(Argon2.blake2b(new Uint8Array(0), 32)) === '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
// BLAKE2b-512("abc") din RFC 7693 apendix A
ok('BLAKE2b-512("abc") RFC 7693', hex(Argon2.blake2b(new TextEncoder().encode('abc'), 64)) === 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');

// RFC 9106 §5: aceiași parametri pentru cele trei variante
const base = { pass: rep(1, 32), salt: rep(2, 16), secret: rep(3, 8), ad: rep(4, 12), t: 3, m: 32, p: 4, len: 32, noYield: true };
const vec = {
  0: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
  1: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
  2: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
};
for (const type of [2, 0, 1]) {
  const t0 = Date.now();
  const out = await Argon2.hash({ ...base, type });
  ok('RFC 9106 Argon2' + 'dii'[type] + (type === 2 ? 'd' : '') + ' (' + (Date.now() - t0) + ' ms)', hex(out) === vec[type], hex(out));
}

// Referință independentă opțională: argon2-cffi (Python) dacă e instalat — aceleași intrări, m=1024, t=2, p=1 și p=2
import { execFileSync } from 'node:child_process';
let py = null;
try { py = execFileSync('python3', ['-I', '-c', 'import argon2.low_level as l,sys\nfor p in (1,2):\n print(l.hash_secret_raw(b"parola de test",b"sare-de-16-octeti",time_cost=2,memory_cost=1024,parallelism=p,hash_len=32,type=l.Type.ID).hex())'], { encoding: 'utf8' }).trim().split('\n'); } catch { py = null; }
if (!py) console.log('  omis  referința argon2-cffi (Python) nu e instalată');
else for (const [i, p] of [1, 2].entries()) {
  const out = await Argon2.hash({ pass: new TextEncoder().encode('parola de test'), salt: new TextEncoder().encode('sare-de-16-octeti'), t: 2, m: 1024, p, len: 32, noYield: true });
  ok('argon2-cffi (referință) p=' + p, hex(out) === py[i], hex(out) + ' != ' + py[i]);
}

// Parametri nevalidi
let threw = false; try { await Argon2.hash({ ...base, m: 4 }); } catch { threw = true; }
ok('parametri nevalizi respinși', threw);

// Deriv. deterministă și sensibilă la fiecare intrare
const x = await Argon2.hash({ ...base, secret: undefined, ad: undefined, m: 64, p: 1, noYield: true });
const y = await Argon2.hash({ ...base, secret: undefined, ad: undefined, m: 64, p: 1, noYield: true });
const z = await Argon2.hash({ ...base, secret: undefined, ad: undefined, m: 64, p: 1, salt: rep(9, 16), noYield: true });
ok('determinism + sensibilitate la sare', hex(x) === hex(y) && hex(x) !== hex(z));

// ---- Container: v1/v2 (PBKDF2, neschimbat) și v3 (Argon2id) — funcțiile reale din index.html ----
{
  const c0 = html.indexOf('const MAGIC = '), c1 = html.indexOf('/* ---------- 4. Armor');
    const core = html.slice(c0, c1);
  const api = new Function('window', 'crypto', 'const subtle = crypto.subtle;' + core + '\nreturn {seal,unseal,A2_PRESETS};')({ crypto: globalThis.crypto }, globalThis.crypto, Argon2);
  const items = [{ name: 'a.txt', bytes: new TextEncoder().encode('salut') }, { name: 'b.bin', bytes: new Uint8Array([1, 2, 3]) }];
  // v2 construit independent cu node:crypto (PBKDF2 + AES-GCM), deschis cu unseal
  const mk = (ver, iter, pass) => {
    const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
    const h = Buffer.alloc(39); Buffer.from('VCRYPT').copy(h, 0); h[6] = ver; h.writeUInt32BE(iter, 7); salt.copy(h, 11); iv.copy(h, 27);
    const key = crypto.pbkdf2Sync(pass, salt, iter, 32, 'sha256');
    const nm = Buffer.from('x.txt'), data = Buffer.from('vechi');
    const pl = ver === 1 ? Buffer.concat([Buffer.from([0, nm.length]), nm, data]) : Buffer.concat([Buffer.from([0, 1, 0, nm.length]), nm, Buffer.from([0, 0, 0, data.length]), data]);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(h);
    const ct = Buffer.concat([c.update(pl), c.final(), c.getAuthTag()]);
    return new Uint8Array(Buffer.concat([h, ct]));
  };
  for (const ver of [1, 2]) {
    const r = await api.unseal(mk(ver, 1000, 'parola veche'), 'parola veche');
    ok('retrocompatibil: container v' + ver + ' (PBKDF2) se deschide', r.ver === ver && r.entries.length === 1 && r.entries[0].name === 'x.txt' && Buffer.from(r.entries[0].data).toString() === 'vechi');
  }
  const sealedOld = await api.seal(items, 'parola-de-test', 1000);
  ok('seal() fără a2 produce tot v2 cu antet de 39 octeți', sealedOld[6] === 2 && sealedOld.length > 39);
  // v3: roundtrip (m redus pentru viteză; valoarea e citită din antet)
  const a2 = { m: 1024, t: 2, p: 1 };
  const s3 = await api.seal(items, 'parola-de-test', 2, a2);
  ok('v3: antet 44 octeți (ver=3, t, m, p)', s3[6] === 3 && Buffer.from(s3).readUInt32BE(7) === 2 && Buffer.from(s3).readUInt32BE(39) === 1024 && s3[43] === 1);
  const r3 = await api.unseal(s3, 'parola-de-test');
  ok('v3: dus-întors (2 fișiere)', r3.ver === 3 && r3.kdf === 'argon2id' && r3.entries.length === 2 && Buffer.from(r3.entries[0].data).toString() === 'salut');
  let code = ''; try { await api.unseal(s3, 'parola-gresita'); } catch (e) { code = e.code; }
  ok('v3: parolă greșită => AUTH', code === 'AUTH');
  const t1 = s3.slice(); t1[20] ^= 1; code = ''; try { await api.unseal(t1, 'parola-de-test'); } catch (e) { code = e.code; }
  ok('v3: antet alterat (sare) => AUTH', code === 'AUTH');
  const t2 = s3.slice(); t2[40] ^= 1; t2[41] ^= 1; code = ''; try { await api.unseal(t2, 'parola-de-test'); } catch (e) { code = e.code; }
  ok('v3: m alterat => AUTH sau BAD (nu reușește)', code === 'AUTH' || code === 'BAD');
  const bad = (f) => { const x = s3.slice(); f(x); return x; };
  for (const [nm, x] of [['m uriaș (>1 GiB)', bad(x => { x[39] = 0x7f; })], ['p=0', bad(x => { x[43] = 0; })], ['p=200', bad(x => { x[43] = 200; })], ['t=0', bad(x => { x[7] = x[8] = x[9] = x[10] = 0; })], ['t=99', bad(x => { x[10] = 99; })], ['trunchiat', s3.slice(0, 50)]]) {
    code = ''; try { await api.unseal(x, 'parola-de-test'); } catch (e) { code = e.code; }
    ok('v3: parametri respinși înainte de derivare: ' + nm, code === 'BAD');
  }
  if (py) {
    // v3 construit independent: cheia din argon2-cffi (Python), AES-GCM din node:crypto
    const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
    const keyHex = execFileSync('python3', ['-I', '-c', 'import argon2.low_level as l,sys\nprint(l.hash_secret_raw("parola externa".encode(),bytes.fromhex(sys.argv[1]),time_cost=2,memory_cost=1024,parallelism=1,hash_len=32,type=l.Type.ID).hex())', salt.toString('hex')], { encoding: 'utf8' }).trim();
    const h = Buffer.alloc(44); Buffer.from('VCRYPT').copy(h, 0); h[6] = 3; h.writeUInt32BE(2, 7); salt.copy(h, 11); iv.copy(h, 27); h.writeUInt32BE(1024, 39); h[43] = 1;
    const nm = Buffer.from('e.txt'), data = Buffer.from('extern');
    const pl = Buffer.concat([Buffer.from([0, 1, 0, nm.length]), nm, Buffer.from([0, 0, 0, data.length]), data]);
    const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv); c.setAAD(h);
    const ext = new Uint8Array(Buffer.concat([h, c.update(pl), c.final(), c.getAuthTag()]));
    const re = await api.unseal(ext, 'parola externa');
    ok('v3 construit independent (argon2-cffi + node:crypto) se deschide', re.entries[0].name === 'e.txt' && Buffer.from(re.entries[0].data).toString() === 'extern');
  }
}
console.log(fail ? '\n' + fail + ' EȘECURI' : '\nToate testele Argon2 au trecut.');
process.exit(fail ? 1 : 0);
