// Teste criptografice (fără browser) pentru VaultCrypt: revizuirea de cod 2026-10-28 (Claude, AI). NU sunt un audit independent.
// Rulare: node tests/cripto.test.mjs        (VC_INDEX=cale/index.html pentru a testa o altă versiune a fișierului)
// Acoperă: compatibilitate cu fișiere create de 3.1.0 (tests/fixtures-compat.json, generate din interfața 3.1.0 înainte de corecții),
// alterarea antetului/etichetei/ciphertextului, parsarea defensivă a conținutului autentic dar malformat, antete absurde,
// unicitatea sării și a IV-ului, decriptare independentă (node:crypto), armura, caracterizarea parolei (fără normalizare Unicode).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(process.env.VC_INDEX || path.resolve(HERE, '../index.html'), 'utf8');
const c0 = html.indexOf('const MAGIC = '), c1 = html.indexOf('/* ---------- 6. UI state');
if (c0 < 0 || c1 < 0) throw new Error('blocurile de cod nu au fost găsite în index.html');
const api = new Function('window', 'crypto', 'const subtle = crypto.subtle;' + html.slice(c0, c1) +
  '\nreturn {seal,unseal,dearmor,armor,parsePayload,zipSafeName,A2_PRESETS,A2_MAX_M,A2_MAX_T,A2_MAX_P};')({ crypto: globalThis.crypto }, globalThis.crypto);
let fail = 0, total = 0;
const ok = (name, cond, extra) => { total++; console.log((cond ? '  ok   ' : '  FAIL ') + name + (cond ? '' : '  ' + (extra || ''))); if (!cond) fail++; };
const code = async (f) => { try { await f(); return 'OK'; } catch (e) { return e.code || ('EXC:' + e.message); } };
const txt = (u) => Buffer.from(u).toString('utf8');
const items = [{ name: 'a.txt', bytes: new TextEncoder().encode('salut') }, { name: 'b.bin', bytes: new Uint8Array([1, 2, 3, 0, 255]) }];

/* ---- 1. compatibilitate: fișiere create de VaultCrypt 3.1.0 (din interfață) se deschid ---- */
const fx = JSON.parse(fs.readFileSync(path.resolve(HERE, 'fixtures-compat.json'), 'utf8'));
for (const f of fx.items) {
  const bytes = f.armored ? api.dearmor(f.armored) : new Uint8Array(Buffer.from(f.b64, 'base64'));
  const r = await api.unseal(bytes, f.pass);
  const good = r.entries.length === f.expect.length && r.entries.every((e, i) => e.name === f.expect[i].name && txt(e.data) === f.expect[i].text);
  ok('compat 3.1.0: ' + f.label + ' (versiune ' + bytes[6] + ')', good && r.ver === bytes[6]);
  ok('compat 3.1.0: ' + f.label + ' — parolă greșită => AUTH', await code(() => api.unseal(bytes, f.pass + 'x')) === 'AUTH');
}

/* ---- 2. alterări: orice octet din antet, versiunea, tag-ul, trunchiere, adăugare => nu se deschide ---- */
const s2 = await api.seal(items, 'parola-de-test-1', 1000);
const s3 = await api.seal(items, 'parola-de-test-1', 2, { m: 1024, t: 2, p: 1 });
for (const [nm, c, hl] of [['v2', s2, 39], ['v3', s3, 44]]) {
  let opened = 0, bad = [];
  for (let i = 0; i < hl; i++) for (const bit of [0, 7]) { const x = c.slice(); x[i] ^= (1 << bit); if (await code(() => api.unseal(x, 'parola-de-test-1')) === 'OK') { opened++; bad.push(i + ':' + bit); } }
  ok(nm + ': alterarea oricărui bit (0 și 7) din oricare din cei ' + hl + ' octeți de antet => refuzat (AAD + derivare)', opened === 0, bad.join(','));
  const lenN = c.length; let o2 = 0;
  for (const i of [hl, hl + 1, lenN - 17, lenN - 16, lenN - 1]) { const x = c.slice(); x[i] ^= 1; if (await code(() => api.unseal(x, 'parola-de-test-1')) === 'OK') o2++; }
  ok(nm + ': alterare în ciphertext/etichetă GCM => AUTH', o2 === 0);
  ok(nm + ': trunchiere cu 1 octet => refuzat', await code(() => api.unseal(c.slice(0, lenN - 1), 'parola-de-test-1')) !== 'OK');
  const ext = new Uint8Array(lenN + 1); ext.set(c); ok(nm + ': un octet adăugat => refuzat', await code(() => api.unseal(ext, 'parola-de-test-1')) !== 'OK');
}
{ // protecție la „downgrade”: eticheta de versiune nu poate fi rescrisă fără ca fișierul să fie respins
  const rel = (c, v) => { const x = c.slice(); x[6] = v; return x; };
  const rs = [];
  for (const v of [1, 2, 3]) { if (v !== 2) rs.push(['v2->' + v, await code(() => api.unseal(rel(s2, v), 'parola-de-test-1'))]); if (v !== 3) rs.push(['v3->' + v, await code(() => api.unseal(rel(s3, v), 'parola-de-test-1'))]); }
  ok('rescrierea etichetei de versiune (v2->1/3, v3->1/2) => respins', rs.every(([, r]) => r !== 'OK'), JSON.stringify(rs));
  const swapIv = s2.slice(); const iv = s2.slice(27, 39); swapIv.set(iv.map((b) => b ^ 0xff), 27); ok('v2: IV schimbat => respins', await code(() => api.unseal(swapIv, 'parola-de-test-1')) !== 'OK');
}

/* ---- 3. antete absurde/malformate: respinse FĂRĂ derivare (rapid) ---- */
{
  const t0 = Date.now(); const rs = [];
  const mkh = (len, f) => { const x = new Uint8Array(len); x.set([0x56, 0x43, 0x52, 0x59, 0x50, 0x54], 0); f(x); return x; };
  const cases = {
    'gol': new Uint8Array(0), 'sub 39 B': new Uint8Array(38), 'magic greșit': mkh(80, (x) => { x[0] = 0x57; x[6] = 2; x[10] = 1; }),
    'versiune 0': mkh(80, (x) => { x[6] = 0; x[10] = 1; }), 'versiune 4': mkh(80, (x) => { x[6] = 4; x[10] = 1; }), 'versiune 255': mkh(80, (x) => { x[6] = 255; x[10] = 1; }),
    'v2 iterații 0': mkh(80, (x) => { x[6] = 2; }), 'v2 iterații 10000001': mkh(80, (x) => { x[6] = 2; x.set([0, 0x98, 0x96, 0x81], 7); }), 'v2 iterații 0xFFFFFFFF': mkh(80, (x) => { x[6] = 2; x.set([255, 255, 255, 255], 7); }),
    'v1 iterații 0xFFFFFFFF': mkh(80, (x) => { x[6] = 1; x.set([255, 255, 255, 255], 7); }),
    'v3 scurt (43 B)': mkh(43, (x) => { x[6] = 3; x[10] = 1; }), 'v3 fără ciphertext (44+15)': mkh(59, (x) => { x[6] = 3; x[10] = 1; x[42] = 8; x[43] = 1; }),
    'v3 m=0xFFFFFFFF': mkh(80, (x) => { x[6] = 3; x[10] = 1; x.set([255, 255, 255, 255], 39); x[43] = 1; }), 'v3 m=7 (<8p)': mkh(80, (x) => { x[6] = 3; x[10] = 1; x[42] = 7; x[43] = 1; }),
    'v3 p=17': mkh(80, (x) => { x[6] = 3; x[10] = 1; x[41] = 4; x[43] = 17; }), 'v3 t=21': mkh(80, (x) => { x[6] = 3; x[10] = 21; x[41] = 4; x[43] = 1; }),
  };
  for (const [n, x] of Object.entries(cases)) rs.push([n, await code(() => api.unseal(x, 'orice'))]);
  ok('antete malformate/absurde => cod BAD', rs.every(([, r]) => r === 'BAD'), JSON.stringify(rs.filter(([, r]) => r !== 'BAD')));
  ok('…și respinse fără derivare (< 3 s în total)', Date.now() - t0 < 3000, (Date.now() - t0) + ' ms');
}

/* ---- 4. conținut autentic dar malformat (producător defect/rău intenționat care cunoaște parola) ---- */
const mkV = (ver, pl, pass = 'pw-test') => { // container v1/v2 construit independent cu node:crypto
  const iter = 1000, salt = crypto.randomBytes(16), iv = crypto.randomBytes(12), h = Buffer.alloc(39);
  Buffer.from('VCRYPT').copy(h, 0); h[6] = ver; h.writeUInt32BE(iter, 7); salt.copy(h, 11); iv.copy(h, 27);
  const c = crypto.createCipheriv('aes-256-gcm', crypto.pbkdf2Sync(pass, salt, iter, 32, 'sha256'), iv); c.setAAD(h);
  return new Uint8Array(Buffer.concat([h, c.update(Buffer.from(pl)), c.final(), c.getAuthTag()]));
};
const be32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
for (const [nm, ver, pl] of [
  ['v2: plaintext gol', 2, []], ['v2: un octet', 2, [0]], ['v2: count=65535 fără date (65535 intrări fantomă)', 2, [255, 255]],
  ['v2: lungime nume peste capăt', 2, [0, 1, 255, 255, 65]], ['v2: lipsește câmpul de lungime date', 2, [0, 1, 0, 1, 65, 0, 0]],
  ['v2: lungime date 4 GiB-1 cu 3 octeți', 2, [0, 1, 0, 1, 65, 255, 255, 255, 255, 1, 2, 3]], ['v2: a doua intrare lipsește', 2, [0, 2, 0, 1, 65, 0, 0, 0, 0]],
  ['v1: plaintext gol', 1, []], ['v1: un octet', 1, [0]], ['v1: lungime nume peste capăt', 1, [255, 255, 65]],
]) ok('conținut malformat respins (nu trunchiere tăcută): ' + nm, await code(() => api.unseal(mkV(ver, pl), 'pw-test')) === 'BAD');
{
  const nm = [...Buffer.from('x.txt')], d = [...Buffer.from('vechi')];
  const r1 = await api.unseal(mkV(1, [0, nm.length, ...nm, ...d]), 'pw-test');
  ok('v1 valid (și cu date goale) se deschide', r1.entries[0].name === 'x.txt' && txt(r1.entries[0].data) === 'vechi' && (await api.unseal(mkV(1, [0, nm.length, ...nm]), 'pw-test')).entries[0].data.length === 0);
  const r2 = await api.unseal(mkV(2, [0, 2, 0, nm.length, ...nm, ...be32(d.length), ...d, 0, 0, 0, 0, 0, 0]), 'pw-test');
  ok('v2 valid: 2 intrări, a doua fără nume și fără date (tipic mesaj/gol)', r2.entries.length === 2 && r2.entries[1].name === '' && r2.entries[1].data.length === 0);
  ok('v2 cu zero intrări ([0,0]) rămâne acceptat (compatibil)', (await api.unseal(mkV(2, [0, 0]), 'pw-test')).entries.length === 0);
  ok('v2: octeți în plus după ultima intrare sunt tolerați (comportament păstrat)', (await api.unseal(mkV(2, [0, 1, 0, 1, 65, 0, 0, 0, 1, 9, 7, 7]), 'pw-test')).entries[0].data.length === 1);
}
{ // limite ale formatului la sigilare
  let r = await code(() => api.seal([{ name: 'x'.repeat(70000), bytes: new Uint8Array(1) }], 'p', 1000)); ok('nume > 65535 octeți refuzat la sigilare', r !== 'OK');
  const many = Array.from({ length: 65536 }, () => ({ name: '', bytes: new Uint8Array(0) })); r = await code(() => api.seal(many, 'p', 1000)); ok('> 65535 fișiere refuzat la sigilare', r !== 'OK');
  const big = [{ name: 'n.txt', bytes: crypto.randomBytes(1 << 20) }]; const rb = await api.unseal(await api.seal(big, 'p-lung-12345', 1000), 'p-lung-12345'); ok('1 MiB dus-întors identic', Buffer.compare(Buffer.from(rb.entries[0].data), big[0].bytes) === 0);
  const uni = [{ name: 'ăâîșț 🔐.txt', bytes: new TextEncoder().encode('ăâîșț 🔐') }]; const ru = await api.unseal(await api.seal(uni, 'p-lung-12345', 1000), 'p-lung-12345'); ok('nume și conținut Unicode dus-întors', ru.entries[0].name === uni[0].name && txt(ru.entries[0].data) === 'ăâîșț 🔐');
}

/* ---- 5. aleatoriu: sare și IV unice, ciphertext diferit la aceeași intrare ---- */
{
  const N = 60, salts = new Set(), ivs = new Set(), cts = new Set(); let zero = 0;
  for (let i = 0; i < N; i++) { const c = await api.seal(items, 'parola-de-test-1', 1000); salts.add(Buffer.from(c.slice(11, 27)).toString('hex')); ivs.add(Buffer.from(c.slice(27, 39)).toString('hex')); cts.add(Buffer.from(c.slice(39)).toString('hex')); if (!c.slice(11, 39).some((b) => b)) zero++; }
  ok('60 sigilări ale aceleiași intrări: 60 de sări, 60 de IV-uri și 60 de ciphertexturi distincte', salts.size === N && ivs.size === N && cts.size === N && zero === 0);
  const cnt = new Array(256).fill(0); for (const s of salts) for (const b of Buffer.from(s, 'hex')) cnt[b]++;
  ok('octeții sării acoperă o gamă largă (sanity, nu test statistic)', cnt.filter(Boolean).length > 150);
}

/* ---- 6. decriptare independentă (node:crypto) a ieșirii aplicației ---- */
{
  const pass = 'parolă independentă';
  const c = await api.seal(items, pass, 5000); const h = Buffer.from(c.slice(0, 39));
  const d = crypto.createDecipheriv('aes-256-gcm', crypto.pbkdf2Sync(pass, c.slice(11, 27), 5000, 32, 'sha256'), c.slice(27, 39)); d.setAAD(h); d.setAuthTag(Buffer.from(c.slice(c.length - 16)));
  const pt = Buffer.concat([d.update(Buffer.from(c.slice(39, c.length - 16))), d.final()]);
  ok('v2: PBKDF2-HMAC-SHA-256 + AES-256-GCM, AAD = antet 39 B, etichetă 16 B — decriptat independent', h[6] === 2 && h.readUInt32BE(7) === 5000 && pt.includes(Buffer.from('salut')) && pt.includes(Buffer.from('a.txt')));
  let py = false; try { execFileSync('python3', ['-I', '-c', 'import argon2.low_level']); py = true; } catch { /* fără argon2-cffi */ }
  const c3 = await api.seal(items, pass, 2, { m: 1024, t: 2, p: 1 });
  if (!py) console.log('  omis  referința argon2-cffi (Python) nu e instalată');
  else {
    const salt3 = Buffer.from(c3.slice(11, 27)).toString('hex');
    const key = Buffer.from(execFileSync('python3', ['-I', '-c', 'import argon2.low_level as l,sys\nprint(l.hash_secret_raw("parolă independentă".encode(),bytes.fromhex(sys.argv[1]),time_cost=2,memory_cost=1024,parallelism=1,hash_len=32,type=l.Type.ID).hex())', salt3]).toString().trim(), 'hex');
    const h3 = Buffer.from(c3.slice(0, 44)); const d3 = crypto.createDecipheriv('aes-256-gcm', key, c3.slice(27, 39)); d3.setAAD(h3); d3.setAuthTag(Buffer.from(c3.slice(c3.length - 16)));
    const pt3 = Buffer.concat([d3.update(Buffer.from(c3.slice(44, c3.length - 16))), d3.final()]);
    ok('v3: Argon2id (argon2-cffi) + AES-256-GCM, AAD = antet 44 B — decriptat independent', h3[6] === 3 && h3.readUInt32BE(39) === 1024 && pt3.includes(Buffer.from('salut')));
  }
}

/* ---- 7. armură ---- */
{
  const c = await api.seal(items, 'parola-de-test-1', 1000), a = api.armor(c);
  const same = (x, y) => Buffer.compare(Buffer.from(x), Buffer.from(y)) === 0;
  ok('armură: dus-întors, CRLF, spații în plus, text în jur', same(api.dearmor(a), c) && same(api.dearmor(a.replace(/\n/g, '\r\n')), c) && same(api.dearmor('Salut!\n\n' + a + '\n-- \nsemnătură'), c) && same(api.dearmor(a.replace(/\n/g, ' \n  ')), c));
  ok('armură: fără marcaje, doar base64 => acceptat', same(api.dearmor(a.split('\n').slice(1, -1).join('')), c));
  ok('armură: gol/gunoi => ARMOR', (await code(() => api.dearmor('!!! ???'))) === 'ARMOR' && (await code(() => api.dearmor(''))) === 'ARMOR');
  ok('armură: corp deteriorat (lungime 4k+1) => ARMORBAD', (await code(() => api.dearmor('-----BEGIN VAULTCRYPT MESSAGE-----\nQUJDR\n-----END VAULTCRYPT MESSAGE-----'))) === 'ARMORBAD');
  let crashed = 0; for (let i = 0; i < 300; i++) { const g = crypto.randomBytes(1 + crypto.randomInt(200)).toString(i % 2 ? 'latin1' : 'base64'); try { api.dearmor(g); } catch (e) { if (e.code !== 'ARMOR' && e.code !== 'ARMORBAD') crashed++; } }
  ok('armură: 300 de intrări aleatorii nu produc excepții neașteptate', crashed === 0);
  const trunc = a.slice(0, a.length - 60); ok('armură trunchiată (fără END) nu se deschide', (await code(async () => api.unseal(api.dearmor(trunc), 'parola-de-test-1'))) !== 'OK');
}

/* ---- 8. caracterizare: parola e codificată UTF-8 FĂRĂ normalizare Unicode (documentat în REVIZUIRE-CRIPTO.md; nu e o promisiune) ---- */
{
  const nfc = 'Parolă-ț-ș-2026'.normalize('NFC'), nfd = nfc.normalize('NFD'); const c = await api.seal(items, nfc, 1000);
  ok('caracterizare: parola NFC se deschide cu NFC', (await code(() => api.unseal(c, nfc))) === 'OK');
  ok('caracterizare: aceeași parolă în NFD NU deschide (nu se normalizează)', (await code(() => api.unseal(c, nfd))) === 'AUTH');
  ok('caracterizare: ș (U+0219, virgulă) ≠ ş (U+015F, sedilă) — alt fișier nu se deschide', (await code(() => api.unseal(c, nfc.replace('ș', 'ş')))) === 'AUTH');
}

/* ---- 9. numele din ZIP ---- */
ok('zipSafeName: ../, //, \\, . eliminate', api.zipSafeName('../../etc/passwd') === 'etc/passwd' && api.zipSafeName('a\\..\\b') === 'a/b' && api.zipSafeName('') === 'file' && api.zipSafeName('/abs/x') === 'abs/x');

console.log(fail ? '\n' + fail + ' EȘECURI din ' + total : '\nToate cele ' + total + ' verificări criptografice au trecut.');
process.exit(fail ? 1 : 0);
