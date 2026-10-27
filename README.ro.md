# VaultCrypt

[English](README.md) · **Română** · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [Português](README.pt.md) · [Deutsch](README.de.md) · [Magyar](README.hu.md)

**Versiune:** 3.1.0 · **Ultima actualizare:** 2026-10-27

**Stare:** experimental · **Offline:** complet

Limbile interfeței: **Română, English, Français, Italiano, Español, Português (PT), Deutsch, Magyar**

**Live / demo:** https://chiuta.github.io/VaultCrypt/

![VaultCrypt — captură de ecran / screenshot](screenshot.ro.png)

Criptare/decriptare de fișiere și text în browser, într-un singur `index.html` (8 limbi), plus generator de parole și sume de control.

## Cum funcționează (din cod)
- Cheie derivată din parolă cu PBKDF2-HMAC-SHA-256 (600.000 / 1.000.000 iterații; implicit „High” = 600.000; ultimul nivel folosit la sigilare este reținut local în `localStorage`, cheia `vaultcrypt.sec`), sare aleatoare de 16 octeți.
- Criptare AES-256-GCM (Web Crypto) cu IV aleator de 12 octeți; antetul containerului (39 octeți) este autentificat ca date adiționale.
- Format `.vault` (magic `VCRYPT`, versiune 1/2, și 3 pentru nivelurile opționale Argon2id) sau bloc „armurat” text pentru mesaje.
- Parolele generate folosesc `crypto.getRandomValues`. Sume de control: SHA-256/384/512 și SHA-1 (SHA-1 este slab; doar pentru verificarea integrității fișierelor, nu pentru securitate).

## Seif cu secrete partajate (3.0.0)
- Fila **Părți** împarte parola seifului (sau orice secret scurt, până la 1024 de octeți) în n părți, oricare k reconstruiesc secretul (schema Shamir peste GF(2^8), coeficienți aleatori din `crypto.getRandomValues`); fiecare parte se afișează ca text `VCS1:…` și cod QR, se poate tipări (una pe pagină), descărca (SVG) și citi înapoi cu camera sau din imagini. Se verifică imediat că recombinarea reproduce exact secretul.
- Formatul `.vault` și criptarea (PBKDF2-SHA-256 + AES-256-GCM, WebCrypto) sunt neschimbate: se împarte doar parola. În **Instrumente**, „Verificare structură seif” citește antetul fără parolă (nu poate confirma conținutul: asta o face doar deschiderea cu parola).

## Detalii criptografice și formatul fișierului (citite din cod, 3.1.0)

> **Neauditat independent.** Schema de mai jos este documentată exact așa cum o implementează codul actual. Este o descriere, nu o garanție de securitate, și nu a fost revizuită de un criptograf extern.

**Derivarea cheii (KDF)**
- Algoritm implicit: **PBKDF2** cu HMAC-SHA-256 (`deriveKey` din Web Crypto); containerele v1/v2 sunt neschimbate. Din 3.1.0 există și un nivel **opțional Argon2id** (vezi mai jos); scrypt nu este folosit.
- Iterații: **600.000** („High”, implicit) sau **1.000.000** („Paranoid”). Numărul este scris în antetul containerului; la deschidere se acceptă valori de la 1 la 10.000.000 (altfel se refuză, ca un antet fabricat să nu blocheze browserul). Containere mai vechi pot avea numere mai mici (ex. 310.000) și se deschid în continuare.
- Sare: 16 octeți aleatori (`crypto.getRandomValues`), nouă la fiecare container.
- Parola: octeții UTF-8 ai textului exact cum a fost tastat, **fără normalizare Unicode** (copia de siguranță `.fff.json`, o funcție separată, normalizează în NFC). Minimum 4 caractere; sub 12 aplicația avertizează și cere „Sigilează oricum”.
- Cheia derivată: AES-256, neexportabilă.

**Criptare**
- **AES-256-GCM** (Web Crypto), IV aleator de 12 octeți, etichetă de autentificare de 128 de biți (valoarea implicită Web Crypto; codul nu setează `tagLength`).
- Date adiționale autentificate (AAD): tot antetul necriptat de 39 de octeți; schimbarea iterațiilor, a sării sau a IV-ului face decriptarea să eșueze.
- Parola greșită și un fișier deteriorat sau modificat dau același eșec GCM; aplicația nu le poate deosebi.

**Structura containerului `.vault` (versiunea 2; aceiași octeți se folosesc în blocul text „armurat”)**

| Octeți | Conținut |
|---|---|
| 0-5 | semnătura `VCRYPT` (`56 43 52 59 50 54`) |
| 6 | versiune (`2`; containerele versiunii `1` se citesc în continuare) |
| 7-10 | iterații PBKDF2, întreg fără semn pe 32 de biți, big-endian |
| 11-26 | sare, 16 octeți |
| 27-38 | IV, 12 octeți |
| 39+ | text criptat AES-GCM urmat de eticheta de 16 octeți |

Conținutul înainte de criptare (v2): `număr de fișiere` (uint16 BE), apoi pentru fiecare fișier `lungime nume` (uint16 BE), `nume` (UTF-8), `lungime date` (uint32 BE), `date`. Limite în format: 65.535 de fișiere, 65.535 de octeți per nume, sub 4 GiB per fișier; aplicația se oprește la circa 400 MB per operație. Versiunea 1: un singur fișier, `lungime nume` (uint16 BE) + `nume` + date. Pentru un mesaj text, singura intrare are numele gol.

**Bloc text „armurat”**: `-----BEGIN VAULTCRYPT MESSAGE-----`, containerul în Base64 împărțit la 64 de caractere, `-----END VAULTCRYPT MESSAGE-----`.

**Ce nu ascunde containerul**: dimensiunea (lungimea textului criptat arată lungimea originală; nu există umplutură), numărul de iterații și faptul că este un container VaultCrypt (octeții de semnătură). Numele fișierelor și numărul lor sunt în partea criptată. Nu există compresie, fișier-cheie sau recuperare.

**Părți de recuperare (Shamir, fila „Părți”)**: împart doar parola (sau alt secret scurt, până la 1024 de octeți); nu schimbă formatul containerului. Shamir (k, n) peste GF(2^8) cu polinomul AES 0x11B, coeficienți aleatori din `crypto.getRandomValues`, n până la 16, x = 1..n. Secretul este completat până la multiplu de 64 de octeți și o etichetă de verificare de 4 octeți (SHA-256 din `"VCS1"` plus partea completată) este împărțită împreună cu el. Textul unei părți: `VCS1:` + grupe Base32 (și ca cod QR), cu un CRC care detectează doar greșelile de tastare. Părțile **nu sunt criptate**: cine are k dintre ele poate reface secretul.

**Copia de siguranță criptată a datelor aplicației (`.fff.json`, fff-kit)**: PBKDF2-HMAC-SHA-256 cu 600.000 de iterații (la import se acceptă 100.000 – 5.000.000), sare de 16 octeți, AES-256-GCM cu IV de 12 octeți, AAD `fff-bundle-enc|1|<slug aplicație>`, parola normalizată NFC, minimum 12 caractere. Plic JSON: `format`, `schema`, `app`, `kdf`, `iter`, `salt`, `iv`, `ct` (Base64).

**Argon2id opțional (3.1.0, `.vault` versiunea 3, nouă)**
- Se alege în „Nivel de securitate”: *Argon2id - 64 MiB, 3 treceri* sau *256 MiB, 3 treceri* (paralelism 1). Argon2id cere multă memorie, deci e mai lent și are nevoie de RAM; rulează în JavaScript (măsurat în sandbox-ul nostru: aprox. 3 s pentru 64 MiB în Node și aprox. 10 s în Chromium fără interfață; telefoanele reale nu au fost testate și pot fi mai lente, iar 256 MiB poate eșua pe dispozitive cu puțină memorie).
- Cheia = Argon2id (RFC 9106, versiunea 0x13, fără secret/date asociate) aplicat parolei UTF-8 și sării de 16 octeți, ieșire de 32 de octeți, folosită direct drept cheie AES-256-GCM. Implicit rămâne PBKDF2.
- Antetul **versiunii 3 = 44 de octeți**: octeții 0-38 ca la versiunea 2, cu octetul 6 = `3` și octeții 7-10 = numărul de treceri *t*; octeții 39-42 = memoria în KiB (uint32 BE); octetul 43 = paralelismul *p*. AAD = tot antetul de 44 de octeți; textul cifrat + eticheta de 16 octeți încep la octetul 44. La deschidere, limitele se verifică înainte de orice derivare: *t* 1-20, *p* 1-16, memorie de la 8p KiB la 1 GiB (un antet creat special nu poate cere mai mult).
- Compatibilitate: containerele v1/v2 (PBKDF2) se deschid în continuare și sunt produse în continuare de nivelurile PBKDF2; **copiile mai vechi ale aplicației nu pot deschide v3** (refuză versiunea necunoscută).
- Implementare: Argon2id + BLAKE2b proprii, compacte, în același fișier (fără bibliotecă). Verificate prin `tests/argon2.test.mjs`: vectorii oficiali RFC 9106 (Argon2d, Argon2i, Argon2id), BLAKE2b față de implementarea din Node și exemplul din RFC 7693, implementarea de referință argon2-cffi (Python, dacă e instalată) pentru p = 1 și 2, un container v1/v2 construit independent cu `node:crypto` care se deschide, un container v3 construit independent (cheia din argon2-cffi, AES-GCM din `node:crypto`) care se deschide, și antete alterate/absurde refuzate. **Este un rezultat de test, nu un audit**: implementarea nu a fost revizuită independent și nu a fost testată pentru canale laterale (JavaScript nu oferă garanții de timp constant).

**Planificat / nefăcut**: audit de securitate independent (necesită un expert extern). Argon2id este implementat ca opțiune (3.1.0); nu este implicit.

## Avertismente
- **Neauditat independent.** Cod scris de un singur autor, fără audit de securitate extern; nu-l folosi ca unică protecție pentru date critice.
- **Parolă pierdută = date pierdute**, cu excepția cazului în care ai creat din timp părți de recuperare (vezi mai jos). Păstrează copii de siguranță și parola într-un loc sigur.
- **Părțile de recuperare (Shamir) nu sunt auditate independent.** Cere un audit independent înainte să te bazezi pe ele pentru date critice. Părțile nu sunt criptate: cine adună k părți poate reconstrui parola.
- Parola rămâne în memoria browserului pe durata sesiunii; un dispozitiv compromis (malware, extensii) anulează protecția.

## Date și confidențialitate
Nicio cerere de rețea: pagina are CSP cu `connect-src 'self'`, iar `fetch`/`XMLHttpRequest`/`sendBeacon` sunt blocate în cod (jurnal „Privacy audit” în pagină). Fără telemetrie, fără fonturi sau scripturi externe. Verificat la audit: 0 cereri externe la încărcare. Singurele legături externe sunt cele din subsol și fereastra „Despre” (se deschid doar la click).

## Limitări
Fișierele sunt citite integral în memorie (de câteva ori, în timpul criptării): limită practică 400 MB per operație (testat: 380 MB ok, ≈860 MB blochează fila). Pentru fișiere mai mari folosește o unealtă desktop.

CSP nu mai permite `'unsafe-inline'` pentru scripturi: scriptul unic din pagină este autorizat prin hash SHA-256 în meta CSP (după orice modificare a scriptului hash-ul trebuie recalculat), iar handlerele inline au fost înlocuite cu delegare de evenimente. Stilurile inline rămân permise. Fișierele mari sunt procesate integral în memorie.

## Licență
MIT, conform antetului din `index.html`; vezi `LICENSE`.

Audit: 2026-10-10

## Istoric / Changelog

### 2.2.5 — 2026-10-22
- fff-kit 1.1.4: ținte tactile și text minim; ținte tactile/text corectate

### 2.2.4 — 2026-10-22
- fff-kit 1.1.2: PBKDF2 600 000 de iterații, protecție anti-clickjacking.

### 2.2.3 — 2026-10-22
- Securitate: parolele sub 12 caractere nu mai sunt acceptate în tăcere: aplicația afișează un avertisment (tradus în cele 8 limbi) și cere confirmarea explicită „Sigilează oricum”. Minimul absolut rămâne 4 caractere.

### 2.2.2 — 2026-10-22
- eticheta de accesibilitate a selectorului de limbă și termenul „additional authenticated data” (AAD) din secțiunea Despre sunt acum traduse în toate limbile.

### 2.2.1 — 2026-10-22
- Titlul, meta tag-urile, avertismentul de securitate din subsol și aria-label-urile urmează acum limba interfeței; descrierea din panoul fff-kit este localizată.

### 2.1.0 — 2026-10-14
- Copie de rezervă și etichetare date (fff-kit).

### 12 octombrie 2026 (v2.0.4)
- 2.0.4 — 2026-10-12: versiunea și data ultimei actualizări sunt afișate în aplicație

### 11 octombrie 2026 (v2.0.3)
- Fișiere mari: testat pe bune (Chromium, offline) — 120 MB și 380 MB se sigilează și se desigilează identic (≈5 s fiecare la 310.000 iterații), dar la ≈860 MB fila se blochează la descărcare. De aceea, de la 150 MB apare o notă „date mari” în timpul operației, iar peste 400 MB aplicația refuză cu un mesaj clar (în loc să blocheze fila); erorile de memorie primesc mesaj propriu, în cele 6 limbi. Limita se aplică și la desigilare.
- Versiune v2.0.3 în subsol.

### 11 octombrie 2026 (v2.0.2)
- Indicator live „parolele coincid / nu coincid încă” sub câmpul de confirmare (`role=status`) și avertisment Caps Lock la câmpurile de parolă, în cele 6 limbi; Ctrl/Cmd+Enter pentru acțiune exista deja. Testat offline cu CSP activ: 0 erori, axe 0.

### 11 octombrie 2026 (v2.0.1)
- Un bloc armurat modificat/trunchiat (base64 invalid, dar cu markerii prezenți) afișează acum un mesaj de integritate separat („deteriorat sau incomplet”), în cele 6 limbi, în loc de „bloc armurat valid negăsit”; o modificare care păstrează base64 valid continuă să dea „parolă greșită sau container alterat”.
- CSP: eliminat `'unsafe-inline'` din `script-src` (hash SHA-256 pentru scriptul unic); cele 26 de handlere inline sunt înlocuite cu delegare de evenimente; testat cu CSP activ.
- Conținutul este încadrat în `<main>` (axe: 0 încălcări); nivelul implicit „High” documentat explicit (memorarea ultimului nivel explică un eventual „Balanced” la redeschidere).
- Versiune v2.0.2 în subsol.
