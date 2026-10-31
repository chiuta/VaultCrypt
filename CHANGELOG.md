# Jurnal de modificări — VaultCrypt

## 3.1.2 — 2026-10-31

Doar interfață (accesibilitate pe telefon, 360×740): caseta „seal-wipe” 13 → 24 px; versiunea din subsol aliniată. Fără alte schimbări de comportament.

## 3.1.1 — 2026-10-28 (anterior: 3.1.0)
Revizuire de cod criptografică făcută de Claude (AI), la cerere: **NU este audit independent** și nu înlocuiește unul. Raport: `docs/REVIZUIRE-CRIPTO.md`. Formatul `.vault` și derivarea cheii NU s-au schimbat; fișierele create cu 3.0.1/3.1.0 se deschid (verificat cu containere generate din interfața 3.1.0, `tests/fixtures-compat.json`).
- Corectat: `parsePayload` accepta conținut autentic dar malformat (trunchiat, lungimi peste capăt, până la 65.535 de intrări fantomă) și raporta succes; acum orice citire în afara limitelor dă eroare. Containerele create de aplicație au payload exact și nu sunt afectate.
- Corectat: Ctrl+Enter în timpul sigilării/deschiderii pornea derivări de cheie simultane (fiecare Argon2id poate aloca 64/256 MiB); acum se ignoră cât timp o operație rulează.
- Corectat: parola slabă confirmată cu „Sigilează oricum” rămânea într-o variabilă globală (`weakAckPass`) pe toată sesiunea; confirmarea se consumă acum la prima folosire.
- Teste noi: `tests/cripto.test.mjs` (52 de verificări: compatibilitate 3.1.0, alterarea antetului/versiunii/ciphertextului, antete absurde, conținut malformat, unicitate sare/IV, decriptare independentă v2/v3, armură, caracterizarea parolei) și `tests/cripto-ui.mjs` (7 teste în browser). Fiecare corecție are un test care eșuează pe 3.1.0 și trece pe 3.1.1.
- `tests/shares.mjs`: două verificări depășite de 3.1.0 au fost actualizate (nivelurile Argon2id nu sunt numere de iterații; cheia i18n `vi_ok_a2` există doar în en/ro). Aplicația nu era afectată.
- Constatări rămase ca recomandări (nu s-au modificat, cer decizie sau schimbă comportamentul): indicatorul de forță a parolei supraestimează parole previzibile; parola nu e normalizată Unicode (ș/ş, NFC/NFD); limite și anulare la deschiderea cu parametri KDF mari; ștergerea/clipboard-ul; vezi raportul.
- Neverificabil aici: timp constant/canale auxiliare în JavaScript, memoria browserului, telefoane reale, lanțul de livrare. Auditul independent (expert extern) rămâne planificat.

## 3.1.0 — 2026-10-27 (anterior: 3.0.1)
- NOU, opțional și retrocompatibil: niveluri **Argon2id** (64 MiB / 256 MiB, 3 treceri) la sigilare, într-un format nou `.vault` versiunea 3 (antet de 44 de octeți: t, m, p). PBKDF2 rămâne implicit; containerele v1/v2 se deschid neschimbat. Schema existentă (PBKDF2 + AES-256-GCM, antet de 39 de octeți) NU s-a modificat.
- Implementare proprie (Argon2id + BLAKE2b, fără bibliotecă). Teste noi `tests/argon2.test.mjs`: vectorii oficiali RFC 9106 (d/i/id), BLAKE2b față de Node, argon2-cffi ca referință independentă, containere v1/v2 construite independent și deschise, container v3 construit independent și deschis, antete alterate/absurde refuzate. Rezultat de test, nu audit.
- Limite la deschiderea v3 (t ≤ 20, p ≤ 16, m ≤ 1 GiB), verificate înainte de derivare. Verificarea de structură (Instrumente) recunoaște v3.
- Texte noi (RO, EN): niveluri, notă de durată, specificația din fereastra „Despre”, README. Celelalte 6 limbi: etichetele noi cad pe engleză (netraduse).
- Rămâne planificat: audit independent (expert extern). Netestat pe telefoane reale (timp/memorie la Argon2id).

## 3.0.1 — 2026-10-27 (anterior: 3.0.0)
Doar texte și documentare; schema criptografică NU s-a schimbat.
- README (EN, RO): secțiune nouă „Detalii criptografice și formatul fișierului”, citită din cod: PBKDF2-HMAC-SHA-256 (600.000 / 1.000.000 iterații, sare 16 octeți), AES-256-GCM (IV 12 octeți, etichetă 128 biți, AAD = antet de 39 octeți), structura `.vault` v1/v2, blocul „armurat”, ce nu ascunde containerul, părțile Shamir, copia `.fff.json`.
- Avertisment „neauditat independent” afișat vizibil sub antetul aplicației (textul tradus exista deja în cele 8 limbi; era doar în subsol).
- „Stare: experimental” și „Offline: complet” în toate cele 8 README.
- Planificat / nefăcut: audit independent (necesită expert extern), opțiune Argon2 (ar schimba formatul).

## 3.0.0 — 2026-10-26
- Seif cu secrete partajate (Shamir k din n, coduri QR).
