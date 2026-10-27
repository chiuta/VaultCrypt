# Jurnal de modificări — VaultCrypt

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
