# Jurnal de modificări — VaultCrypt

## 3.0.1 — 2026-10-27 (anterior: 3.0.0)
Doar texte și documentare; schema criptografică NU s-a schimbat.
- README (EN, RO): secțiune nouă „Detalii criptografice și formatul fișierului”, citită din cod: PBKDF2-HMAC-SHA-256 (600.000 / 1.000.000 iterații, sare 16 octeți), AES-256-GCM (IV 12 octeți, etichetă 128 biți, AAD = antet de 39 octeți), structura `.vault` v1/v2, blocul „armurat”, ce nu ascunde containerul, părțile Shamir, copia `.fff.json`.
- Avertisment „neauditat independent” afișat vizibil sub antetul aplicației (textul tradus exista deja în cele 8 limbi; era doar în subsol).
- „Stare: experimental” și „Offline: complet” în toate cele 8 README.
- Planificat / nefăcut: audit independent (necesită expert extern), opțiune Argon2 (ar schimba formatul).

## 3.0.0 — 2026-10-26
- Seif cu secrete partajate (Shamir k din n, coduri QR).
