# VaultCrypt

Criptare/decriptare de fișiere și text în browser, într-un singur `index.html` (6 limbi), plus generator de parole și sume de control.

## Cum funcționează (din cod)
- Cheie derivată din parolă cu PBKDF2-HMAC-SHA-256 (310.000 / 600.000 / 1.000.000 iterații; implicit 600.000), sare aleatoare de 16 octeți.
- Criptare AES-256-GCM (Web Crypto) cu IV aleator de 12 octeți; antetul containerului (39 octeți) este autentificat ca date adiționale.
- Format `.vault` (magic `VCRYPT`, versiune 1/2) sau bloc „armurat” text pentru mesaje.
- Parolele generate folosesc `crypto.getRandomValues`. Sume de control: SHA-256/384/512 și SHA-1 (SHA-1 este slab; doar pentru verificarea integrității fișierelor, nu pentru securitate).

## Avertismente
- **Neauditat independent.** Cod scris de un singur autor, fără audit de securitate extern; nu-l folosi ca unică protecție pentru date critice.
- **Parolă pierdută = date pierdute.** Nu există recuperare. Păstrează copii de siguranță și parola într-un loc sigur.
- Parola rămâne în memoria browserului pe durata sesiunii; un dispozitiv compromis (malware, extensii) anulează protecția.

## Date și confidențialitate
Nicio cerere de rețea: pagina are CSP cu `connect-src 'self'`, iar `fetch`/`XMLHttpRequest`/`sendBeacon` sunt blocate în cod (jurnal „Privacy audit” în pagină). Fără telemetrie, fără fonturi sau scripturi externe. Verificat la audit: 0 cereri externe la încărcare. Singurele legături externe sunt cele din subsol și fereastra „Despre” (se deschid doar la click).

## Limitări
CSP permite scripturi inline (`'unsafe-inline'`), necesare unui fișier unic. Fișierele mari sunt procesate integral în memorie.

## Licență
CC0 1.0 (domeniu public), conform antetului din `index.html`; vezi `LICENSE`.

Audit: 2026-10-10
