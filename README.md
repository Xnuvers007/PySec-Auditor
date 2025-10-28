# PySec Auditor 🔐

PySec Auditor adalah toolkit audit keamanan HTTP & TLS yang dibuat untuk tujuan defensif dan edukasi.  
Project ini open-source dengan lisensi **MIT**. Developed by Sardidev. ❤️

## Fitur utama
- Audit header keamanan (HSTS, CSP, X-Frame-Options, dll)
- Analisis atribut cookie (Secure, HttpOnly, SameSite)
- Pemeriksaan CORS dasar
- Deteksi eksposur file/direktori sensitif (.git, .env, robots.txt)
- Tes dasar Path Traversal di parameter query
- Informasi sertifikat TLS dan audit cipher suites
- Ekspor hasil ke JSON/HTML

## Cara menjalankan
1. Install dependensi (lihat `document/setup.md`)
2. Jalankan: `python run.py -u example.com -o report.json -l id`

## Struktur proyek
```
PySec_Auditor/
├── run.py
├── src/
└── document/
```

## Lisensi
MIT — Developed by Sardidev. 

[![pytest](https://img.shields.io/badge/test-pytest-brightgreen)](https://docs.pytest.org/)

## Recommendations ✅
- Run this tool only on assets you own or have explicit permission to audit.
- Use in a controlled environment for education and defensive testing.
- Integrate CI (the provided GitHub Actions) to run tests on PRs.
- Consider adding runtime sanitization for untrusted input and rate-limiting for scanning loops.
- For production usage, add logging, retries/backoff, and configuration file support.
