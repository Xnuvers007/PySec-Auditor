# 🛡️ PySec Auditor
### Advanced HTTP & TLS Security Auditing Tool (Open Source Edition)
Developed by **Sardidev** | MIT License

## 📖 Deskripsi
**PySec Auditor** adalah alat analisis keamanan web berbasis Python yang dapat memeriksa:
- Konfigurasi **HTTP Header**
- Validasi **CORS**
- Keamanan **Cookie**
- Informasi **SSL/TLS Certificate**

Dirancang untuk digunakan oleh **developer**, **pentester**, dan **security researcher** guna meningkatkan keamanan aplikasi web secara cepat dan efisien.

## ✨ Fitur
✅ Analisis otomatis:
- Header Keamanan: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, dll  
- Validasi CORS  
- Keamanan Cookie (`Secure`, `HttpOnly`)  
- Inspeksi SSL/TLS  
- Deteksi cipher lemah

✅ Output Laporan:
- Format CLI (Rich)
- Format JSON / HTML

✅ Teknologi:
- Python 3.9+
- Library: `requests`, `rich`, `pyfiglet`

## ⚙️ Instalasi
Lihat document [SETUP.md] untuk panduan instalasi lengkap.

## 🚀 Cara Penggunaan
Lihat document [PLAYBOOK.md] untuk panduan penggunaan dan contoh hasil laporan.

## 🧩 Argumen CLI
| Argumen | Deskripsi | Default |
|----------|------------|----------|
| `-u`, `--url` | URL target audit | Wajib |
| `-t`, `--timeout` | Waktu tunggu (detik) | 5 |
| `-o`, `--output` | File laporan (JSON/HTML) | Opsional |

## 🪪 Lisensi
MIT License  
Copyright (c) 2025 **Sardidev**

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so.

## ⚠️ Disclaimer
Gunakan hanya untuk tujuan **legal** dan **edukatif**.  
Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
