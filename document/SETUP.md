# ⚙️ Setup Guide — PySec Auditor

Panduan ini membantu kamu menginstal dan menjalankan **PySec Auditor** di sistem kamu.

## 🧩 Persyaratan Sistem
- Python 3.9 atau lebih baru
- Koneksi internet
- Sistem operasi: Windows / Linux / macOS / Termux

## 🧰 Instalasi Langkah demi Langkah

### 1️⃣ Clone Repository
```bash
git clone https://github.com/otakukazzee/PySec-Auditor.git
cd pysec-auditor
```

### 2️⃣ Install Dependensi
```bash
pip install -r requirements.txt
```

### 3️⃣ Jalankan Tes Pertama
```bash
python run.py -u https://example.com
```

Jika berhasil, akan muncul output seperti ini:
```
[+] HTTP Header Security Check
[+] SSL/TLS Information
...
```

## 💡 Tips
- Gunakan `python3` jika `python` tidak dikenali.  
- Jika error SSL, pastikan sertifikat CA di sistem ter-update.  
- Untuk menampilkan bantuan:
  ```bash
  python run.py -h
  ```

## ✅ Selesai
Setelah instalasi selesai, lanjutkan ke [PLAYBOOK.md](PLAYBOOK.md) untuk panduan menjalankan audit dan menyimpan laporan.
