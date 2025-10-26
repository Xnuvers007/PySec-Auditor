# 🚀 Playbook — PySec Auditor

Panduan penggunaan praktis untuk melakukan audit web security menggunakan **PySec Auditor**.

## 📘 1. Audit Dasar
```bash
python pysec_auditor.py -u https://example.com
```

## ⚙️ 2. Audit dengan Timeout
```bash
python pysec_auditor.py -u https://example.com -t 10
```

## 💾 3. Simpan Laporan ke File JSON
```bash
python pysec_auditor.py -u https://example.com -o hasil_audit.json
```

Contoh isi file JSON:
```json
{
  "target": "https://example.com",
  "headers": {"X-Frame-Options": "Missing"},
  "ssl": {"issuer": "Let's Encrypt", "protocol": "TLSv1.3"}
}
```

## 📄 4. Simpan Laporan ke File HTML
```bash
python pysec_auditor.py -u https://example.com -o laporan.html
```

## 🧩 5. Bantuan CLI
```bash
python pysec_auditor.py -h
```

## 🎯 6. Best Practice Audit
```bash
python pysec_auditor.py -u https://targetsite.com -t 10 -o audit_target.json
```

## 🧠 Tips Keamanan
- Audit domain kamu sendiri atau situs dengan izin eksplisit.  
- Gunakan `-o` untuk menyimpan hasil agar bisa dianalisis kembali.  
- Jalankan secara periodik untuk memantau perubahan konfigurasi keamanan.

## 🔚 Penutup
**PySec Auditor** adalah alat open-source yang dirancang untuk edukasi dan peningkatan keamanan aplikasi web.

> Developed with ❤️ by **Sardidev**
