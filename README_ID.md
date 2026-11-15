<div align="center">

# 🛡️ DNS Tunneling & Exfiltration Detector

**Framework Keamanan Python untuk Mendeteksi Saluran Tersembunyi (Covert Channel), Tunneling, dan Kebocoran Data (Data Exfiltration) pada Lalu Lintas DNS Menggunakan Analisis Entropi Shannon dan Heuristik Leksikal.**

[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependency](https://img.shields.io/badge/dependencies-zero%20required-success.svg)](requirements.txt)
[![Security](https://img.shields.io/badge/threat-DNS%20Covert%20Channels-red.svg)](#latar-belakang--ancaman)

[English Documentation](README.md) • [Dokumentasi Bahasa Indonesia](README_ID.md)

</div>

---

## 📌 Latar Belakang & Ancaman

Lalu lintas **DNS (Domain Name System)** port 53 UDP/TCP hampir selalu dibuka keluar (*egress*) oleh firewall perusahaan agar perangkat dapat menerjemahkan nama domain ke alamat IP. Celah ini sering dieksploitasi oleh aktor ancaman (APT, malware, ransomware, maupun framework C2 seperti **dnscat2**, **Iodine**, dan **Cobalt Strike**) untuk:

1. **Eksfiltrasi Data Rahasia:** Mengirimkan data sensitif (password, dokumen, file database) yang dipecah dan dienkripsi/dienkode (Base64/Base32/Hex) ke dalam subdomain kueri DNS.
2. **DNS Tunneling / Command & Control (C2):** Membangun jalur komunikasi dua arah dua arah (*covert channel*) melalui respons DNS TXT/NULL tanpa terdeteksi oleh Web Proxy atau firewall standar.

Tool ini dibuat untuk menganalisis log kueri DNS dan lalu lintas live dengan mengombinasikan **Entropi Shannon**, **Panjang Subdomain**, **Distribusi Karakter**, **Anomali Tipe Kueri**, dan **Kardinalitas Apex Domain**.

> **💡 Zero Dependency:** Dapat langsung dijalankan menggunakan pustaka standar Python 3.8+ tanpa wajib menginstal package eksternal! Dependensi opsional (`rich`, `scapy`, `tldextract`) disediakan untuk mempercantik UI terminal dan menangkap paket secara live.

---

## 🔬 Konsep Ilmiah: Entropi Shannon pada DNS

Entropi Shannon mengukur tingkat keacakan (*randomness*) atau kerapatan informasi per karakter dalam suatu string:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Di mana:
- $X$ adalah teks payload (label subdomain).
- $P(x_i)$ adalah probabilitas kemunculan karakter $x_i$ dalam string.
- Domain normal berbahasa manusia (`mail.google.com`, `auth.github.com`) memiliki nilai entropi rendah ($\approx 2.0 - 3.2$ bit/karakter).
- Payload terenkripsi atau hasil encode Base32/Base64/Hex memiliki nilai entropi yang sangat tinggi ($\ge 3.8 - 4.8$ bit/karakter).

---

## ✨ Fitur Utama

- 🧠 **Multi-Factor Risk Scoring (0 - 100):** Menghitung skor risiko gabungan secara akurat untuk meminimalisasi *false positive*.
- 🚨 **Tingkat Keparahan Alert Otomatis:** Mengelompokkan ancaman ke dalam `CRITICAL`, `HIGH`, `MEDIUM`, dan `LOW` disertai panduan mitigasi SOC (*Security Operations Center*).
- 📂 **Dukungan Format Log Fleksibel:**
  - **CSV & TSV:** Deteksi otomatis kolom (`query`, `domain`, `client_ip`, dsb.).
  - **JSON & NDJSON:** Mendukung format Zeek JSON, Suricata EVE DNS, Pi-hole, dan SIEM.
  - **Zeek / Bro TSV Log:** Parsing native untuk `dns.log`.
  - **ISC BIND 9:** Log kueri server DNS BIND.
  - **PCAP / PCAPNG:** Parser libpcap bawaan (tanpa scapy) + integrasi Scapy.
- 📡 **Live Packet Sniffing:** Menangkap kueri DNS langsung dari antarmuka jaringan (interface Wi-Fi / Ethernet).
- 📊 **Ekspor Laporan Komprehensif:**
  - Laporan format **JSON** & **CSV** untuk integrasi ke SIEM (Splunk, Elastic, Wazuh).
  - Laporan ringkasan **Markdown**.
  - Dashboard visual **HTML Dark-Mode** mandiri (*self-contained*).
- 🧮 **Mode Kalkulator Kueri Tunggal (`calc`):** Analisis cepat satu FQDN saat investigasi insiden.
- 🛡️ **Whitelist Bawaan & Kustom:** Mencegah alarm palsu dari layanan cloud dan CDN terpercaya (Cloudflare, Google, AWS, Akamai).

---

## 🚀 Panduan Memulai Cepat (Quickstart)

### 1. Clone Repositori
```bash
git clone https://github.com/c0losseum/dns-tunnel-detector.git
cd dns-tunnel-detector
```

### 2. Jalankan Langsung (Standar Python)
```bash
# Menampilkan bantuan CLI
python main.py --help

# Menganalisis file contoh CSV yang sudah disediakan
python main.py analyze -f samples/dns_tunnel_sample.csv
```

### 3. (Opsional) Mengaktifkan UI Rich & Sniffer Jaringan
```bash
pip install -r requirements.txt
```

---

## 💻 Contoh Penggunaan CLI

### A. Menganalisis File Log & Mengekspor Laporan HTML
```bash
python main.py analyze -f samples/dns_tunnel_sample.csv \
  --output-html reports/laporan_insiden.html \
  --output-csv reports/alert_dns.csv
```

### B. Menganalisis Log Zeek `dns.log`
```bash
python main.py analyze -f samples/zeek_dns.log --format zeek
```

### C. Menganalisis Kueri Tertentu Secara Interaktif (`calc`)
```bash
python main.py calc "4a7f9c2d1b8e3a5c6d0e2f4a8b1c3d5e7f9a0b2c4d6e8f.tunnel.darkc2.org"
```

### D. Menangkap Lalu Lintas Live (Port 53 UDP)
*Membutuhkan Scapy dan hak akses Administrator / Root:*
```bash
# Windows (Buka PowerShell as Administrator)
python main.py live -i "Wi-Fi"

# Linux / macOS
sudo python3 main.py live -i eth0
```

### E. Membuat Dataset Kueri Tiruan (Generator)
```bash
python tools/generate_sample_traffic.py -n 500 -r 0.3 -o samples/kueri_uji.csv
```

---

## 🧪 Menjalankan Unit Test

Untuk memastikan seluruh fungsi bekerja tanpa eror:
```bash
python -m unittest discover -s tests -v
```

---

## 📁 Struktur Direktori Project

```text
├── .github/workflows/ci.yml       # Otomasi pengujian CI GitHub Actions
├── .gitignore
├── LICENSE                        # Lisensi MIT
├── README.md                      # Dokumentasi Bahasa Inggris
├── README_ID.md                   # Dokumentasi Bahasa Indonesia
├── pyproject.toml                 # Standar packaging Python
├── requirements.txt               # Pustaka opsional
├── requirements-dev.txt           # Pustaka untuk testing & linting
├── main.py                        # Entry point eksekusi utama
├── samples/                       # Sampel log untuk pengujian langsung
│   ├── dns_tunnel_sample.csv      # Kumpulan kueri normal & serangan
│   ├── zeek_dns.log               # Contoh log Zeek
│   └── queries.json               # Contoh log JSON
├── src/dns_detector/
│   ├── core/
│   │   ├── entropy.py             # Perhitungan Entropi Shannon & statistik
│   │   ├── domain_utils.py        # Pemisah subdomain & apex domain offline
│   │   ├── metrics.py             # Ekstraksi fitur kueri
│   │   └── engine.py              # Mesin penilaian risiko multi-faktor
│   ├── models/
│   │   ├── query.py               # Model data DNSQuery
│   │   └── alert.py               # Model data DNSAlert
│   ├── parsers/                   # Parser CSV, JSON, Zeek, BIND, PCAP
│   ├── reporting/                 # Tampilan konsol & pengekspor laporan
│   └── live/                      # Sniffer jaringan real-time
├── tests/                         # Unit tests otomatis
└── tools/                         # Generator lalu lintas kueri tiruan
```

---

## 📄 Lisensi

Proyek ini dirilis di bawah lisensi terbuka [MIT License](LICENSE).
Bebas digunakan untuk keperluan portofolio, penelitian akademis, maupun implementasi sistem keamanan nyata.
