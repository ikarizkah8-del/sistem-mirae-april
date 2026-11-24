# Sistem Deteksi Mirai Botnet (Rule-Based, CICIoT2023)

Sistem deteksi serangan Mirai Botnet pada **dataset trafik perangkat IoT CICIoT2023** menggunakan metode
*rule-based* (aturan IF-THEN) berbasis trafik jaringan. Sistem terdiri atas *pipeline* penyusunan aturan dan
aplikasi web Flask dengan empat menu: Beranda, Analisis Trafik, Deteksi Serangan, dan Evaluasi Sistem.

Dokumentasi lengkap (struktur kode, menu, endpoint REST API): [mirai_rulebased/README.md](mirai_rulebased/README.md).

## Isi repositori

| Folder | Isi |
|---|---|
| `mirai_rulebased/` | kode sistem: `pipeline.py`, `rules.py`, `layanan.py`, `api.py` (Flask), tampilan web, dan hasil `output/` (aturan, evaluasi, sampel) |
| `data_uji/data_uji_campuran.csv` | 10.000 baris contoh campuran normal + 3 varian Mirai dari data uji (kolom `label` = kunci jawaban) |

Folder `dataset2023/` (80 berkas CSV, ±725 MB) **tidak disertakan** karena terlalu besar untuk GitHub.
Aplikasi web tetap bisa dijalankan tanpa dataset karena hasil pipeline sudah tersimpan di `mirai_rulebased/output/`.

## Menjalankan aplikasi

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r mirai_rulebased\requirements.txt
.venv\Scripts\python.exe mirai_rulebased\api.py
```

Buka <http://127.0.0.1:5000>. Grafik memakai Plotly.js dari CDN, jadi perlu koneksi internet.

## Menjalankan ulang pipeline (opsional)

1. Unduh berkas CSV per-PCAP CICIoT2023 kelas `BenignTraffic`, `Mirai-greeth_flood`, `Mirai-greip_flood`, dan
   `Mirai-udpplain` dari laman resmi Canadian Institute for Cybersecurity
   (<https://www.unb.ca/cic/datasets/iotdataset-2023.html>).
2. Simpan ke folder `dataset2023/` di sebelah folder `mirai_rulebased/` (subfolder bebas, label diambil dari nama berkas).
3. Jalankan `.venv\Scripts\python.exe mirai_rulebased\pipeline.py` (±2 menit, RAM ±3 GB).

## Hasil utama (data uji 1.064.524 baris)

| Accuracy | Precision | Recall | F1-Score | False Positive | False Negative |
|---|---|---|---|---|---|
| 99,22% | 99,99% | 98,88% | 99,43% | 104 | 8.212 |

Aturan: R1 `Protocol Type ≥ 47 AND Header_Length ≤ 7,2`, R2 `Protocol Type ≥ 47 AND Header_Length ≤ 12,1`,
R3 `TCP ≤ 0,09 AND AVG ≥ 453`. Hasil berlaku pada dataset CICIoT2023 (pengujian *offline*).
