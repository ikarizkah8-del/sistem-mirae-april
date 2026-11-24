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
| `dataset2023/` | 80 berkas CSV per-PCAP CICIoT2023 (±725 MB): `begin` (BenignTraffic, 4 berkas), `mirai greeth` (29), `mirai greip` (22), `Mirai-udpplain` (25) |

Dataset bersumber dari CICIoT2023 (Canadian Institute for Cybersecurity, <https://www.unb.ca/cic/datasets/iotdataset-2023.html>).
Jika memakai dataset ini, kutip: Neto, E. C. P., dkk. (2023). CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale
Attacks in IoT Environment. *Sensors*, 23(13), 5941. https://doi.org/10.3390/s23135941

## Menjalankan aplikasi

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r mirai_rulebased\requirements.txt
.venv\Scripts\python.exe mirai_rulebased\api.py
```

Buka <http://127.0.0.1:5000>. Grafik memakai Plotly.js dari CDN, jadi perlu koneksi internet.

## Menjalankan ulang pipeline (opsional)

Dataset sudah tersedia di folder `dataset2023/` (label diambil dari nama berkas). Jalankan:

```bash
.venv\Scripts\python.exe mirai_rulebased\pipeline.py
```

Waktu proses ±2 menit dengan RAM ±3 GB.

## Hasil utama (data uji 1.064.524 baris)

| Accuracy | Precision | Recall | F1-Score | False Positive | False Negative |
|---|---|---|---|---|---|
| 99,22% | 99,99% | 98,88% | 99,43% | 104 | 8.212 |

Aturan: R1 `Protocol Type ≥ 47 AND Header_Length ≤ 7,2`, R2 `Protocol Type ≥ 47 AND Header_Length ≤ 12,1`,
R3 `TCP ≤ 0,09 AND AVG ≥ 453`. Hasil berlaku pada dataset CICIoT2023 (pengujian *offline*).
