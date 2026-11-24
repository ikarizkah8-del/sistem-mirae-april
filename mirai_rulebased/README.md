# Deteksi Mirai Botnet dengan Metode Rule-Based (CICIoT2023)

Lanjutan dari notebook audit (Tahap 1). Folder ini berisi Tahap 2 sampai 7 sesuai BAB III proposal:
preprocessing → pembagian data → analisis karakteristik → penyusunan rule IF-THEN → deteksi → evaluasi.

## Struktur

| File | Isi |
|---|---|
| `config.py` | lokasi data, kelas, fitur yang dikeluarkan (hasil audit), kelompok indikator |
| `rules.py` | mesin rule IF-THEN, perhitungan ambang (Youden J, persentil), metrik evaluasi |
| `pipeline.py` | menjalankan seluruh tahapan dan menyimpan hasil ke `output/` |
| `api.py` | aplikasi **Flask**: REST API (`/api/...`) + halaman web |
| `layanan.py` | logika aplikasi tanpa framework: memuat hasil pipeline, menjalankan deteksi, riwayat |
| `templates/index.html`, `static/` | tampilan web (4 menu: Beranda, Analisis Trafik, Deteksi Serangan, Evaluasi Sistem); semua data diambil dari API |
| `buat_data_contoh.py` | membuat `..\data_uji\data_uji_campuran.csv`: 10.000 baris campuran normal + 3 varian Mirai dari **data uji** (kolom `label` = kunci jawaban) |
| `output/` | hasil: tabel CSV/JSON, `rules.json`, `sampel.parquet`, `riwayat/` (riwayat deteksi), `rules_kustom.json` (hanya ada jika ambang diubah di Beranda) |

## Menu aplikasi

- **Beranda**: ringkasan hasil uji, kartu aturan aktif, dan **Perubahan Aturan** (uji ambang pada 120.000 baris sampel data uji, lalu simpan atau kembalikan ke hasil penelitian). Ambang kustom hanya dipakai di menu Deteksi Serangan; Evaluasi Sistem selalu memakai aturan hasil penelitian.
- **Analisis Trafik**: protokol (batang/donat), sebaran atribut (pilih atribut, sembunyikan kelas, histogram/kotak, skala log), atribut pembeda (klik atribut untuk membuka sebarannya), ringkasan ciri.
- **Deteksi Serangan**: kiri unggah berkas, kanan pilih sumber data (berkas unggahan, contoh campuran, sampel data uji), lalu **Mulai Deteksi** → data terproses → hasil deteksi (tab Grafik / Tabel / Evaluasi; klik grafik membuka baris datanya), ditambah riwayat.
- **Evaluasi Sistem**: kartu Hasil Deteksi dan Metrik Evaluasi pada data uji, confusion matrix, dan persentase ditandai Mirai per kelas. Analisis overfitting, kualitas aturan, dan uji ketahanan tetap dihitung oleh API (`/api/evaluasi`) untuk file penjelasan sistem.
| `_streamlit_lama/` | cadangan antarmuka Streamlit lama (tidak dipakai lagi) |

## Cara menjalankan

Dari folder `D:\hasil skirpsi april`:

```bash
.venv\Scripts\python.exe mirai_rulebased\pipeline.py
```

```bash
.venv\Scripts\python.exe mirai_rulebased\api.py
```

Lalu buka <http://127.0.0.1:5000>. Pipeline sekitar 2–3 menit (RAM ±3 GB). Lingkungan baru: `pip install -r requirements.txt`.
Grafik memakai Plotly.js dari CDN, jadi browser perlu koneksi internet agar grafik tampil.

## Endpoint API

| Metode | Endpoint | Fungsi |
|---|---|---|
| GET | `/api/status` | status server dan hasil pipeline |
| GET | `/api/beranda` | metrik data uji dan aturan (aktif + hasil penelitian) |
| GET | `/api/aturan` | aturan aktif, aturan hasil penelitian, jejak penyusunan |
| POST | `/api/aturan/uji` | uji ambang usulan `{"ambang": {"R1": [47, 7.2], ...}}` pada sampel data uji |
| PUT | `/api/aturan` | simpan ambang usulan sebagai aturan aktif (kustom) |
| DELETE | `/api/aturan/kustom` | kembali ke aturan hasil penelitian |
| GET | `/api/dataset` | berkas dataset2023 yang dipakai penelitian |
| POST | `/api/data/contoh` | pakai berkas contoh campuran normal + serangan |
| GET | `/api/analisis` | distribusi protokol, daya pisah fitur |
| GET | `/api/analisis/fitur/<nama>?log=1` | histogram + statistik satu fitur |
| POST | `/api/data/unggah` | unggah CSV (form-data, field `files`) sebagai data aktif |
| POST | `/api/data/sampel` | pakai sampel data uji sebagai data aktif |
| GET | `/api/data` | ringkasan data aktif |
| POST | `/api/deteksi` | jalankan deteksi pada data aktif (tercatat di riwayat) |
| GET | `/api/deteksi` | ringkasan hasil deteksi terakhir |
| GET | `/api/deteksi/baris?filter=Mirai&cari=R3&batas=1000` | baris hasil deteksi |
| GET | `/api/deteksi/unduh` | unduh hasil deteksi terakhir (CSV) |
| POST | `/api/deteksi/file?baris=1` | unggah CSV dan langsung dideteksi (satu langkah) |
| POST | `/api/prediksi` | deteksi data JSON |
| GET | `/api/riwayat` | daftar riwayat deteksi |
| GET | `/api/riwayat/<id>/unduh` | unduh hasil deteksi lama (CSV.gz) |
| DELETE | `/api/riwayat` | hapus seluruh riwayat |
| GET | `/api/evaluasi` | evaluasi sistem pada data uji + analisis overfitting |

Contoh pemanggilan dengan curl:

```bash
curl -F "files=@dataset2023/Mirai-udpplain/Mirai-udpplain.pcap.csv" http://127.0.0.1:5000/api/deteksi/file
curl -H "Content-Type: application/json" -d "{\"data\":[{\"Protocol Type\":47,\"Header_Length\":0,\"TCP\":0,\"AVG\":592}]}" http://127.0.0.1:5000/api/prediksi
```

## Perbaikan terhadap notebook awal

1. Notebook baru sampai audit data; pipeline ini menyelesaikan analisis karakteristik, rule, dan evaluasi.
2. Jalur Kaggle diganti dengan folder lokal `dataset2023`.
3. Duplikat dihapus secara global **sebelum** split, lalu data dibagi 70/30 (stratified, seed 42).
   Data uji tidak dipakai sama sekali saat menentukan ambang.
4. Ambang batas diturunkan dari data (Youden J = tumpang tindih terkecil, atau persentil 1/99 kelas Mirai),
   lengkap dengan jejak penyusunannya (`07_jejak_penyusunan_rule.csv`).
5. Setiap rule wajib memakai minimal 2 kelompok indikator berbeda (mis. protokol + ukuran paket),
   sehingga tidak bertumpu pada satu ciri saja.
6. Evaluasi mencakup Confusion Matrix, Accuracy, Precision, Recall, F1, FP/FN, kualitas rule
   (Liu dkk., 2021: ketepatan, cakupan, redundansi, panjang, jumlah rule), dan waktu eksekusi.
7. Uji tambahan: ablasi fitur "hati-hati" (IAT, Std/Min/Max, Rate, Protocol Type) dan uji file-holdout.
8. Skenario 2 (DDoS non-Mirai) tetap dihitung oleh pipeline bila file `DDoS-*.pcap.csv` ditambahkan ke `dataset2023`,
   tetapi tidak lagi ditampilkan di aplikasi.

## Catatan untuk skripsi

- CSV per-PCAP tidak memiliki `flow_duration`, `Duration`, `Srate`; lihat `02b_pemetaan_fitur_proposal.csv`.
- Ukuran jendela berbeda (Benign 10 paket, Mirai 100 paket) → `Number` dan turunannya dikeluarkan.
- R1 dan R2 sama-sama bertumpu pada GRE, sehingga redundansinya tinggi dan GREIP tidak dapat dibedakan dari GREeth.
  Untuk deteksi biner hal ini tidak berpengaruh.
