"""Buat satu berkas CSV contoh berisi campuran trafik normal dan serangan Mirai untuk demo upload.

Baris diambil HANYA dari data uji (30%) hasil pembagian yang sama persis dengan pipeline.py,
sehingga tidak pernah dipakai saat menyusun aturan. Semua 39 kolom asli dipertahankan,
ditambah kolom `label` (kunci jawaban) agar akurasi dapat dihitung di aplikasi.

Jalankan dari folder D:\\hasil skirpsi april:
    .venv\\Scripts\\python.exe mirai_rulebased\\buat_data_contoh.py
Hasil: data_uji\\data_uji_campuran.csv
"""
from __future__ import annotations

import numpy as np
import pandas as pd

import config as C
from pipeline import bagi_acak, muat_data

PER_KELAS = 2_500
OUT_DIR = C.BASE_DIR.parent / "data_uji"


def main() -> None:
    df_raw, _ = muat_data(C.DATA_DIR)
    df_raw = df_raw[~df_raw["kelas"].astype(str).str.startswith(C.PREFIX_DDOS)].copy()
    df_raw["kelas"] = df_raw["kelas"].astype(str)
    meta = ["kelas", "file", "nomor_file"]
    fitur = [c for c in df_raw.columns if c not in meta]

    # Langkah preprocessing yang sama dengan pipeline.preprocessing (urutan baris identik)
    d = df_raw.loc[np.isfinite(df_raw[fitur].to_numpy()).all(axis=1)]
    d = d.loc[~d.duplicated(subset=fitur, keep="first")]
    asal = d.index.to_numpy()                       # indeks baris pada df_raw
    d = d.reset_index(drop=True)
    d["kelas"] = pd.Categorical(d["kelas"], categories=C.KELAS_UTAMA)
    uji = bagi_acak(d)                              # mask data uji, sama persis dengan pipeline

    rng = np.random.default_rng(C.RANDOM_SEED)
    ambil = []
    for kelas in C.KELAS_UTAMA:
        idx = np.flatnonzero(uji & (d["kelas"] == kelas).to_numpy())
        ambil.append(asal[rng.choice(idx, size=min(PER_KELAS, len(idx)), replace=False)])
    pilih = np.concatenate(ambil)
    rng.shuffle(pilih)

    hasil = df_raw.loc[pilih, fitur].reset_index(drop=True)
    hasil["label"] = df_raw.loc[pilih, "kelas"].to_numpy()
    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / "data_uji_campuran.csv"
    hasil.to_csv(path, index=False, float_format="%.6g")
    print(f"Tersimpan {path} ({len(hasil):,} baris)")
    print(hasil["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
