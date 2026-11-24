"""Logika aplikasi deteksi (tanpa framework): memuat hasil pipeline, menjalankan rule, riwayat.

Dipakai oleh api.py (Flask). Semua fungsi mengembalikan tipe Python/JSON biasa agar mudah
dikirim sebagai respons API.
"""
from __future__ import annotations

import io
import json
import math
import re
import time
from dataclasses import replace
from functools import lru_cache

import numpy as np
import pandas as pd

import config as C
from rules import RuleSet, metrik_biner

OUT = C.OUTPUT_DIR
FILE_RULES = OUT / "rules.json"                  # aturan hasil penelitian (dibuat pipeline.py)
FILE_RULES_KUSTOM = OUT / "rules_kustom.json"    # ambang yang diubah pengguna di aplikasi
DIR_RIWAYAT = OUT / "riwayat"
FILE_RIWAYAT = DIR_RIWAYAT / "riwayat_deteksi.csv"
FILE_CONTOH = C.BASE_DIR.parent / "data_uji" / "data_uji_campuran.csv"

WARNA_BINER = {"Normal": "#2a78d6", "Mirai": "#e34948"}
WARNA_KELAS = {"BenignTraffic": "#2a78d6", "Mirai-greeth_flood": "#eb6834",
               "Mirai-greip_flood": "#1baf7a", "Mirai-udpplain": "#eda100"}
NAMA_PROTOKOL = {6.0: "TCP", 17.0: "UDP", 47.0: "GRE", 1.0: "ICMP"}


# ---------------------------------------------------------------------------
# Hasil pipeline (dibaca sekali, disimpan di memori)
# ---------------------------------------------------------------------------

def output_siap() -> bool:
    return FILE_RULES.exists()


def _json(nama):
    with open(OUT / nama, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def hasil_pipeline() -> dict:
    return {
        "meta": _json("00_meta.json"),
        "inventaris": pd.read_csv(OUT / "01_inventaris_file.csv"),
        "status_fitur": pd.read_csv(OUT / "02_status_fitur.csv"),
        "jendela": _json("02c_ukuran_jendela.json"),
        "pre": pd.read_csv(OUT / "03_preprocessing.csv"),
        "bagi": pd.read_csv(OUT / "04_pembagian_data.csv"),
        "stat": pd.read_csv(OUT / "05_statistik_karakteristik.csv"),
        "sep": pd.read_csv(OUT / "06_keterpisahan_fitur.csv"),
        "jejak": pd.read_csv(OUT / "07_jejak_penyusunan_rule.csv"),
        "eval": _json("08_evaluasi_skenario1.json"),
        "waktu": _json("09_waktu_eksekusi.json"),
        "ablasi": pd.read_csv(OUT / "10_ablasi_fitur.csv"),
        "holdout": _json("11_evaluasi_file_holdout.json"),
    }


@lru_cache(maxsize=4)
def _muat_rules(path: str, mtime: float) -> RuleSet:
    return RuleSet.from_json(path)


def ruleset_penelitian() -> RuleSet:
    return _muat_rules(str(FILE_RULES), FILE_RULES.stat().st_mtime)


def kustom_aktif() -> bool:
    return FILE_RULES_KUSTOM.exists()


def ruleset() -> RuleSet:
    """Aturan yang AKTIF untuk deteksi: aturan kustom bila ada, jika tidak aturan hasil penelitian."""
    if kustom_aktif():
        return _muat_rules(str(FILE_RULES_KUSTOM), FILE_RULES_KUSTOM.stat().st_mtime)
    return ruleset_penelitian()


def nama_aturan_aktif() -> str:
    return "kustom" if kustom_aktif() else "hasil penelitian"


@lru_cache(maxsize=1)
def sampel() -> pd.DataFrame:
    return pd.read_parquet(OUT / "sampel.parquet")


def sampel_uji() -> pd.DataFrame:
    s = sampel()
    return s[s["bagian"] == "uji"].drop(columns="bagian").reset_index(drop=True)


def tabel(df: pd.DataFrame) -> list[dict]:
    """DataFrame -> list of dict yang aman untuk JSON (NaN -> None)."""
    return json.loads(df.to_json(orient="records", force_ascii=False))


def aturan_json(rs: RuleSet | None = None) -> list[dict]:
    rs = rs or ruleset()
    return [{"id": r.id, "nama": r.nama, "varian": r.varian, "alasan": r.alasan, "teks": r.teks(),
             "kondisi": [{"fitur": k.fitur, "op": k.op, "ambang": k.ambang, "metode": k.metode, "teks": k.teks()}
                         for k in r.kondisi]}
            for r in rs.rules]


# ---------------------------------------------------------------------------
# Aturan kustom (ubah ambang di aplikasi)
# ---------------------------------------------------------------------------

def _terapkan_ambang(ambang: dict) -> RuleSet:
    """Salin aturan hasil penelitian lalu ganti nilai ambangnya. ambang = {"R1": [47, 7.2], ...}."""
    if not isinstance(ambang, dict):
        raise ValueError('Format salah. Kirim {"ambang": {"R1": [nilai, ...], ...}}')
    rules = []
    for r in ruleset_penelitian().rules:
        nilai = ambang.get(r.id, [k.ambang for k in r.kondisi])
        if not isinstance(nilai, list) or len(nilai) != len(r.kondisi):
            raise ValueError(f"{r.id}: harus berisi {len(r.kondisi)} nilai ambang.")
        kondisi = []
        for k, v in zip(r.kondisi, nilai):
            try:
                v = float(v)
            except (TypeError, ValueError):
                raise ValueError(f"{r.id} / {k.fitur}: '{v}' bukan angka.") from None
            if not math.isfinite(v):
                raise ValueError(f"{r.id} / {k.fitur}: nilai harus angka berhingga.")
            metode = k.metode if v == k.ambang else "diubah manual oleh pengguna"
            kondisi.append(replace(k, ambang=v, metode=metode))
        rules.append(replace(r, kondisi=kondisi))
    return RuleSet(rules)


def uji_ambang(ambang: dict) -> dict:
    """Bandingkan kinerja ambang usulan dengan aturan hasil penelitian pada sampel data uji (120.000 baris)."""
    rs_baru = _terapkan_ambang(ambang)
    d = sampel_uji()
    y = d["kelas"].astype(str).str.startswith("Mirai").to_numpy()
    def nilai(rs):
        pred = rs.prediksi(d)
        m = metrik_biner(y, pred)
        per = (pd.DataFrame({"kelas": d["kelas"].astype(str), "p": pred}).groupby("kelas")["p"].mean() * 100)
        return {**m, "per_kelas": {k: float(v) for k, v in per.items()}}
    return {"jumlah_data": int(len(d)), "penelitian": nilai(ruleset_penelitian()), "usulan": nilai(rs_baru),
            "aturan_usulan": aturan_json(rs_baru)}


def simpan_ambang(ambang: dict) -> list[dict]:
    rs = _terapkan_ambang(ambang)
    if all(k1.ambang == k2.ambang for r1, r2 in zip(rs.rules, ruleset_penelitian().rules)
           for k1, k2 in zip(r1.kondisi, r2.kondisi)):
        hapus_ambang()                       # sama dengan hasil penelitian -> tidak perlu file kustom
    else:
        rs.to_json(FILE_RULES_KUSTOM)
    return aturan_json()


def hapus_ambang() -> None:
    if FILE_RULES_KUSTOM.exists():
        FILE_RULES_KUSTOM.unlink()


def data_aturan() -> dict:
    H = hasil_pipeline()
    return {"aktif": aturan_json(), "penelitian": aturan_json(ruleset_penelitian()),
            "kustom_aktif": kustom_aktif(), "nama_aktif": nama_aturan_aktif(), "jejak": tabel(H["jejak"])}


# ---------------------------------------------------------------------------
# Data masukan
# ---------------------------------------------------------------------------

def kelas_dari_nama_file(nama: str) -> str | None:
    k = re.sub(r"\d*(\.pcap)?(\s*\(\d+\))?\.csv$", "", nama, flags=re.I).strip()
    return k if k in C.KELAS_UTAMA or k.startswith(C.PREFIX_DDOS) else None


def baca_csv(berkas, nama: str) -> pd.DataFrame:
    """Baca satu CSV unggahan; label diambil dari kolom label/kelas atau dari nama file."""
    d = pd.read_csv(berkas, low_memory=False)
    d.columns = d.columns.str.strip()
    kol_label = next((c for c in d.columns if c.lower() in ("label", "kelas")), None)
    if kol_label:
        d = d.rename(columns={kol_label: "kelas"})
    elif kelas_dari_nama_file(nama):
        d["kelas"] = kelas_dari_nama_file(nama)
    d["file"] = nama
    return d


def ringkas_data(d: pd.DataFrame, sumber: str) -> dict:
    hilang = [f for f in ruleset().fitur if f not in d.columns]
    pratinjau = d.head(100).replace([np.inf, -np.inf], np.nan)
    komposisi = None
    if "kelas" in d.columns:
        komposisi = {str(k): int(v) for k, v in d["kelas"].astype(str).value_counts().items()}
    return {"sumber": sumber, "jumlah_baris": int(len(d)), "jumlah_kolom": int(d.shape[1]),
            "atribut_hilang": hilang, "atribut_lengkap": not hilang, "ada_label": "kelas" in d.columns,
            "komposisi_label": komposisi, "atribut_rule": ruleset().fitur,
            "kolom": list(pratinjau.columns), "pratinjau": tabel(pratinjau)}


def contoh_tersedia() -> bool:
    return FILE_CONTOH.exists()


def baca_contoh() -> pd.DataFrame:
    return baca_csv(FILE_CONTOH, FILE_CONTOH.name)


def info_dataset() -> dict:
    """Berkas di folder dataset2023 yang dipakai penelitian, per folder dan kelas."""
    H = hasil_pipeline()
    inv = H["inventaris"]
    per = (inv.groupby(["folder", "kelas"]).agg(jumlah_file=("file", "count"), total_baris=("baris", "sum"),
                                                 ukuran_mb=("ukuran_mb", "sum")).reset_index())
    per["ukuran_mb"] = per["ukuran_mb"].round(1)
    bagi = H["bagi"].rename(columns={"penyusunan_rule": "penyusunan", "uji": "uji"})
    return {"per_folder": tabel(per), "total_file": int(len(inv)), "total_baris": int(inv["baris"].sum()),
            "pembagian": tabel(bagi), "contoh_tersedia": contoh_tersedia(),
            "contoh_nama": FILE_CONTOH.name, "contoh_folder": str(FILE_CONTOH.parent)}


# ---------------------------------------------------------------------------
# Deteksi
# ---------------------------------------------------------------------------

def jalankan_deteksi(data: pd.DataFrame) -> dict:
    rs = ruleset()
    x = data[rs.fitur].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    valid = x.notna().all(axis=1).to_numpy()
    t0 = time.perf_counter()
    xv = x[valid]
    pred = rs.prediksi(xv)
    alasan = rs.jelaskan(xv).to_numpy()
    durasi = time.perf_counter() - t0
    hasil = data.copy()
    kol_pred = np.full(len(hasil), "Tidak valid", dtype=object)
    kol_pred[valid] = np.where(pred, "Mirai", "Normal")
    kol_rule = np.full(len(hasil), "-", dtype=object)
    kol_rule[valid] = alasan
    hasil.insert(0, "Prediksi", kol_pred)
    hasil.insert(1, "Rule terpenuhi", kol_rule)
    return {"hasil": hasil, "durasi": durasi, "n_tidak_valid": int((~valid).sum()), "aturan": nama_aturan_aktif()}


def kolom_hasil(hasil: pd.DataFrame) -> list[str]:
    fitur = [f for f in ruleset_penelitian().fitur if f in hasil.columns]
    return ["Prediksi", "Rule terpenuhi"] + [k for k in ("kelas", "file") if k in hasil.columns] + fitur


def ringkas_deteksi(det: dict) -> dict:
    """Ringkasan hasil deteksi untuk dashboard: jumlah, metrik, confusion matrix, rule terbanyak."""
    hasil = det["hasil"]
    n = len(hasil)
    n_mirai = int((hasil["Prediksi"] == "Mirai").sum())
    n_normal = int((hasil["Prediksi"] == "Normal").sum())
    rc = hasil.loc[hasil["Prediksi"] == "Mirai", "Rule terpenuhi"].value_counts().head(6)
    ringkas = {"jumlah_baris": n, "mirai": n_mirai, "normal": n_normal, "tidak_valid": det["n_tidak_valid"],
               "persen_mirai": 100 * n_mirai / max(n, 1), "durasi_ms": det["durasi"] * 1000,
               "aturan": det.get("aturan", "hasil penelitian"),
               "rule_terbanyak": [{"rule": k, "jumlah": int(v)} for k, v in rc.items()],
               "metrik": None, "per_kelas": None}
    if "kelas" in hasil.columns:
        sah = hasil[hasil["Prediksi"] != "Tidak valid"]
        ringkas["metrik"] = metrik_biner(sah["kelas"].astype(str).str.startswith("Mirai"), sah["Prediksi"] == "Mirai")
        ct = pd.crosstab(sah["kelas"].astype(str), sah["Prediksi"])
        ringkas["per_kelas"] = [{"kelas": k, **{c: int(ct.at[k, c]) for c in ct.columns}} for k in ct.index]
    return ringkas


def baris_hasil(hasil: pd.DataFrame, filt: str = "Semua", cari: str = "", batas: int = 1000) -> dict:
    t = hasil[kolom_hasil(hasil)]
    if filt in ("Mirai", "Normal", "Tidak valid"):
        t = t[t["Prediksi"] == filt]
    if cari:
        teks = t[[k for k in ("Rule terpenuhi", "kelas", "file") if k in t.columns]].astype(str)
        t = t[teks.apply(lambda s: s.str.contains(cari, case=False, regex=False)).any(axis=1)]
    return {"total": int(len(t)), "kolom": list(t.columns),
            "baris": tabel(t.head(batas).replace([np.inf, -np.inf], np.nan))}


def csv_hasil(hasil: pd.DataFrame) -> bytes:
    buf = io.StringIO()
    hasil[kolom_hasil(hasil)].to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")


def prediksi_records(records: list[dict]) -> list[dict]:
    """Deteksi untuk data JSON (dipakai endpoint /api/prediksi)."""
    d = pd.DataFrame(records)
    hilang = [f for f in ruleset().fitur if f not in d.columns]
    if hilang:
        raise ValueError(f"Atribut yang dibutuhkan rule tidak ada: {hilang}")
    det = jalankan_deteksi(d)
    return [{"prediksi": p, "rule_terpenuhi": r} for p, r in
            zip(det["hasil"]["Prediksi"], det["hasil"]["Rule terpenuhi"])]


# ---------------------------------------------------------------------------
# Riwayat (disimpan di output/riwayat/ agar tetap ada setelah aplikasi ditutup)
# ---------------------------------------------------------------------------

def muat_riwayat() -> pd.DataFrame:
    if not FILE_RIWAYAT.exists():
        return pd.DataFrame()
    return pd.read_csv(FILE_RIWAYAT, dtype={"id": str})


def simpan_riwayat(det: dict, sumber: str) -> str:
    DIR_RIWAYAT.mkdir(parents=True, exist_ok=True)
    hasil = det["hasil"]
    rid = time.strftime("%Y%m%d_%H%M%S")
    while (DIR_RIWAYAT / f"{rid}.csv.gz").exists():       # dua deteksi dalam detik yang sama
        rid += "_1"
    r = ringkas_deteksi(det)
    baris = {"id": rid, "waktu": time.strftime("%Y-%m-%d %H:%M:%S"), "sumber_data": sumber,
             "aturan": r["aturan"], "jumlah_baris": r["jumlah_baris"], "mirai": r["mirai"], "normal": r["normal"],
             "tidak_valid": r["tidak_valid"], "persen_mirai": round(r["persen_mirai"], 2),
             "durasi_ms": round(r["durasi_ms"], 1),
             "accuracy": None, "precision": None, "recall": None, "f1": None, "FP": None, "FN": None}
    if r["metrik"]:
        baris.update({k: r["metrik"][k] for k in ("accuracy", "precision", "recall", "f1", "FP", "FN")})
    hasil[kolom_hasil(hasil)].to_csv(DIR_RIWAYAT / f"{rid}.csv.gz", index=False, compression="gzip")
    pd.concat([muat_riwayat(), pd.DataFrame([baris])], ignore_index=True).to_csv(FILE_RIWAYAT, index=False)
    return rid


def daftar_riwayat() -> list[dict]:
    r = muat_riwayat()
    if r.empty:
        return []
    if "aturan" not in r.columns:
        r["aturan"] = None
    r["aturan"] = r["aturan"].fillna("hasil penelitian")
    return tabel(r.iloc[::-1])          # terbaru di atas


def file_riwayat(rid: str):
    if not re.fullmatch(r"[0-9_]+", rid or ""):
        return None
    p = DIR_RIWAYAT / f"{rid}.csv.gz"
    return p if p.exists() else None


def hapus_riwayat() -> int:
    n = 0
    if DIR_RIWAYAT.exists():
        for p in DIR_RIWAYAT.glob("*"):
            p.unlink(); n += 1
    return n


# ---------------------------------------------------------------------------
# Data untuk halaman beranda, analisis, evaluasi
# ---------------------------------------------------------------------------

def data_beranda() -> dict:
    H = hasil_pipeline()
    return {"jumlah_data_uji": H["eval"]["jumlah_data"], "biner": H["eval"]["biner"], **data_aturan(),
            "sampel_uji": int(len(sampel_uji()))}


def distribusi_protokol() -> list[dict]:
    s = sampel()
    train = s[s["bagian"] == "penyusunan"]
    hasil = []
    for kelas in C.KELAS_UTAMA:
        p = train.loc[train["kelas"] == kelas, "Protocol Type"].map(
            lambda v: NAMA_PROTOKOL.get(float(v), "Campuran/lainnya")).value_counts()
        hasil.append({"kelas": kelas, "protokol": {k: int(v) for k, v in p.items()}})
    return hasil


def sebaran_fitur(fitur: str, log_x: bool, bins: int = 80) -> dict:
    """Histogram (persen per kelas) dan statistik satu fitur, dihitung di server."""
    H = hasil_pipeline()
    if fitur not in H["meta"]["fitur_analisis"]:
        raise ValueError(f"Fitur tidak dikenal: {fitur}")
    s = sampel()
    train = s[s["bagian"] == "penyusunan"][[fitur, "kelas"]]
    if log_x:
        train = train[train[fitur] > 0]
    v = train[fitur].to_numpy(np.float64)
    lo, hi = (float(v.min()), float(v.max())) if len(v) else (0.0, 1.0)
    if hi <= lo:
        hi = lo + 1
    tepi = np.logspace(np.log10(lo), np.log10(hi), bins + 1) if log_x else np.linspace(lo, hi, bins + 1)
    seri = []
    for kelas in C.KELAS_UTAMA:
        a = train.loc[train["kelas"] == kelas, fitur].to_numpy(np.float64)
        h, _ = np.histogram(a, tepi)
        q = np.quantile(a, [0, .25, .5, .75, 1]).tolist() if len(a) else [None] * 5
        seri.append({"kelas": kelas, "warna": WARNA_KELAS[kelas], "persen": (100 * h / max(len(a), 1)).tolist(),
                     "kuartil": q})
    stat = H["stat"]
    tab = (stat[stat["fitur"] == fitur].pivot(index="kelas", columns="statistik", values="nilai")
           .reindex(C.KELAS_UTAMA)[["mean", "std", "p05", "median", "p95"]].reset_index())
    tengah = (np.sqrt(tepi[:-1] * tepi[1:]) if log_x else (tepi[:-1] + tepi[1:]) / 2).tolist()
    return {"fitur": fitur, "log": log_x, "tengah_bin": tengah, "seri": seri, "statistik": tabel(tab)}


def daya_pisah(top: int = 15) -> dict:
    sep = hasil_pipeline()["sep"]
    piv = sep.pivot(index="fitur", columns="varian", values="youden_j")
    piv = piv.loc[piv.mean(axis=1).sort_values(ascending=False).index].head(top)
    return {"fitur": list(piv.index), "varian": list(piv.columns), "nilai": piv.round(4).to_numpy().tolist()}


def data_analisis() -> dict:
    H = hasil_pipeline()
    return {"fitur_analisis": H["meta"]["fitur_analisis"], "protokol": distribusi_protokol(),
            "daya_pisah": daya_pisah(), "warna_kelas": WARNA_KELAS}


def analisis_overfitting() -> dict:
    """Bahan analisis: kenapa nilai evaluasi tinggi dan seberapa rawan overfitting."""
    H = hasil_pipeline()
    ev, tr, te = H["eval"], H["eval"]["evaluasi_data_penyusunan"], H["eval"]["biner"]
    ho = H["holdout"]["biner"]
    ab = H["ablasi"]
    rs = ruleset_penelitian()
    sep = H["sep"]
    fitur_rule = rs.fitur
    daya = (sep[sep["fitur"].isin(fitur_rule)].groupby("fitur")["youden_j"].max().round(4)
            .sort_values(ascending=False))
    bagi = H["bagi"]
    return {
        "metrik": [{"metrik": m, "penyusunan": tr[k], "uji": te[k], "file_holdout": ho[k], "selisih_uji": te[k] - tr[k]}
                   for k, m in (("accuracy", "Accuracy"), ("precision", "Precision"), ("recall", "Recall"),
                                ("f1", "F1-Score"), ("fpr", "False Positive Rate"))],
        "jumlah_penyusunan": int(bagi["penyusunan_rule"].sum()), "jumlah_uji": int(bagi["uji"].sum()),
        "jumlah_aturan": len(rs.rules), "jumlah_kondisi": sum(len(r.kondisi) for r in rs.rules),
        "daya_pisah_fitur_rule": [{"fitur": f, "youden_j": float(v)} for f, v in daya.items()],
        "ablasi_f1_min": float(ab["f1"].min()), "ablasi_f1_max": float(ab["f1"].max()),
        "holdout_file_uji": len(H["holdout"].get("file_uji", [])),
        "jendela": {k: int(next(iter(v))) for k, v in H["jendela"].items()},
        "redundansi": ev.get("redundansi_jaccard"),
    }


def data_evaluasi() -> dict:
    H = hasil_pipeline()
    return {"eval": H["eval"], "waktu": H["waktu"], "ablasi": tabel(H["ablasi"]),
            "holdout": {k: H["holdout"][k] for k in ("jumlah_data", "biner", "per_kelas") if k in H["holdout"]},
            "analisis": analisis_overfitting(), "warna_kelas": WARNA_KELAS}
