"""Pipeline penelitian: Deteksi Mirai Botnet dengan metode Rule-Based (CICIoT2023).

Tahapan (mengikuti BAB III proposal):
  1. Muat data dan label dari nama file
  2. Preprocessing: hapus NaN/inf, hapus duplikat global, seleksi fitur (hasil audit)
  3. Bagi data: data penyusunan rule (70%) dan data uji (30%) yang tidak disentuh
  4. Analisis karakteristik trafik Mirai vs normal (HANYA data penyusunan)
  5. Turunkan ambang batas dan susun rule IF-THEN per varian
  6. Implementasi rule pada data uji dan evaluasi (Confusion Matrix, Accuracy, Precision,
     Recall, F1, FP/FN), kualitas rule (Liu dkk., 2021), waktu eksekusi
  7. Uji tambahan: ablasi fitur, file-holdout, Skenario 2 (DDoS non-Mirai, jika data tersedia)

Jalankan:  python pipeline.py
Hasil tersimpan di folder output/ dan ditampilkan oleh app.py (Streamlit).
"""
from __future__ import annotations

import json
import operator
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd

import config as C
from rules import (Kondisi, Rule, RuleSet, bulatkan_ambang, koefisien_tumpang_tindih,
                   metrik_biner, titik_potong_terbaik)

OUT = C.OUTPUT_DIR
OPS_PY = {">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def simpan_json(obj, nama: str) -> None:
    with open(OUT / nama, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=float)


# ---------------------------------------------------------------------------
# 1. Muat data
# ---------------------------------------------------------------------------

def label_dari_file(nama: str) -> str:
    return re.sub(r"\d*(\.pcap)?(\s*\(\d+\))?\.csv$", "", nama, flags=re.I).strip()


def nomor_file(nama: str) -> int:
    m = re.search(r"(\d*)(?:\.pcap)?(?:\s*\(\d+\))?\.csv$", nama, flags=re.I)
    return int(m.group(1)) if m and m.group(1) else 0


def muat_data(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    files = sorted(data_dir.rglob("*.csv"))
    if not files:
        raise FileNotFoundError(f"Tidak ada CSV di {data_dir}")
    bagian, inventaris = [], []
    for p in files:
        kelas = label_dari_file(p.name)
        if kelas not in C.KELAS_UTAMA and not kelas.startswith(C.PREFIX_DDOS):
            continue
        d = pd.read_csv(p, low_memory=False)
        d = d.astype({c: np.float32 for c in d.columns})
        d["kelas"] = kelas
        d["file"] = p.name
        d["nomor_file"] = nomor_file(p.name)
        bagian.append(d)
        inventaris.append({"file": p.name, "folder": p.parent.name, "kelas": kelas,
                           "baris": len(d), "ukuran_mb": round(p.stat().st_size / 1024**2, 2)})
    df = pd.concat(bagian, ignore_index=True)
    df["kelas"] = df["kelas"].astype("category")
    return df, pd.DataFrame(inventaris)


# ---------------------------------------------------------------------------
# 2. Preprocessing
# ---------------------------------------------------------------------------

def preprocessing(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    meta = ["kelas", "file", "nomor_file"]
    fitur_asli = [c for c in df.columns if c not in meta]
    awal = df.groupby("kelas", observed=True).size().rename("baris_awal")

    num = df[fitur_asli]
    buruk = ~np.isfinite(num.to_numpy()).all(axis=1)
    df = df.loc[~buruk]
    setelah_nan = df.groupby("kelas", observed=True).size().rename("setelah_hapus_nan_inf")

    # Duplikat dihapus secara global (sebelum split) agar baris identik tidak muncul
    # di data penyusunan dan data uji sekaligus.
    df = df.loc[~df.duplicated(subset=fitur_asli, keep="first")]
    setelah_dup = df.groupby("kelas", observed=True).size().rename("setelah_hapus_duplikat")

    ringkas = pd.concat([awal, setelah_nan, setelah_dup], axis=1)
    ringkas["nan_inf_dihapus"] = ringkas["baris_awal"] - ringkas["setelah_hapus_nan_inf"]
    ringkas["duplikat_dihapus"] = ringkas["setelah_hapus_nan_inf"] - ringkas["setelah_hapus_duplikat"]

    fitur = [c for c in fitur_asli if c not in C.FITUR_DIKELUARKAN]
    df = df[fitur + meta].reset_index(drop=True)
    return df, ringkas.reset_index(), fitur


def tabel_status_fitur(fitur_asli: list[str]) -> pd.DataFrame:
    baris = []
    for f in fitur_asli:
        if f in C.FITUR_DIKELUARKAN:
            status, alasan = "dikeluarkan", C.FITUR_DIKELUARKAN[f]
        elif f in C.FITUR_RULE:
            grup = next(g for g, fs in C.KELOMPOK_INDIKATOR.items() if f in fs)
            status, alasan = "kandidat rule", f"indikator: {grup}"
        else:
            status, alasan = "hanya analisis", C.FITUR_HANYA_ANALISIS.get(f, "")
        baris.append({"fitur": f, "status": status, "alasan": alasan})
    return pd.DataFrame(baris)


# ---------------------------------------------------------------------------
# 3. Pembagian data
# ---------------------------------------------------------------------------

def bagi_acak(df: pd.DataFrame) -> np.ndarray:
    """Stratified random split per kelas. Mengembalikan mask data uji."""
    rng = np.random.default_rng(C.RANDOM_SEED)
    uji = np.zeros(len(df), dtype=bool)
    for _, idx in df.groupby("kelas", observed=True).indices.items():
        pilih = rng.choice(idx, size=int(round(len(idx) * C.TEST_SIZE)), replace=False)
        uji[pilih] = True
    return uji


def bagi_per_file(df: pd.DataFrame) -> np.ndarray:
    """Uji ketahanan: seluruh baris dari file tertentu dijadikan data uji."""
    return (df["nomor_file"].to_numpy() % C.FILE_HOLDOUT_MOD) == (C.FILE_HOLDOUT_MOD - 1)


# ---------------------------------------------------------------------------
# 4. Analisis karakteristik (data penyusunan saja)
# ---------------------------------------------------------------------------

def statistik_karakteristik(train: pd.DataFrame, fitur: list[str]) -> pd.DataFrame:
    g = train.groupby("kelas", observed=True)[fitur]
    stat = pd.concat({
        "mean": g.mean(), "std": g.std(), "p05": g.quantile(0.05), "p25": g.quantile(0.25),
        "median": g.median(), "p75": g.quantile(0.75), "p95": g.quantile(0.95),
    }, axis=0)
    stat.index.names = ["statistik", "kelas"]
    return stat.stack().rename("nilai").reset_index().rename(columns={"level_2": "fitur"})


def analisis_keterpisahan(train: pd.DataFrame, fitur: list[str]) -> pd.DataFrame:
    neg = train[train["kelas"] == C.KELAS_NORMAL]
    baris = []
    for varian in C.KELAS_MIRAI:
        pos = train[train["kelas"] == varian]
        for f in fitur:
            a, b = pos[f].to_numpy(np.float64), neg[f].to_numpy(np.float64)
            op, ambang, j, tpr, fpr = titik_potong_terbaik(a, b)
            grup = next((g for g, fs in C.KELOMPOK_INDIKATOR.items() if f in fs), "-")
            baris.append({
                "varian": varian, "fitur": f, "kelompok": grup, "op": op, "ambang": ambang,
                "youden_j": j, "tpr": tpr, "fpr": fpr,
                "tumpang_tindih": koefisien_tumpang_tindih(a, b),
                "median_mirai": float(np.median(a)), "median_normal": float(np.median(b)),
                "p01_mirai": float(np.quantile(a, 0.01)), "p99_mirai": float(np.quantile(a, 0.99)),
            })
    return pd.DataFrame(baris).sort_values(["varian", "youden_j"], ascending=[True, False])


# ---------------------------------------------------------------------------
# 5. Penyusunan rule
# ---------------------------------------------------------------------------

ALASAN_KELOMPOK = {
    "Laju paket": "laju paket flood jauh lebih tinggi daripada trafik normal",
    "Jenis protokol": "flood Mirai didominasi satu protokol (GRE=47 atau UDP=17)",
    "Flag TCP": "flood GRE/UDP hampir tidak membawa flag TCP (tidak ada sesi TCP)",
    "Ukuran paket": "paket flood berukuran seragam (payload tetap)",
    "Jeda antarpaket": "jeda antarpaket flood sangat rapat",
    "Panjang header": "panjang header khas protokol flood",
}


def _kandidat_kondisi(baris: pd.Series, pos_vals: np.ndarray) -> list[list[Kondisi]]:
    """Kandidat kondisi untuk satu fitur. Setiap kandidat = daftar Kondisi (1 atau 2).

    - Youden J maksimum (titik tumpang tindih terkecil antara Mirai dan normal)
    - batas cakupan 99% kelas Mirai (persentil 1 atau 99)
    - khusus ukuran paket: rentang persentil 1-99 kelas Mirai (indikator ukuran seragam)
    """
    f, op = baris["fitur"], baris["op"]
    p01, p99 = (bulatkan_ambang(np.quantile(pos_vals, q)) for q in (0.01, 0.99))
    kandidat = [
        [Kondisi(f, op, bulatkan_ambang(baris["ambang"]), "Youden J maksimum (tumpang tindih terkecil)")],
        [Kondisi(f, op, p01 if op == ">=" else p99, "persentil 1/99 kelas Mirai (cakupan 99%)")],
    ]
    if f in C.KELOMPOK_INDIKATOR["Ukuran paket"] and p99 > p01:
        kandidat.append([Kondisi(f, ">=", p01, "rentang persentil 1-99 kelas Mirai (ukuran seragam)"),
                         Kondisi(f, "<=", p99, "rentang persentil 1-99 kelas Mirai (ukuran seragam)")])
    return kandidat


def kelompok_fitur(f: str) -> str:
    return next(g for g, fs in C.KELOMPOK_INDIKATOR.items() if f in fs)


def susun_rule(train: pd.DataFrame, fitur_rule: list[str], min_gain: float = 0.002) -> tuple[RuleSet, pd.DataFrame]:
    """Susun satu rule (konjungsi kondisi) per varian Mirai secara greedy.

    Setiap rule wajib memuat bukti dari minimal MIN_KELOMPOK kelompok indikator yang
    berbeda (mis. protokol + ukuran paket), agar rule mencerminkan karakteristik Mirai
    dan bukan sekadar "trafik non-TCP". Kelompok tambahan (hingga MAKS_KELOMPOK) hanya
    ditambahkan jika menaikkan Youden J rule pada data penyusunan minimal `min_gain`.
    """
    sep = analisis_keterpisahan(train, fitur_rule)
    neg = train[train["kelas"] == C.KELAS_NORMAL]
    rules, jejak = [], []
    for i, varian in enumerate(C.KELAS_MIRAI, start=1):
        pos = train[train["kelas"] == varian]
        kand = sep[sep["varian"] == varian]
        kondisi: list[Kondisi] = []
        grup_dipakai: list[str] = []
        m_pos = np.ones(len(pos), bool); m_neg = np.ones(len(neg), bool)
        j_saat_ini = 0.0
        while len(grup_dipakai) < C.MAKS_KELOMPOK_PER_RULE:
            calon = []
            for _, b in kand.iterrows():
                if b["kelompok"] in grup_dipakai or b["youden_j"] <= 0:
                    continue
                for ks in _kandidat_kondisi(b, pos[b["fitur"]].to_numpy()):
                    mp, mn = m_pos.copy(), m_neg.copy()
                    for k in ks:
                        mp &= k.evaluasi(pos); mn &= k.evaluasi(neg)
                    calon.append((mp.mean() - mn.mean(), b["youden_j"], ks, b["kelompok"], mp, mn))
            if not calon:
                break
            # Di antara kandidat yang J-nya setara (selisih <= TOLERANSI_J), pilih yang paling
            # menekan false positive, lalu fitur dengan daya pisah tunggal tertinggi. Dengan
            # begitu kondisi tambahan benar-benar menambah ciri Mirai, bukan kondisi longgar
            # atau kondisi yang hanya mengulang kondisi sebelumnya (mis. TCP dan ack_flag).
            j_maks = max(c[0] for c in calon)
            setara = [c for c in calon if c[0] >= j_maks - C.TOLERANSI_J]
            terbaik = max(setara, key=lambda c: (-round(c[5].mean(), 5), c[1], c[0]))
            wajib = len(grup_dipakai) < C.MIN_KELOMPOK_PER_RULE
            if not wajib and terbaik[0] - j_saat_ini < min_gain:
                break
            j_saat_ini, _, ks, grup, m_pos, m_neg = terbaik
            kondisi.extend(ks); grup_dipakai.append(grup)
            jejak.append({"varian": varian, "langkah": len(grup_dipakai),
                          "kondisi": " AND ".join(k.teks() for k in ks),
                          "metode_ambang": ks[0].metode, "kelompok": grup,
                          "tpr_train": float(m_pos.mean()), "fpr_train": float(m_neg.mean()),
                          "youden_j_train": float(j_saat_ini)})
        alasan = "; ".join(ALASAN_KELOMPOK[g] for g in grup_dipakai)
        rules.append(Rule(id=f"R{i}", nama=f"Rule {varian}", varian=varian, kondisi=kondisi, alasan=alasan))
    return RuleSet(rules), pd.DataFrame(jejak)


# ---------------------------------------------------------------------------
# 6. Evaluasi
# ---------------------------------------------------------------------------

def evaluasi(ruleset: RuleSet, data: pd.DataFrame) -> dict:
    y = data["kelas"].isin(C.KELAS_MIRAI).to_numpy()
    matriks = ruleset.matriks(data)
    pred = matriks.any(axis=1).to_numpy()
    hasil = {"jumlah_data": int(len(data)), "biner": metrik_biner(y, pred)}

    per_kelas = []
    for kelas, idx in data.groupby("kelas", observed=True).indices.items():
        n = len(idx); terdeteksi = int(pred[idx].sum())
        per_kelas.append({"kelas": kelas, "jumlah": n, "ditandai_mirai": terdeteksi,
                          "persen_ditandai": 100 * terdeteksi / n,
                          "keterangan": "False Positive" if kelas == C.KELAS_NORMAL else "Detection rate"})
    hasil["per_kelas"] = per_kelas

    # Atribusi varian: rule pertama (urutan R1, R2, ...) yang terpenuhi menentukan label varian
    urutan = [r.id for r in ruleset.rules]
    label_rule = {r.id: r.varian for r in ruleset.rules}
    pertama = matriks[urutan].idxmax(axis=1).where(matriks.any(axis=1), None)
    pred_varian = pertama.map(lambda r: label_rule.get(r, C.KELAS_NORMAL) if r else C.KELAS_NORMAL)
    cm = pd.crosstab(data["kelas"].astype(str), pred_varian.astype(str))
    hasil["confusion_varian"] = {"index": cm.index.tolist(), "columns": cm.columns.tolist(),
                                 "data": cm.to_numpy().tolist()}

    # Kualitas rule (Liu dkk., 2021)
    kualitas = []
    for r in ruleset.rules:
        m = matriks[r.id].to_numpy()
        target = (data["kelas"] == r.varian).to_numpy()
        kualitas.append({
            "rule": r.id, "varian": r.varian, "panjang_rule": len(r.kondisi),
            "ketepatan_presisi": float((m & y).sum() / max(m.sum(), 1)),
            "cakupan_varian": float((m & target).sum() / max(target.sum(), 1)),
            "cakupan_semua_mirai": float((m & y).sum() / max(y.sum(), 1)),
            "false_positive": int((m & ~y).sum()),
            "cakupan_unik": float((m & ~matriks.drop(columns=r.id).any(axis=1).to_numpy() & y).sum() / max(y.sum(), 1)),
        })
    hasil["kualitas_rule"] = kualitas
    red = np.zeros((len(urutan), len(urutan)))
    for a, ra in enumerate(urutan):
        for b, rb in enumerate(urutan):
            ma, mb = matriks[ra].to_numpy(), matriks[rb].to_numpy()
            red[a, b] = (ma & mb).sum() / max((ma | mb).sum(), 1)
    hasil["redundansi_jaccard"] = {"rules": urutan, "data": red.tolist()}
    hasil["ukuran_ruleset"] = {"jumlah_rule": len(ruleset.rules),
                               "jumlah_kondisi": sum(len(r.kondisi) for r in ruleset.rules),
                               "fitur_dipakai": ruleset.fitur}
    return hasil


def ukur_waktu(ruleset: RuleSet, data: pd.DataFrame, ulang: int = 5) -> dict:
    sub = data[ruleset.fitur]
    waktu = []
    for _ in range(ulang):
        t0 = time.perf_counter(); ruleset.prediksi(sub); waktu.append(time.perf_counter() - t0)
    med = float(np.median(waktu))
    # latensi per baris jika dijalankan satu per satu (gaya perangkat edge/streaming)
    contoh = sub.head(2000).to_dict("records")
    t0 = time.perf_counter()
    for baris in contoh:
        for r in ruleset.rules:
            if all(OPS_PY[k.op](baris[k.fitur], k.ambang) for k in r.kondisi):
                break
    per_baris = (time.perf_counter() - t0) / len(contoh)
    return {"baris_uji": int(len(data)), "ulangan": ulang, "waktu_batch_detik": med,
            "throughput_baris_per_detik": len(data) / med,
            "latensi_per_baris_mikrodetik": per_baris * 1e6,
            "waktu_semua_ulangan": waktu}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    t_total = time.perf_counter()

    log("1. Memuat data ...")
    df_raw, inventaris = muat_data(C.DATA_DIR)
    inventaris.to_csv(OUT / "01_inventaris_file.csv", index=False)
    fitur_asli = [c for c in df_raw.columns if c not in ("kelas", "file", "nomor_file")]
    tabel_status_fitur(fitur_asli).to_csv(OUT / "02_status_fitur.csv", index=False)
    pd.DataFrame(C.PEMETAAN_FITUR_PROPOSAL, columns=["fitur_proposal", "fitur_dipakai", "catatan"]) \
        .to_csv(OUT / "02b_pemetaan_fitur_proposal.csv", index=False)
    jendela = (df_raw.groupby("kelas", observed=True)["Number"]
               .agg(lambda s: s.value_counts(normalize=True).head(1).to_dict()))
    simpan_json({k: {str(int(n)): float(p) for n, p in v.items()} for k, v in jendela.items()},
                "02c_ukuran_jendela.json")

    log("2. Preprocessing ...")
    ddos = df_raw["kelas"].astype(str).str.startswith(C.PREFIX_DDOS)
    df_ddos_raw = df_raw.loc[ddos]
    df, ringkas_pre, fitur = preprocessing(df_raw.loc[~ddos].assign(kelas=lambda d: d["kelas"].astype(str)))
    del df_raw
    df["kelas"] = pd.Categorical(df["kelas"], categories=C.KELAS_UTAMA)
    ringkas_pre.to_csv(OUT / "03_preprocessing.csv", index=False)
    fitur_rule = [f for f in C.FITUR_RULE if f in fitur]
    fitur_analisis = [f for f in fitur if f not in ("Number",)]

    log("3. Membagi data (stratified 70/30) ...")
    mask_uji = bagi_acak(df)
    train, test = df.loc[~mask_uji].reset_index(drop=True), df.loc[mask_uji].reset_index(drop=True)
    pembagian = pd.DataFrame({"penyusunan_rule": train["kelas"].value_counts(),
                              "uji": test["kelas"].value_counts()}).reindex(C.KELAS_UTAMA)
    pembagian.rename_axis("kelas").reset_index().to_csv(OUT / "04_pembagian_data.csv", index=False)

    log("4. Analisis karakteristik (data penyusunan saja) ...")
    statistik_karakteristik(train, fitur_analisis).to_csv(OUT / "05_statistik_karakteristik.csv", index=False)
    analisis_keterpisahan(train, fitur_analisis).to_csv(OUT / "06_keterpisahan_fitur.csv", index=False)

    log("5. Menyusun rule ...")
    t0 = time.perf_counter()
    ruleset, jejak = susun_rule(train, fitur_rule)
    waktu_susun = time.perf_counter() - t0
    ruleset.to_json(OUT / "rules.json")
    jejak.to_csv(OUT / "07_jejak_penyusunan_rule.csv", index=False)
    for r in ruleset.rules:
        log(f"   {r.id}: {r.teks()}")

    log("6. Evaluasi pada data uji (Skenario 1) ...")
    hasil = evaluasi(ruleset, test)
    hasil["evaluasi_data_penyusunan"] = metrik_biner(train["kelas"].isin(C.KELAS_MIRAI), ruleset.prediksi(train))
    simpan_json(hasil, "08_evaluasi_skenario1.json")
    b = hasil["biner"]
    log(f"   Acc={b['accuracy']:.4f} P={b['precision']:.4f} R={b['recall']:.4f} F1={b['f1']:.4f} FP={b['FP']} FN={b['FN']}")

    waktu = ukur_waktu(ruleset, test)
    waktu["waktu_penyusunan_rule_detik"] = waktu_susun
    waktu["catatan"] = ("Penyusunan rule hanya menghitung statistik ambang (tanpa iterasi pelatihan). "
                        "Pembanding: Guven & Gurkas-Aydin (2023) melaporkan pelatihan ANN > 23 jam.")
    simpan_json(waktu, "09_waktu_eksekusi.json")

    log("7a. Ablasi fitur (dengan/tanpa fitur 'hati-hati') ...")
    skenario_ablasi = {
        "Semua fitur kandidat": fitur_rule,
        "Tanpa IAT": [f for f in fitur_rule if f != "IAT"],
        "Tanpa Std/Min/Max (sensitif ukuran jendela)": [f for f in fitur_rule if f not in ("Std", "Min", "Max")],
        "Tanpa Protocol Type": [f for f in fitur_rule if f != "Protocol Type"],
        "Tanpa Rate": [f for f in fitur_rule if f != "Rate"],
    }
    ablasi = []
    for nama, fs in skenario_ablasi.items():
        rs, _ = susun_rule(train, fs)
        m = metrik_biner(test["kelas"].isin(C.KELAS_MIRAI), rs.prediksi(test))
        ablasi.append({"skenario": nama, **{k: m[k] for k in ("accuracy", "precision", "recall", "f1", "FP", "FN")},
                       "rule": " | ".join(f"{r.id}: " + " AND ".join(k.teks() for k in r.kondisi) for r in rs.rules)})
    pd.DataFrame(ablasi).to_csv(OUT / "10_ablasi_fitur.csv", index=False)

    log("7b. Uji ketahanan file-holdout ...")
    mask_file = bagi_per_file(df)
    rs_file, _ = susun_rule(df.loc[~mask_file], fitur_rule)
    uji_file = df.loc[mask_file]
    hasil_file = evaluasi(rs_file, uji_file)
    hasil_file["file_uji"] = sorted(uji_file["file"].unique().tolist())
    hasil_file["rules"] = [r.teks() for r in rs_file.rules]
    simpan_json(hasil_file, "11_evaluasi_file_holdout.json")
    bf = hasil_file["biner"]
    log(f"   File-holdout: F1={bf['f1']:.4f} R={bf['recall']:.4f} FP={bf['FP']}")

    log("7c. Skenario 2 (DDoS non-Mirai) ...")
    if len(df_ddos_raw):
        d2 = df_ddos_raw.replace([np.inf, -np.inf], np.nan).dropna()
        pred2 = ruleset.prediksi(d2)
        per = (pd.DataFrame({"kelas": d2["kelas"].astype(str), "ditandai": pred2})
               .groupby("kelas")["ditandai"].agg(jumlah="size", salah_ditandai_mirai="sum").reset_index())
        per["persen"] = 100 * per["salah_ditandai_mirai"] / per["jumlah"]
        simpan_json({"tersedia": True, "per_kelas": per.to_dict("records"),
                     "kekhususan": float(1 - pred2.mean())}, "12_skenario2.json")
    else:
        simpan_json({"tersedia": False,
                     "pesan": "File DDoS non-Mirai (mis. DDoS-UDP_Flood*.pcap.csv) belum ada di folder dataset2023. "
                              "Tambahkan file tersebut lalu jalankan ulang pipeline.py."}, "12_skenario2.json")

    log("8. Menyimpan sampel untuk antarmuka ...")
    def sampel(d: pd.DataFrame, n: int) -> pd.DataFrame:
        rng = np.random.default_rng(C.RANDOM_SEED)
        idx = [rng.choice(ix, size=min(n, len(ix)), replace=False)
               for ix in d.groupby("kelas", observed=True).indices.values()]
        return d.iloc[np.concatenate(idx)]
    s_train = sampel(train, C.SAMPLE_PER_CLASS).assign(bagian="penyusunan")
    s_test = sampel(test, C.SAMPLE_PER_CLASS).assign(bagian="uji")
    s = pd.concat([s_train, s_test], ignore_index=True)
    s["kelas"] = s["kelas"].astype(str)
    s.to_parquet(OUT / "sampel.parquet", index=False)

    simpan_json({"waktu_pipeline_detik": time.perf_counter() - t_total,
                 "dibuat": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "seed": C.RANDOM_SEED, "test_size": C.TEST_SIZE,
                 "fitur_analisis": fitur_analisis, "fitur_rule": fitur_rule}, "00_meta.json")
    log(f"Selesai dalam {time.perf_counter() - t_total:.1f} detik. Hasil di {OUT}")


if __name__ == "__main__":
    main()
