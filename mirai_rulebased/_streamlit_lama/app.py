"""Antarmuka Streamlit: Deteksi Mirai Botnet berbasis Rule-Based (CICIoT2023).

Jalankan dari folder ini:
    streamlit run app.py
Pastikan pipeline.py sudah dijalankan agar folder output/ terisi.
"""
from __future__ import annotations

import io
import json
import re
import time

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import config as C
import tampilan as T
from rules import Rule, RuleSet, metrik_biner

st.set_page_config(page_title="Mirai Detector", page_icon="🛡️", layout="wide")
T.pasang_css()

OUT = C.OUTPUT_DIR
PENULIS, NIM = "Aprilah Puspitasari", "60200122092"


# ---------------------------------------------------------------------------
# Data hasil pipeline
# ---------------------------------------------------------------------------

def baca_json(nama):
    with open(OUT / nama, encoding="utf-8") as f:
        return json.load(f)


@st.cache_data
def muat_hasil():
    return {
        "meta": baca_json("00_meta.json"),
        "inventaris": pd.read_csv(OUT / "01_inventaris_file.csv"),
        "status_fitur": pd.read_csv(OUT / "02_status_fitur.csv"),
        "pemetaan": pd.read_csv(OUT / "02b_pemetaan_fitur_proposal.csv"),
        "jendela": baca_json("02c_ukuran_jendela.json"),
        "pre": pd.read_csv(OUT / "03_preprocessing.csv"),
        "bagi": pd.read_csv(OUT / "04_pembagian_data.csv"),
        "stat": pd.read_csv(OUT / "05_statistik_karakteristik.csv"),
        "sep": pd.read_csv(OUT / "06_keterpisahan_fitur.csv"),
        "jejak": pd.read_csv(OUT / "07_jejak_penyusunan_rule.csv"),
        "eval": baca_json("08_evaluasi_skenario1.json"),
        "waktu": baca_json("09_waktu_eksekusi.json"),
        "ablasi": pd.read_csv(OUT / "10_ablasi_fitur.csv"),
        "holdout": baca_json("11_evaluasi_file_holdout.json"),
        "skenario2": baca_json("12_skenario2.json"),
    }


@st.cache_data
def muat_sampel():
    return pd.read_parquet(OUT / "sampel.parquet")


if not (OUT / "rules.json").exists():
    st.error("Folder output/ belum berisi hasil. Jalankan dulu:  `python pipeline.py`")
    st.stop()

H = muat_hasil()
RS = RuleSet.from_json(OUT / "rules.json")


# ---------------------------------------------------------------------------
# Fungsi bantu
# ---------------------------------------------------------------------------

def pct(x, d=2):
    return f"{100 * x:.{d}f}%"


def angka(x):
    return f"{x:,}".replace(",", ".")


def kelas_dari_nama_file(nama: str) -> str | None:
    k = re.sub(r"\d*(\.pcap)?(\s*\(\d+\))?\.csv$", "", nama, flags=re.I).strip()
    return k if k in C.KELAS_UTAMA or k.startswith(C.PREFIX_DDOS) else None


def nama_protokol(v: float) -> str:
    return {6.0: "TCP", 17.0: "UDP", 47.0: "GRE", 1.0: "ICMP"}.get(float(v), "Campuran/lainnya")


def grafik_confusion(m: dict, judul="Confusion Matrix"):
    z = [[m["TN"], m["FP"]], [m["FN"], m["TP"]]]
    total = max(sum(map(sum, z)), 1)
    teks = [[f"{angka(v)}<br>({100 * v / total:.2f}%)" for v in r] for r in z]
    fig = go.Figure(go.Heatmap(
        z=z, x=["Prediksi Normal", "Prediksi Mirai"], y=["Aktual Normal", "Aktual Mirai"],
        text=teks, texttemplate="%{text}", colorscale=T.SKALA_BIRU, showscale=False, xgap=3, ygap=3,
        hovertemplate="%{y} · %{x}<br>Jumlah: %{z:,}<extra></extra>"))
    fig.update_layout(title=judul, yaxis=dict(autorange="reversed"))
    return T.gaya_plot(fig, 330)


def donut(nilai: dict, judul: str, warna: dict, tengah: str = "", tinggi: int = 320):
    total = max(sum(nilai.values()), 1)
    # label persentase hanya untuk irisan >= 5% agar tidak bertumpuk; sisanya lewat legenda/hover
    teks = [f"{100 * v / total:.1f}%" if v / total >= 0.05 else "" for v in nilai.values()]
    fig = go.Figure(go.Pie(labels=list(nilai), values=list(nilai.values()), hole=0.62, sort=False,
                           marker=dict(colors=[warna.get(k, "#9aa6b8") for k in nilai],
                                       line=dict(color="#fff", width=2)),
                           text=teks, textinfo="text", textposition="outside",
                           hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>"))
    fig.update_layout(title=judul, showlegend=True,
                      legend=dict(orientation="h", yanchor="top", y=-0.05, xanchor="center", x=0.5),
                      annotations=[dict(text=tengah, showarrow=False, font=dict(size=15))])
    return T.gaya_plot(fig, tinggi)


def kartu_metrik(m: dict):
    T.baris_kartu([
        T.kartu("target", "Accuracy", pct(m["accuracy"]), nada="biru"),
        T.kartu("check", "Precision", pct(m["precision"]), nada="hijau"),
        T.kartu("activity", "Recall", pct(m["recall"]), nada="ungu"),
        T.kartu("shield", "F1-Score", pct(m["f1"]), nada="biru"),
        T.kartu("alert", "False Positive", angka(m["FP"]), "normal ditandai Mirai", "oranye"),
        T.kartu("alert", "False Negative", angka(m["FN"]), "Mirai lolos", "merah"),
    ])


def tabel_aturan(rules: list[Rule]) -> str:
    baris = "".join(
        f"<tr><td>{i}</td><td>IF " + " <b>AND</b> ".join(f"<code>{k.teks()}</code>" for k in r.kondisi) +
        f"<br><span style='color:{T.TINTA_2};font-size:.8rem'>{r.alasan}</span></td>"
        f"<td>{r.varian}</td><td>Tandai sebagai {T.lencana('Mirai')}</td></tr>"
        for i, r in enumerate(rules, start=1))
    baris += (f"<tr><td>–</td><td><i>Tidak ada rule yang terpenuhi</i></td><td>–</td>"
              f"<td>Tandai sebagai {T.lencana('Normal')}</td></tr>")
    return ("<table class='aturan'><tr><th style='width:40px'>No</th><th>Kondisi (IF)</th>"
            "<th style='width:170px'>Sasaran varian</th><th style='width:190px'>Aksi (THEN)</th></tr>"
            f"{baris}</table>")


def jalankan_deteksi(data: pd.DataFrame) -> dict:
    x = data[RS.fitur].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    valid = x.notna().all(axis=1).to_numpy()
    t0 = time.perf_counter()
    xv = x[valid]
    pred = RS.prediksi(xv)
    alasan = RS.jelaskan(xv).to_numpy()
    durasi = time.perf_counter() - t0
    hasil = data.copy()
    kol_pred = np.full(len(hasil), "Tidak valid", dtype=object)
    kol_pred[valid] = np.where(pred, "Mirai", "Normal")
    kol_rule = np.full(len(hasil), "-", dtype=object)
    kol_rule[valid] = alasan
    hasil.insert(0, "Prediksi", kol_pred)
    hasil.insert(1, "Rule terpenuhi", kol_rule)
    return {"hasil": hasil, "durasi": durasi, "n_tidak_valid": int((~valid).sum())}


# ---------------------------------------------------------------------------
# Riwayat deteksi (disimpan di output/riwayat/ agar tetap ada setelah aplikasi ditutup)
# ---------------------------------------------------------------------------

DIR_RIWAYAT = OUT / "riwayat"
FILE_RIWAYAT = DIR_RIWAYAT / "riwayat_deteksi.csv"


def muat_riwayat() -> pd.DataFrame:
    if not FILE_RIWAYAT.exists():
        return pd.DataFrame()
    return pd.read_csv(FILE_RIWAYAT, dtype={"id": str})


def simpan_riwayat(det: dict, sumber: str) -> None:
    """Catat ringkasan satu kali deteksi + simpan tabel hasilnya untuk diunduh ulang."""
    DIR_RIWAYAT.mkdir(parents=True, exist_ok=True)
    hasil = det["hasil"]
    rid = time.strftime("%Y%m%d_%H%M%S")
    n = len(hasil)
    n_mirai = int((hasil["Prediksi"] == "Mirai").sum())
    n_normal = int((hasil["Prediksi"] == "Normal").sum())
    baris = {"id": rid, "waktu": time.strftime("%Y-%m-%d %H:%M:%S"), "sumber_data": sumber,
             "jumlah_baris": n, "mirai": n_mirai, "normal": n_normal,
             "tidak_valid": det["n_tidak_valid"], "persen_mirai": round(100 * n_mirai / max(n, 1), 2),
             "durasi_ms": round(det["durasi"] * 1000, 1),
             "accuracy": None, "precision": None, "recall": None, "f1": None, "FP": None, "FN": None}
    if "kelas" in hasil.columns:
        sah = hasil[hasil["Prediksi"] != "Tidak valid"]
        m = metrik_biner(sah["kelas"].astype(str).str.startswith("Mirai"), sah["Prediksi"] == "Mirai")
        baris.update({k: m[k] for k in ("accuracy", "precision", "recall", "f1", "FP", "FN")})
    kolom = ["Prediksi", "Rule terpenuhi"] + [k for k in ("kelas", "file") if k in hasil.columns] + RS.fitur
    hasil[kolom].to_csv(DIR_RIWAYAT / f"{rid}.csv.gz", index=False, compression="gzip")
    riwayat = pd.concat([muat_riwayat(), pd.DataFrame([baris])], ignore_index=True)
    riwayat.to_csv(FILE_RIWAYAT, index=False)


def tampilkan_riwayat() -> None:
    st.markdown("##### Riwayat Hasil Deteksi")
    riwayat = muat_riwayat()
    if riwayat.empty:
        st.info("Belum ada riwayat. Setiap kali tombol **Mulai Deteksi** dijalankan, hasilnya tercatat di sini.")
        return
    riwayat = riwayat.iloc[::-1].reset_index(drop=True)      # terbaru di atas
    tampil = riwayat.drop(columns="id").rename(columns={
        "waktu": "Waktu", "sumber_data": "Sumber data", "jumlah_baris": "Jumlah baris", "mirai": "Mirai",
        "normal": "Normal", "tidak_valid": "Tidak valid", "persen_mirai": "% Mirai", "durasi_ms": "Durasi (ms)",
        "accuracy": "Accuracy", "precision": "Precision", "recall": "Recall", "f1": "F1-Score"})
    with st.container(border=True):
        st.dataframe(tampil.style.format({c: "{:.2%}" for c in ("Accuracy", "Precision", "Recall", "F1-Score")},
                                         na_rep="–")
                     .format({"% Mirai": "{:.2f}%", "Durasi (ms)": "{:,.1f}"})
                     .format({c: "{:,.0f}" for c in ("FP", "FN")}, na_rep="–"),
                     hide_index=True, width="stretch")
        st.caption(f"{angka(len(riwayat))} kali deteksi tercatat. Accuracy dan lainnya hanya terisi jika data berlabel.")
        c1, c2, c3 = st.columns([3, 1.4, 1])
        pilih = c1.selectbox("Unduh hasil deteksi lama", riwayat.index, label_visibility="collapsed",
                             format_func=lambda i: f"{riwayat.at[i, 'waktu']} · {riwayat.at[i, 'sumber_data']}"[:120])
        f = DIR_RIWAYAT / f"{riwayat.at[pilih, 'id']}.csv.gz"
        if f.exists():
            c2.download_button("Unduh hasil (CSV)", f.read_bytes(), f"hasil_deteksi_{riwayat.at[pilih, 'id']}.csv.gz",
                               "application/gzip", width="stretch")
        if c3.button("Hapus riwayat", width="stretch"):
            for p in DIR_RIWAYAT.glob("*"):
                p.unlink()
            st.rerun()


# ---------------------------------------------------------------------------
# Sidebar & navigasi
# ---------------------------------------------------------------------------

MENU = {
    "Beranda": ":material/home:",
    "Upload Data": ":material/upload:",
    "Analisis Trafik": ":material/monitoring:",
    "Deteksi Mirai": ":material/shield:",
    "Hasil Deteksi": ":material/list_alt:",
    "Evaluasi Sistem": ":material/analytics:",
    "Tentang": ":material/info:",
}
if "_pindah" in st.session_state:
    st.session_state["menu"] = st.session_state.pop("_pindah")

with st.sidebar:
    st.markdown(f'<div class="brand">{T.ikon("shield", "#ffffff", 34, 2)}'
                '<div><div class="brand-judul">Mirai Detector</div>'
                '<div class="brand-sub">IoT Security</div></div></div>', unsafe_allow_html=True)
    hal = st.radio("Menu", list(MENU), key="menu", label_visibility="collapsed",
                   format_func=lambda k: f"{MENU[k]}&nbsp;&nbsp;{k}")
    st.markdown(f'<div class="pengguna">{T.ikon("user", "#c9d4e5", 22)}'
                f'<div><b style="color:#fff">{PENULIS}</b><br>NIM {NIM}</div></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# 1. Beranda
# ---------------------------------------------------------------------------

if hal == "Beranda":
    st.markdown(
        f'<div class="hero">{T.ikon("shield", T.BIRU, 92, 1.6)}<div>'
        '<div class="hero-judul">Deteksi Serangan Mirai Botnet<br>pada Perangkat IoT</div>'
        '<div class="hero-sub">Menggunakan Metode Rule-Based Berbasis Trafik Jaringan · Dataset CICIoT2023</div>'
        '</div></div>', unsafe_allow_html=True)
    st.markdown("Aplikasi ini digunakan untuk **menganalisis karakteristik trafik jaringan**, menyusun "
                "**aturan deteksi (rule-based)**, dan **mengidentifikasi aktivitas Mirai Botnet** "
                "(varian GREeth Flood, GREIP Flood, dan UDPplain) pada perangkat IoT.")

    b = H["eval"]["biner"]
    st.markdown("##### Hasil pengujian pada data uji")
    T.baris_kartu([
        T.kartu("database", "Total Data Uji", angka(H["eval"]["jumlah_data"]), "baris trafik", "hijau"),
        T.kartu("shield", "Diprediksi Mirai", angka(b["TP"] + b["FP"]), "baris", "biru"),
        T.kartu("check", "Diprediksi Normal", angka(b["TN"] + b["FN"]), "baris", "oranye"),
        T.kartu("target", "Akurasi", pct(b["accuracy"]), f"F1-Score {pct(b['f1'])}", "ungu"),
    ])

    st.markdown("##### Aturan deteksi yang digunakan")
    st.markdown(tabel_aturan(RS.rules), unsafe_allow_html=True)
    st.markdown('<div class="kutipan">"Deteksi dini, keamanan IoT lebih terjaga"</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# 2. Upload Data
# ---------------------------------------------------------------------------

elif hal == "Upload Data":
    st.title("Upload Dataset")
    st.caption("Unggah file trafik jaringan (CSV) berformat CICIoT2023 per-PCAP, atau gunakan sampel data uji.")

    with st.container(border=True):
        files = st.file_uploader("Drag and drop file di sini", type="csv", accept_multiple_files=True)
        c1, c2 = st.columns([1, 1])
        pakai_upload = c1.button("Gunakan file yang diunggah", type="primary", disabled=not files,
                                 width="stretch")
        pakai_sampel = c2.button("Gunakan sampel data uji (120.000 baris)", width="stretch")

    if pakai_upload and files:
        bagian = []
        for f in files:
            d = pd.read_csv(f, low_memory=False)
            kol_label = next((c for c in d.columns if c.lower() in ("label", "kelas")), None)
            if kol_label:
                d = d.rename(columns={kol_label: "kelas"})
            elif kelas_dari_nama_file(f.name):
                d["kelas"] = kelas_dari_nama_file(f.name)
            d["file"] = f.name
            bagian.append(d)
        st.session_state["data"] = pd.concat(bagian, ignore_index=True)
        st.session_state["sumber"] = ", ".join(f.name for f in files)
        st.session_state.pop("deteksi", None)
    if pakai_sampel:
        s = muat_sampel()
        st.session_state["data"] = s[s["bagian"] == "uji"].drop(columns="bagian").reset_index(drop=True)
        st.session_state["sumber"] = "Sampel data uji (30.000 baris per kelas)"
        st.session_state.pop("deteksi", None)

    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("**Format yang didukung:** `.csv`")
        st.markdown("**Atribut yang dibutuhkan rule:**")
        st.markdown("\n".join(f"- `{f}`" for f in RS.fitur))
    with c2:
        st.markdown("**Label (opsional, untuk menghitung akurasi):**")
        st.markdown("- kolom `label` / `kelas`, atau\n"
                    "- nama file CICIoT2023, mis. `Mirai-udpplain3.pcap.csv`, `BenignTraffic.pcap.csv`")

    if "data" in st.session_state:
        d = st.session_state["data"]
        hilang = [f for f in RS.fitur if f not in d.columns]
        st.divider()
        st.markdown(f"**Data aktif:** {st.session_state['sumber']}")
        T.baris_kartu([
            T.kartu("database", "Jumlah baris", angka(len(d)), nada="biru"),
            T.kartu("list", "Jumlah kolom", angka(d.shape[1]), nada="ungu"),
            T.kartu("check" if not hilang else "alert", "Atribut rule",
                    "Lengkap" if not hilang else "Kurang", ", ".join(hilang), "hijau" if not hilang else "merah"),
            T.kartu("info", "Label", "Ada" if "kelas" in d.columns else "Tidak ada",
                    "akurasi dapat dihitung" if "kelas" in d.columns else "hanya prediksi", "oranye"),
        ])
        st.dataframe(d.head(100), width="stretch", height=280)
        if not hilang:
            if st.button("Lanjut ke Deteksi Mirai →", type="primary"):
                st.session_state["_pindah"] = "Deteksi Mirai"
                st.rerun()


# ---------------------------------------------------------------------------
# 3. Analisis Trafik
# ---------------------------------------------------------------------------

elif hal == "Analisis Trafik":
    st.title("Analisis Trafik Jaringan")
    st.caption("Karakteristik trafik Normal vs Mirai (Rumusan Masalah 1). Hanya memakai **data penyusunan rule**.")
    sampel = muat_sampel()
    train_s = sampel[sampel["bagian"] == "penyusunan"]
    t1, t2, t3, t4 = st.tabs(["Distribusi Protokol", "Sebaran Fitur", "Daya Pisah Fitur", "Ringkasan Karakteristik"])

    with t1:
        warna_p = {"TCP": "#2a78d6", "UDP": "#eda100", "GRE": "#e34948", "ICMP": "#1baf7a",
                   "Campuran/lainnya": "#9aa6b8"}
        urut = ["TCP", "UDP", "GRE", "ICMP", "Campuran/lainnya"]
        for baris in (C.KELAS_UTAMA[:2], C.KELAS_UTAMA[2:]):
            for col, kelas in zip(st.columns(2), baris):
                p = train_s.loc[train_s["kelas"] == kelas, "Protocol Type"].map(nama_protokol).value_counts()
                nilai = {k: int(p.get(k, 0)) for k in urut if p.get(k, 0) > 0}
                dominan = max(nilai, key=nilai.get)
                tengah = f"<b>{dominan}</b><br>{100 * nilai[dominan] / sum(nilai.values()):.1f}%"
                with col, st.container(border=True):
                    st.plotly_chart(donut(nilai, kelas, warna_p, tengah, 340), width="stretch")
        st.caption("`Protocol Type` adalah protokol dominan dalam satu jendela paket. "
                   "Trafik normal didominasi TCP, GREeth/GREIP memakai **GRE (47)**, UDPplain memakai **UDP (17)**.")

    with t2:
        fitur_list = H["meta"]["fitur_analisis"]
        c1, c2, c3 = st.columns([2, 1, 1])
        f = c1.selectbox("Fitur", fitur_list, index=fitur_list.index("AVG"))
        log_x = c2.checkbox("Skala log", value=f in ("Rate", "IAT", "Std"))
        jenis = c3.radio("Grafik", ["Histogram", "Box plot"], horizontal=True)
        d = train_s[[f, "kelas"]]
        if log_x:
            d = d[d[f] > 0]
        with st.container(border=True):
            if jenis == "Histogram":
                fig = px.histogram(d, x=f, color="kelas", color_discrete_map=T.WARNA_KELAS, nbins=80,
                                   barmode="overlay", histnorm="percent", log_x=log_x, opacity=0.6,
                                   category_orders={"kelas": C.KELAS_UTAMA})
                fig.update_layout(yaxis_title="% baris dalam kelas")
            else:
                fig = px.box(d, x="kelas", y=f, color="kelas", color_discrete_map=T.WARNA_KELAS, log_y=log_x,
                             category_orders={"kelas": C.KELAS_UTAMA}, points=False)
                fig.update_layout(showlegend=False, xaxis_title=None)
            st.plotly_chart(T.gaya_plot(fig, 400), width="stretch")
        stat = H["stat"]
        tab = stat[stat["fitur"] == f].pivot(index="kelas", columns="statistik", values="nilai")
        st.markdown(f"**Statistik `{f}` per kelas**")
        st.dataframe(tab[["mean", "std", "p05", "median", "p95"]].reindex(C.KELAS_UTAMA).style.format("{:,.4g}"),
                     width="stretch")

    with t3:
        sep = H["sep"]
        piv = sep.pivot(index="fitur", columns="varian", values="youden_j")
        piv = piv.loc[piv.mean(axis=1).sort_values(ascending=False).index].head(15)
        with st.container(border=True):
            fig = px.imshow(piv, color_continuous_scale=T.SKALA_BIRU, zmin=0, zmax=1, aspect="auto",
                            text_auto=".2f", labels=dict(color="Youden J"))
            fig.update_traces(xgap=2, ygap=2, hovertemplate="%{y} · %{x}<br>Youden J: %{z:.3f}<extra></extra>")
            fig.update_layout(title="15 fitur dengan daya pisah tertinggi (Mirai vs Normal)",
                              xaxis_title=None, yaxis_title=None)
            st.plotly_chart(T.gaya_plot(fig, 520), width="stretch")
        st.caption("Youden J = TPR − FPR pada titik potong terbaik (1 = terpisah sempurna, 0 = tidak membedakan). "
                   "Dasar penentuan ambang batas rule.")

    with t4:
        st.markdown("""
| Karakteristik | Normal (BenignTraffic) | Mirai GREeth / GREIP | Mirai UDPplain |
|---|---|---|---|
| Jenis protokol | dominan TCP (6), sebagian UDP | **GRE (47)** | **UDP (17)** |
| Panjang header (`Header_Length`) | ~20–32 (header TCP) | **≈ 0** (GRE tanpa header TCP/UDP) | ≈ 8 (header UDP) |
| Flag TCP (`ack_flag_number`) | tinggi (sesi TCP) | ≈ 0 | ≈ 0 |
| Ukuran paket (`AVG`) | bervariasi (median ~250 B) | **seragam ~578–592 B** | **seragam ~554 B** |
| Laju paket (`Rate`) | median ~170 paket/detik | median ~4.000–4.700 | median ~5.000 |
""")
        kotak = ("Flood Mirai pada dataset ini dikenali dari <b>protokol yang seragam</b> (GRE atau UDP), "
                 "<b>tidak adanya sesi TCP</b>, dan <b>ukuran paket besar yang seragam</b>. Ciri-ciri inilah yang "
                 "diterjemahkan menjadi aturan IF-THEN.")
        T.kotak_info("Kesimpulan", kotak)


# ---------------------------------------------------------------------------
# 4. Deteksi Mirai
# ---------------------------------------------------------------------------

elif hal == "Deteksi Mirai":
    st.title("Deteksi Mirai Botnet (Rule-Based)")
    T.kotak_info("Metode yang digunakan:",
                 "Rule-Based berbasis analisis trafik jaringan. Sistem memeriksa setiap baris trafik terhadap "
                 "aturan IF-THEN. Jika <b>minimal satu aturan terpenuhi</b>, trafik ditandai <b>Mirai</b>; "
                 "jika tidak, ditandai <b>Normal</b>. Tidak ada proses pelatihan model.", "shield")
    st.markdown("##### Aturan Deteksi")
    st.markdown(tabel_aturan(RS.rules), unsafe_allow_html=True)

    with st.expander("Dasar penentuan ambang batas"):
        st.markdown("Ambang batas diturunkan dari data penyusunan (70%): titik potong dengan tumpang tindih "
                    "terkecil (Youden J) atau persentil 1/99 kelas Mirai. Setiap aturan memakai minimal dua "
                    "kelompok indikator berbeda.")
        st.dataframe(H["jejak"].style.format({"tpr_train": "{:.4f}", "fpr_train": "{:.5f}",
                                              "youden_j_train": "{:.4f}"}), hide_index=True, width="stretch")

    st.write("")
    if "data" not in st.session_state:
        st.warning("Belum ada data. Unggah file di menu **Upload Data**, atau gunakan sampel data uji.")
        if st.button("Gunakan sampel data uji"):
            s = muat_sampel()
            st.session_state["data"] = s[s["bagian"] == "uji"].drop(columns="bagian").reset_index(drop=True)
            st.session_state["sumber"] = "Sampel data uji (30.000 baris per kelas)"
            st.rerun()
    else:
        d = st.session_state["data"]
        hilang = [f for f in RS.fitur if f not in d.columns]
        st.caption(f"Data aktif: {st.session_state['sumber']} · {angka(len(d))} baris")
        if hilang:
            st.error(f"Kolom yang dibutuhkan rule tidak ada: {hilang}")
        elif st.button("▶  Mulai Deteksi", type="primary", width="stretch"):
            with st.spinner("Memeriksa trafik terhadap aturan ..."):
                st.session_state["deteksi"] = jalankan_deteksi(d)
                simpan_riwayat(st.session_state["deteksi"], st.session_state["sumber"])
            st.session_state["_pindah"] = "Hasil Deteksi"
            st.rerun()


# ---------------------------------------------------------------------------
# 5. Hasil Deteksi
# ---------------------------------------------------------------------------

elif hal == "Hasil Deteksi":
    st.title("Hasil Deteksi")
    if "deteksi" not in st.session_state:
        st.info("Belum ada hasil pada sesi ini. Jalankan deteksi di menu **Deteksi Mirai**.")
        tampilkan_riwayat()
        st.stop()
    det = st.session_state["deteksi"]
    hasil = det["hasil"]
    n = len(hasil)
    n_mirai = int((hasil["Prediksi"] == "Mirai").sum())
    n_normal = int((hasil["Prediksi"] == "Normal").sum())
    ada_label = "kelas" in hasil.columns
    sah = hasil[hasil["Prediksi"] != "Tidak valid"]
    m = metrik_biner(sah["kelas"].astype(str).str.startswith("Mirai"), sah["Prediksi"] == "Mirai") if ada_label else None

    T.baris_kartu([
        T.kartu("check", "Data Normal", angka(n_normal), f"({100 * n_normal / n:.1f}%)", "hijau"),
        T.kartu("alert", "Data Mirai", angka(n_mirai), f"({100 * n_mirai / n:.1f}%)", "merah"),
        T.kartu("target", "Akurasi", pct(m["accuracy"], 1) if m else "–",
                f"F1-Score {pct(m['f1'], 1)}" if m else "data tanpa label", "biru"),
        T.kartu("clock", "Waktu Deteksi", f"{det['durasi'] * 1000:.1f} ms", f"{angka(n)} baris", "ungu"),
    ])
    if det["n_tidak_valid"]:
        st.caption(f"{angka(det['n_tidak_valid'])} baris memiliki NaN/inf pada atribut rule dan ditandai 'Tidak valid'.")

    st.write("")
    with st.container(border=True):
        c1, c2 = st.columns([2, 1])
        c1.markdown("##### Contoh Hasil Deteksi")
        cari = c2.text_input("Cari", placeholder="Cari rule / kelas / file ...", label_visibility="collapsed")
        filt = st.segmented_control("Filter", ["Semua", "Mirai", "Normal"], default="Semua",
                                    label_visibility="collapsed")
        kolom = ["Prediksi", "Rule terpenuhi"] + [k for k in ("kelas", "file") if k in hasil.columns] + RS.fitur
        tampil = hasil[kolom]
        if filt in ("Mirai", "Normal"):
            tampil = tampil[tampil["Prediksi"] == filt]
        if cari:
            teks = tampil[[k for k in ("Rule terpenuhi", "kelas", "file") if k in tampil.columns]].astype(str)
            tampil = tampil[teks.apply(lambda s: s.str.contains(cari, case=False, regex=False)).any(axis=1)]
        warna = {"Mirai": "background-color:#fdeaea;color:#b42323;font-weight:600",
                 "Normal": "background-color:#e7f7ec;color:#0b6b2c;font-weight:600"}
        st.dataframe(tampil.head(1000).style.map(lambda v: warna.get(v, ""), subset=["Prediksi"])
                     .format({f: "{:,.4g}" for f in RS.fitur}),
                     hide_index=True, width="stretch", height=380)
        st.caption(f"Menampilkan {angka(min(len(tampil), 1000))} dari {angka(len(tampil))} baris.")
        buf = io.StringIO(); hasil[kolom].to_csv(buf, index=False)
        st.download_button("Unduh hasil deteksi (CSV)", buf.getvalue(), "hasil_deteksi.csv", "text/csv")

    c1, c2 = st.columns(2)
    with c1, st.container(border=True):
        st.plotly_chart(donut({"Normal": n_normal, "Mirai": n_mirai}, "Perbandingan Prediksi",
                              T.WARNA_BINER, f"{angka(n)}<br>data"), width="stretch")
    with c2, st.container(border=True):
        rc = hasil.loc[hasil["Prediksi"] == "Mirai", "Rule terpenuhi"].value_counts().head(6)
        fig = px.bar(x=rc.values, y=rc.index, orientation="h", text=[angka(v) for v in rc.values])
        fig.update_traces(marker_color=T.WARNA_BINER["Mirai"], marker_line_width=0)
        fig.update_layout(title="Rule yang paling sering terpenuhi", xaxis_title="jumlah baris", yaxis_title=None,
                          yaxis=dict(autorange="reversed"), bargap=0.4)
        st.plotly_chart(T.gaya_plot(fig, 320), width="stretch")

    if m:
        st.markdown("##### Evaluasi terhadap label")
        kartu_metrik(m)
        c1, c2 = st.columns(2)
        with c1, st.container(border=True):
            st.plotly_chart(grafik_confusion(m), width="stretch")
        with c2, st.container(border=True):
            st.markdown("**Prediksi per kelas aktual**")
            st.dataframe(pd.crosstab(sah["kelas"].astype(str), sah["Prediksi"]), width="stretch")

    st.write("")
    tampilkan_riwayat()


# ---------------------------------------------------------------------------
# 6. Evaluasi Sistem (Ringkasan)
# ---------------------------------------------------------------------------

elif hal == "Evaluasi Sistem":
    st.title("Ringkasan Sistem")
    st.caption("Evaluasi pada data uji penuh (30% data yang tidak dipakai menyusun rule) — Rumusan Masalah 2.")
    ev, b = H["eval"], H["eval"]["biner"]
    total = ev["jumlah_data"]
    mirai, normal = b["TP"] + b["FP"], b["TN"] + b["FN"]
    T.baris_kartu([
        T.kartu("database", "Total Data Uji", angka(total), nada="biru"),
        T.kartu("alert", "Diprediksi Mirai", angka(mirai), f"({100 * mirai / total:.1f}%)", "merah"),
        T.kartu("check", "Diprediksi Normal", angka(normal), f"({100 * normal / total:.1f}%)", "hijau"),
        T.kartu("clock", "Waktu Deteksi", f"{H['waktu']['waktu_batch_detik'] * 1000:.1f} ms",
                f"{H['waktu']['latensi_per_baris_mikrodetik']:.2f} µs per baris", "ungu"),
    ])
    st.write("")
    kartu_metrik(b)
    st.write("")

    c1, c2 = st.columns(2)
    with c1, st.container(border=True):
        st.plotly_chart(grafik_confusion(b), width="stretch")
    with c2, st.container(border=True):
        pk = pd.DataFrame(ev["per_kelas"])
        fig = px.bar(pk, x="persen_ditandai", y="kelas", orientation="h", color="kelas",
                     color_discrete_map=T.WARNA_KELAS, text=pk["persen_ditandai"].map(lambda v: f"{v:.2f}%"))
        fig.update_traces(marker_line_width=0)
        fig.update_layout(title="Persentase ditandai Mirai per kelas", showlegend=False, xaxis_title="%",
                          yaxis_title=None, yaxis=dict(autorange="reversed"), bargap=0.4, xaxis_range=[0, 112])
        st.plotly_chart(T.gaya_plot(fig, 330), width="stretch")
        st.caption("BenignTraffic = tingkat false positive; varian Mirai = detection rate.")

    t1, t2, t3, t4 = st.tabs(["Kualitas Rule", "Uji Ketahanan", "Skenario 2 (DDoS non-Mirai)",
                              "Perbandingan Data Penyusunan vs Uji"])
    with t1:
        kq = pd.DataFrame(ev["kualitas_rule"])
        st.dataframe(kq.style.format({c: "{:.4f}" for c in ("ketepatan_presisi", "cakupan_varian",
                                                             "cakupan_semua_mirai", "cakupan_unik")}),
                     hide_index=True, width="stretch")
        u = ev["ukuran_ruleset"]
        st.markdown(f"Kriteria Liu dkk. (2021): **{u['jumlah_rule']} rule**, **{u['jumlah_kondisi']} kondisi**, "
                    f"fitur: {', '.join(u['fitur_dipakai'])}. R1 dan R2 sama-sama bertumpu pada GRE sehingga "
                    "redundansinya tinggi (GREIP tidak dibedakan dari GREeth); hal ini tidak memengaruhi deteksi biner.")
    with t2:
        st.markdown("**Ablasi fitur**: rule disusun ulang tanpa fitur tertentu.")
        st.dataframe(H["ablasi"].style.format({c: "{:.4f}" for c in ("accuracy", "precision", "recall", "f1")}),
                     hide_index=True, width="stretch")
        st.markdown("**File-holdout**: rule disusun dari sebagian file, diuji pada file rekaman lain.")
        kartu_metrik(H["holdout"]["biner"])
    with t3:
        s2 = H["skenario2"]
        if s2["tersedia"]:
            st.metric("Kekhususan terhadap DDoS non-Mirai", pct(s2["kekhususan"]))
            st.dataframe(pd.DataFrame(s2["per_kelas"]), hide_index=True, width="stretch")
        else:
            st.warning(s2["pesan"])
    with t4:
        tr = ev["evaluasi_data_penyusunan"]
        st.dataframe(pd.DataFrame({
            "Data penyusunan": [tr[k] for k in ("accuracy", "precision", "recall", "f1", "fpr")],
            "Data uji": [b[k] for k in ("accuracy", "precision", "recall", "f1", "fpr")]},
            index=["Accuracy", "Precision", "Recall", "F1-Score", "False Positive Rate"]).style.format("{:.4f}"),
            width="stretch")
        st.caption("Selisih kecil menunjukkan rule tidak overfit pada data penyusunan.")
    T.kotak_info("Kesimpulan", "Sistem berhasil mendeteksi Mirai Botnet dengan metode rule-based berbasis "
                 f"analisis trafik jaringan: F1-Score <b>{pct(b['f1'])}</b>, Recall <b>{pct(b['recall'])}</b>, "
                 f"dengan <b>{angka(b['FP'])}</b> false positive dan <b>{angka(b['FN'])}</b> false negative.", "check")


# ---------------------------------------------------------------------------
# 7. Tentang
# ---------------------------------------------------------------------------

elif hal == "Tentang":
    st.title("Tentang Penelitian")
    st.markdown(f"""
**Deteksi Serangan Mirai Botnet pada Perangkat IoT Menggunakan Metode Rule-Based Berbasis Trafik Jaringan**

{PENULIS} · NIM {NIM}
Jurusan Teknik Informatika, Fakultas Sains dan Teknologi, UIN Alauddin Makassar
""")
    with st.container(border=True):
        st.markdown("##### Alur sistem")
        st.graphviz_chart("""
        digraph { rankdir=LR; bgcolor="transparent";
          node [shape=box, style="rounded,filled", fillcolor="#eef4fd", color="#b7d3f6", fontname="Segoe UI",
                fontsize=11, fontcolor="#0f1d35"]; edge [color="#6da7ec"];
          a [label="Dataset\\nCICIoT2023"]; b [label="Preprocessing"]; c [label="Pembagian data\\n70% / 30%"];
          d [label="Analisis\\nkarakteristik"]; e [label="Pembuatan\\nrule IF-THEN"]; f [label="Deteksi"];
          g [label="Evaluasi"]; a->b->c->d->e->f->g; }""")

    with st.expander("Dataset & preprocessing", expanded=True):
        inv = H["inventaris"]
        st.dataframe(inv.groupby("kelas").agg(jumlah_file=("file", "count"), total_baris=("baris", "sum"))
                     .reset_index(), hide_index=True, width="stretch")
        st.dataframe(H["pre"], hide_index=True, width="stretch")
        st.dataframe(H["bagi"], hide_index=True, width="stretch")
    with st.expander("Seleksi fitur"):
        st.dataframe(H["status_fitur"], hide_index=True, width="stretch")
        st.markdown("**Pemetaan fitur proposal ke kolom dataset**")
        st.dataframe(H["pemetaan"], hide_index=True, width="stretch")
    with st.expander("Catatan metodologis"):
        st.markdown(
            "- **Ukuran jendela berbeda**: BenignTraffic diringkas per 10 paket, Mirai per 100 paket, sehingga "
            "`Number` dan turunannya (`*_count`, `Tot sum`) dikeluarkan.\n"
            "- **Fitur proposal yang tidak tersedia** di CSV per-PCAP: `flow_duration`, `Duration`, `Srate`.\n"
            "- **Tahap scanning dan komunikasi C2** tidak dideteksi karena tidak ada pada label Mirai CICIoT2023 "
            "(sesuai batasan penelitian).\n"
            "- Data uji tidak dipakai saat menentukan ambang, dan aturan tidak disesuaikan setelah hasil uji diketahui.")
