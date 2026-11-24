"""Komponen tampilan (CSS, ikon, kartu) untuk app.py.

Gaya: sidebar navy, aksen biru, kartu putih bersudut membulat (mengikuti rancangan antarmuka).
"""
from __future__ import annotations

import streamlit as st

# Warna utama
NAVY = "#0f1d35"
BIRU = "#1f6fd6"
TINTA = "#0f1d35"
TINTA_2 = "#52607a"

# Warna data (entitas tetap): biner dan per kelas
WARNA_BINER = {"Normal": "#2a78d6", "Mirai": "#e34948"}
WARNA_KELAS = {
    "BenignTraffic": "#2a78d6",
    "Mirai-greeth_flood": "#eb6834",
    "Mirai-greip_flood": "#1baf7a",
    "Mirai-udpplain": "#eda100",
}
SKALA_BIRU = ["#e8f1fc", "#b7d3f6", "#6da7ec", "#2a78d6", "#184f95"]

# Nada kartu: (latar, garis, warna ikon)
NADA = {
    "hijau": ("#effaf3", "#cdeed9", "#0ca30c"),
    "biru": ("#eef4fd", "#d3e3f8", "#1f6fd6"),
    "merah": ("#fdf1f1", "#f5d2d2", "#d03b3b"),
    "oranye": ("#fff8eb", "#f7e2b8", "#c98500"),
    "ungu": ("#f4f2fd", "#dcd7f6", "#4a3aa7"),
}

_PATH = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "check": '<polyline points="20 6 9 17 4 12"/>',
    "alert": '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
             '<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "database": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>'
                '<path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    "target": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    "upload": '<polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/>'
              '<path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>',
    "info": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/>'
            '<line x1="12" y1="8" x2="12.01" y2="8"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    "user": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "list": '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/>'
            '<line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/>'
            '<line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
}


def ikon(nama: str, warna: str = BIRU, ukuran: int = 20, tebal: float = 2) -> str:
    return (f'<svg width="{ukuran}" height="{ukuran}" viewBox="0 0 24 24" fill="none" stroke="{warna}" '
            f'stroke-width="{tebal}" stroke-linecap="round" stroke-linejoin="round">{_PATH[nama]}</svg>')


CSS = f"""
<style>
.block-container {{ padding-top: 2rem; padding-bottom: 3rem; max-width: 1200px; }}
h1, h2, h3 {{ color: {TINTA}; letter-spacing: -0.01em; }}
h1 {{ font-size: 1.7rem !important; }}

/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] {{ background: {NAVY}; }}
section[data-testid="stSidebar"] * {{ color: #c9d4e5; }}
.brand {{ display:flex; align-items:center; gap:.7rem; padding:.2rem 0 1.2rem 0; }}
.brand-judul {{ font-weight:700; color:#fff !important; font-size:1.05rem; line-height:1.1; }}
.brand-sub {{ font-size:.75rem; color:#8fa1bf !important; }}
section[data-testid="stSidebar"] [role="radiogroup"] {{ gap: .3rem; width: 100%; }}
section[data-testid="stSidebar"] [role="radiogroup"] > div {{ width: 100%; }}
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] {{
    display: block; width: 100%; padding: .6rem .85rem; border-radius: 8px; margin: 0;
    cursor: pointer; transition: background .15s;
}}
/* sembunyikan lingkaran radio: div pertama di dalam isi opsi */
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div:first-child {{ display: none; }}
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] p {{ font-size: .93rem; }}
section[data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover {{ background: #1a2b4a; }}
section[data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {{ background: {BIRU}; }}
section[data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] * {{
    color: #fff !important; font-weight: 600;
}}
.pengguna {{ display:flex; gap:.6rem; align-items:center; border-top:1px solid #23365a;
             padding-top:1rem; margin-top:2.5rem; font-size:.8rem; line-height:1.35; }}

/* ---------- Kartu & panel ---------- */
div[data-testid="stVerticalBlockBorderWrapper"]:has(> div > div[data-testid="stVerticalBlock"]) {{
    background: #fff; border-radius: 12px;
}}
.hero {{ display:flex; gap:1.5rem; align-items:center; background:#eaf2fd; border:1px solid #d3e3f8;
         border-radius:14px; padding:1.6rem 1.8rem; margin-bottom:1rem; }}
.hero-judul {{ font-size:1.75rem; font-weight:800; color:{TINTA}; line-height:1.2; }}
.hero-sub {{ color:{TINTA_2}; margin-top:.4rem; }}
.kartu {{ border-radius:12px; padding:1rem 1.1rem; border:1px solid; height:100%; min-height:128px; }}
.kartu-ikon {{ width:36px; height:36px; border-radius:50%; display:flex; align-items:center;
               justify-content:center; margin-bottom:.55rem; }}
.kartu-label {{ font-size:.82rem; color:{TINTA_2}; font-weight:600; }}
.kartu-nilai {{ font-size:1.6rem; font-weight:800; color:{TINTA}; line-height:1.25;
                font-variant-numeric: tabular-nums; }}
.kartu-sub {{ font-size:.78rem; color:{TINTA_2}; }}
.kotak-info {{ display:flex; gap:.8rem; background:#eef4fd; border:1px solid #d3e3f8; border-radius:10px;
               padding:.9rem 1rem; color:{TINTA}; font-size:.92rem; margin:.4rem 0 1rem 0; }}
.kutipan {{ text-align:center; font-style:italic; color:{TINTA_2}; margin-top:1.5rem; }}
table.aturan {{ width:100%; border-collapse:collapse; font-size:.9rem; background:#fff;
                border:1px solid #e3e8f0; border-radius:10px; overflow:hidden; }}
table.aturan th {{ background:#f3f6fb; text-align:left; padding:.6rem .8rem; color:{TINTA};
                   border-bottom:1px solid #e3e8f0; }}
table.aturan td {{ padding:.6rem .8rem; border-bottom:1px solid #eef1f6; vertical-align:top; color:{TINTA}; }}
table.aturan code {{ background:#eef4fd; color:#184f95; padding:.1rem .35rem; border-radius:4px; }}
.lencana {{ display:inline-block; padding:.12rem .55rem; border-radius:999px; font-size:.78rem; font-weight:600; }}
.lencana-mirai {{ background:#fdeaea; color:#b42323; }}
.lencana-normal {{ background:#e7f7ec; color:#0b6b2c; }}
div.stButton > button[kind="primary"] {{ border-radius:8px; font-weight:600; }}
div[data-testid="stFileUploaderDropzone"] {{ border:2px dashed #b7d3f6; background:#f7faff; padding:2rem; }}
</style>
"""


def pasang_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def kartu(nama_ikon: str, label: str, nilai: str, sub: str = "", nada: str = "biru") -> str:
    bg, garis, warna = NADA[nada]
    return (f'<div class="kartu" style="background:{bg};border-color:{garis}">'
            f'<div class="kartu-ikon" style="background:{warna}">{ikon(nama_ikon, "#fff", 18, 2.5)}</div>'
            f'<div class="kartu-label">{label}</div><div class="kartu-nilai">{nilai}</div>'
            f'<div class="kartu-sub">{sub}</div></div>')


def baris_kartu(daftar: list[str]) -> None:
    for col, html in zip(st.columns(len(daftar)), daftar):
        col.markdown(html, unsafe_allow_html=True)


def kotak_info(judul: str, isi: str, nama_ikon: str = "info") -> None:
    st.markdown(f'<div class="kotak-info"><div>{ikon(nama_ikon, BIRU, 22)}</div>'
                f'<div><b>{judul}</b><br>{isi}</div></div>', unsafe_allow_html=True)


def lencana(label: str) -> str:
    kelas = "lencana-mirai" if label == "Mirai" else "lencana-normal"
    return f'<span class="lencana {kelas}">{label}</span>'


def gaya_plot(fig, tinggi: int = 360):
    fig.update_layout(height=tinggi, margin=dict(l=10, r=10, t=40, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color=TINTA), legend_title=None,
                      xaxis=dict(gridcolor="#e9edf3"), yaxis=dict(gridcolor="#e9edf3"))
    return fig
