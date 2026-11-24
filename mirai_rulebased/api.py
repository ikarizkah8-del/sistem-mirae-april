"""Aplikasi Flask: REST API deteksi Mirai (rule-based) + tampilan web yang memakai API tersebut.

Jalankan dari folder D:\\hasil skirpsi april:
    .venv\\Scripts\\python.exe mirai_rulebased\\api.py
lalu buka http://127.0.0.1:5000

Pastikan pipeline.py sudah dijalankan agar folder output/ terisi.

Ringkasan endpoint (semua respons JSON kecuali unduhan):
  GET    /api/status                  status server dan hasil pipeline
  GET    /api/beranda                 metrik data uji dan aturan (aktif + hasil penelitian)
  GET    /api/aturan                  aturan aktif, aturan hasil penelitian, jejak penyusunan
  POST   /api/aturan/uji              uji ambang usulan pada sampel data uji (tanpa menyimpan)
  PUT    /api/aturan                  simpan ambang usulan sebagai aturan aktif (kustom)
  DELETE /api/aturan/kustom           kembali ke aturan hasil penelitian
  GET    /api/analisis                distribusi protokol, daya pisah fitur
  GET    /api/analisis/fitur/<nama>   histogram + statistik satu fitur (?log=1)
  GET    /api/dataset                 berkas dataset2023 yang dipakai penelitian
  POST   /api/data/unggah             unggah satu/lebih CSV (form-data "files") sebagai data aktif
  POST   /api/data/sampel             pakai sampel data uji (120.000 baris) sebagai data aktif
  POST   /api/data/contoh             pakai berkas contoh campuran normal + serangan (10.000 baris)
  GET    /api/data                    ringkasan data aktif
  POST   /api/deteksi                 jalankan deteksi pada data aktif (tercatat di riwayat)
  GET    /api/deteksi                 ringkasan hasil deteksi terakhir
  GET    /api/deteksi/baris           baris hasil (?filter=Semua|Mirai|Normal&cari=&batas=1000)
  GET    /api/deteksi/unduh           unduh hasil deteksi terakhir (CSV)
  POST   /api/deteksi/file            unggah CSV dan langsung dideteksi (tanpa data aktif)
  POST   /api/prediksi                deteksi data JSON {"data": [{fitur: nilai, ...}, ...]}
  GET    /api/riwayat                 daftar riwayat deteksi
  GET    /api/riwayat/<id>/unduh      unduh hasil deteksi lama (CSV.gz)
  DELETE /api/riwayat                 hapus seluruh riwayat
  GET    /api/evaluasi                evaluasi sistem pada data uji + analisis overfitting
"""
from __future__ import annotations

import time
import uuid
from collections import OrderedDict

import pandas as pd
from flask import Flask, jsonify, make_response, render_template, request, send_file

import config as C
import layanan as L

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 600 * 1024 * 1024      # batas unggahan 600 MB
app.json.ensure_ascii = False
app.json.sort_keys = False

PENULIS, NIM = "Aprilah Puspitasari", "60200122092"

# Penyimpanan data aktif per pengguna (di memori). Kunci = cookie "sid".
SESI: "OrderedDict[str, dict]" = OrderedDict()
MAKS_SESI = 5


def sesi() -> dict:
    sid = request.cookies.get("sid")
    if sid not in SESI:
        sid = uuid.uuid4().hex
        SESI[sid] = {}
        while len(SESI) > MAKS_SESI:                  # buang sesi terlama agar RAM tidak penuh
            SESI.popitem(last=False)
    SESI.move_to_end(sid)
    request.environ["sid_baru"] = sid
    return SESI[sid]


@app.after_request
def pasang_cookie(resp):
    sid = request.environ.get("sid_baru")
    if sid and request.cookies.get("sid") != sid:
        resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp


def galat(pesan: str, kode: int = 400):
    return jsonify({"ok": False, "pesan": pesan}), kode


@app.before_request
def cek_output():
    if request.path.startswith("/api/") and request.path != "/api/status" and not L.output_siap():
        return galat("Folder output/ belum berisi hasil. Jalankan dulu: python pipeline.py", 503)


@app.errorhandler(413)
def terlalu_besar(_):
    return galat("Ukuran file melebihi batas 600 MB.", 413)


# ---------------------------------------------------------------------------
# Halaman web
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    # versi = waktu ubah berkas statis, agar browser tidak memakai CSS/JS lama dari cache
    statis = C.BASE_DIR / "static"
    versi = int(max((statis / n).stat().st_mtime for n in ("app.js", "gaya.css")))
    resp = make_response(render_template("index.html", penulis=PENULIS, nim=NIM, versi=versi))
    resp.headers["Cache-Control"] = "no-cache"
    return resp


# ---------------------------------------------------------------------------
# API: informasi
# ---------------------------------------------------------------------------

@app.get("/api/status")
def status():
    siap = L.output_siap()
    return jsonify({"ok": True, "output_siap": siap,
                    "pipeline_dibuat": L.hasil_pipeline()["meta"].get("dibuat") if siap else None,
                    "aturan_aktif": L.nama_aturan_aktif() if siap else None})


@app.get("/api/beranda")
def beranda():
    return jsonify(L.data_beranda())


@app.get("/api/analisis")
def analisis():
    return jsonify(L.data_analisis())


@app.get("/api/analisis/fitur/<path:nama>")
def analisis_fitur(nama):
    try:
        return jsonify(L.sebaran_fitur(nama, request.args.get("log") in ("1", "true")))
    except ValueError as e:
        return galat(str(e), 404)


@app.get("/api/evaluasi")
def evaluasi():
    return jsonify(L.data_evaluasi())


@app.get("/api/dataset")
def dataset():
    return jsonify(L.info_dataset())


# ---------------------------------------------------------------------------
# API: aturan (lihat, uji, ubah ambang)
# ---------------------------------------------------------------------------

def _ambang_dari_body():
    isi = request.get_json(silent=True)
    if not isinstance(isi, dict) or "ambang" not in isi:
        raise ValueError('Kirim JSON {"ambang": {"R1": [nilai, ...], "R2": [...], "R3": [...]}}')
    return isi["ambang"]


@app.get("/api/aturan")
def aturan():
    return jsonify(L.data_aturan())


@app.post("/api/aturan/uji")
def aturan_uji():
    try:
        return jsonify({"ok": True, **L.uji_ambang(_ambang_dari_body())})
    except ValueError as e:
        return galat(str(e))


@app.put("/api/aturan")
def aturan_simpan():
    try:
        L.simpan_ambang(_ambang_dari_body())
    except ValueError as e:
        return galat(str(e))
    return jsonify({"ok": True, **L.data_aturan()})


@app.delete("/api/aturan/kustom")
def aturan_reset():
    L.hapus_ambang()
    return jsonify({"ok": True, **L.data_aturan()})


# ---------------------------------------------------------------------------
# API: data aktif
# ---------------------------------------------------------------------------

def _baca_unggahan() -> tuple[pd.DataFrame, str]:
    files = [f for f in request.files.getlist("files") if f and f.filename]
    if not files:
        raise ValueError("Tidak ada file. Kirim sebagai form-data dengan nama field 'files'.")
    bagian = []
    for f in files:
        if not f.filename.lower().endswith(".csv"):
            raise ValueError(f"{f.filename}: hanya file .csv yang didukung.")
        try:
            bagian.append(L.baca_csv(f.stream, f.filename))
        except Exception as e:                       # noqa: BLE001 - pesan dikirim ke pengguna
            raise ValueError(f"{f.filename}: gagal dibaca ({e}).") from e
    return pd.concat(bagian, ignore_index=True), ", ".join(f.filename for f in files)


def _set_data(d: pd.DataFrame, sumber: str):
    s = sesi()
    s.update(data=d, sumber=sumber)
    s.pop("deteksi", None)
    return jsonify({"ok": True, **L.ringkas_data(d, sumber)})


@app.post("/api/data/unggah")
def data_unggah():
    try:
        d, sumber = _baca_unggahan()
    except ValueError as e:
        return galat(str(e))
    return _set_data(d, sumber)


@app.post("/api/data/sampel")
def data_sampel():
    return _set_data(L.sampel_uji(), f"Sampel data uji ({C.SAMPLE_PER_CLASS:,} baris per kelas)".replace(",", "."))


@app.post("/api/data/contoh")
def data_contoh():
    if not L.contoh_tersedia():
        return galat("Berkas contoh belum dibuat. Jalankan: python mirai_rulebased\\buat_data_contoh.py", 404)
    return _set_data(L.baca_contoh(), f"{L.FILE_CONTOH.name} (contoh campuran normal + serangan)")


@app.get("/api/data")
def data_aktif():
    s = sesi()
    if "data" not in s:
        return jsonify({"ok": True, "ada": False})
    return jsonify({"ok": True, "ada": True, **L.ringkas_data(s["data"], s["sumber"])})


# ---------------------------------------------------------------------------
# API: deteksi
# ---------------------------------------------------------------------------

@app.post("/api/deteksi")
def deteksi():
    s = sesi()
    if "data" not in s:
        return galat("Belum ada data aktif. Unggah file (/api/data/unggah) atau pakai sampel (/api/data/sampel).")
    hilang = [f for f in L.ruleset().fitur if f not in s["data"].columns]
    if hilang:
        return galat(f"Kolom yang dibutuhkan rule tidak ada: {hilang}")
    det = L.jalankan_deteksi(s["data"])
    rid = L.simpan_riwayat(det, s["sumber"])
    s["deteksi"] = det
    return jsonify({"ok": True, "id_riwayat": rid, "sumber": s["sumber"], **L.ringkas_deteksi(det)})


@app.get("/api/deteksi")
def deteksi_terakhir():
    s = sesi()
    if "deteksi" not in s:
        return jsonify({"ok": True, "ada": False})
    return jsonify({"ok": True, "ada": True, "sumber": s["sumber"], **L.ringkas_deteksi(s["deteksi"])})


@app.get("/api/deteksi/baris")
def deteksi_baris():
    s = sesi()
    if "deteksi" not in s:
        return galat("Belum ada hasil deteksi.", 404)
    batas = min(max(request.args.get("batas", 1000, type=int), 1), 5000)
    return jsonify(L.baris_hasil(s["deteksi"]["hasil"], request.args.get("filter", "Semua"),
                                 request.args.get("cari", ""), batas))


@app.get("/api/deteksi/unduh")
def deteksi_unduh():
    s = sesi()
    if "deteksi" not in s:
        return galat("Belum ada hasil deteksi.", 404)
    resp = make_response(L.csv_hasil(s["deteksi"]["hasil"]))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=hasil_deteksi.csv"
    return resp


@app.post("/api/deteksi/file")
def deteksi_file():
    """Satu langkah: unggah CSV -> hasil deteksi. Cocok untuk Postman/curl."""
    try:
        d, sumber = _baca_unggahan()
    except ValueError as e:
        return galat(str(e))
    hilang = [f for f in L.ruleset().fitur if f not in d.columns]
    if hilang:
        return galat(f"Kolom yang dibutuhkan rule tidak ada: {hilang}")
    det = L.jalankan_deteksi(d)
    rid = L.simpan_riwayat(det, sumber)
    hasil = {"ok": True, "id_riwayat": rid, "sumber": sumber, **L.ringkas_deteksi(det)}
    if request.args.get("baris") in ("1", "true"):
        hasil["contoh_baris"] = L.baris_hasil(det["hasil"], batas=100)
    return jsonify(hasil)


@app.post("/api/prediksi")
def prediksi():
    isi = request.get_json(silent=True)
    data = isi.get("data") if isinstance(isi, dict) else isi
    if not isinstance(data, list) or not data or not all(isinstance(r, dict) for r in data):
        return galat('Kirim JSON {"data": [{"Protocol Type": 47, "Header_Length": 0, ...}, ...]}')
    try:
        t0 = time.perf_counter()
        hasil = L.prediksi_records(data)
        return jsonify({"ok": True, "jumlah": len(hasil), "aturan": L.nama_aturan_aktif(),
                        "durasi_ms": (time.perf_counter() - t0) * 1000, "hasil": hasil})
    except ValueError as e:
        return galat(str(e))


# ---------------------------------------------------------------------------
# API: riwayat
# ---------------------------------------------------------------------------

@app.get("/api/riwayat")
def riwayat():
    return jsonify({"ok": True, "riwayat": L.daftar_riwayat()})


@app.get("/api/riwayat/<rid>/unduh")
def riwayat_unduh(rid):
    p = L.file_riwayat(rid)
    if p is None:
        return galat("Riwayat tidak ditemukan.", 404)
    return send_file(p, as_attachment=True, download_name=f"hasil_deteksi_{rid}.csv.gz",
                     mimetype="application/gzip")


@app.delete("/api/riwayat")
def riwayat_hapus():
    return jsonify({"ok": True, "file_dihapus": L.hapus_riwayat()})


if __name__ == "__main__":
    import os
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
