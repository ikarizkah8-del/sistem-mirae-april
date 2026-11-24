"""Mesin rule-based (IF-THEN) dan fungsi statistik untuk menurunkan ambang batas.

Tidak ada pelatihan model: setiap ambang dihitung langsung dari sebaran nilai fitur
pada data penyusunan (train), lalu rule disimpan sebagai JSON yang dapat dibaca manusia.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd

OPS = {">=": np.greater_equal, "<=": np.less_equal, ">": np.greater, "<": np.less}


@dataclass
class Kondisi:
    fitur: str
    op: str
    ambang: float
    metode: str = ""          # cara ambang diperoleh, untuk ketertelusuran

    def evaluasi(self, df: pd.DataFrame) -> np.ndarray:
        return OPS[self.op](df[self.fitur].to_numpy(), self.ambang)

    def teks(self) -> str:
        return f"{self.fitur} {self.op} {self.ambang:g}"


@dataclass
class Rule:
    id: str
    nama: str
    varian: str               # varian Mirai yang menjadi sasaran rule
    kondisi: list[Kondisi] = field(default_factory=list)
    alasan: str = ""

    def evaluasi(self, df: pd.DataFrame) -> np.ndarray:
        hasil = np.ones(len(df), dtype=bool)
        for k in self.kondisi:
            hasil &= k.evaluasi(df)
        return hasil

    def teks(self) -> str:
        return "IF " + " AND ".join(k.teks() for k in self.kondisi) + " THEN Mirai"


class RuleSet:
    """Kumpulan rule; trafik = Mirai jika minimal satu rule terpenuhi (OR)."""

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @property
    def fitur(self) -> list[str]:
        return sorted({k.fitur for r in self.rules for k in r.kondisi})

    def matriks(self, df: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame({r.id: r.evaluasi(df) for r in self.rules}, index=df.index)

    def prediksi(self, df: pd.DataFrame) -> np.ndarray:
        hasil = np.zeros(len(df), dtype=bool)
        for r in self.rules:
            hasil |= r.evaluasi(df)
        return hasil

    def jelaskan(self, df: pd.DataFrame) -> pd.Series:
        """Daftar rule yang terpenuhi per baris (untuk transparansi keputusan)."""
        m = self.matriks(df)
        # Vektorisasi: kombinasi rule yang terpenuhi dikodekan sebagai bitmask, lalu dipetakan
        # ke teks sekali per kombinasi (jauh lebih cepat daripada apply per baris).
        ids = list(m.columns)
        kode = np.zeros(len(m), dtype=np.int64)
        for i, r in enumerate(ids):
            kode |= m[r].to_numpy().astype(np.int64) << i
        teks = {k: ", ".join(r for i, r in enumerate(ids) if k >> i & 1) or "-" for k in np.unique(kode)}
        return pd.Series([teks[k] for k in kode], index=m.index, dtype=object)

    def to_json(self, path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self.rules], f, indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, path) -> "RuleSet":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls([Rule(**{**r, "kondisi": [Kondisi(**k) for k in r["kondisi"]]}) for r in data])


# ---------------------------------------------------------------------------
# Statistik untuk menurunkan ambang batas
# ---------------------------------------------------------------------------

def titik_potong_terbaik(pos: np.ndarray, neg: np.ndarray, n_kandidat: int = 400):
    """Cari ambang yang memaksimalkan Youden J = TPR - FPR (tumpang tindih paling kecil).

    pos = nilai fitur kelas Mirai, neg = nilai fitur kelas normal.
    Arah (>= atau <=) ditentukan dari median kedua kelas.
    Mengembalikan (op, ambang, J, TPR, FPR).
    """
    op = ">=" if np.median(pos) >= np.median(neg) else "<="
    gabungan = np.concatenate([pos, neg])
    kandidat = np.unique(np.quantile(gabungan, np.linspace(0, 1, n_kandidat)))
    pos_s, neg_s = np.sort(pos), np.sort(neg)
    if op == ">=":
        tpr = 1 - np.searchsorted(pos_s, kandidat, side="left") / len(pos_s)
        fpr = 1 - np.searchsorted(neg_s, kandidat, side="left") / len(neg_s)
    else:
        tpr = np.searchsorted(pos_s, kandidat, side="right") / len(pos_s)
        fpr = np.searchsorted(neg_s, kandidat, side="right") / len(neg_s)
    j = tpr - fpr
    i = int(np.argmax(j))
    return op, float(kandidat[i]), float(j[i]), float(tpr[i]), float(fpr[i])


def koefisien_tumpang_tindih(a: np.ndarray, b: np.ndarray, bins: int = 60) -> float:
    """Luas irisan dua histogram ternormalisasi (0 = terpisah sempurna, 1 = identik)."""
    lo, hi = np.nanmin([a.min(), b.min()]), np.nanmax([a.max(), b.max()])
    if hi <= lo:
        return 1.0
    if lo > 0 and hi / lo > 1e3:                       # sebaran sangat lebar -> skala log
        tepi = np.logspace(np.log10(lo), np.log10(hi), bins + 1)
    else:
        tepi = np.linspace(lo, hi, bins + 1)
    ha, _ = np.histogram(a, tepi)
    hb, _ = np.histogram(b, tepi)
    return float(np.minimum(ha / ha.sum(), hb / hb.sum()).sum())


def bulatkan_ambang(x: float) -> float:
    """Bulatkan ke 3 angka penting agar rule mudah dibaca."""
    if x == 0 or not np.isfinite(x):
        return float(x)
    return float(f"{x:.3g}")


# ---------------------------------------------------------------------------
# Evaluasi
# ---------------------------------------------------------------------------

def metrik_biner(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    y_true, y_pred = np.asarray(y_true, bool), np.asarray(y_pred, bool)
    tp = int((y_true & y_pred).sum()); tn = int((~y_true & ~y_pred).sum())
    fp = int((~y_true & y_pred).sum()); fn = int((y_true & ~y_pred).sum())
    akurasi = (tp + tn) / max(tp + tn + fp + fn, 1)
    presisi = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * presisi * recall / max(presisi + recall, 1e-12)
    fpr = fp / max(fp + tn, 1)
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "accuracy": akurasi, "precision": presisi,
            "recall": recall, "f1": f1, "fpr": fpr, "specificity": 1 - fpr}
