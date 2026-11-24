"""Konfigurasi penelitian: lokasi data, kelas, dan kelompok fitur.

Semua keputusan fitur di sini mengikuti hasil audit Tahap 1 (notebook audit):
- fitur turunan `Number` dan redundan dikeluarkan,
- fitur aplikasi/lapisan link tidak dipakai untuk rule karena bukan ciri perilaku flood Mirai.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "dataset2023"
OUTPUT_DIR = BASE_DIR / "output"

RANDOM_SEED = 42
TEST_SIZE = 0.30                 # proporsi data uji (disimpan, tidak dipakai menyusun rule)
SAMPLE_PER_CLASS = 30_000        # sampel untuk grafik di antarmuka
FILE_HOLDOUT_MOD = 4             # uji ketahanan: file bernomor n % 4 == 3 menjadi data uji

KELAS_NORMAL = "BenignTraffic"
KELAS_MIRAI = ["Mirai-greeth_flood", "Mirai-greip_flood", "Mirai-udpplain"]
KELAS_UTAMA = [KELAS_NORMAL] + KELAS_MIRAI
PREFIX_DDOS = "DDoS-"            # Skenario 2: DDoS non-Mirai (dipakai jika file tersedia)

# Hasil audit Tahap 1: fitur yang dikeluarkan beserta alasannya
FITUR_DIKELUARKAN = {
    "Number": "artefak: ukuran jendela paket berbeda (Benign=10, Mirai=100)",
    "ack_count": "turunan: ack_flag_number x Number",
    "syn_count": "turunan: syn_flag_number x Number",
    "fin_count": "turunan: fin_flag_number x Number",
    "rst_count": "turunan: rst_flag_number x Number",
    "Tot sum": "turunan: AVG x Number",
    "Tot size": "redundan: identik dengan AVG",
    "Variance": "redundan: Std^2",
    "Telnet": "konstan (selalu 0)",
}

# Kelompok indikator sesuai BAB III proposal (laju paket, protokol, flag TCP, ukuran paket, IAT).
# Hanya fitur di sini yang boleh menjadi kondisi rule.
KELOMPOK_INDIKATOR = {
    "Laju paket": ["Rate"],
    "Jenis protokol": ["Protocol Type", "TCP", "UDP", "ICMP"],
    "Flag TCP": ["syn_flag_number", "ack_flag_number", "psh_flag_number", "fin_flag_number", "rst_flag_number"],
    "Ukuran paket": ["AVG", "Min", "Max", "Std"],
    "Jeda antarpaket": ["IAT"],
    "Panjang header": ["Header_Length"],
}
FITUR_RULE = [f for fs in KELOMPOK_INDIKATOR.values() for f in fs]

# Fitur yang dianalisis tetapi TIDAK dipakai sebagai kondisi rule (alasan dicatat di laporan)
FITUR_HANYA_ANALISIS = {
    "Time_To_Live": "mencerminkan OS perangkat penyerang di lab, bukan perilaku Mirai",
    "HTTP": "indikator aplikasi; ketiadaannya bukan ciri Mirai",
    "HTTPS": "indikator aplikasi; ketiadaannya bukan ciri Mirai",
    "DNS": "indikator aplikasi",
    "SMTP": "indikator aplikasi", "SSH": "indikator aplikasi", "IRC": "indikator aplikasi",
    "DHCP": "indikator aplikasi", "ARP": "lapisan link", "IGMP": "indikator protokol jarang",
    "IPv": "lapisan link/jaringan, hampir selalu 1", "LLC": "lapisan link, hampir selalu 1",
    "ece_flag_number": "hampir selalu 0", "cwr_flag_number": "hampir selalu 0",
}

# Fitur proposal yang tidak tersedia di CSV per-PCAP (perlu dibahas di skripsi)
PEMETAAN_FITUR_PROPOSAL = [
    ("Rate", "Rate", "tersedia"),
    ("Srate", "-", "tidak ada di CSV per-PCAP; diwakili Rate"),
    ("flow_duration", "-", "tidak ada di CSV per-PCAP; diwakili IAT dan Rate"),
    ("Duration", "-", "tidak ada; kolom serupa adalah Time_To_Live (bukan durasi)"),
    ("syn_count", "syn_flag_number", "syn_count = syn_flag_number x Number (artefak jendela)"),
    ("syn_flag_number", "syn_flag_number", "tersedia"),
    ("Tot size", "AVG", "Tot size identik dengan AVG"),
    ("AVG", "AVG", "tersedia"),
    ("Std", "Std", "tersedia (hati-hati: dihitung pada jendela berbeda)"),
    ("IAT", "IAT", "tersedia"),
    ("TCP / UDP", "TCP / UDP", "tersedia"),
    ("Protocol Type", "Protocol Type", "tersedia (47 = GRE)"),
]

# Panjang rule (kriteria Liu dkk., 2021): jumlah kelompok indikator per rule.
# Minimal 2 agar rule tidak bertumpu pada satu ciri saja; maksimal 3 agar tetap ringkas.
MIN_KELOMPOK_PER_RULE = 2
MAKS_KELOMPOK_PER_RULE = 3
TOLERANSI_J = 0.005   # kandidat dengan selisih Youden J <= nilai ini dianggap setara
