/* Tampilan web Mirai Detector: semua data diambil dari Flask API (/api/...). */
"use strict";

// ---------------------------------------------------------------------------
// Ikon, nama ramah, format
// ---------------------------------------------------------------------------
const PATH = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  upload: '<polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>',
  info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  list: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
  shuffle: '<polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/>',
  sliders: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  play: '<polygon points="5 3 19 12 5 21 5 3"/>',
};
const NADA = {
  hijau: ["#effaf3", "#cdeed9", "#0ca30c"], biru: ["#eef4fd", "#d3e3f8", "#1f6fd6"],
  merah: ["#fdf1f1", "#f5d2d2", "#d03b3b"], oranye: ["#fff8eb", "#f7e2b8", "#c98500"],
  ungu: ["#f4f2fd", "#dcd7f6", "#4a3aa7"],
};
const WARNA_BINER = { Normal: "#2a78d6", Mirai: "#e34948" };
const WARNA_KELAS = { BenignTraffic: "#2a78d6", "Mirai-greeth_flood": "#eb6834", "Mirai-greip_flood": "#1baf7a", "Mirai-udpplain": "#eda100" };
const SKALA_BIRU = [[0, "#e8f1fc"], [0.25, "#b7d3f6"], [0.5, "#6da7ec"], [0.75, "#2a78d6"], [1, "#184f95"]];

const NAMA_KELAS = { BenignTraffic: "Normal", "Mirai-greeth_flood": "Mirai GREeth", "Mirai-greip_flood": "Mirai GREIP", "Mirai-udpplain": "Mirai UDPplain" };
const NAMA_FITUR = {
  Header_Length: ["Panjang header", "ukuran bagian kepala paket"],
  "Protocol Type": ["Jenis protokol", "kode protokol yang paling banyak dipakai"],
  Time_To_Live: ["Umur paket (TTL)", "batas lompatan paket di jaringan"],
  Rate: ["Laju paket", "jumlah paket per detik"],
  fin_flag_number: ["Tanda FIN", "porsi paket penutup koneksi"],
  syn_flag_number: ["Tanda SYN", "porsi paket pembuka koneksi"],
  rst_flag_number: ["Tanda RST", "porsi paket pemutus koneksi"],
  psh_flag_number: ["Tanda PSH", "porsi paket kirim segera"],
  ack_flag_number: ["Tanda ACK", "porsi paket balasan TCP"],
  ece_flag_number: ["Tanda ECE", "sinyal kemacetan jaringan"],
  cwr_flag_number: ["Tanda CWR", "sinyal kemacetan jaringan"],
  HTTP: ["Porsi HTTP", "trafik web"], HTTPS: ["Porsi HTTPS", "trafik web aman"], DNS: ["Porsi DNS", "pencarian alamat"],
  SMTP: ["Porsi SMTP", "trafik email"], SSH: ["Porsi SSH", "akses jarak jauh"], IRC: ["Porsi IRC", "trafik chat"],
  TCP: ["Porsi TCP", "paket dengan sesi koneksi"], UDP: ["Porsi UDP", "paket tanpa sesi koneksi"],
  DHCP: ["Porsi DHCP", "pembagian alamat IP"], ARP: ["Porsi ARP", "pencarian perangkat lokal"],
  ICMP: ["Porsi ICMP", "paket ping"], IGMP: ["Porsi IGMP", "trafik grup"], IPv: ["Porsi IP", "paket berbasis IP"],
  LLC: ["Porsi LLC", "lapisan tautan data"],
  Min: ["Ukuran paket terkecil", "byte"], Max: ["Ukuran paket terbesar", "byte"],
  AVG: ["Ukuran paket rata-rata", "byte per paket"], Std: ["Variasi ukuran paket", "makin kecil makin seragam"],
  IAT: ["Jeda antarpaket", "waktu antara dua paket"],
};
const KELOMPOK_FITUR = [
  ["Ukuran paket", ["AVG", "Min", "Max", "Std", "Header_Length"]],
  ["Waktu & laju", ["Rate", "IAT", "Time_To_Live"]],
  ["Protokol", ["Protocol Type", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SMTP", "SSH", "IRC", "DHCP", "ARP", "IGMP", "IPv", "LLC"]],
  ["Tanda (flag) TCP", ["ack_flag_number", "syn_flag_number", "fin_flag_number", "rst_flag_number", "psh_flag_number", "ece_flag_number", "cwr_flag_number"]],
];
const namaKelas = (k) => NAMA_KELAS[k] || k;
const namaFitur = (f) => (NAMA_FITUR[f] || [f])[0];
const descFitur = (f) => (NAMA_FITUR[f] || ["", ""])[1];

const ikon = (n, w = "#1f6fd6", u = 20, t = 2) =>
  `<svg width="${u}" height="${u}" viewBox="0 0 24 24" fill="none" stroke="${w}" stroke-width="${t}" stroke-linecap="round" stroke-linejoin="round">${PATH[n] || ""}</svg>`;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const angka = (x) => (x == null ? "–" : Number(x).toLocaleString("id-ID", { maximumFractionDigits: 0 }));
const pct = (x, d = 2) => (x == null ? "–" : (100 * x).toFixed(d).replace(".", ",") + "%");
const fmt4 = (x) => (x == null ? "–" : typeof x === "number" ? Number(x.toPrecision(4)).toLocaleString("id-ID") : esc(x));
const desimal = (x, d = 1) => Number(x).toFixed(d).replace(".", ",");
const $ = (sel) => document.querySelector(sel);

function kartu(nIkon, label, nilai, sub = "", nada = "biru") {
  const [bg, garis, warna] = NADA[nada];
  return `<div class="kartu" style="background:${bg};border-color:${garis}">
    <div class="kartu-ikon" style="background:${warna}">${ikon(nIkon, "#fff", 18, 2.5)}</div>
    <div class="kartu-label">${label}</div><div class="kartu-nilai">${nilai}</div><div class="kartu-sub">${sub}</div></div>`;
}
const gridKartu = (arr) => `<div class="grid-kartu ${arr.length === 4 ? "k4" : arr.length === 6 ? "k6" : ""}">${arr.join("")}</div>`;
const kotakInfo = (judul, isi, n = "info") => `<div class="kotak-info"><div>${ikon(n, "#1f6fd6", 22)}</div><div><b>${judul}</b><br>${isi}</div></div>`;
const lencana = (l) => `<span class="lencana ${l === "Mirai" ? "lencana-mirai" : l === "Normal" ? "lencana-normal" : "lencana-netral"}">${esc(l)}</span>`;
const lencanaAturan = (nama) => `<span class="lencana-aturan ${nama === "kustom" ? "kustom" : "penelitian"}">Aturan ${esc(nama)}</span>`;
const judulBagian = (no, judul, sub = "") =>
  `<h2>${no ? `<span class="nomor">${no}</span>` : ""}${judul}</h2>${sub ? `<p class="keterangan">${sub}</p>` : ""}`;
const kepalaIkon = (n, judul, sub = "") =>
  `<div class="kepala-ikon"><span class="bulat">${ikon(n, "#1f6fd6", 18)}</span><b>${judul}</b>${sub ? `<span class="kecil">${sub}</span>` : ""}</div>`;
const segmen = (id, daftar, aktif) =>
  `<div class="segmen" id="${id}">${daftar.map(([v, l]) => `<button data-v="${esc(v)}" class="${v === aktif ? "aktif" : ""}">${l}</button>`).join("")}</div>`;
function ikatSegmen(id, fn) {
  document.querySelectorAll(`#${CSS.escape(id)} button`).forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(`#${CSS.escape(id)} button`).forEach((x) => x.classList.toggle("aktif", x === b));
    fn(b.dataset.v);
  }));
}

/** Tabel HTML dari list of dict. format: {kolom: fungsi(nilai, baris)} */
function tabelHTML(baris, kolom, { format = {}, judul = {}, tinggi = false } = {}) {
  if (!baris || !baris.length) return `<p class="keterangan">Tidak ada data.</p>`;
  kolom = kolom || Object.keys(baris[0]);
  const isAngka = (k) => baris.some((r) => typeof r[k] === "number");
  const kepala = kolom.map((k) => `<th class="${isAngka(k) ? "angka" : ""}">${esc(judul[k] || k)}</th>`).join("");
  const isi = baris.map((r) => "<tr>" + kolom.map((k) => {
    const v = r[k];
    const sel = format[k] ? format[k](v, r) : typeof v === "number" ? fmt4(v) : esc(v ?? "–");
    return `<td class="${typeof v === "number" ? "angka" : ""}">${sel}</td>`;
  }).join("") + "</tr>").join("");
  return `<div class="tabel-wadah ${tinggi ? "tinggi" : ""}"><table><thead><tr>${kepala}</tr></thead><tbody>${isi}</tbody></table></div>`;
}

function kartuMetrik(m) {
  return gridKartu([
    kartu("target", "Accuracy", pct(m.accuracy), "tebakan benar", "biru"),
    kartu("check", "Precision", pct(m.precision), "tuduhan Mirai yang benar", "hijau"),
    kartu("activity", "Recall", pct(m.recall), "Mirai yang tertangkap", "ungu"),
    kartu("shield", "F1-Score", pct(m.f1), "keseimbangan keduanya", "biru"),
    kartu("alert", "False Positive", angka(m.FP), "normal ditandai Mirai", "oranye"),
    kartu("alert", "False Negative", angka(m.FN), "Mirai lolos", "merah"),
  ]);
}

// ---------------------------------------------------------------------------
// Grafik (Plotly)
// ---------------------------------------------------------------------------
const CFG = { displaylogo: false, responsive: true, modeBarButtonsToRemove: ["lasso2d", "select2d", "autoScale2d"] };
function plot(id, data, layout = {}, tinggi = 340) {
  const el = typeof id === "string" ? document.getElementById(id) : id;
  if (!el) return null;
  if (typeof Plotly === "undefined") { el.innerHTML = `<p class="keterangan">Grafik tidak dapat dimuat (Plotly memerlukan koneksi internet).</p>`; return null; }
  Plotly.newPlot(el, data, {
    height: tinggi, margin: { l: 10, r: 10, t: 40, b: 10 }, paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    font: { color: "#0f1d35", family: "Segoe UI, system-ui, sans-serif" },
    hoverlabel: { bgcolor: "#0f1d35", bordercolor: "#0f1d35", font: { color: "#fff" } },
    xaxis: { gridcolor: "#e9edf3", automargin: true, ...(layout.xaxis || {}) },
    yaxis: { gridcolor: "#e9edf3", automargin: true, ...(layout.yaxis || {}) },
    ...Object.fromEntries(Object.entries(layout).filter(([k]) => k !== "xaxis" && k !== "yaxis")),
  }, CFG);
  return el;
}
const saatKlik = (el, fn) => { if (el && el.on) { el.on("plotly_click", fn); el.classList.add("bisa-klik"); } };
const ubahUkuran = (wadah) => { if (typeof Plotly !== "undefined") wadah.querySelectorAll(".js-plotly-plot").forEach((g) => Plotly.Plots.resize(g)); };

function donut(id, nilai, judul, warna, tengah = "", tinggi = 320) {
  const label = Object.keys(nilai), v = Object.values(nilai), tot = v.reduce((a, b) => a + b, 0) || 1;
  return plot(id, [{
    type: "pie", labels: label, values: v, hole: 0.62, sort: false, textinfo: "text", textposition: "outside",
    text: v.map((x) => (x / tot >= 0.05 ? (100 * x / tot).toFixed(1) + "%" : "")),
    marker: { colors: label.map((k) => warna[k] || "#9aa6b8"), line: { color: "#fff", width: 2 } },
    hovertemplate: "%{label}: %{value:,} (%{percent})<extra></extra>",
  }], { title: { text: judul }, showlegend: true, legend: { orientation: "h", y: -0.05, x: 0.5, xanchor: "center" },
        annotations: [{ text: tengah, showarrow: false, font: { size: 15 } }] }, tinggi);
}
function confusion(id, m, judul = "Confusion Matrix") {
  const z = [[m.TN, m.FP], [m.FN, m.TP]], tot = z.flat().reduce((a, b) => a + b, 0) || 1;
  return plot(id, [{
    type: "heatmap", z, x: ["Prediksi Normal", "Prediksi Mirai"], y: ["Aktual Normal", "Aktual Mirai"],
    text: z.map((r) => r.map((v) => `${angka(v)}<br>(${(100 * v / tot).toFixed(2)}%)`)), texttemplate: "%{text}",
    colorscale: SKALA_BIRU, showscale: false, xgap: 3, ygap: 3, hovertemplate: "%{y} · %{x}<br>Jumlah: %{z:,}<extra></extra>",
  }], { title: { text: judul }, yaxis: { autorange: "reversed" } }, 330);
}

// ---------------------------------------------------------------------------
// API & utilitas
// ---------------------------------------------------------------------------
async function api(path, opsi = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opsi });
  let isi = null;
  try { isi = await r.json(); } catch { /* bukan JSON */ }
  if (!r.ok || (isi && isi.ok === false)) throw new Error((isi && isi.pesan) || `Permintaan gagal (${r.status})`);
  return isi;
}
const apiJSON = (path, method, body) => api(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
function toast(pesan) {
  const t = $("#toast"); t.textContent = pesan; t.classList.add("tampil");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("tampil"), 2600);
}
const galatHTML = (e) => `<div class="kotak-galat"><b>Terjadi kesalahan:</b> ${esc(e.message || e)}</div>`;
async function denganMemuat(tombol, label, fn) {
  const asli = tombol.innerHTML; tombol.disabled = true; tombol.innerHTML = `<span class="putar"></span> ${label}`;
  try { return await fn((l) => { tombol.innerHTML = `<span class="putar"></span> ${l}`; }); }
  finally { tombol.innerHTML = asli; tombol.disabled = false; }
}

// ---------------------------------------------------------------------------
// Halaman
// ---------------------------------------------------------------------------
const HAL = {};

// ============================ BERANDA ============================
function kartuAturan(aturan) {
  return `<div class="grid-aturan">${aturan.map((r) => `<div class="kartu-aturan" title="${esc(r.alasan)}">
      <div class="kepala"><span class="id-aturan">${esc(r.id)}</span><span class="kecil">disusun dari ${esc(namaKelas(r.varian))}</span></div>
      <div class="syarat">${r.kondisi.map((k, j) => `${j ? '<span class="dan">DAN</span>' : ""}<span class="syarat-item">
        <span class="kecil">${esc(namaFitur(k.fitur))}</span><code>${esc(k.teks)}</code></span>`).join("")}</div>
      <div class="maka">maka ${lencana("Mirai")}</div></div>`).join("")}
    <div class="kartu-aturan lain"><div class="kepala"><span class="id-aturan abu">–</span><span class="kecil">tidak ada aturan terpenuhi</span></div>
      <div class="syarat"><span class="kecil">Data yang tidak cocok dengan aturan mana pun</span></div>
      <div class="maka">maka ${lencana("Normal")}</div></div></div>
    <p class="keterangan">Setiap baris diperiksa dengan semua aturan. Cukup satu aturan terpenuhi, data ditandai Mirai.</p>`;
}

HAL.beranda = async (el) => {
  const d = await api("/api/beranda"), b = d.biner;
  el.innerHTML = `
    <div class="hero">${ikon("shield", "#1f6fd6", 84, 1.6)}<div>
      <div class="hero-judul">Deteksi Serangan Mirai Botnet<br>pada Perangkat IoT</div>
      <div class="hero-sub">Metode Rule-Based Berbasis Trafik Jaringan · Dataset CICIoT2023 · varian GREeth, GREIP, UDPplain</div></div></div>

    <section class="bagian">${judulBagian("", "Hasil pengujian pada data uji")}
    ${gridKartu([
      kartu("database", "Total Data Uji", angka(d.jumlah_data_uji), "baris trafik", "hijau"),
      kartu("shield", "Diprediksi Mirai", angka(b.TP + b.FP), "baris", "biru"),
      kartu("check", "Diprediksi Normal", angka(b.TN + b.FN), "baris", "oranye"),
      kartu("target", "Akurasi", pct(b.accuracy), `F1-Score ${pct(b.f1)}`, "ungu"),
    ])}</section>

    <section class="bagian">${judulBagian("", `Aturan deteksi yang digunakan <span id="lencanaAktif">${lencanaAturan(d.nama_aktif)}</span>`)}
      <div id="daftarAturan">${kartuAturan(d.aktif)}</div></section>

    <section class="bagian">${judulBagian("", "Perubahan Aturan", "Ubah angka di kolom <b>Nilai dipakai</b>, uji dampaknya, lalu simpan.")}
      <div class="panel">
        <div id="editorAmbang"></div>
        <div class="baris-kontrol ujung">
          <button class="tombol bahaya" id="btnReset">Kembalikan ke hasil penelitian</button>
          <span class="isi"></span>
          <button class="tombol" id="btnUji">${ikon("sliders", "currentColor", 16)} Uji ambang</button>
          <button class="tombol utama" id="btnSimpan">${ikon("check", "currentColor", 16)} Simpan &amp; pakai</button>
        </div>
        <div id="hasilUji"></div>
        <p class="catatan">${ikon("info", "#c98500", 16)} Perubahan hanya dipakai di menu <b>Deteksi Serangan</b>. Menu <b>Evaluasi Sistem</b> tetap memakai aturan hasil penelitian.</p>
      </div>
    </section>`;

  const gambarEditor = (aktif, penelitian) => {
    const baris = [];
    penelitian.forEach((r, i) => r.kondisi.forEach((k, j) => {
      const now = aktif[i].kondisi[j].ambang;
      baris.push(`<tr class="${j === 0 ? "awal-aturan" : ""}"><td>${j === 0 ? `<b>${esc(r.id)}</b> <span class="kecil">${esc(namaKelas(r.varian))}</span>` : ""}</td>
        <td>${esc(namaFitur(k.fitur))} <code>${esc(k.fitur)}</code></td><td class="tengah"><b>${esc(k.op)}</b></td>
        <td class="angka">${fmt4(k.ambang)}</td>
        <td class="angka"><input class="ambang ${now !== k.ambang ? "beda" : ""}" type="number" step="any" data-r="${esc(r.id)}" data-j="${j}" data-asli="${k.ambang}" value="${now}"></td>
        <td class="kecil">${esc(k.metode)}</td></tr>`);
    }));
    $("#editorAmbang").innerHTML = `<div class="tabel-wadah"><table><thead><tr><th>Aturan</th><th>Atribut</th><th class="tengah">Operator</th>
      <th class="angka">Nilai penelitian</th><th class="angka">Nilai dipakai</th><th>Cara mendapatkan angka</th></tr></thead><tbody>${baris.join("")}</tbody></table></div>`;
    document.querySelectorAll("input.ambang").forEach((inp) => inp.addEventListener("input", () =>
      inp.classList.toggle("beda", Number(inp.value) !== Number(inp.dataset.asli))));
  };
  gambarEditor(d.aktif, d.penelitian);

  const kumpulkan = () => {
    const ambang = {};
    document.querySelectorAll("input.ambang").forEach((inp) => {
      (ambang[inp.dataset.r] ||= [])[+inp.dataset.j] = inp.value === "" ? null : Number(inp.value);
    });
    return { ambang };
  };
  const segarkan = (data) => {
    gambarEditor(data.aktif, data.penelitian);
    $("#daftarAturan").innerHTML = kartuAturan(data.aktif);
    $("#lencanaAktif").innerHTML = lencanaAturan(data.nama_aktif);
  };
  $("#btnUji").addEventListener("click", (ev) => denganMemuat(ev.currentTarget, "Menguji …", async () => {
    try {
      const r = await apiJSON("/api/aturan/uji", "POST", kumpulkan());
      const p = r.penelitian, u = r.usulan;
      const selisih = (a, b2, dd = 2) => { const s = 100 * (b2 - a); return s === 0 ? "0" : `<span class="${s > 0 ? "naik" : "turun"}">${s > 0 ? "+" : ""}${s.toFixed(dd).replace(".", ",")}</span>`; };
      const selisihN = (a, b2) => { const s = b2 - a; return s === 0 ? "0" : `<span class="${s < 0 ? "naik" : "turun"}">${s > 0 ? "+" : ""}${angka(s)}</span>`; };
      const metr = [["accuracy", "Accuracy"], ["precision", "Precision"], ["recall", "Recall"], ["f1", "F1-Score"]];
      const kelas = Object.keys(p.per_kelas);
      $("#hasilUji").innerHTML = `<h3 style="margin-top:1rem">Hasil uji pada ${angka(r.jumlah_data)} baris sampel data uji</h3>
        <div class="grid-2">
          <div class="tabel-wadah"><table><thead><tr><th>Ukuran</th><th class="angka">Penelitian</th><th class="angka">Usulan</th><th class="angka">Selisih</th></tr></thead><tbody>
            ${metr.map(([k, l]) => `<tr><td>${l}</td><td class="angka">${pct(p[k])}</td><td class="angka">${pct(u[k])}</td><td class="angka">${selisih(p[k], u[k])}</td></tr>`).join("")}
            <tr><td>False Positive</td><td class="angka">${angka(p.FP)}</td><td class="angka">${angka(u.FP)}</td><td class="angka">${selisihN(p.FP, u.FP)}</td></tr>
            <tr><td>False Negative</td><td class="angka">${angka(p.FN)}</td><td class="angka">${angka(u.FN)}</td><td class="angka">${selisihN(p.FN, u.FN)}</td></tr>
          </tbody></table></div>
          <div class="tabel-wadah"><table><thead><tr><th>Kelas</th><th class="angka">Ditandai Mirai (penelitian)</th><th class="angka">Ditandai Mirai (usulan)</th></tr></thead><tbody>
            ${kelas.map((k) => `<tr><td>${esc(namaKelas(k))}</td><td class="angka">${desimal(p.per_kelas[k], 2)}%</td><td class="angka">${desimal(u.per_kelas[k], 2)}%</td></tr>`).join("")}
          </tbody></table></div>
        </div>`;
    } catch (e) { $("#hasilUji").innerHTML = galatHTML(e); }
  }));
  $("#btnSimpan").addEventListener("click", (ev) => denganMemuat(ev.currentTarget, "Menyimpan …", async () => {
    try { const r = await apiJSON("/api/aturan", "PUT", kumpulkan()); segarkan(r);
          toast(r.kustom_aktif ? "Ambang kustom disimpan dan dipakai untuk deteksi" : "Ambang sama dengan hasil penelitian"); }
    catch (e) { $("#hasilUji").innerHTML = galatHTML(e); }
  }));
  $("#btnReset").addEventListener("click", (ev) => denganMemuat(ev.currentTarget, "Mengembalikan …", async () => {
    const r = await api("/api/aturan/kustom", { method: "DELETE" }); segarkan(r); $("#hasilUji").innerHTML = "";
    toast("Kembali memakai aturan hasil penelitian");
  }));
};

// ============================ ANALISIS ============================
HAL.analisis = async (el) => {
  const d = await api("/api/analisis");
  const W = { ...WARNA_KELAS, ...(d.warna_kelas || {}) };
  const KELAS = d.protokol.map((p) => p.kelas);
  const st = { fitur: "AVG", jenis: "hist", log: null, sembunyi: new Set(), varian: "rata", tampilP: "bar", tampilD: "bar" };
  const cache = new Map();

  el.innerHTML = `<h1>Analisis Trafik Jaringan</h1>
    <p class="keterangan">Perbandingan ciri trafik Normal dan Mirai pada data penyusunan aturan.</p>
    <div class="tab-kepala" id="tabA">${["Protokol", "Sebaran Atribut", "Atribut Pembeda", "Ringkasan Ciri"]
      .map((n, i) => `<button data-i="${i}">${n}</button>`).join("")}</div>
    <div id="isiA"></div>`;
  const isi = $("#isiA");
  const pilih = (i) => {
    document.querySelectorAll("#tabA button").forEach((b) => b.classList.toggle("aktif", +b.dataset.i === i));
    [tabProtokol, tabSebaran, tabPembeda, tabRingkas][i]();
  };
  document.querySelectorAll("#tabA button").forEach((b) => b.addEventListener("click", () => pilih(+b.dataset.i)));
  const keFitur = (f) => { if (d.fitur_analisis.includes(f)) { st.fitur = f; st.log = null; pilih(1); window.scrollTo({ top: 0, behavior: "smooth" }); } };

  // --- Tab 1: protokol
  function tabProtokol() {
    const urut = ["TCP", "UDP", "GRE", "ICMP", "Campuran/lainnya"];
    const warnaP = { TCP: "#2a78d6", UDP: "#eda100", GRE: "#e34948", ICMP: "#1baf7a", "Campuran/lainnya": "#9aa6b8" };
    const per = d.protokol.map((p) => {
      const tot = Object.values(p.protokol).reduce((a, b) => a + b, 0) || 1;
      const persen = Object.fromEntries(urut.map((k) => [k, 100 * (p.protokol[k] || 0) / tot]));
      const dom = urut.reduce((a, b) => (persen[a] >= persen[b] ? a : b));
      return { kelas: p.kelas, persen, dom, nilai: p.protokol };
    });
    isi.innerHTML = `<div class="grid-kartu k4">${per.map((p) => `<div class="stat-kelas" style="--w:${W[p.kelas]}">
        <div class="kecil">${esc(namaKelas(p.kelas))}</div><div class="besar">${p.dom}</div>
        <div class="kecil">${desimal(p.persen[p.dom])}% paket</div></div>`).join("")}</div>
      <div class="panel"><div class="baris-kontrol" style="margin-top:0">
        ${segmen("segP", [["bar", "Batang"], ["donut", "Donat"]], st.tampilP)}
        <span class="kecil">Klik nama protokol di legenda untuk menyembunyikan atau menampilkannya.</span></div>
        <div id="grafP"></div></div>`;
    const gambar = () => {
      const g = $("#grafP");
      if (st.tampilP === "bar") {
        g.className = "";
        plot(g, urut.map((pr) => ({
          type: "bar", orientation: "h", name: pr, y: per.map((p) => namaKelas(p.kelas)), x: per.map((p) => p.persen[pr]),
          marker: { color: warnaP[pr] }, text: per.map((p) => (p.persen[pr] >= 4 ? desimal(p.persen[pr]) + "%" : "")),
          textposition: "inside", insidetextanchor: "middle", hovertemplate: `%{y}<br>${pr}: %{x:.1f}%<extra></extra>`,
        })), { barmode: "stack", bargap: 0.35, xaxis: { range: [0, 100], title: { text: "% paket dalam kelas" }, ticksuffix: "%" },
               yaxis: { autorange: "reversed" }, legend: { orientation: "h", y: 1.12, x: 0, traceorder: "normal" }, margin: { l: 10, r: 10, t: 50, b: 10 } }, 360);
      } else {
        g.className = "grid-2";
        g.innerHTML = per.map((_, j) => `<div id="pie${j}"></div>`).join("");
        per.forEach((p, j) => {
          const nilai = {}; urut.forEach((k) => { if (p.nilai[k]) nilai[k] = p.nilai[k]; });
          donut(`pie${j}`, nilai, namaKelas(p.kelas), warnaP, `<b>${p.dom}</b><br>${desimal(p.persen[p.dom])}%`, 320);
        });
      }
    };
    ikatSegmen("segP", (v) => { st.tampilP = v; gambar(); });
    gambar();
  }

  // --- Tab 2: sebaran atribut
  function tabSebaran() {
    const sisa = d.fitur_analisis.filter((f) => !KELOMPOK_FITUR.some(([, a]) => a.includes(f)));
    const grup = [...KELOMPOK_FITUR, ["Lainnya", sisa]]
      .map(([g, a]) => [g, a.filter((f) => d.fitur_analisis.includes(f))]).filter(([, a]) => a.length);
    if (st.log === null) st.log = ["Rate", "IAT", "Std"].includes(st.fitur);
    isi.innerHTML = `<div class="panel">
        <div class="baris-kontrol" style="margin-top:0">
          <select id="pilihFitur" aria-label="Pilih atribut">${grup.map(([g, a]) => `<optgroup label="${esc(g)}">${a.map((f) =>
            `<option value="${esc(f)}" ${f === st.fitur ? "selected" : ""}>${esc(namaFitur(f))}</option>`).join("")}</optgroup>`).join("")}</select>
          ${segmen("segJenis", [["hist", "Histogram"], ["box", "Kotak"]], st.jenis)}
          <label class="saklar"><input type="checkbox" id="cekLog" ${st.log ? "checked" : ""}><span></span> Skala log</label>
        </div>
        <div class="baris-kontrol" id="chipKelas">${KELAS.map((k) => `<button class="chip ${st.sembunyi.has(k) ? "mati" : ""}" data-k="${esc(k)}"
          style="--w:${W[k]}"><i></i>${esc(namaKelas(k))}</button>`).join("")}</div>
        <div class="judul-grafik" id="judulFitur"></div>
        <div id="grafikFitur" class="grafik"></div>
      </div>
      <div class="grid-kartu k4" id="statKelas" style="margin-top:1rem"></div>
      <details><summary>Lihat angka lengkap</summary><div id="tabelStat"></div></details>`;

    const gambar = async () => {
      const f = st.fitur, kunci = `${f}|${st.log ? 1 : 0}`;
      $("#judulFitur").innerHTML = `<b>${esc(namaFitur(f))}</b> <code>${esc(f)}</code> <span class="kecil">${esc(descFitur(f))}</span>`;
      try {
        if (!cache.has(kunci)) cache.set(kunci, await api(`/api/analisis/fitur/${encodeURIComponent(f)}?log=${st.log ? 1 : 0}`));
        const s = cache.get(kunci);
        const seri = s.seri.filter((r) => !st.sembunyi.has(r.kelas));
        if (st.jenis === "hist") {
          plot("grafikFitur", seri.map((r) => ({ type: "bar", name: namaKelas(r.kelas), x: s.tengah_bin, y: r.persen, opacity: 0.62,
            marker: { color: r.warna }, hovertemplate: `%{y:.2f}%<extra>${esc(namaKelas(r.kelas))}</extra>` })),
            { barmode: "overlay", bargap: 0, hovermode: "x unified", showlegend: false,
              xaxis: { title: { text: namaFitur(f) }, type: s.log ? "log" : "linear" },
              yaxis: { title: { text: "% data dalam kelas" }, ticksuffix: "%" }, margin: { l: 10, r: 10, t: 10, b: 10 } }, 380);
        } else {
          plot("grafikFitur", seri.map((r) => ({ type: "box", name: namaKelas(r.kelas), x: [namaKelas(r.kelas)], q1: [r.kuartil[1]], median: [r.kuartil[2]],
            q3: [r.kuartil[3]], lowerfence: [r.kuartil[0]], upperfence: [r.kuartil[4]], marker: { color: r.warna }, fillcolor: r.warna + "55",
            line: { color: r.warna } })), { showlegend: false, yaxis: { title: { text: namaFitur(f) }, type: s.log ? "log" : "linear" },
            margin: { l: 10, r: 10, t: 10, b: 10 } }, 380);
        }
        $("#statKelas").innerHTML = s.statistik.map((r) => `<div class="stat-kelas ${st.sembunyi.has(r.kelas) ? "redup" : ""}" style="--w:${W[r.kelas]}">
          <div class="kecil">${esc(namaKelas(r.kelas))} · nilai tengah</div><div class="besar">${fmt4(r.median)}</div>
          <div class="kecil">90% data: ${fmt4(r.p05)} – ${fmt4(r.p95)}</div></div>`).join("");
        $("#tabelStat").innerHTML = tabelHTML(s.statistik.map((r) => ({ ...r, kelas: namaKelas(r.kelas) })), ["kelas", "mean", "std", "p05", "median", "p95"], {
          judul: { kelas: "Kelas", mean: "Rata-rata", std: "Simpangan baku", p05: "Persentil 5", median: "Nilai tengah", p95: "Persentil 95" } });
      } catch (e) { $("#grafikFitur").innerHTML = galatHTML(e); }
    };
    $("#pilihFitur").addEventListener("change", (e) => { st.fitur = e.target.value; st.log = ["Rate", "IAT", "Std"].includes(st.fitur); $("#cekLog").checked = st.log; gambar(); });
    $("#cekLog").addEventListener("change", (e) => { st.log = e.target.checked; gambar(); });
    ikatSegmen("segJenis", (v) => { st.jenis = v; gambar(); });
    document.querySelectorAll("#chipKelas .chip").forEach((c) => c.addEventListener("click", () => {
      const k = c.dataset.k;
      if (st.sembunyi.has(k)) st.sembunyi.delete(k);
      else if (st.sembunyi.size < KELAS.length - 1) st.sembunyi.add(k);
      c.classList.toggle("mati", st.sembunyi.has(k)); gambar();
    }));
    gambar();
  }

  // --- Tab 3: atribut pembeda (Youden J)
  function tabPembeda() {
    const p = d.daya_pisah;
    const tingkat = (v) => (v >= 0.9 ? ["#0ca30c", "Sangat jelas"] : v >= 0.7 ? ["#2a78d6", "Cukup jelas"] : ["#b4bdcb", "Lemah"]);
    isi.innerHTML = `<div class="panel">
        <div class="baris-kontrol" style="margin-top:0">
          ${segmen("segVar", [["rata", "Semua varian"], ...p.varian.map((v) => [v, namaKelas(v)])], st.varian)}
          ${segmen("segTampil", [["bar", "Batang"], ["heat", "Peta panas"]], st.tampilD)}
        </div>
        <div class="baris-kontrol legenda"><span><i style="background:#0ca30c"></i>Sangat jelas (≥ 0,9)</span>
          <span><i style="background:#2a78d6"></i>Cukup jelas (0,7–0,9)</span><span><i style="background:#b4bdcb"></i>Lemah (&lt; 0,7)</span>
          <span class="kecil">· klik atribut untuk melihat sebarannya</span></div>
        <div id="grafD"></div></div>`;
    const gambar = () => {
      let g;
      if (st.tampilD === "heat") {
        $("#segVar").style.display = "none";
        g = plot("grafD", [{ type: "heatmap", z: p.nilai, x: p.varian.map(namaKelas), y: p.fitur.map(namaFitur), customdata: p.fitur.map((f) => p.varian.map(() => f)),
          zmin: 0, zmax: 1, colorscale: SKALA_BIRU, xgap: 2, ygap: 2, text: p.nilai.map((r) => r.map((v) => desimal(v, 2))), texttemplate: "%{text}",
          colorbar: { title: { text: "Daya pisah" } }, hovertemplate: "%{y} · %{x}<br>Daya pisah: %{z:.3f}<extra></extra>" }],
          { yaxis: { autorange: "reversed" }, margin: { l: 10, r: 10, t: 10, b: 10 } }, 520);
      } else {
        $("#segVar").style.display = "";
        const kol = st.varian === "rata" ? null : p.varian.indexOf(st.varian);
        const nilai = p.nilai.map((r) => (kol === null ? r.reduce((a, b) => a + b, 0) / r.length : r[kol]));
        const urut = p.fitur.map((f, i) => ({ f, v: nilai[i] })).sort((a, b) => b.v - a.v);
        g = plot("grafD", [{ type: "bar", orientation: "h", y: urut.map((x) => namaFitur(x.f)), x: urut.map((x) => x.v), customdata: urut.map((x) => x.f),
          marker: { color: urut.map((x) => tingkat(x.v)[0]) }, text: urut.map((x) => desimal(x.v, 2)), textposition: "outside",
          hovertemplate: "%{y}<br>Daya pisah: %{x:.3f}<extra></extra>" }],
          { yaxis: { autorange: "reversed" }, xaxis: { range: [0, 1.08], title: { text: "Daya pisah (0 = tidak membedakan, 1 = terpisah sempurna)" } },
            bargap: 0.3, margin: { l: 10, r: 10, t: 10, b: 10 } }, 520);
      }
      saatKlik(g, (ev) => keFitur(ev.points[0].customdata));
    };
    ikatSegmen("segVar", (v) => { st.varian = v; gambar(); });
    ikatSegmen("segTampil", (v) => { st.tampilD = v; gambar(); });
    gambar();
  }

  // --- Tab 4: ringkasan ciri
  function tabRingkas() {
    const CIRI = [
      ["Protocol Type", "Jenis protokol", "TCP (ada sesi)", "GRE", "UDP"],
      ["Header_Length", "Panjang header", "± 20–32", "≈ 0", "≈ 8"],
      ["ack_flag_number", "Paket balasan TCP", "Sering", "Hampir tidak ada", "Hampir tidak ada"],
      ["AVG", "Ukuran paket rata-rata", "Beragam (± 250 B)", "Seragam ± 578–592 B", "Seragam ± 554 B"],
      ["Rate", "Laju paket", "± 170 per detik", "± 4.000–4.700 per detik", "± 5.000 per detik"],
    ];
    isi.innerHTML = `<div class="grid-ciri">${CIRI.map(([f, judul, n, g, u]) => `<button class="kartu-ciri" data-f="${esc(f)}">
        <div class="kepala"><b>${judul}</b><span class="kecil">lihat grafik →</span></div>
        <div class="baris-ciri"><i style="background:${W.BenignTraffic}"></i><span>Normal</span><b>${n}</b></div>
        <div class="baris-ciri mirai"><i style="background:${W["Mirai-greeth_flood"]}"></i><span>Mirai GREeth / GREIP</span><b>${g}</b></div>
        <div class="baris-ciri mirai"><i style="background:${W["Mirai-udpplain"]}"></i><span>Mirai UDPplain</span><b>${u}</b></div>
      </button>`).join("")}</div>
      ${kotakInfo("Intinya", "Trafik Mirai <b>seragam</b>: satu jenis protokol, tanpa sesi TCP, ukuran paket besar dan tetap. Ciri inilah yang menjadi aturan IF-THEN.", "check")}`;
    document.querySelectorAll(".kartu-ciri").forEach((c) => c.addEventListener("click", () => keFitur(c.dataset.f)));
  }

  pilih(0);
};

// ============================ DETEKSI SERANGAN ============================
function htmlRingkasData(d) {
  const hilang = d.atribut_hilang || [];
  const komp = d.komposisi_label ? Object.entries(d.komposisi_label) : null;
  const tot = komp ? komp.reduce((a, [, v]) => a + v, 0) || 1 : 1;
  const mini = (n, label, nilai, sub, warna = "#1f6fd6") => `<div class="mini"><span class="bulat" style="background:${warna}1a">${ikon(n, warna, 18)}</span>
    <div><div class="kecil">${label}</div><b>${nilai}</b>${sub ? `<div class="kecil potong" title="${esc(sub)}">${esc(sub)}</div>` : ""}</div></div>`;
  return `<div class="grid-mini">
      ${mini("database", "Jumlah baris", angka(d.jumlah_baris), d.sumber)}
      ${mini("list", "Jumlah kolom", angka(d.jumlah_kolom), "", "#4a3aa7")}
      ${mini(hilang.length ? "alert" : "check", "Atribut aturan", hilang.length ? "Kurang" : "Lengkap", hilang.length ? hilang.join(", ") : d.atribut_rule.join(", "), hilang.length ? "#d03b3b" : "#0ca30c")}
      ${mini("info", "Label (kunci jawaban)", d.ada_label ? "Ada" : "Tidak ada", d.ada_label ? "akurasi dapat dihitung" : "hanya prediksi", "#c98500")}
    </div>
    ${komp ? `<div class="panel" style="margin-top:.9rem"><div class="kepala-ikon" style="margin-bottom:.6rem"><b>Komposisi label</b>
        <span class="kecil">${komp.length === 1 ? "hanya satu kelas" : `${komp.length} kelas`}</span></div>
      <div class="bar-komposisi">${komp.map(([k, v]) => `<span style="width:${100 * v / tot}%;background:${WARNA_KELAS[k] || "#9aa6b8"}"
        title="${esc(namaKelas(k))}: ${angka(v)} baris"></span>`).join("")}</div>
      <div class="legenda" style="margin-top:.5rem">${komp.map(([k, v]) => `<span><i style="background:${WARNA_KELAS[k] || "#9aa6b8"}"></i>${esc(namaKelas(k))} <b>${angka(v)}</b></span>`).join("")}</div>
      ${komp.length === 1 ? `<p class="catatan">${ikon("alert", "#c98500", 16)} Semua baris berlabel <b>${esc(namaKelas(komp[0][0]))}</b>, jadi hasil deteksi wajar hampir seluruhnya
        <b>${komp[0][0] === "BenignTraffic" ? "Normal" : "Mirai"}</b>. Pakai <b>Contoh campuran</b> untuk melihat sistem memisahkan keduanya.</p>` : ""}
    </div>` : ""}
    <details><summary>Pratinjau 100 baris pertama</summary>${tabelHTML(d.pratinjau, d.kolom, { tinggi: true })}</details>`;
}

async function htmlRiwayat(w) {
  const { riwayat } = await api("/api/riwayat");
  if (!riwayat.length) {
    w.innerHTML = judulBagian("", "Riwayat Hasil Deteksi") + `<div class="panel kosong">${ikon("clock", "#9aa6b8", 28)}<span>Belum ada riwayat. Setiap deteksi akan tercatat di sini.</span></div>`;
    return;
  }
  const p = (v) => (v == null ? "–" : pct(v));
  w.innerHTML = judulBagian("", `Riwayat Hasil Deteksi <span class="lencana lencana-netral">${angka(riwayat.length)}</span>`) + `<div class="panel">
    ${tabelHTML(riwayat, ["waktu", "sumber_data", "aturan", "jumlah_baris", "mirai", "normal", "persen_mirai", "accuracy", "f1", "FP", "FN", "id"], {
      judul: { waktu: "Waktu", sumber_data: "Sumber data", aturan: "Aturan", jumlah_baris: "Jumlah baris", mirai: "Mirai", normal: "Normal",
               persen_mirai: "% Mirai", accuracy: "Accuracy", f1: "F1-Score", id: "Unduh" },
      format: { jumlah_baris: angka, mirai: angka, normal: angka, FP: angka, FN: angka, aturan: (v) => lencanaAturan(v),
                persen_mirai: (v) => desimal(v, 2) + "%", accuracy: p, f1: p,
                id: (v) => `<a href="/api/riwayat/${encodeURIComponent(v)}/unduh">CSV</a>` },
      tinggi: true })}
    <div class="baris-kontrol"><span class="kecil isi">Accuracy dan F1-Score hanya terisi jika data berlabel.</span>
      <button class="tombol bahaya" id="btnHapusRiwayat">Hapus riwayat</button></div></div>`;
  $("#btnHapusRiwayat").addEventListener("click", async () => {
    if (!confirm("Hapus seluruh riwayat deteksi beserta file hasilnya? Tindakan ini tidak dapat dibatalkan.")) return;
    await api("/api/riwayat", { method: "DELETE" }); toast("Riwayat dihapus"); htmlRiwayat(w);
  });
}

function htmlHasil(d) {
  const n = d.jumlah_baris || 1, m = d.metrik;
  return `${gridKartu([
      kartu("check", "Data Normal", angka(d.normal), `${desimal(100 * d.normal / n)}% dari data`, "hijau"),
      kartu("alert", "Data Mirai", angka(d.mirai), `${desimal(100 * d.mirai / n)}% dari data`, "merah"),
      kartu("target", "Akurasi", m ? pct(m.accuracy, 1) : "–", m ? `F1-Score ${pct(m.f1, 1)}` : "data tanpa label", "biru"),
      kartu("clock", "Waktu Deteksi", `${desimal(d.durasi_ms)} ms`, `${angka(d.jumlah_baris)} baris · ${lencanaAturan(d.aturan)}`, "ungu"),
    ])}
    ${d.tidak_valid ? `<p class="keterangan">${angka(d.tidak_valid)} baris memiliki NaN/inf pada atribut aturan dan ditandai 'Tidak valid'.</p>` : ""}
    <div class="panel">
      <div class="tab-kepala" id="tabHasil" style="margin-top:0">
        <button data-t="grafik" class="aktif">Grafik</button><button data-t="tabel">Tabel per baris</button>
        ${m ? '<button data-t="eval">Evaluasi terhadap label</button>' : ""}</div>
      <div data-isi="grafik">
        <div class="grid-2" style="margin-bottom:0"><div id="pieHasil" class="grafik"></div><div id="barRule" class="grafik"></div></div>
        <p class="kecil">Klik bagian grafik untuk membuka baris datanya.</p></div>
      <div data-isi="tabel" hidden>
        <div class="baris-kontrol" style="margin-top:0">
          ${segmen("filter", [["Semua", "Semua"], ["Mirai", "Mirai"], ["Normal", "Normal"]], "Semua")}
          <input type="text" class="isi" id="cari" placeholder="Cari aturan / kelas / file …">
          <a class="tombol" href="/api/deteksi/unduh">Unduh CSV</a>
        </div>
        <div id="tabelHasil"></div><p class="kecil" id="infoHasil"></p></div>
      ${m ? `<div data-isi="eval" hidden>${kartuMetrik(m)}
        <div class="grid-2" style="margin-bottom:0"><div id="cmHasil" class="grafik"></div>
          <div><h3>Prediksi per kelas aktual</h3><div id="perKelas"></div></div></div></div>` : ""}
    </div>`;
}

function aktifkanHasil(d) {
  let filt = "Semua", tunda, evalDigambar = false;
  const tunjuk = (t) => {
    document.querySelectorAll("#tabHasil button").forEach((b) => b.classList.toggle("aktif", b.dataset.t === t));
    document.querySelectorAll("[data-isi]").forEach((x) => { x.hidden = x.dataset.isi !== t; });
    const wadah = document.querySelector(`[data-isi="${t}"]`);
    if (t === "eval" && !evalDigambar && d.metrik) {
      evalDigambar = true;
      confusion("cmHasil", d.metrik);
      $("#perKelas").innerHTML = tabelHTML(d.per_kelas.map((r) => ({ ...r, kelas: namaKelas(r.kelas) })), null,
        { judul: { kelas: "Kelas aktual" }, format: Object.fromEntries(["Mirai", "Normal", "Tidak valid"].map((k) => [k, angka])) });
    }
    if (wadah) ubahUkuran(wadah);
  };
  const setFilter = (f) => {
    filt = f;
    document.querySelectorAll("#filter button").forEach((x) => x.classList.toggle("aktif", x.dataset.v === f));
  };
  const muatBaris = async () => {
    const r = await api(`/api/deteksi/baris?filter=${encodeURIComponent(filt)}&cari=${encodeURIComponent($("#cari").value)}`);
    $("#tabelHasil").innerHTML = tabelHTML(r.baris, r.kolom, { format: { Prediksi: lencana }, tinggi: true });
    $("#infoHasil").textContent = `Menampilkan ${angka(Math.min(r.total, 1000))} dari ${angka(r.total)} baris.`;
  };
  document.querySelectorAll("#tabHasil button").forEach((b) => b.addEventListener("click", () => tunjuk(b.dataset.t)));
  ikatSegmen("filter", (v) => { setFilter(v); muatBaris(); });
  $("#cari").addEventListener("input", () => { clearTimeout(tunda); tunda = setTimeout(muatBaris, 300); });
  muatBaris();

  const pie = donut("pieHasil", { Normal: d.normal, Mirai: d.mirai }, "Perbandingan Prediksi", WARNA_BINER, `${angka(d.jumlah_baris)}<br>data`);
  saatKlik(pie, (ev) => { setFilter(ev.points[0].label); $("#cari").value = ""; muatBaris(); tunjuk("tabel"); });
  const rt = d.rule_terbanyak || [];
  if (rt.length) {
    const bar = plot("barRule", [{ type: "bar", orientation: "h", x: rt.map((r) => r.jumlah), y: rt.map((r) => r.rule), text: rt.map((r) => angka(r.jumlah)),
      textposition: "auto", marker: { color: WARNA_BINER.Mirai }, hovertemplate: "%{y}: %{x:,} baris<extra></extra>" }],
      { title: { text: "Aturan yang paling sering terpenuhi" }, yaxis: { autorange: "reversed" }, xaxis: { title: { text: "jumlah baris" } }, bargap: 0.4 }, 320);
    saatKlik(bar, (ev) => { setFilter("Semua"); $("#cari").value = ev.points[0].y; muatBaris(); tunjuk("tabel"); });
  } else {
    $("#barRule").innerHTML = `<div class="kosong" style="height:100%">${ikon("check", "#0ca30c", 28)}<span>Tidak ada aturan yang terpenuhi: semua data Normal.</span></div>`;
  }
}

HAL.deteksi = async (el) => {
  const [ds, aturan, dataAktif, detAktif] = await Promise.all([api("/api/dataset"), api("/api/aturan"), api("/api/data"), api("/api/deteksi")]);
  let pilihan = ds.contoh_tersedia ? "contoh" : "sampel";
  const opsi = (v, n, judul, desk, meta, mati = false) => `<label class="opsi ${mati ? "mati" : ""}" data-v="${v}">
      <span class="opsi-ikon">${ikon(n, "#1f6fd6", 22)}</span>
      <span class="opsi-teks"><b>${judul}</b><span class="kecil">${desk}</span></span>
      <span class="meta" ${v === "unggah" ? 'id="metaUnggah"' : ""}>${meta}</span>
      <input type="radio" name="sumber" value="${v}" ${mati ? "disabled" : ""}></label>`;

  el.innerHTML = `<h1>Deteksi Serangan</h1>
    <p class="keterangan">Pilih data trafik, lalu jalankan deteksi dengan aturan IF-THEN.</p>
    <div class="langkah-bar" id="langkahBar"></div>

    <section class="panel panel-pilih" id="bagian1">
      <div class="kolom-unggah">
        ${kepalaIkon("upload", "Unggah berkas uji")}
        <label class="dropzone" id="dz">${ikon("upload", "#1f6fd6", 30)}
          <div style="margin-top:.35rem"><b>Pilih file CSV</b></div>
          <div class="kecil">atau seret dan lepas file di sini</div>
          <input type="file" id="inputFile" accept=".csv" multiple></label>
        <div class="daftar-file" id="daftarFile"></div>
        <details class="kecil-detail"><summary>Dataset apa saja yang dipakai sistem?</summary>
          <p class="kecil">Semua <b>${angka(ds.total_file)} berkas</b> di folder <code>dataset2023</code> (${angka(ds.total_baris)} baris).
            Satu berkas hanya berisi <b>satu kelas</b>, sehingga berkas dari folder <code>begin</code> hasilnya Normal semua.</p>
          ${tabelHTML(ds.per_folder.map((r) => ({ ...r, kelas: namaKelas(r.kelas) })), ["folder", "kelas", "jumlah_file", "total_baris"], {
            judul: { folder: "Folder", kelas: "Kelas", jumlah_file: "Berkas", total_baris: "Baris" }, format: { jumlah_file: angka, total_baris: angka } })}
        </details>
      </div>
      <div class="kartu-pilih">
        ${kepalaIkon("database", "Pilih data", "data yang akan diperiksa")}
        ${opsi("unggah", "upload", "Berkas yang diunggah", "CSV CICIoT2023 per-PCAP milik Anda", "belum ada berkas")}
        ${opsi("contoh", "shuffle", "Contoh campuran", "Normal + 3 varian Mirai, sudah berlabel", "10.000 baris", !ds.contoh_tersedia)}
        ${opsi("sampel", "target", "Sampel data uji", "Diambil acak dari 30% data uji", "120.000 baris")}
        <div class="baris-aturan"><span>Aturan yang dipakai</span>${lencanaAturan(aturan.nama_aktif)}<a href="#beranda" class="kecil">ubah di Beranda</a></div>
        <button class="tombol utama lebar besar" id="btnMulai">${ikon("play", "#fff", 16)} Mulai Deteksi</button>
        <div id="pesan1"></div>
        <p class="kecil" style="margin:.5rem 0 0">Data dibaca, diperiksa, lalu dideteksi. Hasilnya tercatat otomatis di riwayat.</p>
      </div>
    </section>

    <section class="bagian" id="bagian2"></section>
    <section class="bagian" id="bagian3"></section>
    <section class="bagian" id="riwayat"></section>`;

  const LANGKAH = [["bagian1", "Pilih data"], ["bagian2", "Data terproses"], ["bagian3", "Hasil deteksi"]];
  const bar = (tahap) => {
    $("#langkahBar").innerHTML = LANGKAH.map(([id, t], i) => `<button data-ke="${id}" class="${i + 1 < tahap ? "selesai" : i + 1 === tahap ? "aktif" : ""}"
      ${i + 1 > tahap ? "disabled" : ""}>${i + 1 < tahap ? "✓" : i + 1}. ${t}</button>`).join("");
    document.querySelectorAll("#langkahBar button").forEach((b) => b.addEventListener("click", () =>
      document.getElementById(b.dataset.ke).scrollIntoView({ behavior: "smooth" })));
  };
  const setPilihan = (v) => {
    pilihan = v;
    document.querySelectorAll(".opsi").forEach((o) => {
      o.classList.toggle("pilih", o.dataset.v === v);
      o.querySelector("input").checked = o.dataset.v === v;
    });
  };
  document.querySelectorAll(".opsi input").forEach((r) => r.addEventListener("change", () => setPilihan(r.value)));

  const tampilkanData = (d) => {
    const hilang = d.atribut_hilang || [];
    $("#bagian2").innerHTML = judulBagian(2, "Data terproses", `Data dibaca dan diperiksa kelengkapannya. Deteksi memakai ${lencanaAturan(aturan.nama_aktif)}.`)
      + htmlRingkasData(d)
      + (hilang.length ? `<div class="kotak-galat">Kolom yang dibutuhkan aturan tidak ada: ${esc(hilang.join(", "))}</div>` : "");
    $("#bagian3").innerHTML = "";
    bar(2);
  };
  const tampilkanHasil = (d, gulir = true) => {
    $("#bagian3").innerHTML = judulBagian(3, "Hasil deteksi", `Sumber: ${esc(d.sumber)}`) + htmlHasil(d);
    aktifkanHasil(d);
    bar(3);
    if (gulir) $("#bagian3").scrollIntoView({ behavior: "smooth" });
  };

  // Berkas unggahan
  const input = $("#inputFile"), dz = $("#dz");
  const tampilFile = () => {
    const f = [...input.files];
    const mb = f.reduce((a, x) => a + x.size, 0) / 1048576;
    $("#daftarFile").innerHTML = f.length ? f.map((x) => `<span class="file-chip">${ikon("list", "#52607a", 14)} ${esc(x.name)}</span>`).join("") : "";
    $("#metaUnggah").textContent = f.length ? `${f.length} berkas · ${desimal(mb)} MB` : "belum ada berkas";
    if (f.length) setPilihan("unggah");
  };
  input.addEventListener("change", tampilFile);
  ["dragenter", "dragover"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.add("seret"); }));
  ["dragleave", "drop"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.remove("seret"); }));
  dz.addEventListener("drop", (ev) => { input.files = ev.dataTransfer.files; tampilFile(); });

  // Mulai deteksi: muat data -> tampilkan data terproses -> deteksi -> hasil
  const btnMulai = $("#btnMulai");
  btnMulai.addEventListener("click", () => {
    $("#pesan1").innerHTML = "";
    if (pilihan === "unggah" && !input.files.length) {
      $("#pesan1").innerHTML = `<div class="kotak-galat">Pilih berkas CSV terlebih dahulu di kotak sebelah kiri.</div>`;
      return;
    }
    denganMemuat(btnMulai, "Membaca data …", async (label) => {
      try {
        let data;
        if (pilihan === "unggah") {
          const fd = new FormData(); [...input.files].forEach((f) => fd.append("files", f));
          data = await api("/api/data/unggah", { method: "POST", body: fd });
        } else {
          data = await api(pilihan === "contoh" ? "/api/data/contoh" : "/api/data/sampel", { method: "POST" });
        }
        tampilkanData(data);
        if ((data.atribut_hilang || []).length) { $("#bagian2").scrollIntoView({ behavior: "smooth" }); return; }
        label("Memeriksa trafik terhadap aturan …");
        const r = await api("/api/deteksi", { method: "POST" });
        tampilkanHasil(r);
        toast("Deteksi selesai dan tercatat di riwayat");
        htmlRiwayat($("#riwayat"));
      } catch (e) { $("#pesan1").innerHTML = galatHTML(e); }
    });
  });

  // Pulihkan keadaan sesi (bila pengguna kembali ke halaman ini)
  setPilihan(pilihan);
  bar(1);
  if (dataAktif.ada) tampilkanData(dataAktif);
  if (detAktif.ada) tampilkanHasil(detAktif, false);
  htmlRiwayat($("#riwayat"));
};

// ============================ EVALUASI ============================
HAL.evaluasi = async (el) => {
  const d = await api("/api/evaluasi"), ev = d.eval, b = ev.biner, w = d.waktu, tot = ev.jumlah_data;
  const mirai = b.TP + b.FP, normal = b.TN + b.FN;
  const W = { ...WARNA_KELAS, ...(d.warna_kelas || {}) };
  const baris = (label, nilai, tip = "", bar = null) => `<div class="baris-kv"><span>${label}${tip ? ` <i class="tanya" title="${esc(tip)}">?</i>` : ""}</span>
    <div><b>${nilai}</b>${bar != null ? `<div class="mini-bar"><i style="width:${(100 * bar).toFixed(2)}%"></i></div>` : ""}</div></div>`;

  el.innerHTML = `<h1>Evaluasi Sistem</h1>
    <p class="keterangan">Aturan hasil penelitian diuji pada <b>${angka(tot)} baris data uji</b> (30% data yang tidak dipakai saat menyusun aturan).</p>

    <section class="bagian">${judulBagian("", "Ringkasan kinerja")}
      <div class="grid-2">
        <div class="kartu-detail" style="--aksen:#1f6fd6">
          <div class="kepala"><h3>Hasil Deteksi</h3><span class="badge">data uji · ${angka(tot)} baris</span></div>
          ${baris("Total data uji", `${angka(tot)} baris`)}
          ${baris("Diprediksi Mirai", `${angka(mirai)} <span class="kecil">(${desimal(100 * mirai / tot)}%)</span>`)}
          ${baris("Diprediksi Normal", `${angka(normal)} <span class="kecil">(${desimal(100 * normal / tot)}%)</span>`)}
          ${baris("Mirai tertangkap benar", angka(b.TP), "True Positive: data Mirai yang ditandai Mirai")}
          ${baris("Normal dikenali benar", angka(b.TN), "True Negative: data normal yang ditandai Normal")}
          ${baris("Waktu deteksi", `${desimal(w.waktu_batch_detik * 1000)} ms`, "waktu memeriksa seluruh data uji sekaligus")}
          ${baris("Kecepatan", `${desimal(w.latensi_per_baris_mikrodetik, 2)} µs per baris`)}
          ${baris("Waktu menyusun aturan", `${desimal(w.waktu_penyusunan_rule_detik)} detik`)}
        </div>
        <div class="kartu-detail" style="--aksen:#6a4fd0">
          <div class="kepala"><h3>Metrik Evaluasi</h3><span class="badge">${ev.kualitas_rule.length} aturan hasil penelitian</span></div>
          ${baris("Accuracy", pct(b.accuracy), "persentase seluruh tebakan yang benar", b.accuracy)}
          ${baris("Precision", pct(b.precision), "dari semua yang dituduh Mirai, berapa yang benar Mirai", b.precision)}
          ${baris("Recall", pct(b.recall), "dari semua Mirai, berapa yang berhasil ditangkap", b.recall)}
          ${baris("F1-Score", pct(b.f1), "nilai gabungan Precision dan Recall", b.f1)}
          ${baris("False Positive", `${angka(b.FP)} <span class="kecil">normal dituduh Mirai</span>`, "trafik normal yang salah ditandai Mirai")}
          ${baris("False Negative", `${angka(b.FN)} <span class="kecil">Mirai lolos</span>`, "trafik Mirai yang tidak terdeteksi")}
        </div>
      </div>
      <div class="grid-2">
        <div class="panel"><div id="cmEval" class="grafik"></div></div>
        <div class="panel"><div id="barKelas" class="grafik"></div>
          <p class="kecil">Normal = salah tuduh (makin kecil makin baik). Varian Mirai = tertangkap (makin besar makin baik).</p></div>
      </div>
    </section>`;

  confusion("cmEval", b);
  const pk = ev.per_kelas;
  plot("barKelas", [{ type: "bar", orientation: "h", x: pk.map((r) => r.persen_ditandai), y: pk.map((r) => namaKelas(r.kelas)),
    customdata: pk.map((r) => [angka(r.ditandai_mirai), angka(r.jumlah)]),
    text: pk.map((r) => desimal(r.persen_ditandai, 2) + "%"), textposition: "auto",
    hovertemplate: "%{y}<br>%{customdata[0]} dari %{customdata[1]} baris ditandai Mirai<extra></extra>",
    marker: { color: pk.map((r) => W[r.kelas] || "#9aa6b8") } }],
    { title: { text: "Persentase ditandai Mirai per kelas" }, yaxis: { autorange: "reversed" }, xaxis: { range: [0, 112], title: { text: "%" } }, bargap: 0.4 }, 330);
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const ALIAS = { unggah: "deteksi", hasil: "deteksi", tentang: "beranda" };   // tautan lama
async function render() {
  let hal = (location.hash || "#beranda").slice(1);
  hal = ALIAS[hal] || hal;
  const fn = HAL[hal] || HAL.beranda;
  document.querySelectorAll("#menu a").forEach((a) => a.classList.toggle("aktif", a.dataset.hal === hal));
  $("#sidebar").classList.remove("buka");
  const el = $("#konten");
  el.innerHTML = `<p class="muat"><span class="putar"></span> Memuat …</p>`;
  window.scrollTo(0, 0);
  try { await fn(el); } catch (e) { el.innerHTML = galatHTML(e); }
}
document.querySelectorAll("[data-ikon]").forEach((s) => {
  const n = s.dataset.ikon;
  s.outerHTML = s.classList.contains("ikon-brand") ? ikon(n, "#ffffff", 34, 2) : ikon(n, "#c9d4e5", n === "user" ? 22 : 18);
});
$("#tombolMenu").addEventListener("click", () => $("#sidebar").classList.toggle("buka"));
window.addEventListener("hashchange", render);
render();
