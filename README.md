# OTP Helper

Aplikasi desktop Windows ringan untuk menyimpan secret dan mengenerate kode 2FA (TOTP) secara offline.

## Download & Cara Pakai

1. Unduh binary `OTP-Helper.exe` siap pakai melalui halaman [GitHub Releases](https://github.com/tiomultazem/otp-helper/releases) (atau kompilasi mandiri dengan menjalankan `build_native.bat`).
2. Jalankan `OTP-Helper.exe`.
3. Buat master password (minimal 6 karakter) saat pertama kali dibuka.

## Cara Ekstrak & Simpan Secret (via Aegis)

1. **Google Authenticator:** Buka menu Transfer Akun > Ekspor Akun (tampilkan kode QR).
2. **Aegis Authenticator:** Scan kode QR tersebut menggunakan Aegis.
3. **Ekspor JSON:** Di Aegis, lakukan ekspor data ke format JSON (Plaintext).
4. **Ambil Secret:** Buka file JSON, cari baris `"secret": "..."`. Nilai string tersebut adalah secret Base32 akun.
5. **Simpan ke Aplikasi:** Buka OTP Helper, klik `+ Tambah`, isi `Nama Akun`, tempel secret ke `Secret Key (Base32)`, lalu klik `Simpan`.

> [!CAUTION]
> **PERINGATAN KEAMANAN:** File JSON hasil ekspor memuat kunci rahasia dalam bentuk teks polos. Segera hapus permanen file JSON dan bersihkan riwayat clipboard setelah selesai memindahkan secret. Jangan pernah menyimpan atau membagikan file tersebut.

## Atribusi

<a href="https://www.flaticon.com/free-icons/secret" title="secret icons">Secret icons created by IwitoStudio - Flaticon</a>

---

2026 made with ❤️, Gilang Wahyu Prasetyo © BPS Kabupaten Tabalong
