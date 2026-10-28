using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace OTPHelper
{
    // =======================================================================
    // UI Helpers (GDI32 Native Rounded Corners)
    // =======================================================================
    public static class UIUtils
    {
        [DllImport("gdi32.dll", EntryPoint = "CreateRoundRectRgn")]
        public static extern IntPtr CreateRoundRectRgn(
            int nLeftRect, int nTopRect, int nRightRect, int nBottomRect,
            int nWidthEllipse, int nHeightEllipse);

        public static void SetRounded(Control control, int radius)
        {
            if (control.Width > 0 && control.Height > 0)
            {
                IntPtr ptr = CreateRoundRectRgn(0, 0, control.Width + 1, control.Height + 1, radius, radius);
                control.Region = Region.FromHrgn(ptr);
            }
        }
    }

    // =======================================================================
    // Data Models
    // =======================================================================
    public class OtpItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Issuer { get; set; }
        public string EncryptedSecret { get; set; }
        public string Iv { get; set; }
        public int Digits { get; set; }
        public int Period { get; set; }
        public string Algorithm { get; set; }

        public OtpItem()
        {
            Digits = 6;
            Period = 30;
            Algorithm = "sha1";
        }
    }

    public class VaultData
    {
        public string MasterHash { get; set; }
        public string Salt { get; set; }
        public bool AutoLock5Min { get; set; }
        public List<OtpItem> Items { get; set; }

        public VaultData()
        {
            AutoLock5Min = true;
            Items = new List<OtpItem>();
        }
    }

    // =======================================================================
    // Cryptography (PBKDF2-HMAC-SHA256 100k + AES-256-CBC)
    // =======================================================================
    public static class Crypto
    {
        public static string HashPassword(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000))
            {
                byte[] hash = pbkdf2.GetBytes(32);
                return Convert.ToBase64String(hash);
            }
        }

        public static bool VerifyPassword(string password, byte[] salt, string expectedHashBase64)
        {
            string hash = HashPassword(password, salt);
            return hash == expectedHashBase64;
        }

        public static void Encrypt(string plainText, string password, byte[] salt, out string cipherBase64, out string ivBase64)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, 100000))
            {
                byte[] key = kdf.GetBytes(32);
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Key = key;
                    aes.GenerateIV();
                    ivBase64 = Convert.ToBase64String(aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        cipherBase64 = Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        public static string Decrypt(string cipherBase64, string ivBase64, string password, byte[] salt)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, 100000))
            {
                byte[] key = kdf.GetBytes(32);
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] cipherBytes = Convert.FromBase64String(cipherBase64);

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Key = key;
                    aes.IV = iv;

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return Encoding.UTF8.GetString(ms.ToArray());
                    }
                }
            }
        }
    }

    // =======================================================================
    // RFC 6238 TOTP Engine & Base32 Decoder
    // =======================================================================
    public static class Totp
    {
        public static string CleanSecret(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new ArgumentException("Secret key tidak boleh kosong.");

            string cleaned = raw.Trim().Replace(" ", "").Replace("-", "").ToUpperInvariant();
            int pad = (8 - (cleaned.Length % 8)) % 8;
            cleaned += new string('=', pad);

            foreach (char c in cleaned)
            {
                if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '='))
                    throw new ArgumentException("Secret mengandung karakter ilegal. Base32 hanya mengizinkan A-Z dan 2-7.");
            }
            return cleaned;
        }

        public static byte[] Base32Decode(string input)
        {
            string clean = CleanSecret(input).TrimEnd('=');
            List<byte> bytes = new List<byte>();
            int buffer = 0;
            int bitsLeft = 0;

            foreach (char c in clean)
            {
                int val;
                if (c >= 'A' && c <= 'Z') val = c - 'A';
                else if (c >= '2' && c <= '7') val = c - '2' + 26;
                else throw new ArgumentException("Karakter tidak valid.");

                buffer = (buffer << 5) | val;
                bitsLeft += 5;
                if (bitsLeft >= 8)
                {
                    bytes.Add((byte)(buffer >> (bitsLeft - 8)));
                    bitsLeft -= 8;
                }
            }
            return bytes.ToArray();
        }

        public static string Generate(string base32Secret, int digits = 6, int period = 30, string algorithm = "sha1")
        {
            try
            {
                byte[] key = Base32Decode(base32Secret);
                long epoch = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
                long counter = epoch / period;

                byte[] counterBytes = BitConverter.GetBytes(counter);
                if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);

                HMAC hmac;
                string alg = algorithm.ToLowerInvariant();
                if (alg == "sha256") hmac = new HMACSHA256(key);
                else if (alg == "sha512") hmac = new HMACSHA512(key);
                else hmac = new HMACSHA1(key);

                using (hmac)
                {
                    byte[] hash = hmac.ComputeHash(counterBytes);
                    int offset = hash[hash.Length - 1] & 0x0F;
                    int binary = ((hash[offset] & 0x7F) << 24)
                               | ((hash[offset + 1] & 0xFF) << 16)
                               | ((hash[offset + 2] & 0xFF) << 8)
                               | (hash[offset + 3] & 0xFF);

                    int otp = binary % (int)Math.Pow(10, digits);
                    return otp.ToString(new string('0', digits));
                }
            }
            catch
            {
                return "ERROR";
            }
        }
    }

    // =======================================================================
    // Storage Engine (Atomic JSON write to disk)
    // =======================================================================
    public static class Storage
    {
        private static readonly string AppDir = AppDomain.CurrentDomain.BaseDirectory;
        private static readonly string DataDir = Path.Combine(AppDir, "data");
        private static readonly string VaultPath = Path.Combine(DataDir, "vault.json");
        private static readonly object FileLock = new object();

        public static bool IsSetupDone()
        {
            var v = Load();
            return v != null && !string.IsNullOrEmpty(v.MasterHash) && !string.IsNullOrEmpty(v.Salt);
        }

        public static VaultData Load()
        {
            lock (FileLock)
            {
                if (!File.Exists(VaultPath)) return new VaultData();
                try
                {
                    string json = File.ReadAllText(VaultPath, Encoding.UTF8);
                    return ParseVault(json);
                }
                catch
                {
                    return new VaultData();
                }
            }
        }

        public static void Save(VaultData vault)
        {
            lock (FileLock)
            {
                Directory.CreateDirectory(DataDir);
                string json = SerializeVault(vault);
                string tmp = VaultPath + ".tmp";
                File.WriteAllText(tmp, json, Encoding.UTF8);
                if (File.Exists(VaultPath)) File.Delete(VaultPath);
                File.Move(tmp, VaultPath);
            }
        }

        private static string Escape(string s)
        {
            if (s == null) s = "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "");
        }

        private static string SerializeVault(VaultData v)
        {
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine(string.Format("  \"master_hash\": \"{0}\",", Escape(v.MasterHash)));
            sb.AppendLine(string.Format("  \"salt\": \"{0}\",", Escape(v.Salt)));
            sb.AppendLine(string.Format("  \"auto_lock_5min\": {0},", v.AutoLock5Min ? "true" : "false"));
            sb.AppendLine("  \"items\": [");
            for (int i = 0; i < v.Items.Count; i++)
            {
                var it = v.Items[i];
                sb.AppendLine("    {");
                sb.AppendLine(string.Format("      \"id\": \"{0}\",", Escape(it.Id)));
                sb.AppendLine(string.Format("      \"name\": \"{0}\",", Escape(it.Name)));
                sb.AppendLine(string.Format("      \"issuer\": \"{0}\",", Escape(it.Issuer)));
                sb.AppendLine(string.Format("      \"encrypted_secret\": \"{0}\",", Escape(it.EncryptedSecret)));
                sb.AppendLine(string.Format("      \"iv\": \"{0}\",", Escape(it.Iv)));
                sb.AppendLine(string.Format("      \"digits\": {0},", it.Digits));
                sb.AppendLine(string.Format("      \"period\": {0},", it.Period));
                sb.AppendLine(string.Format("      \"algorithm\": \"{0}\"", Escape(it.Algorithm)));
                sb.Append("    }");
                if (i < v.Items.Count - 1) sb.AppendLine(",");
                else sb.AppendLine();
            }
            sb.AppendLine("  ]");
            sb.AppendLine("}");
            return sb.ToString();
        }

        private static VaultData ParseVault(string json)
        {
            var v = new VaultData();
            v.MasterHash = ExtractString(json, "\"master_hash\"");
            v.Salt = ExtractString(json, "\"salt\"");

            int alIdx = json.IndexOf("\"auto_lock_5min\"");
            if (alIdx != -1)
            {
                int colon = json.IndexOf(":", alIdx);
                if (colon != -1)
                {
                    string sub = json.Substring(colon + 1, Math.Min(10, json.Length - colon - 1)).Trim().ToLowerInvariant();
                    v.AutoLock5Min = !sub.StartsWith("false");
                }
            }
            else
            {
                v.AutoLock5Min = true;
            }

            int itemsStart = json.IndexOf("\"items\"");
            if (itemsStart != -1)
            {
                int arrStart = json.IndexOf("[", itemsStart);
                int arrEnd = json.LastIndexOf("]");
                if (arrStart != -1 && arrEnd > arrStart)
                {
                    string itemsBlock = json.Substring(arrStart + 1, arrEnd - arrStart - 1);
                    string[] rawObjects = itemsBlock.Split(new[] { "}," }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var raw in rawObjects)
                    {
                        var it = new OtpItem();
                        it.Id = ExtractString(raw, "\"id\"");
                        it.Name = ExtractString(raw, "\"name\"");
                        it.Issuer = ExtractString(raw, "\"issuer\"");
                        it.EncryptedSecret = ExtractString(raw, "\"encrypted_secret\"");
                        it.Iv = ExtractString(raw, "\"iv\"");
                        it.Digits = ExtractInt(raw, "\"digits\"", 6);
                        it.Period = ExtractInt(raw, "\"period\"", 30);
                        it.Algorithm = ExtractString(raw, "\"algorithm\"") ?? "sha1";
                        if (!string.IsNullOrEmpty(it.Name)) v.Items.Add(it);
                    }
                }
            }
            return v;
        }

        private static string ExtractString(string text, string key)
        {
            int idx = text.IndexOf(key);
            if (idx == -1) return null;
            int colon = text.IndexOf(":", idx + key.Length);
            if (colon == -1) return null;
            int startQ = text.IndexOf("\"", colon);
            if (startQ == -1) return null;
            int endQ = text.IndexOf("\"", startQ + 1);
            if (endQ == -1) return null;
            return text.Substring(startQ + 1, endQ - startQ - 1).Replace("\\\"", "\"").Replace("\\\\", "\\");
        }

        private static int ExtractInt(string text, string key, int defaultVal)
        {
            int idx = text.IndexOf(key);
            if (idx == -1) return defaultVal;
            int colon = text.IndexOf(":", idx + key.Length);
            if (colon == -1) return defaultVal;
            int i = colon + 1;
            while (i < text.Length && (char.IsWhiteSpace(text[i]) || text[i] == '\"')) i++;
            int start = i;
            while (i < text.Length && char.IsDigit(text[i])) i++;
            int result;
            if (i > start && int.TryParse(text.Substring(start, i - start), out result))
                return result;
            return defaultVal;
        }
    }

    // =======================================================================
    // UI: Main Form (Ratio 3:4, Futuristic Dark Mode, Centered Cards)
    // =======================================================================
    public class MainForm : Form
    {
        private string masterPassword;
        private byte[] saltBytes;
        private VaultData currentVault;
        private System.Windows.Forms.Timer tickTimer;
        private DateTime lastActivity;
        private NotifyIcon trayIcon;
        private Image appLogo;

        private Panel contentPanel;
        private TextBox txtSearch;
        private FlowLayoutPanel cardsLayout;
        private Dictionary<string, CardWidgets> activeCards = new Dictionary<string, CardWidgets>();

        private class CardWidgets
        {
            public OtpItem Item;
            public Label LblCode;
            public Label LblTimer;
            public ProgressBar Pbar;
            public Button BtnCopy;
            public string CurrentCode;
        }

        public MainForm()
        {
            // Rasio Lebar 3 : Tinggi 4 (450 x 600)
            this.Text = "OTP Helper";
            this.Size = new Size(450, 600);
            this.MinimumSize = new Size(420, 560);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(15, 17, 26);
            this.ForeColor = Color.White;
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            LoadLogo();
            SetupTray();

            contentPanel = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(15, 17, 26) };
            this.Controls.Add(contentPanel);

            this.FormClosing += (s, e) =>
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    this.Hide();
                }
            };

            Application.AddMessageFilter(new ActivityFilter(() => lastActivity = DateTime.UtcNow));
            lastActivity = DateTime.UtcNow;

            tickTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            tickTimer.Tick += OnTick;
            tickTimer.Start();

            if (!Storage.IsSetupDone()) ShowSetup();
            else ShowLogin();
        }

        private void LoadLogo()
        {
            try
            {
                Stream stream = null;
                var asm = typeof(Program).Assembly;
                foreach (string res in asm.GetManifestResourceNames())
                {
                    if (res.IndexOf("logo.png", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        stream = asm.GetManifestResourceStream(res);
                        break;
                    }
                }

                if (stream == null)
                {
                    string logoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logo.png");
                    if (File.Exists(logoPath))
                    {
                        byte[] bytes = File.ReadAllBytes(logoPath);
                        stream = new MemoryStream(bytes);
                    }
                }

                if (stream != null)
                {
                    using (stream)
                    {
                        appLogo = Image.FromStream(stream);
                        using (var bmp = new Bitmap(appLogo))
                        {
                            IntPtr hIcon = bmp.GetHicon();
                            this.Icon = Icon.FromHandle(hIcon);
                        }
                    }
                }
            }
            catch { }
        }

        private void SetupTray()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Buka OTP Helper", null, (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.BringToFront(); });
            menu.Items.Add("Kunci", null, (s, e) => LockApp());
            menu.Items.Add("-");
            menu.Items.Add("Keluar", null, (s, e) => { trayIcon.Visible = false; Application.Exit(); });

            trayIcon = new NotifyIcon
            {
                Text = "OTP Helper",
                Icon = this.Icon ?? SystemIcons.Shield,
                ContextMenuStrip = menu,
                Visible = true
            };
            trayIcon.DoubleClick += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.BringToFront(); };
        }

        private void ClearContent()
        {
            contentPanel.Controls.Clear();
            activeCards.Clear();
        }

        // --- Screen: Setup Master Password ---
        private void ShowSetup()
        {
            ClearContent();
            var p = new Panel { Size = new Size(360, 390), BackColor = Color.FromArgb(23, 26, 40) };
            p.Location = new Point((contentPanel.Width - p.Width) / 2, (contentPanel.Height - p.Height) / 2);
            contentPanel.Resize += (s, e) => p.Location = new Point((contentPanel.Width - p.Width) / 2, (contentPanel.Height - p.Height) / 2);
            p.HandleCreated += (s, e) => UIUtils.SetRounded(p, 20);
            p.Resize += (s, e) => UIUtils.SetRounded(p, 20);

            int topY = 20;
            if (appLogo != null)
            {
                var pic = new PictureBox
                {
                    Image = appLogo,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(48, 48),
                    Location = new Point((p.Width - 48) / 2, topY)
                };
                p.Controls.Add(pic);
                topY += 56;
            }

            var lblTitle = new Label { Text = "OTP Helper Setup", Font = new Font("Segoe UI", 14, FontStyle.Bold), AutoSize = true, Location = new Point((p.Width - 170) / 2, topY), ForeColor = Color.White };
            topY += 28;

            var lblSub = new Label { Text = "Buat Master Password untuk mengenkripsi vault OTP Anda.", ForeColor = Color.FromArgb(148, 163, 184), AutoSize = false, Size = new Size(310, 32), Location = new Point(27, topY), Font = new Font("Segoe UI", 8.5f), TextAlign = ContentAlignment.TopCenter };
            topY += 38;

            var lblPw = new Label { Text = "Master Password (min. 6 karakter):", Location = new Point(27, topY), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
            topY += 22;
            var txtPw = new TextBox { UseSystemPasswordChar = true, Width = 306, Location = new Point(27, topY), BackColor = Color.FromArgb(32, 36, 54), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            topY += 34;

            var lblCf = new Label { Text = "Konfirmasi Password:", Location = new Point(27, topY), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
            topY += 22;
            var txtCf = new TextBox { UseSystemPasswordChar = true, Width = 306, Location = new Point(27, topY), BackColor = Color.FromArgb(32, 36, 54), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            topY += 32;

            var lblErr = new Label { ForeColor = Color.FromArgb(248, 113, 113), AutoSize = true, Location = new Point(27, topY), Font = new Font("Segoe UI", 8.5f) };
            topY += 24;

            var btn = new Button { Text = "Buat Master Password", Width = 306, Height = 42, Location = new Point(27, topY), BackColor = Color.FromArgb(37, 99, 235), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Font = new Font("Segoe UI", 10, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderSize = 0;
            btn.HandleCreated += (s, e) => UIUtils.SetRounded(btn, 14);

            btn.Click += (s, e) =>
            {
                if (txtPw.Text.Length < 6) { lblErr.Text = "Minimal 6 karakter."; return; }
                if (txtPw.Text != txtCf.Text) { lblErr.Text = "Konfirmasi password tidak cocok."; return; }

                byte[] salt = new byte[32];
                using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(salt);
                string hash = Crypto.HashPassword(txtPw.Text, salt);

                var v = new VaultData { MasterHash = hash, Salt = Convert.ToBase64String(salt) };
                Storage.Save(v);

                masterPassword = txtPw.Text;
                saltBytes = salt;
                ShowDashboard();
            };

            p.Controls.AddRange(new Control[] { lblTitle, lblSub, lblPw, txtPw, lblCf, txtCf, lblErr, btn });
            contentPanel.Controls.Add(p);

            var lblFoot = new Label { Text = "2026 © made with ❤️, Gilang Wahyu Prasetyo", Dock = DockStyle.Bottom, Height = 24, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.FromArgb(75, 85, 99), Font = new Font("Segoe UI", 7.5f) };
            contentPanel.Controls.Add(lblFoot);
        }

        // --- Screen: Login ---
        private void ShowLogin()
        {
            ClearContent();
            masterPassword = null;

            var p = new Panel { Size = new Size(350, 360), BackColor = Color.FromArgb(23, 26, 40) };
            p.Location = new Point((contentPanel.Width - p.Width) / 2, (contentPanel.Height - p.Height) / 2);
            contentPanel.Resize += (s, e) => p.Location = new Point((contentPanel.Width - p.Width) / 2, (contentPanel.Height - p.Height) / 2);
            p.HandleCreated += (s, e) => UIUtils.SetRounded(p, 20);
            p.Resize += (s, e) => UIUtils.SetRounded(p, 20);

            int topY = 20;
            if (appLogo != null)
            {
                var pic = new PictureBox
                {
                    Image = appLogo,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(54, 54),
                    Location = new Point((p.Width - 54) / 2, topY)
                };
                p.Controls.Add(pic);
                topY += 62;
            }

            var lblTitle = new Label { Text = "OTP Helper", Font = new Font("Segoe UI", 16, FontStyle.Bold), AutoSize = true, Location = new Point((p.Width - 120) / 2, topY), ForeColor = Color.White };
            topY += 30;

            var lblSub = new Label { Text = "Masukkan master password untuk membuka vault.", ForeColor = Color.FromArgb(148, 163, 184), AutoSize = false, Size = new Size(300, 24), Location = new Point(27, topY), Font = new Font("Segoe UI", 8.5f), TextAlign = ContentAlignment.TopCenter };
            topY += 32;

            var txtPw = new TextBox { UseSystemPasswordChar = true, Width = 296, Location = new Point(27, topY), BackColor = Color.FromArgb(32, 36, 54), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10) };
            topY += 30;

            var initialVault = Storage.Load();
            var chkLock = new CheckBox
            {
                Text = "Kunci 5 menit setelah login",
                Checked = initialVault.AutoLock5Min,
                AutoSize = true,
                Location = new Point(27, topY),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 8.5f),
                Cursor = Cursors.Hand
            };
            topY += 26;

            var lblErr = new Label { ForeColor = Color.FromArgb(248, 113, 113), AutoSize = true, Location = new Point(27, topY), Font = new Font("Segoe UI", 8.5f) };
            topY += 22;

            var btn = new Button { Text = "Buka Brankas", Width = 296, Height = 42, Location = new Point(27, topY), BackColor = Color.FromArgb(37, 99, 235), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Font = new Font("Segoe UI", 10, FontStyle.Bold), Cursor = Cursors.Hand };
            btn.FlatAppearance.BorderSize = 0;
            btn.HandleCreated += (s, e) => UIUtils.SetRounded(btn, 14);

            Action doLogin = () =>
            {
                var v = Storage.Load();
                byte[] salt = Convert.FromBase64String(v.Salt);
                if (Crypto.VerifyPassword(txtPw.Text, salt, v.MasterHash))
                {
                    v.AutoLock5Min = chkLock.Checked;
                    Storage.Save(v);
                    currentVault = v;

                    masterPassword = txtPw.Text;
                    saltBytes = salt;
                    ShowDashboard();
                }
                else
                {
                    lblErr.Text = "Password salah!";
                    txtPw.Clear();
                    txtPw.Focus();
                }
            };

            btn.Click += (s, e) => doLogin();
            txtPw.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; doLogin(); } };

            p.Controls.AddRange(new Control[] { lblTitle, lblSub, txtPw, chkLock, lblErr, btn });
            contentPanel.Controls.Add(p);

            var lblFoot = new Label { Text = "2026 © made with ❤️, Gilang Wahyu Prasetyo", Dock = DockStyle.Bottom, Height = 24, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.FromArgb(75, 85, 99), Font = new Font("Segoe UI", 7.5f) };
            contentPanel.Controls.Add(lblFoot);
            txtPw.Focus();
        }

        // --- Screen: Dashboard ---
        private void ShowDashboard()
        {
            ClearContent();

            var nav = new Panel { Dock = DockStyle.Top, Height = 95, BackColor = Color.FromArgb(20, 23, 34) };

            // Logo & Title
            int brandX = 14;
            if (appLogo != null)
            {
                var picMini = new PictureBox
                {
                    Image = appLogo,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(26, 26),
                    Location = new Point(14, 12)
                };
                nav.Controls.Add(picMini);
                brandX = 46;
            }

            var brand = new Label { Text = "OTP Helper", Font = new Font("Segoe UI", 12.5f, FontStyle.Bold), AutoSize = true, Location = new Point(brandX, 14), ForeColor = Color.White };

            var btnAdd = new Button { Text = "+ Tambah", Width = 75, Height = 28, Location = new Point(nav.Width - 195, 12), BackColor = Color.FromArgb(37, 99, 235), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), Cursor = Cursors.Hand };
            btnAdd.FlatAppearance.BorderSize = 0;
            btnAdd.HandleCreated += (s, e) => UIUtils.SetRounded(btnAdd, 10);
            btnAdd.Click += (s, e) => OpenAddDialog();

            var btnChPw = new Button { Text = "🔑", Width = 32, Height = 28, Location = new Point(nav.Width - 116, 12), BackColor = Color.FromArgb(38, 43, 63), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Cursor = Cursors.Hand };
            btnChPw.FlatAppearance.BorderSize = 0;
            btnChPw.HandleCreated += (s, e) => UIUtils.SetRounded(btnChPw, 10);
            btnChPw.Click += (s, e) => OpenChangePasswordDialog();

            var btnAbout = new Button { Text = "ℹ️", Width = 32, Height = 28, Location = new Point(nav.Width - 80, 12), BackColor = Color.FromArgb(38, 43, 63), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Cursor = Cursors.Hand };
            btnAbout.FlatAppearance.BorderSize = 0;
            btnAbout.HandleCreated += (s, e) => UIUtils.SetRounded(btnAbout, 10);
            btnAbout.Click += (s, e) => OpenAboutDialog();

            var btnLock = new Button { Text = "🔒", Width = 32, Height = 28, Location = new Point(nav.Width - 44, 12), BackColor = Color.FromArgb(38, 43, 63), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Cursor = Cursors.Hand };
            btnLock.FlatAppearance.BorderSize = 0;
            btnLock.HandleCreated += (s, e) => UIUtils.SetRounded(btnLock, 10);
            btnLock.Click += (s, e) => LockApp();

            txtSearch = new TextBox { Location = new Point(14, 52), Width = nav.Width - 28, Height = 26, BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 9.5f) };
            txtSearch.TextChanged += (s, e) => RenderCards();

            nav.Resize += (s, e) =>
            {
                btnAdd.Left = nav.Width - 195;
                btnChPw.Left = nav.Width - 116;
                btnAbout.Left = nav.Width - 80;
                btnLock.Left = nav.Width - 44;
                txtSearch.Width = nav.Width - 28;
            };

            nav.Controls.AddRange(new Control[] { brand, btnAdd, btnChPw, btnAbout, btnLock, txtSearch });

            // Scrollable Container for cards
            cardsLayout = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(0, 10, 0, 10),
                BackColor = Color.FromArgb(15, 17, 26)
            };

            cardsLayout.Resize += (s, e) => AdjustCardWidths();

            var footerPanel = new Panel { Dock = DockStyle.Bottom, Height = 22, BackColor = Color.FromArgb(15, 17, 26) };
            var lblFoot = new Label { Text = "2026 © made with ❤️, Gilang Wahyu Prasetyo", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.FromArgb(75, 85, 99), Font = new Font("Segoe UI", 7.5f) };
            footerPanel.Controls.Add(lblFoot);

            contentPanel.Controls.Add(cardsLayout);
            contentPanel.Controls.Add(footerPanel);
            contentPanel.Controls.Add(nav);

            currentVault = Storage.Load();
            RenderCards();
        }

        private void AdjustCardWidths()
        {
            int clientW = cardsLayout.ClientSize.Width;
            if (clientW <= 0) return;

            int cardW = Math.Min(390, Math.Max(320, clientW - 24));
            int leftPad = Math.Max(0, (clientW - cardW) / 2);

            foreach (Control c in cardsLayout.Controls)
            {
                if (c is Panel)
                {
                    c.Size = new Size(cardW, 105);
                    c.Margin = new Padding(leftPad, 0, leftPad, 12);

                    foreach (Control inner in c.Controls)
                    {
                        if (inner is Button && inner.Text == "✕") inner.Left = cardW - 32;
                        else if (inner is Button && inner.Text.Contains("Salin")) inner.Left = cardW - 90;
                        else if (inner is ProgressBar) inner.Left = cardW - 165;
                        else if (inner is Label && inner.Text.EndsWith("s")) inner.Left = cardW - 160;
                    }

                    UIUtils.SetRounded(c, 16);
                }
            }
        }

        private void RenderCards()
        {
            cardsLayout.Controls.Clear();
            activeCards.Clear();

            string q = (txtSearch.Text ?? "").Trim().ToLowerInvariant();
            var items = currentVault.Items
                .Where(it => string.IsNullOrEmpty(q) || (it.Name ?? "").ToLower().Contains(q) || (it.Issuer ?? "").ToLower().Contains(q))
                .ToList();

            if (items.Count == 0)
            {
                var lblEmpty = new Label { Text = "Tidak ada akun OTP.\nKlik '+ Tambah' untuk mulai.", AutoSize = true, ForeColor = Color.FromArgb(100, 116, 139), Font = new Font("Segoe UI", 10.5f), Margin = new Padding(20, 30, 0, 0) };
                cardsLayout.Controls.Add(lblEmpty);
                return;
            }

            int clientW = cardsLayout.ClientSize.Width;
            int cardW = Math.Min(390, Math.Max(320, clientW > 0 ? clientW - 24 : 380));
            int leftPad = Math.Max(0, (clientW - cardW) / 2);
            long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            foreach (var item in items)
            {
                var card = new Panel { Size = new Size(cardW, 105), BackColor = Color.FromArgb(24, 28, 42), Margin = new Padding(leftPad, 0, leftPad, 12) };
                card.HandleCreated += (s, e) => UIUtils.SetRounded(card, 16);
                card.Resize += (s, e) => UIUtils.SetRounded(card, 16);

                // --- 1. Account Name (Copyable on click!) ---
                var lblName = new Label
                {
                    Text = item.Name,
                    Font = new Font("Segoe UI", 11, FontStyle.Bold),
                    AutoSize = true,
                    Location = new Point(14, 10),
                    ForeColor = Color.White,
                    Cursor = Cursors.Hand
                };
                string accountName = item.Name;
                lblName.Click += (s, e) =>
                {
                    Clipboard.SetText(accountName);
                    string orig = lblName.Text;
                    lblName.Text = "✓ " + orig;
                    lblName.ForeColor = Color.FromArgb(52, 211, 153);
                    var t = new System.Windows.Forms.Timer { Interval = 1200 };
                    t.Tick += (st, et) => { lblName.Text = orig; lblName.ForeColor = Color.White; t.Stop(); t.Dispose(); };
                    t.Start();
                };

                var lblIssuer = new Label
                {
                    Text = string.IsNullOrEmpty(item.Issuer) ? "TOTP" : item.Issuer,
                    ForeColor = Color.FromArgb(148, 163, 184),
                    AutoSize = true,
                    Location = new Point(15, 32),
                    Font = new Font("Segoe UI", 8f)
                };

                // Delete button (Top Right)
                var btnDel = new Button
                {
                    Text = "✕",
                    Width = 24,
                    Height = 24,
                    Location = new Point(cardW - 32, 8),
                    BackColor = Color.Transparent,
                    FlatStyle = FlatStyle.Flat,
                    ForeColor = Color.FromArgb(148, 163, 184),
                    Cursor = Cursors.Hand,
                    Font = new Font("Segoe UI", 8, FontStyle.Bold)
                };
                btnDel.FlatAppearance.BorderSize = 0;
                btnDel.Click += (s, e) => DeleteItem(item);

                // --- 2. OTP Code (Large, Futuristic Neon Cyan) ---
                string secret = Crypto.Decrypt(item.EncryptedSecret, item.Iv, masterPassword, saltBytes);
                string code = Totp.Generate(secret, item.Digits, item.Period, item.Algorithm);
                string fmt = code != "ERROR" && code.Length >= 6 ? code.Substring(0, code.Length / 2) + " " + code.Substring(code.Length / 2) : code;

                var lblCode = new Label
                {
                    Text = fmt,
                    Font = new Font("Consolas", 18, FontStyle.Bold),
                    ForeColor = Color.FromArgb(56, 189, 248),
                    AutoSize = true,
                    Location = new Point(14, 55),
                    Cursor = Cursors.Hand
                };

                // --- 3. Pill Copy Button ---
                var btnCopy = new Button
                {
                    Text = "📋 Salin",
                    Width = 80,
                    Height = 32,
                    Location = new Point(cardW - 90, 54),
                    BackColor = Color.FromArgb(37, 99, 235),
                    FlatStyle = FlatStyle.Flat,
                    ForeColor = Color.White,
                    Font = new Font("Segoe UI", 9, FontStyle.Bold),
                    Cursor = Cursors.Hand
                };
                btnCopy.FlatAppearance.BorderSize = 0;
                btnCopy.HandleCreated += (s, e) => UIUtils.SetRounded(btnCopy, 12);
                string copyCode = code;
                btnCopy.Click += (s, e) => CopyCode(copyCode, btnCopy);
                lblCode.Click += (s, e) => CopyCode(copyCode, btnCopy);

                // --- 4. Countdown Timer & Bar ---
                int rem = item.Period - (int)(now % item.Period);
                var pbar = new ProgressBar
                {
                    Width = 65,
                    Height = 5,
                    Maximum = item.Period,
                    Value = rem,
                    Location = new Point(cardW - 165, 68)
                };
                var lblTimer = new Label
                {
                    Text = rem + "s",
                    ForeColor = rem <= 5 ? Color.FromArgb(248, 113, 113) : Color.FromArgb(148, 163, 184),
                    AutoSize = true,
                    Location = new Point(cardW - 160, 52),
                    Font = new Font("Segoe UI", 8)
                };

                card.Controls.AddRange(new Control[] { lblName, lblIssuer, btnDel, lblCode, btnCopy, pbar, lblTimer });
                cardsLayout.Controls.Add(card);

                activeCards[item.Id] = new CardWidgets
                {
                    Item = item,
                    LblCode = lblCode,
                    LblTimer = lblTimer,
                    Pbar = pbar,
                    BtnCopy = btnCopy,
                    CurrentCode = code
                };
            }
        }

        private void CopyCode(string code, Button btn)
        {
            if (string.IsNullOrEmpty(code) || code == "ERROR") return;
            Clipboard.SetText(code);
            btn.Text = "✓ Tersalin";
            btn.BackColor = Color.FromArgb(22, 163, 74);

            var t = new System.Windows.Forms.Timer { Interval = 1500 };
            t.Tick += (s, e) => { btn.Text = "📋 Salin"; btn.BackColor = Color.FromArgb(37, 99, 235); t.Stop(); t.Dispose(); };
            t.Start();

            // Auto-clear clipboard after 30s
            new Thread(() =>
            {
                Thread.Sleep(30000);
                this.Invoke((Action)(() =>
                {
                    try { if (Clipboard.GetText() == code) Clipboard.Clear(); } catch { }
                }));
            }).Start();
        }

        private void DeleteItem(OtpItem item)
        {
            if (MessageBox.Show("Hapus akun '" + item.Name + "'?", "Hapus OTP", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                currentVault.Items.RemoveAll(i => i.Id == item.Id);
                Storage.Save(currentVault);
                RenderCards();
            }
        }

        private void OpenAddDialog()
        {
            var dlg = new Form
            {
                Text = "Tambah Akun OTP",
                Size = new Size(390, 480),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(20, 23, 34),
                ForeColor = Color.White,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var lblUri = new Label { Text = "otpauth:// URI (Auto-fill):", Location = new Point(20, 15), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
            var txtUri = new TextBox { Width = 330, Location = new Point(20, 35), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblName = new Label { Text = "Nama Akun *:", Location = new Point(20, 70), AutoSize = true, ForeColor = Color.White };
            var txtName = new TextBox { Width = 330, Location = new Point(20, 90), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblSec = new Label { Text = "Secret Key (Base32) *:", Location = new Point(20, 125), AutoSize = true, ForeColor = Color.White };
            var txtSec = new TextBox { Width = 330, Location = new Point(20, 145), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblIss = new Label { Text = "Issuer (Opsional):", Location = new Point(20, 180), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
            var txtIss = new TextBox { Width = 330, Location = new Point(20, 200), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblDig = new Label { Text = "Digits:", Location = new Point(20, 235), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
            var cmbDig = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 95, Location = new Point(20, 255), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White };
            cmbDig.Items.AddRange(new object[] { "6", "8" });
            cmbDig.SelectedIndex = 0;

            var lblPer = new Label { Text = "Period (detik):", Location = new Point(135, 235), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
            var cmbPer = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 95, Location = new Point(135, 255), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White };
            cmbPer.Items.AddRange(new object[] { "30", "60", "90" });
            cmbPer.SelectedIndex = 0;

            var lblAlg = new Label { Text = "Algoritma:", Location = new Point(250, 235), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
            var cmbAlg = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100, Location = new Point(250, 255), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White };
            cmbAlg.Items.AddRange(new object[] { "SHA-1", "SHA-256", "SHA-512" });
            cmbAlg.SelectedIndex = 0;

            // URI Parser
            txtUri.TextChanged += (s, e) =>
            {
                string u = txtUri.Text.Trim();
                if (u.StartsWith("otpauth://"))
                {
                    try
                    {
                        var uri = new Uri(u);
                        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        string q = uri.Query.TrimStart('?');
                        foreach (var part in q.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            var kv = part.Split(new[] { '=' }, 2);
                            if (kv.Length == 2) query[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
                        }

                        string sec = query.ContainsKey("secret") ? query["secret"] : null;
                        string iss = query.ContainsKey("issuer") ? query["issuer"] : null;
                        string dig = query.ContainsKey("digits") ? query["digits"] : null;
                        string per = query.ContainsKey("period") ? query["period"] : null;
                        string alg = query.ContainsKey("algorithm") ? query["algorithm"] : null;

                        string path = uri.AbsolutePath.TrimStart('/');
                        string label = path.Contains(":") ? path.Split(new[] { ':' }, 2)[1] : path;

                        if (!string.IsNullOrEmpty(sec)) txtSec.Text = sec;
                        if (!string.IsNullOrEmpty(label)) txtName.Text = label;
                        if (!string.IsNullOrEmpty(iss)) txtIss.Text = iss;
                        if (dig == "8") cmbDig.SelectedIndex = 1;
                        if (per == "60") cmbPer.SelectedIndex = 1;
                        if (alg != null && alg.ToUpper() == "SHA256") cmbAlg.SelectedIndex = 1;
                    }
                    catch { }
                }
            };

            var lblErr = new Label { ForeColor = Color.FromArgb(248, 113, 113), Location = new Point(20, 300), AutoSize = true };
            
            var btnSave = new Button { Text = "Simpan", Width = 160, Height = 38, Location = new Point(190, 365), BackColor = Color.FromArgb(37, 99, 235), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Font = new Font("Segoe UI", 9, FontStyle.Bold), Cursor = Cursors.Hand };
            btnSave.FlatAppearance.BorderSize = 0;
            btnSave.HandleCreated += (s, e) => UIUtils.SetRounded(btnSave, 12);

            var btnCancel = new Button { Text = "Batal", Width = 160, Height = 38, Location = new Point(20, 365), BackColor = Color.FromArgb(38, 43, 63), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Cursor = Cursors.Hand };
            btnCancel.FlatAppearance.BorderSize = 0;
            btnCancel.HandleCreated += (s, e) => UIUtils.SetRounded(btnCancel, 12);

            btnCancel.Click += (s, e) => dlg.Close();
            btnSave.Click += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(txtName.Text)) { lblErr.Text = "Nama wajib diisi."; return; }
                string cleanedSec;
                try
                {
                    cleanedSec = Totp.CleanSecret(txtSec.Text);
                    Totp.Base32Decode(cleanedSec);
                }
                catch (Exception ex)
                {
                    lblErr.Text = ex.Message;
                    return;
                }

                string enc;
                string iv;
                Crypto.Encrypt(cleanedSec, masterPassword, saltBytes, out enc, out iv);

                var newItem = new OtpItem
                {
                    Id = "otp_" + DateTime.UtcNow.Ticks,
                    Name = txtName.Text.Trim(),
                    Issuer = txtIss.Text.Trim(),
                    EncryptedSecret = enc,
                    Iv = iv,
                    Digits = int.Parse(cmbDig.SelectedItem.ToString()),
                    Period = int.Parse(cmbPer.SelectedItem.ToString()),
                    Algorithm = cmbAlg.SelectedItem.ToString().ToLower().Replace("-", "")
                };

                currentVault.Items.Add(newItem);
                Storage.Save(currentVault);
                dlg.Close();
                RenderCards();
            };

            dlg.Controls.AddRange(new Control[] { lblUri, txtUri, lblName, txtName, lblSec, txtSec, lblIss, txtIss, lblDig, cmbDig, lblPer, cmbPer, lblAlg, cmbAlg, lblErr, btnCancel, btnSave });
            dlg.ShowDialog(this);
        }

        private void OpenChangePasswordDialog()
        {
            var dlg = new Form
            {
                Text = "Ubah Master Password",
                Size = new Size(360, 340),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(20, 23, 34),
                ForeColor = Color.White,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var lblOld = new Label { Text = "Password Lama:", Location = new Point(25, 20), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225) };
            var txtOld = new TextBox { UseSystemPasswordChar = true, Width = 290, Location = new Point(25, 42), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblNew = new Label { Text = "Password Baru (min 6 karakter):", Location = new Point(25, 80), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225) };
            var txtNew = new TextBox { UseSystemPasswordChar = true, Width = 290, Location = new Point(25, 102), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblCf = new Label { Text = "Konfirmasi Password Baru:", Location = new Point(25, 140), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225) };
            var txtCf = new TextBox { UseSystemPasswordChar = true, Width = 290, Location = new Point(25, 162), BackColor = Color.FromArgb(28, 32, 48), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblErr = new Label { ForeColor = Color.FromArgb(248, 113, 113), Location = new Point(25, 195), AutoSize = true };
            
            var btnSave = new Button { Text = "Ubah Password", Width = 140, Height = 36, Location = new Point(175, 230), BackColor = Color.FromArgb(37, 99, 235), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Font = new Font("Segoe UI", 9, FontStyle.Bold), Cursor = Cursors.Hand };
            btnSave.FlatAppearance.BorderSize = 0;
            btnSave.HandleCreated += (s, e) => UIUtils.SetRounded(btnSave, 12);

            var btnCancel = new Button { Text = "Batal", Width = 140, Height = 36, Location = new Point(25, 230), BackColor = Color.FromArgb(38, 43, 63), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Cursor = Cursors.Hand };
            btnCancel.FlatAppearance.BorderSize = 0;
            btnCancel.HandleCreated += (s, e) => UIUtils.SetRounded(btnCancel, 12);

            btnCancel.Click += (s, e) => dlg.Close();
            btnSave.Click += (s, e) =>
            {
                if (!Crypto.VerifyPassword(txtOld.Text, saltBytes, currentVault.MasterHash)) { lblErr.Text = "Password lama salah."; return; }
                if (txtNew.Text.Length < 6) { lblErr.Text = "Password baru minimal 6 karakter."; return; }
                if (txtNew.Text != txtCf.Text) { lblErr.Text = "Konfirmasi password tidak cocok."; return; }

                byte[] newSalt = new byte[32];
                using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(newSalt);

                foreach (var it in currentVault.Items)
                {
                    string plain = Crypto.Decrypt(it.EncryptedSecret, it.Iv, txtOld.Text, saltBytes);
                    string enc;
                    string iv;
                    Crypto.Encrypt(plain, txtNew.Text, newSalt, out enc, out iv);
                    it.EncryptedSecret = enc;
                    it.Iv = iv;
                }

                currentVault.MasterHash = Crypto.HashPassword(txtNew.Text, newSalt);
                currentVault.Salt = Convert.ToBase64String(newSalt);
                Storage.Save(currentVault);

                masterPassword = txtNew.Text;
                saltBytes = newSalt;
                dlg.Close();
            };

            dlg.Controls.AddRange(new Control[] { lblOld, txtOld, lblNew, txtNew, lblCf, txtCf, lblErr, btnCancel, btnSave });
            dlg.ShowDialog(this);
        }

        private void OpenAboutDialog()
        {
            var dlg = new Form
            {
                Text = "Tentang OTP Helper",
                Size = new Size(360, 310),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(20, 23, 34),
                ForeColor = Color.White,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            int topY = 20;
            if (appLogo != null)
            {
                var pic = new PictureBox
                {
                    Image = appLogo,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(48, 48),
                    Location = new Point((dlg.ClientSize.Width - 48) / 2, topY)
                };
                dlg.Controls.Add(pic);
                topY += 56;
            }

            var lblTitle = new Label { Text = "OTP Helper v1.0", Font = new Font("Segoe UI", 13, FontStyle.Bold), AutoSize = true, Location = new Point((dlg.ClientSize.Width - 130) / 2, topY), ForeColor = Color.White };
            topY += 28;

            var lblAuthor = new Label { Text = "Gilang Wahyu Prasetyo\n© 2026 Kabupaten Tabalong", AutoSize = false, Size = new Size(310, 34), Location = new Point(25, topY), TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.FromArgb(148, 163, 184), Font = new Font("Segoe UI", 8.5f) };
            topY += 42;

            var lblIconAttr = new Label { Text = "Icon: Secret icons created by IwitoStudio - Flaticon", AutoSize = false, Size = new Size(310, 18), Location = new Point(25, topY), TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.FromArgb(56, 189, 248), Font = new Font("Segoe UI", 8f, FontStyle.Underline), Cursor = Cursors.Hand };
            lblIconAttr.Click += (s, e) =>
            {
                try { System.Diagnostics.Process.Start("https://www.flaticon.com/free-icons/secret"); } catch { }
            };
            topY += 32;

            var btnClose = new Button { Text = "Tutup", Width = 110, Height = 34, Location = new Point((dlg.ClientSize.Width - 110) / 2, topY), BackColor = Color.FromArgb(37, 99, 235), FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Font = new Font("Segoe UI", 9, FontStyle.Bold), Cursor = Cursors.Hand };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.HandleCreated += (s, e) => UIUtils.SetRounded(btnClose, 10);
            btnClose.Click += (s, e) => dlg.Close();

            dlg.Controls.AddRange(new Control[] { lblTitle, lblAuthor, lblIconAttr, btnClose });
            dlg.ShowDialog(this);
        }

        private void OnTick(object sender, EventArgs e)
        {
            if (masterPassword != null && currentVault != null && currentVault.AutoLock5Min && (DateTime.UtcNow - lastActivity).TotalMinutes >= 5)
            {
                LockApp();
                return;
            }

            if (masterPassword == null || activeCards.Count == 0) return;

            long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            foreach (var kv in activeCards)
            {
                var card = kv.Value;
                int period = card.Item.Period;
                int rem = period - (int)(now % period);

                card.Pbar.Value = Math.Max(0, Math.Min(rem, period));
                card.LblTimer.Text = rem + "s";
                card.LblTimer.ForeColor = rem <= 5 ? Color.FromArgb(248, 113, 113) : Color.FromArgb(148, 163, 184);

                if (rem == period || card.CurrentCode == "ERROR")
                {
                    try
                    {
                        string secret = Crypto.Decrypt(card.Item.EncryptedSecret, card.Item.Iv, masterPassword, saltBytes);
                        string code = Totp.Generate(secret, card.Item.Digits, card.Item.Period, card.Item.Algorithm);
                        card.CurrentCode = code;
                        string fmt = code != "ERROR" && code.Length >= 6 ? code.Substring(0, code.Length / 2) + " " + code.Substring(code.Length / 2) : code;
                        card.LblCode.Text = fmt;
                    }
                    catch { }
                }
            }
        }

        private void LockApp()
        {
            masterPassword = null;
            ShowLogin();
        }
    }

    // =======================================================================
    // Global Idle Tracker
    // =======================================================================
    public class ActivityFilter : IMessageFilter
    {
        private readonly Action onActivity;
        public ActivityFilter(Action onActivity) { this.onActivity = onActivity; }
        public bool PreFilterMessage(ref Message m)
        {
            const int WM_KEYDOWN = 0x0100;
            const int WM_MOUSEMOVE = 0x0200;
            const int WM_LBUTTONDOWN = 0x0201;
            if (m.Msg == WM_KEYDOWN || m.Msg == WM_MOUSEMOVE || m.Msg == WM_LBUTTONDOWN)
            {
                if (onActivity != null) onActivity();
            }
            return false;
        }
    }

    // =======================================================================
    // Program Entrypoint
    // =======================================================================
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
