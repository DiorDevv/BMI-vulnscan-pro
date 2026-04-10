'use strict';
/* ══════════════════════════════════════════════════════════════════
   VulnScan Pro — Frontend Application
   ══════════════════════════════════════════════════════════════════ */

// ── Severity config ────────────────────────────────────────────────────────
const SEV = ['critical','high','medium','low','info'];
const SEV_COLOR = { critical:'#ff2d55', high:'#ff7730', medium:'#ffc107', low:'#00e87a', info:'#60a5fa' };
const SEV_UZ    = { critical:'Kritik', high:'Yuqori', medium:"O'rta", low:'Past', info:"Ma'lumot" };

// ── Uzbek Vulnerability Knowledge Base ────────────────────────────────────
// Hamma zaifliklar uchun to'liq o'zbek tilida tushuntirish
const VULN_UZ = {

  sql_injection: {
    nomi: "SQL In'ektsiya (SQL Injection)",
    emoji: "💉",
    tavsif: `<b>SQL in'ektsiya</b> — tajovuzkor veb-ilova orqali ma'lumotlar bazasiga
zararli SQL buyruqlarini kiritishi imkoni. Bu xavfli zaiflik foydalanuvchi kiritgan
ma'lumotlar <b>filtrsiz to'g'ridan-to'g'ri SQL so'roviga</b> qo'shib yuborilib,
ma'lumotlar bazasini nazorat qilish imkonini beradi.`,
    xavf: [
      "Barcha foydalanuvchilar ma'lumotlari (login, parol, email) o'g'irlanishi",
      "Kredit karta va to'lov ma'lumotlari to'liq olinishi",
      "Admin kirishi parolsiz amalga oshirilishi (autentifikatsiyani chetlab o'tish)",
      "Ma'lumotlar bazasidagi barcha jadvallar o'chirilishi (DROP TABLE)",
      "Server fayllari o'qilishi yoki yozilishi (FILE operatsiyalar)",
      "Boshqa serverlarga hujum (DNS/HTTP orqali)",
    ],
    qanday: `Hujumchi qidiruv yoki kirish maydoniga maxsus belgilar kiritadi: <code>'</code>,
<code>\" OR 1=1--</code>, <code>'; DROP TABLE users;--</code>. Agar ilova bu ma'lumotlarni
filtrsiz SQL ga qo'shsa, hujumchi ixtiyoriy so'rovlarni bajaradi.`,
    tuzatish: [
      "Prepared Statement (PDO / MySQLi parametrlangan so'rovlar) ishlatish",
      "ORM (Eloquent, SQLAlchemy, Hibernate) kutubxonalaridan foydalanish",
      "Barcha foydalanuvchi kiritgan ma'lumotlarni whitelist asosida tekshirish",
      "Ma'lumotlar bazasi foydalanuvchisiga minimal huquqlar berish (least privilege)",
      "WAF (Web Application Firewall) o'rnatish",
      "Xato xabarlarini foydalanuvchilarga ko'rsatmaslik (error handling)",
    ],
  },

  xss_reflected: {
    nomi: "Aks Ettirilgan XSS (Reflected Cross-Site Scripting)",
    emoji: "🎭",
    tavsif: `<b>Reflected XSS</b> — tajovuzkor URL orqali zararli JavaScript kodini
saytga kiritadi. Jabrlanuvchi bu havolani bosganda, kod darhol uning
brauzerida ishlaydi. Zararli havola fishing xabarlari, ijtimoiy tarmoqlar
yoki elektron pochta orqali yuboriladi.`,
    xavf: [
      "Foydalanuvchi session cookie'lari o'g'irlanishi (hisobni qo'lga olish)",
      "Foydalanuvchi nomidan ixtiyoriy amallar bajarilishi",
      "Sahifa ko'rinishini o'zgartirish (soxta kirish formlari — phishing)",
      "Keylogger — klaviatura urilishlarini yashirin yozib borish",
      "Kamera/mikrofonga kirish (zamonaviy brauzer hujumlari)",
      "Boshqa hujumlar uchun pivot sifatida ishlatish",
    ],
    qanday: `Hujumchi <code>?q=&lt;script&gt;stealCookies()&lt;/script&gt;</code> kabi
URL yaratadi. Sayt bu qiymatni filtrsiz sahifaga chiqarsa, jabrlanuvchi
brauzerida kod ishlaydi va cookie'lar hujumchiga yuboriladi.`,
    tuzatish: [
      "Barcha chiquvchi ma'lumotlarni HTML encode qilish (&lt; &gt; &amp; &quot;)",
      "Content-Security-Policy (CSP) sarlavhasini qo'shish",
      "HttpOnly va Secure bayroqlarini cookie'larga qo'shish",
      "DOMPurify kutubxonasidan foydalanish (React, Angular avtomatik qiladi)",
      "X-XSS-Protection sarlavhasini o'rnatish",
      "Input validatsiyasi — HTML teglarni qabul qilmaslik",
    ],
  },

  xss_stored: {
    nomi: "Saqlanadigan XSS (Stored Cross-Site Scripting)",
    emoji: "🎭",
    tavsif: `<b>Stored XSS</b> — zararli kod ma'lumotlar bazasiga saqlanadi va
sahifani har kim ko'rganda avtomatik ishlaydi. Bu <b>eng xavfli XSS turi</b>,
chunki bir marta joylashtirilgan kod barcha foydalanuvchilarga ta'sir qiladi.`,
    xavf: [
      "Saytga kirgan barcha foydalanuvchilar ta'sir ostiga olish",
      "Ommaviy session o'g'irlash — yuz minglab hisoblarni bir vaqtda olish",
      "Sayt ma'murini ham o'z ichiga olgan barcha hisoblarni buzish",
      "Zararli dastur (malware) tarqatish platformasiga aylantirish",
      "Kriptominer botnet yaratish",
    ],
    qanday: `Hujumchi sharh, profil nomi yoki boshqa matn maydoniga JavaScript
kiritadi. Bu saqlangan kod keyinroq sahifani ko'rgan har bir foydalanuvchi
brauzerida ishlab ketadi.`,
    tuzatish: [
      "Ma'lumotlar bazasiga saqlashdan oldin barcha kirishlarni tozalash",
      "Chiqarishda HTML escape qilish (XSS ning ikkinchi liniyasi)",
      "Content-Security-Policy qat'iy holatda o'rnatish",
      "Foydalanuvchi kiritgan HTML ni qabul qiluvchi maydonlarda DOMPurify ishlatish",
      "Antivirus/IDS tizimlarni web-ilovaga ulash",
    ],
  },

  xss_dom: {
    nomi: "DOM-asosidagi XSS (DOM-based XSS)",
    emoji: "🎭",
    tavsif: `<b>DOM XSS</b> — zararli kod server orqali o'tmasdan, to'g'ridan-to'g'ri
brauzerning DOM muhitida ishlaydi. JavaScript kodining o'zi
foydalanuvchi kiritgan ma'lumotlarni xavfli tarzda ishlatadi
(<code>innerHTML</code>, <code>eval()</code>, <code>document.write()</code>).`,
    xavf: [
      "Serverda hech qanday iz qoldirmasdan hujum amalga oshirilishi",
      "Server loglarida ko'rinmasligi (aniqlash qiyin)",
      "Barcha XSS hujumlari kabi session o'g'irlash, phishing",
      "SPA (React, Vue, Angular) ilovalarida keng tarqalgan",
    ],
    qanday: `<code>location.hash</code> yoki <code>location.search</code> dan
olingan qiymat <code>innerHTML</code> ga to'g'ridan-to'g'ri qo'yilsa,
<code>#&lt;img src=x onerror=alert(1)&gt;</code> kabi hujum ishlaydi.`,
    tuzatish: [
      "innerHTML o'rniga textContent / innerText ishlatish",
      "eval(), setTimeout(string), new Function() dan qochish",
      "DOM sink larini tekshirishda DOMPurify ishlatish",
      "JavaScript framework xavfsizlik qoidalarini to'liq bajarish",
      "Strict CSP policy o'rnatish",
    ],
  },

  cors_misconfiguration: {
    nomi: "CORS Noto'g'ri Konfiguratsiyasi",
    emoji: "🌐",
    tavsif: `<b>CORS (Cross-Origin Resource Sharing)</b> — brauzer qaysi saytlar
API ga murojaat qilishini nazorat qiladi. Noto'g'ri sozlanganda
tajovuzkor saytlar jabrlanuvchi brauzeridan autentifikatsiyalangan
so'rovlar yuborib, maxfiy ma'lumotlarni o'g'irishi mumkin.`,
    xavf: [
      "Autentifikatsiyalangan foydalanuvchi hisobidagi ma'lumotlarni o'qish",
      "Foydalanuvchi nomidan amallar bajarish (pul o'tkazish, sozlamalar o'zgartirish)",
      "Wildcard (*) + credentials kombinatsiyasi — to'liq API nazoratsiz ochiq",
      "Null origin ruxsati — iframe sandbox orqali hujum",
      "Subdomain takeover orqali CORS bypass",
    ],
    qanday: `Tajovuzkor sayt <code>evil.com</code> jabrlanuvchi brauzeridan
<code>api.target.com</code> ga so'rov yuboradi. Agar CORS
<code>Access-Control-Allow-Origin: *</code> qaytarsa, xususiy
ma'lumotlar evil.com ga ketadi.`,
    tuzatish: [
      "Origin whitelist — faqat ishonchli domenlarni ruxsat qilish",
      "Wildcard (*) va credentials=true ni birgalikda ishlatmaslik",
      "Null origin ni hech qachon ruxsat etmaslik",
      "Zarur HTTP metodlari va sarlavhalarni aniq ko'rsatish",
      "CORS sozlamalarini muntazam audit qilish",
    ],
  },

  open_redirect: {
    nomi: "Ochiq Yo'naltirish (Open Redirect)",
    emoji: "↗️",
    tavsif: `<b>Open Redirect</b> — sayt foydalanuvchini tashqi URL ga
yo'naltirishda URL ni tekshirmaslik. Bu zaiflik fishing hujumlari
uchun keng ishlatiladi, chunki ishonchli sayt (<code>bank.uz</code>)
nomi orqali foydalanuvchi aldanadi.`,
    xavf: [
      "Fishing hujumlari — 'bank.uz/?redirect=evil.com' kabi ishonchli havola",
      "OAuth token o'g'irlash — autentifikatsiya callback ni yo'naltirish",
      "SSO (Single Sign-On) tizimlarini buzish",
      "Zararli dastur yuklab olish sahifasiga yo'naltirish",
      "SEO spam (search engine optimization abuse)",
    ],
    qanday: `Hujumchi <code>https://ishonchli-sayt.uz/login?next=https://evil.com</code>
havolasi yaratadi. Foydalanuvchi kirgach, zararli saytga o'tkaziladi,
lekin URL ning boshi ishonchli ko'rinadi.`,
    tuzatish: [
      "Tashqi URL yo'naltirishlarini to'liq man etish (faqat ichki sahifalar)",
      "Agar zarur bo'lsa, ruxsat etilgan domenlar ro'yxatini yaratish",
      "Relative URL lardan foydalanish (/profile o'rniga http://..)",
      "Yo'naltirish parametrlarini server tomonida tekshirish va sanitize qilish",
      "Foydalanuvchiga 'siz tashqi saytga o'tmoqdasiz' xabarini ko'rsatish",
    ],
  },

  missing_security_header: {
    nomi: "Xavfsizlik Sarlavhasi Yetishmaydi",
    emoji: "🔒",
    tavsif: `HTTP xavfsizlik sarlavhalari brauzerga saytni qanday himoya
qilishni bildiradi. Yetishmagan sarlavhalar <b>XSS, clickjacking,
MIME sniffing</b> va boshqa hujumlarga yo'l ochadi. Ular tekin va
o'rnatish oson, lekin juda muhim himoya qatlamini ta'minlaydi.`,
    xavf: [
      "HSTS yo'q → HTTP downgrade hujumi, traffic tutib olish (MITM)",
      "CSP yo'q → XSS hujumlari samarali ishlaydi",
      "X-Frame-Options yo'q → Clickjacking (soyali bosish hujumi)",
      "X-Content-Type-Options yo'q → MIME sniffing hujumi",
      "Referrer-Policy yo'q → foydalanuvchi ma'lumotlari 3-partiyaga ketishi",
    ],
    qanday: `Brauzer bu sarlavhalar orqali xavfsizlik cheklovlarini amalga
oshiradi. Masalan, <code>X-Frame-Options: DENY</code> bo'lmasa,
hujumchi saytingizni ko'zga ko'rinmas iframe ichiga joylashtirib,
foydalanuvchi bosishlarini tutib olishi mumkin.`,
    tuzatish: [
      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      "Content-Security-Policy: default-src 'self'; ... ni sozlash",
      "X-Content-Type-Options: nosniff",
      "X-Frame-Options: DENY yoki SAMEORIGIN",
      "Referrer-Policy: strict-origin-when-cross-origin",
      "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ],
  },

  weak_ssl_tls: {
    nomi: "Zaif SSL/TLS Protokoli",
    emoji: "🔓",
    tavsif: `<b>SSL/TLS</b> — internet orqali ma'lumotlarni shifrlash protokoli.
Eski versiyalar (SSLv2, SSLv3, TLS 1.0, TLS 1.1) va zaif shifrlash
algoritmlari taniqli zaifliklarni o'z ichiga oladi va <b>MITM
hujumlari</b> orqali shifrni buzishga imkon beradi.`,
    xavf: [
      "POODLE hujumi — SSLv3 orqali shifrlangan ma'lumotni ochish",
      "BEAST, CRIME, BREACH hujumlari — TLS 1.0/1.1 zaifliklar",
      "RC4, DES, 3DES shifrlari → ma'lum kriptografik hujumlar",
      "Sertifikat muddati tugagan → foydalanuvchi ogohlantirmasi",
      "O'z-o'ziga imzolangan sertifikat → MITM imkoniyati",
      "Man-in-the-Middle — trafikni tutib o'qish va o'zgartirish",
    ],
    qanday: `Agar server hali ham TLS 1.0 ni qo'llasa, BEAST hujumi orqali
tajovuzkor shifrlangan HTTPs trafikdan maxfiy ma'lumotlarni olishi
mumkin. RC4 shifri esa statistik tahlil bilan buziladi.`,
    tuzatish: [
      "Faqat TLS 1.2 va TLS 1.3 ni qo'llash",
      "SSLv2, SSLv3, TLS 1.0, TLS 1.1 ni to'liq o'chirish",
      "Zaif shifr suitlarini (RC4, DES, 3DES, NULL) o'chirish",
      "Let's Encrypt orqali bepul va avtomatik sertifikat olish",
      "HSTS preload listiga qo'shilish",
      "Har 90 kunda sertifikatni yangilash",
    ],
  },

  directory_listing: {
    nomi: "Katalog Ro'yxati Ochiq (Directory Listing)",
    emoji: "📂",
    tavsif: `Veb-server katalog ichidagi barcha fayllar ro'yxatini ko'rsatadi.
Bu <b>ma'lumot oshkoraligi</b> zaifligidir — hujumchi sayt
strukturasini, konfiguratsiya fayllarini, zaxira nusxalarini va
boshqa maxfiy fayllarni ko'rishi mumkin.`,
    xavf: [
      "Zaxira fayllar topilishi (.bak, .old, .sql) → ma'lumotlar o'g'irlanishi",
      "Konfiguratsiya fayllari ko'rinishi (database.yml, config.php)",
      "Manba kodi (source code) ochilishi",
      "Hujumchi uchun recon (razvedka) ma'lumotlari",
      "Parollar, API kalitlar saqlangan fayllar topilishi",
    ],
    qanday: `Nginx yoki Apache da <code>Options Indexes</code> yoqilgan bo'lsa,
<code>https://site.uz/uploads/</code> ga kirganda barcha yuklanmalar
ro'yxati ko'rinadi. Bu qator muhim fayllarning manziliga olib boradi.`,
    tuzatish: [
      "Nginx: autoindex off; Apache: Options -Indexes",
      "Keraksiz kataloglarga kirish taqiqlash (.htaccess)",
      "Maxfiy fayllarni veb-ildiz (webroot) tashqarisida saqlash",
      "Fayl yuklanmalarini alohida xizmatga ko'chirish (S3, CDN)",
      "Muhim fayllar uchun autentifikatsiya talab qilish",
    ],
  },

  sensitive_file_exposed: {
    nomi: "Maxfiy Fayl Ochiq (Sensitive File Exposed)",
    emoji: "🗄️",
    tavsif: `Maxfiy fayllar veb-orqali to'g'ridan-to'g'ri yuklab olinishi
mumkin: <code>.env</code>, <code>config.php</code>,
<code>.git/config</code>, zaxira fayllar va boshqalar.
Bu fayllar ma'lumotlar bazasi parollari, API kalitlar va
serverni to'liq boshqarish uchun ma'lumotlarni o'z ichiga olishi mumkin.`,
    xavf: [
      ".env fayl → DATABASE_URL, API kalitlar, parollar to'liq ochiq",
      ".git/config → manba kodi to'liq yuklab olinishi (git clone)",
      "backup.sql → butun ma'lumotlar bazasi dump i yuklab olish",
      "phpinfo.php → server konfiguratsiyasi, PHP versiyasi, modullar",
      "wp-config.php → WordPress ma'lumotlar bazasi kirish ma'lumotlari",
    ],
    qanday: `Hujumchi taniqli maxfiy fayl manzillarini tekshiradi:
<code>/.env</code>, <code>/.git/config</code>, <code>/config.php.bak</code>.
Agar server 200 qaytarsa, mazmun to'liq yuklab olinadi.`,
    tuzatish: [
      ".env, .git, .htpasswd kabi fayllarni veb-ildizga HECH QACHON joylashtirmaslik",
      "Nginx/Apache konfiguratsiyasida maxfiy fayllarni bloklash",
      "Zaxira fayllarni veb-ildiz tashqarisida saqlash",
      ".gitignore ga barcha maxfiy fayllarni qo'shish",
      "Deployment jarayonida debug fayllar (phpinfo.php) o'chirilishini ta'minlash",
    ],
  },

  open_port: {
    nomi: "Ochiq Port / Xizmat",
    emoji: "🔌",
    tavsif: `Server internetga ochiq portlar orqali xizmatlar ko'rsatadi.
Keraksiz ochiq portlar <b>hujum yuzasini</b> kengaytiradi.
FTP, Telnet, RDP kabi eski protokollar ma'lum zaifliklarni
o'z ichiga oladi va brute-force hujumlariga moyil.`,
    xavf: [
      "FTP (21) → ma'lumotlar shifrsiz uzatiladi, brute-force mumkin",
      "Telnet (23) → barcha trafik ochiq matn, MITM hujumi oson",
      "RDP (3389) → BlueKeep va boshqa kritik zaifliklar",
      "SMB (445) → EternalBlue / WannaCry kabi hujumlar",
      "VNC (5900) → uzoqdan grafik kirish, parol brute-force",
      "MySQL/PostgreSQL (3306/5432) → to'g'ridan-to'g'ri ma'lumotlar bazasi hujumi",
    ],
    qanday: `Hujumchi Nmap, Shodan kabi vositalar bilan serverning
ochiq portlarini skanerlab, har biri uchun zaifliklarni tekshiradi.
Eski versiyali xizmatlar avtomatik exploit bo'lishi mumkin.`,
    tuzatish: [
      "Firewall qoidalari — faqat zarur portlarni ochish",
      "FTP o'rniga SFTP/FTPS ishlatish",
      "Telnet o'rniga SSH (port 22) ishlatish",
      "RDP uchun VPN orqali kirish yoki port o'zgartirish",
      "Ma'lumotlar bazasini faqat localhost ga bog'lash",
      "Fail2ban yoki similar brute-force himoyasini o'rnatish",
    ],
  },
};

// Default for unknown types
const VULN_DEFAULT = {
  nomi: "Xavfsizlik Zaiflik",
  emoji: "⚠️",
  tavsif: "Skanerlash jarayonida ushbu zaiflik aniqlandi.",
  xavf: ["Ma'lumotlar oshkoralanishi", "Tizim xavfsizligiga tahdid"],
  qanday: "Zaiflik skanerlash vaqtida avtomatik aniqlanib tekshirildi.",
  tuzatish: ["Xavfsizlik mutaxassisi bilan maslahat oling", "Tizimni yangilang"],
};

// Module display info
const MOD_INFO = {
  ssl:     { ico:'🔒', txt:'SSL / TLS Tahlili' },
  headers: { ico:'🔍', txt:'HTTP Sarlavhalar' },
  ports:   { ico:'🔌', txt:'Port Skanerlash' },
  crawl:   { ico:'🕷', txt:'Veb Crawler' },
  active:  { ico:'⚡', txt:"Faol Skan (SQLi/XSS)" },
  cors:    { ico:'🌐', txt:'CORS Tekshiruvi' },
  dirs:    { ico:'📂', txt:'Katalog Brute-force' },
};

// ── State ─────────────────────────────────────────────────────────────────
let scanId     = null;
let scanResult = null;
let evtSrc     = null;
let cDonut     = null;
let cTypes     = null;
let cSev       = null;
let clockTimer = null;
let t0         = null;
let activeFilt = 'all';

// ── Helpers ────────────────────────────────────────────────────────────────
const q   = id  => document.getElementById(id);
const show = id => q(id) && q(id).classList.remove('hidden');
const hide = id => q(id) && q(id).classList.add('hidden');
const esc = s   => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const trunc = (s,n) => s && s.length>n ? s.slice(0,n)+'…' : s||'';
const fmt   = iso  => { try { return new Date(iso).toLocaleString('uz-UZ'); } catch{ return iso||'—'; } };

// ── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  q('url-input').addEventListener('keydown', e => e.key === 'Enter' && startScan());
});

/* ════════════════════════════════════════════════════════════════
   START SCAN
   ════════════════════════════════════════════════════════════════ */
async function startScan() {
  const url     = (q('url-input').value || '').trim();
  const profile = q('sel-profile').value;
  const ssl     = q('chk-ssl').checked;
  const robots  = q('chk-robots').checked;

  if (!url)                              { setFormErr("URL manzilini kiriting."); return; }
  if (!/^https?:\/\//i.test(url))        { setFormErr("URL http:// yoki https:// bilan boshlanishi kerak."); return; }
  clearFormErr();

  // Button → loading
  const btn = q('scan-btn');
  btn.disabled = true;
  q('scan-icon').style.animation = 'spin .8s linear infinite';
  q('scan-txt').textContent = 'SKANERLASH…';

  // Prepare scan UI
  resetScanUI();
  q('stb-target').textContent  = url;
  q('stb-profile').textContent = profile.toUpperCase();
  q('stb-status').textContent  = 'Skanerlash boshlandi…';
  show('sec-scan');
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Clock
  t0 = Date.now();
  clockTimer = setInterval(tick, 1000);

  // Modules
  buildModuleList(profile);

  // Chart
  buildDonut();

  try {
    const res  = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, profile, ignore_ssl: ssl, ignore_robots: robots }),
    });

    if (!res.ok) { throw new Error(`Server xatosi ${res.status}`); }
    const data = await res.json();

    if (data.error) { setFormErr(data.error); resetBtn(); return; }

    scanId = data.scan_id;
    tline(`$ vulnscan --target ${url} --scan ${profile}`, 'tl-cmd');
    tline('', '');
    openStream(data.scan_id);

  } catch (err) {
    tline(`✗  ${err.message}`, 'tl-err');
    setDot('failed');
    stopClock();
    resetBtn();
  }
}

/* ════════════════════════════════════════════════════════════════
   SSE STREAM
   ════════════════════════════════════════════════════════════════ */
function openStream(id) {
  if (evtSrc) evtSrc.close();
  evtSrc = new EventSource(`/api/scan/${id}/stream`);
  evtSrc.onmessage = e => { try { handleEv(JSON.parse(e.data)); } catch(_){} };
  evtSrc.onerror   = () => {
    if (!scanResult) { tline('⚠  Stream uzildi.', 'tl-err'); setDot('failed'); stopClock(); }
    evtSrc.close();
    resetBtn();
  };
}

function handleEv(ev) {
  switch (ev.type) {
    case 'phase':
      tline('', '');
      tline(`▶  ${ev.message}`, 'tl-phase');
      break;

    case 'module_start':
      tline(`   ⟳  ${ev.message}`, 'tl-start');
      setMod(ev.module, 'run');
      break;

    case 'module_done': {
      const has = (ev.findings||0) > 0;
      tline(`   ${has?'⚠':'✓'}  ${ev.message}`, has?'tl-warn':'tl-ok');
      setMod(ev.module, has?'warn':'ok');
      break;
    }

    case 'module_skip':
      tline(`   ○  ${ev.message}`, 'tl-muted');
      setMod(ev.module, 'skip');
      break;

    case 'summary':
      tline('', '');
      tline(`✓  ${ev.message}`, 'tl-sum');
      setGauge(ev.risk_score, ev.duration, ev.severity_counts);
      setSevCounts(ev.severity_counts);
      if (q('stb-status')) q('stb-status').textContent = `Risk: ${ev.risk_score}/100 · ${ev.total_findings || 0} ta zaiflik topildi`;
      break;

    case 'done':
      scanResult = ev.result;
      stopClock();
      setDot('done');
      if (q('stb-status')) q('stb-status').textContent = 'Skanerlash yakunlandi ✓';
      tline('', '');
      tline('══════════  Natijalar tayyor — quyida ko\'ring  ══════════', 'tl-sum');
      renderResults(ev.result);
      evtSrc.close();
      resetBtn();
      break;

    case 'error':
      tline(`✗  XATO: ${ev.message}`, 'tl-err');
      setDot('failed');
      stopClock();
      evtSrc.close();
      resetBtn();
      break;

    case 'stream_end':
      evtSrc.close();
      break;
  }
}

/* ════════════════════════════════════════════════════════════════
   TERMINAL
   ════════════════════════════════════════════════════════════════ */
function tline(text, cls) {
  const t = q('term-out');
  if (!t) return;
  const cur = t.querySelector('.tc');
  if (cur) cur.remove();

  if (text !== '') {
    const s = document.createElement('span');
    s.className = `tl ${cls||''}`;
    s.textContent = text;
    t.appendChild(s);
    t.appendChild(document.createElement('br'));
  } else {
    t.appendChild(document.createElement('br'));
  }

  const c = document.createElement('span');
  c.className = 'tc'; c.textContent = '▌';
  t.appendChild(c);
  t.scrollTop = t.scrollHeight;
}

function clearTerm() {
  const t = q('term-out');
  if (t) t.innerHTML = '<span class="tc">▌</span>';
}

/* ════════════════════════════════════════════════════════════════
   MODULE CHECKLIST
   ════════════════════════════════════════════════════════════════ */
function buildModuleList(profile) {
  const keys = profile === 'quick'
    ? ['ssl','headers','ports','crawl','dirs']
    : ['ssl','headers','ports','crawl','active','cors','dirs'];

  const box = q('mod-list');
  if (!box) return;
  box.innerHTML = '';

  for (const k of keys) {
    const info = MOD_INFO[k] || { ico:'•', txt:k };
    const row  = document.createElement('div');
    row.className = 'mod-row';
    row.id = `mr-${k}`;
    row.innerHTML = `
      <span class="mod-ico">${info.ico}</span>
      <span class="mod-name-txt">${info.txt}</span>
      <span class="mbadge mb-wait" id="mb-${k}">kutilmoqda</span>`;
    box.appendChild(row);
  }
}

function setMod(mod, state) {
  const b = q(`mb-${mod}`);
  if (!b) return;
  b.className = 'mbadge';
  if (state === 'run')  { b.classList.add('mb-run');  b.textContent = 'test qilinmoqda…'; }
  if (state === 'ok')   { b.classList.add('mb-ok');   b.textContent = 'tamom ✓'; }
  if (state === 'warn') { b.classList.add('mb-warn'); b.textContent = 'topildi ⚠'; }
  if (state === 'skip') { b.classList.add('mb-skip'); b.textContent = 'o\'tkazib yuborildi'; }
}

/* ════════════════════════════════════════════════════════════════
   GAUGE
   ════════════════════════════════════════════════════════════════ */
function setGauge(score, dur, counts) {
  const arc  = q('g-arc');
  const val  = q('g-val');
  const lbl  = q('g-lbl');
  const durE = q('g-dur');
  const totE = q('g-total');

  if (val) val.textContent = score ?? '—';
  if (arc) {
    const pct    = (score||0) / 100;
    const circum = 251.2;   // 2π × 40
    arc.style.strokeDashoffset = circum - pct * circum;
    let col = '#00e87a';
    if (score >= 75)      col = '#ff2d55';
    else if (score >= 50) col = '#ff7730';
    else if (score >= 25) col = '#ffc107';
    arc.style.stroke = col;
  }

  let label = 'PAST';
  if (score >= 75)      label = 'KRITiK';
  else if (score >= 50) label = 'YUQORI';
  else if (score >= 25) label = "O'RTA";
  if (lbl) lbl.textContent = label;
  if (durE && dur) durE.textContent = `${dur.toFixed(1)} soniya`;
  if (counts) {
    const total = Object.values(counts).reduce((a,b) => a+b, 0);
    if (totE) totE.textContent = `${total} ta zaiflik`;
    setSevCounts(counts);
  }
}

function setSevCounts(c) {
  if (!c) return;
  for (const s of SEV) { const e=q(`cnt-${s}`); if(e) e.textContent = c[s]??0; }
  if (cDonut) {
    cDonut.data.datasets[0].data = SEV.map(s=>c[s]??0);
    cDonut.update('none');
  }
}

/* ════════════════════════════════════════════════════════════════
   LIVE DONUT
   ════════════════════════════════════════════════════════════════ */
function buildDonut() {
  const ctx = q('chart-live');
  if (!ctx) return;
  if (cDonut) { cDonut.destroy(); cDonut=null; }
  cDonut = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Kritik','Yuqori',"O'rta",'Past',"Ma'lumot"],
      datasets: [{ data:[0,0,0,0,0], backgroundColor:Object.values(SEV_COLOR), borderColor:'#0c1628', borderWidth:3, hoverOffset:4 }],
    },
    options: {
      responsive:true, cutout:'72%',
      plugins:{
        legend:{ position:'bottom', labels:{ color:'#8899bb', font:{size:10}, padding:7 } },
        tooltip:{ callbacks:{ label:c=>` ${c.label}: ${c.raw}` } },
      },
    },
  });
}

/* ════════════════════════════════════════════════════════════════
   RENDER FULL RESULTS
   ════════════════════════════════════════════════════════════════ */
function renderResults(r) {
  show('sec-results');
  const sc = r.severity_counts || {};

  // Header
  const rt = q('res-target'); if(rt) rt.textContent = r.target;
  const rm = q('res-meta');
  if (rm) rm.innerHTML = `
    <span>📊 Risk: <b>${r.risk_score}/100</b></span> &nbsp;·&nbsp;
    <span>⏱ Davomiyligi: <b>${(r.duration_seconds||0).toFixed(1)}s</b></span> &nbsp;·&nbsp;
    <span>🔍 Profil: <b>${(r.scan_profile||'').toUpperCase()}</b></span> &nbsp;·&nbsp;
    <span>📋 Modullar: <b>${(r.modules_run||[]).join(', ')}</b></span>`;

  // KPI cards
  renderKPI(sc, r.risk_score||0);

  // Charts
  renderTypesChart(r.findings||[]);
  renderSevChart(sc);
  renderMetrics(r);

  // Findings
  renderFindings(r.findings||[]);

  setTimeout(() => q('sec-results')?.scrollIntoView({ behavior:'smooth', block:'start' }), 350);
}

function renderKPI(sc, score) {
  const box = q('kpi-row');
  if (!box) return;

  let riskClass = 'kl';
  if (score>=75)      riskClass='kc';
  else if (score>=50) riskClass='kh';
  else if (score>=25) riskClass='km';

  let rLabel = 'PAST';
  if (score>=75)      rLabel='KRITiK';
  else if (score>=50) rLabel='YUQORI';
  else if (score>=25) rLabel="O'RTA";

  box.innerHTML = `
    <div class="kpi kc"><div class="kpi-num">${sc.critical??0}</div><div class="kpi-lbl">Kritik</div></div>
    <div class="kpi kh"><div class="kpi-num">${sc.high??0}</div><div class="kpi-lbl">Yuqori</div></div>
    <div class="kpi km"><div class="kpi-num">${sc.medium??0}</div><div class="kpi-lbl">O'rta</div></div>
    <div class="kpi kl"><div class="kpi-num">${sc.low??0}</div><div class="kpi-lbl">Past</div></div>
    <div class="kpi ${riskClass}"><div class="kpi-num">${score}</div><div class="kpi-lbl">Xavf Ball · ${rLabel}</div></div>`;
}

function renderTypesChart(findings) {
  const ctx = q('chart-types');
  if (!ctx) return;
  if (cTypes) { cTypes.destroy(); cTypes=null; }
  if (!findings.length) return;

  const cnt = {};
  for (const f of findings) {
    const vz = VULN_UZ[f.vuln_type];
    const lbl = vz ? vz.nomi.split(' (')[0] : f.vuln_type;
    cnt[lbl] = (cnt[lbl]||0)+1;
  }
  const labels = Object.keys(cnt), data = Object.values(cnt);
  const colors = labels.map((_,i)=>`hsl(${180+i*42},80%,58%)`);

  cTypes = new Chart(ctx, {
    type:'bar',
    data:{ labels, datasets:[{ label:'Soni', data, backgroundColor:colors, borderRadius:5, borderSkipped:false }] },
    options:{
      indexAxis:'y', responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{display:false}, tooltip:{callbacks:{label:c=>` ${c.raw} ta zaiflik`}} },
      scales:{
        x:{ ticks:{color:'#8899bb',stepSize:1}, grid:{color:'rgba(255,255,255,.04)'} },
        y:{ ticks:{color:'#f0f4ff',font:{size:11}}, grid:{display:false} },
      },
    },
  });
}

function renderSevChart(sc) {
  const ctx = q('chart-sev');
  if (!ctx||!sc) return;
  if (cSev) { cSev.destroy(); cSev=null; }

  cSev = new Chart(ctx, {
    type:'bar',
    data:{
      labels:["Kritik","Yuqori","O'rta","Past","Ma'lumot"],
      datasets:[{ label:'Soni', data:SEV.map(s=>sc[s]??0), backgroundColor:Object.values(SEV_COLOR), borderRadius:6, borderSkipped:false }],
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{display:false}, tooltip:{callbacks:{label:c=>` ${c.raw} ta`}} },
      scales:{
        x:{ ticks:{color:'#8899bb'}, grid:{display:false} },
        y:{ ticks:{color:'#8899bb',stepSize:1}, grid:{color:'rgba(255,255,255,.04)'} },
      },
    },
  });
}

function renderMetrics(r) {
  const box = q('metrics-body');
  if (!box) return;
  const sc    = r.severity_counts||{};
  const score = r.risk_score??0;
  let rc='risk-l';
  if(score>=75) rc='risk-c'; else if(score>=50) rc='risk-h'; else if(score>=25) rc='risk-m';

  const rows = [
    ['Umumiy xavf ball', `<span class="met-v ${rc}">${score}/100</span>`],
    ['Jami zaifliklar', `<span class="met-v">${(r.findings||[]).length} ta</span>`],
    ['Kritik', `<span class="met-v vc">${sc.critical??0}</span>`],
    ['Yuqori', `<span class="met-v vh">${sc.high??0}</span>`],
    ['Davomiyligi', `<span class="met-v">${(r.duration_seconds||0).toFixed(1)}s</span>`],
    ['Profil', `<span class="met-v">${r.scan_profile||'—'}</span>`],
    ['Modullar', `<span class="met-v" style="font-size:.7rem;color:var(--t2)">${(r.modules_run||[]).join(', ')}</span>`],
    ['Skan ID', `<span class="met-v" style="font-size:.65rem">${(r.id||'').slice(0,16)}…</span>`],
  ];

  box.innerHTML = rows.map(([k,v])=>`<div class="met"><span class="met-k">${k}</span>${v}</div>`).join('');
}

/* ════════════════════════════════════════════════════════════════
   FINDINGS
   ════════════════════════════════════════════════════════════════ */
function renderFindings(findings) {
  const box   = q('findings-list');
  const badge = q('f-count');
  if (!box) return;

  if (badge) badge.textContent = `${findings.length} ta`;

  if (!findings.length) {
    box.innerHTML = `<div class="empty-findings">
      <div class="empty-findings-icon">✅</div>
      Ushbu skanerlash profilida hech qanday zaiflik aniqlanmadi.
    </div>`;
    return;
  }

  const sorted = [...findings].sort(
    (a,b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity)
  );

  box.innerHTML = sorted.map(buildFindingCard).join('');
}

function buildFindingCard(f) {
  const sev      = (f.severity||'info').toLowerCase();
  const vz       = VULN_UZ[f.vuln_type] || VULN_DEFAULT;
  const cvss     = f.cvss_score ?? '—';
  const col      = SEV_COLOR[sev] || '#60a5fa';
  const rgb      = hexToRgb(col);
  const pillCls  = { critical:'sp-c', high:'sp-h', medium:'sp-m', low:'sp-l', info:'sp-i' }[sev]||'sp-i';
  const cardCls  = { critical:'sc',   high:'sh',   medium:'sm',   low:'sl',   info:'si'   }[sev]||'si';
  const cvssStyle= `background:rgba(${rgb},.15);color:${col};border:1px solid rgba(${rgb},.3)`;

  // Xavf ro'yxati
  const xavfHtml = (vz.xavf||[]).map(x =>
    `<div class="risk-impact-item">${esc(x)}</div>`
  ).join('');

  // Tuzatish qadamlari
  const fixHtml = (vz.tuzatish||[]).map((t,i) =>
    `<div class="fix-step"><span class="fix-num">${i+1}</span><span>${esc(t)}</span></div>`
  ).join('');

  // Texnik optional blocks
  const payloadBlock = f.payload
    ? `<div class="td-row"><span class="td-key">Payload</span>
       <code class="td-code">${esc(f.payload)}</code></div>` : '';

  const paramBlock = f.parameter
    ? `<div class="td-row"><span class="td-key">Parameter</span>
       <code class="td-code">${esc(f.parameter)}</code></div>` : '';

  return `
<div class="fcard ${cardCls}" data-sev="${sev}" id="fc-${f.id}">

  <!-- ── Header ── -->
  <div class="fc-hdr" onclick="toggleFc('${f.id}')">
    <span class="sev-pill ${pillCls}">${SEV_UZ[sev]||sev}</span>
    <span class="fc-title">${vz.emoji} ${esc(vz.nomi)}</span>
    <span class="fc-url" title="${esc(f.url)}">${esc(trunc(f.url,60))}</span>
    <span class="fc-cvss" style="${cvssStyle}">CVSS ${cvss}</span>
    <span class="fc-chev">›</span>
  </div>

  <!-- ── Body ── -->
  <div class="fc-body">
    <div class="fc-inner">

      <!-- ════ O'ZBEK TUSHUNTIRISH ════ -->
      <div class="uz-section">

        <div class="uz-row">
          <div class="uz-row-lbl uz-lbl-desc">Bu zaiflik nima?</div>
          <div class="uz-row-val">${vz.tavsif||''}</div>
        </div>

        <div class="uz-row">
          <div class="uz-row-lbl uz-lbl-risk">Mumkin bo'lgan xavflar</div>
          <div class="uz-row-val">
            <div class="risk-impact">${xavfHtml}</div>
          </div>
        </div>

        <div class="uz-row">
          <div class="uz-row-lbl uz-lbl-how">Qanday ishlaydi?</div>
          <div class="uz-row-val">${vz.qanday||''}</div>
        </div>

        <div class="uz-row" style="border-bottom:none;padding-bottom:0">
          <div class="uz-row-lbl uz-lbl-fix">Qanday tuzatiladi?</div>
          <div class="uz-row-val">
            <div class="fix-steps">${fixHtml}</div>
          </div>
        </div>

      </div>

      <!-- ════ TEXNIK MA'LUMOTLAR (o'z holatida) ════ -->
      <div class="td-section">
        <div class="td-section-title">Technical Details</div>

        <div class="td-grid">
          <div class="td-cell">
            <span class="td-k">Severity</span>
            <span class="td-v" style="color:${col}">${(f.severity||'').toUpperCase()}</span>
          </div>
          <div class="td-cell">
            <span class="td-k">CVSS Score</span>
            <span class="td-v" style="color:${col}">${cvss}</span>
          </div>
          <div class="td-cell">
            <span class="td-k">CWE</span>
            <span class="td-v">${esc(f.cwe_id||'—')}</span>
          </div>
          <div class="td-cell">
            <span class="td-k">OWASP</span>
            <span class="td-v">${esc(f.owasp_ref||'—')}</span>
          </div>
        </div>

        <div class="td-row">
          <span class="td-key">URL</span>
          <code class="td-code" style="word-break:break-all">${esc(f.url)}</code>
        </div>

        ${paramBlock}
        ${payloadBlock}

        <div class="td-row">
          <span class="td-key">Evidence</span>
          <code class="td-code ev-code">${esc((f.evidence||'').slice(0,500))}</code>
        </div>

        <div class="td-row" style="border-bottom:none">
          <span class="td-key">Remediation</span>
          <span class="td-rem">${esc(f.remediation||'—')}</span>
        </div>
      </div>

    </div>
  </div>
</div>`;
}

function toggleFc(id) {
  const card = q(`fc-${id}`);
  if (!card) return;
  card.classList.toggle('open');
}

// (eski switchTab - endi kerak emas, lekin boshqa joylarda chaqirilmaydi)
function switchTab(fid, panel) {
  // no-op: tabs removed

  // Show/hide panels
  ['uz','tech','fix'].forEach(p => {
    const el = q(`fp-${p}-${fid}`);
    if (el) el.classList.toggle('active', p === panel);
  });
}

function filterBy(sev) {
  activeFilt = sev;
  document.querySelectorAll('.fbtn').forEach(b =>
    b.classList.toggle('active', b.dataset.f === sev)
  );
  document.querySelectorAll('.fcard').forEach(c => {
    c.style.display = (sev==='all' || c.dataset.sev===sev) ? '' : 'none';
  });
}

/* ════════════════════════════════════════════════════════════════
   HISTORY
   ════════════════════════════════════════════════════════════════ */
async function toggleHistory() {
  const p = q('hist-panel'), bg = q('hist-bg');
  if (p.classList.contains('hidden')) {
    show('hist-panel'); show('hist-bg');
    await loadHistory();
  } else {
    hide('hist-panel'); hide('hist-bg');
  }
}

async function loadHistory() {
  const body = q('hist-body');
  if (!body) return;
  try {
    const data  = await (await fetch('/api/history')).json();
    const scans = data.scans||[];
    if (!scans.length) {
      body.innerHTML = '<div class="loading-msg">Hech qanday skan yo\'q.</div>';
      return;
    }
    body.innerHTML = scans.map(s => {
      const score = s.risk_score??0;
      let sc='hs-l';
      if(score>=75) sc='hs-c'; else if(score>=50) sc='hs-h'; else if(score>=25) sc='hs-m';
      const d = s.started_at ? new Date(s.started_at).toLocaleString('uz-UZ') : '—';
      return `<div class="hist-item">
        <div class="hist-url">${esc(s.target)}</div>
        <div class="hist-row">
          <span>${d}</span>
          <span class="hist-score ${sc}">Risk ${score}/100 · ${s.profile||'—'}</span>
        </div>
      </div>`;
    }).join('');
  } catch {
    body.innerHTML = '<div class="loading-msg">Tarix yuklanmadi.</div>';
  }
}

/* ════════════════════════════════════════════════════════════════
   EXPORT
   ════════════════════════════════════════════════════════════════ */
function exportJSON() {
  if (!scanResult) return;
  dlBlob(
    new Blob([JSON.stringify(scanResult, null, 2)], { type:'application/json' }),
    `vulnscan_${(scanId||'').slice(0,8)}.json`
  );
}

function exportCSV() {
  if (!scanResult?.findings?.length) return;
  const cols = ['severity','vuln_type','url','parameter','cvss_score','cwe_id','owasp_ref','payload','evidence','remediation'];
  const rows = scanResult.findings.map(f =>
    cols.map(c=>`"${String(f[c]||'').replace(/"/g,'""')}"`).join(',')
  );
  dlBlob(
    new Blob([[cols.join(','),...rows].join('\n')],{type:'text/csv'}),
    `vulnscan_${(scanId||'').slice(0,8)}.csv`
  );
}

function dlBlob(blob, name) {
  const a = Object.assign(document.createElement('a'),{ href:URL.createObjectURL(blob), download:name });
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ════════════════════════════════════════════════════════════════
   UI HELPERS
   ════════════════════════════════════════════════════════════════ */
function newScan() {
  if (evtSrc) { evtSrc.close(); evtSrc=null; }
  stopClock();
  hide('sec-scan'); hide('sec-results');
  scanId=null; scanResult=null; activeFilt='all';
  q('url-input')?.focus();
  resetBtn();
}

function resetScanUI() {
  hide('sec-results');
  clearTerm();
  // Reset gauge
  const arc=q('g-arc');
  if(arc){ arc.style.strokeDashoffset='251.2'; arc.style.stroke='var(--cyan)'; }
  const gv=q('g-val');    if(gv) gv.textContent='—';
  const gl=q('g-lbl');    if(gl) gl.textContent='SKANERLASH…';
  const gd=q('g-dur');    if(gd) gd.textContent='—';
  const gt=q('g-total');  if(gt) gt.textContent='0 ta zaiflik';
  // Reset counts
  SEV.forEach(s=>{ const e=q(`cnt-${s}`); if(e) e.textContent='0'; });
  // Destroy charts
  if(cTypes){ cTypes.destroy(); cTypes=null; }
  if(cSev)  { cSev.destroy();   cSev=null;   }
  // Clear results
  const f=q('findings-list'); if(f) f.innerHTML='';
  const k=q('kpi-row');       if(k) k.innerHTML='';
}

function resetBtn() {
  const btn=q('scan-btn'); if(!btn) return;
  btn.disabled=false;
  q('scan-icon').style.animation='';
  q('scan-txt').textContent='SKANERLASH';
}

function setDot(state) {
  const d=q('stb-dot'); if(!d) return;
  d.className = `stb-dot ${state}`;
}


function tick() {
  if (!t0) return;
  const s = Math.floor((Date.now()-t0)/1000);
  const e=q('stb-timer'); if(e) e.textContent=`${s}s`;
  const gd=q('g-dur'); if(gd && !scanResult) gd.textContent=`${s} soniya`;
}

function stopClock() { if(clockTimer){ clearInterval(clockTimer); clockTimer=null; } }
function setFormErr(m) { const e=q('form-err'); if(e){ e.textContent=m; e.classList.remove('hidden'); } }
function clearFormErr() { const e=q('form-err'); if(e) e.classList.add('hidden'); }

// Convert hex to rgb string for rgba usage
function hexToRgb(hex) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return `${r},${g},${b}`;
}

// Spin animation
document.head.insertAdjacentHTML('beforeend','<style>@keyframes spin{to{transform:rotate(360deg)}}</style>');
