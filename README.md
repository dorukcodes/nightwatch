# 🌙 NightWatch

**Network & Log Threat Analyzer** — Web sunucu loglarını analiz ederek güvenlik tehditlerini tespit eden Python CLI aracı.

```
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

[![Python](https://img.shields.io/badge/Python-3.7%2B-green?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)]()

---

## Nedir?

NightWatch, Nginx ve Apache web sunucularının access log dosyalarını okuyarak içlerindeki saldırı girişimlerini tespit eden bir komut satırı aracıdır. Sıfır harici bağımlılıkla çalışır — sadece Python 3.7+ yeterlidir.

Kendi sunucumun (`doruk.codes`) Nginx loglarını analiz etmek için geliştirdim.

---

## Özellikler

| Özellik | Açıklama |
|---------|----------|
| **10 Tehdit Kategorisi** | SQL Injection, XSS, Directory Traversal, LFI/RFI, Command Injection, Brute Force, Scanner/Bot, Admin Probe, Sensitive File Access, HTTP Method Abuse |
| **Çoklu Log Formatı** | Nginx/Apache Combined Log, Syslog, auth.log |
| **Risk Seviyeleri** | CRITICAL / HIGH / MEDIUM / LOW |
| **Brute-Force Tespiti** | IP başına başarısız istek sayımı |
| **Canlı İzleme** | `--live` ile log dosyasını gerçek zamanlı izle |
| **Rapor Üretimi** | JSON ve TXT formatında detaylı rapor |
| **Severity Filtresi** | Sadece istediğin seviyeyi göster |
| **Sıfır Bağımlılık** | Sadece Python standart kütüphanesi |

---

## Kurulum

```bash
git clone https://github.com/dorukcodes/nightwatch.git
cd nightwatch
python3 nightwatch.py --help
```

Başka bir şey gerekmez.

---

## Kullanım

### Temel Analiz

```bash
python3 nightwatch.py /var/log/nginx/access.log
```

### Sadece HIGH ve üzeri tehditleri göster

```bash
python3 nightwatch.py access.log --severity HIGH
```

### JSON rapor üret

```bash
python3 nightwatch.py access.log --report rapor.json
```

### TXT rapor üret

```bash
python3 nightwatch.py access.log --report rapor.txt --format txt
```

### Brute-force eşiğini ayarla (varsayılan: 20)

```bash
python3 nightwatch.py access.log --brute-threshold 10
```

### Canlı izleme modu

```bash
python3 nightwatch.py /var/log/nginx/access.log --live
```

### Sadece rapor üret, ekrana yazdırma

```bash
python3 nightwatch.py access.log --quiet --report rapor.json
```

### CI/CD Pipeline'da kullan (exit code 1 = tehdit var)

```bash
python3 nightwatch.py access.log --quiet && echo "Temiz" || echo "Tehdit tespit edildi!"
```

---

## Örnek Çıktı

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                               TARAMA SONUÇLARI                               │
└──────────────────────────────────────────────────────────────────────────────┘

  Dosya               /var/log/nginx/access.log
  Toplam Satır        24,831
  Toplam Tehdit       47
  CRITICAL            3
  HIGH                12
  MEDIUM              32
  LOW                 0
  Tarama Süresi       0.38s

  En Çok Görülen Tehditler:
  Admin Panel Probe         ██████████████████████████████ 30
  Scanner / Bot             ████████ 8
  SQL Injection             ████ 4
  Directory Traversal       ███ 3
  Brute Force               ██ 2

  En Şüpheli IP'ler:
  91.108.4.1          31 tespit
  185.220.101.1        5 tespit
```

---

## Tespit Edilen Tehditler

| Kategori | Örnekler |
|----------|----------|
| **SQL Injection** | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `sleep()`, `benchmark()` |
| **XSS** | `<script>`, `onerror=`, `javascript:`, `document.cookie` |
| **Directory Traversal** | `../../../etc/passwd`, `%2e%2e%2f`, `windows/system32` |
| **LFI / RFI** | `php://filter`, `file://`, `phar://`, `=http://evil.com` |
| **Command Injection** | `;cat /etc/passwd`, `\`whoami\``, `\| bash` |
| **Brute Force** | IP başına N+ başarısız istek (ayarlanabilir eşik) |
| **Scanner / Bot** | `sqlmap`, `nikto`, `nmap`, `masscan`, `nuclei`, `dirbuster` |
| **Admin Probe** | `wp-admin`, `phpmyadmin`, `/admin/`, `/cpanel` |
| **Sensitive Files** | `.env`, `.git/`, `config.php`, `id_rsa`, `.bash_history` |
| **HTTP Abuse** | `PUT`, `DELETE`, `TRACE`, `CONNECT` metodları |

---

## Desteklenen Log Formatları

**Nginx / Apache Combined Log Format:**
```
127.0.0.1 - - [21/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

**Syslog / auth.log:**
```
Apr 21 10:00:00 server sshd[1234]: Failed password for root from 1.2.3.4
```

---

## Tüm Seçenekler

```
kullanım: nightwatch.py [seçenekler] logfile

  logfile                    Analiz edilecek log dosyası

  --live,    -l              Canlı izleme modu
  --report,  -r DOSYA        Raporu kaydet (örn: rapor.json)
  --format,  -f {json,txt}   Rapor formatı (varsayılan: json)
  --severity,-s SEVİYE       Filtrele: LOW / MEDIUM / HIGH / CRITICAL
  --brute-threshold,-b N     Brute-force eşiği (varsayılan: 20)
  --limit    N               Ekranda gösterilecek max tehdit sayısı (varsayılan: 50)
  --quiet,   -q              Sessiz mod — sadece rapor üret
  --version, -v              Sürüm bilgisi
```

---

## Proje Yapısı

```
nightwatch/
├── nightwatch.py          # Ana araç
├── generate_test_log.py   # Test log üretici
└── README.md
```

---

## Lisans

MIT — Özgürce kullanabilir, değiştirebilir ve dağıtabilirsin.

---

<p align="center">
  <a href="https://doruk.codes">doruk.codes</a> •
  <a href="https://github.com/dorukcodes">github.com/dorukcodes</a>
</p>
