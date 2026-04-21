#!/usr/bin/env python3
"""
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝

NightWatch v1.0.0 — Network & Log Threat Analyzer
github.com/dorukcodes/nightwatch
"""

import re
import os
import sys
import json
import time
import argparse
import datetime
import ipaddress
import collections
from typing import List, Dict, Optional, Tuple

# ── ANSI Renkleri (sıfır bağımlılık) ─────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

def colored(text: str, color: str) -> str:
    """Windows/pipe uyumlu renk uygulama."""
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.RESET}"

def banner():
    print(colored("""
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
""", C.GREEN))
    print(colored("  NightWatch v1.0.0  —  Network & Log Threat Analyzer", C.CYAN))
    print(colored("  github.com/dorukcodes/nightwatch", C.DIM))
    print()

# ── Tehdit Kuralları ──────────────────────────────────────────────────────────
THREAT_RULES = [
    # (isim, regex, şiddet, açıklama)
    ("SQL Injection",
     r"(union.*select|select.*from|drop\s+table|insert\s+into|delete\s+from"
     r"|or\s+1\s*=\s*1|or\s+'[^']*'\s*=\s*'[^']*'|benchmark\s*\(|sleep\s*\("
     r"|information_schema|xp_cmdshell|waitfor\s+delay|cast\s*\(|convert\s*\()",
     "CRITICAL", "SQL Injection girişimi tespit edildi"),

    ("XSS",
     r"(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|alert\s*\("
     r"|document\.cookie|<iframe|<img[^>]+src\s*=\s*[\"']?javascript)",
     "HIGH", "Cross-Site Scripting (XSS) girişimi"),

    ("Directory Traversal",
     r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e|/etc/passwd"
     r"|/etc/shadow|/proc/self|/windows/system32|boot\.ini)",
     "HIGH", "Dizin geçiş saldırısı"),

    ("Command Injection",
     r"(;.*\bls\b|;.*\bcat\b|;.*\bwhoami\b|;.*\bpwd\b|\|.*bash"
     r"|\`[^`]+\`|\$\([^)]+\)|&&\s*\w+|%60|%7c.*cmd)",
     "CRITICAL", "Komut enjeksiyonu girişimi"),

    ("Brute Force",
     r"",  # Özel işlem — IP bazlı sayım
     "HIGH", "Brute-force saldırısı şüphesi"),

    ("Scanner / Bot",
     r"(sqlmap|nmap|masscan|nikto|dirbuster|gobuster|wfuzz|hydra|medusa"
     r"|zgrab|shodan|censys|nuclei|burpsuite|python-requests|go-http-client"
     r"|curl/[0-9]|wget/[0-9]|libwww-perl|scrapy)",
     "MEDIUM", "Bilinen tarayıcı/bot user-agent"),

    ("Sensitive File Access",
     r"(\.env|\.git/|config\.php|wp-config|database\.yml|settings\.py"
     r"|\.htaccess|web\.config|composer\.json|package\.json|Makefile"
     r"|\.bash_history|\.ssh/|id_rsa|authorized_keys|shadow|passwd)",
     "HIGH", "Hassas dosya erişim girişimi"),

    ("Admin Panel Probe",
     r"(wp-admin|wp-login|phpmyadmin|admin\.php|/admin/|/administrator"
     r"|/manager/|/console|/cpanel|/plesk|/webmin|/pma)",
     "MEDIUM", "Admin panel keşif girişimi"),

    ("HTTP Method Abuse",
     r"^(PUT|DELETE|TRACE|CONNECT|OPTIONS|PATCH)\s",
     "LOW", "Alışılmadık HTTP metodu"),

    ("LFI / RFI",
     r"(php://|file://|expect://|zip://|data://|phar://"
     r"|=http[s]?://|=ftp://|\?.*=.*\.php\?)",
     "CRITICAL", "Local/Remote File Inclusion girişimi"),
]

# ── Log Format'ları ───────────────────────────────────────────────────────────
# Combined Log Format: Nginx / Apache
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Syslog / auth.log formatı
SYSLOG_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+(?P<service>[^:]+):\s+(?P<message>.+)'
)

# ── Log Parser ────────────────────────────────────────────────────────────────
class LogEntry:
    __slots__ = ("ip", "timestamp", "method", "path", "status",
                 "size", "agent", "raw", "line_num")

    def __init__(self, ip="", timestamp="", method="", path="",
                 status=0, size=0, agent="", raw="", line_num=0):
        self.ip        = ip
        self.timestamp = timestamp
        self.method    = method
        self.path      = path
        self.status    = status
        self.size      = size
        self.agent     = agent
        self.raw       = raw
        self.line_num  = line_num


def parse_line(line: str, line_num: int) -> Optional[LogEntry]:
    """Satırı parse et. Combined veya syslog formatını dene."""
    m = COMBINED_LOG_RE.match(line)
    if m:
        try:
            size = int(m.group("size")) if m.group("size") != "-" else 0
        except ValueError:
            size = 0
        return LogEntry(
            ip        = m.group("ip"),
            timestamp = m.group("time"),
            method    = m.group("method") if m.group("method") else "",
            path      = m.group("path")   if m.group("path")   else "",
            status    = int(m.group("status")),
            size      = size,
            agent     = m.group("agent") or "",
            raw       = line.strip(),
            line_num  = line_num,
        )

    # Syslog formatı — message'ı path olarak kullan
    m2 = SYSLOG_RE.match(line)
    if m2:
        return LogEntry(
            ip        = "",
            timestamp = f"{m2.group('month')} {m2.group('day')} {m2.group('time')}",
            method    = "",
            path      = m2.group("message"),
            status    = 0,
            size      = 0,
            agent     = m2.group("service"),
            raw       = line.strip(),
            line_num  = line_num,
        )

    return None


# ── Tehdit Dedektörü ──────────────────────────────────────────────────────────
class ThreatDetection:
    __slots__ = ("entry", "threat_type", "severity", "description", "matched")

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def __init__(self, entry: LogEntry, threat_type: str,
                 severity: str, description: str, matched: str = ""):
        self.entry       = entry
        self.threat_type = threat_type
        self.severity    = severity
        self.description = description
        self.matched     = matched

    @property
    def score(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity, 0)


def detect_threats(entries: List[LogEntry],
                   brute_threshold: int = 20) -> List[ThreatDetection]:
    """Tüm tehditleri tespit et."""
    detections: List[ThreatDetection] = []
    compiled_rules = []

    for name, pattern, severity, desc in THREAT_RULES:
        if pattern:  # Boş pattern = özel işlem (brute force)
            compiled_rules.append((name, re.compile(pattern, re.IGNORECASE), severity, desc))

    # Kural bazlı tarama
    for entry in entries:
        target = (entry.path + " " + entry.agent).lower()
        for name, rx, severity, desc in compiled_rules:
            m = rx.search(target)
            if m:
                detections.append(ThreatDetection(
                    entry, name, severity, desc,
                    matched=m.group(0)[:60]
                ))
                break  # Satır başına tek tespit (en yüksek öncelikli kural zaten üstte)

    # Brute-force tespiti — IP başına 4xx sayısı
    ip_404: Dict[str, List[LogEntry]] = collections.defaultdict(list)
    for entry in entries:
        if entry.status in (401, 403, 404, 429) and entry.ip:
            ip_404[entry.ip].append(entry)

    for ip, hits in ip_404.items():
        if len(hits) >= brute_threshold:
            # En son hit'i temsili olarak kullan
            detections.append(ThreatDetection(
                hits[-1], "Brute Force", "HIGH",
                f"IP başına {len(hits)} başarısız istek ({brute_threshold}+ eşik)",
                matched=f"{len(hits)} istek"
            ))

    # Skora göre sırala
    detections.sort(key=lambda d: d.score, reverse=True)
    return detections


# ── Çıktı / Görselleştirme ────────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.CYAN,
}

SEV_ICON = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}


def print_separator(char="─", width=80, color=C.DIM):
    print(colored(char * width, color))


def print_header(title: str):
    w = 80
    print()
    print(colored("┌" + "─" * (w - 2) + "┐", C.GREEN))
    pad = (w - 2 - len(title)) // 2
    print(colored("│" + " " * pad + title + " " * (w - 2 - pad - len(title)) + "│", C.GREEN + C.BOLD))
    print(colored("└" + "─" * (w - 2) + "┘", C.GREEN))
    print()


def print_summary(entries: List[LogEntry], detections: List[ThreatDetection],
                  filename: str, elapsed: float):
    print_header("TARAMA SONUÇLARI")

    sev_counts = collections.Counter(d.severity for d in detections)
    threat_counts = collections.Counter(d.threat_type for d in detections)
    ip_counts = collections.Counter(d.entry.ip for d in detections if d.entry.ip)

    rows = [
        ("Dosya",              filename),
        ("Toplam Satır",       f"{len(entries):,}"),
        ("Toplam Tehdit",      colored(str(len(detections)), C.RED if detections else C.GREEN)),
        ("CRITICAL",           colored(str(sev_counts.get("CRITICAL", 0)), SEV_COLOR["CRITICAL"])),
        ("HIGH",               colored(str(sev_counts.get("HIGH", 0)),     SEV_COLOR["HIGH"])),
        ("MEDIUM",             colored(str(sev_counts.get("MEDIUM", 0)),   SEV_COLOR["MEDIUM"])),
        ("LOW",                colored(str(sev_counts.get("LOW", 0)),       SEV_COLOR["LOW"])),
        ("Tarama Süresi",      f"{elapsed:.2f}s"),
    ]

    for label, value in rows:
        print(f"  {colored(label.ljust(18), C.CYAN)}  {value}")

    if threat_counts:
        print()
        print(colored("  En Çok Görülen Tehditler:", C.BOLD))
        for threat, count in threat_counts.most_common(5):
            bar = "█" * min(count, 30)
            print(f"  {threat.ljust(25)} {colored(bar, C.RED)} {count}")

    if ip_counts:
        print()
        print(colored("  En Şüpheli IP'ler:", C.BOLD))
        for ip, count in ip_counts.most_common(5):
            print(f"  {colored(ip.ljust(18), C.YELLOW)}  {count} tespit")

    print()


def print_detections(detections: List[ThreatDetection], limit: int = 50):
    if not detections:
        print(colored("  ✓ Tehdit tespit edilmedi.", C.GREEN + C.BOLD))
        return

    print_header(f"TESPİT EDİLEN TEHDİTLER  ({len(detections)} adet)")

    shown = detections[:limit]
    for i, d in enumerate(shown, 1):
        sev_col = SEV_COLOR.get(d.severity, C.WHITE)
        icon    = SEV_ICON.get(d.severity, "•")

        print(f"  {colored(str(i).rjust(4), C.DIM)}  "
              f"{icon} {colored(d.severity.ljust(8), sev_col)}  "
              f"{colored(d.threat_type.ljust(22), C.BOLD)}  "
              f"{colored(d.entry.ip.ljust(16) if d.entry.ip else '?'.ljust(16), C.YELLOW)}"
              f"  Satır {d.entry.line_num}")

        print(f"        {colored('Yol:', C.DIM)} {d.entry.path[:70]}")
        if d.entry.agent:
            print(f"        {colored('UA: ', C.DIM)} {d.entry.agent[:70]}")
        if d.matched:
            print(f"        {colored('Eşleşme:', C.DIM)} {colored(d.matched, C.RED)}")
        print(f"        {colored('Açıklama:', C.DIM)} {d.description}")
        print_separator(width=80)

    if len(detections) > limit:
        print(colored(f"\n  ... ve {len(detections) - limit} tehdit daha (--limit ile artırılabilir)\n", C.DIM))


# ── Rapor Yazıcı ──────────────────────────────────────────────────────────────
def write_report(detections: List[ThreatDetection], entries: List[LogEntry],
                 output_path: str, fmt: str = "json"):
    """JSON veya TXT rapor yaz."""
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "tool":         "NightWatch v1.0.0",
        "total_lines":  len(entries),
        "total_threats": len(detections),
        "detections": [
            {
                "line":        d.entry.line_num,
                "ip":          d.entry.ip,
                "timestamp":   d.entry.timestamp,
                "path":        d.entry.path,
                "user_agent":  d.entry.agent,
                "status":      d.entry.status,
                "threat_type": d.threat_type,
                "severity":    d.severity,
                "description": d.description,
                "matched":     d.matched,
            }
            for d in detections
        ]
    }

    if fmt == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"NightWatch Report — {data['generated_at']}\n")
            f.write("=" * 80 + "\n")
            f.write(f"Toplam Satır  : {len(entries)}\n")
            f.write(f"Toplam Tehdit : {len(detections)}\n\n")
            for d in detections:
                f.write(f"[{d.severity}] {d.threat_type}\n")
                f.write(f"  IP       : {d.entry.ip}\n")
                f.write(f"  Satır    : {d.entry.line_num}\n")
                f.write(f"  Yol      : {d.entry.path}\n")
                f.write(f"  Zaman    : {d.entry.timestamp}\n")
                f.write(f"  Açıklama : {d.description}\n")
                if d.matched:
                    f.write(f"  Eşleşme  : {d.matched}\n")
                f.write("-" * 60 + "\n")

    print(colored(f"\n  ✓ Rapor kaydedildi: {output_path}", C.GREEN))


# ── Canlı İzleme Modu ─────────────────────────────────────────────────────────
def live_mode(filepath: str, brute_threshold: int):
    """Dosyayı canlı izle, yeni satırları analiz et."""
    print(colored(f"\n  [*] Canlı izleme başlatıldı: {filepath}", C.CYAN))
    print(colored("  [*] Çıkmak için CTRL+C\n", C.DIM))
    print_separator()

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # Dosya sonuna git
            line_num = 0
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                line_num += 1
                entry = parse_line(line, line_num)
                if not entry:
                    continue

                # Sadece bu satırı tara
                single = [entry]
                threats = detect_threats(single, brute_threshold)
                if threats:
                    for d in threats:
                        sev_col = SEV_COLOR.get(d.severity, C.WHITE)
                        icon    = SEV_ICON.get(d.severity, "•")
                        ts      = datetime.datetime.now().strftime("%H:%M:%S")
                        print(f"  {colored(ts, C.DIM)}  "
                              f"{icon} {colored(d.severity.ljust(8), sev_col)}  "
                              f"{colored(d.threat_type.ljust(22), C.BOLD)}  "
                              f"{colored(d.entry.ip.ljust(16), C.YELLOW)}  "
                              f"{d.entry.path[:40]}")
    except KeyboardInterrupt:
        print(colored("\n\n  [*] Canlı izleme durduruldu.", C.CYAN))
    except FileNotFoundError:
        print(colored(f"\n  [!] Dosya bulunamadı: {filepath}", C.RED))
        sys.exit(1)


# ── Ana Tarama Akışı ──────────────────────────────────────────────────────────
def analyze(filepath: str, brute_threshold: int,
            report: Optional[str], report_fmt: str,
            limit: int, only_severity: Optional[str],
            quiet: bool):

    if not os.path.isfile(filepath):
        print(colored(f"\n  [!] Dosya bulunamadı: {filepath}", C.RED))
        sys.exit(1)

    if not quiet:
        print(colored(f"  [*] Dosya okunuyor: {filepath}", C.CYAN))

    start = time.time()
    entries: List[LogEntry] = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            entry = parse_line(line, i)
            if entry:
                entries.append(entry)

    if not entries:
        print(colored("  [!] Hiç parse edilebilir satır bulunamadı.", C.YELLOW))
        print(colored("  [?] Desteklenen formatlar: Nginx/Apache Combined Log, Syslog/auth.log", C.DIM))
        sys.exit(0)

    detections = detect_threats(entries, brute_threshold)

    # Filtre uygula
    if only_severity:
        sev_upper = only_severity.upper()
        order = ThreatDetection.SEVERITY_ORDER
        min_score = order.get(sev_upper, 0)
        detections = [d for d in detections if d.score >= min_score]

    elapsed = time.time() - start

    if not quiet:
        print_summary(entries, detections, filepath, elapsed)
        print_detections(detections, limit=limit)

    if report:
        write_report(detections, entries, report, report_fmt)

    # Exit code: tespitler varsa 1
    sys.exit(1 if detections else 0)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="nightwatch",
        description="NightWatch — Network & Log Threat Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python3 nightwatch.py access.log
  python3 nightwatch.py access.log --report rapor.json
  python3 nightwatch.py access.log --report rapor.txt --format txt
  python3 nightwatch.py access.log --severity HIGH
  python3 nightwatch.py access.log --live
  python3 nightwatch.py access.log --brute-threshold 10 --limit 100
        """
    )

    parser.add_argument("logfile",
        nargs="?",
        help="Analiz edilecek log dosyasının yolu")

    parser.add_argument("--live", "-l",
        action="store_true",
        help="Canlı izleme modu (dosyayı sürekli oku)")

    parser.add_argument("--report", "-r",
        metavar="DOSYA",
        help="Raporu kaydet (örn: rapor.json veya rapor.txt)")

    parser.add_argument("--format", "-f",
        choices=["json", "txt"],
        default="json",
        dest="report_fmt",
        help="Rapor formatı (varsayılan: json)")

    parser.add_argument("--severity", "-s",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        metavar="SEVİYE",
        help="Sadece bu seviye ve üzerini göster")

    parser.add_argument("--brute-threshold", "-b",
        type=int,
        default=20,
        metavar="N",
        help="Brute-force eşiği — IP başına kaç istek (varsayılan: 20)")

    parser.add_argument("--limit",
        type=int,
        default=50,
        metavar="N",
        help="Ekranda gösterilecek maksimum tehdit sayısı (varsayılan: 50)")

    parser.add_argument("--quiet", "-q",
        action="store_true",
        help="Sadece rapor üret, ekrana yazdırma")

    parser.add_argument("--version", "-v",
        action="version",
        version="NightWatch 1.0.0")

    args = parser.parse_args()

    if not args.quiet:
        banner()

    if not args.logfile:
        parser.print_help()
        sys.exit(0)

    if args.live:
        live_mode(args.logfile, args.brute_threshold)
    else:
        analyze(
            filepath         = args.logfile,
            brute_threshold  = args.brute_threshold,
            report           = args.report,
            report_fmt       = args.report_fmt,
            limit            = args.limit,
            only_severity    = args.severity,
            quiet            = args.quiet,
        )


if __name__ == "__main__":
    main()
