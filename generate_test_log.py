#!/usr/bin/env python3
"""Test log dosyası üretici."""

import random
import datetime

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/projects", "/skills", "/contact",
    "/style.css", "/app.js", "/favicon.ico", "/robots.txt",
    "/api/visit", "/api/whoami", "/socket.io/",
]

ATTACK_LINES = [
    # SQL Injection
    '185.220.101.1 - - [21/Apr/2026:10:01:01 +0000] "GET /search?q=1+union+select+1,2,3--+- HTTP/1.1" 400 512 "-" "sqlmap/1.7.8"',
    '185.220.101.2 - - [21/Apr/2026:10:01:05 +0000] "GET /page?id=1+OR+1=1-- HTTP/1.1" 403 0 "-" "Mozilla/5.0"',
    '185.220.101.3 - - [21/Apr/2026:10:01:10 +0000] "POST /login HTTP/1.1" 401 0 "-" "python-requests/2.28"',

    # XSS
    '92.63.194.2 - - [21/Apr/2026:10:02:01 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "Mozilla/5.0"',
    '92.63.194.3 - - [21/Apr/2026:10:02:05 +0000] "GET /?name=<img+onerror=alert(document.cookie)> HTTP/1.1" 400 0 "-" "curl/7.85.0"',

    # Directory Traversal
    '45.33.32.156 - - [21/Apr/2026:10:03:01 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 0 "-" "Nikto/2.1.6"',
    '45.33.32.157 - - [21/Apr/2026:10:03:05 +0000] "GET /files/../../windows/system32/drivers/etc/hosts HTTP/1.1" 403 0 "-" "Mozilla/5.0"',

    # Scanner
    '198.54.117.10 - - [21/Apr/2026:10:04:01 +0000] "GET /wp-admin/ HTTP/1.1" 404 0 "-" "masscan/1.3"',
    '198.54.117.11 - - [21/Apr/2026:10:04:02 +0000] "GET /.env HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
    '198.54.117.12 - - [21/Apr/2026:10:04:03 +0000] "GET /config.php HTTP/1.1" 404 0 "-" "zgrab/0.x"',
    '198.54.117.13 - - [21/Apr/2026:10:04:04 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"',

    # Command Injection
    '103.21.244.0 - - [21/Apr/2026:10:05:01 +0000] "GET /cmd?exec=;cat+/etc/passwd HTTP/1.1" 400 0 "-" "Mozilla/5.0"',

    # LFI
    '176.9.0.1 - - [21/Apr/2026:10:06:01 +0000] "GET /page?file=../../../etc/passwd HTTP/1.1" 400 0 "-" "Nikto/2.1.6"',
    '176.9.0.2 - - [21/Apr/2026:10:06:05 +0000] "GET /include?path=php://filter/read=convert.base64-encode/resource=index.php HTTP/1.1" 400 0 "-" "Mozilla/5.0"',

    # Admin probe
    '104.21.0.1 - - [21/Apr/2026:10:07:01 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
    '104.21.0.2 - - [21/Apr/2026:10:07:02 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
]

def generate():
    lines = []
    base = datetime.datetime(2026, 4, 21, 8, 0, 0)
    normal_ips = [f"78.135.{i}.{j}" for i in range(1, 5) for j in range(1, 6)]

    # Normal trafik
    for i in range(200):
        ip = random.choice(normal_ips)
        path = random.choice(NORMAL_PATHS)
        t = base + datetime.timedelta(seconds=i * 10)
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = random.choice([200, 200, 200, 304, 301])
        size = random.randint(512, 8192)
        lines.append(
            f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} '
            f'"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
        )

    # Brute force IP'si — aynı IP'den 30 404
    bf_ip = "91.108.4.1"
    for i in range(30):
        t = base + datetime.timedelta(seconds=i * 2)
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{bf_ip} - - [{ts}] "POST /api/admin/login HTTP/1.1" 401 0 '
            f'"-" "Mozilla/5.0"'
        )

    # Saldırı satırları
    lines.extend(ATTACK_LINES)

    random.shuffle(lines)
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    with open("test_access.log", "w") as f:
        f.write(generate())
    print("test_access.log oluşturuldu.")
