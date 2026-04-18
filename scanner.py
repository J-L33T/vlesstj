#!/usr/bin/env python3
"""
Агрегатор VLESS подписок для обхода белых списков РФ.
Собирает URI из публичных репо, проверяет работоспособность,
фильтрует по принадлежности к российским белым подсетям.
"""

import asyncio
import ipaddress
import re
import ssl
import random
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

# ─── Источники подписок ────────────────────────────────────────────────────────
SOURCES = [
    # zieng2
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    # igareck
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/mts.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/vless.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/configs.txt",
]

# ─── Известные белые подсети РФ операторов ────────────────────────────────────
# IP из этих подсетей с высокой вероятностью проходят белые списки МТС/Теле2
WHITE_SUBNETS = [
    # VK / Mail.ru
    "95.163.0.0/16", "87.240.0.0/16", "93.186.224.0/19",
    "185.30.176.0/22", "185.241.192.0/22", "46.8.16.0/20",
    "178.20.40.0/21", "217.69.128.0/19", "94.100.176.0/22",
    "89.208.224.0/19", "146.185.240.0/21",
    # Яндекс
    "178.154.128.0/17", "5.45.192.0/18", "213.180.192.0/19",
    "77.88.0.0/18", "87.250.224.0/19", "213.180.193.0/24",
    "95.108.0.0/16",
    # Ростелеком / Теле2
    "195.19.220.0/22", "213.248.96.0/19", "217.20.144.0/20",
    "85.30.128.0/19", "176.100.16.0/20",
    # Selectel
    "178.72.128.0/17", "46.4.0.0/16",
    # Timeweb
    "185.104.112.0/22", "194.58.96.0/19",
    # Aeza
    "83.166.232.0/21",
    # МТС собственные
    "80.66.64.0/19", "85.142.24.0/21",
    # Билайн / Вымпелком
    "213.234.0.0/16", "217.118.64.0/18",
]

# Скомпилируем сети один раз
_WHITE_NETS = [ipaddress.ip_network(s, strict=False) for s in WHITE_SUBNETS]

# ─── Настройки ─────────────────────────────────────────────────────────────────
CONNECT_TIMEOUT = 2.5
TLS_TIMEOUT     = 3.0
MAX_WORKERS     = 200
MAX_RESULTS     = 100  # итоговый размер подписки

# ─── Парсинг URI ───────────────────────────────────────────────────────────────
def parse_uri(uri: str) -> dict | None:
    """Парсит VLESS URI, возвращает dict с host/port или None."""
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    try:
        # vless://uuid@host:port?params#name
        without_scheme = uri[8:]
        at_idx = without_scheme.rfind("@")
        if at_idx == -1:
            return None
        hostport = without_scheme[at_idx+1:].split("?")[0].split("#")[0]
        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            return {"uri": uri, "host": host.strip("[]"), "port": int(port)}
    except Exception:
        pass
    return None

def is_in_white_subnet(host: str) -> bool:
    """Проверяет входит ли IP в известные белые подсети."""
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _WHITE_NETS)
    except ValueError:
        # hostname, не IP — пропускаем фильтр
        return True

def get_label(uri: str) -> str:
    """Извлекает метку из URI."""
    if "#" in uri:
        return unquote(uri.split("#", 1)[1])
    return "Unknown"

# ─── Загрузка источников ──────────────────────────────────────────────────────
def fetch_uris() -> list[dict]:
    all_uris = {}  # host:port -> dict (дедупликация)
    for url in SOURCES:
        try:
            print(f"[*] Загружаю {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode(errors="ignore")
            count = 0
            for line in text.splitlines():
                parsed = parse_uri(line)
                if parsed:
                    key = f"{parsed['host']}:{parsed['port']}"
                    if key not in all_uris:
                        all_uris[key] = parsed
                        count += 1
            print(f"    → {count} новых URI")
        except Exception as e:
            print(f"[!] Ошибка {url}: {e}")

    result = list(all_uris.values())
    print(f"[*] Всего уникальных URI: {len(result)}")
    return result

# ─── Проверка TCP + TLS ────────────────────────────────────────────────────────
async def check_server(server: dict, semaphore: asyncio.Semaphore) -> dict | None:
    host = server["host"]
    port = server["port"]

    async with semaphore:
        # TCP connect
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECT_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            return None

        # TLS handshake
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, tls_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=TLS_TIMEOUT
            )
            tls_writer.close()
            try:
                await tls_writer.wait_closed()
            except Exception:
                pass
            return server
        except Exception:
            return None

async def scan(servers: list[dict]) -> list[dict]:
    semaphore = asyncio.Semaphore(MAX_WORKERS)
    print(f"[*] Проверяю {len(servers)} серверов...")
    tasks = [check_server(s, semaphore) for s in servers]
    results = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        done += 1
        if result:
            results.append(result)
            label = get_label(result["uri"])[:40]
            print(f"[+] {result['host']}:{result['port']} — {label}")
    print(f"[*] Живых серверов: {len(results)} из {done}")
    return results

# ─── Фильтрация по белым подсетям ─────────────────────────────────────────────
def filter_white_subnets(servers: list[dict]) -> tuple[list[dict], list[dict]]:
    """Разделяет на белые (приоритет) и остальные."""
    white = []
    other = []
    for s in servers:
        if is_in_white_subnet(s["host"]):
            white.append(s)
        else:
            other.append(s)
    return white, other

# ─── Сборка подписки ──────────────────────────────────────────────────────────
def build_subscription(servers: list[dict], white_count: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Обновлено: {now}",
        f"# Серверов: {len(servers)} (из них ~{white_count} в белых подсетях РФ)",
        f"# Источники: zieng2/wl, igareck/vpn-configs-for-russia",
        "",
    ]
    for uri_data in servers:
        lines.append(uri_data["uri"])
    return "\n".join(lines) + "\n"

# ─── Основная логика ───────────────────────────────────────────────────────────
async def main():
    # 1. Собрать все URI из источников
    all_servers = fetch_uris()
    if not all_servers:
        print("[!] Не удалось загрузить ни одного URI")
        return

    # 2. Проверить живость TCP+TLS
    living = await scan(all_servers)
    if not living:
        print("[!] Нет живых серверов")
        return

    # 3. Разделить на белые подсети и остальные
    white, other = filter_white_subnets(living)
    print(f"[*] В белых подсетях РФ: {len(white)}, остальные: {len(other)}")

    # 4. Приоритет — белые подсети, потом остальные, итого MAX_RESULTS
    random.shuffle(white)
    random.shuffle(other)
    final = (white + other)[:MAX_RESULTS]

    print(f"[*] Итого в подписке: {len(final)}")

    # 5. Сохранить
    content = build_subscription(final, len(white))
    with open("vless.txt", "w") as f:
        f.write(content)
    print("[*] Сохранено в vless.txt")

if __name__ == "__main__":
    asyncio.run(main())
