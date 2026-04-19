#!/usr/bin/env python3
"""
Агрегатор VLESS подписок — только белые подсети РФ.
Собирает URI из публичных репо, проверяет TCP+TLS,
сохраняет ТОЛЬКО серверы из белых подсетей РФ.
"""

import asyncio
import ipaddress
import ssl
import random
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote

# ─── Источники подписок ────────────────────────────────────────────────────────
SOURCES = [
        # zieng2 — специально для белых списков МТС/Теле2
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
        "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",

        # igareck — CIDR подписки для белых списков мобильного интернета РФ
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/mts.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/vless.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/configs.txt",

        # whoahaow — верифицированные конфиги с сортировкой по пингу
        "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/all.txt",
        "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/all-secure.txt",

        # kort0881 — большая коллекция для России
        "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vpn-files/all_posts.txt",
        "https://raw.githubusercontent.com/kort0881/russia-whitelist/main/vless.txt",
]

# ─── Известные белые подсети РФ ───────────────────────────────────────────────
WHITE_SUBNETS = [
        # VK / Mail.ru
    "95.163.0.0/16", "87.240.0.0/16", "93.186.224.0/19",
        "185.30.176.0/22", "185.241.192.0/22", "46.8.16.0/20",
        "178.20.40.0/21", "217.69.128.0/19", "94.100.176.0/22",
        "89.208.224.0/19", "146.185.240.0/21", "213.219.212.0/22",
        # Яндекс
        "178.154.128.0/17", "5.45.192.0/18", "213.180.192.0/19",
        "77.88.0.0/18", "87.250.224.0/19", "95.108.0.0/16",
        # Ростелеком / Теле2
        "195.19.220.0/22", "213.248.96.0/19", "217.20.144.0/20",
        "85.30.128.0/19", "176.100.16.0/20", "46.242.16.0/20",
        # Selectel
        "178.72.128.0/17", "185.88.144.0/21",
        # Timeweb
        "185.104.112.0/22", "194.58.96.0/19", "92.53.96.0/19",
        # Aeza
        "83.166.232.0/21",
        # МТС
        "80.66.64.0/19", "85.142.24.0/21",
        # Билайн
        "213.234.0.0/16", "217.118.64.0/18",
        # DataLine / крупные RU ЦОД
        "212.193.0.0/19", "91.213.160.0/21",
]

_WHITE_NETS = [ipaddress.ip_network(s, strict=False) for s in WHITE_SUBNETS]

# ─── Настройки ─────────────────────────────────────────────────────────────────
CONNECT_TIMEOUT = 2.5
TLS_TIMEOUT     = 3.0
MAX_WORKERS     = 300

# ─── Парсинг URI ───────────────────────────────────────────────────────────────
def parse_uri(line: str) -> dict | None:
        line = line.strip()
        if not line.startswith("vless://"):
                    return None
                try:
                            without_scheme = line[8:]
                            at_idx = without_scheme.rfind("@")
                            if at_idx == -1:
                                            return None
                                        hostport = without_scheme[at_idx+1:].split("?")[0].split("#")[0]
        if ":" in hostport:
                        host, port = hostport.rsplit(":", 1)
            return {"uri": line, "host": host.strip("[]"), "port": int(port)}
except Exception:
        pass
    return None

def is_in_white_subnet(host: str) -> bool:
        try:
                    ip = ipaddress.ip_address(host)
                    return any(ip in net for net in _WHITE_NETS)
except ValueError:
            return False  # hostname — не считаем белым

# ─── Загрузка источников — только белые IP ────────────────────────────────────
def fetch_white_uris() -> list[dict]:
        seen = {}
        for url in SOURCES:
                    try:
                                    print(f"[*] {url.split('/')[-1]} ({url.split('/')[4]})")
                                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                                    with urllib.request.urlopen(req, timeout=15) as r:
                                                        text = r.read().decode(errors="ignore")
                                                    count = 0
                                    for line in text.splitlines():
                                                        parsed = parse_uri(line)
                                                        if parsed and is_in_white_subnet(parsed["host"]):
                                                                                key = f"{parsed['host']}:{parsed['port']}"
                                                                                if key not in seen:
                                                                                                            seen[key] = parsed
                                                                                                            count += 1
                                                                                                print(f"  → +{count} белых (всего: {len(seen)})")
                    except Exception as e:
                                    print(f"  [!] Ошибка: {e}")

                result = list(seen.values())
        print(f"\n[*] Уникальных белых URI для проверки: {len(result)}")
        return result

    # ─── Проверка TCP + TLS ────────────────────────────────────────────────────────
    async def check_server(server: dict, semaphore: asyncio.Semaphore) -> dict | None:
            host, port = server["host"], server["port"]
            async with semaphore:
                        try:
                                        _, w = await asyncio.wait_for(
                                                            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
                                        w.close()
                                        try:
                                                            await w.wait_closed()
                        except Exception:
                                            pass
except Exception:
            return None
        try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        _, w = await asyncio.wait_for(
                            asyncio.open_connection(host, port, ssl=ctx), timeout=TLS_TIMEOUT)
                        w.close()
                        try:
                                            await w.wait_closed()
        except Exception:
                            pass
                        return server
except Exception:
            return None

async def scan(servers: list[dict]) -> list[dict]:
        semaphore = asyncio.Semaphore(MAX_WORKERS)
        print(f"[*] Проверяю {len(servers)} белых серверов (TCP+TLS)...")
        tasks = [check_server(s, semaphore) for s in servers]
        results = []
        done = 0
        for coro in asyncio.as_completed(tasks):
                    result = await coro
                    done += 1
                    if result:
                                    results.append(result)
                                    print(f"[+] {result['host']}:{result['port']}")
                            print(f"\n[*] Живых белых: {len(results)} из {done}")
                return results

# ─── Сборка подписки ──────────────────────────────────────────────────────────
async def main():
        candidates = fetch_white_uris()
    if not candidates:
                print("[!] Нет белых URI для проверки")
                return

    living = await scan(candidates)
    if not living:
                print("[!] Нет живых белых серверов")
                return

    random.shuffle(living)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
                f"# profile-title: JL33T_WL",
                f"# Обновлено: {now}",
                f"# Серверов: {len(living)} (только белые подсети РФ)",
                f"# Источники: zieng2, igareck, whoahaow, kort0881",
                "",
    ]
    for s in living:
                uri = s["uri"]
                if "#" in uri:
                                base, name = uri.rsplit("#", 1)
                                uri = f"{base}#\U0001f1f7\U0001f1fa WL {unquote(name)}"
else:
            uri = f"{uri}#\U0001f1f7\U0001f1fa WL"
            lines.append(uri)

    with open("vless.txt", "w") as f:
                f.write("\n".join(lines) + "\n")
            print(f"[*] Сохранено {len(living)} белых серверов в vless.txt")

if __name__ == "__main__":
        asyncio.run(main())
