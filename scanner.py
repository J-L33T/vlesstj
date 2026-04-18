#!/usr/bin/env python3
"""
Сканер белых подсетей для генерации VLESS подписки.
Берёт IP из antifilter.download, проверяет доступность на 443,
генерирует VLESS URI с параметрами Reality.
"""

import asyncio
import ipaddress
import os
import random
import socket
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote

# ─── Параметры твоего VLESS сервера ───────────────────────────────────────────
UUID    = os.environ.get("VLESS_UUID",   "cf3aa741-4d0e-4734-a249-ae432b4b5394")
PBK     = os.environ.get("VLESS_PBK",    "NRXWQpf05kTAHMAE3jrXx8ZuU5UekAWLXUrO5cC5Fkk")
SID     = os.environ.get("VLESS_SID",    "754ee3270a95c89a")
SNI     = os.environ.get("VLESS_SNI",    "www.tesla.com")
FP      = os.environ.get("VLESS_FP",     "firefox")
PORT    = int(os.environ.get("VLESS_PORT", "443"))

# ─── Настройки сканирования ────────────────────────────────────────────────────
CONNECT_TIMEOUT   = 2.0    # секунд на TCP connect
MAX_WORKERS       = 300    # параллельных проверок
MAX_IPS_PER_NET   = 5      # IP из каждой подсети
MAX_RESULTS       = 150    # максимум в итоговом файле

# Источники подсетей (antifilter.download)
SUBNET_SOURCES = [
    "https://antifilter.download/list/subnet.lst",
    "https://antifilter.download/list/allyouneed.lst",
]

# ─── Генерация URI ─────────────────────────────────────────────────────────────
def make_uri(ip: str, index: int, tag: str = "WL") -> str:
    name = quote(f"{tag} — #{index}")
    return (
        f"vless://{UUID}@{ip}:{PORT}"
        f"?type=tcp&encryption=none&security=reality"
        f"&pbk={PBK}&fp={FP}&sni={SNI}&sid={SID}"
        f"&spx=%2F&flow=xtls-rprx-vision"
        f"#{name}"
    )

# ─── Загрузка подсетей ─────────────────────────────────────────────────────────
def fetch_subnets() -> list[str]:
    subnets = set()
    for url in SUBNET_SOURCES:
        try:
            print(f"[*] Загружаю {url}")
            with urllib.request.urlopen(url, timeout=15) as r:
                for line in r.read().decode().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            ipaddress.ip_network(line, strict=False)
                            subnets.add(line)
                        except ValueError:
                            pass
        except Exception as e:
            print(f"[!] Ошибка загрузки {url}: {e}")
    print(f"[*] Загружено подсетей: {len(subnets)}")
    return list(subnets)

# ─── Выбор IP из подсетей ──────────────────────────────────────────────────────
def sample_ips(subnets: list[str], per_net: int) -> list[str]:
    ips = []
    for cidr in subnets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if not hosts:
                continue
            sample = random.sample(hosts, min(per_net, len(hosts)))
            ips.extend(str(ip) for ip in sample)
        except Exception:
            pass
    random.shuffle(ips)
    return ips

# ─── Асинхронная TCP проверка ──────────────────────────────────────────────────
async def check_ip(ip: str, semaphore: asyncio.Semaphore) -> str | None:
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, PORT),
                timeout=CONNECT_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ip
        except Exception:
            return None

async def scan(ips: list[str]) -> list[str]:
    semaphore = asyncio.Semaphore(MAX_WORKERS)
    print(f"[*] Сканирую {len(ips)} IP на порту {PORT}...")
    tasks = [check_ip(ip, semaphore) for ip in ips]
    results = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        done += 1
        if result:
            results.append(result)
            print(f"[+] {result}  (найдено: {len(results)}, проверено: {done}/{len(ips)})")
        if len(results) >= MAX_RESULTS:
            break
    return results

# ─── Основная логика ───────────────────────────────────────────────────────────
def build_subscription(working_ips: list[str]) -> str:
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"# Обновлено: {now}")
    lines.append(f"# Серверов: {len(working_ips)}")
    lines.append("")
    for i, ip in enumerate(working_ips, 1):
        lines.append(make_uri(ip, i))
    return "\n".join(lines) + "\n"

async def main():
    subnets = fetch_subnets()
    if not subnets:
        print("[!] Не удалось загрузить подсети, выход")
        return

    ips = sample_ips(subnets, MAX_IPS_PER_NET)
    print(f"[*] Отобрано IP для проверки: {len(ips)}")

    working = await scan(ips)
    print(f"\n[*] Рабочих IP: {len(working)}")

    content = build_subscription(working)
    with open("vless.txt", "w") as f:
        f.write(content)
    print(f"[*] Сохранено в vless.txt")

if __name__ == "__main__":
    asyncio.run(main())
