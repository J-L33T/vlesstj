#!/usr/bin/env python3
"""
Агрегатор VLESS подписок — только белые подсети РФ (v3).

Что изменилось по сравнению с v2:
- Белые подсети берутся динамически из hxehex/russia-mobile-internet-whitelist
  (cidrwhitelist.txt) вместо захардкоженного списка — актуальнее и шире
- Новые источники конфигов: whoahaow/bypass, kort0881/ru-sni,
  rachikop/mobile_whitelist, LowiKLive/BypassWhitelistRu,
  Kirillo4ka/vpn-configs-for-russia, 55prosek-lgtm, STR97/STRUGOV
- Дедупликация по (uuid, host, port) — убираем полные дубли когда один
  сервер встречается с разными параметрами в названии
- Источники zieng2 и whoahaow/bypass НЕ проверяются TCP+TLS повторно —
  они уже верифицированы на реальных симках, берём как есть
- Остальные источники — TCP+TLS проверка как раньше
"""

import asyncio
import ipaddress
import socket
import ssl
import random
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse, parse_qs


# ─── Источники: верифицированные на мобилке (TCP-проверка пропускается) ───────
# Эти репы тестируют конфиги на реальных симках МТС/Теле2/Мегафон/Билайн
TRUSTED_SOURCES = [
    # zieng2 — специально для белых списков, тестируется на реальных симках
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",

    # whoahaow bypass — протестированы через Xray-core, отсортированы по пингу
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
]

# ─── Источники: обычные (проходят TCP+TLS проверку) ──────────────────────────
CHECKED_SOURCES = [
    # igareck — реальные проверки, обновляется каждые 1-2 часа
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/mts.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/vless.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/configs.txt",

    # whoahaow default (не bypass — обычные)
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/default/all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/default/all-secure.txt",

    # kort0881 — ru-sni специально для белых списков
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/ru-sni/vless_ru.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/russia-whitelist/main/vless.txt",

    # rachikop — обход белых списков мобильных операторов
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/main/vless.txt",
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/main/configs.txt",

    # LowiKLive — обход белых списков РФ
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/main/WhiteList-Bypass_Ru.txt",

    # Kirillo4ka — форк igareck с доп. серверами
    "https://raw.githubusercontent.com/Kirillo4ka/vpn-configs-for-russia/main/Vless-Rus-Mobile-White-List.txt",

    # 55prosek-lgtm
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/main/whitelist.txt",

    # STR97/STRUGOV
    "https://raw.githubusercontent.com/STR97/STRUGOV/main/STR.BYPASS",
    "https://raw.githubusercontent.com/STR97/STRUGOV/main/BYPASS",
]

# ─── Источник белых подсетей (динамический) ───────────────────────────────────
CIDR_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"

# Fallback если hxehex недоступен — минимальный захардкоженный список
FALLBACK_WHITE_SUBNETS = [
    # VK / Mail.ru
    "95.163.0.0/16", "87.240.0.0/16", "93.186.224.0/19",
    "185.30.176.0/22", "89.208.224.0/19", "94.100.176.0/22",
    # Яндекс
    "178.154.128.0/17", "5.45.192.0/18", "95.108.0.0/16",
    "77.88.0.0/18", "87.250.224.0/19",
    # Selectel
    "178.72.128.0/17",
    # Timeweb
    "185.104.112.0/22", "194.58.96.0/19", "92.53.96.0/19",
    # Aeza
    "83.166.232.0/21",
    # МТС
    "80.66.64.0/19", "85.142.24.0/21",
    # Билайн
    "213.234.0.0/16", "217.118.64.0/18",
    # Ростелеком / Теле2
    "195.19.220.0/22", "213.248.96.0/19",
    # DataLine
    "212.193.0.0/19",
]

# ─── Настройки ─────────────────────────────────────────────────────────────────
CONNECT_TIMEOUT = 5.0
TLS_TIMEOUT     = 6.0
MAX_WORKERS     = 100
TCP_RETRIES     = 3
RETRY_DELAY     = 0.5
LOG_INTERVAL    = 50

# ─── Глобальный список белых сетей (заполняется при запуске) ──────────────────
_WHITE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

# ─── DNS-кэш ──────────────────────────────────────────────────────────────────
_dns_cache: dict[str, str | None] = {}


def resolve_host(host: str) -> str | None:
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
        _dns_cache[host] = ip
        return ip
    except Exception:
        _dns_cache[host] = None
        return None


def load_white_subnets() -> None:
    """Загружает актуальные белые подсети из hxehex, fallback — захардкоженный список."""
    global _WHITE_NETS
    try:
        print(f"[*] Загружаю белые подсети из hxehex/russia-mobile-internet-whitelist...")
        req = urllib.request.Request(
            CIDR_WHITELIST_URL,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode(errors="ignore")

        nets = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass

        if nets:
            _WHITE_NETS = nets
            print(f"    → Загружено {len(nets)} подсетей")
        else:
            raise ValueError("Пустой список")

    except Exception as e:
        print(f"    [!] Не удалось загрузить подсети: {e}")
        print(f"    → Использую fallback список ({len(FALLBACK_WHITE_SUBNETS)} подсетей)")
        _WHITE_NETS = [
            ipaddress.ip_network(s, strict=False)
            for s in FALLBACK_WHITE_SUBNETS
        ]


def is_in_white_subnet(host: str) -> bool:
    """Проверяет, входит ли host в белые подсети. Резолвит домены."""
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _WHITE_NETS)
    except ValueError:
        resolved = resolve_host(host)
        if resolved is None:
            return False
        try:
            ip = ipaddress.ip_address(resolved)
            return any(ip in net for net in _WHITE_NETS)
        except Exception:
            return False


# ─── Парсинг URI ───────────────────────────────────────────────────────────────
def parse_uri(line: str) -> dict | None:
    """Парсит VLESS URI. Возвращает dict с uuid/host/port или None."""
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    try:
        without_scheme = line[8:]
        at_idx = without_scheme.rfind("@")
        if at_idx == -1:
            return None

        uuid = without_scheme[:at_idx]
        hostport_raw = without_scheme[at_idx + 1:].split("?")[0].split("#")[0]

        # IPv6: [::1]:port
        if hostport_raw.startswith("["):
            bracket_end = hostport_raw.index("]")
            host = hostport_raw[1:bracket_end]
            port = int(hostport_raw[bracket_end + 2:])
        else:
            host, port_str = hostport_raw.rsplit(":", 1)
            port = int(port_str)

        return {
            "uri": line,
            "uuid": uuid,
            "host": host,
            "port": port,
            # Ключ дедупликации: один и тот же сервер с разными именами — одна запись
            "dedup_key": f"{uuid}@{host}:{port}",
        }
    except Exception:
        return None


# ─── Загрузка источников ───────────────────────────────────────────────────────
def fetch_sources(urls: list[str], label: str) -> dict[str, dict]:
    """
    Загружает конфиги из списка URL.
    Возвращает dict[dedup_key -> parsed] только для серверов из белых подсетей.
    """
    seen: dict[str, dict] = {}
    for url in urls:
        short = f"{url.split('/')[4]}/{url.split('/')[-1]}"
        try:
            print(f"[*] [{label}] {short}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode(errors="ignore")
            count = 0
            for line in text.splitlines():
                parsed = parse_uri(line)
                if not parsed:
                    continue
                if parsed["dedup_key"] in seen:
                    continue
                if is_in_white_subnet(parsed["host"]):
                    seen[parsed["dedup_key"]] = parsed
                    count += 1
            print(f"    → +{count} белых (всего в пуле: {len(seen)})")
        except Exception as e:
            print(f"    [!] Ошибка {short}: {e}")
    return seen


# ─── Проверка TCP + TLS ────────────────────────────────────────────────────────
async def check_server(server: dict, semaphore: asyncio.Semaphore) -> dict | None:
    host, port = server["host"], server["port"]
    async with semaphore:
        # TCP — несколько попыток
        tcp_ok = False
        for attempt in range(TCP_RETRIES):
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=CONNECT_TIMEOUT
                )
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                tcp_ok = True
                break
            except Exception:
                if attempt < TCP_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY)

        if not tcp_ok:
            return None

        # TLS handshake
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=TLS_TIMEOUT
            )
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
    total = len(servers)
    print(f"[*] Проверяю {total} серверов (TCP×{TCP_RETRIES}+TLS, workers={MAX_WORKERS})...")
    tasks = [check_server(s, semaphore) for s in servers]
    results = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        done += 1
        if result:
            results.append(result)
            print(f"[+] {result['host']}:{result['port']}")
        if done % LOG_INTERVAL == 0:
            print(f"[~] Прогресс: {done}/{total} проверено, живых: {len(results)}")
    print(f"\n[*] Живых: {len(results)} из {done}")
    return results


# ─── Сборка подписки ──────────────────────────────────────────────────────────
def build_subscription(servers: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# profile-title: JL33T_WL",
        f"# Обновлено: {now}",
        f"# Серверов: {len(servers)} (только белые подсети РФ)",
        "# Источники: zieng2, igareck, whoahaow, kort0881, rachikop, LowiKLive, Kirillo4ka, STR97",
        "",
    ]
    for s in servers:
        uri = s["uri"]
        if "#" in uri:
            base, name = uri.rsplit("#", 1)
            uri = f"{base}#\U0001f1f7\U0001f1fa WL {unquote(name)}"
        else:
            uri = f"{uri}#\U0001f1f7\U0001f1fa WL"
        lines.append(uri)
    return "\n".join(lines) + "\n"


# ─── Main ─────────────────────────────────────────────────────────────────────
async def main():
    # 1. Загружаем актуальные белые подсети
    load_white_subnets()

    # 2. Доверенные источники — берём без TCP-проверки (уже верифицированы)
    print(f"\n[*] Загружаю ДОВЕРЕННЫЕ источники (без TCP-проверки)...")
    trusted = fetch_sources(TRUSTED_SOURCES, "TRUSTED")

    # 3. Обычные источники — собираем кандидатов для проверки
    print(f"\n[*] Загружаю обычные источники (пройдут TCP+TLS)...")
    checked_raw = fetch_sources(CHECKED_SOURCES, "CHECKED")

    # 4. Убираем из checked то что уже есть в trusted (дедупликация)
    new_in_checked = {
        k: v for k, v in checked_raw.items()
        if k not in trusted
    }
    print(f"\n[*] Уникальных для TCP-проверки: {len(new_in_checked)}")

    # 5. TCP+TLS проверка обычных источников
    if new_in_checked:
        living_checked = await scan(list(new_in_checked.values()))
    else:
        living_checked = []

    # 6. Объединяем: доверенные (все) + живые обычные
    all_living = list(trusted.values()) + living_checked

    # Финальная дедупликация на случай пересечений
    final_dedup: dict[str, dict] = {}
    for s in all_living:
        if s["dedup_key"] not in final_dedup:
            final_dedup[s["dedup_key"]] = s
    final = list(final_dedup.values())

    print(f"\n[*] Итого уникальных живых серверов: {len(final)}")
    print(f"    → из доверенных источников: {len([s for s in final if s['dedup_key'] in trusted])}")
    print(f"    → прошли TCP+TLS: {len(living_checked)}")

    if not final:
        print("[!] Нет живых серверов — оставляю старый vless.txt без изменений")
        return

    random.shuffle(final)

    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(build_subscription(final))

    print(f"\n[✓] vless.txt обновлён: {len(final)} серверов")


if __name__ == "__main__":
    asyncio.run(main())
