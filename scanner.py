#!/usr/bin/env python3
"""
Агрегатор VLESS подписок — белые подсети РФ (v6).

Фильтрация:
- Только Reality (security=reality)
- IP сервера из белых подсетей проверенных хостеров (по ASN через RIPE API)
- SNI оканчивается на .ru ИЛИ есть в hxehex/whitelist.txt
- Лимит 100, приоритет: zieng2 → whoahaow/bypass → остальные
- Дедупликация по (uuid, host, port)

Логика CIDR:
  Тянем актуальные префиксы конкретных ASN через RIPE stat API.
  Это точнее чем список hxehex который резал рабочие серверы.
  Если RIPE недоступен — fallback на захардкоженные подсети.
"""

import asyncio
import ipaddress
import json
import random
import socket
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote, parse_qs


# ─── ASN хостеров чьи серверы реально проходят через МТС/Теле2 ───────────────
# Проверено на реальных тестах: Selectel, Яндекс, Hetzner проходят
TARGET_ASNS = {
    "AS49505":  "Selectel",
    "AS200350": "Яндекс Облако",
    "AS13238":  "Яндекс",
    "AS24940":  "Hetzner",
    "AS47764":  "VK / Mail.ru",
    "AS286":    "KPN (Hetzner upstream)",
    "AS9002":   "RETN",
    "AS31213":  "МТС",
    "AS8359":   "МТС",
    "AS25513":  "МТС",
    "AS3216":   "Билайн / Вымпелком",
    "AS8402":   "Corbina / Вымпелком",
    "AS15640":  "Selectel доп.",
    "AS44724":  "Selectel доп.",
    "AS197695": "Reg.ru",
    "AS205018": "Aeza",
    "AS9123":   "TimeWeb",
    "AS210226": "TimeWeb доп.",
    "AS57629":  "Serverius (Hetzner-like)",
    "AS60280":  "Aeza доп.",
    # Добавлено по результатам диагностики Cymru (топ срезанных РУ ASN)
    "AS210656": "YACLOUDBMS (RU)",        # 12 срезанных — крупнейший
    "AS198610": "Beget (RU)",             # 4 срезанных
    "AS216246": "Aeza RU-AEZA-AS",       # 4 срезанных
    "AS208677": "Cloud.ru / Сбер (RU)",   # 3 срезанных
    "AS12389":  "Ростелеком",
    "AS34584":  "Ростелеком доп.",
    "AS201153": "Oblako (RU)",
    "AS48282":  "NordNet (RU)",
}

# Fallback подсети если RIPE API недоступен
FALLBACK_CIDRS = [
    # Selectel
    "46.17.40.0/21", "46.17.48.0/20", "62.109.0.0/18",
    "78.108.80.0/20", "80.87.192.0/19", "92.53.96.0/19",
    "95.213.128.0/19", "176.99.0.0/18", "178.72.128.0/17",
    "185.8.176.0/22", "185.22.152.0/22", "185.68.16.0/22",
    "185.104.112.0/22", "188.225.80.0/20", "194.87.0.0/18",
    "212.224.64.0/18", "213.183.32.0/19",
    # Яндекс / Яндекс Облако
    "5.45.192.0/18", "37.9.64.0/18", "77.88.0.0/18",
    "84.201.128.0/17", "87.250.224.0/19", "93.158.128.0/18",
    "95.108.0.0/16", "130.193.32.0/19", "141.8.128.0/18",
    "146.185.240.0/21", "178.154.128.0/17", "213.180.192.0/19",
    "51.250.0.0/16", "158.160.0.0/16",
    # VK / Mail.ru
    "5.61.16.0/20", "5.188.32.0/21", "5.188.40.0/21",
    "79.174.64.0/19", "87.240.128.0/18", "89.208.192.0/19",
    "90.156.192.0/18", "93.186.224.0/19", "95.163.0.0/16",
    "185.30.176.0/22", "194.58.96.0/19",
    # Hetzner (проходит через МТС!)
    "5.9.0.0/16", "5.75.128.0/17", "23.88.0.0/17",
    "37.27.0.0/16", "65.21.0.0/17", "78.46.0.0/15",
    "85.10.192.0/18", "88.99.0.0/17", "88.198.0.0/16",
    "91.107.128.0/17", "94.130.0.0/16", "95.216.0.0/16",
    "116.202.0.0/15", "128.140.0.0/17", "135.181.0.0/16",
    "136.243.0.0/16", "138.201.0.0/16", "142.132.128.0/17",
    "144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16",
    "159.69.0.0/17", "162.55.0.0/16", "167.235.0.0/16",
    "168.119.0.0/16", "176.9.0.0/17", "178.63.0.0/17",
    "188.34.128.0/17", "193.25.8.0/22", "195.201.0.0/16",
    "213.133.96.0/19",
    # МТС / Билайн
    "80.66.64.0/19", "85.142.24.0/21", "213.234.0.0/16",
    "217.118.64.0/18", "195.19.220.0/22", "213.248.96.0/19",
    # Aeza
    "83.166.232.0/21",
    # TimeWeb
    "185.104.112.0/22", "194.58.96.0/19", "92.53.96.0/19",
    # Reg.ru
    "46.4.0.0/16",
]

# ─── Источники конфигов ───────────────────────────────────────────────────────
PRIORITY_1 = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
]

PRIORITY_2 = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/BYPASS",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/Vless",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/CUSTOM",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/Kirillo4ka/vpn-configs-for-russia/refs/heads/main/Vless-Rus-Mobile-White-List.txt",
    "https://raw.githubusercontent.com/liMilCo/v2r/refs/heads/main/all_configs.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/refs/heads/main/vless.txt",
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/refs/heads/main/subscription.txt",
]

LIMIT = 100
P1_LIMIT = 100  # P1 занимает все слоты — только верифицированные источники

# ─── TCP-проверка (только для P1 — они верифицированы на симках но протухают) ─
CONNECT_TIMEOUT = 4.0
MAX_WORKERS     = 80


async def _tcp_check(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    async with semaphore:
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
            return True
        except Exception:
            return False


async def tcp_filter(servers: list[dict]) -> list[dict]:
    """Оставляет только серверы которые отвечают на TCP connect."""
    if not servers:
        return []
    semaphore = asyncio.Semaphore(MAX_WORKERS)
    print(f"[*] TCP-проверка {len(servers)} серверов из P1 (timeout={CONNECT_TIMEOUT}s)...")
    tasks = [_tcp_check(s["host"], s["port"], semaphore) for s in servers]
    results = await asyncio.gather(*tasks)
    alive = [s for s, ok in zip(servers, results) if ok]
    print(f"    → живых: {len(alive)} из {len(servers)}")
    return alive

# ─── Белые домены SNI ─────────────────────────────────────────────────────────
DOMAIN_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"

FALLBACK_DOMAINS = {
    "yandex.ru", "ya.ru", "vk.com", "mail.ru", "ok.ru",
    "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru",
    "sberbank.ru", "gosuslugi.ru", "x5.ru", "wildberries.ru",
    "ozon.ru", "avito.ru", "hh.ru", "max.ru", "vk.ru",
    "selectel.ru", "reg.ru", "timeweb.com",
}

# ─── Глобальные структуры ─────────────────────────────────────────────────────
_WHITE_NETS: list = []
_WHITE_DOMAINS: set = set()
_dns_cache: dict = {}


def _fetch_text(url: str, timeout: int = 15) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode(errors="ignore")
    except Exception as e:
        print(f"    [!] {url.split('/')[-1]}: {e}")
        return None


def _fetch_json(url: str, timeout: int = 15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"    [!] {url}: {e}")
        return None


def load_asn_prefixes() -> list:
    """Загружает IPv4 префиксы для целевых ASN через RIPE stat API."""
    prefixes = []
    for asn, name in TARGET_ASNS.items():
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        data = _fetch_json(url, timeout=20)
        if data:
            asn_prefixes = [
                p["prefix"] for p in data.get("data", {}).get("prefixes", [])
                if ":" not in p["prefix"]  # только IPv4
            ]
            prefixes.extend(asn_prefixes)
            print(f"    {asn} ({name}): {len(asn_prefixes)} префиксов")
        else:
            # Пробуем bgpview как второй вариант
            asn_num = asn.replace("AS", "")
            url2 = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
            data2 = _fetch_json(url2, timeout=20)
            if data2:
                asn_prefixes = [
                    p["prefix"] for p in data2.get("data", {}).get("ipv4_prefixes", [])
                ]
                prefixes.extend(asn_prefixes)
                print(f"    {asn} ({name}): {len(asn_prefixes)} префиксов (bgpview)")
            else:
                print(f"    {asn} ({name}): недоступен")
    return prefixes


def load_whitelists() -> None:
    global _WHITE_NETS, _WHITE_DOMAINS

    # CIDR по ASN
    print("[*] Загружаю префиксы ASN через RIPE stat API...")
    prefixes = load_asn_prefixes()
    if prefixes:
        nets = []
        for p in prefixes:
            try:
                nets.append(ipaddress.ip_network(p, strict=False))
            except ValueError:
                pass
        _WHITE_NETS = nets
        print(f"    → Итого {len(nets)} префиксов из {len(TARGET_ASNS)} ASN")
    else:
        print(f"    → RIPE недоступен, использую fallback ({len(FALLBACK_CIDRS)} подсетей)")
        _WHITE_NETS = [ipaddress.ip_network(s, strict=False) for s in FALLBACK_CIDRS]

    # Белые домены SNI
    print("[*] Загружаю белые домены (hxehex/whitelist.txt)...")
    text = _fetch_text(DOMAIN_URL)
    if text:
        domains = set()
        for line in text.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if "." in line and not line[0].isdigit():
                domains.add(line)
        if domains:
            _WHITE_DOMAINS = domains
            print(f"    → {len(domains)} доменов + любой .ru")
            return
    _WHITE_DOMAINS = FALLBACK_DOMAINS
    print(f"    → fallback: {len(_WHITE_DOMAINS)} доменов + любой .ru")


def cymru_batch_asn(ips: list[str]) -> dict[str, str]:
    """
    Batch ASN lookup через whois.cymru.com.
    Отправляет все IP одним запросом, возвращает dict ip → "ASN (name)".
    """
    if not ips:
        return {}
    result = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(("whois.cymru.com", 43))
        # begin/end для batch режима
        query = "begin\n" + "\n".join(ips) + "\nend\n"
        s.sendall(query.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        for line in response.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("Bulk") or line.startswith("AS"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                asn = parts[0]
                ip = parts[1]
                name = parts[2]
                result[ip] = f"AS{asn} ({name})"
    except Exception as e:
        print(f"    [!] Cymru batch lookup: {e}")
    return result


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


def is_white_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _WHITE_NETS)
    except ValueError:
        resolved = resolve_host(host)
        if not resolved:
            return False
        try:
            ip = ipaddress.ip_address(resolved)
            return any(ip in net for net in _WHITE_NETS)
        except Exception:
            return False


def is_white_sni(sni: str) -> bool:
    sni = sni.lower().strip()
    if not sni:
        return False
    if sni.endswith(".ru"):
        return True
    if sni in _WHITE_DOMAINS:
        return True
    parts = sni.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in _WHITE_DOMAINS:
            return True
    return False


def extract_sni(uri: str) -> str:
    try:
        q_start = uri.index("?")
        params = parse_qs(uri.split("#")[0][q_start + 1:])
        return params.get("sni", [""])[0]
    except Exception:
        return ""


def parse_uri(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    if "security=reality" not in line.lower():
        return None
    try:
        without_scheme = line[8:]
        at_idx = without_scheme.rfind("@")
        if at_idx == -1:
            return None
        uuid = without_scheme[:at_idx]
        hostport_raw = without_scheme[at_idx + 1:].split("?")[0].split("#")[0]
        if hostport_raw.startswith("["):
            bracket_end = hostport_raw.index("]")
            host = hostport_raw[1:bracket_end]
            port = int(hostport_raw[bracket_end + 2:])
        else:
            host, port_str = hostport_raw.rsplit(":", 1)
            port = int(port_str)
        return {
            "uri": line,
            "host": host,
            "port": port,
            "sni": extract_sni(line),
            "dedup_key": f"{uuid}@{host}:{port}",
        }
    except Exception:
        return None


def fetch_sources(urls: list[str], label: str, seen: dict, limit: int = 0) -> list[str]:
    """Возвращает список IP которые были срезаны по IP фильтру — для диагностики ASN."""
    rejected_ips: list[str] = []
    for url in urls:
        if limit and len(seen) >= limit:
            break
        short = f"{url.split('/')[3]}/{url.split('/')[4]}/{url.split('/')[-1]}"
        try:
            print(f"[*] [{label}] {short}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode(errors="ignore")
            count = skip_nr = skip_dup = skip_ip = skip_sni = 0
            for line in text.splitlines():
                if limit and len(seen) >= limit:
                    break
                parsed = parse_uri(line)
                if not parsed:
                    if line.strip().startswith("vless://"):
                        skip_nr += 1
                    continue
                if parsed["dedup_key"] in seen:
                    skip_dup += 1
                    continue
                # Резолвим host в IP для логирования
                host = parsed["host"]
                try:
                    ipaddress.ip_address(host)
                    resolved_ip = host
                except ValueError:
                    resolved_ip = resolve_host(host) or host
                if not is_white_ip(parsed["host"]):
                    skip_ip += 1
                    rejected_ips.append(resolved_ip)
                    continue
                if not is_white_sni(parsed["sni"]):
                    skip_sni += 1
                    continue
                seen[parsed["dedup_key"]] = parsed
                count += 1
            print(f"    → +{count} (итого: {len(seen)}) | срезано: не-Reality={skip_nr} дубль={skip_dup} IP={skip_ip} SNI={skip_sni}")
        except Exception as e:
            print(f"    [!] Ошибка: {e}")
    return rejected_ips


def build_subscription(servers: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# profile-title: JL33T_WL",
        f"# Обновлено: {now}",
        f"# Серверов: {len(servers)} (Reality + белый ASN + белый SNI)",
        "# Источники: zieng2, whoahaow, igareck, kort0881, STR97, LowiKLive, Kirillo4ka, liMilCo, vlesscollector, rachikop",
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


async def main():
    load_whitelists()

    seen: dict = {}
    all_rejected: list[str] = []

    # P1: только верифицированные источники, без P2
    print(f"\n[*] Группа 1 — верифицированные источники (лимит {P1_LIMIT})...")
    all_rejected += fetch_sources(PRIORITY_1, "P1", seen, limit=P1_LIMIT)

    # Диагностика: топ ASN среди срезанных по IP
    if all_rejected:
        print(f"\n[*] Диагностика: {len(all_rejected)} срезанных IP — запрашиваю ASN (Cymru batch)...")
        unique_rejected = list(dict.fromkeys(
            ip for ip in all_rejected
            if ip != "unknown" and ip.replace(".", "").isdigit()
        ))[:200]
        asn_map = cymru_batch_asn(unique_rejected)
        from collections import Counter
        asn_counter: Counter = Counter()
        for ip in unique_rejected:
            asn = asn_map.get(ip, "unknown")
            asn_counter[asn] += 1
        print(f"[*] Топ-15 ASN среди срезанных серверов:")
        for asn, count in asn_counter.most_common(15):
            print(f"    {count:4d}x  {asn}")
        print(f"[*] → Добавь эти ASN в TARGET_ASNS чтобы пропустить больше серверов")

    if not seen:
        print("[!] Нет серверов — оставляю старый vless.txt без изменений")
        return

    final = list(seen.values())
    random.shuffle(final)
    final = final[:LIMIT]

    print(f"\n[*] Итого: {len(final)} серверов (Reality + белый ASN + белый SNI)")

    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(build_subscription(final))

    print(f"[✓] vless.txt обновлён")


if __name__ == "__main__":
    asyncio.run(main())
