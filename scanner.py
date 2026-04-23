#!/usr/bin/env python3
"""
Агрегатор VLESS подписок — белые подсети РФ (v5).

Изменения v5:
- Двойной фильтр: IP в белых CIDR + SNI из белого списка доменов РФ.
  Причина: МТС/Теле2 проверяют оба — белый IP недостаточно, SNI тоже
  должен быть российским (yandex.ru, vk.com, mts.ru и т.п.).
- Белые домены тянутся динамически из hxehex/whitelist.txt.
- Лимит увеличен до 100 — при двойном фильтре качество высокое.
- Только Reality, дедупликация по (uuid, host, port).
"""

import ipaddress
import socket
import random
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse, parse_qs


# ─── Источники по приоритетам ─────────────────────────────────────────────────
PRIORITY_1 = [
    # верифицированы на реальных симках МТС/Теле2
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
]

PRIORITY_2 = [
    # проверены, но не на симках — добираем если P1 не хватило
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
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/refs/heads/main/configs.txt",
]

LIMIT = 100  # максимум серверов в итоговой подписке

# ─── Источники белых списков (hxehex) ─────────────────────────────────────────
CIDR_URL    = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"
DOMAIN_URL  = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"

# Fallback CIDR
FALLBACK_CIDRS = [
    "95.163.0.0/16", "87.240.0.0/16", "93.186.224.0/19",
    "185.30.176.0/22", "89.208.224.0/19", "94.100.176.0/22",
    "178.154.128.0/17", "5.45.192.0/18", "95.108.0.0/16",
    "77.88.0.0/18", "87.250.224.0/19", "178.72.128.0/17",
    "185.104.112.0/22", "194.58.96.0/19", "92.53.96.0/19",
    "83.166.232.0/21", "80.66.64.0/19", "85.142.24.0/21",
    "213.234.0.0/16", "217.118.64.0/18", "195.19.220.0/22",
    "213.248.96.0/19", "212.193.0.0/19",
]

# Fallback домены — самые популярные российские
FALLBACK_DOMAINS = {
    "yandex.ru", "ya.ru", "vk.com", "mail.ru", "ok.ru",
    "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru",
    "sberbank.ru", "gosuslugi.ru", "mos.ru", "rbc.ru",
    "rt.ru", "1tv.ru", "ntv.ru", "ria.ru", "tass.ru",
    "x5.ru", "5post.ru", "wildberries.ru", "ozon.ru",
    "avito.ru", "hh.ru", "cdek.ru", "dns-shop.ru",
    "ads.yandex.ru", "ads.x5.ru", "max.ru", "vk.ru",
    "selectel.ru", "timeweb.com", "reg.ru", "2ip.ru",
}

# ─── Глобальные структуры ─────────────────────────────────────────────────────
_WHITE_NETS: list = []
_WHITE_DOMAINS: set = set()
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


def _fetch_text(url: str) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode(errors="ignore")
    except Exception as e:
        print(f"    [!] Не удалось загрузить {url.split('/')[-1]}: {e}")
        return None


def load_whitelists() -> None:
    global _WHITE_NETS, _WHITE_DOMAINS

    # CIDR
    print("[*] Загружаю белые подсети (hxehex/cidrwhitelist.txt)...")
    text = _fetch_text(CIDR_URL)
    if text:
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
            print(f"    → {len(nets)} подсетей")
        else:
            _WHITE_NETS = [ipaddress.ip_network(s, strict=False) for s in FALLBACK_CIDRS]
            print(f"    → fallback: {len(_WHITE_NETS)} подсетей")
    else:
        _WHITE_NETS = [ipaddress.ip_network(s, strict=False) for s in FALLBACK_CIDRS]
        print(f"    → fallback: {len(_WHITE_NETS)} подсетей")

    # Домены SNI
    print("[*] Загружаю белые домены (hxehex/whitelist.txt)...")
    text = _fetch_text(DOMAIN_URL)
    if text:
        domains = set()
        for line in text.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            # файл может содержать IP или домены — берём только домены
            if "." in line and not line[0].isdigit():
                domains.add(line)
        if domains:
            _WHITE_DOMAINS = domains
            print(f"    → {len(domains)} доменов")
        else:
            _WHITE_DOMAINS = FALLBACK_DOMAINS
            print(f"    → fallback: {len(_WHITE_DOMAINS)} доменов")
    else:
        _WHITE_DOMAINS = FALLBACK_DOMAINS
        print(f"    → fallback: {len(_WHITE_DOMAINS)} доменов")


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
    """Проверяет SNI — домен или его родительский домен должен быть в белом списке."""
    sni = sni.lower().strip()
    if not sni:
        return False
    # прямое совпадение
    if sni in _WHITE_DOMAINS:
        return True
    # проверяем родительские домены: sub.domain.ru → domain.ru → ru
    parts = sni.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in _WHITE_DOMAINS:
            return True
    return False


def extract_sni(uri: str) -> str:
    """Извлекает значение sni= из VLESS URI."""
    try:
        q_start = uri.index("?")
        fragment = uri.split("#")[0]
        params = parse_qs(fragment[q_start + 1:])
        sni_list = params.get("sni", [])
        return sni_list[0] if sni_list else ""
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
        sni = extract_sni(line)
        return {
            "uri": line,
            "host": host,
            "port": port,
            "sni": sni,
            "dedup_key": f"{uuid}@{host}:{port}",
        }
    except Exception:
        return None


def fetch_sources(urls: list[str], label: str, seen: dict, limit: int = 0) -> None:
    for url in urls:
        if limit and len(seen) >= limit:
            break
        short = f"{url.split('/')[3]}/{url.split('/')[4]}/{url.split('/')[-1]}"
        try:
            print(f"[*] [{label}] {short}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode(errors="ignore")
            count = 0
            skip_not_reality = 0
            skip_dup = 0
            skip_ip = 0
            skip_sni = 0
            for line in text.splitlines():
                if limit and len(seen) >= limit:
                    break
                parsed = parse_uri(line)
                if not parsed:
                    if line.strip().startswith("vless://"):
                        skip_not_reality += 1
                    continue
                if parsed["dedup_key"] in seen:
                    skip_dup += 1
                    continue
                if not is_white_ip(parsed["host"]):
                    skip_ip += 1
                    continue
                if not is_white_sni(parsed["sni"]):
                    skip_sni += 1
                    continue
                seen[parsed["dedup_key"]] = parsed
                count += 1
            print(f"    → +{count} (итого: {len(seen)}) | срезано: не-Reality={skip_not_reality} дубль={skip_dup} IP={skip_ip} SNI={skip_sni}")
        except Exception as e:
            print(f"    [!] Ошибка: {e}")


def build_subscription(servers: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# profile-title: JL33T_WL",
        f"# Обновлено: {now}",
        f"# Серверов: {len(servers)} (белые IP + белый SNI)",
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


def main():
    load_whitelists()

    seen: dict = {}

    print(f"\n[*] Группа 1 — верифицированные источники (лимит {LIMIT})...")
    fetch_sources(PRIORITY_1, "P1", seen, limit=LIMIT)

    if len(seen) < LIMIT:
        print(f"\n[*] Группа 2 — добираем до {LIMIT} (сейчас {len(seen)})...")
        fetch_sources(PRIORITY_2, "P2", seen, limit=LIMIT)

    if not seen:
        print("[!] Нет серверов — оставляю старый vless.txt без изменений")
        return

    final = list(seen.values())
    random.shuffle(final)
    final = final[:LIMIT]

    print(f"\n[*] Итого: {len(final)} серверов (Reality + белый IP + белый SNI)")

    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(build_subscription(final))

    print(f"[✓] vless.txt обновлён")


if __name__ == "__main__":
    main()
