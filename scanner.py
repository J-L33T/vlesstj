#!/usr/bin/env python3
"""
Агрегатор VLESS подписок — белые подсети РФ (v5).

Фильтрация:
- Только Reality (security=reality)
- SNI должен быть российским: оканчивается на .ru ИЛИ есть в hxehex/whitelist.txt
- CIDR фильтр убран — он резал рабочие серверы из zieng2 (254 штуки!)
- Лимит 100, приоритет: zieng2 → whoahaow/bypass → остальные
- Дедупликация по (uuid, host, port)
"""

import random
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote, parse_qs


# ─── Источники по приоритетам ─────────────────────────────────────────────────
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

LIMIT = 100

# ─── Белые домены SNI ─────────────────────────────────────────────────────────
DOMAIN_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"

FALLBACK_DOMAINS = {
    "yandex.ru", "ya.ru", "vk.com", "mail.ru", "ok.ru",
    "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru",
    "sberbank.ru", "gosuslugi.ru", "mos.ru", "rbc.ru",
    "rt.ru", "x5.ru", "wildberries.ru", "ozon.ru",
    "avito.ru", "hh.ru", "cdek.ru", "dns-shop.ru",
    "max.ru", "vk.ru", "selectel.ru", "reg.ru",
}

_WHITE_DOMAINS: set = set()


def _fetch_text(url: str) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode(errors="ignore")
    except Exception as e:
        print(f"    [!] Ошибка загрузки {url.split('/')[-1]}: {e}")
        return None


def load_domains() -> None:
    global _WHITE_DOMAINS
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


def is_white_sni(sni: str) -> bool:
    """SNI считается белым если: оканчивается на .ru ИЛИ есть в whitelist (или его родитель)."""
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
            count = skip_nr = skip_dup = skip_sni = 0
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
                if not is_white_sni(parsed["sni"]):
                    skip_sni += 1
                    continue
                seen[parsed["dedup_key"]] = parsed
                count += 1
            print(f"    → +{count} (итого: {len(seen)}) | срезано: не-Reality={skip_nr} дубль={skip_dup} SNI={skip_sni}")
        except Exception as e:
            print(f"    [!] Ошибка: {e}")


def build_subscription(servers: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# profile-title: JL33T_WL",
        f"# Обновлено: {now}",
        f"# Серверов: {len(servers)} (Reality + белый SNI)",
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
    load_domains()

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

    print(f"\n[*] Итого: {len(final)} серверов (Reality + белый SNI)")

    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(build_subscription(final))

    print(f"[✓] vless.txt обновлён")


if __name__ == "__main__":
    main()
