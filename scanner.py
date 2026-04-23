#!/usr/bin/env python3
"""
Агрегатор VLESS подписок — только белые подсети РФ (v4).

Ключевое изменение v4:
- TCP+TLS проверка полностью убрана.
  Причина: GitHub Actions runner находится в Европе, и многие серверы
  которые реально работают через МТС/Теле2 не отвечают из-за рубежа —
  либо фаервол, либо высокий latency, либо DPI на входе. Итог: мы
  отсеивали рабочие серверы и оставляли только те что случайно
  отвечают из Европы (6 из 154 пингуются на МТС).
- Единственный фильтр — принадлежность IP к белым подсетям РФ из
  актуального списка hxehex/russia-mobile-internet-whitelist.
- Мёртвые серверы клиент (v2rayTUN/v2rayNG) отфильтрует сам через URL Test.
- Дедупликация по (uuid, host, port) сохранена.
"""

import ipaddress
import socket
import random
import urllib.request
from datetime import datetime, timezone
from urllib.parse import unquote


# ─── Все источники конфигов ───────────────────────────────────────────────────
ALL_SOURCES = [
    # zieng2 — специально для белых списков, тестируется на реальных симках
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",

    # whoahaow bypass — протестированы через Xray-core, отсортированы по пингу
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure.txt",

    # igareck — реальные проверки, обновляется каждые 1-2 часа
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",

    # kort0881
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/clean/vless.txt",

    # STR97/STRUGOV
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/BYPASS",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/Vless",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/CUSTOM",

    # LowiKLive
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",

    # Kirillo4ka
    "https://raw.githubusercontent.com/Kirillo4ka/vpn-configs-for-russia/refs/heads/main/Vless-Rus-Mobile-White-List.txt",

    # liMilCo/v2r
    "https://raw.githubusercontent.com/liMilCo/v2r/refs/heads/main/all_configs.txt",

    # vlesscollector
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",

    # 55prosek-lgtm
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",

    # rachikop
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/refs/heads/main/vless.txt",
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/refs/heads/main/subscription.txt",
    "https://raw.githubusercontent.com/rachikop/mobile_whitelist/refs/heads/main/configs.txt",
]

# ─── Источник белых подсетей (динамический) ───────────────────────────────────
CIDR_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"

FALLBACK_WHITE_SUBNETS = [
    "95.163.0.0/16", "87.240.0.0/16", "93.186.224.0/19",
    "185.30.176.0/22", "89.208.224.0/19", "94.100.176.0/22",
    "178.154.128.0/17", "5.45.192.0/18", "95.108.0.0/16",
    "77.88.0.0/18", "87.250.224.0/19",
    "178.72.128.0/17",
    "185.104.112.0/22", "194.58.96.0/19", "92.53.96.0/19",
    "83.166.232.0/21",
    "80.66.64.0/19", "85.142.24.0/21",
    "213.234.0.0/16", "217.118.64.0/18",
    "195.19.220.0/22", "213.248.96.0/19",
    "212.193.0.0/19",
]

# ─── Глобальный список белых сетей ────────────────────────────────────────────
_WHITE_NETS: list = []

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
    global _WHITE_NETS
    try:
        print("[*] Загружаю белые подсети из hxehex/russia-mobile-internet-whitelist...")
        req = urllib.request.Request(CIDR_WHITELIST_URL, headers={"User-Agent": "Mozilla/5.0"})
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
        print(f"    [!] Ошибка: {e} — использую fallback ({len(FALLBACK_WHITE_SUBNETS)} подсетей)")
        _WHITE_NETS = [ipaddress.ip_network(s, strict=False) for s in FALLBACK_WHITE_SUBNETS]


def is_in_white_subnet(host: str) -> bool:
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


def parse_uri(line: str) -> dict | None:
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
            "dedup_key": f"{uuid}@{host}:{port}",
        }
    except Exception:
        return None


def fetch_all() -> dict[str, dict]:
    """Загружает все источники, фильтрует по белым подсетям, дедуплицирует."""
    seen: dict[str, dict] = {}
    for url in ALL_SOURCES:
        short = f"{url.split('/')[3]}/{url.split('/')[4]}/{url.split('/')[-1]}"
        try:
            print(f"[*] {short}")
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
            print(f"    → +{count} (итого: {len(seen)})")
        except Exception as e:
            print(f"    [!] Ошибка: {e}")
    return seen


def build_subscription(servers: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# profile-title: JL33T_WL",
        f"# Обновлено: {now}",
        f"# Серверов: {len(servers)} (белые подсети РФ)",
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
    load_white_subnets()

    print(f"\n[*] Загружаю источники (без TCP-проверки)...")
    all_servers = fetch_all()

    if not all_servers:
        print("[!] Нет серверов — оставляю старый vless.txt без изменений")
        return

    final = list(all_servers.values())
    random.shuffle(final)

    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(build_subscription(final))

    print(f"\n[✓] vless.txt обновлён: {len(final)} серверов в белых подсетях РФ")


if __name__ == "__main__":
    main()
