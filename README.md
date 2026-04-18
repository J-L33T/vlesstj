# 🔓 VLESS подписка — обход белых списков МТС/Теле2

Автоматически обновляемая подписка. Обновляется каждый час.
Использует IP из **VK Cloud / VK CDN** — они всегда в белом списке операторов РФ.

## Подписки

| Файл | SNI | Описание |
|------|-----|----------|
| [`vless.txt`](./vless.txt) | все | Все серверы, все SNI |
| [`vk_vk-max.txt`](./vk_vk-max.txt) | `max.ru` | VK домен |
| [`vk_vk-eh.txt`](./vk_vk-eh.txt) | `eh.vk.com` | VK домен |
| [`vk_vk-userapi.txt`](./vk_vk-userapi.txt) | `sun6-22.userapi.com` | VK userapi |
| [`vk_vk-m.txt`](./vk_vk-m.txt) | `m.vk.com` | VK мобильный |

**Ссылка для v2rayTUN:**
```
https://raw.githubusercontent.com/НИК/РЕПО/main/vless.txt
```

## Как работает

Трафик идёт через IP адреса VK Cloud и VK CDN которые операторы
не могут заблокировать — иначе перестанут работать сервисы VK.
SNI замаскирован под VK домены (max.ru, vk.com и т.д.).

```
Телефон → IP из VK Cloud (✓ белый список) → твой VPS → интернет
```

## Настройка секретов

Settings → Secrets and variables → Actions:

| Secret | Значение |
|--------|----------|
| `VLESS_UUID` | UUID сервера |
| `VLESS_PBK`  | Reality Public Key |
| `VLESS_SID`  | Short ID |
| `VLESS_FP`   | firefox / chrome |
| `VLESS_PORT` | 443 |

> SNI задаётся прямо в скрипте — для каждого файла свой VK домен.
