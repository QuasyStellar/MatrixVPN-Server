# MatrixVPN-Server (форк AntiZapret-VPN)

Скрипт для установки на [своём сервере](https://github.com/GubernievS/AntiZapret-VPN#%D0%B3%D0%B4%D0%B5-%D0%BA%D1%83%D0%BF%D0%B8%D1%82%D1%8C-%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80) AntiZapret VPN и обычного VPN.
Работает по протоколам OpenVPN (с патчем для обхода блокировки), WireGuard, AmneziaWG и VLESS (Xray).

Этот проект является форком [AntiZapret-VPN от GubernievS](https://github.com/GubernievS/AntiZapret-VPN) с добавлением поддержки VLESS, Telegram-бота для управления и других улучшений.

## Описание протоколов

### AntiZapret VPN
AntiZapret VPN реализует технологию [раздельного туннелирования](https://encyclopedia.kaspersky.ru/glossary/split-tunneling). Через него проходит трафик только к заблокированным или недоступным из РФ сайтам. Остальные ресурсы работают напрямую через вашего провайдера, сохраняя максимальную скорость и доступ к локальным сервисам (банки, госуслуги и т.д.).

### Полный VPN
Направляет весь ваш трафик через сервер, обеспечивая полную анонимность и обход любых ограничений.

**Внимание!** Для правильной работы AntiZapret VPN нужно [отключить безопасный DNS в браузере](https://www.google.ru/search?q=%D0%BE%D1%82%D0%BA%D0%BB%D1%8E%D1%87%D0%B8%D1%82%D1%8C+%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D1%8B%D0%B9+DNS+%D0%B2+%D0%B1%D1%80%D0%B0%D1%83%D0%B7%D0%B5%D1%80%D0%B5).

### OpenVPN (`*.ovpn`)
- **Порты:** 50080 (UDP), 50443 (TCP)
- **Особенности:** Поддерживает UDP и TCP. Есть патч для обхода блокировок. Один файл `.ovpn` может использоваться несколькими клиентами.
- **Клиенты:** [OpenVPN Connect](https://openvpn.net/client), [OpenVPN (Windows)](https://openvpn.net/community-downloads)

### WireGuard (`*-wg.conf`)
- **Порты:** 51080, 51443 (UDP)
- **Особенности:** Высокая производительность. Каждому клиенту нужен свой файл конфигурации.
- **Клиенты:** [WireGuard](https://www.wireguard.com/install)

### AmneziaWG (`*-am.conf`)
- **Порты:** 52080, 52443 (UDP)
- **Особенности:** Обфусцированная версия WireGuard для обхода блокировок.
- **Клиенты:** [AmneziaWG (Windows)](https://github.com/amnezia-vpn/amneziawg-windows-client/releases), [AmneziaWG (Android)](https://play.google.com/store/apps/details?id=org.amnezia.awg), [AmneziaWG (Apple)](https://apps.apple.com/ru/app/amneziawg/id6478942365)

### VLESS (Xray) (`*.json`)
- **Особенности:** Современный протокол с поддержкой XTLS Reality для эффективной маскировки трафика под обычный HTTPS-трафик.
- **Клиенты:** v2rayN (Windows), v2rayNG (Android), Streisand (iOS) и другие, поддерживающие VLESS.

---

## Установка и обновление

1.  Устанавливать на чистый сервер **Ubuntu 22.04/24.04** или **Debian 11/12**.
2.  Выполнить в терминале под `root`:
    ```sh
    bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/QuasyStellar/MatrixVPN-Server/main/setup.sh)
    ```
3.  В процессе установки вам будет предложено изменить настройки. Вы можете нажимать Enter для выбора значений по умолчанию.
    - **Патч для OpenVPN:** Для обхода блокировок.
    - **OpenVPN DCO:** Снижает нагрузку на CPU.
    - **Выбор DNS:** Разные DNS для AntiZapret и полного VPN.
    - **Блокировка рекламы:** На основе списков AdGuard и OISD.
    - **Настройки VLESS (Xray):**
        - **Порт VLESS:** Порт для VLESS Reality (например, 443).
        - **Сайт для маскировки:** Легитимный сайт для маскировки трафика (например, `www.google.com:443`).
        - **Имена серверов:** Доменные имена для VLESS Reality (например, `google.com`).
    - И другие опции, включая защиту SSH, добавление IP-адресов популярных сервисов и т.д.
4.  В конце установки будет автоматически скачан и настроен [Telegram-бот](https://github.com/QuasyStellar/MatrixVPN) для управления VPN.
5.  После установки сервер перезагрузится. Файлы конфигураций для клиентов будут находиться в папке `/root/antizapret/client/`.

---

## Настройка и управление

### Управление через Telegram-бота

Основной способ управления пользователями — через Telegram-бота, который устанавливается автоматически. Бот позволяет:
- **Пользователям:** Отправлять запросы на доступ, получать файлы конфигурации для всех протоколов.
- **Администратору:** Одобрять и отклонять запросы, удалять пользователей, делать рассылки, продлевать доступ.

Админ-панель доступна по команде `/admin`.

### Ручное управление (`client.py`)

Для ручного управления или для использования в скриптах предназначен `/root/antizapret/client.py`. Запустите его без параметров для входа в интерактивное меню:
```sh
/root/antizapret/client.py
```

Или используйте команды напрямую:

**Создать клиента для всех протоколов:**
```sh
# /root/antizapret/client.py 11 [имя_клиента] [срок_в_днях_для_ovpn]
/root/antizapret/client.py 11 my-client 365
```

**Добавить клиента OpenVPN:**
```sh
# /root/antizapret/client.py 1 [имя_клиента] [срок_в_днях]
/root/antizapret/client.py 1 my-openvpn-client 365
```

**Удалить клиента OpenVPN:**
```sh
/root/antizapret/client.py 2 my-openvpn-client
```

**Добавить клиента WireGuard/AmneziaWG:**
```sh
/root/antizapret/client.py 4 my-wg-client
```

**Добавить пользователя VLESS:**
```sh
# /root/antizapret/client.py 7 [email_пользователя]
/root/antizapret/client.py 7 user@example.com
```

**Удалить пользователя VLESS:**
```sh
/root/antizapret/client.py 8 user@example.com
```

**Показать список пользователей VLESS:**
```sh
/root/antizapret/client.py 9
```

**Удалить клиента из всех протоколов:**
```sh
/root/antizapret/client.py 12 my-client
```

### Добавление своих сайтов и IP-адресов

-   **Сайты для AntiZapret:** Добавьте домены в `/root/antizapret/config/include-hosts.txt`.
-   **IP-адреса для AntiZapret:** Добавьте IP-адреса с маской (например, `8.8.8.8/32`) в `/root/antizapret/config/include-ips.txt`.

После изменений выполните:
```sh
/root/antizapret/doall.sh
```

---

## FAQ

### Как пересоздать все файлы подключений?
Выполните команду:
```sh
/root/antizapret/client.py 13
```

### Как сделать бэкап настроек и клиентов?
Выполните команду:
```sh
/root/antizapret/client.py 14
```
Будет создан архив `backup-*.tar.gz` в папке `/root/antizapret/`.

### Как посмотреть активные соединения?
- **OpenVPN:** `cat /etc/openvpn/server/logs/*-status.log`
- **WireGuard/AmneziaWG:** `wg show`
- **VLESS (Xray):** Статистика доступна через API, но для простого просмотра можно анализировать логи Xray.

---

## Благодарности

-   **[GubernievS](https://github.com/GubernievS)** за оригинальный скрипт AntiZapret-VPN.
-   **ValdikSS** за исходники [antizapret-vpn-container](https://bitbucket.org/anticensority/antizapret-vpn-container/src/master).