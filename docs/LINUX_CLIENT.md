# LINUX_CLIENT — клиент AetherLink под Ubuntu 24.04 (туннель + раздача по WiFi)

Нативный тонкий клиент `aetherlink-cli` (Rust): весь протокол/крипто/стек —
в ядре `aetherlink_core`, хост делает только конфиг, жизненный цикл и
управление хотспотом (как .NET-хост на Windows, только без .NET).

Возможности:

- полный туннель: TUN (`/dev/net/tun`) + userspace-стек ядра, дефолт в
  туннель (def1-трюк, как на Windows), пин-маршрут до сервера,
  direct-правила, DNS **только через туннель** (системный
  `systemd-resolved` переключается на виртуальный резолвер `10.255.0.1`);
- восстановление сети при `down`/краше: журнал `/var/lib/aetherlink/state.json`
  (тот же механизм, что на Windows: `cleanup` идемпотентен);
- **раздача туннелированного трафика по WiFi**: машина становится
  WPA2-точкой доступа, клиенты ходят в интернет через туннель; если
  туннель упал — трафик клиентов блокируется (fail-closed), а не утекает
  напрямую.

## 1. Сборка

Нужен Rust-тулчейн (для сборки; в рантайме — только системные утилиты):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

cd AetherLink
sudo ./scripts/run_client_ubuntu.sh configs/client.yaml   # сборка + запуск
# или вручную:
cargo build --release -p aetherlink-cli
sudo dist/ubuntu-client/aetherlink-cli configs/client.yaml up
```

Бинарник: `dist/ubuntu-client/aetherlink-cli` (он же ставится в
`/usr/local/bin/` для systemd).

Пакеты для хотспота (зависит от бэкенда):

| Бэкенд | Пакеты | Когда |
|---|---|---|
| `network-manager` | ничего ставить не надо | десктоп 24.04 (NM уже есть) |
| `hostapd` | `apt install hostapd dnsmasq nftables` | сервер без NM |

`nftables` и `iproute2` на 24.04 стоят по умолчанию.

## 2. Быстрый старт: туннель + WiFi-раздача

`client.yaml` (полный пример — `configs/client.example.yaml`):

```yaml
client:
  server_addr: "vpn.example.com:443"
  outer_sni: "vpn.example.com"
  psk: "change-me-high-entropy"

full_tunnel:
  enabled: true
  mtu: 1400
  include_private_lan_direct: true
  dns_mode: tunnel

routing:
  default_action: tunnel
  rules: []

hotspot:
  enabled: true
  interface: wlan0            # убрать строку = автопоиск первого WiFi-адаптера
  ssid: AetherLink
  password: "wifi-secret-8+"  # WPA2, 8..63 символа
  subnet: 192.168.243.0/24    # пул клиентов; НЕ должен совпадать с домашней сетью
  backend: auto               # auto | network-manager | hostapd
```

```bash
sudo dist/ubuntu-client/aetherlink-cli client.yaml up
```

Всё: машина подняла туннель и раздаёт `AetherLink`. Подключившиеся
устройства получают DHCP (шлюз и DNS = адрес машины в подсети хотспота),
их трафик и DNS идут через туннель.

Отдельное управление хотспотом (без туннеля):

```bash
sudo aetherlink-cli hotspot up  --password "..." [--iface wlan0 --ssid X --subnet 192.168.243.0/24 --backend auto]
sudo aetherlink-cli hotspot status
sudo aetherlink-cli hotspot down
```

Остальные команды (аналог .NET-хоста Windows):

```bash
sudo aetherlink-cli client.yaml up        # поднять (и ждать сигнала)
sudo aetherlink-cli client.yaml down      # опустить, восстановить сеть
sudo aetherlink-cli client.yaml status    # JSON-статус туннеля и хотспота
sudo aetherlink-cli client.yaml cleanup   # аварийное восстановление после краша
```

## 3. Как устроена раздача по WiFi

- **Бэкенд `network-manager`** (по умолчанию при `auto`, если NM запущен):
  создаётся подключение `aetherlink-hotspot` типа `wifi.mode ap`,
  `ipv4.method shared` — NM сам поднимает DHCP и NAT. Подключение
  одноразовое (`autoconnect no`, при `down` удаляется).
- **Бэкенд `hostapd`**: свои `hostapd` (WPA2-точка) + `dnsmasq`
  (DHCP: пул `.100-.199`, шлюз и DNS = `.1`); конфиги и pid-файлы в
  `/run/aetherlink/`.
- **Изоляция и защита от утечек**: правило `nft` (таблица
  `inet aetherlink_hotspot`) разрешает клиентскому трафику выходить
  **только** в туннельный интерфейс `aether0`; всё остальное из
  интерфейса точки — `drop`. Поэтому при опущенном туннеле клиенты не
  выходят в интернет напрямую, а «висят» — это поведение по умолчанию
  (защита от разрыва туннеля). Таблица удаляется при `hotspot down`.
- **DNS клиентов**: `dnsmasq`/NM отдают клиентам в DNS адрес машины;
  апстрим берётся из системного резолвера машины, который при поднятом
  туннеле принудительно смотрит в `10.255.0.1` (через туннель), а при
  опущенном — в обычный резолвер провайдера. Утечек системного DNS при
  поднятом туннеле нет (инвариант DNS_NO_LEAK).
- **MTU**: клиентские TCP-MSS зажимаются под MTU туннеля автоматически
  (то же правило `nft`, clamp на SYN).
- Подсеть хотспота по умолчанию `192.168.243.0/24` выбрана подальше от
  типовых домашних `192.168.0/1/100/17`; не задавайте её равной вашей
  локальной сети.

## 4. systemd-сервис

```bash
sudo install -m 0755 dist/ubuntu-client/aetherlink-cli /usr/local/bin/
sudo mkdir -p /etc/aetherlink
sudo cp client.yaml /etc/aetherlink/client.yaml
sudo install -m 0644 deploy/linux/aetherlink-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aetherlink-client
journalctl -u aetherlink-client -f
```

`systemctl stop` корректно опускает туннель и хотспот; при обрыве связи
внутренний watchdog замечает мёртвый насос и сервис перезапускается
(`Restart=on-failure`).

## 5. После краша / ребута

Журнал состояния переживает процесс. Восстановление сети:

```bash
sudo aetherlink-cli client.yaml cleanup    # идемпотентно
```

(то же самое делает `up`: при обнаружении старого журнала — `cleanup` и
повторная попытка).

## 6. Отличия от Windows-клиента

| | Windows | Linux (Ubuntu 24.04) |
|---|---|---|
| TUN | Wintun (dll рядом с хостом) | `/dev/net/tun` |
| Маршруты | `route` + ifIndex-биндинг | `ip route` (def1, как на Windows) |
| DNS | `netsh interface ip set dns` | `resolvectl` (systemd-resolved), fallback `/etc/resolv.conf` |
| Хост | .NET + GUI (Avalonia) через FFI | нативный `aetherlink-cli` |
| Раздача трафика | — | хотспот: `network-manager` или `hostapd` |
| Журнал | `C:\ProgramData\AetherLink\state.json` | `/var/lib/aetherlink/state.json` |

## 7. Ограничения (известные)

- Через туннель идут TCP и UDP (и клиентский, и хотспотный трафик);
  ICMP/`ping` от клиентов не проходит (userspace-стек его не
  терминирует) — это поведение всего клиента, не только хотспота.
- Одна точка доступа: один WiFi-интерфейс = один хотспот.
- Бэкенд `network-manager` использует общий пул `shared`-режима NM;
  адресация задаётся `hotspot.subnet`.
- IPv6 в туннеле не заявляется (как и на Windows); хотспот отдаёт
  клиентам только IPv4. Важно: если у аплинка есть нативный IPv6, его
  трафик (и AAAA-запросы) идёт мимо туннеля — поведение совпадает с
  Windows-клиентом. Для полностью изолированного режима отключите IPv6
  на физическом интерфейсе (`sysctl net.ipv6.conf.<iface>.disable_ipv6=1`)
  или убедитесь, что сеть без IPv6.
- Если туннель не поднят, а хотспот поднят отдельно — клиенты получают
  DHCP/DNS от точки, но наружу не выходят (защита «закрыто при падении»
  намеренно дропает трафик мимо `aether0`); это штатный режим ожидания.
- Переподключение при обрыве — через перезапуск `up` (или
  `Restart=on-failure` в systemd); хотспот при этом не трогается.
