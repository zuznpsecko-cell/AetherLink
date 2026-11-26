# DEPLOY_UBUNTU — сервер AetherLink на VPS

Пошагово, с нуля, под root. Итог: `systemctl`-сервис на 443 с wildcard-сертом.

> В примерах домен — `vpn.example.com`; подставьте свой. Скрипты берут домен
> из `DOMAIN=` (или первого аргумента), в конфиги он не зашит.

## -1. Одна команда (рекомендуется)

```bash
bash <(curl -Ls https://raw.githubusercontent.com/zuznpsecko-cell/AetherLink/main/deploy/linux/install-remote.sh)
```

Скрипт сначала спросит домен и Cloudflare-токен (токен вводится вслепую),
покажет план и попросит подтверждение — и только потом ставит зависимости,
собирает, выпускает LE-wildcard, генерит PSK и поднимает сервис.
Без токена — self-signed серт. Полностью неинтерактивно:

```bash
DOMAIN=vpn.example.com CLOUDFLARE_API_TOKEN=xxx bash <(curl -Ls <url>) --yes
```

Ниже — те же шаги вручную, по частям.

## 0. Что нужно заранее

- VPS: Ubuntu 22.04/24.04, root-доступ по SSH.
- DNS: A-запись `vpn.example.com` → IP VPS, режим **DNS-only (серое облако)**.
  Оранжевое (proxied) нельзя: клиенты упрутся в edge Cloudflare, а не в наш сервер.
- Порт **443/TCP** наружу (UDP для транспорта не нужен — всё внутри TLS).

## 1. База и репозиторий

Вариант A — с гитом на VPS:

```bash
apt update && apt install -y git curl
git clone <repo-url> ~/aetherlink && cd ~/aetherlink
# Тулчейн для сборки на самом VPS:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
# .NET SDK 10 (инструкция Microsoft для Ubuntu), затем:
dotnet --version
```

Вариант B — без гита на VPS (сборка в WSL, на VPS только распаковка):

```bash
# 1. На своей машине: поставить дистрибутив (wsl --install Ubuntu), внутри:
./scripts/run_server_ubuntu.sh server.yaml   # заполняет dist/
./scripts/make_bundle.sh                     # aetherlink-ubuntu-<дата>.tar.gz
# 2. Залить и распаковать на VPS (гит там не нужен):
scp aetherlink-ubuntu-*.tar.gz root@vps:/tmp/
ssh root@vps "mkdir -p /tmp/aetherlink && tar -xzf /tmp/aetherlink-ubuntu-*.tar.gz -C /tmp/aetherlink"
# 3. Дальше все пути — относительно распаковки: /tmp/aetherlink/deploy/...,
#    /tmp/aetherlink/scripts/..., конфиги из /tmp/aetherlink/configs/.
```

Полная кросс-сборка Linux-бинарей из-под Windows (без WSL/Linux) не
поддерживается: `.so` ядра собирается только Linux-тулчейном.

## 2. Сертификат (один раз)

Токен Cloudflare: dashboard → My Profile → API Tokens → Create Token →
шаблон «Edit zone DNS», зона `vpn.example.com`.

```bash
echo 'dns_cloudflare_api_token = TOKEN' | sudo tee /etc/letsencrypt/cloudflare.ini
sudo chmod 600 /etc/letsencrypt/cloudflare.ini
sudo DOMAIN=vpn.example.com ./scripts/provision_cert_ubuntu.sh
```

Проверка: `sudo openssl x509 -in /etc/letsencrypt/live/vpn.example.com-wildcard/fullchain.pem -noout -subject -dates`

## 3. Конфиг сервера

```bash
cp configs/server.example.yaml server.yaml
nano server.yaml
```

Выставить:
- `server.listen: "0.0.0.0:443"`, `server.psk` — сгенерировать:
  `openssl rand -base64 32` (тот же PSK потом в клиент!);
- `local_static_root` — оставить `./fallback` (создастся сам);
- `dns_upstream` — по умолчанию `1.1.1.1`/`8.8.8.8`, можно не трогать;
- `max_connections` (512), `max_streams` (4096), `egress` (`deny_private: true`)
  и блоклист рекламы — разумные значения по умолчанию, описаны прямо в
  `configs/server.example.yaml`.

Ключ (`tls_key`) принимается в любом из PEM-форматов: PKCS#8
(`BEGIN PRIVATE KEY`), PKCS#1 (`BEGIN RSA PRIVATE KEY`) или SEC1
(`BEGIN EC PRIVATE KEY`) — конвертировать ключ certbot или openssl не нужно
(DEC-024).

## 4. Сборка, установка, автозапуск

```bash
TLS_CERT=/etc/letsencrypt/live/vpn.example.com-wildcard/fullchain.pem \
TLS_KEY=/etc/letsencrypt/live/vpn.example.com-wildcard/privkey.pem \
./scripts/run_server_ubuntu.sh server.yaml   # smoke: Ctrl+C после старта
sudo ./deploy/linux/install.sh               # → /opt/aetherlink + unit
sudo ufw allow 443/tcp
sudo systemctl enable --now aetherlink-server
```

## 5. Проверка

```bash
systemctl status aetherlink-server --no-pager
journalctl -u aetherlink-server -n 30 --no-pager
echo | openssl s_client -connect vpn.example.com:443 -servername vpn.example.com \
  -tls1_3 -alpn http/1.1 2>/dev/null | openssl x509 -noout -subject -dates
```

Должны увидеть: сервис active, handshake TLS 1.3 + ALPN `http/1.1`, серт на
`vpn.example.com` от Let's Encrypt. Сервер предлагает только `http/1.1`
(статический fallback отвечает HTTP/1.1); `h2` предлагает лишь клиент, и
туннель от ALPN не зависит (DEC-007).

Если listener сервера умер (например, отозвали сокет), процесс пишет в журнал
`AetherLink server stopped: <причина>` и выходит с кодом 1; unit с
`Restart=on-failure` поднимает его через 5 с. Временные ошибки `accept()`
(исчерпаны дескрипторы/память) сервер переживает сам, с паузой 10 мс…1 с
(DEC-024).

## 6. Продление серта без дауна

```bash
sudo certbot reconfigure --cert-name vpn.example.com-wildcard \
  --deploy-hook "systemctl restart aetherlink-server"
sudo certbot renew --dry-run   # проверка цепочки
```

Штатный таймер certbot продлит серт сам; хук перезапустит сервер, чтобы он
подхватил файлы (иначе продолжит отдавать старый из памяти).

## 7. Клиент (для проверки)

```yaml
# client.yaml
server_addr: "vpn.example.com:443"
outer_sni: "vpn.example.com"
psk: "<тот же PSK, что на сервере>"
```

`sudo ./aether-client client.yaml up` (путь из своей сборки).
Диагностика: неверный PSK → сервер молча отдаёт **статический fallback**
(G2), а не ошибку — это ожидаемо, сверяйте PSK побайтово.

## 8. Типовые проблемы

| Симптом | Причина → действие |
|---|---|
| `aether_server_start failed` | битый конфиг — текст причины теперь в исключении |
| handshake висит | 443 закрыт фаерволом / DNS ведёт не туда (`dig +short vpn.example.com`) |
| клиент получает static вместо туннеля | PSK не совпал; `outer_sni` ≠ имени в серте |
| `cert.pem/key.pem not found` | забыты `TLS_CERT`/`TLS_KEY` при smoke-запуске |
| renewal не подхватывается | нет deploy-hook → `systemctl restart aetherlink-server` |
| `bad key pem` / `no private key found` / `bad cert/key` | ключ не PEM, пустой или не от этого серта; поддерживаются PKCS#8, PKCS#1, SEC1 |
| в журнале `AetherLink server stopped: …`, сервис перезапускается | умер listener; причина в той же строке, systemd поднимает сервис сам |
| в журнале `accept: … backing off` | нехватка дескрипторов/памяти (`EMFILE`, `ENOMEM`); сервер ждёт и продолжает, поднимите `LimitNOFILE` или снизьте `max_connections` |

## 9. Обновление

Два скрипта, оба запускаются на VPS под root: тянут свежий `main`, пересобирают,
обновляют блоклист и перезапускают сервис; `server.yaml` (PSK), серты, фаервол и
unit не трогают. Если сборка упала, сервис не останавливается — продолжает
работать старая версия. Скрипты независимы друг от друга.

| Скрипт | Сборка |
|---|---|
| `update-server.sh` | всегда с нуля, в `/tmp/aetherlink-update`: каждый раз заново компилирует все зависимости — долго |
| `update-server-cached.sh` | инкрементальная, кэш в `/var/cache/aetherlink`: зависимости компилируются один раз |

```bash
# update-server-cached.sh, первый раз (на VPS его ещё нет):
curl -fsSL https://raw.githubusercontent.com/zuznpsecko-cell/AetherLink/main/deploy/linux/update-server-cached.sh \
  -o /tmp/update-server-cached.sh && sudo bash /tmp/update-server-cached.sh
# Дальше — свежая копия скрипта всегда лежит в кэше:
sudo bash /var/cache/aetherlink/src/deploy/linux/update-server-cached.sh
```

Кэш `update-server-cached.sh` переживает перезагрузку (в отличие от `/tmp`):

| Каталог | Что даёт |
|---|---|
| `cargo-target/` | собранные сторонние крейты (aws-lc-sys, ring, tokio, rustls…) компилируются один раз и переиспользуются, пока не поменялись `Cargo.lock` или версия Rust |
| `src/` | чекаут обновляется на месте (`git fetch` + `reset`), а не клонируется заново: у неизменённых файлов сохраняется mtime, и cargo пересобирает только реально изменённые крейты проекта |
| `out/` + `out.stamp` | последняя удачная сборка (`libaetherlink_core.so` + publish .NET-хоста); тот же коммит и те же версии тулчейнов → cargo и dotnet не запускаются вовсе |

Первый запуск — полная сборка. Дальше: нет новых коммитов — сборка пропускается
целиком; Rust-код не менялся — cargo ничего не компилирует; менялся —
пересобираются только свои крейты плюс финальная линковка (LTO).

- `--clean` — сбросить кэш и собрать всё с нуля (если сборка ведёт себя странно).
- `CACHE_MAX_MB` (по умолчанию 4096) — потолок для `cargo-target/`: старые версии
  крейтов копятся после обновлений `Cargo.lock`/Rust; при превышении кэш
  очищается, и следующая сборка полная.
- Кэш удаляет `deploy/linux/uninstall.sh`.
