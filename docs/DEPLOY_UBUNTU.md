# DEPLOY_UBUNTU — сервер AetherLink на VPS (selmedia.ru)

Пошагово, с нуля, под root. Итог: `systemctl`-сервис на 443 с wildcard-сертом.

## 0. Что нужно заранее

- VPS: Ubuntu 22.04/24.04, root-доступ по SSH.
- DNS: A-запись `selmedia.ru` → IP VPS, режим **DNS-only (серое облако)**.
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
шаблон «Edit zone DNS», зона `selmedia.ru`.

```bash
echo 'dns_cloudflare_api_token = TOKEN' | sudo tee /etc/letsencrypt/cloudflare.ini
sudo chmod 600 /etc/letsencrypt/cloudflare.ini
sudo ./scripts/provision_cert_ubuntu.sh
```

Проверка: `sudo openssl x509 -in /etc/letsencrypt/live/selmedia.ru-wildcard/fullchain.pem -noout -subject -dates`

## 3. Конфиг сервера

```bash
cp configs/server.example.yaml server.yaml
nano server.yaml
```

Выставить:
- `server.listen: "0.0.0.0:443"`, `server.psk` — сгенерировать:
  `openssl rand -base64 32` (тот же PSK потом в клиент!);
- `local_static_root` — оставить `./fallback` (создастся сам);
- `dns_upstream` — по умолчанию `1.1.1.1`/`8.8.8.8`, можно не трогать.

## 4. Сборка, установка, автозапуск

```bash
TLS_CERT=/etc/letsencrypt/live/selmedia.ru-wildcard/fullchain.pem \
TLS_KEY=/etc/letsencrypt/live/selmedia.ru-wildcard/privkey.pem \
./scripts/run_server_ubuntu.sh server.yaml   # smoke: Ctrl+C после старта
sudo ./deploy/linux/install.sh               # → /opt/aetherlink + unit
sudo ufw allow 443/tcp
sudo systemctl enable --now aetherlink-server
```

## 5. Проверка

```bash
systemctl status aetherlink-server --no-pager
journalctl -u aetherlink-server -n 30 --no-pager
echo | openssl s_client -connect selmedia.ru:443 -servername selmedia.ru \
  -tls1_3 -alpn h2 2>/dev/null | openssl x509 -noout -subject -dates
```

Должны увидеть: сервис active, handshake TLS 1.3 + ALPN `h2`, серт на
`selmedia.ru` от Let's Encrypt.

## 6. Продление серта без дауна

```bash
sudo certbot reconfigure --cert-name selmedia.ru-wildcard \
  --deploy-hook "systemctl restart aetherlink-server"
sudo certbot renew --dry-run   # проверка цепочки
```

Штатный таймер certbot продлит серт сам; хук перезапустит сервер, чтобы он
подхватил файлы (иначе продолжит отдавать старый из памяти).

## 7. Клиент (для проверки)

```yaml
# client.yaml
server_addr: "selmedia.ru:443"
outer_sni: "selmedia.ru"
psk: "<тот же PSK, что на сервере>"
```

`sudo ./aether-client client.yaml up` (путь из своей сборки).
Диагностика: неверный PSK → сервер молча отдаёт **статический fallback**
(G2), а не ошибку — это ожидаемо, сверяйте PSK побайтово.

## 8. Типовые проблемы

| Симптом | Причина → действие |
|---|---|
| `aether_server_start failed` | битый конфиг — текст причины теперь в исключении |
| handshake висит | 443 закрыт фаерволом / DNS ведёт не туда (`dig +short selmedia.ru`) |
| клиент получает static вместо туннеля | PSK не совпал; `outer_sni` ≠ имени в серте |
| `cert.pem/key.pem not found` | забыты `TLS_CERT`/`TLS_KEY` при smoke-запуске |
| renewal не подхватывается | нет deploy-hook → `systemctl restart aetherlink-server` |
