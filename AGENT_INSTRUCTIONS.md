# AETHERLINK v1.5 — АВТОНОМНАЯ РАЗРАБОТКА

## 0. Роль

Senior-инженер: Rust (ядро), FFI, .NET-обёртки, Wintun/TUN/VpnService, Android/TV.
Личный проект: README краткий; главное — рабочий код, тесты, deploy-скрипты.

### Правила
1. Прочитай файл целиком.
2. Canonical wire protocol и крипто — **только Rust**.
3. Любой клиент/сервер (.NET, Android, CLI) ходит в ядро **только через FFI** (C ABI / uniffi). Запрещён второй protocol stack на C#/Kotlin.
4. G1/G2/G3 + No-Proxy-Surface соблюдать.
5. Не логировать PSK/session keys.
6. Не писать эксплойты.
7. При сомнениях — DECISIONS.md, сохранить инварианты ниже.

---

## 1. Архитектурный канон (P0, FIXED)

### 1.1. Единое ядро
┌─────────────────────────────────────────┐
│ aetherlink-core (Rust, cdylib + static)│
│ frame, crypto, mux, session, netstack, │
│ dns, routing-engine, tun-pipeline │
└─────────────────┬───────────────────────┘
│ FFI (C ABI / uniffi)
┌────────────┼────────────┬──────────────┐
▼ ▼ ▼ ▼
.NET Server .NET Client Rust CLI Android JNI
(host only) (host+UI) (optional) Kotlin UI

text


- **.NET** = host: конфиг, service/systemd, Wintun load path, tray optional, вызовы FFI.
- **Android** = Kotlin UI + VpnService; data plane в Rust через FFI/JNI.
- Golden tests и SPEC живут в `protocol/` (Rust). .NET **не** дублирует AEAD/frames.

### 1.2. Data plane = L3 TUN «как v2rayN + Wintun» (FIXED)

Модель (аналог v2rayN / sing-box / xray TUN inbound):

1. Поднять виртуальный NIC:
   - Windows: **Wintun**;
   - Linux: `/dev/net/tun`;
   - Android/TV: `VpnService` TUN fd → в Rust.
2. Читать/писать **IP-пакеты** (IPv4 обязательно; IPv6 best-effort).
3. **Userspace network stack** в Rust (предпочтительно `smoltcp` или аналог gVisor-netstack через безопасную обёртку; выбор в DECISIONS):
   - TCP → логические соединения;
   - UDP → логические ассоциации (в т.ч. DNS).
4. Каждое TCP-соединение / UDP-flow → **stream/flow frames** в AetherLink поверх TLS 1.3.
5. Сервер (Rust core): reverse — из flows → `dial` TCP/UDP к цели, NAT/relay ответов обратно.
6. Не заявлять «сырой IP-packet relay без стека», если не реализован; канон MVP = **TUN + userspace stack + TCP/UDP flows** (как у v2rayN-класса клиентов).
App → OS route → Wintun/TUN → Rust netstack → TCP/UDP flows
→ AetherLink mux/AEAD → TLS 1.3 → Server core
→ dial target → reply back

text


### 1.3. DNS — только через туннель (FIXED, no leak)

Инвариант **DNS_NO_LEAK**:

1. При active full tunnel системный DNS **не** должен резолвить в обход туннеля.
2. Все DNS-запросы (UDP/53, и TCP/53 если есть) идут:
   - в TUN (маршрутом/VpnService) **или**
   - перехватом в userspace stack как UDP/TCP flow через AetherLink.
3. На сервере DNS-flow → к настроенным upstream resolvers сервера
   (`server.dns_upstream`, default `1.1.1.1:53` / `8.8.8.8:53` — выбрать и зафиксировать) **или** transparent as-is к dst из пакета, если dst уже DNS resolver в tunnel.
4. Рекомендуемый MVP:
   - клиент подменяет DNS на «виртуальный» DNS gateway туннеля (например `aether_dns_ip` в subnet TUN, типа `x.x.x.1`);
   - stack перехватывает DNS к этому IP;
   - core шлёт DNS query через отдельный flow/stream на сервер;
   - сервер резолвит upstream и отвечает.
5. DoH/DoT внутри приложений (Chrome) туннелируются как обычный TCP **если** app в туннеле — ok; это не system DNS leak.
6. **Bypass domain rules** (direct): резолв имени для построения direct host-route делается **через tunnel DNS**, затем к IP ставится **direct route**. Так имя не утекает в системный DNS провайдера.
7. При `down` — полное restore DNS (Windows NRPT/interface DNS, Linux resolv.conf/resolved, Android VpnService teardown).

Запрещено в connected state:
- слать DNS на ISP resolver в обход TUN;
- оставлять старый DHCP DNS без override.

### 1.4. Full tunnel + routing rules

**Full tunnel:** default route → TUN (IPv4; IPv6 если включено), кроме:
- pin route до IP сервера AetherLink через physical GW (**до** смены default);
- loopback;
- `action: direct` rules (ip/cidr/range/domain/suffix);
- optional private LAN direct (`include_private_lan_direct: true` default).

**Precedence (FIXED):**
1. loopback  
2. pin server IP(s)  
3. routing rules `direct` (по priority + longest prefix)  
4. Android app split (allow/deny) — только Android/TV  
5. default → tunnel  

**DNS always via tunnel** даже для имён, которые потом получат direct route (см. 1.3.6).

### 1.5. Split apps
Только **Android / Android TV / Google TV**.  
Default: `mode: all`.  
Windows/Linux — без per-app split.

---

## 2. Инварианты видимости

**G1** — on-path: TLS 1.3 + ciphertext, вид browser HTTPS.  
**G2** — no/bad auth: web fallback static, без tunnel banner.  
**G3** — auth ok: mux внутри TLS.

No-Proxy-Surface: без proxy headers/banners; fallback **по умолчанию только static** (не open reverse-proxy).

TLS fingerprint: в **Rust core** (rustls + best-effort ClientHello profile). .NET не открывает свой SslStream для data plane туннеля — только FFI к core.

---

## 3. FFI API (минимальный контракт)

Реализовать стабильный C ABI (имена уточнить в коде, смысл сохранить):

```c
// lifecycle
aether_version()
aether_server_start(config_json) -> handle
aether_server_stop(handle)
aether_client_create(config_json) -> handle
aether_client_up(handle) -> error
aether_client_down(handle) -> error
aether_client_status(handle, out_json)
aether_client_force_cleanup()  // idempotent, после краша

// routing rules
aether_client_rules_list / set / reload

// android
aether_client_android_set_tun_fd(handle, fd, mtu)
aether_client_set_split_config(handle, json)

// logs callback без секретов
aether_set_log_callback(cb)
Config — UTF-8 JSON/YAML path. Ошибки — коды + last_error_message.

Сборка: cdylib + headers; Windows aetherlink_core.dll, Linux .so, Android .so per abi.

.NET: P/Invoke / NativeAOT load.
Android: JNI bridge thin.

4. Протокол (Rust only)
4.1 TLS
TLS 1.3 only в core (rustls).
ALPN h2,http/1.1.
ECH deferred ok.
4.2 AUTH
text

token = HMAC-SHA256(PSK, "aetherlink-auth-v1" || client_nonce[32])
Server: nonce replay cache (TTL, e.g. 5 min).

4.3 Frame
text

Length(u24)=len(Ciphertext), Type, Flags, StreamID, Sequence,
AEAD(ChaCha20-Poly1305), Padding → size ∶ pad_multiple
Types:

0 DATA
1 OPEN_TCP (ex HEADERS): addr_type, addr, port
2 PING
3 AUTH
4 WINDOW_UPDATE
5 GOAWAY
6 RST
7 OPEN_UDP: addr_type, addr, port (UDP flow open)
8 UDP_DATAGRAM: payload for UDP flow (или DATA+flags — зафиксировать один стиль)
9 DNS_QUERY / DNS_RESPONSE — опционально, если DNS только как UDP flow к virtual DNS; тогда 9 не нужен. Предпочтительно DNS = обычный UDP flow к virtual resolver.
Version byte в первом AUTH или отдельный PREFACE — PROTOCOL_VERSION=1.

4.4 Key schedule
HKDF-SHA256 как в v1.4; anti-replay window ≥ 1024.

4.5 Server
text

TLS accept → peek
  valid AUTH → TUNNEL (TCP+UDP flows, DNS upstream)
  else → STATIC web fallback only (default)
4.6 SOCKS5
Optional на desktop, default off если full_tunnel on; debug only.

5. Full tunnel safety (обязательно)
Как v1.4 lifecycle, плюс DNS:

Resolve server hostname до up (можно system DNS один раз до tunnel) → pin IP.
Snapshot routes и DNS.
Create TUN/Wintun → configure address/MTU.
Pin server route via old GW.
Apply direct rules.
Default route → TUN.
Force DNS → tunnel DNS (virtual resolver / interface DNS = tunnel IP).
Healthcheck optional.
On any fail → rollback routes+DNS+TUN.
down/crash/reboot: force_cleanup restore snapshot (persistent file, e.g. %ProgramData%\AetherLink\state.json / /var/lib/aetherlink/state.json).
Идемпотентность up/down. Mutex на reconfigure.

Тесты:

up → DNS query leaves only via tunnel path (capture mark / no ISP DNS);
up → kill → cleanup → network+DNS ok;
failed auth → no broken routes;
domain direct rule: resolve via tunnel, connect direct to IP.
6. Routing rules
YAML

routing:
  default_action: tunnel
  dns_mode: tunnel          # FIXED: only tunnel in v1.5; system = forbidden when up
  include_private_lan_direct: true
  rules:
    - name: lan
      action: direct
      priority: 10
      when: { cidr: "192.168.0.0/16" }
    - name: site
      action: direct
      priority: 50
      when: { suffix: ".example.com" }
    - name: host
      action: direct
      priority: 50
      when: { domain: "api.example.com" }
    - name: one
      action: direct
      priority: 40
      when: { ip: "198.51.100.10" }
    - name: pool
      action: direct
      priority: 40
      when: { ip_range: "203.0.113.10-203.0.113.50" }
Match types: ip, cidr, ip_range, domain (exact), suffix (поддомены: .example.com matches a.b.example.com).

Domain/suffix → IP materialization:

resolve through tunnel DNS;
install host routes direct;
re-resolve with debounce (min 30s / TTL).
7. Платформы
Артефакт	Роль
Rust core	aetherlink_core dll/so	всё
.NET Server linux/win	self-contained host	FFI server_start, service
.NET Client linux/win	self-contained host	FFI up/down, Wintun/TUN load
Android phone/TV	APK	VpnService fd → FFI, split UI
CLI	optional rust or .NET	thin
Wintun: как v2rayN — wintun.dll рядом, create adapter, session, ring buffers → IP packets into core.

Linux: TUN + ip route/ip rule.

Android: Builder.establish() → fd в core; split allow/deny; DNS via VpnService DNS servers = tunnel DNS.

8. Конфиг (client example)
YAML

client:
  server_addr: "server.example.com:443"
  outer_sni: "server.example.com"
  psk: "change-me-high-entropy"
  pad_multiple: 128
  keepalive_s: 15

full_tunnel:
  enabled: true
  mtu: 1400
  kill_switch: false
  restore_on_exit: true
  include_private_lan_direct: true
  # dns only through tunnel — no system DNS when connected
  dns_mode: tunnel

routing:
  default_action: tunnel
  rules: []

# Android only:
# split_tunnel: { mode: all, apps: [] }
Server:

YAML

server:
  listen: "0.0.0.0:443"
  tls_cert: "..."
  tls_key: "..."
  psk: "..."
  local_static_root: "./fallback"
  dns_upstream:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  max_streams: 4096
9. Структура репо
text

protocol/  or crates/     # Rust workspace: core, ffi, netstack, server-lib, client-lib
dotnet/                   # thin hosts Server/Client only
apps/android/
deploy/linux|windows|docker
configs/
scripts/
docs/SPEC DECISIONS STATUS FULL_TUNNEL ROUTING DNS DEPLOY_* BUILD
dist/                     # dll/so + hosts publish
testdata/                 # golden vectors
README — 10–20 строк как запустить; без маркетинга.

10. План работ
Bootstrap
Rust frame/crypto/AUTH + golden
Mux TCP OPEN + DATA
UDP flows + DNS virtual path
Server static fallback + tunnel relay TCP/UDP/DNS
FFI C API + smoke from C or .NET
Linux TUN + netstack + full tunnel safety + DNS no leak
Routing rules engine
Windows Wintun (v2rayN-style) + .NET host
.NET server host + services
Android/TV VpnService + split + DNS
deploy scripts + lifecycle tests
11. DoD
 Один Rust core; нет protocol stack в C#/Kotlin
 FFI up/down/server работает
 TCP+UDP через туннель (netstack)
 DNS при up только через туннель (тест no leak)
 Domain direct: resolve via tunnel, connect direct
 Wintun path Windows (как v2rayN-класс)
 Linux TUN full tunnel + rollback
 .NET hosts self-contained win/linux
 Android+TV split default all
 G2 static fallback
 force_cleanup restores network+DNS
 DEPLOY_LINUX/WINDOWS (личный, с нуля)
12. Defaults
dns_mode: tunnel only when connected
kill_switch: false
LAN direct: true
split: Android only, default all
fallback: static only
fingerprint: rust core best-effort
13. DECISIONS must record
netstack crate choice
TUN IP subnet (e.g. 10.255.0.0/30) + virtual DNS IP
UDP frame layout (type 7/8)
Wintun version/license path
DNS upstream list
nonce replay TTL
14. Non-goals MVP
второй crypto stack на .NET
per-app split Windows/Linux
kill switch complex
ECH обязательно
open reverse-proxy fallback
README polish
15. Цикл
Шаги 0–11 автономно. PARTIAL только если нет Windows/Android в среде — код+docs всё равно.

16. Отчёт
text

## Отчёт AetherLink
- Статус:
- Core/FFI:
- TUN/Wintun/netstack:
- DNS no-leak:
- Routing rules:
- .NET hosts:
- Android/TV:
- Tests:
- Отклонения:
- Пути:
17. Старт
Немедленно Шаг 0 → 11.

text


