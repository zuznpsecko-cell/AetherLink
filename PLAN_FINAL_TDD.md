# PLAN_FINAL_TDD — AetherLink v1.5 до финала без заглушек

Методология: каждый шаг — Red (падающий тест) → Green (минимум кода) → ворота
(`cargo fmt --check`, `clippy --all-targets`, `cargo test --workspace`,
`check_thin_hosts.ps1`, `check_quickstart.ps1`). Ни один шаг не закрыт без
зелёных ворот. Порядок — от транспорта к краям: сначала то, от чего зависят
остальные.

Легенда статусов: DONE — реализовано и покрыто; STUB — честная заглушка
с именованной ошибкой; TODO — отсутствует.

---

## Фаза A. Сессия: AUTH-хендшейк поверх TLS (ядро всего туннеля)

Зависит: ни от чего нового (TLS, AUTH, ключи, mux готовы и покрыты).
Блокирует: B, C, E2E.

- [ ] A1. Red: `core/tests/session_handshake.rs` — клиент/сервер поверх
      localhost-TLS (`tls::accept_tls`/`connect_tls` + rcgen):
      PREFACE (`PROTOCOL_VERSION=1`) → AUTH frame (nonce+token) → сервер
      `verify` → обе стороны `derive_traffic_keys` → DATA туда-обратно через
      `MuxManager::seal_data`/`open_data` теми ключами; чужой PSK → Err;
      повтор nonce → Err (NonceCache).
- [ ] A2. Green: `core/session.rs` — `handshake_client(stream, psk, nonce)`,
      `handshake_server(stream, psk, cache)`, отдающие
      `(MuxManager, SessionKeys)`; PSK/secrets никогда в логах и ошибках.
- [ ] A3. Ворота + `STATUS.md`: session STUB → DONE.

Приёмка: handshake-тесты 5+/5, утечек секретов нет (grep по `psk|secret|key`
в сообщениях ошибок).

## Фаза B. Сервер: accept-loop (fallback + туннель)

Зависит: A. Блокирует: E2E.

- [ ] B1. Red: `server/tests/accept_loop.rs` — TCP-листенер localhost:
      валидный AUTH → поток `tunnel`; мусор/плохой AUTH → `static`
      (проверяется байтами первого ответа, без баннера туннеля);
      OPEN_TCP → байты доходят до локального echo-таргета и обратно;
      UDP DATAGRAM → echo через `relay_udp`.
- [ ] B2. Green: `server/lib.rs::Server::{bind,serve_once}` поверх
      `tls::accept_tls` + `fallback::decide` + `auth::verify` (+ NonceCache
      TTL 5 мин) + `MuxManager` + `dial_tcp`/`relay_udp`/`dns::resolve`.
      `Server::new` хранит конфиг; сеть стартует только в `serve_*`.
- [ ] B3. Убрать `resolve`-стаб? Уже реализован (UDP relay). Остаётся
      TCP-UDP-шины mux↔relay внутри serve-loop — часть B2.

Приёмка: localhost-клиент получает echo через серверный туннель.

## Фаза C. Клиент: полный `up` (пин → снапшот → TUN → TLS → AUTH → mux)

Зависит: A, netstack-platform (D). Блокирует: E2E, FFI-up.

- [ ] C1. Red: `client/tests/up_down.rs` — `up` без привилегий возвращает
      `Err` и не оставляет следов (таблица маршрутов/DNS не тронуты —
      проверка через platform-trait с fake-бэкендом, без root);
      `down` после неуспешного `up` — Ok; повторный `up` — Ok no-op;
      `force_cleanup` чистит fake-состояние.
- [ ] C2. Green: `client/lifecycle.rs::up` — resolve server hostname
      (системный DNS один раз до туннеля) → pin IP → `Snapshot::save` →
      TUN (`netstack`) → pin route → direct-правила (`Ruleset`) → default
      в TUN → DNS в туннель → TLS (`tls::connect_tls`) → `handshake_client`
      → mux. Любая ошибка — rollback по `rollback_plan`, затем Err.
      Mutex на reconfigure; идемпотентность up/down.
- [ ] C3. `Client::up/status` в `client/lib.rs` — делегировать lifecycle;
      `status` возвращает JSON (up/down, server, dns_mode).
- [ ] C4. `client/config.rs` — схема §8 (server_addr, psk, pad_multiple,
      keepalive, full_tunnel.*, routing.*) с валидацией обязательных полей.

Приёмка: fake-бэкенд-тесты зелёные; на машине без прав — чистая ошибка.

## Фаза D. Netstack platform: TUN + smoltcp-памп (нужны права)

Зависит: ничего (идёт параллельно A–C). Требует: Linux root / Windows admin
для живых проверок; юнит-уровень — без прав.

- [ ] D1. Red: `netstack/tests/pump.rs` — IP-пакет (TCP SYN / UDP DNS)
      через `smoltcp_wrapper` превращается в OPEN_TCP/OPEN_UDP + DATAGRAM
      и обратно (ответ собирается в IP-пакет); таблица потоков expiring.
- [ ] D2. Green: `netstack/smoltcp_wrapper.rs` — iface + TCP/UDP сокеты,
      polls, mapping `MuxManager`↔sockets, DNS-перехват к `10.255.0.1:53`.
- [ ] D3. Red: `netstack/tests/tun_io.rs` (помечены `#[ignore]` без прав) —
      open/close устройства, чтение/запись IP-пакета loopback.
- [ ] D4. Green: `netstack/tun.rs::TunInterface::open` — Linux
      `/dev/net/tun` (ioctl; stub with named privilege error until a Linux
      dev host exists), Windows — crate `wintun` **0.5.1** (latest real;
      there is no 0.14): load order exe-dir → CWD, open-or-create adapter,
      `start_session(MAX_RING_CAPACITY)`; `wintun.dll` рядом с хостом.
      DONE on Windows except live run (see Phase W).
- [ ] D5. Живая проверка под root/admin: `up` → ping/TCP через туннель,
      `kill -9` → `force_cleanup` → сеть+DNS целы; снять `#[ignore]`
      локально, в CI оставить ignore с пометкой.

Приёмка: SQUID-памп-тесты зелёные без прав; живые — под правами вручную.

## Фаза E. FFI: остаток C ABI

Зависит: C (rules), D (tun fd), тесты — без прав.

- [ ] E1. Red: `ffi/tests/ffi_surface.rs` — `rules_list/set/reload`
      roundtrip через JSON; `set_log_callback` получает линию без секретов;
      `android_set_tun_fd`/`set_split_config` валидируют хендл и аргументы.
- [ ] E2. Green: `ffi/lib.rs` — rules поверх `client::routing::Ruleset`
      (сериализация/парсинг, reload атомарен); log-callback без
      PSK/session keys (проверяется тестом на красные слова);
      `android_set_tun_fd`/`set_split_config` — валидация + staging
      (применение — в D).
- [ ] E3. JNI: пробросить то же через `ffi/jni.rs` + символы в `llvm-nm`
      (чек уже есть в `check_thin_hosts.ps1`).

Приёмка: все C ABI из §3 вызываются из тестов, TODO в `ffi/lib.rs` — ноль.

## Фаза F. Конфиги ядра и .NET-поверхность

- [ ] F1. `core/config.rs` — общая схема + `load(path)` (JSON→YAML fallback,
      как в FFI `parse_config`; вынести общий парсер в core, FFI — тонкий
      вызов).
- [ ] F2. `Server::new`/`Client::new` принимают типизированный конфиг
      вместо сырого `Value` (parse-don't-validate на границе).
- [ ] F3. .NET: `status` в клиенте печатает JSON; `cleanup` уже есть;
      пересобрать оба хоста 0/0 после изменений FFI.

## Фаза G. E2E: байты сквозь весь тракт (главные ворота финала)

Зависит: A–D. Требует прав только для TUN-ног; core-путь — без.

- [ ] G1. Red: `tests/e2e_tunnel.rs` (корневой интеграционный):
      сервер (localhost) + клиентский mux через `session::handshake_*`
      → OPEN_TCP к локальному echo → `hello` туда-обратно;
      UDP DATAGRAM → echo; DNS-запрос → canned-ответ через
      `dns::resolve`-путь.
- [ ] G2. Green: склейка (в основном уже есть из A–D) + фиксы по красному.
- [ ] G3. Живой E2E под правами (ручной чек-лист в `docs/STATUS.md`):
      `up` → `curl` через туннель → `down`; `kill -9` → cleanup → сеть жива;
      DNS только через туннель (захват/счётчик); domain-direct: резолв через
      туннель, коннект напрямую.

Приёмка G1 зелёная в CI; G3 — подписанный чек-лист.

## Фаза H. Deploy, доки, DoD

- [ ] H1. `deploy/linux/install.sh`, `deploy/windows/install.ps1` — ставить
      из `dist/` (publish-вывод), а не из корня; плюс `uninstall` инверсия.
- [ ] H2. `configs/*.example.yaml` валидируются парсерами C4/F1 в тестах
      (золотые конфиги).
- [ ] H3. `docs/STATUS.md` — правда по фазам; `README` 10–20 строк запуска;
      `DEPLOY_LINUX/WINDOWS` личный с нуля; `PLAN_TDD.md` — архивный пометить.
- [ ] H4. DoD из AGENT_INSTRUCTIONS §11 по пунктам: 1 (один Rust core —
      держит `check_thin_hosts.ps1`), 2 (FFI up/down/server — E1+G1),
      3 (TCP+UDP — G1), 4 (DNS no-leak — G3), 5 (domain direct — G3),
      6 (Wintun — D4), 7 (rollback — C1+D5), 8 (.NET self-contained — F3),
      9 (Android split — on-device чек), 10 (G2 fallback — B1),
      11 (`force_cleanup` — C1+D5), 12 (deploy-доки — H1–H3).
- [ ] H5. Финальные ворота: `cargo test --workspace` 100% зелёных,
      `clippy -D warnings`, `fmt --check`, оба чек-скрипта, `dotnet build`
      0/0, `assembleDebug` 0/0, `grep -rn "not implemented\|TODO" crates/*/src`
      — пусто (кроме осознанных `#[ignore]` живых тестов).

## Фаза I. Сборка сквозного тракта (VPN работает по-настоящему)

Зависит: A–H (все компоненты готовы и покрыты). Требует прав только G3/D5.
Цель: байт из приложения → TUN → сервер → цель и обратно, без стабов
на горячем пути. Каждый шаг — Red → Green → ворота.

- [ ] I1. Mux OPEN-кадры: `MuxManager::seal_open_tcp/seal_open_udp` +
      `parse_open_{tcp,udp}` (цель узнаётся из кадра, а не из тестовой таблицы).
      Red: roundtrip seal→parse в `mux/tests/`; Green: реализация поверх
      `frame::types::Frame::{open_tcp,open_udp}`.
- [ ] I2. Сервер слушает: `Server::bind(addr)` → `TcpListener`;
      `serve_forever` (поток на соединение) строит `ServerCtx` из типизированного
      конфига (`tls::load_cert_key` + `server_config`, `NonceCache`,
      тело static из `local_static_root`-файла); маршруты учатся из OPEN-кадров
      через `register_inbound`; релей dial-кэш уже есть в `accept.rs`.
      Red: `server/tests/bind_serve.rs` — клиент против `bind` на localhost.
- [ ] I3. Клиентский `up`, хвост транспорта: после шагов платформы —
      `tls::connect_tls` + `handshake_client` + памп-поток
      TUN fd ↔ TLS-поток (парсинг `smoltcp_wrapper`, `seal/open` через `MuxManager`).
      Сокетные TCP-state-машины smoltcp — следующим refinement, начать
      со stateless отображения пакет↔кадр + DNS-flow.
- [ ] I4. Ключи сессии в mux тракте сервера: убедиться, что `tunnel_loop`
      использует ключи именно этого handshake (сейчас так, зафиксировать тестом
      на два параллельных соединения с разными PSK).
- [ ] I5. Потоки в FFI: `aether_server_start` поднимает accept-loop в фоне
      и отдаёт хендл; `stop` — join; `client up/down` — аналогично, без
      блокировки вызывающего. Red: тесты на старт/стоп/дабл-старт.
- [ ] I6. Живой E2E под правами (D5/G3 из плана): `up` → `curl` через туннель
      → `down`; `kill -9` → cleanup → сеть жива; DNS только через туннель;
      domain-direct: резолв через туннель, коннект напрямую.
- [ ] I7. E2E-тест без прав как ворота CI: `bind` + handshake + 2 стрима
      через `serve_connection`-путь (расширение `e2e_tunnel.rs`).

Приёмка фазы I: `curl` через поднятый туннель на реальной паре + I7 зелёный.

## Фаза W. Windows bring-up без прав лишних (сделано, кроме живого прогона)

- [x] W1. Парсинг `route print -4` / `ipconfig` без привязки к локали
  (форма строк, а не заголовки) + билдеры аргументов `route`/`netsh`;
  `RealPlatform`: snapshot/apply/restore поверх них
  (`client/tests/windows_net.rs`, 7 тестов).
- [x] W2. Открытие Wintun через крейт 0.5.1: load order, open-or-create,
  session в хендле; без dll/прав — именованные ошибки
  (`netstack/tests/bring_up.rs`, 9 тестов).
- [x] W3. `DataPump` (TUN↔mux мост): `TunPackets` трейт + `try_recv` /
  `send_packet` у `TunInterface` (`Arc<Session>` для wintun 0.5),
  `client/src/pump.rs`, RED-тесты с `FakeTun` в `client/tests/pump.rs`
  (TCP SYN→OPEN+DATA, UDP DNS→OPEN+DATAGRAM, mux→TUN обе стороны,
  тампер/обрыв fail closed, 6 тестов green).
- [x] W4. Памп-потоки в `up()`/`down()`: `client/src/threads.rs`
  (`spawn_pump`/`PumpHandle::stop`, TUN->wire + wire->TUN, `tx`/`rx`
  ключи сессии, тампер дропается без убийства цикла),
  `Client::start_pump`/`stop_pump` (+ `down()` останавливает памп),
  `client/tests/pump_threads.rs` (4 теста: обе стороны, двойной stop,
  `down` останавливает памп), живой чек-лист `docs/LIVE_W4.md`,
  команда `down` в thin-хосте (идемпотентна, Ctrl+C больше не нужен).
- [x] W5. Памп внутри TLS: `DataPump::with_mux` (переиспользует mux сессии),
  `threads::spawn_pump_tls` (одна нить владеет `ClientTlsStream`, ключи
  `tx`/`rx` сессии, таймаут чтения 200мс), `Client::start_pump_tls`,
  `client/tests/pump_tls.rs` (2 теста поверх настоящего localhost-TLS:
  roundtrip туда-обратно, двойной stop).
- [x] W6. Живой цикл Windows (2026-09-22, без V2RayN): `up` поднимает
  `aether0` 10.255.0.2/30 + пин + LAN-direct + default в TUN + DNS в туннель;
  `down`/`cleanup` проигрывают журнал `UpState` (маршруты, DNS на
  persist-интерфейс, удаление адаптера) — чистый цикл доказан живым
  прогоном. По пути починены: удержание wintun-сессии, friendly name,
  OEM/cp866-декод `ipconfig`, `(Основной)`-суффиксы, регистрация newborn
  NIC (enable), `force_cleanup` реально восстанавливает, guard двойного
  `up`. Осталось: пришить `connect()+start_pump_tls()` в `up()` и гнать
  трафик (curl/DNS через туннель).

## Карта заглушек → фазы

| Файл | Заглушка | Фаза |
|---|---|---|
| `core/session.rs` | handshake + key schedule | A |
| `core/config.rs` | схема/парсинг | F1 |
| `server/lib.rs` | accept-loop (bind/serve) | B |
| `client/lifecycle.rs` + `lib.rs` | `up`/`status` | C |
| `client/config.rs` | схема §8 | C4 |
| `netstack/smoltcp_wrapper.rs` | userspace stack + памп | D2 ✅ |
| `netstack/tun.rs` open path | Windows wintun open (Linux ioctls — только под root) | W2 ✅ / D4🔄 |
| `netstack/sockets.rs` | socket-level pump (TCP/UDP state machines) | D-sock ✅ (4 теста) |
| TunPackets + DataPump + pump threads | мост TUN↔mux в `up()`/`down()` | W3 ✅ / W4 ⏳ активное |
| `ffi/lib.rs` | rules, log cb, android fd/split | E |
| `deploy/*` | установка из исходников, нет uninstall | H1 |

## Отложено (после доводки Windows-клиента)

- Android SOCKS5 с ротацией: логин/пароль/порт генерируются перед каждым
  стартом прокси, без авторизации доступа нет. Сейчас SOCKS5 в коде нет
  вообще (ни Rust, ни Kotlin) — проектировать после живого `up` на Windows.

## Риски и требования к среде

- Linux root (или CAP_NET_ADMIN) — D5/G3; Windows admin + `wintun.dll` — D4/G3.
- Android-устройство/ТВ — on-device чек split + VpnService (APK уже собирается).
- Сеть для cargo/Gradle-зависимостей (уже кэшированы: registry, gradle-8.10.2, AGP).
- Java для Gradle — JBR 21 от Rider (Gradle 8.10 не стартует на Java 25 из новой Studio).
