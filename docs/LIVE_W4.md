# LIVE W4 — живой прогон под админом (чек-лист)

Цель: доказать сквозной тракт TUN→mux→сервер→цель и обратно на реальной
паре Windows (админ) ↔ VPS `selmedia.ru:443`. Каждый пункт подписывается
ручкой (дата + OK/FAIL); FAIL останавливает прогон и уходит в issues.

Предусловия: `wintun.dll` рядом с exe (см. `deploy/windows/install.ps1`),
релиз собран (`cargo build --release -p aetherlink-ffi` + стейджинг
`aetherlink_ffi.dll → aetherlink_core.dll`), сервер на VPS `active`
(`docs/DEPLOY_UBUNTU.md`), PowerShell **от администратора**.

## Прогон

- [ ] 1. `.\scripts\run_server_windows.ps1` локально (дым: сервер слушает;
      промыть: `openssl s_client -connect 127.0.0.1:443 -tls1_3 -alpn h2`).
- [ ] 2. `.\scripts\run_client_windows.ps1` (админ): `up` — TUN `aether0`
      `10.255.0.2`, default `0.0.0.0/0` через TUN, DNS `10.255.0.1`,
      пин сервера через старый gateway (`route print -4` до/после в лог).
- [ ] 3. `curl` через туннель (HTTP к белому IP): ответ пришёл, в логе
      сервера виден OPEN_TCP с тем же id, что выдал клиентский памп.
- [ ] 4. DNS: `nslookup example.com 10.255.0.1` отвечает; захват показывает
      запросы только через TUN (no-leak).
- [ ] 5. `down`: таблица/DNS как до `up` (сверить с шагом 2), state-файл удалён.
- [ ] 6. `kill -9` клиента в состоянии up → `force_cleanup` → сеть+DNS целы
      (пинг шлюза + резолв без туннеля).
- [ ] 7. domain-direct: правило на домен — резолв через туннель, коннект
      напрямую (пин маршрута виден в `route print -4`).

## Прогон 2026-09-22 (чистый цикл, без V2RayN)

- [x] 2. `up`: TUN `aether0` `10.255.0.2/30`, default `0.0.0.0/0` через
  `10.255.0.1`, пин сервера, LAN-direct (10/8, 172.16/12, 192.168/16),
  DNS `10.255.0.1` на физическом интерфейсе.
- [x] 5. `down` (команда `down`, не Ctrl+C): таблица/DNS как до `up`,
  state-файл удалён, адаптер `aether0` удалён (в `ncpa.cpl` не копится).
- Примечания: V2RayN на время теста ВЫКЛ (его default metric 0 всё
  равно выиграет); `127.0.0.4` вместо `127.0.0.1` (там висит ssh);
  Ctrl+C до процесса через pipe может не дойти — штатный путь это
  `...exe client.local.yaml down`; `[Console]::OutputEncoding = UTF8`
  перед запуском, иначе кракозябры; `$env:AETHERLINK_DEBUG='1'` для трасс.
- [ ] 3. `curl` через туннель (ждёт пришивки транспорта в `up()`).
- [ ] 4. DNS no-leak захватом (то же).
- [ ] 6. `kill -9` → cleanup (журнал replay готов, нужен прогон).
- [ ] 7. domain-direct (то же).

## Остаточная проводка (закрыто кодом)

~~Памп-потоки ездят поверх `TcpStream`~~ — закрыто: `spawn_pump_tls`
одна нить владеет `ClientTlsStream` (таймаут через `get_mut()`),
`Client::start_pump_tls` принимает `lifecycle::connect`-туннель целиком,
тесты `pump_tls.rs` гоняют roundtrip внутри настоящего localhost-TLS.
Продуктовый `up()`: `connect()` → `start_pump_tls()` → работа;
FFI поверхность не менялась (шов — `Client`, сечение `check_thin_hosts`
зелёное). Живому прогону нужны только привилегии: реальный TUN
(`wintun.dll` + админ) и сеть до VPS.
