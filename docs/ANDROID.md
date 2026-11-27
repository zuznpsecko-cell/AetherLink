# Android-клиент AetherLink

Статус: **Kotlin-хост написан полностью (Phase 2–4 плана), на устройстве ещё
не проверен.** План: [`PLAN_ANDROID.md`](../PLAN_ANDROID.md).

| Слой | Состояние |
|---|---|
| Ядро для Android (Phase 1: план интерфейса, split, `connect_protected`, `AndroidTun`, cleanup, inline CA) | ✅ готово, тесты на хосте (журнал ниже) |
| FFI/JNI (`crates/aetherlink-ffi/src/android_api.rs`, `jni.rs`) | ✅ 9 JNI-функций: `clientCreate/Plan/Connect/AttachTun/Status/Disconnect/Free`, `lastError`, `forceCleanup`; `clientConnect` защищает сокет через `AetherCore.protectFd` → `VpnService.protect`; panic-safe, отложенный `clientFree` (DEC-024) |
| Kotlin-хост (`apps/android`) | ✅ 13 файлов: `MainActivity`, `AppPickerActivity`, `AetherVpnService` (foreground, worker-поток), `ConfigStore`, L1-тесты Robolectric |
| CI | ✅ job `android`: clippy под Android, `.so` для 3 ABI, Kotlin L1, APK-артефакт `android-debug` |
| Сквозной туннель на устройстве | ⏳ не проверен (L2: нужен телефон/эмулятор и сервер) |

### Поток подключения

1. `MainActivity` сохраняет настройки в `ConfigStore`, проверяет их
   (`ConfigCodec.validate`), на Android 13+ спрашивает `POST_NOTIFICATIONS`,
   затем `VpnService.prepare()` (диалог согласия) и
   `startForegroundService(ACTION_CONNECT)`. В Intent только действие:
   PSK и CA сервис читает из `ConfigStore` сам.
2. `AetherVpnService.onStartCommand` сразу зовёт `startForeground`
   (`specialUse`), вся работа с ядром — на одном worker-потоке.
3. `TunnelSession`: `clientCreate(json)` → `clientConnect` (ядро резолвит
   сервер, создаёт сокет, зовёт `AetherCore.protectFd(fd)` →
   `VpnService.protect(fd)` **до** connect, затем TLS + AUTH) →
   `clientPlan` → `VpnBuilderSpec.applyTo(Builder)` → `establish()` →
   `detachFd()` → `clientAttachTun(h, fd, mtu)`.
   Отличие от D1 плана: `clientConnect` идёт **до** `establish()` — DNS сервера
   резолвится через обычную сеть, а недоступный сервер не оставляет
   полуподнятый интерфейс, который съел бы трафик всех приложений.
4. Раз в 2 с `clientStatus`: если `pump_alive=false`, сервис сам рвёт туннель
   и показывает причину (иначе маршруты и DNS вели бы в мёртвый tun).
5. Отключение (кнопка, действие в уведомлении, `onRevoke`) →
   `clientDisconnect` + `clientFree`, `stopForeground`, `stopSelf`.

Владение fd (D2): после `detachFd()` Kotlin fd не закрывает; если
`clientAttachTun` отказал, fd закрывает ядро (`android_api::attach`). До
`detachFd()` при ошибке закрывается `ParcelFileDescriptor`.

### Текущие ограничения

- На устройстве не запускалось: CI собирает APK и гоняет L1-тесты, но живой
  туннель (L2) нужно проверить руками (см. «Проверка на устройстве»).
- PSK хранится в `SharedPreferences` private mode без шифрования (как YAML
  на десктопе); `allowBackup=false`, чтобы он не уходил в облачный бэкап.
- В UI только режимы `all` / `allow`; `deny` и `subnets` ядро умеет, но из
  приложения их не задать.
- Нет автопереподключения при смене сети: обрыв pump → состояние «Ошибка»,
  подключаться заново кнопкой.
- C ABI по-прежнему staging'ует `aether_client_android_set_tun_fd` /
  `set_split_config` (desktop-путь); через JNI они больше не экспортируются.

## Сборка

```powershell
# из корня репозитория
.\scripts\build_android.ps1
```

Требования: Rust-таргеты `aarch64-linux-android`, `armv7-linux-androideabi`,
`x86_64-linux-android`; `cargo-ndk`; Android SDK + NDK; **JDK 17–23** (проверено
на 21). Gradle 8.10.2 + AGP 8.6.1 на Java 25 (JBR из Android Studio) не
тестировались, поэтому скрипт сам выбирает JDK 21, если `JAVA_HOME` новее.

Скрипт собирает `aetherlink-ffi` под три ABI, переименовывает
`libaetherlink_ffi.so` → `libaetherlink_core.so` в
`app/src/main/jniLibs/<abi>/` (хост грузит `aetherlink_core`, как .NET-хосты
грузят `aetherlink_core.dll`) и запускает `assembleDebug`.
APK: `apps/android/app/build/outputs/apk/debug/app-debug.apk`.

Проверки контрактов:

```powershell
.\scripts\check_android_build.ps1   # wrapper, 3 ABI в APK, JNI-символы
.\scripts\check_android_host.ps1    # контракт Kotlin-хоста (гейтится в CI)
Push-Location apps\android; .\gradlew.bat testDebugUnitTest; Pop-Location
```

`apps/android/gradle.properties` включает `android.useAndroidX=true` — без этого
Robolectric/androidx.test не резолвятся.

## Установка

```powershell
adb install -r apps\android\app\build\outputs\apk\debug\app-debug.apk
```

APK собирает и CI (артефакт `android-debug` в job `android`).

### Проверка на устройстве

1. Открыть AetherLink, ввести сервер (`vpn.example.com` или
   `203.0.113.10:443`), SNI (если отличается), PSK и PEM внутреннего CA.
2. «Подключить» → разрешить уведомления и VPN → статус «Подключено».
3. Проверить: браузер открывает сайты, `adb shell dumpsys connectivity`
   показывает VPN, `adb logcat | Select-String aether` без ошибок.
4. «Приложения» → отметить одно приложение → переподключиться: через туннель
   идёт только оно.
5. Остановить сервер → в течение пары секунд статус «Ошибка: Туннель
   оборвался», интернет возвращается.

## Конфиг

Сервер, SNI, PSK и CA вводятся в главном окне и сохраняются в
`SharedPreferences` (PSK — private mode; не шифруется). PSK короче 16 байт
UTF-8 форма отвергает до подключения («PSK короче 16 байт», как ядро, DEC-025). CA — PEM внутреннего
CA (`ca-cert.pem`); системное хранилище Android клиенту недоступно, поэтому
`client.tls.ca_pem` добавляется к системным и webpki-корням. Проверка
сертификата не отключается: сертификат от другого CA по-прежнему отвергается.

## Split tunneling

Два экрана: главное окно и «Приложения» (список с чекбоксами и поиском,
каждое переключение сохраняется сразу и применяется при следующем
подключении). Не установленные приложения пропускаются и показываются в
статусе.

- список приложений пуст → весь трафик в туннеле (`mode: all`);
- выбраны приложения → через туннель только они (`mode: allow`);
- `deny` и `subnets` — только через конфиг (advanced, в UI не выводятся);
- IPv6 блокируется «чёрной дырой» (`fd00:1::1/64` + `::/0`), не tunnelируется;
- domain/suffix-split на Android невозможен средствами `VpnService`.

## Troubleshooting

- **`JAVA_HOME` указывает на JDK 24+** — Gradle 8.10 падает; поставьте JDK 21
  (Android Studio: `C:\Program Files\Android\openjdk\jdk-21.0.8`).
- **`cargo ndk` не найден** — `cargo install cargo-ndk --version "^3"`.
- **Gradle качает дистрибутив** — первый запуск wrapper скачивает Gradle 8.10.2.
- **`NativeCommandError` от cargo** — скрипт уже гоняет нативные команды через
  `cmd /c`; если вызываете cargo вручную, используйте `cmd /c "cargo ..."`.
- **«Ошибка: UnsatisfiedLinkError»** — в APK нет `libaetherlink_core.so` для
  ABI устройства: собирайте через `build_android.ps1`/`.sh`, не голым Gradle.
- **«connect to server failed: PermissionDenied»** — `VpnService.protect()`
  отказал (согласие VPN отозвано): переподключитесь, подтвердив диалог.
- **«AuthError» / «NetworkError»** — PSK, адрес или CA; текст ошибки ядра
  выводится в статусе. Дальше — `adb logcat | Select-String aether`.

## TDD log

Формат: `шаг | команда | RED | GREEN | коммиты`. Заполняется по ходу работы;
без записи шаг не считается закрытым.

```
P0-R1 build+host contracts | .\scripts\check_android_build.ps1 -SkipBuild; .\scripts\check_android_host.ps1 | RED: build 7 failed (no root build.gradle, no wrapper, no build scripts); host 29 failed (no MainActivity/CoreApi/ConfigStore/..., no LAUNCHER, no FGS specialUse, service is a 0L stub) | GREEN: pending | red: a59a5af
P0-G1 build green | .\scripts\check_android_build.ps1 | RED: 7 build checks failed | GREEN: all android build checks passed (3 ABI libaetherlink_core.so in APK, JNI symbols match AetherCore.kt); APK built in 22s, wrapper 8.10.2, JDK 21 | red: a59a5af green: f29a904
P0-R2 Robolectric harness | Push-Location apps\android; .\gradlew.bat testDebugUnitTest | RED: compileDebugUnitTestKotlin FAILED — Unresolved reference 'junit'/'robolectric'/'androidx.test' (no test dependencies), 18 errors | GREEN: pending | red: e63f01d
P0-G2 harness green | .\gradlew.bat testDebugUnitTest | RED: unresolved references | GREEN: BUILD SUCCESSFUL, HarnessSmokeTest tests=1 failures=0 (78.8s, first Robolectric boot); needs android.useAndroidX=true in gradle.properties | red: e63f01d green: 0cfba1b
P0-R3 baseline cargo gates | cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace | RED: fmt fails in crates/aetherlink-client/src/threads.rs; clippy stops in aetherlink-crypto (unused imports, `next` vs Iterator::next), 88 warnings without -D; test --workspace hangs on aetherlink-server e2e_tunnel::infinite_fast_download_aborted_by_rst_immediately_allows_upload (>50 min). With that test skipped: 0 failed across all binaries | GREEN: n/a (baseline; cleanup moved to P6-R0/G0, recorded in docs/LIVE_ISSUES.md) | red: n/a
P0-G3 repo hygiene + G0 | git clone --no-hardlinks → .\scripts\build_android.ps1; .\scripts\check_android_build.ps1 -SkipBuild | RED: n/a (hygiene) | GREEN: clean clone (commit 9d68bd0) builds APK in 56s Rust + 6s Gradle, exit 0; check PASS in the clone — 3 ABI .so in APK, JNI symbols match; .so is ignored, wrapper jar is tracked, gradlew is LF | green: 9d68bd0
P1-R1 plan JSON contract | cargo test -p aetherlink-client --test android_plan | RED: E0432 unresolved import `aetherlink_client::android_plan` | GREEN: 2 passed (exact key set, tunnel 10.255.0.2/30, DNS /32, apps all, block_ipv6; typed plan == JSON) | red: 9a1f549 green: 4bd35ce
P1-R2 split modes | тот же тест | RED: E0432 unresolved `plan_json_for`/`AndroidSplit`/`SplitMode` (модуль откатан до G1 через git stash) | GREEN: 6 passed (allow/deny lists, subnets = prefixes + DNS, 9 invalid selections → ConfigError) | red: 83f1ccc green: b902a9e
P1-R3 RFC1918 subtraction | тот же тест | RED: E0432 unresolved `subtract_prefixes` | GREEN: 9 passed (LAN-direct: public covered, RFC1918 bypassed, 10.255.0.0/30 + DNS kept; /0, /32, exact/half cut, neighbour split, sibling merge). Одна ошибка была в тесте (/23 вместо /22), реализация верна | red: 2f0b0d3 green: 9f297de
P1-R4 android.split + tls.ca_pem | cargo test -p aetherlink-client --test config_android | RED: E0609 no field `tls_ca_pem`/`android_split` on `ClientConfig` (4 ошибки). GREEN: 7 passed + 9 прежних; desktop-конфиг без новых секций не меняется | red: cb5d04b green: f38db7a
P1-R5 connect_protected | cargo test -p aetherlink-client --test connect_protected | RED: E0432 unresolved `connect_protected`/`SocketHandle`, E0599 no variant `PermissionDenied` | GREEN: 4 passed — protector runs once on the real socket before connect; `false` → `PermissionDenied` и на loopback-листенере нет SYN (nonblocking `accept` → `WouldBlock`); `true` → TLS+AUTH проходит; бюджет 300 мс на TEST-NET-1 соблюдён; `connect()` без protector работает. `socket2` нужен, потому что `TcpStream::connect_timeout` защищает уже после SYN. Правка теста: `expect_err` → `.err().expect(..)`, у `ConnectedTunnel` нет `Debug` | red: 2a1f3ce green: 68c46e0
P1-R6 AndroidTun + FdOps | cargo test -p aetherlink-netstack android_tun | RED: E0432 unresolved `AndroidTun`/`FdOps` (файл с тестами без реализации) | GREEN: 11 passed — один `read` = один пакет, `EAGAIN` → `None`, 3 байта/обрезанный IPv4 → `InvalidPacket`, EOF → `TunError`, `write_all` добивает короткие записи, `EAGAIN` → `poll` → retry, вечно занятый fd → таймаут, `close` ровно один раз (`close()` и `Drop`), битый MTU всё равно закрывает fd. `attach` ставит `O_NONBLOCK`; IPv6 и прочий не-IPv4 `AndroidTun` пропускает как есть, а pump отбрасывает их fail-closed (`parse_ipv4_packet`). Правка теста: импорт `TunPackets` | red: 6420339 green: 83a288d
P1-R7 driven Client flow | cargo test -p aetherlink-client --test android_state | RED: E0599 нет `android_connect`/`android_attach_tun_with`/`android_disconnect`/`android_plan`/`android_status` | GREEN: 6 passed — порядок Kotlin на живом TLS+PSK сервере: `android_connect` (protector ровно один раз) паркует транспорт, `android_attach_tun_with` поднимает pump на FakeTun, `android_status` даёт up/pump_alive/server, `android_disconnect` останавливает pump и сервер видит EOF. Отказ protector → `PermissionDenied` и клиент down; attach без connect → `PlatformError`; disconnect до connect — no-op; `android_plan` несёт configured split; цикл проходит дважды. Правка теста: сервер считает закрытием и `UnexpectedEof`; `expect_err` → match (линт `err_expect`) | red: ee337cf green: 03b0e6f
P1-R8 host-aware cleanup | cargo test -p aetherlink-client --test cleanup_android | RED: E0432 unresolved `force_cleanup_for_with`/`HostKind` | GREEN: 4 passed — `HostKind::Android` только удаляет свой state-файл и не делает ни одного вызова платформы (лог пуст, «протухший» DNS `10.255.0.1` остаётся: им владеет VpnService); отсутствующий файл — Ok; desktop по-прежнему replay'ит лог через платформу, потребляет файл и лечит stale DNS без файла | red: 51c338b green: c8a322c
P1-R9 inline CA PEM | cargo test -p aetherlink-core --test tls_ca | RED: E0425 `system_client_config_with_ca` not found (4 вызова) | GREEN: 4 passed — приватный CA из `ca_pem` подтверждает свой сервер (TLS1.3 handshake + данные), чужой приватный CA отвергается (`TlsError`), desktop без CA тоже его не принимает, битый/пустой PEM → `ConfigError`, `with_ca(None)` эквивалентен `system_client_config()`. CA аддитивный (native + webpki + `ca_pem`), `dangerous()` не используется: доверие доказывается поведением, а не grep'ом; при заданном CA недоступный native-store не фатален (webpki + CA). Клиентский connect передаёт `config.tls_ca_pem`. Правка теста: второе рукопожатие требует новый listener | red: 3dd4985 green: 9aedf76
G1 host-core gate | cargo test --workspace --no-fail-fast -- --skip infinite_fast_download_aborted_by_rst_immediately_allows_upload; cargo ndk --platform 26 -t arm64-v8a check -p aetherlink-core -p aetherlink-client -p aetherlink-netstack -p aetherlink-ffi; cargo clippy --workspace --all-targets; cargo fmt --check | RED: n/a (gate) | GREEN: test — 318 passed, 0 failed (вечный e2e-тест пропущен как baseline P0-R3); ndk check — 4 крейта Finished; clippy — 88 warnings, ровно baseline, в новых файлах 0; fmt — падает только на baseline-файлах (`threads.rs`, `client_tcp.rs`, `pump_tls.rs`, `accept.rs`), долг P6-R0/G0. P1-R1…R9 закрыты; desktop-путь (connect/up/down/cleanup) зелёный | green: 9aedf76
P2-R1 JNI surface for the Android flow | python-эмуляция check_android_build.ps1 (external fun ↔ Java_*) + check_android_host.ps1 | RED: host-гейт 29 failed (P0-R1); JNI экспортировал desktop `clientUp/clientDown/setTunFd/setSplitConfig`, `clientConnect` всегда `PermissionDenied` (protector = None) | GREEN: 9 экспортов = 8 `external fun` + `forceCleanup`; `clientConnect` зовёт `protectFd(I)Z` на инстансе `AetherCore`; отказ `attach` закрывает уже переданный fd | red: P0-R1 green: этот PR (компиляция — CI job android)
P2-R2 TunnelSession orchestration | ./gradlew testDebugUnitTest --tests '*ServiceOrchestrationTest' | RED: n/a — тесты написаны вместе с кодом, локально нет JDK/SDK (честно: RED не наблюдался) | GREEN: pending (CI job android) — порядок create→connect→plan→establish→detach→attach, protector вызывается, отказ на каждом шаге освобождает handle, fd после detach не закрывается, busy-статус ≠ мёртвый туннель | этот PR
P3-R1 UI + FGS + config store | python-эмуляция check_android_host.ps1; ConfigCodecTest | RED: host-гейт 29 failed (P0-R1) | GREEN: эмуляция — 0 failed (13 файлов, LAUNCHER, specialUse, POST_NOTIFICATIONS, нет javax.crypto, нет PSK в extras); ConfigCodecTest — pending (CI) | этот PR
P4-R1 split apply + picker | VpnBuilderSpecTest, AppPickerModelTest | RED: n/a (как P2-R2) | GREEN: pending (CI) — all/allow/deny, IPv6 black hole, пропуск не установленных пакетов, пустой allow не расширяется до «все приложения» | этот PR
L2 device | ручная проверка (раздел «Проверка на устройстве») | RED: — | GREEN: pending (нужен телефон/эмулятор + сервер) | —
```

Примечание к G1: долги baseline, перечисленные в P0-R3 и G1 (88 предупреждений
clippy, `cargo fmt --check` на старых файлах, вечный e2e-тест), позже закрыты:
fmt/clippy `-D warnings`/`cargo test --workspace` зелёные и блокирующие в CI
(DEC-023, `docs/LIVE_ISSUES.md` «Android TDD baseline»).
