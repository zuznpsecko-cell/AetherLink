# PLAN_ANDROID — доведение Android-клиента AetherLink до рабочего состояния (TDD)

_Составлен: 2026-10-20. Переработан под TDD: 2026-10-22. Основание: аудит `apps/android`, `crates/aetherlink-client`, `crates/aetherlink-ffi`, `crates/aetherlink-netstack`._

Статус: **черновик к исполнению**. Реализация начинается после подтверждения плана.

**Методология (как в `PLAN_FINAL_TDD.md`):** каждый шаг — **Red → Green → Refactor → ворота**. Падающий тест пишется первым и должен упасть по ожидаемой причине; production-код появляется только чтобы сделать его зелёным. Шаг не закрыт, пока в `docs/ANDROID.md` (TDD-журнал) не записано: ID шага, имя теста, команда, красный вывод, зелёный вывод, коммиты `red:`/`green:`.

---

## 0. Резюме

Сейчас Android-часть — каркас:

- нет `Activity`/LAUNCHER, нет `VpnService.prepare()`, нет UI и хранения конфига;
- `AetherVpnService.handle()` всегда `0L`, поэтому все JNI-вызовы возвращают `InvalidHandle`;
- `setTunFd` только складывает fd в `HashMap`, потребителя нет;
- в Rust нет Android-платформы: `Client::up()` жёстко Windows-only (`route`/`ipconfig`/`netsh`/Wintun);
- JNI `clientUp` вызывает `Client::up()` вместо `up_full()`, транспорт/pump не стартует;
- `protect()` для сокета к серверу не вызывается (риск петли маршрутизации);
- нет foreground-сервиса, `onRevoke`, обработки смены сети;
- `.so` в `jniLibs` не в git, скрипта сборки нет; бинарники от 2026-09-18 при исходниках от 2026-10-20;
- **нет Gradle wrapper и корневого `build.gradle`** — сборка невоспроизводима;
- **нет ни одного теста** (ни Rust-Android, ни Kotlin JVM, ни instrumentation);
- split tunneling: **на Windows он не реализован** — `lifecycle::up` ставит только direct-маршруты из IP-правил, режимы `allow`/`deny`/`subnets` не реализованы и не проверялись; `split_tunnel` в конфиге закомментирован и не парсится. На Android ничего не применяется, `setSplitConfig` только «стейджится». **Готового работающего референса нет** — Android-split делаем с нуля.

Цель плана — получить **устанавливаемое, запускаемое и реально тоннелирующее** Android-приложение с full tunnel и раздельным туннелированием (per-app + подсети), с воспроизводимой сборкой и проверяемыми критериями приёмки, **разработанное через TDD**.

---

## 1. Что считаем «рабочим» (Definition of Done)

Приложение считается готовым, когда на реальном устройстве или эмуляторе:

1. APK собирается из чистого клона одной командой (wrapper + Rust core + `.so` + Gradle).
2. Приложение открывается из лаунчера, сохраняет конфиг (сервер, SNI, PSK, CA, список приложений).
3. Нажатие Connect: системный диалог согласия VPN → статус `Up`, `pump_alive=true`.
4. Весь IPv4-трафик устройства идёт через туннель: внешний IP равен IP VPS; HTTP/HTTPS и DNS работают.
5. IPv6 не утекает: Builder получает IPv6-«чёрную дыру» (`fd00:1::1/64` + `::/0`), а Rust дропает всё, что не IPv4. Отсутствие IPv6-маршрута само по себе IPv6 **не** блокирует.
6. Split tunneling работает в трёх режимах:
   - `all` (полный туннель, опционально с исключением RFC1918);
   - `allow` / `deny` (per-app allowlist или denylist, не одновременно);
   - `subnets` (в туннель идут только перечисленные CIDR).
   **UI минималистичный:** в интерфейсе доступны только `all` (список приложений пуст) и `allow` (выбранные приложения); `deny`/`subnets` — advanced-конфиг, в UI не выводятся.
7. Disconnect / force-stop / отзыв VPN системой корректно возвращают сеть; повторный Connect работает.
8. Все автоматические ворота зелёные:
   `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo fmt --check`, `gradlew testDebugUnitTest`, `gradlew assembleDebug`,
   `scripts/check_thin_hosts.ps1`, `scripts/check_android_build.ps1`,
   `scripts/check_android_host.ps1`, `scripts/check_jni_symbols.ps1`,
   `scripts/check_no_panic.ps1`.
9. Device-ворота: `gradlew connectedDebugAndroidTest` (при подключённом устройстве) + ручная тест-матрица §7 заполнена.
10. `scripts/check_thin_hosts.ps1` проверяет реальные контракты (Activity, prepare, attach fd, отсутствие крипто в Kotlin), а не подстроки.
11. Для каждого шага плана есть запись в TDD-журнале; багфиксы после реализации начинаются с regression-теста.

---

## 2. TDD-стратегия

### 2.1 Уровни тестов

| Уровень | Где выполняется | Что покрывает | Команда |
|---|---|---|---|
| **L0 Rust host** | Windows/Linux dev-хост | чистая логика: plan JSON, CIDR-вычитание, конфиг, TLS-CA, `connect_protected`, `AndroidTun` через `FdOps` fake, FFI-API | `cargo test --workspace` |
| **L0.5 Android compile** | dev-хост + NDK | код под `#[cfg(target_os = "android")]` компилируется | `cargo check --target aarch64-linux-android -p aetherlink-netstack -p aetherlink-ffi` |
| **L1 Kotlin JVM** | dev-хост (Robolectric/JUnit) | `ConfigStore`, `VpnBuilderSpec`, `ServiceState`, оркестрация сервиса с fake-портами, manifest-контракт, `ConnectFlow` | `gradlew testDebugUnitTest` |
| **L2 Android device** | эмулятор/устройство | реальные `VpnService.protect/establish`, JNI на устройстве, fd-пайплайн, per-app split, revoke | `gradlew connectedDebugAndroidTest` |
| **L3 Live/manual** | устройство + VPS | фактический трафик, DNS, IPv6, смена сети, always-on | тест-матрица §7 |

Правило: **G0–G2 закрываются без устройства** (L0/L0.5 + скрипты). **G3–G5 требуют L2/L3** — это приёмка, а не юнит-тесты.

### 2.2 Тестовые швы (что выносим, чтобы тестировать без устройства)

Без этих швов TDD на Android превращается в «проверим руками». Они — часть дизайна, а не тестовая обвязка.

| Шов | Где | Зачем |
|---|---|---|
| `AndroidPlan` + `plan_json` | `client/src/android_plan.rs` | план интерфейса — чистая функция от `ClientConfig` |
| `subtract_v4(base, excludes)` | `android_plan.rs` | вычитание RFC1918 — чистая функция, property-тесты |
| `connect_protected(..., protector: impl Fn(RawFd) -> bool)` | `client/src/lifecycle.rs` | protector инжектируется; на desktop — no-op |
| `FdOps` trait (`read`/`write`/`poll`/`close`) | `netstack/src/android_tun.rs` | `AndroidTun` тестируется fake-реализацией на любом хосте |
| `TunPackets` + `FakeTun` | `netstack` / `client/tests` | памп и Android-состояние без реального fd |
| `HostKind::Android` в `cleanup` | `client/src/cleanup.rs` | no-op на Android проверяется на хосте |
| `CoreApi` (interface) + `AetherCore` (adapter) | Kotlin | сервис тестируется с fake-core, без JNI |
| `VpnFacade` (interface) + `AndroidVpnFacade` | Kotlin | `VpnService.Builder`/`protect` прячутся за порт; Robolectric не эмулирует `establish()` |
| `VpnBuilderSpec` (чистые данные) | Kotlin | маппинг plan JSON → параметры Builder тестируется на JVM |
| `ServiceState` (машина состояний + listeners) | Kotlin | переходы/ошибки без Android-сервиса |
| `ConsentGate` (interface) | Kotlin | `VpnService.prepare()` заменяется fake в тестах Activity |
| `ConfigCodec` | Kotlin | JSON-кодек конфига без SharedPreferences |
| `NetworkMonitor` (interface) | Kotlin | смена сети/backoff с fake-монитором и fake-часами |

### 2.3 Правила TDD

1. **Нет production-кода без красного теста.** Исключение — декларативные артефакты (manifest, layout, gradle): их «красный тест» — Robolectric-проверка контракта или чек-скрипт, который падает до изменения.
2. **Red падает по правильной причине.** Ассерт на тип ошибки/сообщение/поле, а не «не компилируется». Для нового Kotlin-API допускается сначала тест на интерфейс (компилируется), затем реализация.
3. **Один шаг = один тест-кейс (или связная группа) = один коммит** `red:` затем `green:`.
4. **Багфикс начинается с regression-теста**, воспроизводящего баг.
5. **Детерминизм:** unit-тесты без сети, без `sleep`, без реального времени; таймауты и часы инжектируются.
6. **Секреты:** PSK/ключи не попадают в тестовые артефакты, логи и сообщения ошибок (проверяется grep-тестом).
7. **Refactor — только на зелёном**, поведение не меняется.
8. **Нельзя «позеленить» тест удалением ассерта/теста.** Тест можно изменить только если изменилось требование — с записью в журнале.
9. **Живые проверки (L3) не заменяют unit-тесты** и наоборот.

### 2.4 Ворота (команды)

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --target aarch64-linux-android -p aetherlink-netstack -p aetherlink-ffi
.\scripts\check_thin_hosts.ps1
.\scripts\check_android_build.ps1
.\scripts\check_android_host.ps1
Push-Location apps\android; .\gradlew.bat testDebugUnitTest; .\gradlew.bat assembleDebug; Pop-Location
# только при подключённом устройстве:
Push-Location apps\android; .\gradlew.bat connectedDebugAndroidTest; Pop-Location
```

Два Android-гейта разделены намеренно:

- `check_android_build.ps1` — воспроизводимость сборки (wrapper, скрипт, 3 ABI, JNI-символы);
- `check_android_host.ps1` — контракт Kotlin-хоста (Activity, `prepare`, lifecycle, split-UI, thin host).

`check_thin_hosts.ps1` не трогаем до Phase 6: он остаётся зелёным на desktop-хостах, а Android-часть проверяет `check_android_host.ps1`.

### 2.5 TDD-журнал

Файл `docs/ANDROID.md`, раздел «TDD log». Формат строки:

```
P1-R3 subtract_rfc1918 | cargo test -p aetherlink-client android_plan | RED: assertion failed (route 10.0.0.0/8 leaks) | GREEN: ok (12 tests) | red:abc1234 green:def5678
```

Журнал обязателен: без него гейт не закрывается. Скрипт `P6` проверяет, что у каждого `P*-R*` есть запись.

---

## 3. Зафиксированные архитектурные решения

### D1. Порядок жизненного цикла (по документации Android)

```
Activity: VpnService.prepare() + согласие
  → startForegroundService(AetherVpnService)
Service:  startForeground()  (в первые 5 c)
  → clientCreate(configJson)            // Rust: валидация конфига
  → clientPlan(handle)                  // Rust: JSON-план интерфейса
  → Builder(...).establish()            // Kotlin: TUN + маршруты (как в ToyVpn)
  → clientConnect(handle)               // Rust: socket → protect() → TCP → TLS → AUTH
  → pfd.detachFd()                      // владение fd переходит Rust
  → clientAttachTun(handle, fd, mtu)    // Rust: AndroidTun + spawn_pump_tls
  → статус Up
```

Почему так: маршруты появляются только после `establish()`; поэтому `protect()` имеет смысл только после `establish()` и **обязателен до** `connect()` — иначе сокет к серверу уйдёт в туннель (петля). Короткое окно между `establish()` и `attach` — пакеты в TUN-очереди; TCP их ретранслирует, pump стартует сразу после handshake.

Дополнительно:

- Все блокирующие вызовы (`clientConnect`, TLS/AUTH) — на одном worker-executor; `onStartCommand` только сразу вызывает `startForeground` и ставит job. Main thread не блокируется (иначе ANR).
- PSK/CA **не передаются через `Intent`**: сервис читает конфиг из `ConfigStore`. В extras — только команда (`CONNECT`/`DISCONNECT`).

**TDD-следствие:** порядок проверяется L1-тестом `ServiceOrchestrationTest` с fake `CoreApi` + fake `VpnFacade` (журнал вызовов), без устройства; `clientConnect` обязан выполняться не на main thread (проверяется fake-executor/`Thread.currentThread`).

### D2. Владение fd

- `ParcelFileDescriptor.detachFd()` вызывается непосредственно перед `clientAttachTun`.
- Rust сразу заворачивает fd в `AndroidTun` (владение с первой строки JNI-функции); при любой ошибке fd закрывается.
- Kotlin не закрывает fd после `detachFd()`; PFD больше не владеет им.
- Если `clientConnect` упал до `detachFd`, Kotlin закрывает PFD и гасит сервис (fd ещё принадлежит PFD).
- Остановка: Rust закрывает fd при drop → `poll`/`read` в pump завершаются.

**TDD-следствие:** L0-тест `AndroidTun` с fake `FdOps` проверяет «close ровно один раз» и «ошибка attach → close». L1-тест — «attach вернул ошибку → PFD не закрывается повторно».

### D3. `VpnService.protect()` — через JNI-колбэк

- Rust создаёт сокет сам (переиспользуем существующую логику таймаутов/опций), но перед `connect()` вызывает зарегистрированный protector.
- Kotlin:
  ```kotlin
  object AetherCore {
      @Volatile var vpn: AetherVpnService? = null
      @JvmStatic fun protectFd(fd: Int): Boolean = vpn?.protect(fd) ?: false
  }
  ```
- Rust кэширует `JavaVM` при `clientCreate` (в `JNI_OnLoad`/первом вызове) и в protector делает `attach_current_thread` (protector может вызываться не с JVM-потока), затем
  `env.call_static_method("link/aether/client/AetherCore", "protectFd", "(I)Z", ...)`.
- Protector возвращает `false` → `ClientError::PermissionDenied`, connect не начинается.
- На desktop protector не задан — поведение не меняется.

**TDD-следствие:** protector — параметр функции; L0-тест «protector=false → сервер не принял соединение», «protector получил fd сокета до connect».

### D4. Split tunneling на Android: что реально возможно

VpnService умеет **только include-маршруты** и **per-app allow/deny**. Поэтому:

> **Не опираемся на Windows-split.** На Windows раздельного туннелирования фактически нет: `lifecycle::up` добавляет лишь direct-маршруты для IP-правил, а `allow`/`deny`/`subnets` и per-app не реализованы. Поэтому `android_plan.rs` не переиспользует `lifecycle`-путь и не считается «вторым хостом поверх готового движка»: семантика режимов реализуется и тестируется заново. Из `routing.rs` берём только типы (`Matcher`, `Action`) как справочник, не как проверенное поведение.

| Режим | Реализация |
|---|---|
| `all` | `addRoute("0.0.0.0", 0)`; при `include_private_lan_direct: true` — вычитаем RFC1918 из `0/0` (Rust считает список префиксов) |
| `allow` | `addRoute(0/0)` + `addAllowedApplication(pkg...)` |
| `deny` | `addRoute(0/0)` + `addDisallowedApplication(pkg...)` |
| `subnets` | `addRoute(cidr...)` только для перечисленных подсетей, без `0/0` |

Ограничения (фиксируем явно, не пытаемся «побороть»):

- **domain/suffix-based direct на Android невозможен** средствами VpnService (нет exclude-маршрутов, домен → IP неизвестен до DNS). Доменные правила остаются desktop-only; на Android UI это пишет текстом.
- allow и deny нельзя смешивать (`UnsupportedOperationException`); режим выбирается одним значением.
- per-app списки применяются только при `establish()`: смена списка = пересоздание VPN. `addAllowedApplication`/`addDisallowedApplication` бросают, если пакет не установлен — ловим и показываем предупреждение, не крашим сервис.
- **IPv6:** отсутствие IPv6-маршрута НЕ блокирует утечку — IPv6-трафик уйдёт через физический интерфейс. Поэтому всегда добавляем «чёрную дыру»: `addAddress("fd00:1::1", 64)` + `addRoute("::", 0)`; `AndroidTun`/pump дропает всё, что не IPv4. Это и есть anti-leak.
- **DNS-маршрут:** `10.255.0.1/32` всегда входит в план и в `Builder.addRoute`, даже в режиме `subnets` и при вычитании RFC1918; иначе DNS-запросы не попадут в туннель. Адрес туннеля (`10.255.0.0/30`) также никогда не исключается.

**UI-минимум (2 экрана):**

1. **Главное окно:** поля `Server`, `SNI`, `PSK` (маскированный ввод), `CA` (вставка/выбор файла), строка статуса, кнопка `Connect`/`Disconnect`, кнопка `Приложения`. Никаких лишних кнопок и переключателей режимов.
2. **Экран «Приложения»:** список установленных приложений с чекбоксами + поиск; выбрано «через туннель только эти». Пустой список = все приложения (`mode: all`), непустой = `mode: allow`.

`deny` и `subnets` остаются в движке и конфиге, но **не выводятся в UI** (advanced). Это осознанное упрощение: два экрана, один список.

**UI-стиль:** один вертикальный `LinearLayout` с отступами, системная светлая/тёмная тема, крупная кнопка `Connect`, статус — `TextView` под ней, `Приложения` — вторичная кнопка. Без тулбаров, иконок, анимаций и кастомных шрифтов. В списке приложений — `CheckBox`-строки и поле поиска; выбор сохраняется сразу при переключении (без отдельной кнопки Save).

**TDD-следствие:** вся семантика режимов — в `AndroidPlan` (L0). L1-тест `VpnBuilderSpec` проверяет «ровно один тип списка», «subnets без 0/0». L2 — реальные `addAllowed/Disallowed`.

### D5. Android не использует `lifecycle::up()` / `RealPlatform`

`lifecycle::up` — Windows-сценарий (snapshot, `route`, `netsh`, DNS, state-файл). На Android маршрутизацию и DNS задаёт `VpnService.Builder`, поэтому Android-путь:

- не вызывает `lifecycle::up`/`Client::up`;
- использует только `lifecycle::connect*` (TLS+AUTH) и `threads::spawn_pump_tls`;
- не пишет `/var/lib/aetherlink/state.json`;
- `forceCleanup()` на Android — no-op (система сама убирает VPN-интерфейс).

`RealPlatform` и desktop-путь не трогаем, чтобы не регрессировать Windows/Linux-хосты.

**TDD-следствие:** L0-тест «Android cleanup — Ok и не трогает пути»; регресс desktop-тестов — стоп-условие.

### D6. TLS-доверие

Реальный деплой использует самоподписанный/внутренний CA (`ca-cert.pem`, `cert.pem`, SNI `selmedia.ru`). На Android системное хранилище Android недоступно `rustls-native-certs`.

Решение:

- новое поле `client.tls.ca_pem` (inline PEM, строка) — добавляется в `RootCertStore` вместе с системными и webpki-корнями; если `rustls-native-certs` на Android недоступен — **не падаем**, используем webpki + `ca_pem`;
- Kotlin читает выбранный файл/вставленный текст и кладёт PEM в JSON конфига;
- `insecure_skip_verify` **не добавляем** (осознанно; для лабораторных тестов — отдельный тестовый конфиг с CA).
- Требование к сертификату: SAN должен содержать `outer_sni` (нынешний `selmedia.ru`).

**TDD-следствие:** L0-тест «валидный PEM → RootCertStore содержит сертификат», «битый PEM → ConfigError», «без CA поведение desktop не меняется»; grep-тест «в коде нет `dangerous()`/skip-verify».

### D7. Воспроизводимая сборка

- `.so` не коммитим (уже в `.gitignore`), но добавляем скрипты:
  - `scripts/build_android.ps1`, `scripts/build_android.sh`
  - `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o apps/android/app/src/main/jniLibs build --release -p aetherlink-ffi`
- Добавляем **Gradle wrapper 8.10.2** и корневой `apps/android/build.gradle` (сейчас их нет).
- Скрипт проверяет наличие `cargo-ndk`, NDK и Java 21, печатает путь к APK.
- `scripts/check_android_build.ps1` проверяет артефакт (ABI, JNI-символы, свежесть `.so`).

**TDD-следствие:** чек-скрипт пишется первым и падает на текущем HEAD.

---

## 4. Контракт API

### 4.1 JNI-поверхность (`link.aether.client.AetherCore`)

```kotlin
object AetherCore : CoreApi {
    init { System.loadLibrary("aetherlink_core") }

    external fun clientCreate(configJson: String): Long   // 0 = ошибка
    external fun clientPlan(handle: Long): String         // JSON; "" = ошибка
    external fun clientConnect(handle: Long): Int         // resolve+protect+TCP+TLS+AUTH
    external fun clientAttachTun(handle: Long, fd: Int, mtu: Int): Int
    external fun clientDisconnect(handle: Long): Int
    external fun clientFree(handle: Long): Int
    external fun clientStatus(handle: Long): String       // JSON статуса
    external fun lastError(): String                      // текст последней ошибки

    @Volatile var vpn: AetherVpnService? = null
    @JvmStatic fun protectFd(fd: Int): Boolean = vpn?.protect(fd) ?: false
}
```

Коды ошибок — существующий `AetherError` (`0`, `-1…-11`). JNI-функции обязаны:

- писать текст ошибки в **глобальный** слот `LAST_ERROR` (`Mutex<Option<String>>`), не thread-local: `lastError()` может вызываться с другого потока, чем упавший вызов;
- не паниковать на невалидных handle/fd (проверять до `unwrap`);
- очищать `LAST_ERROR` при успехе (семантика фиксируется тестом).

`CoreApi` — Kotlin-интерфейс с теми же сигнатурами; `AetherCore` — единственная реализация. Это позволяет L1-тестам подменять core. JNI-адаптеры остаются тонкими: вся логика — в Rust-функциях `android_api`, которые тестируются на хосте (L0).

C ABI (`aether_client_*`) сохраняется для Windows/.NET. Функции `aether_client_android_set_tun_fd` / `aether_client_set_split_config` переводятся на реальную реализацию (не staging) либо помечаются deprecated и не используются Android-хостом.

### 4.2 Plan JSON (`clientPlan`)

```json
{
  "session": "AetherLink",
  "mtu": 1400,
  "address": { "ip": "10.255.0.2", "prefix": 30 },
  "dns": ["10.255.0.1"],
  "routes": [
    { "ip": "0.0.0.0", "prefix": 5 },
    { "ip": "8.0.0.0", "prefix": 7 },
    { "ip": "10.255.0.1", "prefix": 32 }
  ],
  "apps": { "mode": "all", "packages": [] },
  "block_ipv6": true
}
```

- `routes` — итог вычитания RFC1918 (если `include_private_lan_direct: true`) или список подсетей; **всегда** содержит `10.255.0.1/32` (DNS) и не исключает адрес туннеля `10.255.0.0/30`.
- `apps.mode`: `all | allow | deny`.
- Kotlin применяет ровно один тип списка приложений.
- `block_ipv6: true` → Kotlin добавляет IPv6-«чёрную дыру» (`fd00:1::1/64` + `::/0`); Rust дропает не-IPv4 пакеты из TUN.
- JSON — контракт: L0-тест сравнивает точную схему (snake_case, порядок не важен, лишние поля запрещены).

### 4.3 Дополнения конфига клиента

Добавить в `ClientConfig` (desktop игнорирует, парсинг не должен ломаться):

```yaml
client:
  server_addr: "31.57.158.233:443"
  outer_sni: "selmedia.ru"
  psk: "..."
  tls:
    ca_pem: |            # inline PEM (Android: вставляется из UI)
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----

android:
  split:
    mode: all            # all | allow | deny | subnets
    apps: []             # package names для allow/deny
    subnets: []          # CIDR для mode: subnets
  use_full_tunnel_lan_direct: true   # вычитать RFC1918 из 0/0 (по умолчанию = full_tunnel.include_private_lan_direct)
```

Валидация:

- `mode` — одно из четырёх значений;
- `apps` — непустые строки, допустимые имена пакетов `[A-Za-z0-9._]+`;
- `subnets` — валидные IPv4 CIDR, `prefix <= 32`;
- `allow`/`deny` + `subnets` взаимоисключающи по смыслу: `subnets` берётся только при `mode: subnets`;
- `ca_pem` — парсится `rustls_pemfile::certs`, при ошибке — `ConfigError`.

---

## 5. Работы по фазам (TDD)

Каждая фаза заканчивается гейтом. Внутри фазы шаги выполняются строго по порядку `R → G`; следующий `R` не начинается, пока предыдущий `G` не зелёный.

### Phase 0 — Воспроизводимая сборка и тестовый каркас

| Шаг | Действие | Файлы |
|---|---|---|
| **P0-R1** | Red: `scripts/check_android_build.ps1` — проверяет wrapper, корневой `build.gradle`, скрипт сборки, **всегда пересобирает core**, затем APK, 3 ABI и JNI-символы (свежесть по mtime не проверяем — она врёт). Плюс `scripts/check_android_host.ps1` — контракт Kotlin-хоста (LAUNCHER, `prepare`, `clientConnect`, `clientAttachTun`, отсутствие крипто в Kotlin, split-UI); red-гейт, позеленеет к G3/G4. Запуск на текущем HEAD → FAIL оба | `scripts/check_android_build.ps1`, `scripts/check_android_host.ps1` |
| **P0-G1** | Green: `apps/android/build.gradle`, Gradle wrapper 8.10.2, `scripts/build_android.ps1`, `scripts/build_android.sh`; `check_android_build.ps1` → PASS (3 ABI в APK, JNI-символы), `check_android_host.ps1` остаётся красным до Phase 3 (это ожидаемо) | `apps/android/build.gradle`, `apps/android/gradle/wrapper/*`, `gradlew*`, `scripts/build_android.*` |
| **P0-R2** | Red: `HarnessSmokeTest` — JUnit + Robolectric context (`RuntimeEnvironment.getApplication() != null`), падает, пока нет тестовых зависимостей/`includeAndroidResources` | `apps/android/app/src/test/.../HarnessSmokeTest.kt` |
| **P0-G2** | Green: тестовые зависимости (`junit:junit:4.13.2`, `org.robolectric:robolectric:4.14.1`, `androidx.test:core:1.6.1`, `androidx.test.ext:junit:1.2.1`), `testOptions.unitTests.includeAndroidResources = true`; Robolectric `@Config(sdk=[34])`; smoke зелёный | `app/build.gradle` |
| **P0-R3** | Baseline: зафиксировать текущие `cargo test/clippy/fmt` на HEAD до изменений Rust. Результат: `test --workspace` — один вечный тест (`infinite_fast_download_aborted_by_rst_immediately_allows_upload`), остальное зелёное; `clippy -D warnings` — красный (88 warnings); `fmt --check` — красный (`threads.rs`). Всё — в `docs/LIVE_ISSUES.md`, чистится в P6-R0 | `docs/LIVE_ISSUES.md` |
| **P0-G3** | Обновить `.gitignore`/`README` (сборка через скрипт, `.so` не коммитится) | `.gitignore`, `README.md` |

**Предпосылки P0** (проверяются скриптом): `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`, `cargo-ndk`, Android SDK + NDK (`ANDROID_NDK_HOME`), JDK 17–23 (проверено на 21). Без них G0 не закрывается.

Детали, проверенные практикой и закреплённые в скриптах:

- **JDK:** Gradle 8.10 / AGP 8.6 не тестировались на Java 25 (JBR из Android Studio). `build_android.ps1` перебирает кандидатов и берёт JDK 21 первым; предупреждает, если остался только 24+.
- **Имя библиотеки:** crate собирается как `aetherlink_ffi` (`cargo ndk` кладёт `libaetherlink_ffi.so`), хост грузит `aetherlink_core`. Скрипт **переименовывает** `.so` в `libaetherlink_core.so` — то же правило, что у .NET-хостов (`aetherlink_ffi.dll` → `aetherlink_core.dll`). `Cargo.toml` не переименовываем: это сломало бы C ABI.
- **Прогресс сборки в stderr:** нативные команды вызываются через `cmd /c ... > log 2>&1`, иначе PowerShell с `$ErrorActionPreference=Stop` превращает stderr cargo в `NativeCommandError`, а pipe к Gradle-демону не закрывается и вешает скрипт.
- **Чистка `jniLibs`:** перед сборкой удаляются все `*.so` в ABI-каталогах, чтобы старые библиотеки не попадали в APK.

**Гейт G0:** чистый клон → `scripts/build_android.ps1` → APK; в APK `lib/*/libaetherlink_core.so`; JNI-символы совпадают с `AetherCore.kt`; `check_android_build.ps1` PASS; `check_android_host.ps1` красный (зафиксировано в журнале, позеленеет к G3); `testDebugUnitTest` и `assembleDebug` зелёные; baseline зафиксирован.

---

### Phase 1 — Rust: Android data plane (без UI)

| Шаг | Действие | Файлы |
|---|---|---|
| **P1-R1** | Red: `android_plan_json_all_mode` — точная схема JSON, `mode=all`, `block_ipv6=true`, DNS/address/mtu; `routes` всегда содержит `10.255.0.1/32` | `crates/aetherlink-client/tests/android_plan.rs` (new) |
| **P1-G1** | Green: `AndroidPlan` + `plan_json(&ClientConfig)` | `crates/aetherlink-client/src/android_plan.rs` (new), `src/lib.rs` |
| **P1-R2** | Red: режимы `allow`/`deny`/`subnets` → ожидаемые `routes`/`apps`; невалидные комбинации → ошибка | `android_plan.rs` tests |
| **P1-G2** | Green: маппинг режимов и валидация | `android_plan.rs` |
| **P1-R3** | Red: `subtract_rfc1918` — нет пересечений, public-адреса покрыты, RFC1918 исключены, edge `/0`, `/32`, соседние сети, пустой exclude; **10.255.0.1/32 и 10.255.0.0/30 остаются в маршрутах** | `android_plan.rs` tests |
| **P1-G3** | Green: `subtract_v4` + слияние/нормализация префиксов | `android_plan.rs` |
| **P1-R4** | Red: парсинг `client.tls.ca_pem` и `android.split.*`; валидные/невалидные; desktop-конфиг без секций грузится как раньше | `crates/aetherlink-client/tests/config_android.rs` (new) |
| **P1-G4** | Green: поля + валидация в `ClientConfig` | `client/src/config.rs` |
| **P1-R5** | Red: `connect_protected` — protector вызван до connect и получает fd сокета; `false` → `PermissionDenied`, сервер не принял соединение; `true` → connect; таймаут соблюдён; desktop protector не задан | `client/tests/connect_protected.rs` (new) |
| **P1-G5** | Green: `connect_protected` на `socket2::Socket` | `client/src/lifecycle.rs`, `Cargo.toml` (`socket2` для android/unix) |
| **P1-R6** | Red: `AndroidTun` через fake `FdOps` — один пакет, `EAGAIN` → повтор, короткое чтение → ошибка, `write_all` цикл, `close` ровно один раз | `netstack/src/android_tun.rs` tests |
| **P1-G6** | Green: `AndroidTun` + `FdOps`; `#[cfg(any(target_os = "android", test))]` | `netstack/src/android_tun.rs` (new), `src/lib.rs` |
| **P1-R7** | Red: Android-состояние `Client` с `FakeTun` — connect(protector) против тестового TLS/PSK-сервера, attach fake tun, статус `Up`/`pump_alive`, disconnect останавливает памп | `client/tests/android_state.rs` (new) |
| **P1-G7** | Green: `android_connect/android_attach_tun_with/android_disconnect/android_plan/android_status` | `client/src/lib.rs` |
| **P1-R8** | Red: `force_cleanup_for(HostKind::Android)` → `Ok`, пути не тронуты (fake path provider); desktop поведение прежнее | `client/tests/cleanup_android.rs` (new) |
| **P1-G8** | Green: выбор платформы в `cleanup` | `client/src/cleanup.rs` |
| **P1-R9** | Red: `ca_pem` в TLS — валидный PEM добавляется в `RootCertStore`, битый → `ConfigError`, без CA desktop-путь не меняется, недоступный native-cert-store не валит старт (webpki fallback) | `core/tests/tls_ca.rs` (new) |
| **P1-G9** | Green: `system_client_config_with_ca(Option<&str>)` | `crates/aetherlink-core/src/tls.rs` |

**Гейт G1:** `cargo test --workspace` и `cargo clippy -D warnings` зелёные; `cargo check --target aarch64-linux-android` для netstack/ffi проходит; новые тесты покрывают §P1-R1…R9; desktop-тесты без изменений.

---

### Phase 2 — FFI/JNI: новый контракт

| Шаг | Действие | Файлы |
|---|---|---|
| **P2-R1** | Red: `android_api` — `create` (битый JSON → 0 + last_error), `plan` roundtrip, `connect` без protector → `PermissionDenied`, `attach` с невалидным fd → ошибка без паники, `free` идемпотентен, `status` JSON | `crates/aetherlink-ffi/tests/android_api.rs` (new) |
| **P2-G1** | Green: Rust-API `android_api` поверх `Client`; JNI — тонкий адаптер | `ffi/src/lib.rs`, `ffi/src/jni.rs` |
| **P2-R2** | Red: `LAST_ERROR` — глобальный (не thread-local): непустой после ошибки и читается с другого потока, NUL-safe, очищается на успехе | `ffi/tests/android_api.rs` |
| **P2-G2** | Green: глобальный error-слот (`Mutex`) и семантика очистки | `ffi/src/jni.rs`, `src/lib.rs` |
| **P2-R3** | Red: `scripts/check_jni_symbols.ps1` (или блок в `check_thin_hosts.ps1`) — сверяет `llvm-nm` свежего `.so` со списком; на текущем `.so` FAIL | `scripts/check_jni_symbols.ps1` (new) |
| **P2-G3** | Green: JNI-функции, кэш `JavaVM`, `protect_via_jvm`; символы на месте | `ffi/src/jni.rs` |
| **P2-R4** | Red: удалить staging-мэпы `TUN`/`SPLIT` — падающие тесты на то, что они не используются Android-путём (или deprecated C ABI) | `ffi/src/lib.rs`, `jni.rs` |
| **P2-G4** | Green: реальный attach/split либо явный deprecated-путь | `ffi/src/lib.rs` |
| **P2-R5** | Red: L2 `JniSmokeTest` — `clientCreate("{bad}")` → 0, `lastError()` непустой | `app/src/androidTest/.../JniSmokeTest.kt` (new) |
| **P2-G5** | Green: JNI на устройстве проходит smoke | — |

**Гейт G2:** `cargo test -p aetherlink-ffi` зелёный; `check_jni_symbols` PASS; `clientConnect` с protector=false возвращает `PermissionDenied` и не паникует; device smoke (если устройство подключено) зелёный.

---

### Phase 3 — Kotlin: минимальный рабочий клиент (full tunnel)

| Шаг | Действие | Файлы |
|---|---|---|
| **P3-R1** | Red: `ConfigCodec` — encode/decode roundtrip, обязательные поля, PSK не логируется | `app/src/test/.../ConfigCodecTest.kt` (new) |
| **P3-G1** | Green: `ConfigStore` + `ConfigCodec` (SharedPreferences, PSK private) | `ConfigStore.kt` (new) |
| **P3-R2** | Red: `VpnBuilderSpec` — plan JSON → address/dns/routes/apps; битый JSON → ошибка; ровно один тип списка | `VpnBuilderSpecTest.kt` (new) |
| **P3-G2** | Green: парсер + `VpnBuilderSpec` | `VpnBuilderSpec.kt` (new) |
| **P3-R3** | Red: `ServiceState` — переходы `Idle→Preparing→Connecting→Up→Stopping→Idle`, ошибки, listeners | `ServiceStateTest.kt` (new) |
| **P3-G3** | Green: `ServiceState` | `ServiceState.kt` (new) |
| **P3-R4** | Red: `ServiceOrchestrationTest` (Robolectric + fake `CoreApi`/`VpnFacade`) — порядок вызовов D1 (`establish` до `connect`); `clientConnect` не на main thread; connect fail после `establish` → PFD закрыт и teardown; attach fail → teardown; `onRevoke`/`onDestroy` → teardown; двойной connect идемпотентен; PSK не в `Intent` | `AetherVpnServiceTest.kt` (new) |
| **P3-G4** | Green: переписать `AetherVpnService` под fake-порты + worker-executor | `AetherVpnService.kt` |
| **P3-R5** | Red: `VpnFacade` на устройстве — `establish` возвращает fd, `protect(socket)` true после старта | `app/src/androidTest/.../VpnFacadeTest.kt` (new) |
| **P3-G5** | Green: `AndroidVpnFacade` | `AndroidVpnFacade.kt` (new) |
| **P3-R6** | Red: `ManifestContractTest` — Robolectric: LAUNCHER Activity, `BIND_VPN_SERVICE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`, service `exported=false` + intent-filter `android.net.VpnService`, `foregroundServiceType="specialUse"`; XML-парсер manifest: `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE">` | `ManifestContractTest.kt` (new) |
| **P3-G6** | Green: manifest + `AetherCore.protectFd` + `CoreApi` | `AndroidManifest.xml`, `AetherCore.kt` |
| **P3-R7** | Red: `ConnectFlow` — отказ в consent → сообщение и нет сервиса; согласие → старт сервиса; поля сохраняются; запрос `POST_NOTIFICATIONS` на 33+ | `ConnectFlowTest.kt` (new) |
| **P3-G7** | Green: `MainActivity : ComponentActivity` (нужен для `registerForActivityResult`), минимальный layout (Server/SNI/PSK/CA, статус, Connect/Disconnect, «Приложения»), `ConnectFlow`, runtime-запрос `POST_NOTIFICATIONS` | `MainActivity.kt` (new), `res/layout/activity_main.xml` |
| **P3-R8** | Red: `MainActivity` Robolectric smoke — экран открывается, поля/кнопки на месте, ошибка core отображается; в главном окне нет лишних элементов (только настройки/статус/Connect/«Приложения») | `MainActivityTest.kt` (new) |
| **P3-G8** | Green: доводка UI | `MainActivity.kt` |

**L2-предпосылка:** согласие VPN выдано (`adb shell appops set link.aether.client ACTIVATE_VPN allow`); иначе device-тест помечается `@Ignore` и проверяется вручную.

**Гейт G3 (главный):** L1-тесты зелёные, `assembleDebug` зелёный; на эмуляторе/устройстве:
- Connect → статус `Up`, `pump_alive=true`;
- внешняя проверка IP (браузер/`curl` на устройстве) показывает IP VPS — отдельной кнопки в UI нет;
- браузер открывает HTTPS-сайты, DNS резолвит;
- Disconnect → интернет возвращается; повторный Connect работает;
- force-stop приложения → VPN исчезает, сеть восстанавливается.

---

### Phase 4 — Split tunneling (реализация с нуля, без опоры на Windows)

> Windows-split не является рабочим референсом. Принимается только то, что доказано L0/L1-тестами Android-плана; поведение `routing.rs`/`lifecycle.rs` на Windows не считается эталоном.

| Шаг | Действие | Файлы |
|---|---|---|
| **P4-R1** | Red: Rust — `subnets`/`allow`/`deny` валидация (пустой allow/subnets запрещён, неизвестный формат CIDR — ошибка), план не содержит `0/0` для `subnets` | `android_plan.rs` tests |
| **P4-G1** | Green: доводка валидации | `android_plan.rs`, `config.rs` |
| **P4-R2** | Red: Kotlin — `VpnBuilderSpec` применяет только один список; allow+deny → ошибка; пустой список → ошибка | `SplitSpecTest.kt` (new) |
| **P4-G2** | Green: применение в сервисе | `AetherVpnService.kt` |
| **P4-R3** | Red: модель выбора приложений (`AppPickerModel`) — список с чекбоксами + поиск, выбор/снятие, сохранение; выбранные = идут через туннель; список пакетов доступен через `<queries>`/`QUERY_ALL_PACKAGES` (для MVP — `QUERY_ALL_PACKAGES`; Play-политика вне рамок) | `AppPickerModelTest.kt` (new) |
| **P4-G3** | Green: `AppPickerActivity` (второй и единственный дополнительный экран) + layout | `AppPickerActivity.kt` (new), `res/layout/activity_app_picker.xml` |
| **P4-R4** | Red: смена списка приложений → явное пересоздание VPN (fake); кнопка «Приложения» открывает экран и возвращает сохранённый список | `ConfigChangeTest.kt` (new) |
| **P4-G4** | Green: teardown → connect; навигация главное окно ↔ «Приложения» | `MainActivity.kt`, `AetherVpnService.kt` |
| **P4-R5** | Red: L2 device — allow/deny/subnets/LAN-direct (автоматизируемая часть: `Builder` не бросает, маршруты в статусе) | `app/src/androidTest/.../SplitVpnTest.kt` (new) |
| **P4-G5** | Green: device-тест зелёный; если устройства нет — `BLOCKED(device)` и запись в журнале | — |

**UI-правило:** экран «Приложения» — единственный способ настроить split в UI. Пустой список → `mode: all`; непустой → `mode: allow`. `deny`/`subnets` в UI не выводятся (только конфиг).

**Гейт G4** (L3, ручная матрица §7, строки 8–11):
- allow: выбранные приложения ходят через VPS, остальные — напрямую;
- пустой список: все приложения через VPS (`all`);
- deny: зеркально (проверяется конфигом, не UI);
- subnets: трафик к указанной подсети идёт через туннель, к остальным — напрямую (конфиг);
- LAN-direct: `192.168.x.x` доступен при `include_private_lan_direct: true`;
- allow+deny одновременно невозможно (валидация конфига; UI физически не предлагает deny).

---

### Phase 5 — Hardening

| Шаг | Действие | Файлы |
|---|---|---|
| **P5-R1** | Red: `ReconnectPolicy` — backoff, «pump мёртв» → teardown+reconnect, отмена при disconnect (fake clock) | `ReconnectPolicyTest.kt` (new) |
| **P5-G1** | Green: `NetworkMonitor` + политика | `NetworkMonitor.kt` (new), `AetherVpnService.kt` |
| **P5-R2** | Red: `PumpSupervisor` — `pump_alive=false` → статус ошибки и teardown (без «вечного Up») | `PumpSupervisorTest.kt` (new) |
| **P5-G2** | Green: супервизор | `PumpSupervisor.kt` (new) |
| **P5-R3** | Red: уведомление (Robolectric) — канал, ongoing, action Disconnect, `stopForeground` | `NotificationTest.kt` (new) |
| **P5-G3** | Green: уведомление | `AetherVpnService.kt`, `res/` |
| **P5-R4** | Red: always-on (`null` intent) → загрузка сохранённого конфига | `AlwaysOnTest.kt` (new) |
| **P5-G4** | Green: путь always-on | `AetherVpnService.kt` |
| **P5-R5** | Red: импорт CA — валидный/битый PEM, ошибка понятна, `insecure_skip_verify` отсутствует (grep-тест) | `CaImportTest.kt` (new) |
| **P5-G5** | Green: импорт через SAF + парсинг | `MainActivity.kt`, `ConfigStore.kt` |
| **P5-R6** | Red: `scripts/check_no_panic.ps1` — grep `unwrap(|expect(|panic!` в android-путях; FAIL при находках | `scripts/check_no_panic.ps1` (new) |
| **P5-G6** | Green: убрать/заменить на именованные ошибки | Rust |
| **P5-R7** | Red: логи без секретов — тест на «красные слова» (`psk`, `key`, `secret`) в log-callback | `ffi/tests/log_redaction.rs` (new) |
| **P5-G7** | Green: редактирование логов | `ffi/src/lib.rs`, `jni.rs` |

**Гейт G5** (L2/L3): always-on стартует после перезагрузки; смена Wi-Fi↔LTE восстанавливает туннель; уведомление управляет сервисом; импорт CA работает; в логах нет PSK/ключей.

---

### Phase 6 — Верификация, документация, скрипты

| Шаг | Действие | Файлы |
|---|---|---|
| **P6-R0** | Red: §2.4-ворота красные по baseline P0-R3 — `cargo fmt --check` (`threads.rs`), `cargo clippy -- -D warnings` (88 warnings, первый стоп в `aetherlink-crypto`), вечный тест в `e2e_tunnel`. Зафиксировать повторным прогоном, чтобы отличить долг от регрессий Android-работ | `docs/LIVE_ISSUES.md` |
| **P6-G0** | Green: `cargo fmt` одним коммитом; clippy-чистка (unsafe-блоки, `# Safety`, unused imports, `match` → `?`); решение по вечному тесту (fix или `#[ignore = "…"]` с issue); `cargo test --workspace` завершается | Rust |
| **P6-R1** | Проверка: `check_thin_hosts.ps1` (реальные проверки написаны ещё в P0-R1) — финальный прогон; red на старом скелете зафиксирован в журнале | `scripts/check_thin_hosts.ps1` |
| **P6-G1** | Green: скрипт проходит на новом коде | `scripts/check_thin_hosts.ps1` |
| **P6-R2** | Red: `scripts/check_tdd_log.ps1` — у каждого `P*-R*` есть запись в `docs/ANDROID.md` (сам P6-R2 и шаги `BLOCKED(device)` исключаются); сейчас FAIL | `scripts/check_tdd_log.ps1` (new) |
| **P6-G2** | Green: журнал заполнен по всем шагам | `docs/ANDROID.md` |
| **P6-R3** | Red: `docs/ANDROID.md` содержит сборку/установку/конфиг/режимы split/ограничения/troubleshooting; `check_quickstart.ps1` не ломается | `docs/ANDROID.md` (new) |
| **P6-G3** | Green: документация соответствует поведению | `docs/ANDROID.md` |
| **P6-R4** | Red: тест-матрица §7 прогнана, результаты внесены | `docs/ANDROID.md` |
| **P6-G4** | Green: `docs/STATUS.md`, `docs/DECISIONS.md` (DEC-013/014) обновлены | `docs/*` |
| **P6-R5** | Red: `scripts/android_smoke.ps1` — adb install + запуск + сброс логов; проверяется на устройстве | `scripts/android_smoke.ps1` (new) |
| **P6-G5** | Green: скрипт работает | `scripts/android_smoke.ps1` |

**Гейт G6:** документация соответствует поведению; `check_thin_hosts.ps1` (red на старом скелете зафиксирован в P0) проходит на новом коде; `check_tdd_log.ps1` PASS; тест-матрица заполнена; финальные ворота §2.4 зелёные (baseline-долг из P0-R3 закрыт в P6-G0).

---

## 6. Файлы, которые будут изменены/созданы

### Rust

- `crates/aetherlink-netstack/src/android_tun.rs` — **new** (`FdOps` + `AndroidTun`, `#[cfg(any(target_os = "android", test))]`)
- `crates/aetherlink-netstack/src/lib.rs` — mod
- `crates/aetherlink-client/src/android_plan.rs` — **new** (чистая логика + тесты)
- `crates/aetherlink-client/src/lib.rs` — Android-состояние и методы
- `crates/aetherlink-client/src/lifecycle.rs` — `connect_protected`
- `crates/aetherlink-client/src/config.rs` — `tls`, `android`
- `crates/aetherlink-client/Cargo.toml` — `socket2` для android/unix
- `crates/aetherlink-core/src/tls.rs` — CA из конфига
- `crates/aetherlink-client/src/cleanup.rs` — no-op на Android
- `crates/aetherlink-ffi/src/jni.rs` — новый контракт, JVM-кэш, ошибки
- `crates/aetherlink-ffi/src/lib.rs` — `android_api`, deprecated staging
- `crates/aetherlink-ffi/tests/android_api.rs` — **new**
- `crates/aetherlink-ffi/tests/log_redaction.rs` — **new**
- `crates/aetherlink-client/tests/android_plan.rs` — **new**
- `crates/aetherlink-client/tests/config_android.rs` — **new**
- `crates/aetherlink-client/tests/connect_protected.rs` — **new**
- `crates/aetherlink-client/tests/android_state.rs` — **new**
- `crates/aetherlink-client/tests/cleanup_android.rs` — **new**
- `crates/aetherlink-core/tests/tls_ca.rs` — **new**

### Android (build/infra)

- `apps/android/build.gradle` — **new** (корневой)
- `apps/android/gradle/wrapper/gradle-wrapper.properties`, `gradlew`, `gradlew.bat` — **new**
- `apps/android/app/build.gradle` — тестовые зависимости, `versionCode 2`
- `apps/android/app/src/main/AndroidManifest.xml`
- `apps/android/app/src/test/java/link/aether/client/` — **new** (L1)
- `apps/android/app/src/androidTest/java/link/aether/client/` — **new** (L2)

### Android (код)

- `.../MainActivity.kt` — **new**
- `.../AetherVpnService.kt` — переписать
- `.../AetherCore.kt` — `CoreApi` + новые external
- `.../CoreApi.kt` — **new**
- `.../VpnFacade.kt`, `.../AndroidVpnFacade.kt` — **new**
- `.../ConfigStore.kt`, `.../ConfigCodec.kt` — **new**
- `.../ServiceState.kt`, `.../ServiceOrchestrator.kt` — **new**
- `.../VpnBuilderSpec.kt`, `.../ConnectFlow.kt` — **new**
- `.../AppPickerActivity.kt`, `.../AppPickerModel.kt` — **new**
- `.../ReconnectPolicy.kt`, `.../NetworkMonitor.kt`, `.../PumpSupervisor.kt` — **new**
- `.../res/layout/activity_main.xml`, `activity_app_picker.xml`, `res/values/strings.xml` — **new**

### Скрипты/доки

- `scripts/build_android.ps1`, `scripts/build_android.sh` — **new**
- `scripts/check_android_build.ps1`, `scripts/check_android_host.ps1`, `scripts/check_jni_symbols.ps1`, `scripts/check_no_panic.ps1`, `scripts/check_tdd_log.ps1`, `scripts/android_smoke.ps1` — **new**
- `scripts/check_thin_hosts.ps1` — обновить (Android-часть в Phase 6, desktop-проверки не ломаются)
- `docs/ANDROID.md` — **new** (включая TDD-журнал)
- `docs/DECISIONS.md` (DEC-013/014), `docs/STATUS.md`, `docs/LIVE_ISSUES.md` (если нужно), `README.md`

---

## 7. Тест-матрица

Колонка «Авто»: L0/L1/L2 — автоматизировано, «ручн.» — L3.

| # | Сценарий | Как проверить | Критерий | Авто |
|---|---|---|---|---|
| 1 | Сборка с нуля | чистый клон → `scripts/build_android.ps1` | APK + 3 `.so`, символы JNI на месте | скрипт |
| 2 | Запуск | установка, иконка в лаунчере | Activity открывается без краша | L1/L2 |
| 3 | Согласие VPN | Connect без ранее выданного согласия | системный диалог, отказ обрабатывается | L1 + ручн. |
| 4 | Full tunnel IPv4 | Connect + внешняя проверка IP (браузер/`curl`) | IP = VPS | ручн. |
| 5 | HTTP/HTTPS | браузер | сайты открываются | ручн. |
| 6 | DNS | открыть новый домен | резолвится, нет утечки на физический DNS | ручн. |
| 7 | IPv6 | `curl -6` / сайт с AAAA | IPv6 уходит в «чёрную дыру», не работает; утечки нет | ручн. |
| 8 | allow-list | 2 приложения, внешний IP | разрешённое = VPS, остальные = домашний IP | L2 + ручн. |
| 9 | deny-list | зеркально | наоборот | L2 + ручн. |
| 10 | subnets | CIDR + внешний IP | только подсеть через VPS | L2 + ручн. |
| 11 | LAN-direct | `192.168.x.x` при include_private_lan_direct | LAN доступен | L0 + ручн. |
| 12 | Disconnect | кнопка | сеть вернулась, статус Down | L1 + ручн. |
| 13 | Force-stop | `adb shell am force-stop` | VPN исчез, сеть вернулась | ручн. |
| 14 | Revoke | отзыв в настройках | сервис остановлен, сеть вернулась | L1 + ручн. |
| 15 | Повторный Connect | 3 цикла connect/disconnect | без утечек fd/потоков, стабильно | L1 + ручн. |
| 16 | Смена сети | Wi-Fi ↔ LTE | туннель восстанавливается | L1 + ручн. |
| 17 | Always-on | включить в настройках, перезагрузка | VPN поднимается сам | L1 + ручн. |
| 18 | CA | импорт `ca-cert.pem` | TLS проходит; без CA — понятная ошибка | L0/L1 + ручн. |
| 19 | Android 8 / 14 / 15 | эмуляторы | FGS, permissions, VPN работают | ручн. |
| 20 | Android TV | D-pad | UI управляется пультом | ручн. |

---

## 8. Риски и меры

| Риск | Мера |
|---|---|
| Петля маршрутизации (сокет к серверу уходит в VPN) | `protect()` до `connect()`; L0-тест `connect_protected` с `protector=false` |
| Android убьёт сервис | `startForeground` ≤5 c, тип `specialUse`, уведомление; тест на 14/15 |
| `addAllowed` + `addDisallowed` → `UnsupportedOperationException` | Один режим в UI и в plan JSON; L0/L1 взаимоисключающая валидация |
| Смена split-списка не применяется | Явное пересоздание VPN (teardown → connect); L1-тест |
| CA/SNI не совпадают | Валидация `outer_sni` и SAN при импорте; понятная ошибка TLS |
| `rustls-native-certs` на Android не видит системные корни | CA из конфига + webpki fallback; L0-тест с CA |
| `panic=abort` убьёт процесс | `check_no_panic.ps1`; проверки fd/handle до работы |
| `.so` снова устареет | `build_android` + `check_android_build`; версия/дата в APK |
| Per-app split и always-on конфликтуют | Документировать: при always-on списки фиксируются на момент establish |
| VpnService на эмуляторе ведёт себя иначе | L3 на реальном устройстве обязателен (G3) |
| Нет Gradle wrapper / сборка невоспроизводима | P0: wrapper 8.10.2 + корневой `build.gradle` + чек-скрипт |
| Windows-split не реализован — его нельзя использовать как готовый компонент | Android-split реализуется независимо в `android_plan.rs` + `VpnBuilderSpec`; `routing.rs` — только справочник типов; приёмка только по L0/L1/L2-тестам Android-пути |
| Robolectric не эмулирует `VpnService.Builder.establish()` | `VpnFacade`-порт; реальный Builder — только L2 |
| IPv6-утечка: нет IPv6-маршрута — трафик уходит мимо VPN | «Чёрная дыра» `fd00:1::1/64` + `::/0`, Rust дропает не-IPv4; L3-проверка `curl -6` |
| DNS не идёт в туннель в `subnets`/LAN-direct | `10.255.0.1/32` всегда в плане и маршрутах; L0-тест |
| Блокирующий `clientConnect` на main thread → ANR | worker-executor; L1-тест «не main thread» |
| Нет runtime-разрешения `POST_NOTIFICATIONS` на 33+ | запрос в Activity до старта сервиса; L1-тест |
| Список приложений недоступен на API 30+ | `QUERY_ALL_PACKAGES` для MVP (Play — вне рамок) или `<queries>` |
| Тест «зеленеет» из-за отсутствия ассерта | Ревью каждого `R`-шага: ассерт на причину, `check_tdd_log.ps1` |

---

## 9. Вне рамок (сознательно)

- IPv6-туннель (IPv6 блокируется «чёрной дырой» — это anti-leak, не баг).
- Domain/suffix-based direct split на Android (невозможен средствами VpnService; остаётся desktop).
- Kill switch на Android (потребует always-on + собственной блокировки; отдельная задача).
- Play Store-политика, подпись release-ключом, AAB, CI.
- Изменения desktop-хостов (.NET/Windows/Linux) и сервера.
- Переписывание UI на Compose/Material (берём простые View, чтобы не раздувать зависимости).

---

## 10. Порядок исполнения и правила

```
G0  build pipeline + test harness   →  G1  Rust data plane
→  G2  JNI contract                 →  G3  Kotlin MVP (full tunnel works)
→  G4  split tunneling              →  G5  hardening
→  G6  verification + docs
```

Правила:

1. Не начинать фазу, пока предыдущий гейт не зелёный.
2. Внутри фазы — строго `R → G`; следующий `R` только после зелёного `G`.
3. Каждый шаг — отдельный набор коммитов `red:`/`green:`; `.so` не коммитить.
4. Любая правка протокола/крипто — вне рамок; Android-хост не содержит крипто и парсинга кадров.
5. При регрессе desktop-тестов — стоп и разбор (desktop-путь не должен меняться).
6. Живые проверки (G3–G5) фиксировать в `docs/ANDROID.md` с датой, устройством, Android-версией и результатом.
7. TDD-журнал ведётся по ходу, не задним числом; `check_tdd_log.ps1` — часть гейта G6.
8. Если тест требует устройства, а устройства нет — шаг помечается `BLOCKED(device)`, код и L0/L1-часть всё равно закрываются; гейт не закрывается до L3.

---

## 11. Первый рабочий инкремент (что покажем после Phase 3)

- APK с иконкой, минимальным главным окном (Server/SNI/PSK/CA, статус, Connect) и экраном «Приложения».
- Connect → системный запрос VPN → статус Up.
- Весь IPv4-трафик через VPS, DNS через туннель.
- Disconnect/force-stop/revoke возвращают сеть.
- Внешняя проверка IP показывает IP сервера (отдельной кнопки в UI нет).
- Всё вышеперечисленное закрыто L0/L1-тестами (кроме L3-строк матрицы), сборка воспроизводима с чистого клона.

Это минимально доказывает, что Android-клиент живой; split (Phase 4) и hardening (Phase 5) — следующие инкременты.
