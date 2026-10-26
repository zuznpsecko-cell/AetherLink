# Android-клиент AetherLink

Статус: **Phase 0 в работе** (TDD). План: [`PLAN_ANDROID.md`](../PLAN_ANDROID.md).

## Сборка

```powershell
# из корня репозитория
.\scripts\build_android.ps1
```

Требования: Rust-таргеты `aarch64-linux-android`, `armv7-linux-androideabi`,
`x86_64-linux-android`; `cargo-ndk`; Android SDK + NDK; Java 17+ (JBR 21).
Скрипт собирает `aetherlink-ffi` под три ABI в `app/src/main/jniLibs` и запускает
`assembleDebug`. APK: `apps/android/app/build/outputs/apk/debug/app-debug.apk`.

Проверка контракта сборки:

```powershell
.\scripts\check_android_build.ps1
```

## Установка

```powershell
adb install -r apps\android\app\build\outputs\apk\debug\app-debug.apk
adb shell am start -n link.aether.client/.MainActivity
```

## Конфиг

Сервер, SNI, PSK и CA вводятся в главном окне и сохраняются в
`SharedPreferences` (PSK — private mode; не шифруется). CA — PEM внутреннего
CA (`ca-cert.pem`); системное хранилище Android клиенту недоступно.

## Split tunneling

Два экрана: главное окно и «Приложения».

- список приложений пуст → весь трафик в туннеле (`mode: all`);
- выбраны приложения → через туннель только они (`mode: allow`);
- `deny` и `subnets` — только через конфиг (advanced, в UI не выводятся);
- IPv6 блокируется «чёрной дырой» (`fd00:1::1/64` + `::/0`), не tunnelируется;
- domain/suffix-split на Android невозможен средствами `VpnService`.

## Troubleshooting

- **`JAVA_HOME` не найден** — укажите JBR: `F:\Program Files\Android\jbr`.
- **`cargo ndk` не найден** — `cargo install cargo-ndk`.
- **Gradle качает дистрибутив** — первый запуск wrapper скачивает Gradle 8.10.2.
- **VPN не поднимается** — проверьте согласие VPN и `adb logcat | Select-String aether`.

## TDD log

Формат: `шаг | команда | RED | GREEN | коммиты`. Заполняется по ходу работы.

```
P0-R1 build+host contract | .\scripts\check_android_build.ps1 -SkipBuild; .\scripts\check_android_host.ps1 | RED: 7 build checks failed (no wrapper/root build/scripts); 29 host checks failed (skeleton) | GREEN: pending | red: pending
```
