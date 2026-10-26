# Android-клиент AetherLink

Статус: **Phase 0 в работе** (TDD). План: [`PLAN_ANDROID.md`](../PLAN_ANDROID.md).

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
.\scripts\check_android_host.ps1    # контракт Kotlin-хоста (red до G3/G4)
Push-Location apps\android; .\gradlew.bat testDebugUnitTest; Pop-Location
```

`apps/android/gradle.properties` включает `android.useAndroidX=true` — без этого
Robolectric/androidx.test не резолвятся.

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

- **`JAVA_HOME` указывает на JDK 24+** — Gradle 8.10 падает; поставьте JDK 21
  (Android Studio: `C:\Program Files\Android\openjdk\jdk-21.0.8`).
- **`cargo ndk` не найден** — `cargo install cargo-ndk`.
- **Gradle качает дистрибутив** — первый запуск wrapper скачивает Gradle 8.10.2.
- **`NativeCommandError` от cargo** — скрипт уже гоняет нативные команды через
  `cmd /c`; если вызываете cargo вручную, используйте `cmd /c "cargo ..."`.
- **VPN не поднимается** — проверьте согласие VPN и `adb logcat | Select-String aether`.

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
```
