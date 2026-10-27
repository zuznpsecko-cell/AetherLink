# Windows GUI: endpoint profiles

Статус: **Phase 1–3 закрыты** (код, тесты, гейты); Phase 4 — ручная приёмка
на живых серверах (требует admin и реальные PSK). План и матрица приёмки:
[`PLAN_ENDPOINTS_WINDOWS.md`](../PLAN_ENDPOINTS_WINDOWS.md).

GUI умеет несколько профилей подключения (эндпоинтов): добавление,
редактирование, дублирование, удаление и выбор активного. Профиль — это
`name`, `server_addr`, `outer_sni`, `psk`. Full tunnel, MTU, DNS mode и
routing rules общие для всех профилей.

## Сборка и проверки

```powershell
dotnet build dotnet/AetherLink.Gui/AetherLink.Gui.csproj -c Release
dotnet test  dotnet/AetherLink.Gui.Tests/AetherLink.Gui.Tests.csproj -c Release
powershell -NoProfile -File scripts/check_gui_endpoints.ps1
powershell -NoProfile -File scripts/check_thin_hosts.ps1
.\scripts\run_gui_windows.ps1
```

`check_gui_endpoints.ps1` — контракт профилей: YAML-поля, привязки XAML,
команды Add/Duplicate/Delete, отсутствие PSK в логах, отсутствие
криптостека и заглушек `NotImplementedException` в GUI.
`check_thin_hosts.ps1` дополнительно проверяет, что в `dotnet/AetherLink.Gui`
нет `SslStream|ChaCha|HMAC|AesGcm`.

## Использование

Вкладка **Server** — список профилей слева и редактор справа.

- **Add** — новый профиль `endpoint`, `endpoint 2`, … сразу выбран.
- **Duplicate** — копия выбранного: `home (copy)`, `home (copy 2)`, …
- **Delete** — удаляет выбранный профиль и выбирает соседний. Последний
  профиль удалить нельзя: кнопка disabled, `Connect` без профиля невозможен.
- Поля справа (`Name`, `Server address`, `Outer SNI`, `PSK`) правят выбранный
  профиль; PSK вводится под `PasswordChar="*"`.
- **Connect** всегда использует выбранный профиль. Перед `Up` конфиг
  сохраняется, и выбранный профиль зеркалится в legacy-поля.

Выбор другого профиля:

| Состояние туннеля | Поведение |
|---|---|
| Down | профиль просто выбирается и сохраняется, native не вызывается |
| Up | `Down` → сохранение конфига → `Up` на новом профиле; статус `Switching...`, затем `Up (<имя>)` |
| Up, новый профиль битый | `Down`, сеть восстановлена, показана ошибка, профиль остаётся выбранным для повтора через Connect |
| Up, нажат Disconnect во время switch | после `Down` reconnect не выполняется |

Статус при поднятом туннеле: `Up (<endpoint name>)`.

## YAML

Файл: `client.local.yaml` рядом с exe (иначе `client.yaml`; путь виден в
редакторе как `Config: ...`). Логи: `logs/gui-<date>.log`.

```yaml
client:
  active_endpoint: "home"
  endpoints:
    - name: "home"
      server_addr: "server.example.com:443"
      outer_sni: "server.example.com"
      psk: "change-me-high-entropy"
    - name: "backup"
      server_addr: "backup.example.com:8443"
      outer_sni: ""          # пусто → host из server_addr

  # Зеркало активного профиля: core и CLI читают только эти три поля.
  server_addr: "server.example.com:443"
  outer_sni: "server.example.com"
  psk: "change-me-high-entropy"

  pad_multiple: 128
  keepalive_s: 15
  wintun_dll_path: "./wintun.dll"

full_tunnel: { ... }   # общее для всех профилей
routing: { ... }       # общее для всех профилей
```

`ConfigService.Load`:

| Ситуация | Результат |
|---|---|
| есть `endpoints` + известный `active_endpoint` | список и выбранный профиль |
| `active_endpoint` пуст/неизвестен | выбран первый профиль |
| `endpoints` нет, но есть `server_addr` | один профиль `default` (миграция старого конфига) |
| `endpoints` есть, зеркало отличается | побеждает список |
| `endpoints: []` | профиль `default` из зеркала (битый конфиг не теряет сервер) |
| нет ни списка, ни `server_addr` | пустой список, Connect блокируется |

`ConfigService.Save` пишет `endpoints` в порядке UI, `active_endpoint` и
зеркало `server_addr/outer_sni/psk` выбранного профиля (пустой SNI
зеркалится как host). `pad_multiple`, `keepalive_s`, `wintun_dll_path`,
`full_tunnel` и `routing` сохраняются как раньше. Запись пересобирает
документ целиком, поэтому комментарии и незнакомые ключи в YAML теряются —
это известное ограничение (см. план, §6).

## Валидация

Тонкая проверка в GUI до вызова native; окончательно конфиг проверяет core
при `aether_client_create`.

| Поле | Правило | Сообщение |
|---|---|---|
| `name` | trim, 1..64, уникален без учёта регистра | `endpoint name is empty`, `endpoint name 'x' is used twice` |
| `server_addr` | `host:port`, порт 1..65535 | `endpoint 'x': server address must be host:port` |
| `outer_sni` | может быть пустым → host адреса | — |
| `psk` | непустой | `endpoint 'x': PSK is empty` |
| список | ≥ 1 профиля | `add at least one endpoint` |

Ошибка показывается как `config error: <текст>`; native при этом не
вызывается.

## Ограничения

- Только ручное переключение. Автоматического failover, health-check и
  замеров задержки нет: ошибка подключения показывается, туннель остаётся
  Down.
- PSK хранится в plaintext-YAML, как и раньше; в GUI он не логируется и не
  попадает в сообщения об ошибках, но и не шифруется at rest.
- PSK выбранного профиля намеренно продублирован в YAML (список + зеркало).
- Профили принадлежат Windows GUI. Core, FFI и CLI не менялись и видят один
  сервер через зеркало; `client.endpoints` — host-only состояние.
- Android пока не умеет профили: это отдельный этап после живого теста.
- Переименование выбранного профиля сохраняется при потере фокуса/переключении,
  отдельной кнопки «Save» нет.

## Ручная приёмка (Phase 4, L3)

Требует администратора (`app.manifest`: `requireAdministrator`) и реальных
серверов. Матрица — `PLAN_ENDPOINTS_WINDOWS.md` §5; отметки ставить после
прогона:

| # | Сценарий | Ожидание | Статус |
|---|---|---|---|
| 1 | старый `client.local.yaml` только с `server_addr` | профиль `default`, Connect работает | ⏳ |
| 2 | Add → ввод → Connect → перезапуск GUI | профиль сохранён и выбран | ⏳ |
| 3 | переключение профиля при Down | native не вызывается, выбор сохранён | ⏳ |
| 4 | переключение профиля при Up | `Switching...`, затем `Up (new)`, egress = новый сервер | ⏳ |
| 5 | переключение на неверный профиль | Down, сеть/DNS восстановлены, ошибка, Connect повторяет | ⏳ |
| 6 | пустое имя / битый адрес / пустой PSK | Connect заблокирован, native не вызван | ⏳ |
| 7 | Delete активного / Delete последнего | выбран сосед / кнопка disabled | ⏳ |
| 8 | routing rules и full tunnel у разных профилей | общие, не дублируются | ⏳ |
| 9 | профиль без SNI | подключается, SNI = host | ⏳ |
| 10 | PSK в логах и ошибках | отсутствует | ⏳ |
| 11 | kill процесса при активном профиле | после рестарта Connect/auto-restore stale state работает | ⏳ |

## TDD log

Формат: `шаг | команда | RED | GREEN | коммиты`. Тесты — xUnit,
`dotnet/AetherLink.Gui.Tests`, TFM `net10.0-windows`, `InternalsVisibleTo`
из GUI. Итог: **49/49** в Debug и Release.

```
E0-R1 smoke | dotnet test (EndpointBookTests) | RED: EmptyBook_RequiresAtLeastOneEndpoint — NotImplementedException; каркас тестов, модели и seam ITunnelController собраны | GREEN: pending | red: 7a37156
E1-R1 rules | dotnet test --filter EndpointRulesTests | RED: 14/14 — NotImplementedException (имя, длина, дубликаты, host:port, PSK, SNI-fallback) | GREEN: pending | red: 2cc3733
E1-G1 rules | dotnet test --filter EndpointRulesTests | RED: 14 failed | GREEN: 14 passed; EndpointRules + EndpointProfile | green: f5b5cef
E1-R2 book | dotnet test --filter EndpointBookTests | RED: 10 failed — NotImplementedException (Add/Duplicate/Remove/Select/Load/Validate) | GREEN: pending | red: 807cefc
E1-G2 book | dotnet test --filter EndpointBookTests | RED: 2 failed (имя копии `home (copy) 2`, регистр в сообщении о дубликате) | GREEN: 11 passed; уникальные имена, выбор соседа, последний профиль защищён | green: 6f7a7bf
E1-R3 config | dotnet test --filter ConfigServiceTests | RED: 8 failed — нет endpoints/active_endpoint, миграции и зеркала | GREEN: pending | red: ad8a7d8
E1-G3 config | dotnet test --filter ConfigServiceTests | RED: 8 failed | GREEN: 8 passed; Load/Save, миграция `default`, список побеждает зеркало, пустой SNI → host, общие routing/full_tunnel сохранены | green: cc87156
E1-R4 core | cargo test -p aetherlink-client --test config_schema | RED: characterization — core должен игнорировать client.endpoints и читать зеркало | GREEN: pending (ожидаемо: тест фиксирует текущее поведение) | red: 952a83c (вместе с E1-R5)
E1-G4/R5 core+example | cargo test -p aetherlink-client --test config_schema; check example | RED: n/a | GREEN: 3/3 passed; `gui_endpoint_list_is_ignored_by_core`, `configs/client.example.yaml` документирует endpoints/active_endpoint | green: 952a83c
E2-R1 switch | dotnet test --filter EndpointSwitcherTests | RED: 4 failed — NotImplementedException | GREEN: pending | red: b5bdf0b
E2-G1 switch | dotnet test --filter EndpointSwitcherTests | RED: 4 failed | GREEN: 4 passed; Down → buildConfig → Up, cancel после Down, ошибка Up оставляет Down | green: d7e838f
E2-R2..R5 view model | dotnet test --filter MainViewModelTests | RED: 8 failed — VM не использует профили | GREEN: pending | red: 7ffcaad
E2-G2..G5 view model | dotnet test --filter MainViewModelTests | RED: 8 failed (плюс AVLN2000: XAML ещё биндится на ServerAddr/OuterSni/Psk) | GREEN: 12 passed; SelectedEndpoint, Add/Duplicate/Delete, Down→Up, сохранение при выборе и Shutdown, отказ при дубликатах имён | green: c94ad96
E3 UI+gates | dotnet build -c Release; dotnet test -c Release; check_gui_endpoints.ps1; check_thin_hosts.ps1 | RED: нет привязок Endpoints/SelectedEndpoint и команд | GREEN: build 0/0, 49/49, all gui endpoint checks passed, thin-host checks passed | green: c94ad96
```

Замечания по прогону:

- `dotnet test` в Debug: 49/49 (150 ms), в Release: 49/49 (403 ms).
- `cargo test -p aetherlink-client --test config_schema`: 3/3 passed.
- Полные `cargo fmt --check` / `clippy -D warnings` / `cargo test --workspace`
  имеют известные pre-existing падения (см. `docs/ANDROID.md`,
  `docs/LIVE_ISSUES.md`); в этой итерации Rust-код не менялся, кроме
  characterization-теста.
- Ручной smoke GUI (`--minimized`) и живые переключения не выполнялись: нужен
  admin и реальные PSK (см. матрицу выше).
