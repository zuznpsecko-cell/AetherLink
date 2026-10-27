# PLAN — несколько эндпоинтов в Windows-клиенте AetherLink

_Дата: 2026-10-26. Клиент: `dotnet/AetherLink.Gui` (Avalonia, Windows). Android — отдельным этапом после живого теста (§10)._

Статус: черновик к исполнению. Реализация — только после подтверждения плана.

## 0. Задача и границы

Сейчас GUI умеет один сервер: вкладка **Server** → `server_addr`, `outer_sni`, `psk`, сохраняется в `client.local.yaml`, `Connect` поднимает туннель на нём. Нужно добавить **несколько эндпоинтов** (профилей подключения): добавление, редактирование, удаление, выбор активного.

**Эндпоинт** = именованный профиль: `name`, `server_addr`, `outer_sni`, `psk`.
Full tunnel, MTU, DNS-режим и routing rules — **общие** для всех профилей и в эндпоинт не дублируются.

Границы итерации:

- только `dotnet/AetherLink.Gui`;
- Rust core, FFI и CLI `AetherLink.Client` **не меняются**: core по-прежнему получает один `server_addr`; выбранный профиль зеркалится в legacy-поля `client.server_addr/outer_sni/psk`;
- автоматический failover (перебор серверов при ошибке/обрыве) — **не входит** (§10);
- Android — **не входит**, добавляем отдельно после теста.

### Принятые по умолчанию решения

Вопросы по поведению остались без ответа, поэтому план исходит из этих вариантов. Если нужно иначе — скажи, поправлю до реализации.

| Вопрос | Решение |
|---|---|
| Где хранить | в том же `client.local.yaml`, секция `client.endpoints` + `client.active_endpoint` |
| Переключение | ручное; выбор другого профиля при поднятом туннеле = автоматический `Down → Up` на новом |
| Failover | нет; ошибка подключения показывается, туннель остаётся Down |
| Идентичность профиля | `name` (уникальный, без учёта регистра); отдельный `id` в YAML не вводим |
| Удаление | последний профиль удалить нельзя (кнопка disabled) |
| Секреты | PSK остаётся в plaintext-YAML, как сейчас; в логи/ошибки не попадает |

## 1. Контракт данных

### 1.1. YAML

```yaml
client:
  active_endpoint: "home"
  endpoints:
    - name: "home"
      server_addr: "server.example.com:443"
      outer_sni: "server.example.com"
      psk: "change-me-high-entropy"
    - name: "backup"
      server_addr: "backup.example.com:443"
      outer_sni: "backup.example.com"
      psk: "another-psk"

  # Зеркало активного профиля: core и CLI читают только эти поля.
  server_addr: "server.example.com:443"
  outer_sni: "server.example.com"
  psk: "change-me-high-entropy"

  pad_multiple: 128
  keepalive_s: 15
  wintun_dll_path: "./wintun.dll"

full_tunnel: { ... }   # общее
routing: { ... }       # общее
```

Правила загрузки (`ConfigService.Load`):

| Ситуация | Результат |
|---|---|
| есть `endpoints` и валидный `active_endpoint` | список + выбранный профиль |
| `active_endpoint` пуст/неизвестен | выбран первый профиль |
| `endpoints` нет, но есть `server_addr` | один профиль `default` (миграция старого конфига) |
| `endpoints` есть, зеркало отличается | побеждает список (зеркало игнорируется при чтении) |
| `endpoints` пустой массив | конфиг считается битым: профиль `default` из зеркала, предупреждение в UI |
| нет ни списка, ни `server_addr` | пустой список, Connect заблокирован с понятной ошибкой |

Правила сохранения (`ConfigService.Save`):

1. пишет `endpoints` (в порядке UI) и `active_endpoint` = имя выбранного;
2. перезаписывает зеркало `server_addr/outer_sni/psk` значениями выбранного;
3. сохраняет `pad_multiple`, `keepalive_s`, `wintun_dll_path`, `full_tunnel`, `routing` как сейчас;
4. PSK не попадает ни в сообщения об ошибках, ни в лог.

### 1.2. Модели C#

```csharp
// Models/EndpointProfile.cs — ObservableObject, чтобы правая панель редактора
// обновлялась при вводе.
public sealed partial class EndpointProfile : ObservableObject
{
    [ObservableProperty] public partial string Name { get; set; } = "";
    [ObservableProperty] public partial string ServerAddr { get; set; } = "";
    [ObservableProperty] public partial string OuterSni { get; set; } = "";
    [ObservableProperty] public partial string Psk { get; set; } = "";
    public string Display => string.IsNullOrWhiteSpace(Name) ? "(без имени)" : Name;
}
```

`Services/EndpointBook.cs` — чистая логика без Avalonia:

- `ObservableCollection<EndpointProfile> Items`;
- `EndpointProfile? Active` + инварианты выбора;
- `Add()`, `Duplicate()`, `Remove(profile)`, `ValidateAll()`, `EnsureLegacy(ClientSection)`.

`Services/EndpointRules.cs` — валидация одного профиля:

| Поле | Правило | Сообщение |
|---|---|---|
| `name` | trim, 1..64, уникален без учёта регистра | `endpoint name is empty` / `endpoint name 'x' is used twice` |
| `server_addr` | `host:port` через `rsplit_once(':')`, host непустой, порт 1..65535 | `endpoint 'x': server address must be host:port` |
| `outer_sni` | может быть пустым → host из адреса (как в core) | — |
| `psk` | непустой | `endpoint 'x': PSK is empty` |
| весь список | ≥ 1 профиля | `add at least one endpoint` |

Валидация в GUI — «тонкая»: окончательно конфиг проверяет core при `aether_client_create`.

## 2. UX

Вкладка **Server** превращается в менеджер эндпоинтов:

```
┌ Server ─────────────────────────────────────────────────────┐
│ ┌ Endpoints ─────────┐ ┌ Редактор ────────────────────────┐ │
│ │ home   1.2.3.4:443 │ │ Name       [home             ]   │ │
│ │ backup 5.6.7.8:443 │ │ Address    [1.2.3.4:443      ]   │ │
│ │                    │ │ Outer SNI  [selmedia.ru      ]   │ │
│ │ [Add] [Duplicate]  │ │ PSK        [************     ]   │ │
│ │ [Delete]           │ │                                  │ │
│ └────────────────────┘ │ Full tunnel [x]                  │ │
│                        │ DNS mode    [tunnel           ]   │ │
│                        │ [Refresh egress IP]              │ │
│                        │ [Restore network]                │ │
│                        └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

Поведение:

- список слева — `ListBox` с `ItemsSource="{Binding Endpoints}"`, `SelectedItem="{Binding SelectedEndpoint}"`;
- справа поля привязаны к `SelectedEndpoint.*` (`Name`, `ServerAddr`, `OuterSni`, `Psk`), PSK — `PasswordChar="*"`;
- `Add` создаёт профиль `endpoint N` с пустыми полями и выбирает его; `Duplicate` копирует выбранный с именем `X (copy)`, `X (copy 2)`…; `Delete` удаляет выбранный и выбирает соседний, для последнего — disabled;
- `Connect` использует `SelectedEndpoint`; перед `Up` вызывается `SaveConfig()`, как сейчас;
- **выбор другого профиля при поднятом туннеле**: статус `Switching…`, `Down`, `Save`, `Up` с новым профилем; при неудаче — туннель Down, сеть восстановлена, ошибка на экране, профиль остаётся выбранным (пользователь может повторить Connect);
- **выбор при опущенном туннеле**: только сохраняет выбор, native-вызовов нет;
- `Disconnect` во время переключения отменяет предстоящий `Up` (переиспользуем `_disconnectRequested`);
- статус вверху показывает имя профиля: `Up (home)`; в трее пункт Connect/Disconnect работает с выбранным профилем;
- всё остальное (Routes, Logs, Restore network, Refresh egress, autostart, `--minimized`) не меняется.

При переключении во время активного туннеля — никаких модальных подтверждений: короткий разрыв уже виден по статусу, а лишний диалог мешает. Если нужен confirm — добавляется одной опцией.

## 3. TDD-план

Методология как в `PLAN_ANDROID.md`: каждый шаг `R → G`, красный тест падает по ожидаемой причине, production-код появляется только для зелёного. Запись в TDD-журнал (`docs/WINDOWS_GUI.md`, новый) обязательна: ID шага, тест, команда, красный вывод, зелёный вывод, коммиты `red:`/`green:`.

### Phase 0 — тестовый каркас

| Шаг | Действие | Файлы |
|---|---|---|
| **E0-G1** | Инфраструктура: проект `AetherLink.Gui.Tests` (xUnit + `Microsoft.NET.Test.Sdk`, TFM `net10.0-windows`), `InternalsVisibleTo("AetherLink.Gui.Tests")`, пустые типы `EndpointProfile`/`EndpointBook`/`EndpointRules` (броски `NotImplementedException`), интерфейс `ITunnelController` + адаптер `TunnelService` без изменения поведения. Build и существующие гейты зелёные. | `dotnet/AetherLink.Gui.Tests/*`, `AetherLink.Gui.csproj`, `Services/ITunnelController.cs` |
| **E0-R1** | Red: smoke `EndpointBook.Empty_HasNoActive` — падает `NotImplementedException`, а не ошибкой компиляции. | `EndpointBookTests.cs` |

### Phase 1 — модель, валидация, конфиг

| Шаг | Действие | Файлы |
|---|---|---|
| **E1-R1** | Red: `EndpointRules` — валидный профиль ok; пустое/дублирующееся (регистр) имя, адрес без порта, пустой host, порт `0`/`65536`, пустой PSK → заданные ошибки; пустой SNI допустим и подставляется host. | `EndpointRulesTests.cs` |
| **E1-G1** | Green: `EndpointRules` + `EndpointProfile` | `Models/EndpointProfile.cs`, `Services/EndpointRules.cs` |
| **E1-R2** | Red: инварианты `EndpointBook`: Add выбирает новый; Duplicate даёт уникальное имя; Remove активного выбирает соседа; Remove последнего запрещён; переименование активного не теряет выбор; список сохраняет порядок. | `EndpointBookTests.cs` |
| **E1-G2** | Green: `EndpointBook` | `Services/EndpointBook.cs` |
| **E1-R3** | Red: `ConfigService` round-trip: новый YAML с `endpoints` + `active_endpoint`; миграция legacy-конфига в профиль `default`; неизвестный active → первый; список побеждает зеркало; Save пишет список, active и зеркало, сохраняет `pad_multiple`/`keepalive_s`/`wintun_dll_path`/`full_tunnel`/`routing`; PSK отсутствует в тексте исключений. | `ConfigServiceTests.cs` (временные файлы в `Path.GetTempPath()`) |
| **E1-G3** | Green: расширить `ConfigService.Load/Save` | `Services/ConfigService.cs`, `Models/ClientConfig.cs` |
| **E1-R4** | Red (защитный, может быть зелёным сразу): core игнорирует неизвестный ключ `client.endpoints` — `ClientConfig::parse` по-прежнему читает `server_addr`. Зафиксировать в журнале как characterization, не «позеленять» удалением теста. | `crates/aetherlink-client/tests/config_schema.rs` |
| **E1-G4** | Green: ничего в core не меняем; тест подтверждает совместимость. | — |
| **E1-R5** | Red: `configs/client.example.yaml` документирует `endpoints` и `active_endpoint` (проверяется скриптом §4, падает сейчас). | `configs/client.example.yaml` |
| **E1-G5** | Green: пример конфига + пояснение, что зеркало нужно core/CLI. | `configs/client.example.yaml` |

### Phase 2 — подключение и переключение

| Шаг | Действие | Файлы |
|---|---|---|
| **E2-R1** | Red: `EndpointSwitcher` (чистая логика, fake `ITunnelController`): при Down — только выбор, без native; при Up — порядок `Down → buildConfig → Up`; неудачный Up → остаётся Down и возвращается ошибка; повторный вызов во время операции игнорируется; отмена (`disconnectRequested`) не запускает второй Up. | `EndpointSwitcherTests.cs`, `FakeTunnelController.cs` |
| **E2-G1** | Green: `ITunnelController` + `EndpointSwitcher` | `Services/EndpointSwitcher.cs` |
| **E2-R2** | Red: `MainViewModel` (Avalonia.Headless.XUnit) — Connect собирает конфиг из **выбранного** профиля, а не из legacy-полей; `SaveConfig` до `Up`; `StatusText` содержит имя профиля. | `MainViewModelTests.cs` |
| **E2-G2** | Green: VM переводится на `EndpointBook`/`SelectedEndpoint`, удаляются одиночные `ServerAddr`/`OuterSni`/`Psk`; `ConnectDisconnect` использует выбранный профиль. | `ViewModels/MainViewModel.cs`, `Views/MainWindow.axaml` (биндинги) |
| **E2-R3** | Red: `Connect` с невалидным списком (дубль имени, пустой PSK, битый адрес) показывает ошибку и **не** вызывает `ITunnelController.Up`; пустой список — `add at least one endpoint`. | `MainViewModelTests.cs` |
| **E2-G3** | Green: вызов `EndpointBook.ValidateAll()` перед Up, ошибка в `LastError`. | `ViewModels/MainViewModel.cs` |
| **E2-R4** | Red: сохранение — при смене профиля, при Add/Duplicate/Delete и в `Shutdown()`; закрытие окна не теряет новый профиль. | `MainViewModelTests.cs` |
| **E2-G4** | Green: точки сохранения + `SaveConfig` в `Shutdown`. | `ViewModels/MainViewModel.cs` |
| **E2-R5** | Red: переключение при Up через VM — Down и Up получили одинаковый конфиг нового профиля; во время операции `ConnectLabel` = `Switching…`/`Cancel`; ошибка не оставляет `IsUp`. | `MainViewModelTests.cs` |
| **E2-G5** | Green: проводка `EndpointSwitcher` в VM, `_busy`/`_disconnectRequested` без регрессий. | `ViewModels/MainViewModel.cs` |

### Phase 3 — UI и ворота

| Шаг | Действие | Файлы |
|---|---|---|
| **E3-R1** | Red: `scripts/check_gui_endpoints.ps1` — проверяет: `ConfigService` пишет `endpoints`/`active_endpoint`; XAML биндит `Endpoints`, `SelectedEndpoint`, команды `AddEndpoint/DuplicateEndpoint/DeleteEndpoint`; PSK не логируется (grep); в `dotnet/AetherLink.Gui` нет `SslStream|ChaCha|HMAC|AesGcm` (thin host); пример конфига содержит `endpoints`. На текущем HEAD — FAIL. | `scripts/check_gui_endpoints.ps1` |
| **E3-G1** | Green: доводка XAML/команд/конфига до прохождения скрипта. | `Views/MainWindow.axaml`, `ViewModels/MainViewModel.cs`, `configs/client.example.yaml` |
| **E3-R2** | Red: headless UI-тест — окно загружается, в списке 2 профиля, выбор обновляет редактор, `Delete` disabled на последнем, `Add` добавляет и выбирает новый. | `MainWindowTests.cs` |
| **E3-G2** | Green: layout Server-вкладки (Grid: список + редактор), кнопки, disabled-состояния. | `Views/MainWindow.axaml` |
| **E3-R3** | Red: ручная матрица §5, строки 1–11 — заполняется в журнале; найденные дефекты получают regression-тест до фикса. | `docs/WINDOWS_GUI.md` |
| **E3-G3** | Green: фиксы по матрице. | — |

### Phase 4 — документация и приёмка

| Шаг | Действие | Файлы |
|---|---|---|
| **E4-G1** | `DEC-013: Endpoint profiles in client YAML` — хранение, зеркало, почему не core-failover сейчас. | `docs/DECISIONS.md` |
| **E4-G2** | `docs/WINDOWS_GUI.md` — как добавить/переключить профиль, миграция старого конфига, поведение при переключении, ограничения; ссылка из README. | `docs/WINDOWS_GUI.md`, `README.md` |
| **E4-G3** | `docs/STATUS.md` — строка о мультиэндпоинтах; журнал TDD заполнен. | `docs/STATUS.md` |
| **E4-G4** | Release-сборка GUI и smoke-запуск `--minimized`; туннель с двумя профилями на живом сервере. | `dist/win-gui` |

## 4. Ворота

```powershell
dotnet build dotnet/AetherLink.Gui/AetherLink.Gui.csproj -c Release
dotnet test  dotnet/AetherLink.Gui.Tests/AetherLink.Gui.Tests.csproj -c Release
powershell -File scripts/check_gui_endpoints.ps1
powershell -File scripts/check_thin_hosts.ps1
.\scripts\run_gui_windows.ps1

# регресс ядра не требуется, но проверяем, что не задет:
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`check_thin_hosts.ps1` дополняется блоком: в `dotnet/AetherLink.Gui` нет крипто-примитивов (сейчас GUI этим скриптом не проверяется — закрываем дыру).

## 5. Ручная тест-матрица (L3)

| # | Сценарий | Ожидание |
|---|---|---|
| 1 | Старый `client.local.yaml` только с `server_addr` | загружается один профиль `default`, Connect работает |
| 2 | Add → заполнить → Connect → перезапуск GUI | профиль и выбор сохранились |
| 3 | Переключение при Down | native-вызовов нет, выбор сохранён |
| 4 | Переключение при Up | статус `Switching…`, краткий разрыв, `Up (new)`, egress = новый сервер |
| 5 | Переключение на недоступный сервер | туннель Down, сеть/DNS восстановлены, ошибка видна, Connect повторяется |
| 6 | Дубль имени / битый порт / пустой PSK | Connect заблокирован, понятное сообщение, native не вызывался |
| 7 | Delete активного / Delete последнего | выбирается соседний / кнопка disabled |
| 8 | Routing rules и full tunnel после смены профиля | применяются те же правила |
| 9 | Два профиля на один сервер с разным SNI | оба подключаются, SNI уходит правильный |
| 10 | PSK в логах и сообщениях | отсутствует |
| 11 | Kill процесса во время переключения | следующий Connect сам восстанавливает сеть (существующий stale-state auto-restore) |

## 6. Риски и как закрываем

| Риск | Мера |
|---|---|
| `ConfigService.Save` перезаписывает YAML и теряет комментарии/неизвестные ключи (уже сейчас так) | фиксируем в docs; отдельной задачей — merge-writer, если понадобится |
| PSK хранится дважды (список + зеркало) | зеркало — только совместимость с core/CLI; документируем; grep-тест на отсутствие PSK в логах/ошибках |
| Внешнее редактирование конфига при работающем GUI | last-write-wins, отмечено в docs |
| Авто-reconnect при выборе профиля может удивить | статус `Switching…`; при необходимости добавляется confirm одной опцией |
| Дубли имён после ручной правки YAML | валидация блокирует Connect; active резолвится по имени |
| Регресс существующего Connect/Down (гонки `_busy`/`_disconnectRequested`) | тесты E2-R1…R5 + существующее поведение stale-state покрыто матрицей #5/#11 |

## 7. Не входит в эту итерацию

- автоматический failover, health-check, замер задержки и сортировка по ней;
- отдельные routing/full_tunnel на эндпоинт;
- импорт/экспорт профилей, подписки, QR, синхронизация;
- шифрование PSK at rest;
- мультиэндпоинты в CLI и в core (Rust);
- Android/TV UI — следующий отдельный план, контракт YAML берём этот же (`client.endpoints` + `active_endpoint`), чтобы конфиг переносился.

## 8. Критерии приёмки

1. На вкладке Server можно добавить, продублировать, отредактировать и удалить профиль; последний удалить нельзя.
2. Connect использует выбранный профиль; переключение при Up переподключает, при Down — только сохраняет выбор.
3. Старый конфиг открывается без ручной миграции как один профиль `default`.
4. После перезапуска GUI список и активный профиль на месте; `client.local.yaml` остаётся валидным для core и CLI.
5. Валидация не даёт уйти в native с пустым PSK/битым адресом/дублем имени.
6. Все ворота §4 зелёные, матрица §5 заполнена, `docs/WINDOWS_GUI.md` и DEC-013 добавлены, TDD-журнал закрыт.
