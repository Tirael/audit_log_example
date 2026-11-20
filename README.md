# Tamper-evident журнал аудита на .NET 10

Учебный, но полностью рабочий пример журнала аудита, который невозможно незаметно переписать:
записи образуют **дерево Меркла** (RFC 6962 / Certificate Transparency), а корень дерева
**закрепляется вне базы данных** — в HashiCorp Vault, с подписью через Transit.

Домен — заказы: `Create → Confirm → Ship / Cancel`. Каждая команда меняет заказ и добавляет
запись аудита в одной транзакции, которая коммитится только после того, как корень нового
состояния дерева записан и подписан в Vault.

```
API ──(1) BEGIN ──> PostgreSQL
 │                   │
 │   (2) INSERT order + audit_log, пересчёт Merkle frontier (под блокировкой строки лиджера)
 │                   │
 │   (3) POST transit/sign + secret/data/.../checkpoints + .../heads ──> Vault
 │                   │
 └──(4) COMMIT <─────┘      если Vault недоступен — ROLLBACK и 503
```

## Модель угроз

| Что защищаем | Кто недоверенный субъект |
| --- | --- |
| История заказов и действий | DBA или любой, у кого есть доступ к PostgreSQL: может править, удалять, вставлять строки, откатывать базу из бэкапа |
| | **Но не** имеет доступа к Vault и не может подписать произвольный корень |

- **Доверяем:** Vault (KV v2 как неизменяемое хранилище якорей + Transit как подписант).
- **Не доверяем:** PostgreSQL целиком. Никакие значения из БД при проверке не считаются истиной —
  включая таблицу с кешем Merkle-состояния.
- **Вне области:** компрометация хоста с API, кража root-токена Vault, отказ Vault в обслуживании
  (журнал в этом случае просто не принимает записи).

## Как это устроено

### 1. Дерево Меркла

- Лист: `SHA-256(0x00 || canonical_bytes)` — domain separation как в RFC 6962.
- Внутренний узел: `SHA-256(0x01 || left || right)`.
- Форма дерева: `MTH(D[n]) = node(MTH(D[0:k]), MTH(D[k:n]))`, `k` — наибольшая степень двойки `< n`.
- Лог растёт вечно; состояние хранится как **frontier** (пики совершенных поддеревьев), поэтому
  добавление стоит `O(log n)`, а корень — свёртка пиков справа налево.
- Реализованы inclusion proof и consistency proof; проверка — то, что делает `GET /audit/verify`.

### 2. Канонизация

Запись хешируется не через JSON-сериализатор, а через фиксированное бинарное кодирование
(`src/AuditLog/Canonical/AuditCanonicalizer.cs`):

```
"AULG" | u8 schema_version | string ledger | i64 timestamp_micros (UTC) | string actor |
string action | string entity_type | string entity_id | nullable string from_status |
nullable string to_status | 32-byte data_hash
```

`string = u32 длина | UTF-8`, nullable-строка — флаг `0/1`. Позиция записи в логе (`leaf_index`)
в канонизацию **не входит**: её задаёт индекс листа в дереве, поэтому вставка/перестановка строк
ломает корень, а не «объясняется» полем.

Свободный payload события хранится рядом (`data_canonical bytea`), в канонизации участвует только
его SHA-256. Поэтому проверка может пересчитать всё из колонок и сравнить с сохранёнными байтами.

### 3. Закрепление корня в Vault

Каждая транзакция порождает чекпоинт:

```json
{"schema_version":1,"ledger":"orders","seq":12,"tree_size":42,"root":"…","previous_checkpoint_hash":"…","created_at":"…"}
```

- `vault/transit` подписывает ровно эти байты ключом `audit-signer` (ECDSA P-256, SHA-256).
- `secret/data/audit-ledger/checkpoints/orders/<год>/<seq>` — отдельный KV-ключ на каждый чекпоинт,
  ничего не перезаписывается.
- `secret/data/audit-ledger/heads/orders` — указатель на последний чекпоинт.
- Каждый чекпоинт содержит `previous_checkpoint_hash`, то есть **якоря сами образуют hash-chain**:
  удалить или переставить чекпоинт нельзя, не сломав цепочку и `heads`.

Публичный ключ доступен через `GET /audit/public-key`, поэтому экспорт журнала
(`GET /audit/export`) проверяется офлайн, без Vault.

### 4. Что именно проверяет `GET /audit/verify`

1. `leaf_index` идёт подряд `0..n-1` (удаления и вставки в середину).
2. Каждая запись заново кодируется и хешируется из своих колонок (правки полей).
3. Корень пересчитывается из всех листьев и сравнивается с чекпоинтами по их `tree_size`.
4. Чекпоинты в БД сверяются с копиями в Vault (payload, подпись), подпись проверяется
   публичным ключом нужной версии Transit.
5. Цепочка `previous_checkpoint_hash` непрерывна.
6. Не осталось записей, не покрытых ни одним чекпоинтом.
7. `heads` в Vault не «впереди» базы (защита от отката БД) и совпадает с последним чекпоинтом.

Коды проблем в `findings`:

| Код | Что означает |
| --- | --- |
| `leaf_index_gap` | запись удалена/вставлена/переставлена |
| `canonical_payload_mismatch` | поля записи не перекодируются в сохранённые канонические байты |
| `leaf_hash_mismatch` | сохранённый хеш листа не соответствует канонизации |
| `unanchored_entries` | записи в логе, которые не покрыты ни одним чекпоинтом |
| `checkpoint_beyond_log` | чекпоинт больше текущего лога |
| `checkpoint_root_mismatch` | пересчитанный корень не совпал с чекпоинтом |
| `checkpoint_sequence_gap` / `checkpoint_chain_broken` | цепочка якорей повреждена |
| `checkpoint_payload_hash_mismatch` | payload чекпоинта не соответствует его хешу |
| `checkpoint_missing_in_vault` / `checkpoint_payload_mismatch` / `checkpoint_signature_mismatch` | БД и Vault расходятся |
| `checkpoint_signature_invalid` | подпись Transit недействительна |
| `database_rolled_back` | Vault знает дерево большего размера, чем есть в БД |
| `anchors_missing` / `anchor_heads_mismatch` | указатель `heads` отсутствует или не совпадает |
| `anchor_ahead_of_database` | запись в Vault обогнала БД (сбой после закрепления); следующий успешный коммит чинит состояние |

Frontier в таблице `audit_ledger` — **только кеш** для ускорения записи; проверка им не пользуется
(есть тест, который портит его и убеждается, что журнал всё равно цел).

## Запуск

Требуется Docker.

```bash
docker compose up -d --build      # postgres:18 + vault:1.20 (dev) + bootstrap + api
./scripts/smoke.sh                # полный сценарий: запись → проверка → подмена → обнаружение
```

Что поднимается:

| Сервис | Роль |
| --- | --- |
| `postgres` | база с заказами и журналом (недоверенная) |
| `vault` | dev-режим: KV v2 и Transit (доверенный якорь) |
| `vault-bootstrap` | включает движки, создаёт ключ `audit-signer`, policy `audit-api` и AppRole |
| `api` | .NET 10 minimal API; внутри образа работает **Vault Agent** в режиме cache-proxy: AppRole → токен, приложение токенов не знает |

Проверить руками:

```bash
curl -s localhost:8080/healthz
curl -s -H 'Content-Type: application/json' -H 'X-Actor: alice' \
     -d '{"customer":"acme","amount":99.90}' localhost:8080/orders
curl -s localhost:8080/audit/verify | python3 -m json.tool
```

Демонстрация подмены:

```bash
docker compose exec -T postgres psql -U audit -d audit \
  -c "UPDATE audit_log SET actor='mallory' WHERE leaf_index=0"
curl -s localhost:8080/audit/verify | python3 -m json.tool   # ok:false, canonical_payload_mismatch
```

### Локально, без контейнера с API

```bash
docker compose up -d postgres vault vault-bootstrap
Vault__Token=root dotnet run --project src/Orders.Api   # http://localhost:8080
```

Без Vault Agent приложение берёт статический токен из конфигурации (`Vault:Token`); с агентом
`Vault:Address` указывает на локальный listener агента, а токен не задаётся вовсе.

## API

| Метод | Путь | Назначение |
| --- | --- | --- |
| `POST` | `/orders` | создать заказ (`{customer, amount}`), `X-Actor` — автор |
| `POST` | `/orders/{id}/confirm` | `draft → confirmed` |
| `POST` | `/orders/{id}/ship` | `confirmed → shipped` |
| `POST` | `/orders/{id}/cancel` | `draft/confirmed → cancelled` (иначе `409`) |
| `GET` | `/orders/{id}` | состояние заказа |
| `GET` | `/audit/entries?after=&limit=` | записи журнала |
| `GET` | `/audit/proof/{leafIndex}` | inclusion proof против последнего закреплённого корня |
| `GET` | `/audit/consistency?first=&second=` | consistency proof между двумя закреплёнными размерами |
| `GET` | `/audit/checkpoints` | чекпоинты с подписями |
| `GET` | `/audit/export?from=&to=` | экспорт для офлайн-проверки (записи, чекпоинты, публичный ключ, heads) |
| `GET` | `/audit/public-key` | публичный ключ Transit (PEM) |
| `GET` | `/audit/verify` | полная проверка журнала |
| `GET` | `/openapi/v1.json` | OpenAPI |
| `GET` | `/healthz` | liveness |

Ошибки — RFC 9457 `application/problem+json`. Недоступный Vault — `503` + `Retry-After`.

## Тесты

```bash
dotnet test
```

- `tests/AuditLog.UnitTests` (113) — Merkle-frontier против рекурсивной реализации на 257 размерах,
  inclusion/consistency proofs для всех пар размеров, отказ на подделках, golden-вектор канонизации,
  кодирование чекпоинта, офлайн-проверка подписи.
- `tests/AuditLog.IntegrationTests` (14) — поднимают настоящие `postgres:18` и Vault через
  Testcontainers и проверяют пять атак: `UPDATE`, `DELETE`, `INSERT`, откат БД при актуальных `heads`,
  подмена frontier-кеша; плюс подмену подписи, счастливый путь, конкурентные записи и падение Vault
  (заказ отклоняется, БД не меняется).

## Структура

```
src/AuditLog/                 ядро: канонизация, Merkle, чекпоинты, подписи, клиент Vault
src/Orders.Api/               заказы, linq2db-доступ, FluentMigrator, эндпоинты, verify
tests/AuditLog.UnitTests/     криптография и дерево
tests/AuditLog.IntegrationTests/  Testcontainers + WebApplicationFactory
docker/                       образ API с Vault Agent, bootstrap Vault
scripts/smoke.sh              сценарий демонстрации
```

Стек: .NET 10, C#, [linq2db](https://linq2db.github.io/) (fluent mapping, без атрибутов),
FluentMigrator, PostgreSQL 18 (нативный `uuidv7()`), HashiCorp Vault 1.20, xUnit v3,
AwesomeAssertions, Testcontainers.

## Ограничения демо и что нужно для продакшена

- **Vault в dev-режиме** — только для демонстрации. В проде: настоящий сервер, Raft-хранилище,
  unseal/auto-unseal, отдельные политики на сервис, audit devices, ротация ключа.
- **Нет аутентификации** — `X-Actor` это плейсхолдер; в проде actor берётся из токена, а AppRole
  заменяется на Kubernetes/OIDC auth.
- **Один писатель**: append сериализуется блокировкой строки лиджера. Для нескольких инстансов нужен
  лидер-выбор или шардирование журналов по ledger.
- **`verify` пересчитывает дерево целиком** — нормально для демо и первых тысяч записей; для больших
  объёмов нужно инкрементальное состояние, проверка через consistency proofs и снапшоты.
- **Ретенция и архивация** не реализованы: журнал append-only и растёт; экспорт пригоден для
  выгрузки в WORM-хранилище.
- Подпись хранится и в Vault, и в БД; истина — Vault. Офлайн-проверка опирается на публичный ключ,
  полученный заранее.

## Лицензия

MIT — см. [LICENSE](LICENSE).
