# wolfee-agent-triage

Триаж находок SAST и SCA. Отвечает на один вопрос по каждой находке: **уязвимо
здесь или нет, и почему** — с файлом, строкой и трассой, если да.

Отсутствие данных нигде не читается как «безопасно». Каждый шаг, который не
отработал, попадает в отчёт с причиной.

---

## Как триажит

### SAST — находки в вашем коде

```
выгрузка сканера → область → эвристики → контекст → модель → пост-проверка → отчёт
```

Контекст собирается детерминированно: трасса из SARIF, расширение сниппета из
исходников, определения и вызовы от языкового сервера, таблица маршрутов,
соглашения фреймворка, описание среды. Модель получает факты, а не догадки.

Для CWE, зависящих от пользовательского ввода, действует строгий gate:

```text
source→sink trace от CodeQL/Psalm/Semgrep
+ production entrypoint от LSP/route index
= решённый verdict
```

Одной половины недостаточно: результат становится `unknown`. Для закрытия
дополнительно нужен заземлённый `SANITIZED_DATAFLOW`, для подтверждения —
`EXPLOITABLE_DATAFLOW`. Intrinsic-классы (секреты, криптография, TLS,
misconfiguration) этого пути не требуют.

Пост-проверка может только **понижать** вердикт. Каждая цитата ищется в точном
тексте промпта — не нашлась, ответ отбрасывается.

### SCA — уязвимости в зависимостях

```
cdxgen → OSV/GHSA/NVD → коммит с фиксом → символ → parent bridges → достижимость → вердикт
```

1. **cdxgen** строит SBOM: пакеты, версии, рёбра зависимостей. Единственный
   источник графа — прямая зависимость отличается от транзитивной, и от этого
   зависит, что вообще можно обновить.
2. **OSV, GHSA, NVD** — какие advisory задевают эту версию. Сбой базы
   отличается от «уязвимостей нет».
3. **Коммит с исправлением** — модель называет уязвимую функцию. Имя обязано
   встречаться в диффе, цитата — в строке, которую фикс менял. Функция,
   появившаяся только в добавленных строках, отбрасывается: в уязвимой версии
   её нет.
4. **Поиск в вашем коде** — строго: вызов, а не упоминание; язык пакета; класс в
   области видимости; тесты отдельно от рабочего кода.
5. **Транзитивные bridge-цепочки** — для каждого пути cdxgen исходники exact
   version берутся сначала из локального `vendor`, затем из ограниченного
   Packagist/GitHub archive. Каждый пакет загружается один раз за запуск; ни
   Composer install, ни package scripts не выполняются.
6. **Достижимость** для CWE, требующих пользовательского ввода — языковой
   сервер, CodeQL, конфигурация DI-контейнера, чтение файла моделью.
7. **EPSS и CISA KEV** — очередь разбора: что эксплуатируют в дикой природе,
   идёт первым.

**Закрыть находку могут только факты:** пакет только для сборки; библиотека
нигде в коде не упоминается; условие эксплуатации не выполняется; уязвимого
кода нет в устанавливаемом пакете; вопрос относится к инфраструктуре, а не к
сервису. Ответ модели может понизить находку, но не закрыть её.

Состав пакетов, exact versions, родители и все dependency paths берутся **только
из cdxgen CycloneDX `dependsOn`**. Packagist/GitHub не участвуют в разрешении
графа и используются только как источник архива уже известного узла SBOM.

---

## Что нужно

**Обязательно**

| | зачем |
|---|---|
| Python 3.11+ | сам агент |
| LLM-провайдер | Ollama (закрытый контур), DeepSeek или OpenAI — профиль в `configs/providers/` |

**Для SCA**

| | зачем |
|---|---|
| `cdxgen` | SBOM и граф зависимостей, единственный источник |
| сеть к `osv.dev`, `github.com`, `first.org`, `cisa.gov` | advisory, фиксы, EPSS, KEV |

**Сканеры — по языкам проекта**

| | |
|---|---|
| CodeQL | Go, Python, JS/TS, Java/Kotlin, C/C++, C#, Ruby, Rust, Swift |
| govulncheck | Go: обязательная проверка вызовов vulnerable symbols, не только версии модуля |
| semgrep + psalm | PHP: паттерны плюс обязательный source→sink taint |
| gitleaks | секреты |

**Языковые серверы** — `phpactor`, `gopls`, `typescript-language-server`,
`pylsp`. Для PHP/Python/Go/JS/TS они обязательны; `--no-lsp` разрешает только
явно деградированный прогон, где input-driven findings уйдут в `unknown`.

Для Go полный прогон требует все три независимых плеча: `gopls` для callers и
definitions, CodeQL для first-party dataflow и `govulncheck -scan=symbol` для
достижимости уязвимых функций зависимостей. Если CodeQL или govulncheck
недоступен, scan завершается как incomplete, а не выдаёт чистый отчёт. В полном
`run` флаг `--no-lsp` для Go запрещён; он остаётся только для явно деградированного
standalone `triage` готовой выгрузки.

```bash
appsec-triage doctor
```

Печатает, что установлено и чего не хватает.

---

## Запуск в контейнере

Один образ со всем набором — сканеры, языковые серверы, cdxgen:

```bash
docker build -t wolfee-agent-triage .
```

Джоба в пайплайне: находит уязвимые зависимости, потом триажит.

```bash
docker run --rm \
  -v "$CI_PROJECT_DIR:/src:ro" -v "$CI_PROJECT_DIR/out:/out" \
  --env-file .env wolfee-agent-triage \
  sbom /src -o /out/deps.json

docker run --rm \
  -v "$CI_PROJECT_DIR:/src:ro" -v "$CI_PROJECT_DIR/out:/out" \
  --env-file .env wolfee-agent-triage \
  triage /out/deps.json --source-root /src --resolve-symbols -p deepseek -o /out
```

Сканеры и триаж вместе — одной командой:

```bash
docker run --rm -v "$CI_PROJECT_DIR:/src:ro" -v "$CI_PROJECT_DIR/out:/out" \
  --env-file .env wolfee-agent-triage \
  run /src --resolve-symbols -p deepseek -o /out --fail-on confirmed
```

Коды возврата: `0` — чисто, `1` — scanner/gate failure или сработал `--fail-on`,
`2` — не поднялся обязательный языковой сервер либо неполно отработала SCA.

Образ ~6,4 ГБ: CodeQL с наборами запросов, Go, PHP, Node и четыре языковых сервера. Это цена «весь анализ в одном артефакте».

## Запуск локально

```bash
pip install -e .
```

### Runtime-контекст сервиса

Exposure и бизнес-критичность не хранятся в репозитории. Job экспортирует три
переменные перед запуском одного и того же образа агента:

```bash
export TRIAGE_INTERNET_EXPOSED=true       # true | false | unknown
export TRIAGE_AUTH_REQUIRED=false         # true | false | unknown
export TRIAGE_BUSINESS_CRITICAL=true      # true | false | unknown

appsec-triage run /src --resolve-symbols -o /out
```

Отсутствующее, пустое или невалидное значение считается `unknown`, а не
безопасным `false`. Snapshot переменных сохраняется в JSONL и summary.

Общий baseline зашит на уровне агента для всех сервисов: Kubernetes,
ограниченный egress, shared Nginx ingress/external LB, backend без прямой внешней
публикации. Это влияет на priority и exposure, но Nginx/LB не считается WAF,
санитайзером или причиной закрыть уязвимость.

Priority вычисляется детерминированно и имеет ровно четыре значения:

```text
score >= 75  Critical
score >= 55  High
score >= 30  Medium
иначе        Low
```

Internet exposure, отсутствие authentication и business critical повышают
score. Internal/authenticated/non-critical понижают его. Для открытой находки
`TRIAGE_BUSINESS_CRITICAL=true` задаёт минимум `High`; `false_positive` и
`external_fp` всегда имеют `Low`, так как не входят в очередь ручного триажа.

Только триаж готовой выгрузки:

```bash
appsec-triage triage findings.sarif --source-root . -o out/
```

Сканеры и триаж вместе, с разбором зависимостей:

```bash
appsec-triage run /path/to/project --resolve-symbols -o out/
```

`--resolve-symbols` включает цепочку SCA. Требует доступа в сеть.

---

## Что на выходе

`out/report.html` — таблица по всем находкам:

| Что | Priority | Уязвимо | Где | Трасса | Вне кода | Почему |
|---|---|---|---|---|---|---|
| пакет или CWE | Critical / High / Medium / Low | да / нет / external mitigated / не установлено | файл, строка, функция | что прошли | EXTERNAL и владелец | вердикт |

Сортировка — как очередь: сначала то, что требует человека. Ниже — раскрывающиеся
карточки с полным обоснованием, цитатами и потоком данных.

`out/verdicts.jsonl` — те же решения построчно, для ASOC.

Четыре результата не смешиваются:

- `confirmed` — уязвимость подтверждена;
- `false_positive` — уязвимого состояния нет;
- `external_fp` — путь уязвим, но проверенный внешний compensating control покрывает его; AI-closed, в ручной процент не входит;
- `unknown` — доказательств недостаточно, нужен человек.

---

## Настройка

| файл | что задаёт |
|---|---|
| `configs/pipeline.yaml` | слои, пороги, поведение |
| `configs/providers/*.yaml` | модели и их профили |
| `configs/lsp.yaml` | языковые серверы |
| `configs/deployment.yaml` | где приложение работает — влияет на условия эксплуатации |
| `prompts/default/` | промпты по классам уязвимостей |

`deployment.yaml` заполняется **по факту**, а не по намерению: неверное «мы не
смотрим в интернет» тише и дороже, чем лишняя позиция в очереди. Обычный
Ingress/Nginx/LB не является защитой. Для `external_fp` нужен отдельный
`compensating_controls` с точным CWE/route/path coverage, `verified: true` и
`bypass_possible: false`; post-validation дополнительно требует scanner trace и
production entrypoint от LSP/route index.
