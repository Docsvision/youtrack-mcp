# Запуск двух YouTrack MCP под Linux

Используется тот же production Compose, что и под Windows:

```text
локальный клиент -> 127.0.0.1:8001/mcp -> mcp-sanitized -> sanitizer -> YouTrack
локальный клиент -> 127.0.0.1:8002/mcp -> mcp-plain -----------------> YouTrack
```

Оба MCP работают только на чтение. Первый обязательно санитизирует выдачу,
второй возвращает исходные данные для локальной диагностики. Sidecar доступен
только во внутренней Docker-сети.

## 1. Требования

- современный x86-64 или ARM64 Linux;
- Docker Engine;
- Docker Compose plugin, запускаемый как `docker compose`;
- минимум 8 GB свободной RAM и около 10 GB на диске для первой сборки моделей.

Устанавливайте [Docker Engine](https://docs.docker.com/engine/install/) по
официальной инструкции для своего дистрибутива и используйте актуальный
[Docker Compose plugin](https://docs.docker.com/compose/install/linux/), а не
устаревший отдельный пакет `docker-compose`. Для production-сервера стоит
рассмотреть [rootless Docker](https://docs.docker.com/engine/security/rootless/):
демон и контейнеры тогда работают без root.

Проверка установки:

```bash
docker version
docker compose version
docker info
```

`docker version` должен показывать и `Client`, и `Server`.

## 2. Получение проекта

```bash
git clone https://github.com/Docsvision/youtrack-mcp.git
cd youtrack-mcp
git switch feature/output-sanitization-boundary
```

Если изменения уже слиты в основную ветку, переключение отдельной ветки не
требуется.

Сейчас production-изменения находятся в локальном рабочем дереве. Перед
развёртыванием на другой Linux-машине их нужно закоммитить и отправить в форк
либо безопасно перенести всю рабочую копию.

## 3. Создание конфигурации и секретов

Запустите Bash-инициализатор из корня репозитория:

```bash
bash ./scripts/initialize_production.sh
```

Или передайте URL сразу:

```bash
bash ./scripts/initialize_production.sh \
  --url https://youtrack.company.ru
```

Токены вводятся скрыто и не попадают в историю shell. Скрипт создаст:

```text
deploy/mcp-sanitized.env
deploy/mcp-plain.env
deploy/secrets/youtrack-sanitized.token
deploy/secrets/youtrack-plain.token
deploy/secrets/sanitizer-pseudonym.key
```

Файлы создаются с правами `600`. Проверьте их без вывода содержимого:

```bash
find deploy -type f ! -name '*.example' ! -name README.md \
  -printf '%m %u:%g %p\n'
```

Для повторной генерации существующих файлов требуется явный `--force`.
YouTrack-токены должны принадлежать аккаунту только с правами чтения.

## 4. Проверка и сборка

```bash
docker compose -f docker-compose.production.yml config --quiet
docker compose -f docker-compose.production.yml build --pull
docker compose -f docker-compose.production.yml up -d
```

Первая сборка sidecar занимает больше времени, потому что в образ загружаются
русская и английская модели Stanza.

Проверка состояния:

```bash
docker compose -f docker-compose.production.yml ps
docker compose -f docker-compose.production.yml logs -f sanitizer
```

После загрузки моделей все три сервиса должны стать `healthy`.

Проверка локальных портов:

```bash
ss -ltn | grep -E '127\.0\.0\.1:(8001|8002)'
```

## 5. Проверка без внешней модели

Создайте локальное окружение только для проверочного MCP-клиента:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.runtime.txt
.venv/bin/python scripts/check_dual_mcp.py SUP-14337
```

Будут созданы:

```text
work/mcp-comparison/SUP-14337-sanitized.json
work/mcp-comparison/SUP-14337-plain.json
```

В защищённом результате должны встречаться `USER-...`, `COMPANY-...`,
`[INTERNAL_HOST]`, `[SECRET]` и другие маркеры. Plain-файл содержит исходные
данные YouTrack — не передавайте его внешней модели.

Проверка обновления словаря компаний:

```bash
docker compose -f docker-compose.production.yml logs mcp-sanitized \
  | grep 'Company dictionary'
```

## 6. Подключение локального Codex

Добавьте в `~/.codex/config.toml`:

```toml
[mcp_servers.youtrack_sanitized]
url = "http://127.0.0.1:8001/mcp"
required = true
startup_timeout_sec = 30
tool_timeout_sec = 120

[mcp_servers.youtrack_plain]
url = "http://127.0.0.1:8002/mcp"
required = false
startup_timeout_sec = 30
tool_timeout_sec = 120
```

Перезапустите Codex. Для обычной работы используйте только
`youtrack_sanitized`; plain-сервер нужен для контролируемой локальной проверки.

Если клиент находится на другой машине, текущие порты ему недоступны. Не
заменяйте `127.0.0.1` на `0.0.0.0` напрямую: используйте VPN или reverse proxy с
TLS, аутентификацией и сетевым allowlist.

## 7. Эксплуатация

Журналы:

```bash
docker compose -f docker-compose.production.yml logs --tail 200 mcp-sanitized
docker compose -f docker-compose.production.yml logs --tail 200 mcp-plain
docker compose -f docker-compose.production.yml logs --tail 200 sanitizer
```

Перезапуск и обновление:

```bash
docker compose -f docker-compose.production.yml restart

git pull --ff-only
docker compose -f docker-compose.production.yml build --pull
docker compose -f docker-compose.production.yml up -d --remove-orphans
```

Остановка:

```bash
docker compose -f docker-compose.production.yml down
```

Ротация токена:

```bash
umask 077
printf '%s' 'NEW_READ_ONLY_TOKEN' > deploy/secrets/youtrack-sanitized.token
chmod 600 deploy/secrets/youtrack-sanitized.token
docker compose -f docker-compose.production.yml \
  up -d --force-recreate mcp-sanitized
```

Чтобы токен не попал в историю shell, на реальном сервере вводите его через
скрытый prompt или секрет-хранилище, а не вставляйте буквально в показанную
команду.

Контейнеры имеют `restart: unless-stopped`, поэтому после запуска Docker daemon
они поднимутся автоматически. Для rootless Docker дополнительно включите linger
пользователя согласно официальной инструкции Docker.

## 8. Резервное копирование и безопасность

- Зашифрованно сохраните `sanitizer-pseudonym.key`: он обеспечивает стабильные
  `USER-...` маркеры после переноса на другую машину.
- Не включайте plain MCP в процессы, которые отправляют результат внешней модели.
- Не публикуйте порты 8001/8002 в общую сеть без дополнительной аутентификации.
- Не запускайте MCP с административным YouTrack-токеном.
- Защищённый экземпляр работает fail-closed: отсутствие sidecar или начального
  словаря клиентов блокирует выдачу.
