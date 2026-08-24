# Два YouTrack MCP на одной машине

Эта конфигурация запускает три контейнера:

```text
Codex/Cursor -> 127.0.0.1:8001/mcp -> mcp-sanitized -> sanitizer -> YouTrack
Codex/Cursor -> 127.0.0.1:8002/mcp -> mcp-plain -----------------> YouTrack
```

Оба MCP работают только на чтение и публикуются исключительно на loopback
интерфейсе машины. `mcp-sanitized` обязательно обрабатывает каждую выдачу через
sidecar и словарь компаний. `mcp-plain` возвращает исходные read-only данные и
нужен для локального сравнения. Sidecar не публикует порт на хост.

## 1. Требования

- Windows 10/11 x64;
- включённая аппаратная виртуализация в BIOS/UEFI;
- WSL 2;
- Docker Desktop в режиме Linux containers;
- минимум 8 GB свободной RAM и около 10 GB на диске для первой сборки моделей
  Stanza/Presidio.

Проверка:

```powershell
wsl --status
docker version
docker compose version
```

Если `docker version` не показывает секцию `Server`, сначала исправьте запуск
Docker Desktop/WSL 2. Контейнерный вариант без работающей виртуализации не
запустится.

## 2. Создание конфигурации и секретов

Из корня репозитория запустите:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\initialize_production.ps1
```

Скрипт запросит URL YouTrack и read-only токены без отображения их в терминале.
Можно использовать один токен для обоих MCP либо два отдельных. Он создаст:

```text
deploy/mcp-sanitized.env
deploy/mcp-plain.env
deploy/secrets/youtrack-sanitized.token
deploy/secrets/youtrack-plain.token
deploy/secrets/sanitizer-pseudonym.key
```

Секреты исключены из Git. Не добавляйте их в коммиты и резервные копии без
шифрования. У аккаунта токена должны быть только права чтения в YouTrack.

Если нужно заменить существующие файлы, осознанно добавьте `-Force`.

## 3. Проверка и сборка

```powershell
docker compose -f docker-compose.production.yml config --quiet
docker compose -f docker-compose.production.yml build --pull
docker compose -f docker-compose.production.yml up -d
```

Первая сборка sidecar может быть долгой: в образ загружаются русская и
английская модели Stanza. Следите за состоянием:

```powershell
docker compose -f docker-compose.production.yml ps
docker compose -f docker-compose.production.yml logs -f sanitizer
```

После старта все три сервиса должны перейти в состояние `healthy`:

```powershell
docker compose -f docker-compose.production.yml ps
Test-NetConnection 127.0.0.1 -Port 8001
Test-NetConnection 127.0.0.1 -Port 8002
```

## 4. Локальная проверка без модели

Скрипт вызывает одинаковые MCP tools у двух контейнеров и сохраняет ответы на
локальный диск:

```powershell
.\.venv\Scripts\python.exe .\scripts\check_dual_mcp.py SUP-14337
```

Результаты:

```text
work/mcp-comparison/SUP-14337-sanitized.json
work/mcp-comparison/SUP-14337-plain.json
```

В защищённом файле должны присутствовать маркеры `USER-...`, `COMPANY-...`,
`[INTERNAL_HOST]`, `[SECRET]` и другие маркеры политики. В plain-файле будут
исходные данные YouTrack. Не передавайте plain-файл внешней модели.

Для просмотра событий словаря компаний:

```powershell
docker compose -f docker-compose.production.yml logs mcp-sanitized |
    Select-String "Company dictionary"
```

## 5. Подключение к Codex

Добавьте оба streamable HTTP endpoint в `%USERPROFILE%\.codex\config.toml`:

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

Перезапустите Codex после изменения конфигурации. Для обычной работы используйте
`youtrack_sanitized`. `youtrack_plain` включайте только для локальной диагностики
и сравнения, так как его ответы не очищаются.

## 6. Эксплуатация

Просмотр журналов:

```powershell
docker compose -f docker-compose.production.yml logs --tail 200 mcp-sanitized
docker compose -f docker-compose.production.yml logs --tail 200 mcp-plain
docker compose -f docker-compose.production.yml logs --tail 200 sanitizer
```

Перезапуск:

```powershell
docker compose -f docker-compose.production.yml restart
```

Обновление после получения нового кода:

```powershell
docker compose -f docker-compose.production.yml build --pull
docker compose -f docker-compose.production.yml up -d --remove-orphans
```

Остановка без удаления образов:

```powershell
docker compose -f docker-compose.production.yml down
```

Ротация токена: замените соответствующий файл в `deploy/secrets`, затем
пересоздайте сервис — обычный `restart` не перемонтирует изменившийся Docker
secret надёжно во всех версиях Compose:

```powershell
docker compose -f docker-compose.production.yml up -d --force-recreate mcp-sanitized
```

Резервное копирование ключа `sanitizer-pseudonym.key` позволяет сохранять
стабильные `USER-...` маркеры после переноса на другую машину.

## 7. Границы безопасности

- Порты `8001` и `8002` привязаны к `127.0.0.1`; не меняйте привязку на
  `0.0.0.0` без TLS, аутентификации и сетевого allowlist/reverse proxy.
- Plain MCP намеренно не санитизирует данные. Любой локальный процесс
  пользователя может обратиться к его порту.
- Read-only защита реализована в реестре MCP и центральной обёртке, но токен
  YouTrack всё равно должен иметь только права чтения.
- Защищённый MCP работает fail-closed: при недоступном sidecar или невозможности
  первоначально загрузить поле `Клиент` ответ блокируется.
- Sidecar находится в отдельной внутренней Docker-сети и недоступен с хоста.
