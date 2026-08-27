# YouTrack MCP output sanitization

The MCP server sends every tool result through one central output boundary.
The boundary calls a local sidecar which applies two independent protections:

1. A per-tool structural allowlist removes fields which the model does not
   need. Issue reads retain all custom fields. The diagnostic profile replaces
   identities and `@login` mentions with stable non-reversible aliases. The
   strict profile drops identities entirely.
2. Microsoft Presidio with English and Russian Stanza models anonymizes PII,
   while Yelp detect-secrets removes credentials and known token patterns.
   Additional recognizers remove GUIDs, database names, internal host/node
   names, and UNC paths. Dates are retained as useful diagnostic data.

## Start the sanitizer

```bash
docker compose -f docker-compose.sanitizer.yml up --build -d
```

The service listens only on localhost by default.

## Configure the MCP process

The compose configuration uses the `diagnostic` profile and requires a secret
pseudonym key so aliases remain stable across restarts:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
$env:SANITIZER_PSEUDONYM_KEY = '<paste generated value>'
docker compose -f docker-compose.sanitizer.yml up --build -d
```

Set `SANITIZER_PROFILE=strict` to remove authors, reporters, assignees, and
mentions instead of pseudonymizing them.

```text
YOUTRACK_SANITIZER_URL=http://127.0.0.1:8090/sanitize
YOUTRACK_SANITIZER_TIMEOUT=10
YOUTRACK_SANITIZER_FAIL_CLOSED=true
YOUTRACK_SANITIZER_REQUIRED=true
YOUTRACK_COMPANY_SANITIZATION=true
YOUTRACK_COMPANY_SANITIZATION_REQUIRED=true
SANITIZER_PII_BATCH_MAX_CHARS=4000
YOUTRACK_COMPANY_PROJECT=SUP
YOUTRACK_COMPANY_FIELD=Клиент
YOUTRACK_COMPANY_REFRESH_SECONDS=86400
YOUTRACK_COMPANY_PSEUDONYM_KEY=<optional stable secret>
ENABLED_TOOLS=get_issue,search_issues,get_issue_comments,get_issue_links,get_projects
```

When `YOUTRACK_SANITIZER_REQUIRED=true`, the MCP process blocks every tool
result if the URL is missing or the sanitizer cannot produce a valid response.

## Concurrent use and capacity

MCP protocol handling remains asynchronous while blocking YouTrack and
sanitizer calls run in a bounded worker pool. Each worker thread has its own
YouTrack HTTP session, so multiple MCP sessions can execute safely in parallel.
The sanitizer uses separate Uvicorn worker processes because the NLP pipeline
is CPU-heavy and is not shared between processes. Work inside each sanitizer
worker is intentionally serialized to protect the Stanza/Presidio model state.

The production compose file exposes the main capacity controls:

```text
MCP_TOOL_MAX_CONCURRENCY=8
MCP_TOOL_MAX_PENDING=32
MCP_TOOL_QUEUE_TIMEOUT=40
SANITIZER_WORKERS=2
SANITIZER_THREADS_PER_WORKER=2
SANITIZER_MEMORY_LIMIT=5g
SANITIZER_CPU_LIMIT=4.0
SANITIZER_MAX_CONCURRENCY_PER_WORKER=1
SANITIZER_QUEUE_TIMEOUT=40
YOUTRACK_SANITIZER_TIMEOUT=45
MCP_SANITIZED_BIND_IP=127.0.0.1
MCP_PLAIN_BIND_IP=127.0.0.1
```

Increase `SANITIZER_WORKERS` for sustained parallel sanitization, allowing RAM
for a separate English/Russian NLP model in every worker. Keep
`SANITIZER_MAX_CONCURRENCY_PER_WORKER=1`; add worker processes or service
replicas instead of concurrently calling one model instance. The MCP pool and
pending queue provide backpressure. Once capacity is exhausted, new work gets
a bounded `server_busy`/HTTP 503 response rather than blocking MCP initialize,
health checks, and all other users indefinitely.

## Company dictionary

Before data is sent to the local sidecar, the MCP process reads the enum values
of the `Клиент` custom field from project `SUP`. The list is refreshed once per
day and is used to replace:

- a full company name;
- each distinctive word in the name;
- an explicit abbreviation contained in the name;
- an automatically derived acronym, such as `СУЭК` for
  `Сибирская угольная энергетическая компания`.

Every form of one company receives the same non-reversible `COMPANY-...` alias.
A word shared by several companies is considered ambiguous and is not replaced
on its own; the full names are still replaced. If a periodic refresh fails, the
last successful dictionary remains active. If the initial load fails and
`YOUTRACK_COMPANY_SANITIZATION_REQUIRED=true`, the central boundary blocks the
output.

If `YOUTRACK_COMPANY_PSEUDONYM_KEY` is omitted, its value is derived locally
from the YouTrack API token. Setting an independent secret keeps aliases stable
when that API token is rotated.

The optional `SANITIZER_ALLOWED_CUSTOM_FIELDS` sidecar variable can restrict
issue reads to a comma-separated allowlist. By default, and when set to `*`,
all custom fields are retained. For example, a restricted configuration is:

```text
State,Priority,Type,Subsystem,Fix versions,Affected versions,Estimation,Assignee
```

Raw attachments, raw issues, users, and writes are rejected by policy. The
`get_issue_image` tool is a narrow exception for raster images. It is enabled
only for projects listed in both `YOUTRACK_ALLOWED_IMAGE_PROJECTS` on the MCP
service and `SANITIZER_ALLOWED_IMAGE_PROJECTS` on the sidecar. The production
configuration allows `GBL`. Image bytes are type- and size-checked but are not
OCR-sanitized; filenames still pass through text sanitization.

## Read-only mode

The MCP server is read-only by default:

```text
YOUTRACK_READ_ONLY=true
```

Two independent checks enforce this setting. Mutating and unknown tools are
removed from the MCP registry, and the central wrapper blocks them again before
their method can make an HTTP request to YouTrack. `ENABLED_TOOLS` can narrow the
read allowlist further, but cannot re-enable a write operation while read-only
mode is active.

For defense in depth, the YouTrack token used by this MCP server should also
belong to an account whose YouTrack permissions are limited to reading.
