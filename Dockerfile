FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.runtime.txt ./requirements.txt
RUN pip install --no-cache-dir --requirement requirements.txt

RUN addgroup --system mcp && adduser --system --ingroup mcp --home /app mcp
COPY --chown=mcp:mcp main.py ./main.py
COPY --chown=mcp:mcp youtrack_mcp ./youtrack_mcp

ENV MCP_SERVER_NAME="youtrack-mcp"
ENV MCP_SERVER_DESCRIPTION="YouTrack MCP Server"
ENV MCP_DEBUG="false"
ENV YOUTRACK_VERIFY_SSL="true"
ENV YOUTRACK_URL=""
ENV YOUTRACK_API_TOKEN=""
ENV TRANSPORT="stdio"
ENV PORT="8000"
ENV YOUTRACK_SANITIZER_URL=""
ENV YOUTRACK_SANITIZER_TIMEOUT="10"
ENV YOUTRACK_SANITIZER_FAIL_CLOSED="true"
ENV YOUTRACK_SANITIZER_REQUIRED="false"
ENV YOUTRACK_READ_ONLY="true"

USER mcp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
    CMD python -c "import os,socket; s=socket.create_connection(('127.0.0.1',int(os.getenv('PORT','8000'))),5); s.close()"

ENTRYPOINT ["python", "main.py"]
