FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV STANZA_RESOURCES_DIR=/opt/stanza_resources

WORKDIR /app

COPY sanitizer_service/requirements.txt ./requirements.txt
# Stanza needs PyTorch, but the sanitizer is CPU-only. Installing it first from
# the official CPU wheel index prevents pip from pulling the multi-GB CUDA stack.
RUN pip install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    "torch==2.13.0+cpu"
RUN pip install --no-cache-dir -r requirements.txt
RUN python -c "import stanza; stanza.download('en'); stanza.download('ru')"

RUN addgroup --system sanitizer && adduser --system --ingroup sanitizer --home /app sanitizer
COPY --chown=sanitizer:sanitizer sanitizer_service ./sanitizer_service

USER sanitizer
EXPOSE 8090
CMD ["uvicorn", "sanitizer_service.service:app", "--host", "0.0.0.0", "--port", "8090"]
