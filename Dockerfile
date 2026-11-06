FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 chat_hook \
    && mkdir -p /data && chown 10001:10001 /data
COPY chat_hook ./chat_hook
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "chat_hook.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
