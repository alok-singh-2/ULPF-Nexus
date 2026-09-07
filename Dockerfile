FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt \
    && useradd --system --create-home --uid 10001 nexus
COPY . /app
RUN mkdir -p /app/backend/data && chown -R nexus:nexus /app
USER nexus
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()"
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
