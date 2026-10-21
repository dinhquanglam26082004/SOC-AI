FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.8.0
RUN pip install --no-cache-dir --retries 10 --timeout 120 -r requirements.txt

COPY . .

EXPOSE 8100

HEALTHCHECK --interval=20s --timeout=5s --start-period=90s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=3)"
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "1"]
