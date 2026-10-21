FROM python:3.12-slim
WORKDIR /app
COPY wazuh_integration /app/wazuh_integration
CMD ["python", "-m", "wazuh_integration.forwarder"]
