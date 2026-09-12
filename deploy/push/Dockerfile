# §push: контейнер релея APNs (push.ecorp.red). Секрет .p8 НЕ в образе —
# монтируется томом (/secrets/AuthKey.p8, chmod 600 на хосте). БД — том /data.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY push_relay.py .
EXPOSE 8080
CMD ["python", "push_relay.py"]
