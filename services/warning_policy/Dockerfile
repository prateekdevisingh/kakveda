FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY services/warning_policy /app
COPY services/shared /app/services/shared
COPY services/__init__.py /app/services/__init__.py
ENV PYTHONPATH=/app
EXPOSE 8105
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8105"]
