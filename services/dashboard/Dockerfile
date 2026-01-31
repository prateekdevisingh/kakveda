FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Service code + shared libs
COPY services/dashboard /app

# Compatibility: dashboard imports `from shared...`.
# Copy the shared package to `/app/shared` so it is importable on PYTHONPATH.
COPY shared /app/shared

# Keep the services namespace available for any `services.*` imports.
COPY services/shared /app/services/shared
COPY services/__init__.py /app/services/__init__.py

ENV PYTHONPATH=/app
EXPOSE 8110
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8110"]
