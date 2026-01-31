FROM python:3.11-slim
WORKDIR /app

# Reuse repo-level pinned requirements for a consistent demo.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/agent_echo /app

ENV PYTHONPATH=/app
EXPOSE 8120
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8120"]
