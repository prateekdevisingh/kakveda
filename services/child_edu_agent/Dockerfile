FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    httpx \
    pydantic

# Copy application
COPY services/child_edu_agent/app.py .
COPY services/child_edu_agent/__init__.py .

# Expose port
EXPOSE 8120

# Run
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8120"]
