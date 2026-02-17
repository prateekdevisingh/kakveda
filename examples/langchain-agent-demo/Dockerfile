FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Allow `docker run <image> --run-once ...` to pass args cleanly.
ENTRYPOINT ["python", "agent_app.py"]
CMD []

