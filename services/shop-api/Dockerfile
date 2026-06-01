FROM docker.io/library/users-api:latest
WORKDIR /app
RUN apt-get update -qq && apt-get install -y -qq postgresql-client && rm -rf /var/lib/apt/lists/*
COPY main.py .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
