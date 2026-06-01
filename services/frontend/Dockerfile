FROM docker.io/library/users-api:latest
WORKDIR /app
COPY index.html .
COPY serve.py .
CMD ["uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "80"]
