FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests fastapi sqlalchemy pydantic
COPY synthesize.py .
CMD ["python3", "-u", "synthesize.py"]
