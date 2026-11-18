FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests rich fastapi uvicorn "sqlalchemy>=2" "pydantic>=2" httpx email-validator python-multipart
COPY synthesizer/synthesize.py ./
COPY common ./common
RUN mkdir -p /app/common && true
CMD ["python3", "-u", "synthesize.py"]
