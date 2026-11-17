FROM mcr.microsoft.com/playwright/python:v1.48.0-noble
WORKDIR /app
RUN pip install --no-cache-dir playwright==1.48.0
COPY explore.py .
CMD ["python3", "-u", "explore.py"]
