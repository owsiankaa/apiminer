FROM mcr.microsoft.com/playwright/python:v1.48.0-noble
WORKDIR /app
RUN pip install --no-cache-dir playwright==1.48.0 rich requests
COPY explorer/*.py ./
COPY common ./common
CMD ["python3", "-u", "explore.py"]
