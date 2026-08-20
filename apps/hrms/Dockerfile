# A small downstream system. No xmlsec, no compiled dependencies, so this is a
# plain slim image that builds in seconds — unlike the platform's own image, which
# has to build xmlsec from source.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./

# The SQLite file lives on a volume so provisioned employees survive a restart.
# Somebody watching a demo should not lose the thing they just provisioned.
RUN mkdir -p /data
VOLUME /data

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
