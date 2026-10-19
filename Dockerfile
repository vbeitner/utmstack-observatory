FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data PORT=8765 BIND=0.0.0.0
# Debian security updates released after the base image was published
RUN apt-get update -q && apt-get upgrade -y -q --no-install-recommends && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home observatory \
 && mkdir -p /data && chown observatory:observatory /data
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir --no-compile -r requirements.txt \
 && pip uninstall -y -q pip   # fpdf2: PDF reports; everything else is stdlib. pip itself is not needed at runtime
COPY app/ /app/
USER observatory
VOLUME ["/data"]
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=6s --start-period=40s --retries=3 CMD ["python3", "-I", "/app/healthcheck.py"]
CMD ["python3", "-I", "/app/server.py"]
