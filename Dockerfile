FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data PORT=8765 BIND=0.0.0.0
RUN useradd --system --uid 10001 --no-create-home observatory \
 && mkdir -p /data && chown observatory:observatory /data
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir --no-compile -r requirements.txt   # fpdf2: PDF report generation; everything else is stdlib
COPY app/ /app/
USER observatory
VOLUME ["/data"]
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=6s --start-period=40s --retries=3 CMD ["python3", "-I", "/app/healthcheck.py"]
CMD ["python3", "-I", "/app/server.py"]
