FROM python:3.12-slim

WORKDIR /app

# Copy source and tests
COPY detector/ ./detector/
COPY tests/ ./tests/

# Install test dependency only
RUN pip install --no-cache-dir pytest==8.0.*

# Run parser tests at build time — fast, no IO needed
# Update imports to match the renamed package
RUN sed -i 's/from log_monitor\./from detector./g' tests/test_parser.py tests/test_tailer.py && \
    python -m pytest tests/test_parser.py -q

ENV NGINX_LOG_PATH=/var/log/nginx/hng-access.log
ENV DEAD_LETTER_PATH=/var/log/nginx/hng-access.dead.log
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "detector.main"]
