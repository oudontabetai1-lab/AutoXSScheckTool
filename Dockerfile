# WScan — containerized intranet server build
#
# Builds a self-contained image with Python, the scanner, and a Chromium
# browser (via Playwright) so the dashboard can be hosted on a server and
# operated from the intranet over a web browser.
FROM python:3.11-slim

# Avoid interactive prompts and keep Python output unbuffered for logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    # Default bind/port — override via docker-compose or `docker run -e`.
    WSCAN_HOST=0.0.0.0 \
    WSCAN_PORT=8765

WORKDIR /app

# Install Python dependencies first to leverage Docker layer caching.
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    # Fetch the Chromium build matching the installed Playwright version,
    # together with the required OS libraries.
    playwright install --with-deps chromium

# Copy the application source.
COPY . .

# Reports are written here; mount a volume to persist them on the host.
RUN mkdir -p /app/output
VOLUME ["/app/output"]

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('WSCAN_PORT','8765')+'/health', timeout=3)" || exit 1

# Start the persistent dashboard server. WSCAN_AUTH_TOKEN (if set) enables
# the login page; WSCAN_HOST / port are honoured by `serve`.
CMD ["sh", "-c", "python main.py serve --host \"$WSCAN_HOST\" --port \"$WSCAN_PORT\" --no-open-browser"]
