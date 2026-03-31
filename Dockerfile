# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
