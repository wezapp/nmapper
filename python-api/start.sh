#!/bin/bash
mkdir -p /home/runner/workspace/python-api/scans
exec /home/runner/workspace/.pythonlibs/bin/uvicorn main:asgi_app \
  --app-dir /home/runner/workspace/python-api \
  --host 0.0.0.0 \
  --port "$PORT"
