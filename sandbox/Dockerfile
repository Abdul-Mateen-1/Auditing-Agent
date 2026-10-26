# Build this trusted image separately; audited repositories never supply the image.
FROM python:3.12-slim
RUN python -m pip install --no-cache-dir pytest==8.4.2 ruff==0.12.0
USER 65534:65534
WORKDIR /repo
