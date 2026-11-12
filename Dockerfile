# ============================================================================
# SENTRIX Production Containerfile (Multi-Stage Build)
# Stage 1: Build React 19 Frontend with Vite
# Stage 2: Deploy Production Python 3.12 Runtime + Static Asset Serving
# ============================================================================

# Stage 1: Frontend Static Build
FROM node:20-alpine AS frontend-builder

WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Production Python Runtime
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    SENTRIX_SERVE_STATIC=1

# Install lightweight operational utilities (health checks)
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install Python backend dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code, ML artifacts, and security lab
COPY backend/ ./backend/
COPY ml/ ./ml/
COPY security_lab/ ./security_lab/
COPY attack_request.json benign_request.json ./

# Copy built frontend assets from Stage 1 into the static mount location
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Persistent data directory for SQLite & audit logs
RUN mkdir -p /app/data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
