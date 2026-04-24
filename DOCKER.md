# Docker Setup for NetAudit

## Quick Start

### Build & Run with Docker Compose
```bash
# Start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

Access the app at: **http://localhost:8080**

---

## Manual Docker Commands

### Build the image
```bash
docker build -t netaudit:latest .
```

### Run the container
```bash
docker run -d \
  --name netaudit \
  -p 8080:8080 \
  -e PORT=8080 \
  netaudit:latest
```

---

## Development with Live Reload

The docker-compose.yml includes a volume mount for `web/static`:
```yaml
volumes:
  - ./web/static:/app/web/static
```

This allows you to edit static files (HTML, CSS, JS) and see changes immediately without rebuilding.

**To restart the Go server after code changes:**
```bash
docker-compose restart netaudit
```

---

## Health Check

The container includes a built-in health check:
```bash
docker ps  # Status shows "healthy" when running well
```

Or manually:
```bash
curl http://localhost:8080/api/health
```

---

## Environment Variables

Set via docker-compose.yml or at runtime:
```bash
docker run -e PORT=9000 netaudit:latest
```

- `PORT` - Server port (default: 8080)

---

## Multi-stage Build Benefits

✅ **Smaller image size** - Only runtime dependencies in final image  
✅ **Fast builds** - Layer caching optimized  
✅ **Clean environment** - No build tools in production  

Final image is ~30MB (Alpine-based), much smaller than full Go image.

---

## Updating After Code Changes

### Frontend only (HTML/CSS/JS):
```bash
docker-compose restart netaudit
```

### Backend code changes:
```bash
docker-compose up --build
```

### Full rebuild:
```bash
docker-compose down
docker-compose up --build -d
```
