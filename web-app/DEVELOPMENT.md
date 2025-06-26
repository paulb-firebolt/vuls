# 🚀 Vuls Web Application - Development Guide

## 🔧 Development Environment Setup

### **Quick Start**
```bash
# Start development environment with hot reload
cd web-app
./start-dev.sh

# Access the application
open http://localhost:8000
```

### **Development vs Production**

| Feature | Development (`start-dev.sh`) | Production (`start.sh`) |
|---------|------------------------------|-------------------------|
| **Hot Reload** | ✅ Enabled | ❌ Disabled |
| **Code Mounting** | ✅ Live code changes | ❌ Baked into image |
| **Restart Speed** | ⚡ Instant | 🐌 Full rebuild |
| **Docker Profile** | `dev` | `web` |
| **Container Name** | `vuls-web-dev` | `vuls-web` |

## 🔄 Development Workflow

### **1. Start Development Environment**
```bash
cd web-app
./start-dev.sh
```

### **2. Make Code Changes**
- Edit files in `web-app/app/` directory
- Changes are automatically detected and server restarts
- No need to rebuild Docker containers

### **3. View Logs**
```bash
# Watch development logs
docker compose logs -f vuls-web-dev

# View all services
docker compose logs -f
```

### **4. Stop Development Environment**
```bash
docker compose --profile dev down
```

## 📁 Project Structure

```
web-app/
├── app/                    # 🔄 Hot-reloaded source code
│   ├── __init__.py
│   ├── main.py            # FastAPI application
│   ├── config.py          # Configuration settings
│   ├── auth.py            # Authentication system
│   ├── models/            # Database models
│   │   ├── base.py
│   │   ├── user.py
│   │   ├── host.py
│   │   ├── scan.py
│   │   └── vulnerability.py
│   ├── api/               # API endpoints
│   │   ├── auth.py
│   │   ├── hosts.py
│   │   ├── scans.py
│   │   └── reports.py
│   └── templates/         # HTML templates
│       ├── base.html
│       ├── login.html
│       └── dashboard.html
├── static/                # 🔄 Hot-reloaded static files
│   ├── css/
│   └── js/
├── Dockerfile             # Production build
├── Dockerfile.dev         # Development build
├── pyproject.toml         # Dependencies
├── start.sh              # Production startup
└── start-dev.sh          # Development startup
```

## 🛠 Development Features

### **Hot Reload**
- **Automatic**: Code changes trigger server restart
- **Fast**: Only reloads Python application, not container
- **Comprehensive**: Watches all files in `/app` directory

### **Volume Mounts**
```yaml
volumes:
  - ./web-app/app:/app/app:rw          # Source code
  - ./web-app/static:/app/static:rw    # Static files
  - ./web-app/pyproject.toml:/app/pyproject.toml:ro  # Dependencies
```

### **Development Dependencies**
- **uvicorn**: ASGI server with auto-reload
- **watchfiles**: File change detection
- **debugpy**: Python debugging support

## 🔐 Authentication System

### **Cookie-Based Sessions**
- **Secure**: HTTP-only cookies with JWT tokens
- **Timeout**: 30-minute session expiration
- **CSRF Protection**: SameSite cookie attributes

### **Development Login**
1. **Create Admin**: Click "Create Admin" on login page
2. **Default Credentials**: `admin` / `admin123`
3. **Auto-Redirect**: Successful login redirects to dashboard

## 🐛 Debugging

### **View Application Logs**
```bash
# Real-time logs
docker compose logs -f vuls-web-dev

# Filter by service
docker compose logs vuls-web-dev

# Last 100 lines
docker compose logs --tail=100 vuls-web-dev
```

### **Database Access**
```bash
# Connect to PostgreSQL
docker exec -it vuls-db psql -U vuls -d vuls

# View tables
\dt

# Check users
SELECT * FROM users;
```

### **Container Shell Access**
```bash
# Access development container
docker exec -it vuls-web-dev bash

# Check Python environment
uv run python --version

# Run commands inside container
uv run python -c "from app.config import settings; print(settings.app_name)"
```

## 🚀 Making Changes

### **Adding New API Endpoints**
1. Create new file in `app/api/`
2. Define routes using FastAPI decorators
3. Import and include router in `main.py`
4. Changes auto-reload immediately

### **Modifying Templates**
1. Edit HTML files in `app/templates/`
2. Use Jinja2 templating syntax
3. Changes reflect immediately on page refresh

### **Database Changes**
1. Modify models in `app/models/`
2. Database tables auto-create on startup
3. For migrations, consider using Alembic

### **Adding Dependencies**
1. Edit `pyproject.toml`
2. Restart development environment to install new packages
3. Or run: `docker exec vuls-web-dev uv sync`

## 📊 Performance Tips

### **Fast Development Cycle**
- ✅ Use `start-dev.sh` for development
- ✅ Keep containers running between sessions
- ✅ Only restart when adding new dependencies
- ❌ Don't use `start.sh` during development

### **Efficient Debugging**
- ✅ Use `docker compose logs -f` for real-time monitoring
- ✅ Add print statements for quick debugging
- ✅ Use browser dev tools for frontend issues
- ❌ Don't rebuild containers for code changes

## 🔧 Troubleshooting

### **Port Already in Use**
```bash
# Stop all containers
docker compose --profile dev down
docker compose --profile web down

# Check what's using port 8000
lsof -i :8000

# Kill process if needed
kill -9 <PID>
```

### **Database Connection Issues**
```bash
# Check database status
docker compose ps

# Restart database
docker compose restart vuls-db

# View database logs
docker compose logs vuls-db
```

### **Hot Reload Not Working**
```bash
# Check if files are mounted correctly
docker exec vuls-web-dev ls -la /app/app/

# Restart development container
docker compose restart vuls-web-dev
```

## 🎯 Next Steps

### **Ready for Development**
- ✅ Hot reload environment running
- ✅ Authentication system working
- ✅ Database connected
- ✅ API endpoints accessible
- ✅ Web interface functional

### **Development Tasks**
- 🔨 Add host management features
- 🔨 Implement scan orchestration
- 🔨 Create vulnerability dashboards
- 🔨 Build reporting system
- 🔨 Add user management

---

**🌐 Your development environment is ready at http://localhost:8000**

**🔄 Code changes will automatically reload - no container restarts needed!**
