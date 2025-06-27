"""Main FastAPI application"""

from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from .config import settings
from .models.base import get_db, engine
from .models import Base
from .auth import get_current_active_user_from_cookie
from .models.user import User

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="Centralized Vulnerability Management System",
    version="0.1.0",
    debug=settings.debug
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main dashboard - redirect to login if not authenticated"""
    from .auth import get_current_user_from_cookie

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # User is authenticated, show dashboard
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user}
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


@app.get("/ssh-config", response_class=HTMLResponse)
async def ssh_config_page(request: Request, db: Session = Depends(get_db)):
    """SSH Configuration page"""
    from .auth import get_current_user_from_cookie

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # User is authenticated, show SSH config page
    return templates.TemplateResponse(
        "ssh_config.html",
        {"request": request, "user": user}
    )


@app.get("/scheduler", response_class=HTMLResponse)
async def scheduler_page(request: Request, db: Session = Depends(get_db)):
    """Task Scheduler page"""
    from .auth import get_current_user_from_cookie

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # User is authenticated, show scheduler page
    return templates.TemplateResponse(
        "scheduler.html",
        {"request": request, "user": user}
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": settings.app_name}


# Include API routes
from .api import auth, hosts, scans, reports, ssh_config, scheduled_tasks, websocket

app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(hosts.router, prefix="/api/hosts", tags=["hosts"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(ssh_config.router, prefix="/api/ssh", tags=["ssh-config"])
app.include_router(scheduled_tasks.router, prefix="/api/scheduled-tasks", tags=["scheduled-tasks"])
app.include_router(websocket.router, prefix="/api", tags=["websocket"])


# Global subscriber instance
notification_subscriber = None

async def startup():
    """Initialize services on startup"""
    global notification_subscriber
    from .utils.notification_service import NotificationSubscriber
    from .api.websocket import manager

    # Start the Redis notification subscriber
    notification_subscriber = NotificationSubscriber(manager)
    await notification_subscriber.start_listening()
    print("Redis notification subscriber started")

async def shutdown():
    """Cleanup on shutdown"""
    global notification_subscriber
    if notification_subscriber:
        notification_subscriber.stop_listening()

# Add startup and shutdown events
@app.on_event("startup")
async def startup_event():
    await startup()

@app.on_event("shutdown")
async def shutdown_event():
    await shutdown()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
