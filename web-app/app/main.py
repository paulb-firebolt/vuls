"""Main FastAPI application"""

import asyncio
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
    from .models.host import Host
    from .models.scan import Scan
    from sqlalchemy import func, desc

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # Get dashboard statistics
    total_hosts = db.query(Host).filter(Host.is_active == True).count()
    recent_scans = db.query(Scan).filter(Scan.status == "completed").count()

    # Get latest vulnerability counts across all active hosts
    latest_scans_subquery = db.query(
        Scan.host_id,
        func.max(Scan.completed_at).label('latest_completed_at')
    ).filter(
        Scan.status == "completed"
    ).group_by(Scan.host_id).subquery()

    latest_scans = db.query(Scan).join(
        latest_scans_subquery,
        (Scan.host_id == latest_scans_subquery.c.host_id) &
        (Scan.completed_at == latest_scans_subquery.c.latest_completed_at)
    ).all()

    total_vulnerabilities = sum(scan.total_vulnerabilities or 0 for scan in latest_scans)
    total_critical = sum(scan.critical_count or 0 for scan in latest_scans)

    # Get recent hosts with their latest scans
    hosts_with_scans = db.query(Host).filter(Host.is_active == True).order_by(desc(Host.last_scan_at)).limit(5).all()

    # User is authenticated, show dashboard
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "total_hosts": total_hosts,
            "recent_scans": recent_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "total_critical": total_critical,
            "hosts_with_scans": hosts_with_scans
        }
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


@app.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request, db: Session = Depends(get_db)):
    """Hosts listing page"""
    from .auth import get_current_user_from_cookie

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # User is authenticated, show hosts page
    return templates.TemplateResponse(
        "hosts.html",
        {"request": request, "user": user}
    )


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, db: Session = Depends(get_db)):
    """Scans listing page"""
    from .auth import get_current_user_from_cookie

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # User is authenticated, show scans page
    return templates.TemplateResponse(
        "scans.html",
        {"request": request, "user": user}
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, db: Session = Depends(get_db)):
    """Reports page"""
    from .auth import get_current_user_from_cookie

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # User is authenticated, show reports page
    return templates.TemplateResponse(
        "reports.html",
        {"request": request, "user": user}
    )


@app.get("/hosts/{host_id}/vulnerabilities", response_class=HTMLResponse)
async def host_vulnerabilities_page(request: Request, host_id: int, db: Session = Depends(get_db)):
    """Host vulnerabilities page"""
    from .auth import get_current_user_from_cookie
    from .models.host import Host

    # Check if user is authenticated
    user = get_current_user_from_cookie(request, db)
    if not user:
        # Redirect to login page if not authenticated
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # Get the host
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Host not found")

    # Get latest scan
    latest_scan = host.latest_scan

    # User is authenticated, show vulnerabilities page
    return templates.TemplateResponse(
        "host_vulnerabilities.html",
        {
            "request": request,
            "user": user,
            "host": host,
            "latest_scan": latest_scan
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": settings.app_name}


# Include API routes
from .api import auth, hosts, scans, reports, ssh_config, scheduled_tasks, websocket, vulnerabilities

app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(hosts.router, prefix="/api/hosts", tags=["hosts"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(ssh_config.router, prefix="/api/ssh", tags=["ssh-config"])
app.include_router(scheduled_tasks.router, prefix="/api/scheduled-tasks", tags=["scheduled-tasks"])
app.include_router(websocket.router, prefix="/api", tags=["websocket"])
app.include_router(vulnerabilities.router, tags=["vulnerabilities"])


# Global subscriber instance
notification_subscriber = None

async def startup():
    """Initialize services on startup"""
    print("Application startup complete")
    # Redis notification subscriber will be started lazily when first WebSocket connects

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
