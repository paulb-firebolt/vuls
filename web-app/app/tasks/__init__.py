"""Celery tasks for the Vuls Web application"""

from ..celery_app import celery_app

# Import all task modules to register them with Celery
from . import scan_tasks
from . import db_update_tasks
from . import scheduler_tasks
from . import host_sync_tasks

__all__ = ["celery_app"]
