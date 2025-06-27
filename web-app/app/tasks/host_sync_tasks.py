"""Host synchronization tasks"""

import logging
from typing import Dict, Any
from celery import current_task

from ..celery_app import celery_app
from ..models.base import get_db
from ..utils.vuls_config import sync_hosts_from_vuls_config, get_vuls_config_info

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="sync_hosts_from_vuls_config")
def sync_hosts_from_config_task(self) -> Dict[str, Any]:
    """
    Celery task to synchronize hosts from Vuls configuration file

    Returns:
        Dict with sync statistics and status
    """
    task_id = self.request.id
    logger.info(f"Starting host sync task {task_id}")

    try:
        # Update task status
        current_task.update_state(
            state='PROGRESS',
            meta={'status': 'Reading Vuls configuration...', 'progress': 10}
        )

        # Get database session
        db = next(get_db())

        try:
            # Update task status
            current_task.update_state(
                state='PROGRESS',
                meta={'status': 'Synchronizing hosts...', 'progress': 50}
            )

            # Perform the sync
            stats = sync_hosts_from_vuls_config(db)

            # Update task status
            current_task.update_state(
                state='PROGRESS',
                meta={'status': 'Finalizing...', 'progress': 90}
            )

            logger.info(f"Host sync task {task_id} completed: {stats}")

            return {
                'status': 'completed',
                'task_id': task_id,
                'stats': stats,
                'message': f"Successfully synchronized {stats['total']} hosts from Vuls config"
            }

        finally:
            db.close()

    except Exception as e:
        error_msg = f"Host sync task {task_id} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)

        return {
            'status': 'failed',
            'task_id': task_id,
            'error': str(e),
            'message': error_msg
        }


@celery_app.task(bind=True, name="get_vuls_config_status")
def get_vuls_config_status_task(self) -> Dict[str, Any]:
    """
    Celery task to get Vuls configuration status

    Returns:
        Dict with configuration information
    """
    task_id = self.request.id
    logger.info(f"Starting Vuls config status task {task_id}")

    try:
        config_info = get_vuls_config_info()

        logger.info(f"Vuls config status task {task_id} completed")

        return {
            'status': 'completed',
            'task_id': task_id,
            'config_info': config_info,
            'message': f"Found {config_info['host_count']} hosts in Vuls config"
        }

    except Exception as e:
        error_msg = f"Vuls config status task {task_id} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)

        return {
            'status': 'failed',
            'task_id': task_id,
            'error': str(e),
            'message': error_msg
        }


@celery_app.task(bind=True, name="scheduled_host_sync")
def scheduled_host_sync_task(self) -> Dict[str, Any]:
    """
    Scheduled task to automatically sync hosts from Vuls config
    This can be run periodically to keep hosts in sync

    Returns:
        Dict with sync results
    """
    task_id = self.request.id
    logger.info(f"Starting scheduled host sync task {task_id}")

    try:
        # Get database session
        db = next(get_db())

        try:
            # Check if config file exists and has hosts
            config_info = get_vuls_config_info()

            if not config_info['config_exists']:
                return {
                    'status': 'skipped',
                    'task_id': task_id,
                    'message': 'Vuls config file not found, skipping sync'
                }

            if config_info['host_count'] == 0:
                return {
                    'status': 'skipped',
                    'task_id': task_id,
                    'message': 'No hosts found in Vuls config, skipping sync'
                }

            # Perform the sync
            stats = sync_hosts_from_vuls_config(db)

            logger.info(f"Scheduled host sync task {task_id} completed: {stats}")

            return {
                'status': 'completed',
                'task_id': task_id,
                'stats': stats,
                'config_info': config_info,
                'message': f"Scheduled sync: {stats['created']} created, {stats['updated']} updated, {stats['errors']} errors"
            }

        finally:
            db.close()

    except Exception as e:
        error_msg = f"Scheduled host sync task {task_id} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)

        return {
            'status': 'failed',
            'task_id': task_id,
            'error': str(e),
            'message': error_msg
        }
