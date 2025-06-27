"""Notification service for real-time updates via Redis pub/sub"""

import json
import logging
import asyncio
import redis
from typing import Dict, Any
from datetime import datetime
from ..config import settings

logger = logging.getLogger(__name__)

# Redis client for publishing notifications
redis_client = redis.from_url(
    settings.redis_url,
    decode_responses=True
)

NOTIFICATION_CHANNEL = "task_notifications"


def publish_task_notification(task_id: int, task_run_id: int, status: str, task_name: str = None, result_data: dict = None):
    """Publish a task notification via Redis pub/sub"""
    try:
        notification = {
            "type": "task_update",
            "data": {
                "task_id": task_id,
                "task_run_id": task_run_id,
                "status": status,
                "task_name": task_name,
                "result_data": result_data or {},
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        # Publish to Redis
        redis_client.publish(NOTIFICATION_CHANNEL, json.dumps(notification))
        logger.info(f"Published task notification: {status} for task_run_id {task_run_id}")

    except Exception as e:
        logger.error(f"Error publishing task notification: {e}")


class NotificationSubscriber:
    """Redis subscriber for task notifications"""

    def __init__(self, websocket_manager):
        self.websocket_manager = websocket_manager
        self.redis_client = redis.from_url(
            settings.redis_url,
            decode_responses=True
        )
        self.pubsub = self.redis_client.pubsub()
        self.running = False

    async def start_listening(self):
        """Start listening for Redis notifications"""
        try:
            self.pubsub.subscribe(NOTIFICATION_CHANNEL)
            self.running = True
            logger.info("Started listening for task notifications")

            # Run in a separate thread to avoid blocking
            import threading
            thread = threading.Thread(target=self._listen_loop, daemon=True)
            thread.start()

        except Exception as e:
            logger.error(f"Error starting notification listener: {e}")

    def _listen_loop(self):
        """Listen for Redis messages in a separate thread"""
        try:
            for message in self.pubsub.listen():
                if message['type'] == 'message':
                    try:
                        notification = json.loads(message['data'])
                        # Forward to WebSocket clients
                        asyncio.run(self._forward_to_websockets(notification))
                    except Exception as e:
                        logger.error(f"Error processing notification: {e}")
        except Exception as e:
            logger.error(f"Error in notification listen loop: {e}")

    async def _forward_to_websockets(self, notification: Dict[str, Any]):
        """Forward notification to WebSocket clients"""
        try:
            await self.websocket_manager.broadcast(notification)
            logger.info(f"Forwarded notification to WebSocket clients: {notification['data']['status']}")
        except Exception as e:
            logger.error(f"Error forwarding to WebSocket: {e}")

    def stop_listening(self):
        """Stop listening for notifications"""
        self.running = False
        self.pubsub.unsubscribe(NOTIFICATION_CHANNEL)
        self.pubsub.close()
        logger.info("Stopped listening for task notifications")
