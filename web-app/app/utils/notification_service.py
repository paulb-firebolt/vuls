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
        message_json = json.dumps(notification)
        result = redis_client.publish(NOTIFICATION_CHANNEL, message_json)
        logger.info(f"Published task notification: {status} for task_run_id {task_run_id}, subscribers: {result}")
        logger.debug(f"Notification content: {message_json}")

    except Exception as e:
        logger.error(f"Error publishing task notification: {e}")
        # Try to test Redis connection
        try:
            redis_client.ping()
            logger.error("Redis is reachable but publish failed")
        except Exception as redis_e:
            logger.error(f"Redis connection failed: {redis_e}")


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
        self._loop = None
        self._task = None

    async def start_listening(self):
        """Start listening for Redis notifications"""
        try:
            self.running = True
            self._loop = asyncio.get_event_loop()

            # Start the listening task in background - don't await it
            self._task = asyncio.create_task(self._listen_loop())
            logger.info("Started listening for task notifications")

            # Return immediately without waiting for the task to start
            return

        except Exception as e:
            logger.error(f"Error starting notification listener: {e}")

    async def _listen_loop(self):
        """Listen for Redis messages asynchronously"""
        try:
            # Add a small delay to ensure startup completes first
            await asyncio.sleep(0.1)

            # Use modern redis library's async functionality
            try:
                logger.info("Using modern redis library async functionality")
                await self._listen_loop_async()
            except Exception as e:
                logger.warning(f"Async Redis failed: {e}, falling back to sync")
                await self._listen_loop_sync()

        except Exception as e:
            logger.error(f"Error in notification listen loop: {e}")

    async def _listen_loop_sync(self):
        """Fallback sync listening with proper async handling"""
        import threading
        import queue

        logger.info("Starting sync Redis listener with async wrapper")

        # Create a queue to pass messages from sync thread to async handler
        message_queue = queue.Queue()

        def sync_listener():
            """Sync listener that puts messages in queue"""
            try:
                logger.info("Sync Redis listener thread started, subscribing to Redis")
                # Subscribe inside the thread to avoid blocking startup
                self.pubsub.subscribe(NOTIFICATION_CHANNEL)
                logger.info(f"Subscribed to Redis channel: {NOTIFICATION_CHANNEL}")

                for message in self.pubsub.listen():
                    if not self.running:
                        logger.info("Sync Redis listener stopping")
                        break
                    if message['type'] == 'message':
                        logger.info(f"Received Redis message: {message['data'][:100]}...")
                        message_queue.put(message['data'])
            except Exception as e:
                logger.error(f"Error in sync listener: {e}")

        # Start sync listener in thread
        thread = threading.Thread(target=sync_listener, daemon=True)
        thread.start()
        logger.info("Sync Redis listener thread started")

        # Process messages asynchronously without blocking
        async def process_messages():
            logger.info("Starting message processing loop")
            while self.running:
                try:
                    # Use asyncio.to_thread to make queue.get non-blocking
                    try:
                        # Check for messages with a very short timeout to avoid blocking
                        message_data = await asyncio.to_thread(message_queue.get, timeout=0.1)
                        notification = json.loads(message_data)
                        await self._forward_to_websockets(notification)
                    except queue.Empty:
                        # No message available, sleep briefly and continue
                        await asyncio.sleep(0.1)
                        continue
                    except Exception as e:
                        logger.error(f"Error processing queued message: {e}")
                        await asyncio.sleep(0.1)
                except Exception as e:
                    logger.error(f"Error in async message processing: {e}")
                    await asyncio.sleep(1)

        # Start message processing in background and return immediately
        asyncio.create_task(process_messages())
        logger.info("Sync Redis message processing started in background")

    async def _listen_loop_async(self):
        """Async Redis listening using modern redis library"""
        logger.info("Starting async Redis listener with modern redis library")

        try:
            # Create async Redis client using redis.asyncio
            async_redis = redis.asyncio.from_url(settings.redis_url, decode_responses=True)

            # Create pubsub
            pubsub = async_redis.pubsub()
            await pubsub.subscribe(NOTIFICATION_CHANNEL)
            logger.info(f"Subscribed to Redis channel: {NOTIFICATION_CHANNEL}")

            # Listen for messages
            while self.running:
                try:
                    # Get message with timeout
                    message = await asyncio.wait_for(pubsub.get_message(ignore_subscribe_messages=True), timeout=1.0)

                    if message and message['type'] == 'message':
                        logger.info(f"Received async Redis message: {message['data'][:100]}...")
                        notification = json.loads(message['data'])
                        await self._forward_to_websockets(notification)

                except asyncio.TimeoutError:
                    # Timeout is normal, continue listening
                    continue
                except Exception as e:
                    logger.error(f"Error processing async message: {e}")
                    await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Error in async Redis listener: {e}")
            raise
        finally:
            try:
                await pubsub.unsubscribe(NOTIFICATION_CHANNEL)
                await async_redis.close()
            except:
                pass

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
        if self._task:
            self._task.cancel()
        self.pubsub.unsubscribe(NOTIFICATION_CHANNEL)
        self.pubsub.close()
        logger.info("Stopped listening for task notifications")
