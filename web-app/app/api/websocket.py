"""WebSocket endpoints for real-time updates"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import json
import logging
import asyncio
from datetime import datetime

from ..models.base import get_db
from ..auth import get_current_user_from_cookie
from ..utils.notification_service import NotificationSubscriber

logger = logging.getLogger(__name__)

router = APIRouter()

# Global notification subscriber
notification_subscriber = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info(f"WebSocket connected for user {user_id}. Total connections: {len(self.active_connections)}")

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        logger.info(f"WebSocket disconnected for user {user_id}. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: Dict[str, Any], user_id: str):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error sending message to user {user_id}: {e}")
                self.disconnect(user_id)

    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for user_id, connection in self.active_connections.items():
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error broadcasting to user {user_id}: {e}")
                disconnected.append(user_id)

        # Remove disconnected connections
        for user_id in disconnected:
            self.disconnect(user_id)

    async def send_task_update(self, task_update: Dict[str, Any], user_id: str = None):
        """Send task update to specific user or broadcast to all"""
        message = {
            "type": "task_update",
            "data": task_update,
            "timestamp": datetime.utcnow().isoformat()
        }

        if user_id:
            await self.send_personal_message(message, user_id)
        else:
            await self.broadcast(message)

manager = ConnectionManager()


async def ensure_notification_subscriber():
    """Ensure the notification subscriber is running"""
    global notification_subscriber
    if notification_subscriber is None:
        try:
            # Create and start the notification subscriber
            notification_subscriber = NotificationSubscriber(manager)
            await notification_subscriber.start_listening()
            logger.info("Redis notification subscriber started on first WebSocket connection")

            # Update the main module's reference
            import sys
            main_module = sys.modules.get('app.main')
            if main_module:
                main_module.notification_subscriber = notification_subscriber

        except Exception as e:
            logger.error(f"Failed to start notification subscriber: {e}")
            raise e

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    # Accept the connection first, then handle authentication if needed
    await websocket.accept()

    # For now, we'll use a simple connection without user authentication
    # In production, you'd want to authenticate the WebSocket connection
    user_id = "anonymous"  # This should be replaced with actual user authentication

    # Add to connection manager
    manager.active_connections[user_id] = websocket
    logger.info(f"WebSocket connected for user {user_id}. Total connections: {len(manager.active_connections)}")

    # Start notification subscriber on first connection
    if len(manager.active_connections) == 1:
        try:
            await ensure_notification_subscriber()
            logger.info("Notification subscriber started successfully")
        except Exception as e:
            logger.error(f"Failed to start notification subscriber: {e}")
            await websocket.send_text(f"Error: Failed to start notification subscriber: {e}")

    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()

            # Handle ping/pong for connection health
            if data == "ping":
                await websocket.send_text("pong")
            else:
                # Echo back for now
                await websocket.send_text(f"Echo: {data}")

    except WebSocketDisconnect:
        if user_id in manager.active_connections:
            del manager.active_connections[user_id]
        logger.info(f"WebSocket disconnected for user {user_id}. Total connections: {len(manager.active_connections)}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if user_id in manager.active_connections:
            del manager.active_connections[user_id]
        logger.info(f"WebSocket disconnected for user {user_id}. Total connections: {len(manager.active_connections)}")


# Function to be called from scan tasks
async def notify_task_completion(task_id: int, task_run_id: int, status: str, result_data: Dict[str, Any] = None):
    """Notify all connected clients about task completion"""
    update = {
        "task_id": task_id,
        "task_run_id": task_run_id,
        "status": status,
        "result_data": result_data or {},
        "completed_at": datetime.utcnow().isoformat()
    }

    await manager.send_task_update(update)


# Function to be called when task starts
async def notify_task_started(task_id: int, task_run_id: int, task_name: str):
    """Notify all connected clients about task start"""
    update = {
        "task_id": task_id,
        "task_run_id": task_run_id,
        "task_name": task_name,
        "status": "started",
        "started_at": datetime.utcnow().isoformat()
    }

    await manager.send_task_update(update)


# Export the manager for use in other modules
__all__ = ["router", "manager", "notify_task_completion", "notify_task_started"]
