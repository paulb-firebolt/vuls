#!/usr/bin/env python3
"""
Test Redis connection from within container
"""

import redis
from ..config import settings
from ..utils.notification_service import publish_task_notification
import json

def test_redis_connection():
    """Test Redis connection"""
    print("🧪 Testing Redis Connection")
    print("=" * 40)
    try:
        client = redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
        print("✅ Redis connection successful")
        print(f"   Redis URL: {settings.redis_url}")
        return True
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        print(f"   Redis URL: {settings.redis_url}")
        return False

def test_publish_notification():
    """Test publishing notification"""
    print("\n📤 Testing Notification Publishing")
    print("=" * 40)
    try:
        publish_task_notification(
            task_id=999,
            task_run_id=999,
            status="success",
            task_name="Container Test Task",
            result_data={"test": True, "source": "container"}
        )
        print("✅ Notification published successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to publish notification: {e}")
        return False

def test_redis_pubsub():
    """Test Redis pub/sub"""
    print("\n📡 Testing Redis Pub/Sub")
    print("=" * 40)
    try:
        client = redis.from_url(settings.redis_url, decode_responses=True)

        # Test publishing and check subscriber count
        result = client.publish("task_notifications", json.dumps({
            "type": "task_update",
            "data": {"status": "test", "message": "Direct Redis test"}
        }))

        print(f"📡 Published to Redis, subscribers: {result}")
        if result > 0:
            print("✅ Message delivered to subscribers")
        else:
            print("⚠️  No subscribers currently listening")
        return True
    except Exception as e:
        print(f"❌ Redis pub/sub test failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Container Redis Test")
    print("=" * 50)

    success = True
    success &= test_redis_connection()
    success &= test_publish_notification()
    success &= test_redis_pubsub()

    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
