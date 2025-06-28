#!/usr/bin/env python3
"""
End-to-end test of the notification system
"""

import asyncio
import websockets
import json
import sys
from ..utils.notification_service import publish_task_notification

async def test_notification_delivery():
    """Test that notifications are delivered via WebSocket"""
    uri = "ws://localhost:8000/api/ws"

    try:
        print("🔌 Connecting to WebSocket...")
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected")

            # Send ping to establish connection
            await websocket.send("ping")
            pong = await websocket.recv()
            if pong == "pong":
                print("📥 Ping/pong successful")

            print("📤 Publishing test notification...")

            # Publish a notification
            publish_task_notification(
                task_id=123,
                task_run_id=456,
                status="success",
                task_name="End-to-End Test Task",
                result_data={
                    "test": True,
                    "message": "This is an end-to-end test",
                    "vulnerabilities": 5,
                    "critical": 1,
                    "high": 2,
                    "medium": 2,
                    "low": 0
                }
            )

            print("🔄 Waiting for WebSocket notification...")

            # Wait for the notification to arrive
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=10.0)

                try:
                    data = json.loads(message)
                    if data.get("type") == "task_update":
                        task_data = data.get("data", {})
                        print(f"🎯 Received task update!")
                        print(f"   Task: {task_data.get('task_name', 'Unknown')}")
                        print(f"   Status: {task_data.get('status', 'Unknown')}")
                        print(f"   Task ID: {task_data.get('task_id', 'Unknown')}")
                        print(f"   Run ID: {task_data.get('task_run_id', 'Unknown')}")

                        result_data = task_data.get('result_data', {})
                        if result_data:
                            print(f"   Result: {result_data}")

                        print("✅ End-to-end notification test PASSED!")
                        return True
                    else:
                        print(f"📥 Received other message: {data}")
                        return False

                except json.JSONDecodeError:
                    print(f"📥 Received non-JSON message: {message}")
                    return False

            except asyncio.TimeoutError:
                print("❌ No notification received within 10 seconds")
                print("   This suggests the Redis pub/sub -> WebSocket forwarding is not working")
                return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def main():
    print("🧪 End-to-End Notification Test")
    print("=" * 50)
    print("This test will:")
    print("1. Connect to WebSocket")
    print("2. Publish a Redis notification")
    print("3. Verify it's received via WebSocket")
    print("=" * 50)

    success = await test_notification_delivery()

    print("\n" + "=" * 50)
    if success:
        print("✅ End-to-end test PASSED!")
        print("   The notification system is working correctly!")
    else:
        print("❌ End-to-end test FAILED!")
        print("   Check the Redis subscriber and WebSocket forwarding")

    return success

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n👋 Test interrupted by user")
        sys.exit(0)
