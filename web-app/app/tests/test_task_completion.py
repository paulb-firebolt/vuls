#!/usr/bin/env python3
"""
Test actual task completion notification flow
"""

import asyncio
import websockets
import json
import sys
from ..tasks.task_utils import update_task_status

async def test_task_completion_notification():
    """Test that task completion triggers WebSocket notifications"""
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

            print("📤 Triggering task completion...")

            # This simulates what happens when a real task completes
            # Note: This will run as a Celery task, so it's async
            task_result = update_task_status.delay(
                task_run_id=999,  # Fake task run ID
                status="success",
                result_data={
                    "scan_id": 123,
                    "vulnerabilities": 7,
                    "critical": 2,
                    "high": 3,
                    "medium": 2,
                    "low": 0
                }
            )

            print(f"📋 Celery task submitted: {task_result.id}")
            print("🔄 Waiting for WebSocket notification...")

            # Wait for the notification to arrive
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=15.0)

                try:
                    data = json.loads(message)
                    if data.get("type") == "task_update":
                        task_data = data.get("data", {})
                        print(f"🎯 Received task completion notification!")
                        print(f"   Task: {task_data.get('task_name', 'Unknown')}")
                        print(f"   Status: {task_data.get('status', 'Unknown')}")
                        print(f"   Task ID: {task_data.get('task_id', 'Unknown')}")
                        print(f"   Run ID: {task_data.get('task_run_id', 'Unknown')}")

                        result_data = task_data.get('result_data', {})
                        if result_data:
                            print(f"   Result: {result_data}")

                        print("✅ Task completion notification test PASSED!")
                        return True
                    else:
                        print(f"📥 Received other message: {data}")
                        # Continue waiting for the right message
                        return False

                except json.JSONDecodeError:
                    print(f"📥 Received non-JSON message: {message}")
                    return False

            except asyncio.TimeoutError:
                print("❌ No notification received within 15 seconds")
                print("   This suggests the task completion -> notification flow is not working")
                print("   Check if:")
                print("   - Celery worker is running")
                print("   - update_task_status is calling publish_task_notification")
                print("   - The task run ID exists in the database")
                return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def main():
    print("🧪 Task Completion Notification Test")
    print("=" * 50)
    print("This test will:")
    print("1. Connect to WebSocket")
    print("2. Trigger update_task_status via Celery")
    print("3. Verify notification is received via WebSocket")
    print("=" * 50)

    success = await test_task_completion_notification()

    print("\n" + "=" * 50)
    if success:
        print("✅ Task completion test PASSED!")
        print("   Real task completions will trigger WebSocket notifications!")
    else:
        print("❌ Task completion test FAILED!")
        print("   Check Celery worker and database setup")

    return success

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n👋 Test interrupted by user")
        sys.exit(0)
