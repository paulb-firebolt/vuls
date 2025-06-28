#!/usr/bin/env python3
"""
Test WebSocket connection from within container
"""

import asyncio
import websockets
import json
import sys

async def test_websocket():
    """Test WebSocket connection and listen for messages"""
    uri = "ws://localhost:8000/api/ws"

    try:
        print(f"🔌 Connecting to {uri}...")
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected successfully!")

            # Send a ping to test the connection
            await websocket.send("ping")
            print("📤 Sent ping")

            # Listen for messages for a short time
            print("🔄 Listening for messages (5 second timeout)...")
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=5.0)

                if message == "pong":
                    print("📥 Received pong - connection working!")
                    return True
                elif message.startswith("Echo:"):
                    print(f"📥 Received echo: {message}")
                    return True
                else:
                    try:
                        data = json.loads(message)
                        if data.get("type") == "task_update":
                            task_data = data.get("data", {})
                            print(f"🎯 Task Update: {task_data.get('task_name', 'Unknown')} - {task_data.get('status', 'Unknown')}")
                            return True
                        else:
                            print(f"📥 Received message: {message}")
                            return True
                    except json.JSONDecodeError:
                        print(f"📥 Received raw message: {message}")
                        return True

            except asyncio.TimeoutError:
                print("⏰ No response received within timeout")
                return False

    except websockets.exceptions.ConnectionRefused:
        print("❌ Connection refused. Make sure the web application is running")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def main():
    print("🧪 WebSocket Connection Test")
    print("=" * 50)

    success = await test_websocket()

    print("\n" + "=" * 50)
    if success:
        print("✅ WebSocket test passed!")
    else:
        print("❌ WebSocket test failed!")

    return success

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n👋 Test interrupted by user")
        sys.exit(0)
