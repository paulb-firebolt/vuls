#!/usr/bin/env python3
"""
Test script to verify executor service connection
"""

import asyncio
import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.utils.executor_client import sync_health_check, ExecutorClient


def test_executor_connection():
    """Test connection to executor service"""
    print("Testing executor service connection...")

    try:
        # Test health check
        is_healthy = sync_health_check()
        if is_healthy:
            print("✅ Executor service is healthy and reachable")
            return True
        else:
            print("❌ Executor service is not healthy or not reachable")
            return False
    except Exception as e:
        print(f"❌ Error connecting to executor service: {e}")
        return False


async def test_executor_async():
    """Test async executor client"""
    print("\nTesting async executor client...")

    try:
        client = ExecutorClient()
        is_healthy = await client.health_check()
        if is_healthy:
            print("✅ Async executor client works correctly")
            return True
        else:
            print("❌ Async executor client failed health check")
            return False
    except Exception as e:
        print(f"❌ Error with async executor client: {e}")
        return False


if __name__ == "__main__":
    print("Executor Service Connection Test")
    print("=" * 40)

    # Test synchronous client
    sync_result = test_executor_connection()

    # Test asynchronous client
    async_result = asyncio.run(test_executor_async())

    print("\n" + "=" * 40)
    if sync_result and async_result:
        print("✅ All tests passed! Executor service is working correctly.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Check executor service configuration.")
        sys.exit(1)
