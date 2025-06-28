# WebSocket Notification System Tests

This directory contains tests for the WebSocket-based real-time notification system.

## Test Files

### `test_redis.py`

Tests Redis connection and notification publishing functionality.

**Usage:**

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_redis
```

**What it tests:**

- Redis connection to `vuls-redis` container
- Notification publishing via `publish_task_notification()`
- Redis pub/sub subscriber count

### `test_websocket_client.py`

Tests WebSocket connection and basic communication.

**Usage:**

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_websocket_client
```

**What it tests:**

- WebSocket connection to `/api/ws`
- Ping/pong communication
- Basic message handling

### `test_end_to_end.py`

Tests complete notification flow from Redis to WebSocket.

**Usage:**

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_end_to_end
```

**What it tests:**

- WebSocket connection
- Redis notification publishing
- Message delivery via WebSocket
- Complete notification data structure

### `test_task_completion.py`

Tests actual task completion notification flow via Celery.

**Usage:**

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_task_completion
```

**What it tests:**

- Celery task execution
- `update_task_status()` function
- Task completion notifications
- Real-world notification flow

## Running All Tests

To run all tests in sequence:

```bash
# From the project root
docker exec vuls-web-dev uv run python -m app.tests.test_redis
docker exec vuls-web-dev uv run python -m app.tests.test_websocket_client
docker exec vuls-web-dev uv run python -m app.tests.test_end_to_end
```

## Expected Results

All tests should pass with output similar to:

```
✅ Redis connection successful
✅ WebSocket connected successfully!
✅ End-to-end test PASSED!
```

## Troubleshooting

If tests fail, check:

1. **Redis container is running:** `docker ps | grep redis`
2. **Web application is running:** `docker ps | grep web-dev`
3. **Celery worker is running:** `docker ps | grep worker`
4. **Network connectivity between containers**

See `docs/development/websocket-troubleshooting.md` for detailed troubleshooting steps.
