# WebSocket Troubleshooting Guide

## Issue: WebSocket Messages Not Received

If you're not seeing WebSocket messages when tasks complete, follow these troubleshooting steps:

### 1. Check Redis Connection

First, verify that Redis is running and accessible:

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_redis
```

Expected output:

```
✅ Redis connection successful
✅ Notification published successfully
📡 Published to Redis, subscribers: 1
```

### 2. Test WebSocket Connection

Test the WebSocket connection:

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_websocket_client
```

Expected output:

```
✅ WebSocket connected successfully!
📤 Sent ping
📥 Received pong - connection working!
```

### 3. Test End-to-End Notification

Test the complete notification flow:

```bash
docker exec vuls-web-dev uv run python -m app.tests.test_end_to_end
```

Expected output:

```
✅ WebSocket connected
📤 Publishing test notification...
🎯 Received task update!
✅ End-to-end notification test PASSED!
```

### 4. Check Application Logs

Look for these log messages in your application:

**WebSocket Connection:**

```
WebSocket connected for user anonymous. Total connections: 1
Redis notification subscriber started on first WebSocket connection
```

**Task Completion:**

```
Published task notification: success for task_run_id 123, subscribers: 1
Forwarded notification to WebSocket clients: success
```

### 5. Common Issues and Solutions

#### Redis Not Running

**Symptoms:** `Redis connection failed` error
**Solution:** Start Redis service or check Docker Compose configuration

#### No Subscribers

**Symptoms:** `subscribers: 0` in logs
**Solution:** Ensure WebSocket connection is established before running tasks

#### WebSocket Not Starting Subscriber

**Symptoms:** No "Redis notification subscriber started" message
**Solution:** Check for errors in WebSocket endpoint initialization

#### Task Not Publishing Notifications

**Symptoms:** No "Published task notification" messages
**Solution:** Verify `update_task_status()` is being called in task completion

### 6. Debug Mode

Enable debug logging by setting log level to DEBUG in your application configuration.

### 7. Manual Redis Test

Test Redis pub/sub manually:

**Terminal 1 (Subscribe):**

```bash
redis-cli SUBSCRIBE task_notifications
```

**Terminal 2 (Publish):**

```bash
redis-cli PUBLISH task_notifications '{"type":"task_update","data":{"status":"test"}}'
```

### 8. Docker Environment

If running in Docker, ensure:

- Redis container is running: `docker ps | grep redis`
- Network connectivity between containers
- Environment variables are correctly set

### 9. Celery Worker Logs

Check Celery worker logs for task execution:

```bash
docker logs vuls-worker
```

Look for:

- Task execution messages
- `update_task_status` calls
- Redis connection errors

### 10. Browser Developer Tools

In the browser:

1. Open Developer Tools (F12)
2. Go to Console tab
3. Look for WebSocket connection messages
4. Check for JavaScript errors

Expected console messages:

```
WebSocket connected
Received task update: Task Name - success
```

## Testing Checklist

- [ ] Redis is running and accessible
- [ ] WebSocket connects successfully
- [ ] Manual notifications work
- [ ] Task completion triggers notifications
- [ ] Browser receives and displays updates
- [ ] No errors in application logs
- [ ] No errors in browser console

## Still Having Issues?

1. Check all service dependencies are running
2. Verify environment variables are set correctly
3. Ensure firewall/network settings allow connections
4. Check for version compatibility issues
5. Review application startup logs for initialization errors
