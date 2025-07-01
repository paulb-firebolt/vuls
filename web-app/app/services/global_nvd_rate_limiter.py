"""Global NVD Rate Limiter for coordinated API access across the application."""

import time
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class GlobalNVDRateLimiter:
    """
    Global rate limiter for NVD API access.
    Ensures coordinated rate limiting across all parts of the application.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return

        self._initialized = True

        # NVD API rate limits (without API key)
        self.requests_per_30_seconds = 5
        self.min_delay_between_requests = 6  # seconds

        # Request tracking
        self.request_times = []
        self.last_request_time = 0
        self.request_lock = threading.Lock()

        # Backoff configuration
        self.base_backoff_delay = 30  # seconds
        self.max_backoff_delay = 300  # 5 minutes
        self.backoff_multiplier = 2
        self.current_backoff_delay = self.base_backoff_delay

        # Rate limit violation tracking
        self.consecutive_429s = 0
        self.last_429_time = 0

        logger.info("Global NVD Rate Limiter initialized")

    def can_make_request(self) -> bool:
        """Check if we can make a request without violating rate limits."""
        with self.request_lock:
            current_time = time.time()

            # Clean old request times (older than 30 seconds)
            self.request_times = [t for t in self.request_times if current_time - t < 30]

            # Check if we're in backoff period
            if self.consecutive_429s > 0:
                time_since_last_429 = current_time - self.last_429_time
                if time_since_last_429 < self.current_backoff_delay:
                    return False

            # Check rate limits
            if len(self.request_times) >= self.requests_per_30_seconds:
                return False

            # Check minimum delay between requests
            if current_time - self.last_request_time < self.min_delay_between_requests:
                return False

            return True

    def wait_for_rate_limit(self, timeout: float = 60) -> bool:
        """
        Wait until we can make a request, respecting rate limits.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if we can proceed, False if timeout exceeded
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.can_make_request():
                return True

            # Calculate how long to wait
            with self.request_lock:
                current_time = time.time()

                # If in backoff, wait for backoff to expire
                if self.consecutive_429s > 0:
                    time_since_last_429 = current_time - self.last_429_time
                    backoff_remaining = self.current_backoff_delay - time_since_last_429
                    if backoff_remaining > 0:
                        wait_time = min(backoff_remaining, 5)  # Wait max 5 seconds at a time
                        logger.debug(f"Waiting {wait_time:.1f}s for backoff to expire")
                        time.sleep(wait_time)
                        continue

                # Check rate limit window
                self.request_times = [t for t in self.request_times if current_time - t < 30]

                if len(self.request_times) >= self.requests_per_30_seconds:
                    # Wait for oldest request to age out
                    oldest_request = min(self.request_times)
                    wait_time = min(30 - (current_time - oldest_request), 5)
                    logger.debug(f"Waiting {wait_time:.1f}s for rate limit window")
                    time.sleep(wait_time)
                    continue

                # Check minimum delay
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.min_delay_between_requests:
                    wait_time = self.min_delay_between_requests - time_since_last
                    logger.debug(f"Waiting {wait_time:.1f}s for minimum delay")
                    time.sleep(wait_time)
                    continue

        logger.warning(f"Rate limit wait timeout exceeded ({timeout}s)")
        return False

    def record_request(self) -> None:
        """Record that a request was made."""
        with self.request_lock:
            current_time = time.time()
            self.request_times.append(current_time)
            self.last_request_time = current_time

            # Reset backoff on successful request
            if self.consecutive_429s > 0:
                logger.info(f"Successful request after {self.consecutive_429s} 429 errors, resetting backoff")
                self.consecutive_429s = 0
                self.current_backoff_delay = self.base_backoff_delay

    def record_429_error(self) -> None:
        """Record that a 429 error occurred and increase backoff."""
        with self.request_lock:
            current_time = time.time()
            self.consecutive_429s += 1
            self.last_429_time = current_time

            # Increase backoff delay
            self.current_backoff_delay = min(
                self.current_backoff_delay * self.backoff_multiplier,
                self.max_backoff_delay
            )

            logger.warning(
                f"429 error #{self.consecutive_429s}, "
                f"backing off for {self.current_backoff_delay}s"
            )

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        try:
            # Use a timeout to prevent deadlock
            if self.request_lock.acquire(timeout=1):
                try:
                    current_time = time.time()

                    # Clean old request times
                    self.request_times = [t for t in self.request_times if current_time - t < 30]

                    # Calculate can_make_request without calling the method (to avoid nested lock)
                    can_make_request = True

                    # Check if we're in backoff period
                    if self.consecutive_429s > 0:
                        time_since_last_429 = current_time - self.last_429_time
                        if time_since_last_429 < self.current_backoff_delay:
                            can_make_request = False

                    # Check rate limits
                    if len(self.request_times) >= self.requests_per_30_seconds:
                        can_make_request = False

                    # Check minimum delay between requests
                    if current_time - self.last_request_time < self.min_delay_between_requests:
                        can_make_request = False

                    return {
                        "requests_in_last_30s": len(self.request_times),
                        "max_requests_per_30s": self.requests_per_30_seconds,
                        "time_since_last_request": current_time - self.last_request_time,
                        "min_delay_between_requests": self.min_delay_between_requests,
                        "consecutive_429s": self.consecutive_429s,
                        "current_backoff_delay": self.current_backoff_delay,
                        "in_backoff": self.consecutive_429s > 0 and (current_time - self.last_429_time) < self.current_backoff_delay,
                        "can_make_request": can_make_request
                    }
                finally:
                    self.request_lock.release()
            else:
                # Timeout acquiring lock, return basic stats
                return {
                    "requests_in_last_30s": "unknown (lock timeout)",
                    "max_requests_per_30s": self.requests_per_30_seconds,
                    "time_since_last_request": "unknown (lock timeout)",
                    "min_delay_between_requests": self.min_delay_between_requests,
                    "consecutive_429s": "unknown (lock timeout)",
                    "current_backoff_delay": "unknown (lock timeout)",
                    "in_backoff": "unknown (lock timeout)",
                    "can_make_request": "unknown (lock timeout)"
                }
        except Exception as e:
            return {
                "error": f"Error getting stats: {e}",
                "max_requests_per_30s": self.requests_per_30_seconds,
                "min_delay_between_requests": self.min_delay_between_requests
            }


# Global instance
global_nvd_rate_limiter = GlobalNVDRateLimiter()
