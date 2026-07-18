"""One shared Redis connection for the app (rate limiting today, more later)."""

import redis

from app.config import settings

# decode_responses=True -> we get str back, not bytes.
redis_client = redis.from_url(settings.redis_url, decode_responses=True)
