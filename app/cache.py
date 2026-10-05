"""Redis client. Used for server-side sessions (Step 2) and rate limiting (Phase 2)."""

import redis
from fastapi import Request


def create_redis(url: str) -> redis.Redis:
    client = redis.Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=2,
        socket_connect_timeout=2,
        health_check_interval=30,
    )
    client.ping()  # fail at startup if Redis is unreachable or the password is wrong
    return client


async def get_redis(request: Request) -> redis.Redis:
    return request.app.state.redis
