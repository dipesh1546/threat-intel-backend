"""
Rate Limiting for authentication endpoints
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

# Create limiter
limiter = Limiter(key_func=get_remote_address)

def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Custom handler for rate limit exceeded"""
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests. Please try again later."}
    )

# Rate limit decorator for auth endpoints
def auth_rate_limit(limit: str = "5/minute"):
    """Rate limit for auth endpoints - 5 attempts per minute"""
    return limiter.limit(limit)
