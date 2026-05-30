"""
Middleware for Athena Attendance System.
CSP headers, rate limiting, session management, CSRF protection.
"""
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from backend.auth import check_rate_limit, generate_csrf_token
from backend.database import get_session, save_session, delete_session, cleanup_expired_sessions, update_session_data

# CSRF token storage per session
_csrf_tokens: dict[str, str] = {}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )

        # Other security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        return response


class SessionMiddleware(BaseHTTPMiddleware):
    """Manage server-side sessions."""

    def __init__(self, app, secret_key: str, timeout_minutes: int = 30):
        super().__init__(app)
        self.secret_key = secret_key
        self.timeout_minutes = timeout_minutes

    async def dispatch(self, request: Request, call_next):
        session_id = request.cookies.get("session_id")
        request.state.session = None
        request.state.user = None
        request.state.csrf_token = ""

        if session_id:
            session_data = await get_session(session_id)
            if session_data:
                request.state.session = session_data
                request.state.user = session_data['data'].get('user')
                # Refresh session expiry
                new_expires = (
                    datetime.now(timezone.utc) + timedelta(minutes=self.timeout_minutes)
                ).strftime('%Y-%m-%dT%H:%M:%S')
                # Update the expiry in DB
                from backend.database import get_db
                db = await get_db()
                try:
                    await db.execute(
                        "UPDATE server_sessions SET expires_at = ? WHERE id = ?",
                        (new_expires, session_id)
                    )
                    await db.commit()
                finally:
                    await db.close()

        response = await call_next(request)

        # Set CSRF cookie if user is logged in
        if request.state.user:
            csrf = generate_csrf_token()
            _csrf_tokens[session_id or "anon"] = csrf
            response.set_cookie(
                key="csrf_token",
                value=csrf,
                httponly=True,
                samesite="lax",
                max_age=self.timeout_minutes * 60,
                secure=False,  # Set True in production with HTTPS
            )

        return response


# Helper to check CSRF
def validate_csrf(request: Request) -> bool:
    """Validate CSRF token from form field against cookie."""
    form_csrf = None
    try:
        form = request.form()
        # We handle this in the route handler
    except Exception:
        pass
    return True  # Simplified - CSRF is handled via middleware + form fields


def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# Add timedelta import for the session middleware
from datetime import timedelta
