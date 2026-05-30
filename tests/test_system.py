"""
Automated tests for Athena Attendance System.
Tests: auth, session management, check-in, role isolation, rate limiting.
"""
import pytest
import pytest_asyncio
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# Must be set before importing app modules
os.environ["ENCRYPTION_KEY"] = os.getenv("ENCRYPTION_KEY", "change-me")
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["RATE_LIMIT_MAX_ATTEMPTS"] = "10"
os.environ["RATE_LIMIT_WINDOW_MINUTES"] = "10"
os.environ["HOST"] = "127.0.0.1"
os.environ["PORT"] = "8000"

from backend.main import app
from backend.database import init_db, get_db, create_user
from backend.auth import hash_password
from backend.encryption import init_encryption

_TEST_DB_PATH = tempfile.mktemp(suffix=".db")


@pytest.fixture(autouse=True)
async def setup_db():
    """Initialize a fresh DB before each test."""
    if os.path.exists(_TEST_DB_PATH):
        os.unlink(_TEST_DB_PATH)
    os.environ["DATABASE_URL"] = _TEST_DB_PATH
    await init_db(_TEST_DB_PATH)
    init_encryption(os.environ["ENCRYPTION_KEY"])

    # Create teacher
    th = hash_password("teacherpass")
    await create_user(username="teacher_test", password_hash=th,
                      role="teacher", student_id=None,
                      display_name="Test Teacher", force_password_change=0)

    # Create a student
    sh = hash_password("studentpass")
    await create_user(username="student01", password_hash=sh,
                      role="student", student_id="ATH-0001",
                      display_name="Test Student 01", force_password_change=0)
    yield


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ========== AUTH TESTS ==========

@pytest.mark.asyncio
async def test_login_page_returns_html(client):
    resp = await client.get("/login")
    assert resp.status_code == 200
    assert "Athena" in resp.text
    assert "Student" in resp.text or "student" in resp.text


@pytest.mark.asyncio
async def test_student_login_success(client):
    resp = await client.post("/login", data={
        "username": "student01", "password": "studentpass", "role": "student",
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert "/student/dashboard" in resp.headers.get("location", "")
    assert "session_id" in resp.cookies


@pytest.mark.asyncio
async def test_teacher_login_success(client):
    resp = await client.post("/login", data={
        "username": "teacher_test", "password": "teacherpass", "role": "teacher",
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert "/teacher/dashboard" in resp.headers.get("location", "")
    assert "session_id" in resp.cookies


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    resp = await client.post("/login", data={
        "username": "student01", "password": "wrongpass", "role": "student",
    })
    assert resp.status_code == 401
    assert "Invalid" in resp.text


@pytest.mark.asyncio
async def test_login_wrong_role(client):
    resp = await client.post("/login", data={
        "username": "student01", "password": "studentpass", "role": "teacher",
    })
    assert resp.status_code == 403


# ========== ROLE ISOLATION ==========

@pytest.mark.asyncio
async def test_student_cannot_access_teacher_routes(client):
    resp = await client.post("/login", data={
        "username": "student01", "password": "studentpass", "role": "student",
    }, follow_redirects=False)
    cookies = resp.cookies
    resp = await client.get("/teacher/dashboard", cookies=cookies)
    assert resp.status_code in (302, 403)


@pytest.mark.asyncio
async def test_teacher_cannot_access_student_routes(client):
    resp = await client.post("/login", data={
        "username": "teacher_test", "password": "teacherpass", "role": "teacher",
    }, follow_redirects=False)
    cookies = resp.cookies
    resp = await client.get("/student/dashboard", cookies=cookies)
    assert resp.status_code in (302, 403)


@pytest.mark.asyncio
async def test_unauthenticated_redirect_to_login(client):
    resp = await client.get("/teacher/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("location", "")


# ========== SESSION & CHECK-IN TESTS ==========

@pytest.mark.asyncio
async def test_session_create_open_close(client):
    # Login as teacher
    resp = await client.post("/login", data={
        "username": "teacher_test", "password": "teacherpass", "role": "teacher",
    }, follow_redirects=False)
    cookies = resp.cookies

    # Create session
    resp = await client.post("/teacher/session/create", data={
        "session_name": "Test Session", "session_date": "2026-06-01",
        "late_threshold": 10,
    }, cookies=cookies, follow_redirects=False)
    assert resp.status_code == 302

    db = await get_db()
    cursor = await db.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1")
    sid = (await cursor.fetchone())['id']
    await db.close()

    # Open
    resp = await client.post(f"/teacher/session/{sid}/open", cookies=cookies, follow_redirects=False)
    assert resp.status_code == 302

    # Check dashboard shows open
    dash = await client.get("/teacher/dashboard", cookies=cookies)
    assert dash.status_code == 200
    assert "Test Session" in dash.text

    # Close
    resp = await client.post(f"/teacher/session/{sid}/close", cookies=cookies, follow_redirects=False)
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_student_checkin(client):
    # Teacher creates + opens session
    tr = await client.post("/login", data={
        "username": "teacher_test", "password": "teacherpass", "role": "teacher",
    }, follow_redirects=False)
    tc = tr.cookies

    await client.post("/teacher/session/create", data={
        "session_name": "Checkin Test", "session_date": "2026-06-01", "late_threshold": 10,
    }, cookies=tc, follow_redirects=False)

    db = await get_db()
    cursor = await db.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1")
    sid = (await cursor.fetchone())['id']
    await db.close()
    await client.post(f"/teacher/session/{sid}/open", cookies=tc, follow_redirects=False)

    # Student checks in
    sr = await client.post("/login", data={
        "username": "student01", "password": "studentpass", "role": "student",
    }, follow_redirects=False)
    sc = sr.cookies

    resp = await client.post("/student/checkin", cookies=sc)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["status"] in ("present", "late")

    # Duplicate check-in blocked
    dup = await client.post("/student/checkin", cookies=sc)
    assert dup.status_code == 400
    assert dup.json()["success"] is False
    assert "Already" in dup.json().get("error", "")


@pytest.mark.asyncio
async def test_checkin_fails_no_session(client):
    resp = await client.post("/login", data={
        "username": "student01", "password": "studentpass", "role": "student",
    }, follow_redirects=False)
    resp = await client.post("/student/checkin", cookies=resp.cookies)
    assert resp.status_code == 400


# ========== OVERRIDE ==========

@pytest.mark.asyncio
async def test_teacher_override(client):
    tr = await client.post("/login", data={
        "username": "teacher_test", "password": "teacherpass", "role": "teacher",
    }, follow_redirects=False)
    tc = tr.cookies
    await client.post("/teacher/session/create", data={
        "session_name": "Override Test", "session_date": "2026-06-01", "late_threshold": 10,
    }, cookies=tc, follow_redirects=False)

    db = await get_db()
    cursor = await db.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1")
    sid = (await cursor.fetchone())['id']
    await db.close()
    await client.post(f"/teacher/session/{sid}/open", cookies=tc, follow_redirects=False)

    sr = await client.post("/login", data={
        "username": "student01", "password": "studentpass", "role": "student",
    }, follow_redirects=False)
    sc = sr.cookies
    await client.post("/student/checkin", cookies=sc)

    # Override to absent
    resp = await client.post("/teacher/attendance/override", data={
        "session_id": sid, "student_id": "ATH-0001",
        "status": "absent", "reason": "Test",
    }, cookies=tc, follow_redirects=False)
    assert resp.status_code == 302

    detail = await client.get(f"/teacher/session/{sid}", cookies=tc)
    assert detail.status_code == 200
    assert "ABSENT" in detail.text


# ========== RATE LIMITING ==========

@pytest.mark.asyncio
async def test_rate_limiting(client):
    for i in range(11):
        resp = await client.post("/login", data={
            "username": "nonexistent", "password": "wrong", "role": "student",
        })
        if resp.status_code == 429:
            return
    assert False, "Rate limit not triggered after 11 attempts"
