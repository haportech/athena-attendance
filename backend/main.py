"""
Athena Attendance System - Main Application
FastAPI + Jinja2 server with all routes for student and teacher portals.
"""
import os
import csv
import io
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from dotenv import load_dotenv

# Backend modules
from backend.encryption import init_encryption
from backend.database import (
    init_db, get_user_by_username, get_user_by_id, get_all_students,
    create_session, open_session, close_session, get_active_session,
    get_session_by_id, get_sessions, check_in_student,
    get_attendance_for_session, get_all_attendance_with_students,
    check_student_checked_in, override_attendance, override_attendance_by_student,
    get_attendance_stats, get_student_attendance_summary,
    get_attendance_for_student, create_announcement, get_active_announcements,
    get_all_announcements, toggle_announcement, log_audit, get_audit_logs,
    save_session, delete_session, check_db_integrity,
    update_user_password, create_user, update_user, reset_student_password,
    cleanup_expired_sessions
)
from backend.auth import (
    hash_password, verify_password, check_rate_limit, reset_rate_limit,
    generate_session_id, get_session_timeout_minutes
)
from backend.middleware import (
    SecurityHeadersMiddleware, SessionMiddleware, get_client_ip
)

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
DATABASE_URL = os.getenv("DATABASE_URL", "athena_attendance.db")
TIMEZONE_STR = os.getenv("TIMEZONE", "Asia/Vientiane")
SESSION_TIMEOUT_MINUTES = get_session_timeout_minutes(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
DEFAULT_LATE_THRESHOLD = int(os.getenv("DEFAULT_LATE_THRESHOLD", "10"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "5"))
RATE_LIMIT_WINDOW_MINUTES = int(os.getenv("RATE_LIMIT_WINDOW_MINUTES", "10"))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, "frontend", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Global CSRF store (in production, use Redis or DB)
_csrf_store: dict[str, str] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown."""
    # Startup
    await init_db(DATABASE_URL)
    init_encryption(ENCRYPTION_KEY)
    await cleanup_expired_sessions()
    logger.info(f"Athena Attendance System started on {HOST}:{PORT}")
    yield
    # Shutdown
    logger.info("Shutting down...")


app = FastAPI(
    title="Athena Attendance System",
    description="Year 11 Athena - Online Attendance Management",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,  # Disable Swagger in production
    redoc_url=None,
)

# Middleware - order matters (Session must be first to set request.state)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    timeout_minutes=SESSION_TIMEOUT_MINUTES,
)
app.add_middleware(SecurityHeadersMiddleware)

# Static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# --- Template Helpers ---

def get_now_local() -> str:
    """Get current datetime in configured timezone as string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def get_context(request: Request, extra: dict = None) -> dict:
    """Get base template context."""
    ctx = {
        "request": request,
        "user": request.state.user,
        "now": get_now_local(),
        "timezone": TIMEZONE_STR,
    }
    if extra:
        ctx.update(extra)
    return ctx


# --- Auth Dependencies ---

async def require_login(request: Request):
    """Redirect to login if not authenticated."""
    if not request.state.user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})


async def require_teacher(request: Request):
    """Require teacher role."""
    if not request.state.user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    if request.state.user.get("role") != "teacher":
        raise HTTPException(status_code=403, detail="Access denied")


async def require_student(request: Request):
    """Require student role."""
    if not request.state.user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    if request.state.user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Access denied")


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.state.user:
        if request.state.user.get("role") == "teacher":
            return RedirectResponse(url="/teacher/dashboard", status_code=302)
        return RedirectResponse(url="/student/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


# ========== AUTH ==========

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.state.user:
        if request.state.user.get("role") == "teacher":
            return RedirectResponse(url="/teacher/dashboard", status_code=302)
        return RedirectResponse(url="/student/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", get_context(request))


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
):
    ip = get_client_ip(request)

    # Rate limiting
    if not check_rate_limit(ip, RATE_LIMIT_MAX_ATTEMPTS, RATE_LIMIT_WINDOW_MINUTES):
        await log_audit(None, username, "LOGIN_BLOCKED", "Rate limit exceeded", ip,
                        request.headers.get("user-agent", ""))
        return templates.TemplateResponse(
            "login.html", get_context(request, {"error": "Too many login attempts. Try again later."}),
            status_code=429
        )

    user = await get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        await log_audit(None, username, "LOGIN_FAILED", "Invalid credentials", ip,
                        request.headers.get("user-agent", ""))
        return templates.TemplateResponse(
            "login.html", get_context(request, {"error": "Invalid username or password."}),
            status_code=401
        )

    if user["role"] != role:
        await log_audit(user["id"], username, "LOGIN_FAILED",
                        f"Wrong role selected (tried: {role}, actual: {user['role']})",
                        ip, request.headers.get("user-agent", ""))
        return templates.TemplateResponse(
            "login.html", get_context(request, {"error": "Invalid role selection for this account."}),
            status_code=403
        )

    if not user["is_active"]:
        await log_audit(user["id"], username, "LOGIN_BLOCKED", "Account deactivated", ip,
                        request.headers.get("user-agent", ""))
        return templates.TemplateResponse(
            "login.html", get_context(request, {"error": "Account is deactivated. Contact your teacher."}),
            status_code=403
        )

    # Successful login
    reset_rate_limit(ip)
    session_id = generate_session_id()
    expires = (
        datetime.now(timezone.utc) + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    session_data = {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "student_id": user.get("student_id"),
            "display_name": user["display_name"],
            "force_password_change": user["force_password_change"],
        }
    }

    await save_session(session_id, user["id"], session_data, expires)
    await log_audit(user["id"], username, "LOGIN_SUCCESS", "User logged in", ip,
                    request.headers.get("user-agent", ""))

    response = RedirectResponse(
        url="/teacher/dashboard" if user["role"] == "teacher" else "/student/dashboard",
        status_code=302
    )
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TIMEOUT_MINUTES * 60,
        secure=False,
    )

    return response


@app.get("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        await delete_session(session_id)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_id")
    response.delete_cookie("csrf_token")
    return response


@app.get("/force-password-change", response_class=HTMLResponse)
async def force_password_change_page(request: Request):
    if not request.state.user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("change_password.html", get_context(request))


@app.post("/force-password-change")
async def force_password_change_submit(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    if not request.state.user:
        return RedirectResponse(url="/login", status_code=302)

    user_id = request.state.user["id"]
    user = await get_user_by_id(user_id)

    if not verify_password(current_password, user["password_hash"]):
        return templates.TemplateResponse(
            "change_password.html",
            get_context(request, {"error": "Current password is incorrect."}),
            status_code=401
        )

    if new_password != confirm_password:
        return templates.TemplateResponse(
            "change_password.html",
            get_context(request, {"error": "New passwords do not match."}),
            status_code=400
        )

    if len(new_password) < 8:
        return templates.TemplateResponse(
            "change_password.html",
            get_context(request, {"error": "Password must be at least 8 characters."}),
            status_code=400
        )

    new_hash = hash_password(new_password)
    await update_user_password(user_id, new_hash)
    await log_audit(user_id, user["username"], "PASSWORD_CHANGE", "Password changed", 
                    get_client_ip(request), request.headers.get("user-agent", ""))

    # Update session data so force_password_change reflects immediately
    session_id = request.cookies.get("session_id")
    if session_id and request.state.session:
        sd = request.state.session["data"]
        if "user" in sd:
            sd["user"]["force_password_change"] = 0
            request.state.user["force_password_change"] = 0
            from backend.database import update_session_data
            await update_session_data(session_id, sd)

    return RedirectResponse(
        url="/teacher/dashboard" if user["role"] == "teacher" else "/student/dashboard",
        status_code=302
    )


# ========== STUDENT PORTAL ==========

@app.get("/student/dashboard", response_class=HTMLResponse)
async def student_dashboard(request: Request):
    if not request.state.user or request.state.user.get("role") != "student":
        return RedirectResponse(url="/login", status_code=302)

    user = request.state.user

    # Check forced password change
    if user.get("force_password_change"):
        return RedirectResponse(url="/force-password-change", status_code=302)

    active_session = await get_active_session()
    student_id = user["student_id"]
    announcements = await get_active_announcements(5)
    stats = await get_student_attendance_summary(student_id)

    already_checked_in = None
    if active_session:
        already_checked_in = await check_student_checked_in(active_session["id"], student_id)

    return templates.TemplateResponse(
        "student/dashboard.html",
        get_context(request, {
            "active_session": active_session,
            "announcements": announcements,
            "stats": stats,
            "already_checked_in": already_checked_in,
        })
    )


@app.post("/student/checkin")
async def student_checkin(request: Request):
    if not request.state.user or request.state.user.get("role") != "student":
        return JSONResponse({"success": False, "error": "Unauthorized"}, status_code=403)

    user = request.state.user
    active_session = await get_active_session()

    if not active_session:
        return JSONResponse({"success": False, "error": "No active session"}, status_code=400)

    already = await check_student_checked_in(active_session["id"], user["student_id"])
    if already:
        return JSONResponse({"success": False, "error": "Already checked in"}, status_code=400)

    ip = get_client_ip(request)
    result = await check_in_student(
        active_session["id"], user["student_id"], ip,
        active_session["late_threshold_minutes"]
    )

    if result["success"]:
        await log_audit(user["id"], user["username"],
                        "CHECKIN", f"Checked in as {result['status']} for session {active_session['id']}",
                        ip, request.headers.get("user-agent", ""))

    return JSONResponse(result)


@app.get("/student/history", response_class=HTMLResponse)
async def student_history(request: Request):
    if not request.state.user or request.state.user.get("role") != "student":
        return RedirectResponse(url="/login", status_code=302)

    student_id = request.state.user["student_id"]
    records = await get_attendance_for_student(student_id, 100)
    stats = await get_student_attendance_summary(student_id)

    return templates.TemplateResponse(
        "student/history.html",
        get_context(request, {"records": records, "stats": stats})
    )


# ========== TEACHER PORTAL ==========

@app.get("/teacher/dashboard", response_class=HTMLResponse)
async def teacher_dashboard(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    if request.state.user.get("force_password_change"):
        return RedirectResponse(url="/force-password-change", status_code=302)

    active_session = await get_active_session()
    attendance_data = []
    stats = {"present": 0, "late": 0, "absent": 0, "checked_in": 0, "total": 20}

    if active_session:
        attendance_data = await get_all_attendance_with_students(active_session["id"])
        stats = await get_attendance_stats(active_session["id"])
        # Ensure absent students count towards total
        stats["total"] = 20

    announcements = await get_active_announcements(5)
    sessions = await get_sessions(10)

    return templates.TemplateResponse(
        "teacher/dashboard.html",
        get_context(request, {
            "active_session": active_session,
            "attendance_data": attendance_data,
            "stats": stats,
            "announcements": announcements,
            "sessions": sessions,
            "late_threshold": DEFAULT_LATE_THRESHOLD,
        })
    )


@app.post("/teacher/session/create")
async def teacher_create_session(
    request: Request,
    session_name: str = Form(...),
    session_date: str = Form(...),
    late_threshold: int = Form(10),
):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    session_id = await create_session(
        session_name, session_date, now_utc, late_threshold, request.state.user["id"]
    )

    await log_audit(request.state.user["id"], request.state.user["username"],
                    "SESSION_CREATED", f"Created session: {session_name} on {session_date}",
                    get_client_ip(request), request.headers.get("user-agent", ""))

    return RedirectResponse(url="/teacher/dashboard", status_code=302)


@app.post("/teacher/session/{session_id}/open")
async def teacher_open_session(request: Request, session_id: int):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    await open_session(session_id)
    await log_audit(request.state.user["id"], request.state.user["username"],
                    "SESSION_OPENED", f"Opened session {session_id}",
                    get_client_ip(request), request.headers.get("user-agent", ""))

    return RedirectResponse(url="/teacher/dashboard", status_code=302)


@app.post("/teacher/session/{session_id}/close")
async def teacher_close_session(request: Request, session_id: int):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    await close_session(session_id)
    await log_audit(request.state.user["id"], request.state.user["username"],
                    "SESSION_CLOSED", f"Closed session {session_id}",
                    get_client_ip(request), request.headers.get("user-agent", ""))

    return RedirectResponse(url="/teacher/dashboard", status_code=302)


@app.post("/teacher/attendance/override")
async def teacher_override_attendance(
    request: Request,
    session_id: int = Form(...),
    student_id: str = Form(...),
    status: str = Form(...),
    reason: str = Form(""),
):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return JSONResponse({"success": False, "error": "Unauthorized"}, status_code=403)

    await override_attendance_by_student(
        session_id, student_id, status, request.state.user["id"], reason
    )

    await log_audit(request.state.user["id"], request.state.user["username"],
                    "ATTENDANCE_OVERRIDE",
                    f"Overrode {student_id} to {status} in session {session_id}. Reason: {reason}",
                    get_client_ip(request), request.headers.get("user-agent", ""))

    return RedirectResponse(url="/teacher/dashboard", status_code=302)


@app.get("/teacher/sessions", response_class=HTMLResponse)
async def teacher_sessions(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    sessions = await get_sessions(100)
    return templates.TemplateResponse(
        "teacher/sessions.html",
        get_context(request, {"sessions": sessions})
    )


@app.get("/teacher/session/{session_id}", response_class=HTMLResponse)
async def teacher_session_detail(request: Request, session_id: int):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    session = await get_session_by_id(session_id)
    attendance = await get_all_attendance_with_students(session_id)
    stats = await get_attendance_stats(session_id)

    return templates.TemplateResponse(
        "teacher/session_detail.html",
        get_context(request, {
            "session": session,
            "attendance": attendance,
            "stats": stats,
        })
    )


@app.get("/teacher/history", response_class=HTMLResponse)
async def teacher_history(
    request: Request,
    student: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    sessions = await get_sessions(200)
    students = await get_all_students()

    # Filter logic on sessions
    filtered_sessions = []
    for s in sessions:
        include = True
        if date_from and s["session_date"] < date_from:
            include = False
        if date_to and s["session_date"] > date_to:
            include = False
        if include:
            filtered_sessions.append(s)

    # Build combined attendance data
    attendance_data = []
    for s in filtered_sessions:
        records = await get_all_attendance_with_students(s["id"])
        for r in records:
            if student and r["student_id"] != student:
                continue
            if status_filter and r["status"] != status_filter:
                continue
            attendance_data.append({
                "session_name": s["session_name"],
                "session_date": s["session_date"],
                "student_id": r["student_id"],
                "display_name": r["display_name"],
                "status": r["status"],
                "check_in_time": r.get("check_in_time", "-"),
                "ip_address": r.get("ip_address", "-"),
            })

    return templates.TemplateResponse(
        "teacher/history.html",
        get_context(request, {
            "attendance_data": attendance_data,
            "students": students,
            "filter_student": student,
            "filter_date_from": date_from,
            "filter_date_to": date_to,
            "filter_status": status_filter,
        })
    )


@app.get("/teacher/analytics", response_class=HTMLResponse)
async def teacher_analytics(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    students = await get_all_students()
    sessions = await get_sessions(200)

    # Per-student stats
    student_stats = []
    for s in students:
        stats = await get_student_attendance_summary(s["student_id"])
        student_stats.append({
            "student_id": s["student_id"],
            "display_name": s["display_name"],
            **stats
        })

    # Per-session stats
    session_stats = []
    for s in sessions:
        stats = await get_attendance_stats(s["id"])
        session_stats.append({
            "session_name": s["session_name"],
            "session_date": s["session_date"],
            **stats
        })

    # Overall class stats
    total_present = sum(s["present"] for s in session_stats)
    total_late = sum(s["late"] for s in session_stats)
    total_absent = sum(s["absent"] for s in session_stats)
    total_all = total_present + total_late + total_absent
    overall_percentage = round((total_present / total_all * 100) if total_all > 0 else 0, 1)

    return templates.TemplateResponse(
        "teacher/analytics.html",
        get_context(request, {
            "student_stats": student_stats,
            "session_stats": session_stats,
            "overall_percentage": overall_percentage,
            "total_present": total_present,
            "total_late": total_late,
            "total_absent": total_absent,
            "total_all": total_all,
        })
    )


@app.get("/teacher/export/csv")
async def teacher_export_csv(request: Request, session_id: Optional[int] = Query(None)):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Student ID", "Student Name", "Status", "Check-in Time", "IP Address", "Session", "Date"])

    if session_id:
        session = await get_session_by_id(session_id)
        records = await get_all_attendance_with_students(session_id)
        for r in records:
            writer.writerow([
                r["student_id"], r["display_name"], r["status"],
                r.get("check_in_time", "-"), r.get("ip_address", "-"),
                session["session_name"], session["session_date"]
            ])
    else:
        sessions = await get_sessions(200)
        for s in sessions:
            records = await get_all_attendance_with_students(s["id"])
            for r in records:
                writer.writerow([
                    r["student_id"], r["display_name"], r["status"],
                    r.get("check_in_time", "-"), r.get("ip_address", "-"),
                    s["session_name"], s["session_date"]
                ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attendance_export.csv"}
    )


@app.get("/teacher/export/pdf")
async def teacher_export_pdf(request: Request, session_id: Optional[int] = Query(None)):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Athena Attendance Report")

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Year 11 Athena - Attendance Report", styles['Title']))
    elements.append(Spacer(1, 12))

    data = [["Student ID", "Name", "Status", "Check-in Time", "IP Address"]]

    if session_id:
        session = await get_session_by_id(session_id)
        records = await get_all_attendance_with_students(session_id)
        elements.append(Paragraph(f"Session: {session['session_name']} - {session['session_date']}", styles['Heading2']))
        elements.append(Spacer(1, 12))
        for r in records:
            data.append([
                r["student_id"], r["display_name"], r["status"].upper(),
                r.get("check_in_time", "-")[:19] if r.get("check_in_time") else "-",
                r.get("ip_address", "-")
            ])
    else:
        sessions = await get_sessions(200)
        for s in sessions:
            elements.append(Paragraph(f"Session: {s['session_name']} - {s['session_date']}", styles['Heading3']))
            records = await get_all_attendance_with_students(s["id"])
            data = [["Student ID", "Name", "Status", "Check-in Time", "IP Address"]]
            for r in records:
                data.append([
                    r["student_id"], r["display_name"], r["status"].upper(),
                    r.get("check_in_time", "-")[:19] if r.get("check_in_time") else "-",
                    r.get("ip_address", "-")
                ])

            table = Table(data, colWidths=[1*inch, 1.8*inch, 0.8*inch, 1.8*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))
            continue

        table = Table(data, colWidths=[1*inch, 1.8*inch, 0.8*inch, 1.8*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(table)

    doc.build(elements)
    buf.seek(0)

    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=attendance_report.pdf"}
    )


@app.get("/teacher/announcements", response_class=HTMLResponse)
async def teacher_announcements(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    announcements = await get_all_announcements()
    return templates.TemplateResponse(
        "teacher/announcements.html",
        get_context(request, {"announcements": announcements})
    )


@app.post("/teacher/announcements/create")
async def teacher_create_announcement(
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    await create_announcement(title, content, request.state.user["id"])
    await log_audit(request.state.user["id"], request.state.user["username"],
                    "ANNOUNCEMENT", f"Created announcement: {title}",
                    get_client_ip(request), request.headers.get("user-agent", ""))

    return RedirectResponse(url="/teacher/announcements", status_code=302)


@app.post("/teacher/announcements/{announcement_id}/toggle")
async def teacher_toggle_announcement(request: Request, announcement_id: int):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    from backend.database import get_db
    db = await get_db()
    try:
        cursor = await db.execute("SELECT is_active FROM announcements WHERE id = ?", (announcement_id,))
        row = await cursor.fetchone()
        if row:
            await toggle_announcement(announcement_id, 0 if row['is_active'] else 1)
    finally:
        await db.close()

    return RedirectResponse(url="/teacher/announcements", status_code=302)


@app.get("/teacher/students", response_class=HTMLResponse)
async def teacher_students(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    students = await get_all_students()
    return templates.TemplateResponse(
        "teacher/students.html",
        get_context(request, {"students": students})
    )


@app.post("/teacher/students/reset-password")
async def teacher_reset_password(
    request: Request,
    student_id: str = Form(...),
):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    new_hash = hash_password("Athena2025!")
    await reset_student_password(student_id, new_hash)

    await log_audit(request.state.user["id"], request.state.user["username"],
                    "PASSWORD_RESET", f"Reset password for {student_id}",
                    get_client_ip(request), request.headers.get("user-agent", ""))

    return RedirectResponse(url="/teacher/students", status_code=302)


@app.post("/teacher/students/toggle")
async def teacher_toggle_student(
    request: Request,
    user_id: int = Form(...),
):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    from backend.database import get_db
    db = await get_db()
    try:
        cursor = await db.execute("SELECT is_active FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        if row:
            await update_user(user_id, is_active=0 if row['is_active'] else 1)
    finally:
        await db.close()

    return RedirectResponse(url="/teacher/students", status_code=302)


@app.get("/teacher/audit-log", response_class=HTMLResponse)
async def teacher_audit_log(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return RedirectResponse(url="/login", status_code=302)

    logs = await get_audit_logs(200)
    return templates.TemplateResponse(
        "teacher/audit_log.html",
        get_context(request, {"logs": logs})
    )


@app.get("/teacher/integrity-check")
async def teacher_integrity_check(request: Request):
    if not request.state.user or request.state.user.get("role") != "teacher":
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    result = await check_db_integrity()
    return JSONResponse(result)


# ========== API (for dynamic check-in status) ==========

@app.get("/api/active-session")
async def api_active_session(request: Request):
    active = await get_active_session()
    if active:
        attendance_data = await get_all_attendance_with_students(active["id"])
        stats = await get_attendance_stats(active["id"])
        return {
            "active": True,
            "session": {
                "id": active["id"],
                "name": active["session_name"],
                "date": active["session_date"],
                "start_time": active["start_time"],
                "late_threshold": active["late_threshold_minutes"],
            },
            "attendance": [
                {
                    "student_id": r["student_id"],
                    "display_name": r["display_name"],
                    "status": r["status"],
                    "check_in_time": r.get("check_in_time"),
                    "ip_address": r.get("ip_address"),
                }
                for r in attendance_data
            ],
            "stats": {
                "present": stats["present"],
                "late": stats["late"],
                "absent": stats["absent"],
                "checked_in": stats["checked_in"],
                "total": 20,
            }
        }
    return {"active": False}


# ========== ERROR HANDLERS ==========

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return templates.TemplateResponse("error.html", get_context(request, {
        "code": 404, "message": "Page not found"
    }), status_code=404)


@app.exception_handler(403)
async def forbidden(request: Request, exc):
    return templates.TemplateResponse("error.html", get_context(request, {
        "code": 403, "message": "Access denied"
    }), status_code=403)


@app.exception_handler(500)
async def server_error(request: Request, exc):
    return templates.TemplateResponse("error.html", get_context(request, {
        "code": 500, "message": "Internal server error"
    }), status_code=500)


# --- Entry point ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=True)
