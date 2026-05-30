"""
Database setup and operations for Athena Attendance System.
Uses aiosqlite for async SQLite access with parameterized queries only.
Sensitive fields are encrypted at rest via backend.encryption module.
"""
import aiosqlite
import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Any

from backend.encryption import encrypt, decrypt

logger = logging.getLogger(__name__)

DB_PATH = None

# SQL for schema creation
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student', 'teacher')),
    student_id TEXT UNIQUE,
    display_name TEXT NOT NULL,
    force_password_change INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_name TEXT NOT NULL,
    session_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    late_threshold_minutes INTEGER DEFAULT 10,
    is_active INTEGER DEFAULT 1,
    is_open INTEGER DEFAULT 0,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attendance_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    student_id TEXT NOT NULL REFERENCES users(student_id),
    check_in_time TEXT,
    status TEXT NOT NULL DEFAULT 'absent' CHECK(status IN ('present','late','absent')),
    ip_address_enc TEXT,
    is_override INTEGER DEFAULT 0,
    overridden_by INTEGER REFERENCES users(id),
    override_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(session_id, student_id)
);

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    posted_by INTEGER REFERENCES users(id),
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    details_enc TEXT,
    ip_address_enc TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS server_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance_records(session_id);
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance_records(student_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_date ON sessions(session_date);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_open);
CREATE INDEX IF NOT EXISTS idx_server_sessions_expires ON server_sessions(expires_at);
"""


async def get_db() -> aiosqlite.Connection:
    """Get async database connection."""
    if DB_PATH is None:
        raise RuntimeError("Database not initialized - call init_db() first")
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db(db_path: str):
    """Initialize database, creating tables if they don't exist."""
    global DB_PATH
    DB_PATH = db_path
    db = await get_db()
    try:
        await db.executescript(SCHEMA_SQL)
        await db.commit()
        logger.info(f"Database initialized at {db_path}")
    finally:
        await db.close()


# --- User Queries ---

async def get_user_by_username(username: str) -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, password_hash, role, student_id, display_name, "
            "force_password_change, is_active, created_at FROM users WHERE username = ? AND is_active = 1",
            (username,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_user_by_id(user_id: int) -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, password_hash, role, student_id, display_name, "
            "force_password_change, is_active, created_at FROM users WHERE id = ?",
            (user_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_all_students() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, student_id, display_name, is_active, created_at "
            "FROM users WHERE role = 'student' ORDER BY student_id"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def create_user(username: str, password_hash: str, role: str,
                      student_id: Optional[str], display_name: str,
                      force_password_change: int = 0) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO users (username, password_hash, role, student_id, display_name, force_password_change) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, password_hash, role, student_id, display_name, force_password_change)
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_user_password(user_id: int, new_password_hash: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, force_password_change = 0, "
            "updated_at = datetime('now') WHERE id = ?",
            (new_password_hash, user_id)
        )
        await db.commit()
    finally:
        await db.close()


async def update_user(user_id: int, display_name: Optional[str] = None,
                      is_active: Optional[int] = None):
    sets = []
    params = []
    if display_name is not None:
        sets.append("display_name = ?")
        params.append(display_name)
    if is_active is not None:
        sets.append("is_active = ?")
        params.append(is_active)
    if not sets:
        return
    sets.append("updated_at = datetime('now')")
    params.append(user_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE users SET {', '.join(sets)} WHERE id = ?", params
        )
        await db.commit()
    finally:
        await db.close()


async def reset_student_password(student_id: str, new_password_hash: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, force_password_change = 1, "
            "updated_at = datetime('now') WHERE student_id = ?",
            (new_password_hash, student_id)
        )
        await db.commit()
    finally:
        await db.close()


# --- Session Queries ---

async def create_session(name: str, session_date: str, start_time: str,
                         late_threshold: int, created_by: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO sessions (session_name, session_date, start_time, "
            "late_threshold_minutes, is_active, is_open, created_by) "
            "VALUES (?, ?, ?, ?, 1, 0, ?)",
            (name, session_date, start_time, late_threshold, created_by)
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def open_session(session_id: int):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE sessions SET is_open = 1, start_time = datetime('now') WHERE id = ?",
            (session_id,)
        )
        await db.commit()
    finally:
        await db.close()


async def close_session(session_id: int):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE sessions SET is_open = 0, end_time = datetime('now') WHERE id = ?",
            (session_id,)
        )
        await db.commit()
    finally:
        await db.close()


async def get_active_session() -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT s.*, u.display_name as teacher_name FROM sessions s "
            "LEFT JOIN users u ON s.created_by = u.id "
            "WHERE s.is_open = 1 AND s.is_active = 1 ORDER BY s.id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_session_by_id(session_id: int) -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT s.*, u.display_name as teacher_name FROM sessions s "
            "LEFT JOIN users u ON s.created_by = u.id "
            "WHERE s.id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_sessions(limit: int = 50, offset: int = 0) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT s.*, u.display_name as teacher_name FROM sessions s "
            "LEFT JOIN users u ON s.created_by = u.id "
            "ORDER BY s.created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# --- Attendance Queries ---

async def check_in_student(session_id: int, student_id: str, ip_address: str,
                           late_threshold_minutes: int) -> dict:
    """Record student check-in. Returns status info."""
    db = await get_db()
    try:
        # Get session start_time to determine if late
        cursor = await db.execute(
            "SELECT start_time FROM sessions WHERE id = ?", (session_id,)
        )
        session = await cursor.fetchone()
        if not session:
            return {"success": False, "error": "Session not found"}

        session_start = datetime.fromisoformat(session['start_time'])
        now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        checkin_dt = datetime.fromisoformat(now_utc).replace(tzinfo=timezone.utc)

        # Calculate minutes late
        session_start_utc = session_start.replace(tzinfo=timezone.utc)
        diff_minutes = (checkin_dt - session_start_utc).total_seconds() / 60
        status = "present" if diff_minutes <= late_threshold_minutes else "late"

        ip_enc = encrypt(ip_address)

        await db.execute(
            "INSERT OR REPLACE INTO attendance_records "
            "(session_id, student_id, check_in_time, status, ip_address_enc, is_override, created_at) "
            "VALUES (?, ?, ?, ?, ?, 0, datetime('now'))",
            (session_id, student_id, now_utc, status, ip_enc)
        )
        await db.commit()

        return {"success": True, "status": status, "check_in_time": now_utc}
    except Exception as e:
        logger.error(f"Check-in failed: {e}")
        return {"success": False, "error": str(e)}
    finally:
        await db.close()


async def get_attendance_for_session(session_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT ar.*, u.display_name, u.username, u.student_id "
            "FROM attendance_records ar "
            "RIGHT JOIN users u ON ar.student_id = u.student_id AND ar.session_id = ? "
            "WHERE u.role = 'student' AND u.is_active = 1 "
            "ORDER BY u.student_id",
            (session_id,)
        )
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get('ip_address_enc'):
                d['ip_address'] = decrypt(d['ip_address_enc'])
            else:
                d['ip_address'] = '-'
            result.append(d)
        return result
    finally:
        await db.close()


async def get_attendance_for_student(student_id: str, limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT ar.*, s.session_name, s.session_date, s.start_time, s.late_threshold_minutes "
            "FROM attendance_records ar "
            "JOIN sessions s ON ar.session_id = s.id "
            "WHERE ar.student_id = ? "
            "ORDER BY s.session_date DESC, s.start_time DESC LIMIT ?",
            (student_id, limit)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_all_attendance_with_students(session_id: int) -> list[dict]:
    """Get all students with their attendance for a session, including absent ones."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT u.id as user_id, u.student_id, u.display_name, "
            "ar.id as record_id, ar.check_in_time, ar.status, ar.ip_address_enc, "
            "ar.is_override, ar.override_reason "
            "FROM users u "
            "LEFT JOIN attendance_records ar ON u.student_id = ar.student_id AND ar.session_id = ? "
            "WHERE u.role = 'student' AND u.is_active = 1 "
            "ORDER BY u.student_id",
            (session_id,)
        )
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get('ip_address_enc'):
                d['ip_address'] = decrypt(d['ip_address_enc'])
            else:
                d['ip_address'] = '-'
            if not d['status']:
                d['status'] = 'absent'
            result.append(d)
        return result
    finally:
        await db.close()


async def override_attendance(record_id: int, new_status: str,
                               overridden_by: int, reason: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE attendance_records SET status = ?, is_override = 1, "
            "overridden_by = ?, override_reason = ? WHERE id = ?",
            (new_status, overridden_by, reason, record_id)
        )
        await db.commit()
    finally:
        await db.close()


async def override_attendance_by_student(session_id: int, student_id: str,
                                          new_status: str, overridden_by: int,
                                          reason: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE attendance_records SET status = ?, is_override = 1, "
            "overridden_by = ?, override_reason = ? "
            "WHERE session_id = ? AND student_id = ?",
            (new_status, overridden_by, reason, session_id, student_id)
        )
        await db.commit()
    finally:
        await db.close()


async def check_student_checked_in(session_id: int, student_id: str) -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM attendance_records WHERE session_id = ? AND student_id = ?",
            (session_id, student_id)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_attendance_stats(session_id: int) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT status, COUNT(*) as count FROM attendance_records WHERE session_id = ? GROUP BY status",
            (session_id,)
        )
        rows = await cursor.fetchall()
        stats = {"present": 0, "late": 0, "absent": 0, "total": 20}
        for r in rows:
            stats[r['status']] = r['count']
        stats['checked_in'] = stats['present'] + stats['late']
        return stats
    finally:
        await db.close()


async def get_student_attendance_summary(student_id: str) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT status, COUNT(*) as count FROM attendance_records WHERE student_id = ? GROUP BY status",
            (student_id,)
        )
        rows = await cursor.fetchall()
        stats = {"present": 0, "late": 0, "absent": 0, "total": 0}
        for r in rows:
            stats[r['status']] = r['count']
        stats['total'] = stats['present'] + stats['late'] + stats['absent']
        stats['percentage'] = round((stats['present'] / stats['total'] * 100) if stats['total'] > 0 else 0, 1)
        return stats
    finally:
        await db.close()


# --- Announcement Queries ---

async def create_announcement(title: str, content: str, posted_by: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO announcements (title, content, posted_by) VALUES (?, ?, ?)",
            (title, content, posted_by)
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_active_announcements(limit: int = 10) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT a.*, u.display_name as author_name FROM announcements a "
            "JOIN users u ON a.posted_by = u.id "
            "WHERE a.is_active = 1 ORDER BY a.created_at DESC LIMIT ?",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_all_announcements(limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT a.*, u.display_name as author_name FROM announcements a "
            "JOIN users u ON a.posted_by = u.id "
            "ORDER BY a.created_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def toggle_announcement(announcement_id: int, is_active: int):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE announcements SET is_active = ? WHERE id = ?",
            (is_active, announcement_id)
        )
        await db.commit()
    finally:
        await db.close()


# --- Audit Log Queries ---

async def log_audit(user_id: Optional[int], username: Optional[str], action: str,
                     details: str, ip_address: str, user_agent: str = ""):
    db = await get_db()
    try:
        details_enc = encrypt(details) if details else ""
        ip_enc = encrypt(ip_address) if ip_address else ""
        await db.execute(
            "INSERT INTO audit_log (user_id, username, action, details_enc, ip_address_enc, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, username, action, details_enc, ip_enc, user_agent)
        )
        await db.commit()
    finally:
        await db.close()


async def get_audit_logs(limit: int = 100, offset: int = 0) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get('details_enc'):
                d['details'] = decrypt(d['details_enc'])
            else:
                d['details'] = ''
            if d.get('ip_address_enc'):
                d['ip_address'] = decrypt(d['ip_address_enc'])
            else:
                d['ip_address'] = '-'
            result.append(d)
        return result
    finally:
        await db.close()


# --- Session Store (for server-side sessions) ---

async def save_session(session_id: str, user_id: int, data: dict, expires_at: str):
    db = await get_db()
    try:
        await db.execute(
            "INSERT OR REPLACE INTO server_sessions (id, user_id, data, expires_at) VALUES (?, ?, ?, ?)",
            (session_id, user_id, json.dumps(data), expires_at)
        )
        await db.commit()
    finally:
        await db.close()


async def get_session(session_id: str) -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM server_sessions WHERE id = ? AND expires_at > datetime('now')",
            (session_id,)
        )
        row = await cursor.fetchone()
        if row:
            d = dict(row)
            d['data'] = json.loads(d['data'])
            return d
        return None
    finally:
        await db.close()


async def delete_session(session_id: str):
    db = await get_db()
    try:
        await db.execute("DELETE FROM server_sessions WHERE id = ?", (session_id,))
        await db.commit()
    finally:
        await db.close()


async def cleanup_expired_sessions():
    db = await get_db()
    try:
        await db.execute(
            "DELETE FROM server_sessions WHERE expires_at <= datetime('now')"
        )
        await db.commit()
    finally:
        await db.close()


async def update_session_data(session_id: str, data: dict):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE server_sessions SET data = ? WHERE id = ?",
            (json.dumps(data), session_id)
        )
        await db.commit()
    finally:
        await db.close()


# --- DB Integrity Check ---

async def check_db_integrity() -> dict:
    """Run integrity checks on the database."""
    db = await get_db()
    result = {"status": "ok", "checks": []}
    try:
        # quick integrity check
        cursor = await db.execute("PRAGMA quick_check")
        row = await cursor.fetchone()
        ok = row[0] == 'ok'
        result['checks'].append({"name": "quick_check", "passed": ok, "detail": row[0]})

        # foreign key check
        cursor = await db.execute("PRAGMA foreign_key_check")
        fk_violations = await cursor.fetchall()
        result['checks'].append({
            "name": "foreign_keys",
            "passed": len(fk_violations) == 0,
            "detail": f"{len(fk_violations)} violations" if fk_violations else "ok"
        })

        # table count check
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        row = await cursor.fetchone()
        table_count = row['cnt']
        result['checks'].append({
            "name": "tables_present",
            "passed": table_count >= 5,
            "detail": f"{table_count} tables found (expected 6+)"
        })

        result['status'] = "ok" if all(c['passed'] for c in result['checks']) else "warning"
    except Exception as e:
        result['status'] = "error"
        result['error'] = str(e)
    finally:
        await db.close()

    return result
