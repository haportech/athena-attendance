"""
Seed script for Athena Attendance System.
Creates 20 student accounts + 1 teacher account + 3 mock sessions with attendance data.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from backend.database import init_db, get_db, create_user, create_session, open_session, close_session
from backend.auth import hash_password
from backend.encryption import init_encryption


async def seed():
    db_path = os.getenv("DATABASE_URL", "athena_attendance.db")
    enc_key = os.getenv("ENCRYPTION_KEY", "")

    await init_db(db_path)
    init_encryption(enc_key)

    print("Seeding database...")

    # Create teacher account
    existing = await get_user_by_username_simple("teacher_athena")
    if not existing:
        pw_hash = hash_password("TeacherAthena2025!")
        await create_user(
            username="teacher_athena",
            password_hash=pw_hash,
            role="teacher",
            student_id=None,
            display_name="Mrs. Athena",
            force_password_change=0  # Teacher doesn't need to change on first login
        )
        print("  ✓ Teacher account created: teacher_athena / TeacherAthena2025!")
    else:
        print("  - Teacher account already exists")

    # Get teacher ID
    db = await get_db()
    try:
        cursor = await db.execute("SELECT id FROM users WHERE username = 'teacher_athena'")
        row = await cursor.fetchone()
        teacher_id = row['id']
    finally:
        await db.close()

    # Create 20 student accounts
    for i in range(1, 21):
        student_id = f"ATH-{i:04d}"
        username = f"student{i:02d}"
        display_name = f"Student {i:02d}"

        existing = await get_user_by_student_id(student_id)
        if not existing:
            pw_hash = hash_password("Athena2025!")
            await create_user(
                username=username,
                password_hash=pw_hash,
                role="student",
                student_id=student_id,
                display_name=display_name,
                force_password_change=1  # Force password change on first login
            )
            print(f"  ✓ Created {student_id} — {display_name} (pw: Athena2025!)")
        else:
            print(f"  - {student_id} already exists")

    # Create 3 mock past sessions with attendance data
    from datetime import datetime, timedelta, timezone
    import random

    mock_sessions = [
        ("Week 1 — Monday", "2026-05-11"),
        ("Week 1 — Wednesday", "2026-05-13"),
        ("Week 1 — Friday", "2026-05-15"),
    ]

    db = await get_db()
    try:
        for session_name, session_date in mock_sessions:
            # Check if session exists
            cursor = await db.execute(
                "SELECT id FROM sessions WHERE session_name = ? AND session_date = ?",
                (session_name, session_date)
            )
            existing_session = await cursor.fetchone()
            if existing_session:
                print(f"  - Session '{session_name}' already exists")
                continue

            # Create session
            start_time = f"{session_date}T08:00:00"
            cursor = await db.execute(
                "INSERT INTO sessions (session_name, session_date, start_time, end_time, late_threshold_minutes, is_active, is_open, created_by, created_at) "
                "VALUES (?, ?, ?, datetime('now'), 10, 1, 0, ?, datetime('now'))",
                (session_name, session_date, start_time, teacher_id)
            )
            session_id = cursor.lastrowid
            print(f"  ✓ Created session: {session_name} ({session_date})")

            # Random attendance for all 20 students
            for i in range(1, 21):
                sid = f"ATH-{i:04d}"
                # Random status weighted: 70% present, 15% late, 15% absent
                roll = random.random()
                if roll < 0.70:
                    status = "present"
                    checkin_offset = random.randint(0, int(0.9 * 10))  # within threshold
                elif roll < 0.85:
                    status = "late"
                    checkin_offset = random.randint(11, 30)
                else:
                    status = "absent"
                    checkin_offset = None

                if checkin_offset is not None:
                    checkin_time = f"{session_date}T08:{checkin_offset:02d}:{random.randint(0,59):02d}"
                    ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                    from backend.encryption import encrypt
                    ip_enc = encrypt(ip)

                    await db.execute(
                        "INSERT OR IGNORE INTO attendance_records "
                        "(session_id, student_id, check_in_time, status, ip_address_enc, created_at) "
                        "VALUES (?, ?, ?, ?, ?, datetime('now'))",
                        (session_id, sid, checkin_time, status, ip_enc)
                    )
            print(f"  ✓ Attendance recorded for {session_name}")

        await db.commit()
    finally:
        await db.close()

    print("\n✅ Seeding complete!")
    print("\nLogin credentials:")
    print("  Teacher: teacher_athena / TeacherAthena2025!")
    print("  Students: student01–student20 / Athena2025! (force change on first login)")


async def get_user_by_username_simple(username: str):
    from backend.database import get_user_by_username
    return await get_user_by_username(username)


async def get_user_by_student_id(student_id: str):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT id FROM users WHERE student_id = ?", (student_id,))
        row = await cursor.fetchone()
        return row
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(seed())
