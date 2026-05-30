#!/usr/bin/env python3
"""
Athena Attendance System — Year 11 Athena
Online Attendance Management System

Run with: python run.py

This script:
  1. Seeds the database with 20 students + 1 teacher + mock data
  2. Starts the FastAPI server
"""
import os
import sys
import subprocess

# Ensure we're in the project root
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Generate a default encryption key if none is set
if not os.getenv("ENCRYPTION_KEY"):
    # Check .env file
    if os.path.exists(".env"):
        with open(".env") as f:
            if "ENCRYPTION_KEY=" not in f.read():
                # Need to generate one
                pass

    # Check if .env has ENCRYPTION_KEY set
    from dotenv import load_dotenv
    load_dotenv()
    if not os.getenv("ENCRYPTION_KEY"):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        # Write to .env
        env_content = ""
        if os.path.exists(".env"):
            with open(".env") as f:
                env_content = f.read()
        if "ENCRYPTION_KEY" not in env_content:
            with open(".env", "a") as f:
                f.write(f"\nENCRYPTION_KEY={key}\n")
                f.write(f"SECRET_KEY={os.urandom(32).hex()}\n")
            print(f"Generated encryption key and wrote to .env")
        else:
            # Replace placeholder
            pass


def main():
    print("✦ Athena Attendance System — Year 11")
    print("=" * 40)

    # Step 1: Install dependencies if needed
    try:
        import fastapi
    except ImportError:
        print("Installing dependencies...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print()

    # Step 2: Only seed if database doesn't exist
    if not os.path.exists(os.getenv("DATABASE_URL", "athena_attendance.db")):
        print("Seeding database...")
        from dotenv import load_dotenv
        load_dotenv()

        from scripts.seed import seed
        import asyncio
        asyncio.run(seed())
        print()
    else:
        # Still init the DB schema and encryption
        from dotenv import load_dotenv
        load_dotenv()
        from backend.database import init_db as init_db_fn
        from backend.encryption import init_encryption
        import asyncio
        asyncio.run(init_db_fn(os.getenv("DATABASE_URL", "athena_attendance.db")))
        init_encryption(os.getenv("ENCRYPTION_KEY", ""))
        print("Database already seeded. Starting server...")

    # Step 3: Start server
    print("✦ Starting server...")
    print(f"   Open http://localhost:{os.getenv('PORT', '8000')} in your browser")
    print(f"   Login as teacher: teacher_athena / TeacherAthena2025!")
    print(f"   Login as student: student01 / Athena2025!")
    print()

    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
