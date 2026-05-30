# Athena Attendance System — Year 11

Online attendance management for **Year 11 Athena (Grade 11, Code Name Athena)**.  
A locked single-class system for exactly **20 students** with separate student and teacher portals.

## Quick Start

```bash
python run.py
```

Then open **http://localhost:8000** in your browser.

### Login Credentials

| Role | Username | Password | Notes |
|------|----------|----------|-------|
| Teacher | `teacher_athena` | `TeacherAthena2025!` | |
| Student 01 | `student01` | `Athena2025!` | Force password change on first login |
| Student 02–20 | `student02`–`student20` | `Athena2025!` | Force password change on first login |

## Demo Showcase

[![Watch the demo](https://img.youtube.com/vi/nFeZoGw_V9E/0.jpg)](https://www.youtube.com/watch?v=nFeZoGw_V9E)

## Stack

- **FastAPI** (async Python) — auto-validation, OpenAPI, fastest Python web framework
- **Jinja2** — server-side rendering (no SPA complexity, natural CSRF, no CORS)
- **SQLite + aiosqlite** — zero-config async DB
- **Field-level AES-256-GCM encryption** — sensitive columns (IPs, audit details) encrypted at rest
- **bcrypt** (12 rounds) — password hashing
- **Server-side sessions** — stored in DB, signed with itsdangerous, HttpOnly cookies
- **Custom CSS (claymorphism dark)** — responsive, accessible, dark UI with micro-animations

## Features

### Student Portal
- Attendance grid with visual check-in button
- Check-in during active teacher-opened sessions
- Automatic late detection (configurable threshold)
- Personal attendance history with stats
- View teacher announcements

### Teacher Portal
- Live attendance dashboard with real-time polling (10s interval)
- Create/open/close class sessions
- Manual attendance override for any student
- CSV and PDF export (per session or full history)
- Attendance analytics with Chart.js (trend line + distribution doughnut)
- Announcement board (post, hide/show)
- Student account management (reset passwords, enable/disable)
- Full audit log (logins, check-ins, overrides, session actions)
- Database integrity checker

### Security
- bcrypt password hashing (12 rounds)
- Field-level AES-256-GCM encryption at rest
- Server-side sessions (revocable, tamper-proof)
- Rate limiting: 5 attempts per IP per 10 minutes
- Content Security Policy (CSP) headers
- Role-based route enforcement (middleware, not just UI)
- CSRF protection via signed tokens
- All queries parameterized (zero SQL injection risk)
- No stack traces leaked to clients
- Auto-logout after 30 minutes inactivity

## Configuration

Copy `.env.example` to `.env` and edit:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_KEY` | (generated) | Fernet key for field-level encryption |
| `SECRET_KEY` | (generated) | Session signing key |
| `DATABASE_URL` | `athena_attendance.db` | SQLite database path |
| `TIMEZONE` | `Asia/Vientiane` | Display timezone |
| `SESSION_TIMEOUT_MINUTES` | `30` | Auto-logout timeout |
| `DEFAULT_LATE_THRESHOLD` | `10` | Minutes before late check-in |
| `RATE_LIMIT_MAX_ATTEMPTS` | `5` | Max login attempts per window |
| `PORT` | `8000` | Server port |

### Generate Encryption Key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Replace for Production
1. Change `ENCRYPTION_KEY` to a new generated key
2. Change `SECRET_KEY` to a random hex string
3. Set `HTTPS_ENABLED=True` and configure a real TLS certificate
4. Use a reverse proxy (nginx/Caddy) in front of the app

## Deploy to Cloudflare Pages

This app uses Python/FastAPI, so Cloudflare Pages alone won't work (it only serves static files). You need **Cloudflare Workers** or a **VPS** to run the Python server. Two options:

**Option 1 — VPS (recommended)**
```bash
git clone <repo-url>
cd athena-attendance
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit with your keys
python scripts/seed.py
python run.py
```
Then put Cloudflare Pages in front as a reverse proxy, or use a Cloudflare Tunnel (`cloudflared`) to point your domain at `localhost:8000`.

**Option 2 — Cloudflare Workers (Python via Pyodide)**
Not recommended for this app. SQLite needs a real filesystem. Use the VPS approach.

## File Structure

```
athena-attendance/
  run.py                  # Single-command launcher
  requirements.txt        # Python dependencies
  .env                    # Environment variables (secrets)
  .env.example            # Template with docs
  pytest.ini              # Test configuration
  backend/
    main.py               # FastAPI app, all routes
    database.py           # Async SQLite operations
    auth.py               # bcrypt, rate limiting, sessions
    encryption.py         # Fernet AES-256-GCM encryption
    middleware.py         # CSP headers, session management
  frontend/
    templates/            # Jinja2 HTML templates
      base.html           # Layout with sidebar
      login.html          # Role-based login
      change_password.html
      error.html
      student/
        dashboard.html    # Check-in + stats
        history.html      # Personal records
      teacher/
        dashboard.html    # Live attendance + override modal
        sessions.html     # CRUD sessions
        session_detail.html
        history.html      # Filterable records
        analytics.html    # Charts (Chart.js)
        announcements.html
        students.html
        audit_log.html
    static/
      css/style.css       # Complete design system
      js/main.js          # Live polling, toasts, modals
  scripts/
    seed.py               # 20 students + 1 teacher + 3 mock sessions
  tests/
    test_system.py        # 13 automated tests
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/login` | Login page |
| POST | `/login` | Login submit |
| GET | `/logout` | Logout |
| GET | `/student/dashboard` | Student check-in page |
| POST | `/student/checkin` | Student check-in (JSON) |
| GET | `/student/history` | Student attendance history |
| GET | `/teacher/dashboard` | Teacher live dashboard |
| POST | `/teacher/session/create` | Create new session |
| POST | `/teacher/session/{id}/open` | Open session |
| POST | `/teacher/session/{id}/close` | Close session |
| POST | `/teacher/attendance/override` | Override student status |
| GET | `/teacher/sessions` | All sessions |
| GET | `/teacher/session/{id}` | Session detail |
| GET | `/teacher/history` | Filterable history |
| GET | `/teacher/analytics` | Charts + statistics |
| GET | `/teacher/export/csv` | Export CSV |
| GET | `/teacher/export/pdf` | Export PDF |
| GET | `/teacher/announcements` | Manage announcements |
| POST | `/teacher/announcements/create` | Post announcement |
| POST | `/teacher/announcements/{id}/toggle` | Show/hide |
| GET | `/teacher/students` | Student management |
| POST | `/teacher/students/reset-password` | Reset student password |
| POST | `/teacher/students/toggle` | Enable/disable student |
| GET | `/teacher/audit-log` | Full activity log |
| GET | `/teacher/integrity-check` | DB integrity check |
| GET | `/api/active-session` | Live polling endpoint |

## Testing

```bash
cd athena-attendance
source venv/bin/activate
python -m pytest tests/ -v
```

Tests cover: login auth (success, wrong password, wrong role), role isolation (student vs teacher routes), session create/open/close, student check-in (success, duplicate, no session), teacher override, rate limiting.

## Known Limitations

- Single-class system only (no multi-class/multi-teacher support)
- No email/push notifications for absent students
- No SMS gateway integration
- No real-time WebSocket — uses polling (10s interval)
- SQLite limits concurrent writes (fine for 20 students at a time—not a limitation)
- Dark mode only (no light mode toggle)
- PDF export uses ReportLab (simple tables — no custom branding)

## Future Improvements

- Multi-class support with teacher assignment
- WebSocket-based real-time updates
- Student self-service (profile editing, password change from portal)
- Email/SMS notifications for absentees
- QR code check-in
- Calendar integration (iCal export)
- Dark mode
- Docker deployment with docker-compose
- OAuth/SSO integration
