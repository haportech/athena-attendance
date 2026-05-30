/* Athena Attendance — Micro-interactions & Claymorphism UX */

// ===== TOAST SYSTEM =====
window.showToast = function(message, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    toast.innerHTML = `<span style="font-weight:700;font-size:1.1em;">${icons[type]||'ℹ'}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.transform = 'translateX(40px)';
        toast.style.opacity = '0';
        toast.style.transition = 'all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1)';
        setTimeout(() => toast.remove(), 350);
    }, 3500);
};

// ===== LIVE ATTENDANCE POLLING =====
let attendancePollInterval = null;

function startAttendancePolling() {
    if (attendancePollInterval) clearInterval(attendancePollInterval);
    attendancePollInterval = setInterval(async () => {
        try {
            const resp = await fetch('/api/active-session');
            const data = await resp.json();
            if (!data.active) { clearInterval(attendancePollInterval); location.reload(); return; }
            const s = data.stats;
            ['present','late','absent'].forEach(k => {
                const el = document.getElementById(`stat-${k}`);
                if (el && el.textContent !== String(s[k])) {
                    el.textContent = s[k];
                    el.style.animation = 'countUp 0.3s ease-out';
                    setTimeout(() => el.style.animation = '', 400);
                }
            });
            const ci = document.getElementById('checked-in-count');
            if (ci && ci.textContent !== String(s.checked_in)) {
                ci.textContent = s.checked_in;
                ci.style.animation = 'countUp 0.3s ease-out';
                setTimeout(() => ci.style.animation = '', 400);
            }
            data.attendance.forEach(row => {
                const tr = document.getElementById(`student-row-${row.student_id}`);
                if (!tr) return;
                const st = tr.querySelector('.attendance-status');
                const tt = tr.querySelector('.attendance-time');
                const it = tr.querySelector('.attendance-ip');
                const newBadge = getStatusBadgeHTML(row.status);
                if (st && st.innerHTML !== newBadge) {
                    st.innerHTML = newBadge;
                    st.style.animation = 'scaleIn 0.25s ease-out';
                    setTimeout(() => st.style.animation = '', 300);
                }
                if (tt) tt.textContent = row.check_in_time ? new Date(row.check_in_time+'Z').toLocaleTimeString() : '-';
                if (it) it.textContent = row.ip_address || '-';
            });
        } catch(e) { /* silent */ }
    }, 10000);
}

function getStatusBadgeHTML(status) {
    const map = { present: 'Present', late: 'Late', absent: 'Absent' };
    return `<span class="status-badge status-badge--${status}">${map[status]||status}</span>`;
}

// ===== CHECK-IN BUTTON =====
async function handleCheckIn(btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Checking in...';
    btn.style.transform = 'scale(0.96)';
    try {
        const r = await fetch('/student/checkin', { method: 'POST' });
        const d = await r.json();
        if (d.success) {
            showToast(`Checked in as ${d.status.toUpperCase()}!`, 'success');
            btn.style.transform = 'scale(1)';
            btn.innerHTML = '✓ Checked In';
            btn.style.background = '#166534';
            btn.style.borderColor = '#22C55E';
            setTimeout(() => location.reload(), 1200);
        } else {
            showToast(d.error || 'Check-in failed', 'error');
            btn.disabled = false;
            btn.innerHTML = 'Check In';
            btn.style.transform = 'scale(1)';
        }
    } catch(e) {
        showToast('Network error', 'error');
        btn.disabled = false;
        btn.innerHTML = 'Check In';
        btn.style.transform = 'scale(1)';
    }
}

// ===== OVERRIDE MODAL =====
function openOverrideModal(sessionId, studentId, name, status) {
    const m = document.getElementById('override-modal');
    if (!m) return;
    m.classList.remove('hidden');
    m.style.display = 'flex';
    document.getElementById('override-session-id').value = sessionId;
    document.getElementById('override-student-id').value = studentId;
    document.getElementById('override-student-name').textContent = name;
    document.getElementById('override-status').value = status;
}

function closeOverrideModal() {
    const m = document.getElementById('override-modal');
    if (m) { m.classList.add('hidden'); m.style.display = 'none'; }
}

// ===== CONFIRM =====
function confirmAction(msg) { return confirm(msg); }

// ===== PASSWORD TOGGLE =====
function togglePassword(id, btn) {
    const inp = document.getElementById(id);
    if (!inp) return;
    const isPw = inp.type === 'password';
    inp.type = isPw ? 'text' : 'password';
    btn.textContent = isPw ? 'Hide' : 'Show';
}

// ===== ENTRANCE ANIMATIONS =====
function staggerCards() {
    document.querySelectorAll('.card, .stat-card, .session-banner').forEach((el, i) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(16px)';
        el.style.transition = 'all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1)';
        setTimeout(() => {
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        }, 80 + i * 60);
    });
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
    staggerCards();

    if (document.getElementById('teacher-dashboard') && document.getElementById('active-session-id')) {
        startAttendancePolling();
    }

    document.querySelectorAll('.alert').forEach(el => {
        setTimeout(() => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(-8px)';
            el.style.transition = 'all 0.4s ease';
            setTimeout(() => el.remove(), 500);
        }, 5000);
    });

    document.querySelectorAll('.modal-overlay').forEach(el => {
        el.addEventListener('click', function(e) {
            if (e.target === this) closeOverrideModal();
        });
    });

    // Claymorphism hover effects on stat cards
    document.querySelectorAll('.stat-card').forEach(el => {
        el.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-3px)';
        });
        el.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
});
