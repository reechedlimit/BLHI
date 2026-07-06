"""
Authentication, authorization, and TOTP 2FA system for the
Family History Documentation Tool.

Roles: owner > admin > editor > user
- owner: full system access, can manage admins
- admin: can manage users, roles, and all trees
- editor: can create/edit trees (standard content creator)
- user: basic access (default for new registrations)

TOTP 2FA: Time-based One-Time Password via authenticator apps.
"""
import sqlite3
import secrets
import hashlib
import base64
from io import BytesIO
from functools import wraps
from datetime import datetime, timedelta

from flask import session, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

from models import get_db

# ─── Configuration ───────────────────────────────────────────────────────

SESSION_EXPIRY_HOURS = 24  # Session lasts 24 hours by default
SESSION_EXPIRY_ADMIN_HOURS = 8  # Admin sessions expire after 8 hours
RECOVERY_CODE_COUNT = 8  # Number of recovery codes generated
TOTP_ISSUER = "BLHI Genealogy Tool"

# ─── Role Hierarchy ──────────────────────────────────────────────────────

ROLE_HIERARCHY = {
    'owner': 100,
    'admin': 80,
    'editor': 50,
    'user': 10,
}


def role_at_least(min_role):
    """Check if a role meets the minimum level."""
    return ROLE_HIERARCHY.get(session.get('role', 'user'), 0) >= ROLE_HIERARCHY.get(min_role, 0)


# ─── User CRUD ───────────────────────────────────────────────────────────

def create_user(name, email, password, role='user'):
    """Register a new user. Returns (user_id, error_string)."""
    conn = get_db()
    try:
        password_hash = generate_password_hash(password)
        cursor = conn.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (name, email, password_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id, None
    except sqlite3.IntegrityError:
        conn.close()
        return None, "A user with this email already exists."


def verify_login(email, password):
    """Verify login credentials. Returns user dict or None."""
    conn = get_db()
    user = conn.execute(
        "SELECT id, name, email, password_hash, role, totp_enabled FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        return {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'role': user['role'],
            'totp_enabled': bool(user['totp_enabled']),
        }
    return None


def get_user(user_id):
    """Get a user by ID."""
    conn = get_db()
    user = conn.execute(
        "SELECT id, name, email, role, totp_enabled, created_at FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    """Get all users (admin function)."""
    conn = get_db()
    users = conn.execute(
        "SELECT id, name, email, role, totp_enabled, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]


def update_user_role(user_id, new_role, current_user_id):
    """Update a user's role. Only owner can create admins. Only admin can create editors."""
    conn = get_db()

    # Get current user's role
    current = conn.execute("SELECT role FROM users WHERE id = ?", (current_user_id,)).fetchone()
    target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()

    if not current or not target:
        conn.close()
        return "User not found."

    current_role_level = ROLE_HIERARCHY.get(current['role'], 0)
    new_role_level = ROLE_HIERARCHY.get(new_role, 0)
    target_role_level = ROLE_HIERARCHY.get(target['role'], 0)

    # Permissions: owner can set any role. Admin can set editor/user only.
    if current['role'] == 'owner':
        pass  # Owner can do anything
    elif current['role'] == 'admin' and new_role in ('editor', 'user'):
        pass  # Admin can promote to editor or demote to user
    else:
        conn.close()
        return "You don't have permission to set that role."

    # Cannot change your own role
    if user_id == current_user_id:
        conn.close()
        return "You cannot change your own role."

    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return None


# ─── Role-Based Decorators ───────────────────────────────────────────────

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        # Session expiry check
        last_activity = session.get('last_activity')
        if last_activity:
            max_age = SESSION_EXPIRY_ADMIN_HOURS if session.get('role') in ('owner', 'admin') else SESSION_EXPIRY_HOURS
            if datetime.fromisoformat(last_activity) + timedelta(hours=max_age) < datetime.now():
                session.clear()
                flash("Your session has expired. Please log in again.", "warning")
                return redirect(url_for('login'))
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function


def role_required(min_role):
    """Decorator to require a minimum role level. Usage: @role_required('editor')"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not role_at_least(min_role):
                flash("You don't have permission to access this page.", "error")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator for routes requiring admin or owner role."""
    return role_required('admin')(f)


def owner_required(f):
    """Decorator for routes requiring owner role."""
    return role_required('owner')(f)


# ─── TOTP 2FA ────────────────────────────────────────────────────────────

def generate_totp_secret():
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(secret, email):
    """Get the otpauth:// URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=TOTP_ISSUER
    )


def verify_totp(secret, code):
    """Verify a TOTP code against a secret. Allows some clock drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_recovery_codes():
    """Generate recovery codes (plaintext). Returns list of codes."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        code = secrets.token_hex(4).upper()  # 8-char hex code
        # Format as XXXX-XXXX
        code = f"{code[:4]}-{code[4:]}"
        codes.append(code)
    return codes


def store_recovery_codes(user_id, codes):
    """Hash and store recovery codes for a user."""
    conn = get_db()
    # Remove old unused codes first
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ? AND used = 0", (user_id,))
    for code in codes:
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            (user_id, code_hash)
        )
    conn.commit()
    conn.close()


def verify_recovery_code(user_id, code):
    """Verify a recovery code. Returns True if valid and marks it used."""
    code = code.strip().upper()
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    conn = get_db()
    record = conn.execute(
        "SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
        (user_id, code_hash)
    ).fetchone()
    if record:
        conn.execute("UPDATE recovery_codes SET used = 1 WHERE id = ?", (record['id'],))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def get_remaining_recovery_codes(user_id):
    """Get count of unused recovery codes."""
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) as c FROM recovery_codes WHERE user_id = ? AND used = 0",
        (user_id,)
    ).fetchone()['c']
    conn.close()
    return count


# ─── Session & Auth Helpers ──────────────────────────────────────────────

def setup_user_session(user):
    """Set up session for a logged-in user (post-2FA if applicable)."""
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['role'] = user.get('role', 'user')
    session['totp_verified'] = not user.get('totp_enabled', False)
    session['last_activity'] = datetime.now().isoformat()


def require_2fa_verification():
    """Check if the current session needs 2FA verification.
    Called by a before_request handler."""
    if 'user_id' in session and not session.get('totp_verified', True):
        # Skip on the 2FA verification route itself
        if request.endpoint in ('verify_2fa', 'static', 'logout', 'uploaded_file'):
            return
        return redirect(url_for('verify_2fa'))


# ─── Rate Limiting (Simple In-Memory) ────────────────────────────────────
# Note: For production, use flask-limiter. This is a lightweight in-memory
# version that works without external dependencies.

_login_attempts = {}  # {ip: [timestamp, ...]}


def check_rate_limit(ip, limit=5, window=300):
    """Check if an IP has exceeded the rate limit.
    5 attempts per 5 minutes by default."""
    now = datetime.now()
    if ip not in _login_attempts:
        _login_attempts[ip] = []

    # Remove old attempts
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < timedelta(seconds=window)]

    if len(_login_attempts[ip]) >= limit:
        return False

    _login_attempts[ip].append(now)
    return True


def clear_rate_limit(ip):
    """Clear rate limit for an IP on successful login."""
    _login_attempts.pop(ip, None)