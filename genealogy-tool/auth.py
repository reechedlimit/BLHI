"""
Authentication helpers for the Family History Documentation Tool.
Simple session-based auth using werkzeug security.
"""
import sqlite3
from functools import wraps
from flask import session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import get_db


def create_user(name, email, password):
    """Register a new user. Returns (user_id, error_string)."""
    conn = get_db()
    try:
        password_hash = generate_password_hash(password)
        cursor = conn.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, password_hash)
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
        "SELECT id, name, email, password_hash FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        return {'id': user['id'], 'name': user['name'], 'email': user['email']}
    return None


def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function