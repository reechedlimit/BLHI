"""
Newsletter subscription Blueprint for the Family History Documentation Tool.
Provides a public subscribe endpoint and an admin-only subscribers listing.
"""
import re
import sqlite3
from flask import Blueprint, jsonify, request, current_app
from models import get_db

newsletter_bp = Blueprint('newsletter', __name__, url_prefix='/api')


def _is_valid_email(email):
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip())) if email else False


def init_subscribers_table():
    """Create the subscribers table if it doesn't exist (safe to call multiple times)."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


@newsletter_bp.route('/subscribe', methods=['POST'])
def subscribe():
    """Subscribe an email to the newsletter.
    
    Accepts JSON: {"email": "user@example.com"}
    Returns JSON with success/error message.
    """
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Request must be JSON.'}), 400

    data = request.get_json()
    email = (data.get('email') or '').strip().lower()

    if not email:
        return jsonify({'success': False, 'error': 'Email is required.'}), 400

    if not _is_valid_email(email):
        return jsonify({'success': False, 'error': 'Invalid email format.'}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO subscribers (email) VALUES (?)",
            (email,)
        )
        conn.commit()
        conn.close()
        return jsonify({
            'success': True,
            'message': 'Thank you for subscribing to the BLHI newsletter!'
        }), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({
            'success': False,
            'error': 'This email is already subscribed.'
        }), 409
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': 'An error occurred.'}), 500


@newsletter_bp.route('/subscribers')
def subscribers():
    """List all newsletter subscribers (admin only)."""
    # Import here to avoid circular import
    from auth import role_at_least
    if not role_at_least('admin'):
        return jsonify({'success': False, 'error': 'Admin access required.'}), 403

    conn = get_db()
    rows = conn.execute(
        "SELECT id, email, subscribed_at, active FROM subscribers ORDER BY subscribed_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])