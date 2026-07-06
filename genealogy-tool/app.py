"""
Family History Documentation Tool — Main Application
Black Lineage & Heritage Institute

Features: Family trees, people, relationships, stories, records,
auth with 2FA, role-based access control, admin dashboard.
"""
import os
import json
import base64
import re
from io import BytesIO
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename

from config import Config
from models import get_db, init_db, run_migrations
from auth import (
    create_user, verify_login, login_required, admin_required, owner_required,
    role_at_least, get_user, get_all_users, update_user_role,
    generate_totp_secret, get_totp_uri, verify_totp,
    generate_recovery_codes, store_recovery_codes,
    verify_recovery_code, get_remaining_recovery_codes,
    setup_user_session, require_2fa_verification,
    check_rate_limit, clear_rate_limit,
)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize database on first run
if not os.path.exists(Config.DATABASE_PATH):
    init_db()
else:
    try:
        conn = get_db()
        conn.execute("SELECT COUNT(*) FROM users")
        conn.close()
    except Exception:
        init_db()

# Run migrations for existing databases
run_migrations()


# ─── Before Request ──────────────────────────────────────────────────────

@app.before_request
def before_request():
    """Check session expiry and 2FA verification on every request."""
    # Static files, public routes, and auth routes are exempt from 2FA check
    exempt_endpoints = ['static', 'login', 'register', 'logout',
                        'verify_2fa', 'uploaded_file', 'index', 'about']
    if request.endpoint in exempt_endpoints:
        return

    # Check session expiry
    if 'user_id' in session:
        from auth import SESSION_EXPIRY_HOURS, SESSION_EXPIRY_ADMIN_HOURS
        last_activity = session.get('last_activity')
        if last_activity:
            max_age = SESSION_EXPIRY_ADMIN_HOURS if session.get('role') in ('owner', 'admin') else SESSION_EXPIRY_HOURS
            try:
                if datetime.fromisoformat(last_activity) + timedelta(hours=max_age) < datetime.now():
                    session.clear()
                    flash("Your session has expired. Please log in again.", "warning")
                    return redirect(url_for('login'))
            except (ValueError, TypeError):
                pass
        session['last_activity'] = datetime.now().isoformat()

        # Check 2FA verification
        if not session.get('totp_verified', True):
            return redirect(url_for('verify_2fa'))


# ─── Helper ──────────────────────────────────────────────────────────────

def get_user_trees(user_id):
    """Get all family trees for a user."""
    conn = get_db()
    trees = conn.execute(
        "SELECT * FROM family_trees WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return trees


def allowed_file(filename):
    """Check if file extension is allowed for upload."""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'csv', 'mp3', 'wav'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ─── Public Routes ───────────────────────────────────────────────────────

@app.route('/')
def index():
    """Landing page for the genealogy tool."""
    return render_template('index.html', user=session.get('user_name'))


@app.route('/about')
def about():
    return render_template('about.html')


# ─── Auth Routes ─────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template('register.html')

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template('register.html')

        # New users get 'user' role by default
        user_id, error = create_user(name, email, password, role='user')
        if error:
            flash(error, "error")
            return render_template('register.html')

        user = get_user(user_id)
        setup_user_session(user)
        flash("Account created! Welcome to the Family History Documentation Tool.", "success")
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Rate limiting
        client_ip = request.remote_addr or 'unknown'
        if not check_rate_limit(client_ip):
            flash("Too many login attempts. Please wait 5 minutes.", "error")
            return render_template('login.html')

        user = verify_login(email, password)
        if user:
            clear_rate_limit(client_ip)
            setup_user_session(user)

            # If user has 2FA enabled, redirect to verification
            if user.get('totp_enabled'):
                session['totp_verified'] = False
                session['pre_2fa_user'] = user
                return redirect(url_for('verify_2fa'))

            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "error")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))


# ─── 2FA Verification ────────────────────────────────────────────────────

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """TOTP 2FA verification page after login."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('totp_verified'):
        return redirect(url_for('dashboard'))

    user = get_user(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if not user.get('totp_enabled'):
        session['totp_verified'] = True
        return redirect(url_for('dashboard'))

    error = None
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        is_recovery = request.form.get('is_recovery') == '1'

        if is_recovery:
            # Recovery code flow
            if verify_recovery_code(user['id'], code):
                session['totp_verified'] = True
                remaining = get_remaining_recovery_codes(user['id'])
                flash(f"Recovery code accepted! {remaining} recovery codes remaining. Consider re-enabling 2FA.", "success")
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid or already used recovery code."
        else:
            # TOTP code flow
            conn = get_db()
            secret = conn.execute(
                "SELECT totp_secret FROM users WHERE id = ?", (user['id'],)
            ).fetchone()['totp_secret']
            conn.close()

            if secret and verify_totp(secret, code):
                session['totp_verified'] = True
                flash("2FA verified successfully!", "success")
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid verification code. Please try again."

    return render_template('verify_2fa.html', error=error)


# ─── 2FA Setup ───────────────────────────────────────────────────────────

@app.route('/settings/2fa/setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Set up TOTP 2FA for the current user."""
    user = get_user(session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('dashboard'))

    # If already enabled, show management page instead
    if user.get('totp_enabled'):
        remaining = get_remaining_recovery_codes(user['id'])
        return render_template('setup_2fa.html',
                             enabled=True,
                             remaining=remaining,
                             secret=None,
                             qr_svg=None)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'verify':
            # Step 2: Verify the code to confirm setup
            code = request.form.get('code', '').strip()
            secret = session.get('pending_totp_secret')
            if not secret:
                flash("Session expired. Please start over.", "error")
                return redirect(url_for('setup_2fa'))

            if verify_totp(secret, code):
                # Enable 2FA
                conn = get_db()
                conn.execute(
                    "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                    (secret, user['id'])
                )
                conn.commit()
                conn.close()

                # Generate and store recovery codes
                recovery_codes = generate_recovery_codes()
                store_recovery_codes(user['id'], recovery_codes)

                session.pop('pending_totp_secret', None)
                session['totp_verified'] = True

                return render_template('setup_2fa.html',
                                     enabled=True,
                                     just_enabled=True,
                                     recovery_codes=recovery_codes,
                                     secret=None,
                                     qr_svg=None)
            else:
                flash("Invalid code. Please try again.", "error")
                # Re-show the verification step
                secret = session.get('pending_totp_secret')
                uri = get_totp_uri(secret, user['email'])
                qr = _generate_qr_svg(uri)
                return render_template('setup_2fa.html',
                                     enabled=False,
                                     step='verify',
                                     secret=secret,
                                     qr_svg=qr)

        elif action == 'disable':
            # Disable 2FA
            conn = get_db()
            conn.execute(
                "UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?",
                (user['id'],)
            )
            conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user['id'],))
            conn.commit()
            conn.close()
            flash("2FA has been disabled for your account.", "info")
            return redirect(url_for('dashboard'))

    # GET: Step 1 - Generate secret and show QR code
    secret = generate_totp_secret()
    session['pending_totp_secret'] = secret
    uri = get_totp_uri(secret, user['email'])
    qr_svg = _generate_qr_svg(uri)

    return render_template('setup_2fa.html',
                         enabled=False,
                         step='setup',
                         secret=secret,
                         qr_svg=qr_svg)


def _generate_qr_svg(uri):
    """Generate an SVG QR code for the TOTP URI."""
    import qrcode
    import qrcode.image.svg

    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    # Generate as SVG string
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buffer = BytesIO()
    img.save(buffer)
    return buffer.getvalue().decode('utf-8')


# ─── Dashboard ───────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    trees = get_user_trees(session['user_id'])

    # Get stats
    conn = get_db()
    person_count = conn.execute(
        "SELECT COUNT(*) as c FROM people p JOIN family_trees t ON p.tree_id = t.id WHERE t.user_id = ?",
        (session['user_id'],)
    ).fetchone()['c']
    story_count = conn.execute(
        "SELECT COUNT(*) as c FROM stories s JOIN family_trees t ON s.tree_id = t.id WHERE t.user_id = ?",
        (session['user_id'],)
    ).fetchone()['c']
    record_count = conn.execute(
        "SELECT COUNT(*) as c FROM records r JOIN family_trees t ON r.tree_id = t.id WHERE t.user_id = ?",
        (session['user_id'],)
    ).fetchone()['c']
    conn.close()

    return render_template('dashboard.html',
                         trees=trees,
                         person_count=person_count,
                         story_count=story_count,
                         record_count=record_count,
                         user_name=session.get('user_name'),
                         role=session.get('role'))


# ─── Family Tree CRUD ────────────────────────────────────────────────────

@app.route('/tree/new', methods=['GET', 'POST'])
@login_required
def new_tree():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        conn = get_db()
        conn.execute(
            "INSERT INTO family_trees (user_id, name, description) VALUES (?, ?, ?)",
            (session['user_id'], name, description)
        )
        conn.commit()
        tree_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        flash(f"Family tree '{name}' created!", "success")
        return redirect(url_for('view_tree', tree_id=tree_id))

    return render_template('tree_form.html', action='Create')


@app.route('/tree/<int:tree_id>')
@login_required
def view_tree(tree_id):
    """View a single family tree with all its people."""
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ?",
            (tree_id,)
        ).fetchone()
    else:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ? AND user_id = ?",
            (tree_id, session['user_id'])
        ).fetchone()

    if not tree:
        flash("Family tree not found.", "error")
        return redirect(url_for('dashboard'))

    people = conn.execute(
        "SELECT * FROM people WHERE tree_id = ? ORDER BY last_name, first_name",
        (tree_id,)
    ).fetchall()

    stories = conn.execute(
        "SELECT * FROM stories WHERE tree_id = ? ORDER BY created_at DESC",
        (tree_id,)
    ).fetchall()

    records = conn.execute(
        "SELECT * FROM records WHERE tree_id = ? ORDER BY uploaded_at DESC",
        (tree_id,)
    ).fetchall()

    conn.close()
    return render_template('view_tree.html',
                         tree=tree, people=people,
                         stories=stories, records=records)


@app.route('/tree/<int:tree_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tree(tree_id):
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ?",
            (tree_id,)
        ).fetchone()
    else:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ? AND user_id = ?",
            (tree_id, session['user_id'])
        ).fetchone()
    conn.close()

    if not tree:
        flash("Family tree not found.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        conn = get_db()
        conn.execute(
            "UPDATE family_trees SET name = ?, description = ? WHERE id = ?",
            (name, description, tree_id)
        )
        conn.commit()
        conn.close()
        flash("Family tree updated!", "success")
        return redirect(url_for('view_tree', tree_id=tree_id))

    return render_template('tree_form.html', action='Edit', tree=tree)


@app.route('/tree/<int:tree_id>/delete', methods=['POST'])
@login_required
def delete_tree(tree_id):
    conn = get_db()
    if role_at_least('admin'):
        conn.execute("DELETE FROM family_trees WHERE id = ?", (tree_id,))
    else:
        conn.execute("DELETE FROM family_trees WHERE id = ? AND user_id = ?",
                     (tree_id, session['user_id']))
    conn.commit()
    conn.close()
    flash("Family tree deleted.", "info")
    return redirect(url_for('dashboard'))


# ─── People CRUD ─────────────────────────────────────────────────────────

@app.route('/tree/<int:tree_id>/person/new', methods=['GET', 'POST'])
@login_required
def new_person(tree_id):
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        birth_date = request.form.get('birth_date', '')
        death_date = request.form.get('death_date', '')
        birth_place = request.form.get('birth_place', '')
        death_place = request.form.get('death_place', '')
        notes = request.form.get('notes', '')

        # Handle photo upload
        photo_url = ''
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(Config.UPLOAD_FOLDER, f"person_{session['user_id']}_{filename}")
                file.save(filepath)
                photo_url = f"/uploads/{os.path.basename(filepath)}"

        conn = get_db()
        conn.execute(
            """INSERT INTO people (tree_id, first_name, last_name, birth_date, death_date,
               birth_place, death_place, notes, photo_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tree_id, first_name, last_name, birth_date, death_date,
             birth_place, death_place, notes, photo_url)
        )
        conn.commit()
        conn.close()
        flash(f"Added {first_name} {last_name} to the tree.", "success")
        return redirect(url_for('view_tree', tree_id=tree_id))

    return render_template('person_form.html', tree_id=tree_id, action='Add')


@app.route('/person/<int:person_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_person(person_id):
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        person = conn.execute(
            """SELECT p.* FROM people p
               JOIN family_trees t ON p.tree_id = t.id
               WHERE p.id = ?""",
            (person_id,)
        ).fetchone()
    else:
        person = conn.execute(
            """SELECT p.* FROM people p
               JOIN family_trees t ON p.tree_id = t.id
               WHERE p.id = ? AND t.user_id = ?""",
            (person_id, session['user_id'])
        ).fetchone()
    conn.close()

    if not person:
        flash("Person not found.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        birth_date = request.form.get('birth_date', '')
        death_date = request.form.get('death_date', '')
        birth_place = request.form.get('birth_place', '')
        death_place = request.form.get('death_place', '')
        notes = request.form.get('notes', '')

        photo_url = person['photo_url']
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(Config.UPLOAD_FOLDER, f"person_{session['user_id']}_{filename}")
                file.save(filepath)
                photo_url = f"/uploads/{os.path.basename(filepath)}"

        conn = get_db()
        conn.execute(
            """UPDATE people SET first_name=?, last_name=?, birth_date=?, death_date=?,
               birth_place=?, death_place=?, notes=?, photo_url=? WHERE id=?""",
            (first_name, last_name, birth_date, death_date,
             birth_place, death_place, notes, photo_url, person_id)
        )
        conn.commit()
        conn.close()
        flash(f"Updated {first_name} {last_name}.", "success")
        return redirect(url_for('view_tree', tree_id=person['tree_id']))

    return render_template('person_form.html', person=person, action='Edit')


@app.route('/person/<int:person_id>/delete', methods=['POST'])
@login_required
def delete_person(person_id):
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        person = conn.execute(
            """SELECT p.* FROM people p
               JOIN family_trees t ON p.tree_id = t.id
               WHERE p.id = ?""",
            (person_id,)
        ).fetchone()
    else:
        person = conn.execute(
            """SELECT p.* FROM people p
               JOIN family_trees t ON p.tree_id = t.id
               WHERE p.id = ? AND t.user_id = ?""",
            (person_id, session['user_id'])
        ).fetchone()
    if person:
        tree_id = person['tree_id']
        conn.execute("DELETE FROM people WHERE id = ?", (person_id,))
        conn.commit()
        conn.close()
        flash("Person removed.", "info")
        return redirect(url_for('view_tree', tree_id=tree_id))

    conn.close()
    flash("Person not found.", "error")
    return redirect(url_for('dashboard'))


# ─── Relationships ───────────────────────────────────────────────────────

@app.route('/tree/<int:tree_id>/relationship/new', methods=['GET', 'POST'])
@login_required
def new_relationship(tree_id):
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ?", (tree_id,)
        ).fetchone()
    else:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ? AND user_id = ?",
            (tree_id, session['user_id'])
        ).fetchone()

    if not tree:
        conn.close()
        flash("Tree not found.", "error")
        return redirect(url_for('dashboard'))

    people = conn.execute(
        "SELECT id, first_name, last_name FROM people WHERE tree_id = ? ORDER BY last_name",
        (tree_id,)
    ).fetchall()
    conn.close()

    if request.method == 'POST':
        person_1_id = request.form['person_1_id']
        person_2_id = request.form['person_2_id']
        relationship_type = request.form['relationship_type']

        if person_1_id == person_2_id:
            flash("Cannot create a relationship with the same person.", "error")
            return render_template('relationship_form.html', tree_id=tree_id, people=people)

        conn = get_db()
        conn.execute(
            "INSERT INTO relationships (tree_id, person_1_id, person_2_id, relationship_type) VALUES (?, ?, ?, ?)",
            (tree_id, person_1_id, person_2_id, relationship_type)
        )
        conn.commit()
        conn.close()
        flash("Relationship added!", "success")
        return redirect(url_for('view_tree', tree_id=tree_id))

    return render_template('relationship_form.html', tree_id=tree_id, people=people)


# ─── Stories ─────────────────────────────────────────────────────────────

@app.route('/tree/<int:tree_id>/story/new', methods=['GET', 'POST'])
@login_required
def new_story(tree_id):
    conn = get_db()
    people = conn.execute(
        "SELECT id, first_name, last_name FROM people WHERE tree_id = ? ORDER BY last_name",
        (tree_id,)
    ).fetchall()
    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        person_id = request.form.get('person_id') or None
        author = request.form.get('author', session.get('user_name', ''))

        conn = get_db()
        conn.execute(
            "INSERT INTO stories (tree_id, person_id, title, content, author) VALUES (?, ?, ?, ?, ?)",
            (tree_id, person_id, title, content, author)
        )
        conn.commit()
        conn.close()
        flash("Story saved!", "success")
        return redirect(url_for('view_tree', tree_id=tree_id))

    return render_template('story_form.html', tree_id=tree_id, people=people)


@app.route('/story/<int:story_id>/delete', methods=['POST'])
@login_required
def delete_story(story_id):
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        story = conn.execute(
            """SELECT s.* FROM stories s
               JOIN family_trees t ON s.tree_id = t.id
               WHERE s.id = ?""",
            (story_id,)
        ).fetchone()
    else:
        story = conn.execute(
            """SELECT s.* FROM stories s
               JOIN family_trees t ON s.tree_id = t.id
               WHERE s.id = ? AND t.user_id = ?""",
            (story_id, session['user_id'])
        ).fetchone()
    if story:
        tree_id = story['tree_id']
        conn.execute("DELETE FROM stories WHERE id = ?", (story_id,))
        conn.commit()
        conn.close()
        flash("Story deleted.", "info")
        return redirect(url_for('view_tree', tree_id=tree_id))

    conn.close()
    flash("Story not found.", "error")
    return redirect(url_for('dashboard'))


# ─── Records ─────────────────────────────────────────────────────────────

@app.route('/tree/<int:tree_id>/record/new', methods=['GET', 'POST'])
@login_required
def new_record(tree_id):
    conn = get_db()
    people = conn.execute(
        "SELECT id, first_name, last_name FROM people WHERE tree_id = ? ORDER BY last_name",
        (tree_id,)
    ).fetchall()
    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        record_type = request.form.get('record_type', 'document')
        description = request.form.get('description', '')
        record_date = request.form.get('record_date', '')
        person_id = request.form.get('person_id') or None

        # Handle file upload
        file_url = ''
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(Config.UPLOAD_FOLDER, f"rec_{session['user_id']}_{filename}")
                file.save(filepath)
                file_url = f"/uploads/{os.path.basename(filepath)}"

        conn = get_db()
        conn.execute(
            "INSERT INTO records (tree_id, person_id, title, record_type, file_url, description, record_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tree_id, person_id, title, record_type, file_url, description, record_date)
        )
        conn.commit()
        conn.close()
        flash(f"Record '{title}' added!", "success")
        return redirect(url_for('view_tree', tree_id=tree_id))

    return render_template('record_form.html', tree_id=tree_id, people=people,
                         record_types=['document', 'photo', 'census', 'certificate', 'letter', 'audio', 'other'])


@app.route('/record/<int:record_id>/delete', methods=['POST'])
@login_required
def delete_record(record_id):
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        record = conn.execute(
            """SELECT r.* FROM records r
               JOIN family_trees t ON r.tree_id = t.id
               WHERE r.id = ?""",
            (record_id,)
        ).fetchone()
    else:
        record = conn.execute(
            """SELECT r.* FROM records r
               JOIN family_trees t ON r.tree_id = t.id
               WHERE r.id = ? AND t.user_id = ?""",
            (record_id, session['user_id'])
        ).fetchone()
    if record:
        tree_id = record['tree_id']
        if record['file_url']:
            filepath = os.path.join(Config.UPLOAD_FOLDER, os.path.basename(record['file_url']))
            if os.path.exists(filepath):
                os.remove(filepath)
        conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        conn.commit()
        conn.close()
        flash("Record deleted.", "info")
        return redirect(url_for('view_tree', tree_id=tree_id))

    conn.close()
    flash("Record not found.", "error")
    return redirect(url_for('dashboard'))


# ─── Export ──────────────────────────────────────────────────────────────

@app.route('/tree/<int:tree_id>/export')
@login_required
def export_tree(tree_id):
    """Export family tree data as JSON."""
    conn = get_db()
    is_admin = role_at_least('admin')
    if is_admin:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ?", (tree_id,)
        ).fetchone()
    else:
        tree = conn.execute(
            "SELECT * FROM family_trees WHERE id = ? AND user_id = ?",
            (tree_id, session['user_id'])
        ).fetchone()
    if not tree:
        conn.close()
        flash("Tree not found.", "error")
        return redirect(url_for('dashboard'))

    people = conn.execute(
        "SELECT * FROM people WHERE tree_id = ?", (tree_id,)
    ).fetchall()

    relationships = conn.execute(
        "SELECT * FROM relationships WHERE tree_id = ?", (tree_id,)
    ).fetchall()

    stories = conn.execute(
        "SELECT * FROM stories WHERE tree_id = ?", (tree_id,)
    ).fetchall()

    records = conn.execute(
        "SELECT * FROM records WHERE tree_id = ?", (tree_id,)
    ).fetchall()
    conn.close()

    export_data = {
        'tree': dict(tree),
        'people': [dict(p) for p in people],
        'relationships': [dict(r) for r in relationships],
        'stories': [dict(s) for s in stories],
        'records': [dict(r) for r in records],
        'exported_at': datetime.now().isoformat()
    }

    response = app.response_class(
        response=json.dumps(export_data, indent=2, default=str),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename={tree["name"]}_export.json'
    return response


# ─── Search ──────────────────────────────────────────────────────────────

@app.route('/search', methods=['GET'])
@login_required
def search():
    """Search across all trees for a user (admin can search all)."""
    query = request.args.get('q', '').strip()
    results = {'people': [], 'stories': [], 'records': []}

    if query:
        conn = get_db()
        is_admin = role_at_least('admin')

        if is_admin:
            results['people'] = [dict(r) for r in conn.execute(
                """SELECT p.*, t.name as tree_name, t.id as tree_id FROM people p
                   JOIN family_trees t ON p.tree_id = t.id
                   WHERE p.first_name LIKE ? OR p.last_name LIKE ? OR p.birth_place LIKE ? OR p.death_place LIKE ?""",
                (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%')
            ).fetchall()]
            results['stories'] = [dict(r) for r in conn.execute(
                """SELECT s.*, t.name as tree_name, t.id as tree_id FROM stories s
                   JOIN family_trees t ON s.tree_id = t.id
                   WHERE s.title LIKE ? OR s.content LIKE ?""",
                (f'%{query}%', f'%{query}%')
            ).fetchall()]
            results['records'] = [dict(r) for r in conn.execute(
                """SELECT r.*, t.name as tree_name, t.id as tree_id FROM records r
                   JOIN family_trees t ON r.tree_id = t.id
                   WHERE r.title LIKE ? OR r.description LIKE ?""",
                (f'%{query}%', f'%{query}%')
            ).fetchall()]
        else:
            results['people'] = [dict(r) for r in conn.execute(
                """SELECT p.*, t.name as tree_name, t.id as tree_id FROM people p
                   JOIN family_trees t ON p.tree_id = t.id
                   WHERE t.user_id = ? AND (p.first_name LIKE ? OR p.last_name LIKE ? OR p.birth_place LIKE ? OR p.death_place LIKE ?)""",
                (session['user_id'], f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%')
            ).fetchall()]
            results['stories'] = [dict(r) for r in conn.execute(
                """SELECT s.*, t.name as tree_name, t.id as tree_id FROM stories s
                   JOIN family_trees t ON s.tree_id = t.id
                   WHERE t.user_id = ? AND (s.title LIKE ? OR s.content LIKE ?)""",
                (session['user_id'], f'%{query}%', f'%{query}%')
            ).fetchall()]
            results['records'] = [dict(r) for r in conn.execute(
                """SELECT r.*, t.name as tree_name, t.id as tree_id FROM records r
                   JOIN family_trees t ON r.tree_id = t.id
                   WHERE t.user_id = ? AND (r.title LIKE ? OR r.description LIKE ?)""",
                (session['user_id'], f'%{query}%', f'%{query}%')
            ).fetchall()]
        conn.close()

    return render_template('search.html', query=query, results=results)


# ─── Admin Routes ────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard showing system stats."""
    conn = get_db()
    user_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    tree_count = conn.execute("SELECT COUNT(*) as c FROM family_trees").fetchone()['c']
    person_count = conn.execute("SELECT COUNT(*) as c FROM people").fetchone()['c']
    story_count = conn.execute("SELECT COUNT(*) as c FROM stories").fetchone()['c']
    record_count = conn.execute("SELECT COUNT(*) as c FROM records").fetchone()['c']

    # Users by role
    roles = {}
    for r in conn.execute("SELECT role, COUNT(*) as c FROM users GROUP BY role").fetchall():
        roles[r['role']] = r['c']

    # 2FA stats
    totp_count = conn.execute("SELECT COUNT(*) as c FROM users WHERE totp_enabled = 1").fetchone()['c']
    conn.close()

    return render_template('admin_dashboard.html',
                         user_count=user_count,
                         tree_count=tree_count,
                         person_count=person_count,
                         story_count=story_count,
                         record_count=record_count,
                         roles=roles,
                         totp_count=totp_count)


@app.route('/admin/users')
@admin_required
def admin_users():
    """Manage users."""
    users = get_all_users()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/<int:user_id>/edit-role', methods=['POST'])
@admin_required
def admin_edit_role(user_id):
    """Change a user's role."""
    new_role = request.form.get('role')
    if new_role not in ('owner', 'admin', 'editor', 'user'):
        flash("Invalid role.", "error")
        return redirect(url_for('admin_users'))

    error = update_user_role(user_id, new_role, session['user_id'])
    if error:
        flash(error, "error")
    else:
        target_user = get_user(user_id)
        flash(f"Updated {target_user['name']}'s role to {new_role}.", "success")

    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user account."""
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('admin_users'))

    target = get_user(user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for('admin_users'))

    # Only owner can delete admin users
    if target['role'] == 'admin' and session.get('role') != 'owner':
        flash("Only the owner can delete admin accounts.", "error")
        return redirect(url_for('admin_users'))

    if target['role'] == 'owner':
        flash("Cannot delete the owner account.", "error")
        return redirect(url_for('admin_users'))

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash(f"Deleted user {target['name']}.", "info")
    return redirect(url_for('admin_users'))

# ─── Newsletter Subscription API ─────────────────────────────────────────

def _is_valid_email(email):
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip())) if email else False


@app.route('/api/subscribe', methods=['POST'])
def api_subscribe():
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
    except Exception as e:
        conn.close()
        # Check for duplicate email
        if 'UNIQUE constraint' in str(e):
            return jsonify({
                'success': False,
                'error': 'This email is already subscribed.'
            }), 409
        return jsonify({'success': False, 'error': 'An error occurred.'}), 500


@app.route('/api/subscribers')
@admin_required
def api_subscribers():
    """List all newsletter subscribers (admin only)."""
    conn = get_db()
    subscribers = conn.execute(
        "SELECT id, email, subscribed_at, active FROM subscribers ORDER BY subscribed_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(s) for s in subscribers])


# ─── Uploaded Files ──────────────────────────────────────────────────────

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files."""
    return send_from_directory(Config.UPLOAD_FOLDER, filename)


# ─── Main ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Bind to all interfaces on port 3000 for the team's public site
    app.run(host='0.0.0.0', port=3000, debug=True)