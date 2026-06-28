"""
Family History Documentation Tool — Main Application
Black Lineage & Heritage Institute
"""
import os
import json
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename

from config import Config
from models import get_db, init_db
from auth import create_user, verify_login, login_required

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Ensure directories exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.SESSION_FILE_DIR, exist_ok=True)

# Initialize database on first run
if not os.path.exists(Config.DATABASE_PATH):
    init_db()
else:
    # Ensure tables exist even if db file exists but is empty
    try:
        conn = get_db()
        conn.execute("SELECT COUNT(*) FROM users")
        conn.close()
    except Exception:
        init_db()


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

        user_id, error = create_user(name, email, password)
        if error:
            flash(error, "error")
            return render_template('register.html')

        session['user_id'] = user_id
        session['user_name'] = name
        flash("Account created! Welcome to the Family History Documentation Tool.", "success")
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = verify_login(email, password)
        if user:
            session['user_id'] = user['id']
            session['user_name'] = user['name']
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
                         user_name=session.get('user_name'))


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
    record = conn.execute(
        """SELECT r.* FROM records r
           JOIN family_trees t ON r.tree_id = t.id
           WHERE r.id = ? AND t.user_id = ?""",
        (record_id, session['user_id'])
    ).fetchone()
    if record:
        tree_id = record['tree_id']
        # Delete the file from disk if it exists
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
    """Search across all trees for a user."""
    query = request.args.get('q', '').strip()
    results = {'people': [], 'stories': [], 'records': []}

    if query:
        conn = get_db()
        # Search people
        results['people'] = [dict(r) for r in conn.execute(
            """SELECT p.*, t.name as tree_name, t.id as tree_id FROM people p
               JOIN family_trees t ON p.tree_id = t.id
               WHERE t.user_id = ? AND (p.first_name LIKE ? OR p.last_name LIKE ? OR p.birth_place LIKE ? OR p.death_place LIKE ?)""",
            (session['user_id'], f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%')
        ).fetchall()]

        # Search stories
        results['stories'] = [dict(r) for r in conn.execute(
            """SELECT s.*, t.name as tree_name, t.id as tree_id FROM stories s
               JOIN family_trees t ON s.tree_id = t.id
               WHERE t.user_id = ? AND (s.title LIKE ? OR s.content LIKE ?)""",
            (session['user_id'], f'%{query}%', f'%{query}%')
        ).fetchall()]

        # Search records
        results['records'] = [dict(r) for r in conn.execute(
            """SELECT r.*, t.name as tree_name, t.id as tree_id FROM records r
               JOIN family_trees t ON r.tree_id = t.id
               WHERE t.user_id = ? AND (r.title LIKE ? OR r.description LIKE ?)""",
            (session['user_id'], f'%{query}%', f'%{query}%')
        ).fetchall()]
        conn.close()

    return render_template('search.html', query=query, results=results)


# ─── Uploaded Files ──────────────────────────────────────────────────────

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files."""
    return send_from_directory(Config.UPLOAD_FOLDER, filename)


# ─── Main ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Bind to all interfaces on port 3000 for the team's public site
    app.run(host='0.0.0.0', port=3000, debug=True)