"""
Database models and schema for the Family History Documentation Tool.
Uses SQLite for lightweight, portable storage.
"""
import sqlite3
import os
from config import Config


def get_db():
    """Get a database connection with row_factory set for dict-like access."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize the database schema with all tables and migrations."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            totp_secret TEXT DEFAULT NULL,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS family_trees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS people (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tree_id INTEGER NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            birth_date TEXT DEFAULT '',
            death_date TEXT DEFAULT '',
            birth_place TEXT DEFAULT '',
            death_place TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            photo_url TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tree_id) REFERENCES family_trees(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tree_id INTEGER NOT NULL,
            person_1_id INTEGER NOT NULL,
            person_2_id INTEGER NOT NULL,
            relationship_type TEXT NOT NULL CHECK(relationship_type IN ('spouse', 'parent-child', 'sibling', 'other')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tree_id) REFERENCES family_trees(id) ON DELETE CASCADE,
            FOREIGN KEY (person_1_id) REFERENCES people(id) ON DELETE CASCADE,
            FOREIGN KEY (person_2_id) REFERENCES people(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tree_id INTEGER NOT NULL,
            person_id INTEGER,
            title TEXT NOT NULL,
            record_type TEXT NOT NULL DEFAULT 'document',
            file_url TEXT DEFAULT '',
            description TEXT DEFAULT '',
            record_date TEXT DEFAULT '',
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tree_id) REFERENCES family_trees(id) ON DELETE CASCADE,
            FOREIGN KEY (person_id) REFERENCES people(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tree_id INTEGER NOT NULL,
            person_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tree_id) REFERENCES family_trees(id) ON DELETE CASCADE,
            FOREIGN KEY (person_id) REFERENCES people(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active INTEGER NOT NULL DEFAULT 1
        );
    """)

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


def run_migrations():
    """Run incremental migrations for existing databases.
    Adds columns that may not exist in older database versions."""
    conn = get_db()

    # Migration 1: Add role column
    try:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        print("Migration: Added role column to users")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Migration 2: Add totp_secret column
    try:
        conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL")
        print("Migration: Added totp_secret column to users")
    except sqlite3.OperationalError:
        pass

    # Migration 3: Add totp_enabled column
    try:
        conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
        print("Migration: Added totp_enabled column to users")
    except sqlite3.OperationalError:
        pass

    # Migration 4: Create recovery_codes table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    print("Migration: Ensured recovery_codes table exists")

    # Migration 5: Create subscribers table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)
    print("Migration: Ensured subscribers table exists")

    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()