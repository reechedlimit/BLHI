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
    """Initialize the database schema."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    """)

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


if __name__ == '__main__':
    init_db()