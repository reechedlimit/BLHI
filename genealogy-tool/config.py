"""Configuration for the Family History Documentation Tool."""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Use /tmp for writable storage on Vercel (serverless), local dir otherwise
VERCEL = os.environ.get('VERCEL', '0') == '1'
DATA_DIR = '/tmp' if VERCEL else BASE_DIR

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DATABASE_PATH = os.path.join(DATA_DIR, 'genealogy.db')
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32MB max upload
    # Use signed cookies for sessions — no filesystem writes needed
    SESSION_TYPE = 'null'  # Disable Flask-Session, use default cookie sessions
    SESSION_PERMANENT = False