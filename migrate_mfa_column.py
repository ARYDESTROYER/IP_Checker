from app import app
from models import db, User
from sqlalchemy import text

with app.app_context():
    # Only add columns if they don't exist (safe for SQLite)
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN mfa_secret VARCHAR(32)'))
    except Exception as e:
        if 'duplicate column name' not in str(e):
            print('Error adding mfa_secret:', e)
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0'))
    except Exception as e:
        if 'duplicate column name' not in str(e):
            print('Error adding mfa_enabled:', e)
    db.session.commit()
    print('MFA columns migration complete.')
