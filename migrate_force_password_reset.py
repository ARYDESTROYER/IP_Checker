from models import db, User
from app import app

def migrate():
    with app.app_context():
        # Add the new column if it doesn't exist
        if not hasattr(User, 'force_password_reset'):
            db.engine.execute('ALTER TABLE user ADD COLUMN force_password_reset BOOLEAN DEFAULT 0')
        else:
            # Column already exists
            pass
        print('Migration complete.')

if __name__ == '__main__':
    migrate()
