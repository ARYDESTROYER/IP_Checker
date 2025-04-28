from models import db, User
from app import app

def migrate():
    with app.app_context():
        # Add the new column if it doesn't exist
        if not hasattr(User, 'phone'):
            db.engine.execute('ALTER TABLE user ADD COLUMN phone VARCHAR(20)')
        else:
            # Column already exists
            pass
        print('Phone column migration complete.')

if __name__ == '__main__':
    migrate()
