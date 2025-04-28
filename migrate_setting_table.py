from models import db, Setting
from app import app

def migrate():
    with app.app_context():
        db.create_all()
        # Set a default session timeout if not present
        if not Setting.query.filter_by(key='session_timeout').first():
            db.session.add(Setting(key='session_timeout', value='1800'))  # 30 minutes default
            db.session.commit()
        print('Setting table migration complete.')

if __name__ == '__main__':
    migrate()
