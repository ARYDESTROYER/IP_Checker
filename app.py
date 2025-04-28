import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
from models import db, User
from utils import is_valid_username, is_valid_email, is_valid_password
from ip_checker import (
    is_valid_ip,
    get_ip_info,
    get_virustotal_rep,
    get_abuseipdb_rep,
    get_pulsedive_rep,
    get_greynoise_rep
)
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'changeme')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# @app.before_first_request
def create_tables():
    db.create_all()

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.status != 'active':
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# --- Protect all sensitive routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        # Validate fields
        if not is_valid_username(username):
            flash('Invalid username. Use 3-30 letters only.')
            return render_template('register.html')
        if not is_valid_email(email):
            flash('Invalid email address.')
            return render_template('register.html')
        if not is_valid_password(password):
            flash('Password must be at least 8 characters, with letters and numbers.')
            return render_template('register.html')
        # Check uniqueness
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already registered.')
            return render_template('register.html')
        # Create user with pending status
        user = User(username=username, email=email, role='user', status='pending')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Await admin approval.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_email = request.form['username_email'].strip()
        password = request.form['password']
        user = None
        if is_valid_email(username_email):
            user = User.query.filter_by(email=username_email.lower()).first()
        elif is_valid_username(username_email):
            user = User.query.filter_by(username=username_email).first()
        else:
            flash('Invalid username/email format.')
            return render_template('login.html')
        if not user or not user.check_password(password):
            flash('Invalid credentials.')
            return render_template('login.html')
        session['user_id'] = user.id
        session['role'] = user.role
        session['status'] = user.status
        if user.status != 'active':
            flash('Your account is pending admin approval.')
            return render_template('login.html')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    users = User.query.all()
    if request.method == 'POST':
        uid = int(request.form['user_id'])
        action = request.form['action']
        user = User.query.get(uid)
        if user:
            if action == 'approve':
                user.status = 'active'
            elif action == 'pending':
                user.status = 'pending'
            db.session.commit()
    return render_template('admin.html', users=users)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    ip = ''
    ip_info = None
    reports = []
    error = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not is_valid_ip(ip):
            error = f"'{ip}' is not a valid IP address."
        else:
            ip_info = get_ip_info(ip)
            reports = [
                get_virustotal_rep(ip, os.getenv('VT_API_KEY')),
                get_abuseipdb_rep(ip, os.getenv('ABUSEIPDB_API_KEY')),
                get_pulsedive_rep(ip, os.getenv('PULSEDIVE_API_KEY')),
                get_greynoise_rep(ip, os.getenv('GREYNOISE_API_KEY')),
            ]
    return render_template('index.html', ip=ip, ip_info=ip_info, reports=reports, error=error)

# --- Ensure all other routes redirect to login if not logged in ---
@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(e):
    # Optionally, redirect to login or show a custom 404 page
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
