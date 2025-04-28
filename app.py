import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
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
import pyotp
import qrcode
import io
import base64

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
@app.before_request
def check_force_password_reset():
    allowed_routes = ['logout', 'reset_password', 'static', 'login', 'register', 'mfa_verify']
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and getattr(user, 'force_password_reset', False):
            if request.endpoint not in allowed_routes and not request.endpoint.startswith('static'):
                return redirect(url_for('reset_password'))

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
        if user and user.check_password(password):
            if user.mfa_enabled:
                session['pre_mfa_user_id'] = user.id
                return redirect(url_for('mfa_verify'))
            else:
                session['user_id'] = user.id
                session['role'] = 'admin' if user.is_admin() else 'user'
                flash('Logged in successfully!')
                return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pre_mfa_user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['pre_mfa_user_id'])
    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            session['user_id'] = user.id
            session['role'] = 'admin' if user.is_admin() else 'user'
            session.pop('pre_mfa_user_id', None)
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid MFA code. Please try again.')
    return render_template('mfa_verify.html', email=user.email)

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
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        if action == 'set_status':
            new_status = request.form.get('new_status')
            user.status = new_status
            db.session.commit()
            flash(f"Status for {user.email} set to {new_status}.")
        elif action == 'set_role':
            new_role = request.form.get('new_role')
            user.role = new_role
            db.session.commit()
            flash(f"Role for {user.email} set to {new_role}.")
        elif action == 'force_reset':
            user.force_password_reset = True
            db.session.commit()
            flash(f"Password reset required for {user.email}.")
        return redirect(url_for('admin'))
    return render_template('admin.html', users=users)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password and new_password == confirm_password:
            user.set_password(new_password)
            user.force_password_reset = False
            db.session.commit()
            flash('Password reset successfully!')
            return redirect(url_for('index'))
        else:
            flash('Passwords do not match. Please try again.')
    return render_template('reset_password.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        display_name = request.form.get('display_name')
        phone = request.form.get('phone')
        if display_name:
            user.username = display_name
        if phone:
            user.phone = phone
        db.session.commit()
        flash('Profile updated successfully!')
    return render_template('profile.html', user=user)

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

@app.route('/security', methods=['GET'])
@login_required
def security():
    user = User.query.get(session['user_id'])
    mfa_enabled = user.mfa_enabled
    mfa_verified = False
    qr_code_url = None
    # DEBUG: print MFA state for troubleshooting
    print(f"[DEBUG] mfa_secret={user.mfa_secret}, mfa_enabled={user.mfa_enabled}")
    if user.mfa_secret and not user.mfa_enabled:
        totp = pyotp.TOTP(user.mfa_secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="IP Reputation Checker")
        print(f"[DEBUG] TOTP URI: {uri}")
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format='PNG')
        qr_code_url = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()
        print(f"[DEBUG] QR code generated (length): {len(qr_code_url)}")
        mfa_verified = False
    elif user.mfa_enabled:
        mfa_enabled = True
        mfa_verified = True
    else:
        mfa_enabled = False
        mfa_verified = False
    return render_template('security.html', mfa_enabled=mfa_enabled, mfa_verified=mfa_verified, qr_code_url=qr_code_url)

@app.route('/security/start-mfa', methods=['POST'])
@login_required
def start_mfa():
    user = User.query.get(session['user_id'])
    # Always generate a new secret and clear mfa_enabled to force QR code display
    user.mfa_secret = pyotp.random_base32()
    user.mfa_enabled = False
    db.session.commit()
    return redirect(url_for('security'))

@app.route('/security/verify-mfa', methods=['POST'])
@login_required
def verify_mfa():
    user = User.query.get(session['user_id'])
    code = request.form.get('code')
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code):
        user.mfa_enabled = True
        db.session.commit()
        flash('MFA enabled successfully!')
    else:
        flash('Invalid code. Please try again.')
    return redirect(url_for('security'))

@app.route('/security/disable-mfa', methods=['POST'])
@login_required
def disable_mfa():
    user = User.query.get(session['user_id'])
    user.mfa_secret = None
    user.mfa_enabled = False
    db.session.commit()
    flash('MFA disabled.')
    return redirect(url_for('security'))

@app.route('/security/regenerate-mfa', methods=['POST'])
@login_required
def regenerate_mfa():
    user = User.query.get(session['user_id'])
    user.mfa_secret = pyotp.random_base32()
    user.mfa_enabled = False
    db.session.commit()
    flash('MFA secret regenerated. Please scan the new code.')
    return redirect(url_for('security'))

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
