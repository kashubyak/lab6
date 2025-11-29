import re
import os
import io
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
from datetime import datetime
import pyotp
import qrcode
from sqlalchemy.exc import IntegrityError
from flask_dance.contrib.google import make_google_blueprint, google

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

RECAPTCHA_SITE_KEY = '6LcM6xssAAAAAHiYf3RLqakle5VFqVXoOCCAbk0C' 
RECAPTCHA_SECRET_KEY = '6LcM6xssAAAAAMXXQRTCv-yb_1w3SEQ7FTlWgUNz' 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Тут має бути дуже довгий та секретний ключ!' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER') 
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS') 
app.config['MAIL_DEFAULT_SENDER'] = ('Security App', app.config['MAIL_USERNAME'])

app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=["profile", "email"],
    redirect_to="google_login_callback"
)
google_bp.authorization_url_params["prompt"] = "select_account"
app.register_blueprint(google_bp, url_prefix="/login")

db = SQLAlchemy(app)
mail = Mail(app)

s = Serializer(app.config['SECRET_KEY']) 
ACTIVATION_TOKEN_EXPIRATION = 60 * 60 * 24
PASSWORD_RESET_TOKEN_EXPIRATION = 60 * 60

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=False) 
    login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True) 
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<User {self.email}>'

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)

def verify_recaptcha(response):
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response
    }
    resp = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = resp.json()
    return result.get('success', False)

def validate_password_policy(password):
    if len(password) < 8:
        return "Пароль повинен бути не менше 8 символів."
    if not re.search(r"[A-Z]", password):
        return "Пароль повинен містити хоча б одну велику літеру."
    if not re.search(r"[a-z]", password):
        return "Пароль повинен містити хоча б одну малу літеру."
    if not re.search(r"\d", password):
        return "Пароль повинен містити хоча б одну цифру."
    if not re.search(r"[^a-zA-Z0-9\s]", password):
        return "Пароль повинен містити хоча б один спеціальний символ."
    return None

def send_email(recipients, subject, body):
    msg = Message(
        subject=subject,
        recipients=recipients,
        body=body
    )
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Помилка відправки пошти. Перевірте MAIL_USERNAME та MAIL_PASSWORD: {e}") 
        return False

def send_activation_email(user_email):
    token = s.dumps(user_email, salt='email-confirm') 
    activation_url = url_for('activate_account', token=token, _external=True)

    body = f"""
Шановний користувач,

Ваш обліковий запис було успішно зареєстровано.
Будь ласка, перейдіть за цим посиланням, щоб активувати його:
{activation_url}

Посилання дійсне протягом {ACTIVATION_TOKEN_EXPIRATION // 3600} годин.

З повагою,
Команда Безпеки.
"""
    return send_email([user_email], 'Активація облікового запису', body)

def send_password_reset_email(user_email):
    token = s.dumps(user_email, salt='password-reset') 
    reset_url = url_for('reset_password', token=token, _external=True)

    body = f"""
Шановний користувач,

Ви запросили відновлення пароля для вашого облікового запису.
Будь ласка, перейдіть за цим посиланням, щоб встановити новий пароль:
{reset_url}

Посилання дійсне протягом {PASSWORD_RESET_TOKEN_EXPIRATION // 60} хвилин.
Якщо ви не робили цей запит, просто проігноруйте цей лист.

З повагою,
Команда Безпеки.
"""
    return send_email([user_email], 'Відновлення Пароля', body)


with app.app_context():
    db.create_all()

@app.context_processor
def inject_global_vars():
    return dict(RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            flash('Помилка CAPTCHA. Будь ласка, підтвердьте, що ви не робот.', 'danger')
            return render_template('register.html')

        error_message = validate_password_policy(password)
        if error_message:
            flash(error_message, 'error')
            return render_template('register.html', email=email) 

        if User.query.filter_by(email=email).first():
            flash('Користувач з цією електронною поштою вже зареєстрований.', 'warning')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        
        new_user = User(email=email, password_hash=password_hash, is_active=False)
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Помилка реєстрації. Можливо, email вже використовується.', 'warning')
            return redirect(url_for('register'))
        
        if send_activation_email(email):
            flash('Реєстрація успішна! На вашу пошту надіслано лист для активації облікового запису.', 'success')
        else:
            flash('Реєстрація успішна, але сталася помилка при відправці листа. Перевірте налаштування пошти у app.py!', 'warning')
        
        return redirect(url_for('login'))
        
    return render_template('register.html')


@app.route('/activate/<token>')
def activate_account(token):
    try:
        email = s.loads(
            token, 
            salt='email-confirm', 
            max_age=ACTIVATION_TOKEN_EXPIRATION
        )
    except:
        flash('Посилання для активації недійсне або термін його дії минув.', 'danger')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first()

    if user and not user.is_active:
        user.is_active = True
        db.session.commit()
        flash('Обліковий запис успішно активовано! Тепер ви можете увійти.', 'success')
    elif user and user.is_active:
        flash('Ваш обліковий запис вже активовано.', 'info')
    else:
         flash('Користувача з цим email не знайдено.', 'danger')

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        ip_address = request.remote_addr 

        user = User.query.filter_by(email=email).first()

        if user is None:
            log_attempt = LoginAttempt(email=email, ip_address=ip_address, success=False)
            db.session.add(log_attempt)
            db.session.commit()
            
            flash('Користувача з таким email не знайдено. Будь ласка, зареєструйтесь.', 'danger')
            return redirect(url_for('register'))

        if user.is_locked:
            flash('Ваш обліковий запис заблоковано через забагато невдалих спроб входу.', 'danger')
            return redirect(url_for('login'))

        if check_password_hash(user.password_hash, password):
            
            if not user.is_active:
                log_attempt = LoginAttempt(email=email, ip_address=ip_address, success=False)
                db.session.add(log_attempt)
                db.session.commit()
                flash('Ваш обліковий запис не активовано. Будь ла ласка, перевірте пошту.', 'warning')
                return redirect(url_for('login'))
                
            if user.two_factor_enabled:
                session['2fa_pending_email'] = user.email
                flash('Введіть код 2FA.', 'info')
                return redirect(url_for('verify_2fa'))

            user.login_attempts = 0 
            session['user_id'] = user.id
            session['user_email'] = user.email
            
            log_attempt = LoginAttempt(email=email, ip_address=ip_address, success=True)
            db.session.add(log_attempt)
            db.session.commit()
            
            flash(f'Успішний вхід, {user.email}!', 'success')
            return redirect(url_for('profile'))
            
        else:
            user.login_attempts += 1
            log_attempt = LoginAttempt(email=email, ip_address=ip_address, success=False)
            db.session.add(log_attempt)
            
            MAX_ATTEMPTS = 5
            if user.login_attempts >= MAX_ATTEMPTS:
                user.is_locked = True
                flash(f'Неправильний пароль. Ваш обліковий запис заблоковано через {MAX_ATTEMPTS} невдалих спроб.', 'danger')
            else:
                flash(f'Неправильний пароль. Залишилось спроб: {MAX_ATTEMPTS - user.login_attempts}', 'danger')

            db.session.commit()
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route("/login/google/callback")
def google_login_callback():
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    try:
        resp = google.get("/oauth2/v2/userinfo")
    except Exception as e:
        flash(f"Помилка з'єднання з Google: {e}", "danger")
        return redirect(url_for("login"))

    if not resp.ok:
        flash("Не вдалося отримати дані від Google.", "danger")
        return redirect(url_for("login"))
    
    google_info = resp.json()
    email = google_info.get("email")
    
    if not email:
        flash("Google не надав email.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    
    if user:
        if user.is_locked:
             flash('Ваш обліковий запис заблоковано. Зверніться до адміністратора.', 'danger')
             return redirect(url_for('login'))
             
        session['user_id'] = user.id
        session['user_email'] = user.email
        
        log_attempt = LoginAttempt(email=email, ip_address=request.remote_addr, success=True)
        db.session.add(log_attempt)
        db.session.commit()

        flash(f"Вітаємо, {email}! Ви увійшли через Google.", "success")
        return redirect(url_for('profile'))
    else:
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(secrets.choice(alphabet) for i in range(16))
        password_hash = generate_password_hash(random_password)
        
        new_user = User(email=email, password_hash=password_hash, is_active=True)
        db.session.add(new_user)
        
        log_attempt = LoginAttempt(email=email, ip_address=request.remote_addr, success=True)
        db.session.add(log_attempt)
        
        try:
            db.session.commit()
            session['user_id'] = new_user.id
            session['user_email'] = new_user.email
            flash(f"Обліковий запис створено через Google! Вітаємо, {email}.", "success")
            return redirect(url_for('profile'))
        except IntegrityError:
            db.session.rollback()
            flash('Помилка бази даних при створенні користувача.', 'danger')
            return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            if send_password_reset_email(email):
                flash('Якщо обліковий запис існує, на вашу пошту надіслано інструкції для відновлення пароля. Посилання дійсне 1 годину.', 'info')
            else:
                flash('Виникла помилка при відправці листа. Перевірте налаштування пошти.', 'danger')
        else:
            flash('Якщо обліковий запис існує, на вашу пошту надіслано інструкції для відновлення пароля. Посилання дійсне 1 годину.', 'info')

        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(
            token, 
            salt='password-reset', 
            max_age=PASSWORD_RESET_TOKEN_EXPIRATION
        )
    except:
        flash('Посилання для відновлення пароля недійсне або термін його дії минув.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        
        error_message = validate_password_policy(new_password)
        if error_message:
            flash(error_message, 'error')
            return render_template('reset_password.html', token=token)

        user.password_hash = generate_password_hash(new_password)
        user.is_locked = False
        user.login_attempts = 0
        db.session.commit()
        
        flash('Ваш пароль успішно оновлено! Тепер ви можете увійти.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    email = session.get('2fa_pending_email')
    if not email:
        flash('Помилка авторизації. Спробуйте увійти знову.', 'warning')
        return redirect(url_for('login'))
        
    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        token = request.form.get('token')
        
        if pyotp.TOTP(user.two_factor_secret).verify(token):
            user.login_attempts = 0
            session.pop('2fa_pending_email')
            session['user_id'] = user.id
            session['user_email'] = user.email
            
            log_attempt = LoginAttempt(email=email, ip_address=request.remote_addr, success=True)
            db.session.add(log_attempt)
            db.session.commit()
            
            flash('Вхід з 2FA успішний!', 'success')
            return redirect(url_for('profile'))
        else:
            user.login_attempts += 1
            log_attempt = LoginAttempt(email=email, ip_address=request.remote_addr, success=False)
            db.session.add(log_attempt)
            db.session.commit()
            
            flash('Неправильний код 2FA. Спробуйте ще раз.', 'danger')
            return render_template('verify_2fa.html')
            
    return render_template('verify_2fa.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть для доступу до профілю.', 'warning')
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    return render_template('profile.html', 
        user_email=user.email,
        user_2fa_enabled=user.two_factor_enabled
    ) 

@app.route('/profile/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть для налаштування 2FA.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.two_factor_enabled:
        flash('2FA вже активовано.', 'info')
        return redirect(url_for('profile'))

    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()
    
    otp_uri = pyotp.totp.TOTP(user.two_factor_secret).provisioning_uri(
        name=user.email,
        issuer_name="SecurityAppLab6"
    )
    
    img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    if request.method == 'POST':
        token = request.form.get('token')
        
        if pyotp.TOTP(user.two_factor_secret).verify(token):
            user.two_factor_enabled = True
            db.session.commit()
            flash('Двохфакторна аутентифікація успішно активована!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неправильний код 2FA. Спробуйте ще раз.', 'danger')
            
    return render_template('setup_2fa.html', qr_code_base64=qr_code_base64)

@app.route('/profile/disable_2fa', methods=['POST'])
def disable_2fa():
    if 'user_id' not in session:
        flash('Ви не авторизовані.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.two_factor_enabled:
        flash('2FA не було активовано.', 'info')
        return redirect(url_for('profile'))

    user.two_factor_enabled = False
    user.two_factor_secret = None
    db.session.commit()
    flash('Двохфакторна аутентифікація вимкнена.', 'info')
    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('2fa_pending_email', None)
    flash('Ви вийшли з системи.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/logs')
def admin_logs():
    if 'user_id' not in session:
        flash('У вас немає прав доступу до цієї сторінки.', 'danger')
        return redirect(url_for('login'))
        
    logs = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)