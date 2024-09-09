from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import requests

app = Flask(__name__)
app.secret_key = '@Proudof55'  # Change this to a random secret key

# Configuring SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuring Flask-Mail for Gmail
sq = 'wnoc ddnj djxy pial'  # Dummy password
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'seyeoyelayo@gmail.com'
app.config['MAIL_PASSWORD'] = sq  # Replace with your Gmail password or App Password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Create a serializer for generating and verifying tokens
s = URLSafeTimedSerializer(app.secret_key)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    company = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_active = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Home route - landing page
@app.route('/')
def home():
    return render_template('index.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirmation = request.form['password_confirmation']
        email = request.form['email']
        company = request.form['company']

        if password != password_confirmation:
            return render_template('index.html', error='Passwords do not match.')

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('index.html', error='Username already exists.')

        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return render_template('index.html', error='Email already exists.')

        new_user = User(username=username, email=email, company=company)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        token = s.dumps(email, salt='email-confirm')
        verification_link = url_for('verify_email', token=token, _external=True)
        msg = Message('Please verify your email', sender='seyeoyelayo@gmail.com', recipients=[email])
        msg.body = f'Click the link to verify your email: {verification_link}'
        mail.send(msg)

        return render_template('index.html', message='Registration successful! Please check your email to verify your account.')
    return render_template('index.html')

# Email verification route
@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # Token valid for 1 hour
    except SignatureExpired:
        return 'The verification link has expired.'
    except BadTimeSignature:
        return 'Invalid verification link.'

    # Activate the user account
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_active = True
        db.session.commit()
        return redirect(url_for('login'))
    return 'User not found.'

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('index.html', error='Username and password are required.')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if user.is_active:
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                return render_template('index.html', error='Account is not activated.')
        else:
            return render_template('index.html', error='Invalid username or password.')
    return render_template('index.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))



# Initialize the database
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
