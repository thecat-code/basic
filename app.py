from flask import Flask, request, render_template, redirect, url_for
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random

app = Flask(__name__)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_app_password'     # Replace with your email app password
mail = Mail(app)

# Temporary OTP storage
otp_store = {}

# Initialize the database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['newUsername']
        email = request.form['email']
        password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        if password != confirm_password:
            return "Passwords do not match."

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        otp_store[email] = {
            'otp': otp,
            'username': username,
            'password': password
        }

        # Send OTP via email
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP code is {otp}'
        mail.send(msg)

        return render_template('verify_otp.html', email=email)

    return render_template('Createaccount.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form['email']
    entered_otp = request.form['otp']

    if email in otp_store and otp_store[email]['otp'] == entered_otp:
        data = otp_store.pop(email)
        hashed_password = generate_password_hash(data['password'])

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (data['username'], email, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return 'Username or email already exists.'
    else:
        return "Invalid OTP. Please try again."

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        conn.close()
        if result and check_password_hash(result[0], password):
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password. Please try again.'
    return render_template('login.html', error=error)

@app.route("/home")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0")
