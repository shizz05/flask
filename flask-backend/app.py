from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import bcrypt
from uuid import uuid4
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage
import os
from werkzeug.utils import secure_filename
from flask import jsonify

app = Flask(__name__)
app.secret_key = 'Apollo$ecureTyrePlatform@2025'

# ------------------------ PostgreSQL Connection ------------------------
def get_db_connection():
    return psycopg2.connect(
        dbname='admin',
        user='postgres',
        password='apolloatr',
        host='localhost',
        port='5432'
    )

# ------------------------ Send Reset Email ------------------------
def send_reset_email(to_email, reset_link):
    EMAIL_ADDRESS = 'kushikabillionaire@gmail.com'
    EMAIL_PASSWORD = 'xsck vmhp kifd ujxw'  # App password

    msg = EmailMessage()
    msg['Subject'] = 'Apollo Tyres Password Reset Link'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(f'''
Dear Admin,

We received a password reset request for your Apollo Tyres account.

Click the link below to reset your password (valid for 15 minutes):
{reset_link}

If you didn’t request this, please ignore this email.

Regards,
Apollo Tyres Security Team
''')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# ------------------------ Routes ------------------------

@app.route('/')
def landing():
    return render_template('landing_page.html')

# ------------------------ Admin Login ------------------------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email.endswith('@apollotyres.com'):
            flash("Email must end with @apollotyres.com", "error")
            return render_template('loginad.html')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password FROM admins WHERE email = %s", (email,))
        result = cur.fetchone()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            cur.execute("INSERT INTO login_logs (email, status) VALUES (%s, %s)", (email, 'success'))
            session['admin_email'] = email
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for('admin_panel'))
        else:
            cur.execute("INSERT INTO login_logs (email, status) VALUES (%s, %s)", (email, 'failed'))
            conn.commit()
            cur.close()
            conn.close()
            flash("Invalid credentials", "error")
            return render_template('loginad.html')

    return render_template('loginad.html')

# ------------------------ Admin Panel ------------------------
@app.route('/admin_panel')
def admin_panel():
    if 'admin_email' not in session:
        return redirect(url_for('admin_login'))
    return render_template('admin.html')

# ------------------------ Logout ------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

# ------------------------ Generate Hashed Password ------------------------
@app.route('/generate_hash/<plaintext>')
def generate_hash(plaintext):
    hashed = bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return f"<h4>Hashed password for '{plaintext}':</h4><code>{hashed}</code>"

# ------------------------ Forgot Password ------------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = str(uuid4())
            expires_at = datetime.now() + timedelta(minutes=15)
            cur.execute("INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)", (email, token, expires_at))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found in system", "error")

        cur.close()
        conn.close()

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data:
        flash("Invalid or expired token", "error")
        return redirect(url_for('forgot_password'))

    email, expires_at = token_data
    if datetime.now() > expires_at:
        flash("Token has expired", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("UPDATE admins SET password = %s WHERE email = %s", (hashed_password, email))
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password successfully updated. Please login.", "success")
        cur.close()
        conn.close()
        return redirect(url_for('admin_login'))

    cur.close()
    conn.close()
    return render_template('reset_password.html', token=token)

# ------------------------ Admin: Add Admin ------------------------
@app.route('/add_admin', methods=['POST'])
def add_admin():
    if 'admin_email' not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for('admin_login'))

    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        flash("Email and password are required", "error")
        return redirect(url_for('admin_panel'))

    if not email.endswith('@apollotyres.com'):
        flash("Only Apollo Tyres emails are allowed", "error")
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
    if cur.fetchone():
        flash("Admin already exists", "error")
    else:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("INSERT INTO admins (email, password) VALUES (%s, %s)", (email, hashed_password))
        conn.commit()
        flash("New admin added successfully", "success")

    cur.close()
    conn.close()
    return redirect(url_for('admin_panel'))

# ------------------------ Admin: Update Password & Passcode ------------------------
@app.route('/admin_security_update', methods=['POST'])
def admin_security_update():
    if 'admin_email' not in session:
        flash("Unauthorized", "error")
        return redirect(url_for('admin_login'))

    new_passcode = request.form['new_passcode']
    current_pw = request.form['current_password']
    new_pw = request.form['new_password']
    confirm_pw = request.form['confirm_password']
    admin_email = session['admin_email']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO system_settings (setting_key, setting_value)
        VALUES ('registration_passcode', %s)
        ON CONFLICT (setting_key) DO UPDATE
        SET setting_value = EXCLUDED.setting_value
    """, (new_passcode,))
    conn.commit()

    if new_pw != confirm_pw:
        flash("New passwords do not match", "error")
    else:
        cur.execute("SELECT password FROM admins WHERE email = %s", (admin_email,))
        row = cur.fetchone()
        if not row or not bcrypt.checkpw(current_pw.encode('utf-8'), row[0].encode('utf-8')):
            flash("Incorrect current password", "error")
        else:
            new_hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cur.execute("UPDATE admins SET password = %s WHERE email = %s", (new_hashed_pw, admin_email))
            conn.commit()
            flash("Passcode and password updated successfully", "success")

    cur.close()
    conn.close()
    return redirect(url_for('admin_panel'))

# ------------------------ USER FLOW ------------------------

# Step 1: User enters email & password
@app.route('/user_login', methods=['GET', 'POST'])
def user_entry():
    if request.method == 'POST':
        session['temp_user_email'] = request.form['email']
        session['temp_user_password'] = request.form['password']
        return redirect(url_for('user_passcode'))
    return render_template('loginus.html')

# Step 2: User enters passcode (only first time)
@app.route('/user_passcode', methods=['GET', 'POST'])
def user_passcode():
    if 'temp_user_email' not in session or 'temp_user_password' not in session:
        return redirect(url_for('user_entry'))

    if request.method == 'POST':
        passcode = request.form['passcode']

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'registration_passcode'")
        row = cur.fetchone()

        if not row or row[0] != passcode:
            flash("Invalid passcode", "error")
            return render_template('user_passcode.html')

        email = session['temp_user_email']
        password = session['temp_user_password']

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        if not cur.fetchone():
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_pw))
            flash("User registered successfully.", "success")
        else:
            flash("Welcome back!", "info")

        cur.execute("INSERT INTO login_logs (email, status) VALUES (%s, 'success')", (email,))
        conn.commit()
        cur.close()
        conn.close()

        session['user_email'] = email
        session.pop('temp_user_email', None)
        session.pop('temp_user_password', None)
        return redirect(url_for('user_dashboard'))

    return render_template('user_passcode.html')

# Step 3: User login (direct if already registered)
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE email = %s", (email,))
        row = cur.fetchone()

        if row and bcrypt.checkpw(password.encode('utf-8'), row[0].encode('utf-8')):
            cur.execute("INSERT INTO login_logs (email, status) VALUES (%s, 'success')", (email,))
            conn.commit()
            session['user_email'] = email
            cur.close()
            conn.close()
            return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid login credentials", "error")
            cur.execute("INSERT INTO login_logs (email, status) VALUES (%s, 'failed')", (email,))
            conn.commit()
            cur.close()
            conn.close()

    return render_template('loginus.html')

# Dashboard
@app.route('/user_dashboard')
def user_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('user_login'))
    return render_template('user.html')

    # ------------------------ User Forgot Password ------------------------
@app.route('/user_forgot_password', methods=['GET', 'POST'])
def user_forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = str(uuid4())
            expires_at = datetime.now() + timedelta(minutes=15)
            cur.execute("INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)", (email, token, expires_at))
            conn.commit()
            reset_link = url_for('user_reset_password', token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found in system", "error")

        cur.close()
        conn.close()

    return render_template('user_forgot_password.html')

# ------------------------ User Reset Password ------------------------
@app.route('/user_reset_password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data:
        flash("Invalid or expired token", "error")
        return redirect(url_for('user_forgot_password'))

    email, expires_at = token_data
    if datetime.now() > expires_at:
        flash("Token has expired", "error")
        return redirect(url_for('user_forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password successfully updated. Please login.", "success")
        cur.close()
        conn.close()
        return redirect(url_for('user_login'))

    cur.close()
    conn.close()
    return render_template('user_reset_password.html', token=token)

@app.route('/upload_inc_file', methods=['POST'])
def upload_inc_file():
    if 'admin_email' not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for('admin_login'))

    if 'inc_file' not in request.files:
        flash("No file part", "error")
        return redirect(url_for('admin_panel'))

    file = request.files['inc_file']
    if file.filename == '':
        flash("No selected file", "error")
        return redirect(url_for('admin_panel'))

    if not file.filename.endswith('.inc'):
        flash("Only .inc files are allowed", "error")
        return redirect(url_for('admin_panel'))

    filename = secure_filename(file.filename)
    filepath = os.path.join('uploads', filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(filepath)

    try:
        with open(filepath, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]

        conn = get_db_connection()
        cur = conn.cursor()

        category = ""
        compound_name = ""
        density = ""
        model = ""
        reduced_poly = ""

        i = 0
        while i < len(lines):
            line = lines[i]

            # Capture Category from comment headings
            if line.startswith("**"):
                category = line.replace("*", "").strip()
                i += 1
                continue

            # Start of new compound
            if line.startswith("*MATERIAL") and "NAME=" in line.upper():
                compound_name = line.split("NAME=")[-1].strip()
                density = ""
                model = ""
                reduced_poly = ""

                i += 1
                while i < len(lines):
                    subline = lines[i]

                    if subline.startswith("*MATERIAL"):  # new material starts
                        i -= 1
                        break
                    if subline.startswith("*DENSITY"):
                        i += 1
                        density = lines[i].replace(",", "")
                    elif subline.startswith("*HYPERELASTIC"):
                        model = "HYPERELASTIC"
                        i += 1
                        reduced_poly = lines[i].replace(",", "")
                    i += 1

                # Insert into DB if valid
                if compound_name and density and model and reduced_poly:
                    cur.execute("""
                        INSERT INTO compounds (compound_name, category, density, model, reduced_polynomial)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (compound_name, category, density, model, reduced_poly))

            i += 1

        conn.commit()
        cur.close()
        conn.close()
        flash("File uploaded and compound data saved.", "success")

    except Exception as e:
        flash(f"Failed to process file: {str(e)}", "error")

    return redirect(url_for('admin_panel'))
@app.route('/compound_suggestions')
def compound_suggestions():
    prefix = request.args.get('q', '').lower()  # Match 'q' from frontend JavaScript

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT compound_name
        FROM compounds
        WHERE LOWER(compound_name) LIKE %s
        ORDER BY compound_name
        LIMIT 10
    """, (prefix + '%',))

    suggestions = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()

    return jsonify(suggestions)

@app.route('/compound_density')
def compound_density():
    name = request.args.get('name', '').strip()
    category = request.args.get('category', '').strip()

    print(f"Querying for compound: {name}, category: {category}")  # DEBUG

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT density FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
        LIMIT 1
    """, (name, category))
    row = cur.fetchone()
    cur.close()
    conn.close()

    print("Result:", row)  # DEBUG

    return jsonify({"density": row[0] if row else None})

@app.route('/compound_full_data', methods=['POST'])
def compound_full_data():
    data = request.get_json()
    name = data.get('compound_name')
    category = data.get('category')
    model = data.get('model')
    reduced_poly = data.get('reduced_polynomial')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT compound_name, category, density, model
        FROM compounds
        WHERE compound_name = %s AND category = %s AND model = %s AND reduced_polynomial = %s
        LIMIT 1
    """, (name, category, model, reduced_poly))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        return jsonify({
            "compound_name": row[0],
            "category": row[1],
            "density": row[2],
            "model": row[3]
        })
    else:
        return jsonify({"error": "Compound not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
