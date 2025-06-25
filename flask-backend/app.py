from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import bcrypt
from uuid import uuid4
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage

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

# ------------------------ Email Sending ------------------------
def send_reset_email(to_email, reset_link):
    EMAIL_ADDRESS = 'kushikabillionaire@gmail.com'
    EMAIL_PASSWORD = 'xsck vmhp kifd ujxw'

    msg = EmailMessage()
    msg['Subject'] = 'Apollo Tyres Password Reset Link'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(f'''
Dear Admin,

Click the link below to reset your password (valid for 15 minutes):
{reset_link}

If you didn’t request this, please ignore this email.

Regards,
Apollo Tyres Security Team
''')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# ------------------------ Landing ------------------------
@app.route('/')
def landing():
    return render_template('landing_page.html')

# ------------------------ Admin Login ------------------------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

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
            cur.execute("INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)",
                        (email, token, expires_at))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found", "error")

        cur.close()
        conn.close()

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data or datetime.now() > token_data[1]:
        flash("Invalid or expired token", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form['new_password']
        hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("UPDATE admins SET password = %s WHERE email = %s", (hashed, token_data[0]))
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password reset successful", "success")
        return redirect(url_for('admin_login'))

    return render_template('reset_password.html')

# ------------------------ Admin Security Update ------------------------
@app.route('/admin_security_update', methods=['POST'])
def admin_security_update():
    if 'admin_email' not in session:
        flash("Unauthorized", "error")
        return redirect(url_for('admin_login'))

    new_passcode = request.form['new_passcode']
    current_pw = request.form['current_password']
    new_pw = request.form['new_password']
    confirm_pw = request.form['confirm_password']
    email = session['admin_email']

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
        flash("Passwords do not match", "error")
        return redirect(url_for('admin_panel'))

    cur.execute("SELECT password FROM admins WHERE email = %s", (email,))
    row = cur.fetchone()

    if not row or not bcrypt.checkpw(current_pw.encode('utf-8'), row[0].encode('utf-8')):
        flash("Incorrect current password", "error")
        return redirect(url_for('admin_panel'))

    new_hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cur.execute("UPDATE admins SET password = %s WHERE email = %s", (new_hashed_pw, email))
    conn.commit()
    flash("Security settings updated", "success")
    return redirect(url_for('admin_panel'))

# ------------------------ User Login (No validation) ------------------------
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        session['pending_user_email'] = request.form['email']
        session['pending_user_password'] = request.form['password']
        return redirect(url_for('user_passcode'))
    return render_template('loginus.html')

# ------------------------ User Passcode ------------------------
@app.route('/user_passcode', methods=['GET', 'POST'])
def user_passcode():
    if 'pending_user_email' not in session:
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        entered = request.form['passcode']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'registration_passcode'")
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row and entered == row[0]:
            session['user_email'] = session.pop('pending_user_email')
            session.pop('pending_user_password', None)
            return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid passcode", "error")

    return render_template('user_passcode.html')

# ------------------------ User Dashboard ------------------------
@app.route('/user_dashboard')
def user_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('user_login'))
    return render_template('user.html')

# ------------------------ Run ------------------------
if __name__ == '__main__':
    app.run(debug=True)
