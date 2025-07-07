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
import re
import io
from flask import send_file


app = Flask(__name__)
app.secret_key = "Apollo$ecureTyrePlatform@2025"


# ------------------------ PostgreSQL Connection ------------------------
from urllib import parse as urlparse


def get_db_connection():
    urlparse.uses_netloc.append("postgres")
    db_url = urlparse.urlparse(
        os.environ[
            "postgresql://flask_db_xaju_user:XeEDCYtCMifQ0sjvZjiXZO8W3iiBHstI@dpg-d1ljqere5dus73fpktu0-a/flask_db_xaju"
        ]
    )

    return psycopg2.connect(
        dbname=db_url.path[1:],
        user=db_url.username,
        password=db_url.password,
        host=db_url.hostname,
        port=db_url.port,
    )


# ------------------------ Send Reset Email ------------------------
def send_reset_email(to_email, reset_link):
    EMAIL_ADDRESS = "kushikabillionaire@gmail.com"
    EMAIL_PASSWORD = "xsck vmhp kifd ujxw"  # App password

    msg = EmailMessage()
    msg["Subject"] = "Apollo Tyres Password Reset Link"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg.set_content(
        f"""
Dear Admin,

We received a password reset request for your Apollo Tyres account.

Click the link below to reset your password (valid for 15 minutes):
{reset_link}

If you didn’t request this, please ignore this email.

Regards,
Apollo Tyres Security Team
"""
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


# ------------------------ Routes ------------------------


@app.route("/")
def landing():
    return render_template("landing_page.html")


# ------------------------ Admin Login ------------------------
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email.endswith("@apollotyres.com"):
            flash("Email must end with @apollotyres.com", "error")
            return render_template("loginad.html")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password FROM admins WHERE email = %s", (email,))
        result = cur.fetchone()

        if result and bcrypt.checkpw(
            password.encode("utf-8"), result[0].encode("utf-8")
        ):
            cur.execute(
                "INSERT INTO login_logs (email, status) VALUES (%s, %s)",
                (email, "success"),
            )
            session["admin_email"] = email
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("admin_panel"))
        else:
            cur.execute(
                "INSERT INTO login_logs (email, status) VALUES (%s, %s)",
                (email, "failed"),
            )
            conn.commit()
            cur.close()
            conn.close()
            flash("Invalid credentials", "error")
            return render_template("loginad.html")

    return render_template("loginad.html")


# ------------------------ Admin Panel ------------------------
@app.route("/admin_panel")
def admin_panel():
    if "admin_email" not in session:
        return redirect(url_for("admin_login"))
    return render_template("admin.html")


# ------------------------ Logout ------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ------------------------ Generate Hashed Password ------------------------
@app.route("/generate_hash/<plaintext>")
def generate_hash(plaintext):
    hashed = bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    return f"<h4>Hashed password for '{plaintext}':</h4><code>{hashed}</code>"


# ------------------------ Forgot Password ------------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = str(uuid4())
            expires_at = datetime.now() + timedelta(minutes=15)
            cur.execute(
                "INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)",
                (email, token, expires_at),
            )
            conn.commit()
            reset_link = url_for("reset_password", token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found in system", "error")

        cur.close()
        conn.close()

    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data:
        flash("Invalid or expired token", "error")
        return redirect(url_for("forgot_password"))

    email, expires_at = token_data
    if datetime.now() > expires_at:
        flash("Token has expired", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["new_password"]
        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        cur.execute(
            "UPDATE admins SET password = %s WHERE email = %s", (hashed_password, email)
        )
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password successfully updated. Please login.", "success")
        cur.close()
        conn.close()
        return redirect(url_for("admin_login"))

    cur.close()
    conn.close()
    return render_template("reset_password.html", token=token)


# ------------------------ Admin: Add Admin ------------------------
@app.route("/add_admin", methods=["POST"])
def add_admin():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        flash("Email and password are required", "error")
        return redirect(url_for("admin_panel"))

    if not email.endswith("@apollotyres.com"):
        flash("Only Apollo Tyres emails are allowed", "error")
        return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
    if cur.fetchone():
        flash("Admin already exists", "error")
    else:
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        cur.execute(
            "INSERT INTO admins (email, password) VALUES (%s, %s)",
            (email, hashed_password),
        )
        conn.commit()
        flash("New admin added successfully", "success")

    cur.close()
    conn.close()
    return redirect(url_for("admin_panel"))


# ------------------------ Admin: Update Password & Passcode ------------------------
@app.route("/admin_security_update", methods=["POST"])
def admin_security_update():
    if "admin_email" not in session:
        flash("Unauthorized", "error")
        return redirect(url_for("admin_login"))

    new_passcode = request.form["new_passcode"]
    current_pw = request.form["current_password"]
    new_pw = request.form["new_password"]
    confirm_pw = request.form["confirm_password"]
    admin_email = session["admin_email"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO system_settings (setting_key, setting_value)
        VALUES ('registration_passcode', %s)
        ON CONFLICT (setting_key) DO UPDATE
        SET setting_value = EXCLUDED.setting_value
    """,
        (new_passcode,),
    )
    conn.commit()

    if new_pw != confirm_pw:
        flash("New passwords do not match", "error")
    else:
        cur.execute("SELECT password FROM admins WHERE email = %s", (admin_email,))
        row = cur.fetchone()
        if not row or not bcrypt.checkpw(
            current_pw.encode("utf-8"), row[0].encode("utf-8")
        ):
            flash("Incorrect current password", "error")
        else:
            new_hashed_pw = bcrypt.hashpw(
                new_pw.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            cur.execute(
                "UPDATE admins SET password = %s WHERE email = %s",
                (new_hashed_pw, admin_email),
            )
            conn.commit()
            flash("Passcode and password updated successfully", "success")

    cur.close()
    conn.close()
    return redirect(url_for("admin_panel"))


# ------------------------ USER FLOW ------------------------


# Step 1: User enters email & password
@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE email = %s", (email,))
        row = cur.fetchone()

        if row:
            # Existing user: check password
            if bcrypt.checkpw(password.encode("utf-8"), row[0].encode("utf-8")):
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, 'success')",
                    (email,),
                )
                conn.commit()
                session["user_email"] = email
                cur.close()
                conn.close()
                return redirect(url_for("user_dashboard"))
            else:
                flash("Incorrect password", "error")
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, 'failed')",
                    (email,),
                )
                conn.commit()
                cur.close()
                conn.close()
                return redirect(url_for("user_login"))
        else:
            # New user: store temp and ask passcode
            session["temp_user_email"] = email
            session["temp_user_password"] = password
            cur.close()
            conn.close()
            return redirect(url_for("user_passcode"))

    return render_template("loginus.html")


# Step 2: User enters passcode (only shown for new users)
@app.route("/user_passcode", methods=["GET", "POST"])
def user_passcode():
    if "temp_user_email" not in session or "temp_user_password" not in session:
        return redirect(url_for("user_login"))

    if request.method == "POST":
        passcode = request.form["passcode"].strip()

        conn = get_db_connection()
        cur = conn.cursor()

        # Get the registration passcode from settings
        cur.execute(
            "SELECT setting_value FROM system_settings WHERE setting_key = 'registration_passcode'"
        )
        row = cur.fetchone()

        if not row or row[0] != passcode:
            flash("Invalid passcode", "error")
            return render_template("user_passcode.html")

        email = session["temp_user_email"]
        password = session["temp_user_password"]

        # Check again (safety): if user was somehow registered meanwhile
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if not existing_user:
            # Register user
            hashed_pw = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            cur.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_pw),
            )
            flash("User registered successfully.", "success")
        else:
            flash("User already registered. Logging you in...", "info")

        # Log login
        cur.execute(
            "INSERT INTO login_logs (email, status) VALUES (%s, 'success')",
            (email,),
        )

        conn.commit()
        cur.close()
        conn.close()

        session["user_email"] = email
        session.pop("temp_user_email", None)
        session.pop("temp_user_password", None)
        return redirect(url_for("user_dashboard"))

    return render_template("user_passcode.html")


# Dashboard
@app.route("/user_dashboard")
def user_dashboard():
    if "user_email" not in session:
        return redirect(url_for("user_login"))
    return render_template("user.html")

    # ------------------------ User Forgot Password ------------------------


@app.route("/user_forgot_password", methods=["GET", "POST"])
def user_forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = str(uuid4())
            expires_at = datetime.now() + timedelta(minutes=15)
            cur.execute(
                "INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)",
                (email, token, expires_at),
            )
            conn.commit()
            reset_link = url_for("user_reset_password", token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found in system", "error")

        cur.close()
        conn.close()

    return render_template("user_forgot_password.html")


# ------------------------ User Reset Password ------------------------
@app.route("/user_reset_password/<token>", methods=["GET", "POST"])
def user_reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data:
        flash("Invalid or expired token", "error")
        return redirect(url_for("user_forgot_password"))

    email, expires_at = token_data
    if datetime.now() > expires_at:
        flash("Token has expired", "error")
        return redirect(url_for("user_forgot_password"))

    if request.method == "POST":
        new_password = request.form["new_password"]
        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        cur.execute(
            "UPDATE users SET password = %s WHERE email = %s", (hashed_password, email)
        )
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password successfully updated. Please login.", "success")
        cur.close()
        conn.close()
        return redirect(url_for("user_login"))

    cur.close()
    conn.close()
    return render_template("user_reset_password.html", token=token)


@app.route("/upload_inc_file", methods=["POST"])
def upload_inc_file():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    file = request.files.get("inc_file")
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("admin_panel"))

    if not file.filename.endswith(".inc"):
        flash("Only .inc files allowed.", "error")
        return redirect(url_for("admin_panel"))

    filename = secure_filename(file.filename)
    filepath = os.path.join("uploads", filename)
    os.makedirs("uploads", exist_ok=True)

    file.save(filepath)

    # ✅ PRE-DECLARE all variables inside the function
    conn = None
    cur = None
    errors = []
    success_count = 0
    compound_name = ""
    category = ""
    model = ""

    try:
        with open(filepath, "r") as f:
            lines = [line.rstrip() for line in f if line.strip()]

        if not lines:
            flash("Uploaded file is empty or invalid.", "error")
            return redirect(url_for("admin_panel"))

        # Continue parsing and DB logic here...
        # Make sure to use cur.execute() and conn.commit() only while conn is open

    except Exception as e:
        print("❌ Upload error:", e)
        errors.append(f"General error: {str(e)}")
        flash(f"❌ Internal DB error after processing file: {str(e)}", "error")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    if errors:
        for err in errors:
            flash(err, "error")
        flash(
            f"⚠️ {len(errors)} error(s) found. {success_count} compound(s) inserted.",
            "error",
        )
    else:
        flash(
            f"✅ File uploaded successfully. {success_count} compounds inserted.",
            "success",
        )
        # Log the upload in audit logs
        log_audit("UPLOAD", session.get("admin_email"), None, None, None, filename)

    return redirect(url_for("admin_panel"))


@app.route("/compound_suggestions")
def compound_suggestions():
    prefix = request.args.get("q", "").lower()  # Match 'q' from frontend JavaScript

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT compound_name
        FROM compounds
        WHERE LOWER(compound_name) LIKE %s
        ORDER BY compound_name
        LIMIT 10
    """,
        (prefix + "%",),
    )

    suggestions = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()

    return jsonify(suggestions)


@app.route("/compound_density")
def compound_density():
    name = request.args.get("name", "").strip()
    category = request.args.get("category", "").strip()

    print(f"Querying for compound: {name}, category: {category}")  # DEBUG

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT density FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
        LIMIT 1
    """,
        (name, category),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    print("Result:", row)  # DEBUG

    return jsonify({"density": row[0] if row else None})


@app.route("/compound_full_data", methods=["POST"])
def get_compound_full_data():
    print("✅ /compound_full_data route is active")
    data = request.get_json()
    name = data.get("compound_name")
    category = data.get("category")
    model = data.get("model", "").upper()
    selected_n = data.get("n")

    try:
        selected_n = int(selected_n)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid N value"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT compound_name, category, density, model, reduced_polynomial
        FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
          AND LOWER(model) = LOWER(%s)
        LIMIT 1
        """,
        (name, category, model),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        reduced = row[4]
        coeffs = [x.strip() for x in reduced.split(",") if x.strip()]
        expected_coeffs = selected_n * 2

    if model == "HYPERELASTIC" or model == "VISCOELASTIC":
        if len(coeffs) == expected_coeffs:
            return jsonify(
                {
                    "compound_name": row[0],
                    "category": row[1],
                    "density": row[2],
                    "model": row[3],
                    "reduced_polynomial": row[4],
                }
            )
        else:
            return (
                jsonify({"error": f"Reduced polynomial for N={selected_n} not found."}),
                404,
            )
    else:
        # For other models (future), just return without N-check
        return jsonify(
            {
                "compound_name": row[0],
                "category": row[1],
                "density": row[2],
                "model": row[3],
                "reduced_polynomial": row[4],
            }
        )


import matplotlib.pyplot as plt
import io
import base64


# Function to generate a graph image for Reduced Polynomial data
def generate_reduced_polynomial_graph(coefficients):
    """
    coefficients: list of floats (length 2N, eg: C10, C20..., D1, D2...)
    Returns: base64 image string
    """
    N = len(coefficients) // 2
    C = coefficients[:N]
    D = coefficients[N:]

    strain = [i * 0.1 for i in range(21)]  # 0 to 2 in 0.1 steps
    stress = []

    for e in strain:
        W = 0
        for i in range(N):
            W += C[i] * (e ** (2 * (i + 1)))
        for j in range(N):
            W += D[j] * e
        stress.append(W)

    # Plotting
    fig, ax = plt.subplots()
    ax.plot(strain, stress, label="Reduced Polynomial Fit", marker="o", color="cyan")
    ax.set_title("Reduced Polynomial Graph")
    ax.set_xlabel("Strain")
    ax.set_ylabel("Stress")
    ax.grid(True)
    ax.legend()

    # Save plot to base64
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight", facecolor="black")
    plt.close(fig)
    buf.seek(0)
    graph_url = base64.b64encode(buf.read()).decode("utf-8")
    return f"data:image/png;base64,{graph_url}"


# Example usage
coeffs = [0.7, -0.1, 0.04, 0.03, 0, 0]  # Sample Reduced Polynomial (N=3)
graph_image_url = generate_reduced_polynomial_graph(coeffs)


# You can now embed `graph_image_url` in an <img src="..."> tag in your Flask template
@app.route("/generate_graph")
def generate_graph():
    import matplotlib.pyplot as plt
    import io
    from flask import send_file, request

    name = request.args.get("name")
    category = request.args.get("category")
    model = request.args.get("model")
    reduced_poly = request.args.get("reduced_poly")

    try:
        points = [float(p.strip()) for p in reduced_poly.split(",")]
        x = list(range(1, len(points) + 1))
        y = points

        fig, ax = plt.subplots()
        ax.plot(x, y, marker="o")
        ax.set_title(f"{name} - {category} - {model}")
        ax.set_xlabel("Coefficient Index")
        ax.set_ylabel("Value")
        ax.grid(True)

        buf = io.BytesIO()
        plt.savefig(buf, format="png")
        buf.seek(0)
        plt.close(fig)

        return send_file(buf, mimetype="image/png")
    except Exception as e:
        return f"Error generating graph: {e}", 500


@app.route("/delete_compound", methods=["POST"])
def delete_compound():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    delete_type = request.form.get("delete_type")  # compound or file

    if delete_type == "file":
        filename = request.form.get("file_name", "").strip()

        if not filename or not filename.endswith(".inc"):
            flash("❌ Invalid file name. Only .inc files allowed.", "error")
            return redirect(url_for("admin_panel"))

        filepath = os.path.join("uploads", secure_filename(filename))

        # Always open DB connection regardless of file presence, to delete related compounds
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Delete all compounds from this file
            cur.execute(
                """
                DELETE FROM compounds WHERE source_file = %s
                """,
                (filename,),
            )

            # Remove file from disk (only if it exists)
            if os.path.exists(filepath):
                os.remove(filepath)
                flash(
                    f"✅ File '{filename}' and associated data deleted successfully.",
                    "success",
                )
            else:
                flash(
                    f"⚠️ File '{filename}' not found in uploads folder. Associated data removed from DB.",
                    "warning",
                )

            # Log the deletion in audit_logs
            log_audit(
                "DELETE_FILE", session.get("admin_email"), None, None, None, filename
            )

            conn.commit()

        except Exception as e:
            print("❌ Delete file error:", e)
            flash(f"❌ Error deleting file or compounds: {str(e)}", "error")

        finally:
            cur.close()
            conn.close()

    elif delete_type == "compound":
        compound_name = request.form.get("compound_name", "").strip()
        category = request.form.get("category", "").strip()

        if not compound_name or not category:
            flash("❌ Compound name and category are required.", "error")
            return redirect(url_for("admin_panel"))

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Fetch model for audit
            cur.execute(
                """
                SELECT model FROM compounds
                WHERE compound_name = %s AND category = %s
                """,
                (compound_name, category),
            )
            row = cur.fetchone()
            model = row[0] if row else None

            # Delete compound
            cur.execute(
                """
                DELETE FROM compounds
                WHERE compound_name = %s AND category = %s
                """,
                (compound_name, category),
            )

            # Log compound deletion
            if row:
                cur.execute(
                    """
                    INSERT INTO audit_logs (actor_email, action_type, compound_name, category, model)
                    VALUES (%s, 'DELETE', %s, %s, %s)
                    """,
                    (session.get("admin_email"), compound_name, category, model),
                )

            conn.commit()
            flash("✅ Compound deleted successfully.", "success")

        except Exception as e:
            print("❌ Delete error:", e)
            flash("❌ Error deleting compound.", "error")
        finally:
            cur.close()
            conn.close()

    else:
        flash("❌ Invalid delete type selected.", "error")

    return redirect(url_for("admin_panel"))


@app.route("/update_compound", methods=["POST"])
def update_compound():
    conn = None
    cur = None
    try:
        compound_name = request.form["compound_name"].strip()
        category = request.form["category"].strip()
        density = request.form["density"].strip()
        model = request.form["model"].strip().upper()
        reduced_poly = request.form["reduced_polynomial"].strip()
        # === Validation Starts ===

        # 1. Validate compound name: alphanumeric + underscore
        if not re.match(r"^[A-Za-z0-9_-]+$", compound_name):
            flash(
                "❌ Invalid compound name. Use only letters, digits, or underscores.",
                "error",
            )
            return redirect(url_for("admin_panel"))

        # 2. Validate density (scientific notation)
        if not re.match(r"^\d+(\.\d+)?[eE][-+]?\d+$", density):
            flash(
                "❌ Invalid density format. Use scientific notation like 1.178E-09.",
                "error",
            )
            return redirect(url_for("admin_panel"))

        # 3. Validate model
        if model not in ["HYPERELASTIC", "VISCOELASTIC"]:
            flash(
                "❌ Unsupported model. Choose either 'Hyperelastic' or 'Viscoelastic'.",
                "error",
            )
            return redirect(url_for("admin_panel"))

        # 4. Validate reduced polynomial by N
        coeffs = [c.strip() for c in reduced_poly.split(",")]
        if model == "HYPERELASTIC":
            if len(coeffs) not in [2, 4, 6]:
                flash(
                    "❌ Hyperelastic requires 2 (N=1), 4 (N=2), or 6 (N=3) coefficients.",
                    "error",
                )
                return redirect(url_for("admin_panel"))
        elif model == "VISCOELASTIC":
            if len(coeffs) < 1:
                flash(
                    "❌ Viscoelastic model requires at least one coefficient.",
                    "error",
                )
                return redirect(url_for("admin_panel"))

        # Validate all coefficients are numeric
        for coef in coeffs:
            if not re.match(r"^-?\d+(\.\d+)?$", coef):
                flash(f"❌ Invalid coefficient value: {coef}", "error")
                return redirect(url_for("admin_panel"))

        # === DB Insert or Update ===
        conn = get_db_connection()
        print("✅ Connected to:", conn.dsn)  # Debugging output
        cur = conn.cursor()
        filename = "MANUAL_UPDATE"
        cur.execute(
            """
        INSERT INTO compounds (compound_name, category, density, model, reduced_polynomial, source_file)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (compound_name, category, model)
        DO UPDATE SET 
        density = EXCLUDED.density,
        reduced_polynomial = EXCLUDED.reduced_polynomial,
        source_file = EXCLUDED.source_file
        """,
            (compound_name, category, density, model, reduced_poly, filename),
        )

        # Log only if it was an update

        cur.execute(
            """
                INSERT INTO audit_logs (actor_email, action_type, compound_name, category, model)
                VALUES (%s, 'UPDATE', %s, %s, %s)
                """,
            (session.get("admin_email"), compound_name, category, model),
        )

        conn.commit()
        flash("✅ Compound updated successfully.", "success")

    except Exception as e:
        print("❌ Update error:", e)
        flash("❌ Error updating compound: " + str(e), "error")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return redirect(url_for("admin_panel"))


@app.route("/remove_user_or_admins", methods=["POST"])
def remove_user_or_admins():
    role = request.form["role"]
    email = request.form["email"]

    conn = get_db_connection()
    cur = conn.cursor()

    if role == "admins":
        cur.execute("DELETE FROM admins WHERE email = %s", (email,))
    elif role == "user":
        cur.execute("DELETE FROM users WHERE email = %s", (email,))

    conn.commit()
    cur.close()
    conn.close()

    flash(f"{role.capitalize()} with email {email} removed successfully.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/routes")
def list_routes():
    import urllib

    output = []
    for rule in app.url_map.iter_rules():
        methods = ",".join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint}: {methods} {rule}")
        output.append(line)
    return "<br>".join(sorted(output))


@app.route("/export_compound", methods=["POST"])
def export_compound():
    data = request.get_json()
    name = data.get("compound_name")
    density = data.get("density")
    model = data.get("model").upper()
    reduced = data.get("reduced_polynomial")

    lines = []
    lines.append(f"*MATERIAL, NAME={name}")
    lines.append("*DENSITY")
    lines.append(f"{density},")

    if model == "HYPERELASTIC":
        coeffs = reduced.split(",")
        N = len(coeffs) // 2
        lines.append(f"*HYPERELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
        lines.append(f"{reduced}")
        lines.append("*" * 84)
    elif model == "VISCOELASTIC":
        lines.append("*VISCOELASTIC")
        lines.append(f"{reduced}")
    else:
        return jsonify({"error": "Unsupported model for export"}), 400

    # Add footer separator
    lines.append("*" * 84)

    inc_data = "\n".join(lines)

    buffer = io.BytesIO()
    buffer.write(inc_data.encode())
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name="compound_export.inc",
        mimetype="text/plain",
    )


@app.route("/export_multiple_compounds", methods=["POST"])
def export_multiple_compounds():
    print("✅ Exporting multiple compounds")
    data = request.get_json()
    compounds = data.get("compounds", [])

    if not compounds:
        return jsonify({"error": "No compounds provided"}), 400

    lines = []
    conn = get_db_connection()
    cur = conn.cursor()

    for item in compounds:
        name = item.get("compound_name")
        category = item.get("category")
        model = item.get("model").upper()

        if not name or not category or not model:
            continue

        cur.execute(
            """
            SELECT density, reduced_polynomial FROM compounds
            WHERE compound_name = %s AND category = %s AND model = %s
            """,
            (name, category, model),
        )
        row = cur.fetchone()

        if row:
            density, reduced = row
            lines.append(f"*MATERIAL, NAME={name}")
            lines.append("*DENSITY")
            lines.append(f"{density},")
            if model.upper() == "HYPERELASTIC":
                coeffs = reduced.split(",")
                N = len(coeffs) // 2
                lines.append(f"*HYPERELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(reduced)
                lines.append("*" * 84)
            elif model.upper() == "VISCOELASTIC":
                coeffs = [c.strip() for c in reduced.split(",") if c.strip()]
                N = len(coeffs) // 2
                lines.append(f"*VISCOELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(",".join(coeffs))
                lines.append("*" * 84)
    cur.close()
    conn.close()

    if not lines:
        return jsonify({"error": "No valid compound data found"}), 400

    inc_data = "\n".join(lines)
    buffer = io.BytesIO()
    buffer.write(inc_data.encode())
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="multiple_compounds.inc",
        mimetype="text/plain",
    )


@app.route("/user_panel")
def user_panel():
    return render_template("user.html")


@app.route("/user_compound_full_data", methods=["POST"])
def user_compound_full_data():
    print("✅ /user_compound_full_data triggered")
    data = request.get_json()
    name = data.get("compound_name")
    category = data.get("category")
    model = data.get("model", "").upper()
    selected_n = data.get("n")

    try:
        selected_n = int(selected_n)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid N value"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT compound_name, category, density, model, reduced_polynomial
        FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
          AND LOWER(model) = LOWER(%s)
        """,
        (name, category, model),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        reduced = row[4]
        coeffs = [x.strip() for x in reduced.split(",") if x.strip()]
        expected_coeffs = selected_n * 2
        if len(coeffs) == expected_coeffs:
            return jsonify(
                {
                    "compound_name": row[0],
                    "category": row[1],
                    "density": row[2],
                    "model": row[3],
                    "reduced_polynomial": row[4],
                }
            )
        else:
            return (
                jsonify(
                    {
                        "error": "Reduced polynomial data for N={} not found.".format(
                            selected_n
                        )
                    }
                ),
                404,
            )

    return jsonify({"error": "Compound not found"}), 404


@app.route("/user_export_multiple_compounds", methods=["POST"])
def user_export_multiple_compounds():
    print("✅ Exporting user-selected compounds")
    data = request.get_json()
    compounds = data.get("compounds", [])

    if not compounds:
        return jsonify({"error": "No compounds provided"}), 400

    lines = []
    conn = get_db_connection()
    cur = conn.cursor()

    for item in compounds:
        name = item.get("compound_name")
        category = item.get("category")
        model = item.get("model", "").upper()

        if not name or not category or not model:
            continue

        cur.execute(
            """
            SELECT density, reduced_polynomial FROM compounds
            WHERE LOWER(compound_name) = LOWER(%s)
              AND LOWER(category) = LOWER(%s)
              AND LOWER(model) = LOWER(%s)
            """,
            (name, category, model),
        )
        row = cur.fetchone()

        if row:
            density, reduced = row
            lines.append(f"*MATERIAL, NAME={name}")
            lines.append("*DENSITY")
            lines.append(f"{density},")
            if model == "HYPERELASTIC":
                coeffs = reduced.split(",")
                N = len(coeffs) // 2
                lines.append(f"*HYPERELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(reduced)
            elif model == "VISCOELASTIC":
                coeffs = [c.strip() for c in reduced.split(",") if c.strip()]
                N = len(coeffs) // 2
                lines.append(f"*VISCOELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(",".join(coeffs))
            lines.append("*" * 84)

    cur.close()
    conn.close()

    if not lines:
        return jsonify({"error": "No valid compound data found"}), 400

    inc_data = "\n".join(lines)
    buffer = io.BytesIO()
    buffer.write(inc_data.encode())
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="user_compounds.inc",
        mimetype="text/plain",
    )


def log_audit(
    action_type, actor_email, compound_name, category=None, model=None, file_name=None
):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if action_type in ["UPLOAD", "DELETE_FILE"]:
            cur.execute(
                """
                INSERT INTO audit_logs (actor_email, action_type, file_name, timestamp)
                VALUES (%s, %s, %s, NOW())
                """,
                (actor_email, action_type, file_name),
            )
        elif action_type in ["UPDATE", "DELETE"]:
            cur.execute(
                """
                INSERT INTO audit_logs (actor_email, action_type, compound_name, category, model, file_name, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """,
                (actor_email, action_type, compound_name, category, model, file_name),
            )
        conn.commit()
    except Exception as e:
        print("❌ Audit log error:", e)
    finally:
        cur.close()
        conn.close()


@app.route("/view_table/<table>")
def view_table(table):
    allowed_tables = [
        "compounds",
        "audit_logs",
        "login_logs",
        "admins",
        "users",
        "reset_tokens",
        "system_settings",
    ]

    # ✅ Validate table name
    if table not in allowed_tables:
        flash("❌ Invalid table requested.", "error")
        return redirect(url_for("admin_panel"))

    try:
        # ✅ Connect to DB
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch all rows and column names
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
        colnames = [desc[0] for desc in cur.description]

        cur.close()
        conn.close()

        # ✅ Render view_table.html
        return render_template(
            "view_table.html", table_name=table, columns=colnames, rows=rows
        )

    except Exception as e:
        flash(f"❌ Error fetching data from {table}: {str(e)}", "error")
        return redirect(url_for("admin_panel"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
