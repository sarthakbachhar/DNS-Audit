# Handles login, user creation, session management, and access control.
# DB credentials are hardcoded here so there's only one place to change them.

import os
import logging
from functools import wraps

import mysql.connector
import mysql.connector.errors
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, session,
)

logger = logging.getLogger(__name__)

# Database connection details — read from environment variables so Docker/docker-compose
# can inject the correct host. Falls back to the original hardcoded values for local dev.
DB_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "localhost"),
    "port":     int(os.environ.get("DB_PORT", 3306)),
    "user":     os.environ.get("DB_USER",     "root"),
    "password": os.environ.get("DB_PASSWORD", "mysql@toor"),
    "database": os.environ.get("DB_NAME",     "iso_audit"),
}

auth_bp = Blueprint('auth', __name__)


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


def init_db():
    # Connect without specifying a database first so we can create it if it doesn't exist
    cfg = {k: v for k, v in DB_CONFIG.items() if k != "database"}
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    # Now connect to the database and create the tables we need
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INT          AUTO_INCREMENT PRIMARY KEY,
                username      VARCHAR(80)  UNIQUE NOT NULL,
                email         VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role          ENUM('admin','user') NOT NULL DEFAULT 'user',
                created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
                is_active     BOOLEAN      DEFAULT TRUE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id           INT          AUTO_INCREMENT PRIMARY KEY,
                audit_id     VARCHAR(60)  UNIQUE NOT NULL,
                host         VARCHAR(255) NOT NULL,
                ad_username  VARCHAR(255),
                status       VARCHAR(20)  DEFAULT 'in_progress',
                results_json LONGTEXT,
                created_at   TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
                created_by   INT,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS playbook_settings (
                control_id  VARCHAR(20) PRIMARY KEY,
                enabled     BOOLEAN     NOT NULL DEFAULT TRUE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id           INT          AUTO_INCREMENT PRIMARY KEY,
                action       VARCHAR(100) NOT NULL,
                performed_by VARCHAR(80),
                details      TEXT,
                created_at   TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        conn.commit()
        logger.info("Database schema ready.")
    finally:
        cursor.close()
        conn.close()


# --- User management ---

def create_user(username: str, email: str, password: str,
                role: str = "user") -> dict | None:
    # Hash the password before storing — never save plaintext
    password_hash = generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) "
            "VALUES (%s, %s, %s, %s)",
            (username, email, password_hash, role),
        )
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cursor.fetchone()
    except mysql.connector.errors.IntegrityError:
        # Username or email already taken
        return None
    finally:
        cursor.close()
        conn.close()


def validate_login(username: str, password: str) -> dict | None:
    # Look up the user and verify the password hash
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, username, password_hash, role, is_active "
            "FROM users WHERE username = %s",
            (username,),
        )
        user = cursor.fetchone()
        if user and check_password_hash(user["password_hash"], password):
            return user
        return None
    finally:
        cursor.close()
        conn.close()


def user_count() -> int:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        row = cursor.fetchone()
        return row[0] if row else 0
    finally:
        cursor.close()
        conn.close()


def get_user_by_id(user_id: int) -> dict | None:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def get_all_users() -> list:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, username, email, role, is_active, created_at "
            "FROM users ORDER BY created_at ASC"
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def delete_user(user_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


# --- Activity logging ---

def log_activity(action: str, performed_by: str = None, details: str = '') -> None:
    # Silently swallow errors so logging never breaks the main flow
    try:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO activity_logs (action, performed_by, details) "
                "VALUES (%s, %s, %s)",
                (action, performed_by, details or ''),
            )
            conn.commit()
        finally:
            cursor.close()
            conn.close()
    except Exception:
        pass


def get_all_logs(limit: int = 500) -> list:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, action, performed_by, details, created_at "
            "FROM activity_logs ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def clear_logs() -> None:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM activity_logs")
        conn.commit()
    finally:
        cursor.close()
        conn.close()


# --- Access control decorators ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("auth.login"))
        if session.get("role") != "admin":
            flash("Administrator access is required for this action.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def inject_current_user():
    # Makes the logged-in user available as `current_user` in every template
    if "user" in session:
        return {
            "current_user": {
                "id":       session.get("user_id"),
                "username": session.get("user"),
                "role":     session.get("role", "user"),
                "is_admin": session.get("role") == "admin",
            }
        }
    return {"current_user": None}


# --- Routes ---

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("index"))

    active_tab = "login"

    if request.method == "POST":
        action = request.form.get("action", "login")

        if action == "login":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if not username or not password:
                flash("Username and password are required.", "error")
                return render_template("login.html", active_tab="login")

            user = validate_login(username, password)

            if user is None:
                log_activity("Login Failed", username, f"Bad credentials from {request.remote_addr}")
                flash("Invalid username or password.", "error")
                return render_template("login.html", active_tab="login")

            if not bool(user.get("is_active", 1)):
                flash("Your account is disabled. Contact an administrator.", "error")
                return render_template("login.html", active_tab="login")

            session.permanent = True
            session["user"]    = user["username"]
            session["role"]    = user["role"]
            session["user_id"] = user["id"]

            log_activity("Login", user["username"], f"Signed in from {request.remote_addr}")
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("index"))

        elif action == "register":
            active_tab = "register"

            username = request.form.get("reg_username", "").strip()
            email    = request.form.get("reg_email",    "").strip()
            password = request.form.get("reg_password", "").strip()
            confirm  = request.form.get("reg_confirm",  "").strip()
            role     = request.form.get("reg_role",     "user").strip()

            if not all([username, email, password, confirm]):
                flash("All fields are required.", "error")
                return render_template("login.html", active_tab=active_tab)

            if len(username) < 3:
                flash("Username must be at least 3 characters.", "error")
                return render_template("login.html", active_tab=active_tab)

            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return render_template("login.html", active_tab=active_tab)

            if password != confirm:
                flash("Passwords do not match.", "error")
                return render_template("login.html", active_tab=active_tab)

            if role not in ("admin", "user"):
                role = "user"

            # The very first account registered gets admin regardless of what was selected
            first_user = user_count() == 0
            if first_user:
                role = "admin"

            new_user = create_user(username, email, password, role)
            if new_user is None:
                flash("Username or email is already taken.", "error")
                return render_template("login.html", active_tab=active_tab)

            role_label = "Admin" if role == "admin" else "User"
            log_activity("User Registered", username, f"New account created with role: {role_label}")

            if first_user:
                flash(
                    f"Account '{username}' created as Admin "
                    "(first account is always administrator). You can now sign in.",
                    "success",
                )
            else:
                flash(
                    f"Account '{username}' created with {role_label} role. "
                    "You can now sign in.",
                    "success",
                )
            return render_template("login.html", active_tab="login")

    return render_template("login.html", active_tab="login")


@auth_bp.route("/logout")
def logout():
    username = session.get("user", "User")
    log_activity("Logout", username, "User signed out")
    session.clear()
    flash(f"You have been signed out, {username}.", "info")
    return redirect(url_for("auth.login"))
