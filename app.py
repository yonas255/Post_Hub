from flask import Flask, render_template, request, redirect, session, make_response
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
import time

app = Flask(__name__)
app.secret_key = os.environ.get("POSTHUB_SECRET_KEY", "super-secret-fallback")  # secure key via environment variable
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False   # remains False for localhost
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# -----------------------------
# SECURE: Database connection
# -----------------------------
def get_db():
    conn = sqlite3.connect("secure.db")
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# SECURE ROUTES
# -----------------------------

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect("/login")
    return redirect("/posts")


# -----------------------------
# SECURE REGISTRATION
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")

        db = get_db()
        db.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password))
        db.commit()

        return redirect("/login")

    return render_template("register.html")


# -----------------------------
# SECURE LOGIN
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect("/posts")

        return "Invalid credentials", 401

    return render_template("login.html")


# -----------------------------
# SECURE POSTS (AUTO ESCAPED)
# -----------------------------
@app.route("/posts")
def posts():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    posts = db.execute("SELECT * FROM posts").fetchall()

    return render_template("posts.html", posts=posts)


# -----------------------------
# SECURE CREATE POST
# -----------------------------
@app.route("/create", methods=["GET", "POST"])
def create():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]  # auto-escaped by Jinja

        db = get_db()
        db.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))
        db.commit()

        return redirect("/posts")

    return render_template("create_post.html")


# -----------------------------
# SECURE SEARCH (Reflected XSS fixed)
# -----------------------------
@app.route("/search")
def search():
    query = request.args.get("q", "")
    safe_query = query.replace("<", "&lt;").replace(">", "&gt;")
    return f"You searched for: {safe_query}"


# -----------------------------
# SECURE DOM PAGE
# -----------------------------
@app.route("/dom")
def dom():
    return render_template("dom_secure.html")


# -----------------------------
# SECURITY HEADERS (OWASP Recommended)
# -----------------------------
@app.after_request
def apply_security_headers(response):

    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Block dangerous cross-site scripts
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Content Security Policy (VERY IMPORTANT)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"

    # Limit referrer info
    response.headers["Referrer-Policy"] = "no-referrer"

    # Add HSTS (HTTPS only – will be used on real hosting, safe here)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    return response

@app.before_request
def session_timeout():
    session.permanent = True
    now = int(time.time())
    expiry_time = session.get("expiry", now)

    if now > expiry_time:
        session.clear()
        return redirect("/login")

    # Extend session by 5 minutes
    session["expiry"] = now + 300

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(debug=False)  # secure mode
