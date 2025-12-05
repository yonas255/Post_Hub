from flask import Flask, render_template, request, redirect, session, make_response
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import sqlite3
from flask import g
from markupsafe import escape
import os
import time


# DATABASE establishment clean and secure
#creates secure.db with secure tabel and defaults

def init_db():
    db = sqlite3.connect("secure.db")
    cursor = db.cursor()

    # Users table with required credentials
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lockout_until INTEGER DEFAULT 0
)
""")


    #post table for content auto escaping during the output
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    """)

    #log table for auditing important events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.commit()
    db.close()




app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = os.environ.get("POSTHUB_SECRET_KEY", "super-secret-fallback")  # secure key via environment variable
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False   # remains False for localhost
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# secure db connection wth thread safe
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("secure.db", check_same_thread=False, timeout=10)
        g.db.row_factory= sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db= g.pop("db", None)
    if db is not None:
        db.close()
        
# a simple event logger for security auditing
def log_event(event_type, message):
    db = get_db()
    db.execute("INSERT INTO logs (event_type, message) VALUES (?, ?)", (event_type, message))
    db.commit()
    
# generate CSRF Tokens for all forms
@app.context_processor
def csrf_token_context():
    return dict(csrf_token=generate_csrf) # type: ignore


#secure routes for home (requires login)

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect("/login")
    return redirect("/posts")



# secure route for registration which stores hashed password only

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        hashed_password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")

        db = get_db()
        
        try:
            db.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password))
            db.commit()
        except sqlite3.IntegrityError:
            return "Email already registered. Please choose another.", 400

        return redirect("/login")

    return render_template("register.html")


# secure route to Login (brute force protection)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        now = int(time.time())

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        # user doesn't exit in the database
        if not user:
            return render_template("login.html", error_message="Invalid credentials.")

        # the account will be locked temporarily(3 min) after 5 wrong attemts
        if user["lockout_until"] and now < user["lockout_until"]:
            remaining = user["lockout_until"] - now
            return render_template(
                "login.html",
                error_message=f"Account locked. Try again in {remaining} seconds."
            )

        # login successfuland it reset the counter
        if bcrypt.check_password_hash(user["password"], password):
            db.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE id = ?", (user["id"],))
            db.commit()
            session["user_id"] = user["id"]
            return redirect("/posts")

        # Wrong password ---> increase failed attempt count
        new_count = user["failed_attempts"] + 1

        # 3 min account lock down after 5 incorrect inputs
        if new_count >= 5:
            lock_time = now + 180  # 3 minutes
            db.execute(
                "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
                (new_count, lock_time, user["id"])
            )
            db.commit()

            return render_template(
                "login.html",
                error_message="Too many attempts. Your account is locked for 3 minutes."
            )

        
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (new_count, user["id"]))
        db.commit()

        return render_template(
            "login.html",
            error_message=f"Invalid credentials. {new_count}/5 failed attempts."
        )

    return render_template("login.html")




#secure route to post page with jinja autoescaping prevents XSS
@app.route("/posts")
def posts():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    posts = db.execute("SELECT * FROM posts").fetchall()

    return render_template("posts.html", posts=posts)


# Safe route to create page with safe input handling
@app.route("/create", methods=["GET", "POST"])
def create():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]  # auto-escaped by Jinja

        db = get_db()
        db.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))
        log_event("post_created", f"New post created with title: {title}")
        db.commit()

        return redirect("/posts")

    return render_template("create_post.html")


#safe route to search page with reflected xss is fixed
@app.route("/search")
def search():
    print("TEMPLATE FOLDER:", app.template_folder)
    print("WORKING DIR", os.getcwd())
    
    query = request.args.get("q", "")
    safe_query = str(escape(query))
    
    #the log attempted attacks
    if "<" in query or ">" in query or "script" in query.lower():
        log_event("xss_attempt", f"User attempted XSS payload: {query}")
    
    return render_template ("search_result.html", query=safe_query)

#safe route to logout
@app.route("/logout")
def logout():
    log_event("logout", "User logged out")
    session.clear()
    return redirect("/login")


#secure route to DOM page with safe CSP
@app.route("/dom")
def dom():
    response = make_response(render_template("dom_secure.html"))
    response.headers["Content-security-policy"] = ("default-src 'self';" "script-src 'self' 'unsafe-inline'; " "object-src 'none'" )
    return response


#safe route to Global security headers with OWASP
@app.after_request
def apply_security_headers(response):
    path = request.path

    # defult csp for each page
    default_csp = ( "default-src 'self'; " "script-src 'self'; " "object-src 'none'; " "style-src 'self'; " "img-src 'self'; " "base-uri 'self'; " "frame-ancestors 'none'; " "form-action 'self';")

    # Special CSP for /dom page
    dom_csp = ( "default-src 'self'; " "script-src 'self' 'unsafe-inline'; " "object-src 'none'; " "style-src 'self'; " "img-src 'self';" )

    # Apply correct CSP depending on route
    if path == "/dom":
        response.headers["Content-Security-Policy"] = dom_csp
    else:
        response.headers["Content-Security-Policy"] = default_csp

    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Limit referrer info
    response.headers["Referrer-Policy"] = "no-referrer"
    # Add HSTS (HTTPS only – will be used on real hosting, safe here)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    
    return response

# auto logout (session timeout)
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

# RUN APP
if __name__ == "__main__":
    print("creating the DataBase(secure.db)...")
    init_db()
    app.run(debug=False)  # secure mode
