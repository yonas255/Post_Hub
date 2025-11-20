import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session, g
from datetime import datetime

app = Flask(__name__)
app.secret_key = "SUPER_INSECURE_SECRET"  # hard-coded, bad on purpose


DATABASE = "posthub_insecure.db"


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    # users table - password stored as PLAINTEXT (insecure)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        """
    )
    # posts table - content not sanitized (stored XSS)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("posts"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")  # plain text (insecure)

        if not username or not email or not password:
            error = "All fields are required."
        else:
            # INSECURE: string concatenation, allows SQL injection
            query = (
                "INSERT INTO users (username, email, password) "
                f"VALUES ('{username}', '{email}', '{password}')"
            )
            try:
                db.execute(query)
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Email already registered."

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    error = None

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # INSECURE: vulnerable to SQL injection
        query = (
            "SELECT * FROM users WHERE email = '"
            + email
            + "' AND password = '"
            + password
            + "'"
        )
        user = db.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("posts"))
        else:
            error = "Invalid email or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/posts")
def posts():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    posts = db.execute(
        """
        SELECT posts.id, posts.content, posts.created_at, users.username
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
        """
    ).fetchall()

    # content is rendered raw in the template (stored XSS)
    return render_template("posts.html", posts=posts)


@app.route("/create", methods=["GET", "POST"])
def create_post():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    error = None

    if request.method == "POST":
        content = request.form.get("content")

        if not content:
            error = "Content cannot be empty."
        else:
            # No sanitization (stored XSS)
            db.execute(
                """
                INSERT INTO posts (user_id, content, created_at)
                VALUES (?, ?, ?)
                """,
                (session["user_id"], content, datetime.utcnow().isoformat()),
            )
            db.commit()
            return redirect(url_for("posts"))

    return render_template("create_post.html", error=error)

@app.route("/search")
def search():
    query = request.args.get("q", "")

    # INSECURE: reflects user input directly (Reflected XSS)
    return f"You searched for: {query}"

@app.route("/dom")
def dom_xss():
    return render_template("dom_xss.html")


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)  # debug=True is also insecure
