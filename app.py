from flask import Flask, render_template, request, session, redirect
from flask_session import Session
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

from utils import login_required, error

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
Session(app)

connection = sqlite3.connect('projects.db')
cursor = connection.cursor()

cursor.execute("create TABLE users IF NOT EXISTS (id INTEGER NOT NULL, name TEXT NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, hash TEXT NOT NULL, position TEXT NOT NULL, team TEXT, PRIMARY KEY (id))")
cursor.execute("create TABLE teams IF NOT EXISTS (id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE, FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE ON UPDATE CASCADE")
cursor.execute("create TABLE projects IF NOT EXISTS (id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL, FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE ON UPDATE CASCADE")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    # TODO
    return render_template('index.html')


@app.route("/login", method=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # If method = POST
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return error("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return error("must provide password", 403)

        # Query database for username
        res = cursor.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        rows = res.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return error("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Clear session
    session.clear()

    # Check if method is post
    if request.method == "POST":
        # Name, username, email, password, position are required
        if request.form.get("name") == '' or request.form.get("username") == '' or request.form.get("password") == '' or request.form.get("position") == '':
            return error('All the fields are required', 403)

        # Check if user exist
        res = cursor.execute('SELECT username FROM users')
        usernames = res.fetchall()
        for username in usernames:
            if request.form.get('username') == username["username"]:
                return error('User already exists', 403)

        # Check if password = confirm password
        if request.form.get("password") != request.form.get("confirmation"):
            return error("Passwords don't match", 403)

        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        hash_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        position = request.form.get("position")
        cursor.execute('INSERT INTO users (name, username, email, password, position) VALUES (?, ?, ?, ?, ?)', (name, username, email, hash_password, position))
        connection.commit()

        # Query database for username
        rows = cursor.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect('/')

    else:
        return render_template('register.html')


@app.route("/team")
def team():
    # TODO
    return render_template('team.html')


@app.route("/project")
def project():
    # TODO
    return render_template('project.html')


@app.route("/newteam")
def new_team():
    # TODO
    return render_template('newTeam.html')


@app.route("/newproject")
def new_project():
    # TODO
    return render_template('newProject.html')


@app.route("/profile")
def profile():
    # TODO
    return render_template('profile.html')
