from flask import Flask, render_template, request, session, redirect
from flask_session import Session
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

from utils import login_required, error

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config.from_object(__name__)
app.secret_key = 'super secret key'
Session(app)

connection = sqlite3.connect('projects.db', check_same_thread=False)
cursor = connection.cursor()

cursor.execute("create TABLE IF NOT EXISTS users (id INTEGER NOT NULL, name TEXT NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, hash TEXT NOT NULL, position TEXT NOT NULL, team_id INTEGER, FOREIGN KEY(team_id) REFERENCES teams(id), PRIMARY KEY (id))")
cursor.execute("create TABLE IF NOT EXISTS teams (id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, user_id INTEGER, project_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(project_id) REFERENCES projects(id))")
cursor.execute("create TABLE IF NOT EXISTS projects (id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL, team_id INTEGER, FOREIGN KEY(team_id) REFERENCES teams(id))")


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
    return render_template('index.html')


@app.route("/logout")
def logout():
    session.clear()

    return redirect('/')


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    # session.clear()

    # If method = POST
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return error("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return error("must provide password", 403)

        # Query database for username and password
        res = cursor.execute("SELECT username, hash, id FROM users")
        users = res.fetchall()
        # print(users)
        for user in range(len(users)):
            try:
                if request.form.get("username") in users[user][0] and check_password_hash(users[user][1], request.form.get("password")):
                    session["user_id"] = users[user][2]
                    session["user_name"] = users[user][0]
                    print(session)
                    print(users[user][0])
                    return redirect("/")
            except request.form.get("username") not in users[user][0] and not check_password_hash(users[user][1], request.form.get("password")):
                error("Invalid username and/or password", 403)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Clear session
    # session.clear()

    # Check if method is post
    if request.method == "POST":
        # Name, username, email, password, position are required
        if request.form.get("name") == '' or request.form.get("username") == '' or request.form.get("password") == '' or request.form.get("position") == '':
            return error('All the fields are required', 403)

        # Check if user exist
        res = cursor.execute('SELECT username FROM users')
        usernames = res.fetchall()
        # print(usernames)
        for username in range(len(usernames)):
            if request.form.get('username') == usernames[username][0]:
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
        cursor.execute("INSERT INTO users (name, username, email, hash, position) VALUES (?, ?, ?, ?, ?)", (name, username, email, hash_password, position))
        connection.commit()

        # Query database by username
        res = cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = res.fetchall()
        # print(user)

        # Remember which user has logged in
        session["user_id"] = user[0][0]
        session["user_name"] = user[0][1]

        return redirect('/')
    else:
        return render_template('register.html')


@app.route("/team")
@login_required
def team_page():
    resp = cursor.execute("SELECT * FROM teams")
    teams = resp.fetchall()
    print(teams)
    if len(teams) < 1:
        error('There is not team yet!!', 403)
    else:
        return render_template('team.html', teams=teams)


@app.route('/team/<team_id>')
@login_required
def single_team(team_id):
    res = cursor.execute('SELECT * FROM teams where id = ?', team_id)
    team = res.fetchone()
    response = cursor.execute('SELECT name FROM users WHERE id = (SELECT user_id from teams WHERE id = ?)', team_id)
    user = response.fetchone()
    print(user)
    print(team)
    return render_template('teamId.html', team_id=team_id, team=team, user=user)


@app.route("/assign-user", methods=["POST"])
@login_required
def assign_user():
    if request.method == 'POST':
        res = cursor.execute("SELECT username, id FROM users")
        users = res.fetchall()
        print(users)
        for user in range(len(users)):
            username = users[user][0]
            user_id = users[user][1]
            if request.form.get("username") == username:
                cursor.execute("INSERT INTO teams (user_id) VALUES (?)", user_id)
                connection.commit()
        return redirect('/team')


@app.route("/project")
@login_required
def project():
    # TODO
    return render_template('project.html')


@app.route("/newteam", methods=["POST", "GET"])
@login_required
def new_team():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        res = cursor.execute('SELECT * FROM users')
        user_list = res.fetchall()
        print(user_list)
        try:
            for user in range(len(user_list)):
                if user_list[user][1] or user_list[user][2] == request.form.get('name'):
                    cursor.execute('INSERT INTO teams (name, description, user_id) VALUES (?, ?, ?)', (name, description, user_list[user][0]))
                    connection.commit()
        except TypeError:
            raise error('No user match', 403)

        return redirect('/team')
    else:
        return render_template('newTeam.html')


@app.route("/newproject")
@login_required
def new_project():
    # TODO
    return render_template('newProject.html')


@app.route("/profile")
@login_required
def profile():
    # TODO
    return render_template('profile.html')
