from flask import Flask, render_template, request, session, redirect
from flask_session import Session
import sqlite3

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
Session(app)

connection = sqlite3.connect('projects.db')
cursor = connection.cursor()


@app.route("/")
def index():
    # TODO
    return render_template('index.html')


@app.route("/login")
def login():
    # TODO
    return render_template('login.html')


@app.route("/register")
def register():
    # TODO
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
