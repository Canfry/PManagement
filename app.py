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
    return render_template('index.html')
