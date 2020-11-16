import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///wish.db")

@app.route("/register", methods=["GET", "POST"])
def register():
    # This method registers new users

    # Forget any user id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        # TODO:
        # username at least 3 letter long
        #if not request.form.get("username"):
        #    return render_template("register.html")
        

        # Ensure password was submitted
        # TODO:
        # compare password and confirmation (javascript potentially)
        # password at least 8 char long
        #if not request.form.get("password"):
        #   return render_template("register.html")

        
        # Query database for username
        #rows = db.execute("SELECT * FROM users WHERE username = :username",
                          #username=request.form.get("username"))
        
        # Ensure that username isn't already in database
        # TODO:
        # Redirect to register page with message that username is already in use
        #if len(rows) != 0:
        #   return render_template("register.html")


        # Save user data submitted in form
        name = str(request.form.get("first-name"))
        surname = str(request.form.get("surname"))
        username = str(request.form.get("username"))
        email = str(request.form.get("email"))
        city = str(request.form.get("city"))
        country = str(request.form["country"])

        print(name)
        print(surname)
        print(username)
        print(email)
        print(city)
        print(country)

        # Generate password hash
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # Add new user to database, table 'users'
        db.execute("INSERT INTO users (username, hash, name, surname, email, city, country) VALUES (:iusername, :ihash, :iname, :isurname, :iemail, :icity, :icountry)", iusername=username, ihash=hash, iname=name, isurname=surname, iemail=email, icity=city, icountry=country)

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # This method is used to log in

    # Forget any user id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        return render_template("login.html")
    else:
        return render_template("login.html")