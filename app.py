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

        # Save user data submitted in form
        name = str(request.form.get("first-name"))
        surname = str(request.form.get("surname"))
        username = str(request.form.get("username"))
        email = str(request.form.get("email"))
        city = str(request.form.get("city"))
        country = str(request.form["country"])

        # Generate password hash
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # Add new user to database, table 'users'
        db.execute("INSERT INTO users (username, hash, name, surname, email, city, country) VALUES (:iusername, :ihash, :iname, :isurname, :iemail, :icity, :icountry)", 
                    iusername=username, ihash=hash, iname=name, isurname=surname, iemail=email, icity=city, icountry=country)

        # Redirect to login panel
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # This method is used to log in
    # Forget any user id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Username and password input fields are both set to required in html code
        # Additional check if username was submited
        if not request.form.get("username"):
            print("INFO: INFO: additional username submit check failed")
            return redirect("/login")

        # Additional check if password was submited
        if not request.form.get("password"):
            print("INFO: additional password submit check failed")
            return redirect("/login")

        # Query database for account details
        rows = db.execute("SELECT id, username, hash FROM users WHERE username = :username", username=request.form.get("username"))

        # If there is no user with that username or password do not match, redirect to login
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Terminal info
        print(f"INFO: Starting new session; user_id: {session['user_id']}; username: {session['username']}")

        # Redirect to homepage
        return redirect("/")

    else:
        return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    # This method is used to log out
    session.clear()
    # Redirect to log in panel
    return redirect("/login")

@app.route("/")
@login_required
def index():
    # TODO
    return render_template("index.html")

@app.route("/profile")
@login_required
def user():
    # This method redirects users profile with dynamic url
    return redirect(f"/profile/{session['username']}")


@app.route("/profile/<username>")
@login_required
def user_profile(username):
    # This method displays user's account card
    # Query database for account details where userids are equal
    user_data = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])

    # Save data
    name = user_data[0]["name"]
    surname = user_data[0]["surname"]
    email = user_data[0]["email"]
    city = user_data[0]["city"]
    country = user_data[0]["country"]
    
    # Render user's account page
    return render_template("profile.html", username=username, name=name, surname=surname, email=email, city=city, country=country)

@app.route("/change/password", methods=["GET", "POST"])
@login_required
def change_password():
    # This method changes password
    if request.method == "POST":

        # Old password and new password input fields are both set to required in html code
        # Additional check if password was submited
        if not request.form.get("password") or not request.form.get("password-new"):
            print("INFO: additional password submit check failed; route: change/password")
            return redirect("/change/password")

        if request.form.get("password") != request.form.get("password-new"):
            print("INFO: additional check failed: password and new password not equal; route: change/password")
            return redirect("/change/password")

        # Query database for account details
        rows = db.execute("SELECT id, username, hash FROM users WHERE id = :id", id=session['user_id'])

        # If there is no user with that id or password do not match, redirect
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return redirect("/change/password")
        
        # Generate hash for new password
        new_hash = generate_password_hash(request.form.get("password-new"), method='pbkdf2:sha256', salt_length=8)

        # Update existing hash with new hash
        db.execute("UPDATE users SET hash = :new_hash WHERE id = :id", new_hash=new_hash, id=session['user_id'])
        
    else:
        return render_template("changepassword.html")