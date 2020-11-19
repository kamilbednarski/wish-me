import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

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


# IMPORTANT - configuration of absolute path to store uploaded images
app.config["IMAGE_UPLOADS"] = "/Users/kamilmac/Documents/Development/wish-me/static/image/uploads"
# IMPORTANT - configuration of allowed image types
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["PNG", "JPG", "JPEG", "GIF", "BMP"]


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

        # Add new user to database, table 'users' and 'images'
        db.execute("INSERT INTO users (username, hash, name, surname, email, city, country) VALUES (:iusername, :ihash, :iname, :isurname, :iemail, :icity, :icountry)", 
                    iusername=username, ihash=hash, iname=name, isurname=surname, iemail=email, icity=city, icountry=country)
        id = db.execute("SELECT id FROM users WHERE username = :username", username=username)
        db.execute("INSERT INTO images (id) VALUES (:id)", id=id[0]['id'])

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
    id = session["user_id"]
    user_data = db.execute("SELECT * FROM users WHERE id = :id", id=id)

    # Save data
    name = user_data[0]["name"]
    surname = user_data[0]["surname"]
    email = user_data[0]["email"]
    city = user_data[0]["city"]
    country = user_data[0]["country"]

    images = db.execute("SELECT * FROM images WHERE id = :id", id=id)
    is_image = images[0]["image"]
    if is_image == 0:
        image_source = "profileimg.bmp"
    if is_image == 1:
        image_source = f"/uploads/{id}.jpg"

    # Render user's account page
    return render_template("profile.html", username=username, name=name, surname=surname, email=email, city=city, country=country, image_source=image_source)



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

        return redirect("/")

    else:
        return render_template("changepassword.html")


@app.route("/change/email", methods=["GET", "POST"])
@login_required
def change_email():
    # This method changes email
    if request.method == "POST":

        # Password and email input fields are both set to required in html code
        # Additional check if password was submited
        if not request.form.get("password"):
            print("INFO: additional password submit check failed; route: change/email")
            return redirect("/change/email")

        # Query database for account details
        rows = db.execute("SELECT id, username, hash FROM users WHERE id = :id", id=session['user_id'])

        # If there is no user with that id or password do not match, redirect
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return redirect("/change/password")

        new_email = request.form.get("email-new")

        # Update existing email with new email
        db.execute("UPDATE users SET email = :new_email WHERE id = :id", new_email=new_email, id=session['user_id'])

        return redirect("/")

    else:
        return render_template("changeemail.html")



def allowed_image(filename):
    # This method validates uploaded image for allowed extensions

    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():

    id=session["user_id"]
    # Query database for account details where userids are equal
    user_data = db.execute("SELECT * FROM users WHERE id = :id", id=id)

    # Save data
    username = user_data[0]["username"]
    name = user_data[0]["name"]
    surname = user_data[0]["surname"]
    email = user_data[0]["email"]
    city = user_data[0]["city"]
    country = user_data[0]["country"]

    # This method displays user's account card
    if request.method == "POST":

        # If image provided
        if request.files:
            new_image = request.files["image"]
            # Log info about loaded file
            print(new_image)

            # Check if file has filename
            if new_image.filename == "":
                print("Image without filename")
                return redirect(request.url)
            
            # Check if allowed image extension
            if not allowed_image(new_image.filename):
                print("Wrong file extension")
                return redirect(request.url)

            else:
                new_file_name = f"{id}.jpg"
                # Save uploaded image
                new_image.save(os.path.join(app.config["IMAGE_UPLOADS"], new_file_name))

                # Save information that user has custom profile image
                db.execute("UPDATE images SET image=1 WHERE id=:id", id=id)

                # Log info about saved file
                print("Image saved")
            

        # If name provided
        if request.form.get("name"):
            new_name = request.form.get("name")
            db.execute("UPDATE users SET name = :new_name WHERE id = :id", new_name=new_name, id=id)
        
        # If surname provided
        if request.form.get("surname"):
            new_surname = request.form.get("surname")
            db.execute("UPDATE users SET surname = :new_surname WHERE id = :id", new_surname=new_surname, id=id)
        
        # If city provided
        if request.form.get("city"):
            new_city = request.form.get("city")
            db.execute("UPDATE users SET city = :new_city WHERE id = :id", new_city=new_city, id=id)
        
        # If country provided
        if request.form.get("country"):
            new_country = request.form.get("country")
            db.execute("UPDATE users SET name = :new_country WHERE id = :id", new_country=new_country, id=id)
        
        # Render user's account page
        return redirect("/profile")

    else:
        return render_template("profileedit.html", username=username, name=name, surname=surname, email=email, city=city, country=country)


@app.route("/profile/delete", methods=["GET", "POST"])
@login_required
def delete_profile():

    id=session["user_id"]
    if request.method == "POST":

        if request.form.get("password") and request.form.get("password-confirm" and request.form.get("password") == request.form.get("password-confirm")):
            
            rows = db.execute("SELECT hash FROM users WHERE id = :id", id=id)

            if check_password_hash(rows[0]["hash"], request.form.get("password")):

                # Remove user's data from database
                db.execute("DELETE FROM users WHERE id = :id", id=id)
                print("INFO: user deleted from users; route: profile/delete")
                db.execute("DELETE FROM images WHERE id = :id", id=id)
                print("INFO: user deleted from images; route: profile/delete")

                # Remove user's profile image
                os.remove(f"/static/image/uploads/{id}.jpg")
                print("INFO: user's profile image deleted from image/uploads; route: profile/delete")

                # Redirect to login page
                return redirect("/login")
        
    else:
        return render_template("profiledelete.html")


