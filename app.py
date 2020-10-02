import os
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO

import secrets

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from helper import *

from pprint import pprint as pp

UPLOAD_FOLDER = "attendance_files"
ALLOWED_EXTENSIONS = {"txt"}

app = Flask(__name__)

# Set secret key (subject to change of course)
app.secret_key = "super_secret_key_ooOoOooOoo"

# Configure upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

# TODO since PyLinter kinda doesn't like SQLAlchemy I'm using SQLite for the time being
# TODO probably don't forget to check for same thread
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

Session(app)


@app.route("/", methods=["GET", "POST"])
@login_required
def main():
    # Upload from: https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
    # If the user is posting then go through checking the file
    if request.method == "POST":

        # Check that the file exists
        if "file" not in request.files:
            flash("No file found")
            return redirect(request.url)

        # Get the file from request.files
        file = request.files["file"]

        # Check if the file has a name
        if file.filename == "":
            flash("File was not selected")
            return redirect("No selected file")

        # CHeck if the file exists and if it is in the allowed files
        if file and allowed_files(file.filename):

            # Securely get the filename
            filename = secure_filename(file.filename)

            # Generate a key
            key = key_gen(16)

            # Format the file to give it a new name
            formatted_file_name = f"{filename[0:len(filename) - 4]}_{key}_{filename[-4:]}"

            # Save the file to the upload folder
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], formatted_file_name))

            # TODO Turn class_id into a list of things as opposed to just this one thing and this can be done
            # through having the user have access to some sort of text field and separate the values through commas
            # request.form.get("class_id") -- enter variations OR allow a submission of numerous
            return redirect(url_for("process_file", path=f"{formatted_file_name}", class_ids="t627a-001 t627a-001 "
                                                                                             "t627 t627a"))
        else:
            # Return error template for anything that is not a txt file
            return render_template("status.html", message="Error")

    # Temporary html return, but will instead be returning a render_template("index.html)
    return '''
        <!doctype html>
        <title>Upload new File</title>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
          <input type=file name=file>
          <input type=submit value=Upload>
        </form>
        '''


@app.route("/register", methods=["GET", "POST"])
def register():
    # Clear session
    session.clear()

    if request.method == "POST":

        user_inp = request.form.get("username")
        p1 = request.form.get("password")
        p2 = request.form.get("confirm")
        email = request.form.get("email")

        if not email:
            return "Email was not entered"
        elif email[-8:] != "@cpsd.us":
            return "You are not authorized to access this site"
        elif not user_inp:
            return "Could not find username"
        elif not p1:
            return "Password was not submitted"
        elif p1 != p2:
            return "Password do not match"
        elif db.execute("SELECT * FROM users WHERE username = :username", {"username": user_inp}).fetchone():
            return "Username already exists"

        # I should validate the email somewhere here

        hashed_pass = generate_password_hash(p1)
        db.execute("INSERT INTO users(username, password) VALUES (:username, :hash)",
                   {"username": user_inp, "hash": hashed_pass})

        db.commit()

        rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": user_inp}).fetchone()

        session["user_id"] = rows[0]

        # Security measure: send an email to the email address above and ask if they registered and send a key
        # and a col in the table to see if the account has been confirmed
        return "aye sick, you're signed up"
        # return redirect("/dashboard")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username": request.form.get("username")}).fetchall()

        # Ensure username exists and password is correct

        # TODO Can add something here to be like "or not rows[0]["verified"]
        # if not rows[0][3]:
        #    # TODO "click here to resend it"?
        #    return apology("well, you should probably confirm this account. until then this account is inactive. you "
        #                   "have received an email already.", 403)
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]
        print(session["user_id"])
        db.close()

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


def handle_attendance_contents():
    # TODO
    return "TODO"


# TODO Not optimal at all and instead I want to use user sessions/ids to store the data, or javascript cookies to store
# the path temporarily before throwing it away after processing -- this way people can't just try to
# guess files and classes, although it probably wouldn't matter all too much as it is only available for a certain time
@app.route("/process/<class_ids>/<path>", methods=["GET"])
def process_file(class_ids, path):
    # Assemble the actual path
    path = f"attendance_files/{path}"

    # Get the classes from the class_id string and format into list
    classes = class_ids.split()

    # Open the file and read the lines
    try:
        with open(path, "r") as f:
            file_contents = f.readlines()
    except FileNotFoundError:
        return apology("File not found, bucko. Don't try and guess the file names!", 404)

    # Make everything lower case
    file_contents = [message.lower() for message in file_contents]

    # Print for debugging
    pp(file_contents)

    # Formatted messages initialized here
    formatted_messages = []

    # Check if the class_id exists in a list and if it does then append it to a final list
    for message in file_contents:

        # Compare the message through the class_ids
        for class_id in classes:

            # If class_id is found in the message then append into the formatted messages list and break
            if class_id in message:
                formatted_messages.append(message[16:])
                break

    # Strip and clean the message
    for message in formatted_messages:
        formatted_messages[formatted_messages.index(message)] = message.split(":")[1][1:].strip("\n")

    # Printing for debugging
    print(classes)

    # Remove the file as to not leave any trace of it

    # Might want to have a confirmation before deleting just to make sure the teacher does not have to redo everything
    os.remove(path)

    # Return the formatted messages because I am not processing any further
    return str(formatted_messages)


# Check if the file is allowed to be uploaded
def allowed_files(file_name):
    return "." in file_name and file_name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/verify/<key>")
def verify_account(key):
    is_key_found = db.execute("SELECT * FROM confirmations WHERE con_key=:con_key", {"con_key": key}).fetchone()

    # Figure out date/time stuff here
    request_dt = is_key_found[4]

    # Check if the key has been used already and make sure the object exists
    if is_key_found and not is_key_found[3]:
        user_id = is_key_found[1]


# Create a verification key and relevant information
def create_verification():
    key = key_gen(32)
    user_id = session["user_id"]
    request_date = get_current_formatted_datetime()
    db.execute("INSERT INTO confirmations (user_id, con_key, request_date) VALUES (:user_id, :con_key, :request_date)",
               {"user_id": user_id, "con_key": key, "request_date": request_date})
    return key


# hah, american formatting
def get_current_formatted_datetime():
    return datetime.now().strftime("%m-%d-%y %H:%M:%S")


# Generate key for the file to make sure teachers or students cant access random files
def key_gen(length):
    return secrets.token_urlsafe(length)


if __name__ == '__main__':
    app.run(threaded=True)
