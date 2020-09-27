import os
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import secrets

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

engine = create_engine("sqlite:///db/attendinez.db")
db = scoped_session(sessionmaker(bind=engine))

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
            key = key_gen()

            # Format the file to give it a new name
            formatted_file_name = f"{filename[0:len(filename) - 4]}_{key}_{filename[-4:]}"

            # Save the file to the upload folder
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], formatted_file_name))

            # TODO Turn class_id into a list of things as opposed to just this one thing and this can be done
            # through having the user have access to some sort of text field and separate the values through commas
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
        db.execute("INSERT INTO users(username, password) VALUES (:username, :hash)", {"username": user_inp, "hash": hashed_pass})

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
        rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": request.form.get("username")}).fetchall()

        # Ensure username exists and password is correct

        # TODO Can add something here to be like "or not rows[0]["verified"]
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    with open(path, "r") as f:
        file_contents = f.readlines()

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


# Generate key for the file to make sure teachers or students cant access random files
def key_gen():
    return secrets.token_urlsafe(16)


if __name__ == '__main__':
    app.run()
