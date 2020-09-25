import os
from flask import Flask, flash, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import secrets

from pprint import pprint as pp

UPLOAD_FOLDER = "attendance_files"
ALLOWED_EXTENSIONS = {"txt"}

app = Flask(__name__)
app.secret_key = "super_secret_key_ooOoOooOoo"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/", methods=["GET", "POST"])
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
            formatted_file_name = f"{filename[0:len(filename)-4]}_{key}_{filename[-4:]}"

            # Save the file to the upload folder
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], formatted_file_name))

            # Turn class_id into a list of things as opposed to just this one thing and this can be done
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
