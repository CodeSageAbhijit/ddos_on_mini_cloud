import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask import url_for
from flask import send_from_directory,send_file
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
from helpers import apology, login_required, lookup, usd
import base64
from io import BytesIO

# Configure application
app = Flask(__name__)



# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///cloud.db")


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
    # Fetch user account information from the database
    user_info = db.execute(
        "SELECT username FROM users WHERE id = :user_id",
        user_id=session["user_id"]
    )
    user_info = user_info[0]  # Extracting username from the tuple
    user_info = user_info['username']
    user_id = session["user_id"]

    # Get the number of files uploaded by the user
    num_files_uploaded = db.execute("SELECT COUNT(*) FROM user_files WHERE user_id = :user_id", user_id= session["user_id"])[0]
    # print(num_files_uploaded)
    num_files_uploaded = num_files_uploaded['COUNT(*)']


    return render_template("index.html",
                           user_id=user_id,
                           username=user_info,
                           num_files=num_files_uploaded)



@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    user_name = db.execute(
        "SELECT username FROM users WHERE id = :user_id",
        user_id=session["user_id"]
    )

    if user_name:
        user_name = user_name[0]  # Extracting username from the tuple
        user_name = user_name['username']
        # print("first",user_name)
        # Construct the directory path
        user_directory = os.path.join("/workspaces/139953838/own_cloud_server-main/files", user_name)

        # Create the directory if it doesn't exist
        os.makedirs(user_directory, exist_ok=True)

    UPLOAD_FOLDER = user_directory

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect("/")
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect("/")
        # Check if the file already exists in the directory

        if file:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            # file.save(file_path)

            if os.path.exists(file_path):
                flash("A file with the same name already exists")
                return redirect("/")


            key = Fernet.generate_key()
            key = key.decode()
            cipher = Fernet(key)

            file_data = file.read()

            # Encrypt the file data
            encrypted_data = cipher.encrypt(file_data)
            encrypted_data = base64.b64encode(encrypted_data)

            # Save the encrypted data to the file
            with open(file_path, "wb") as f:
                f.write(encrypted_data)



            db.execute(
            "INSERT INTO user_files (user_id, file_name, file_key) VALUES (:user_id, :file_name, :file_key)",
            user_id=session["user_id"],
            file_name=file.filename,
            file_key=key
        )
            flash("File uploaded successfully")
            return redirect("/")
    return render_template("upload.html")

@app.route("/download")
@login_required
def download():
    user_name = db.execute(
        "SELECT username FROM users WHERE id = :user_id",
        user_id = session["user_id"]
    )

    if user_name:
        user_name = user_name[0]
        user_name = user_name['username']
        user_directory = os.path.join("/workspaces/139953838/own_cloud_server-main/files", user_name)

        # Check if the directory exists
        if not os.path.exists(user_directory):
            flash('Directory not found.', 'error')
            return redirect(url_for('upload_file'))  # Redirect to upload page or handle as needed

        # Get the list of files in the user's directory
        files = os.listdir(user_directory)

        return render_template("download.html", files=files)
    else:
        flash("User not found", 'error')
        return redirect(url_for('upload_file'))

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    user_name = db.execute(
        "SELECT username FROM users WHERE id = :user_id",
        user_id = session["user_id"]
    )

    if user_name:
        user_name = user_name[0]
        user_name = user_name['username']
        user_directory = os.path.join("/workspaces/139953838/own_cloud_server-main/files", user_name)

        file_path = os.path.join(user_directory, filename)
        if os.path.exists(file_path):
            with open(file_path,'rb') as f:
                encrypted_data = f.read()

            # Retrieve the encryption key associated with the file from the database
            result = db.execute(
                "SELECT file_key FROM user_files WHERE user_id = :user_id AND file_name = :file_name",
                user_id=session["user_id"],
                file_name=filename
            )
            if result:
                key = result[0]["file_key"]
                cipher = Fernet(key)
                # Decrypt the encrypted data
                decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))

                 # Serve the decrypted data directly from memory
                decrypted_file = BytesIO(decrypted_data)
                decrypted_file.seek(0)  # Reset file pointer to the beginning
                # Return the decrypted data for downloading
                return send_file(decrypted_file, as_attachment=True, download_name=filename)



            else:
                flash("File key not found", 'error')
                return redirect(url_for('download'))
            return send_from_directory(user_directory, filename, as_attachment=True)
        else:
            flash('File not found.', 'error')
            return redirect(url_for('download'))  # Redirect to download page or handle as needed
    else:
        flash("User not found", 'error')
        return redirect(url_for('upload_file'))






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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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





@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password doesn't match!", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username= ?", request.form.get("username")
        )

        if len(rows) != 0:
            return apology("username already exists", 400)

        db.execute(
            "INSERT INTO users (username,hash) VALUES (?,?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        # querying database for newly inserted user
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # remebering which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")





@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "POST":
        password = request.form.get("newpassword")

        if not password:
            return apology("must provide new password", 403)

        user_id = session["user_id"]
        db.execute(
            "UPDATE users SET hash= ? WHERE id =?",
            generate_password_hash(password),
            user_id,
        )

        flash(" Password Change Successfully!!!")
        return redirect("/")
    else:
        return render_template("changepassword.html")
