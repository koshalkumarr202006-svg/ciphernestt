from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, session
)
from pymongo import MongoClient
from cryptography.fernet import Fernet
from bson.objectid import ObjectId
import os, datetime, hashlib, tempfile

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = "ciphernestt_secret_key"

# -------------------------------------------------
# DATABASE
# -------------------------------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["ciphernestt_db"]
users = db["users"]
files = db["files"]

# -------------------------------------------------
# ENCRYPTION (PERSISTENT KEY)
# -------------------------------------------------
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

cipher = Fernet(open(KEY_FILE, "rb").read())

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def safe_int(val):
    try:
        return int(val)
    except:
        return 0

def login_required():
    return "user_id" in session

# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")

# ---------------- AUTH ----------------
@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    if users.find_one({"username": username}):
        flash("Username already exists")
        return redirect(url_for("register_page"))

    users.insert_one({
        "username": username,
        "password": password
    })

    flash("Account created successfully. Please login.")
    return redirect(url_for("login_page"))

@app.route("/login", methods=["POST"])
def login():
    user = users.find_one({
        "username": request.form["username"],
        "password": request.form["password"]
    })

    if not user:
        flash("Invalid username or password")
        return redirect(url_for("login_page"))

    session["user_id"] = str(user["_id"])
    session["username"] = user["username"]

    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")

# ---------------- ENCRYPT + OPTIONAL TIME LOCK ----------------
@app.route("/encrypt-upload", methods=["POST"])
def encrypt_upload():
    if not login_required():
        return redirect(url_for("login_page"))

    file = request.files.get("file")
    pin = request.form.get("pin")

    if not file or not pin:
        flash("File and PIN required")
        return redirect(url_for("dashboard"))

    if len(pin) < 4:
        flash("PIN must be at least 4 digits")
        return redirect(url_for("dashboard"))

    years   = safe_int(request.form.get("years"))
    months  = safe_int(request.form.get("months"))
    days    = safe_int(request.form.get("days"))
    hours   = safe_int(request.form.get("hours"))
    minutes = safe_int(request.form.get("minutes"))
    seconds = safe_int(request.form.get("seconds"))

    total_seconds = (
        years * 31536000 +
        months * 2592000 +
        days * 86400 +
        hours * 3600 +
        minutes * 60 +
        seconds
    )

    unlock_time = None
    if total_seconds > 0:
        unlock_time = datetime.datetime.now() + datetime.timedelta(seconds=total_seconds)

    encrypted_data = cipher.encrypt(file.read())
    encrypted_name = file.filename + ".enc"

    with open(os.path.join(UPLOAD_FOLDER, encrypted_name), "wb") as f:
        f.write(encrypted_data)

    files.insert_one({
        "user_id": session["user_id"],          # 🔐 USER ISOLATION
        "original_name": file.filename,
        "encrypted_name": encrypted_name,
        "pin_hash": hash_pin(pin),
        "wrong_attempts": 0,
        "destroyed": False,
        "unlock_time": unlock_time,
        "upload_time": datetime.datetime.now()
    })

    if unlock_time:
        flash("File encrypted with time-lock applied")
    else:
        flash("File encrypted with PIN protection")

    return redirect(url_for("my_files"))

# ---------------- MY FILES ----------------
@app.route("/my-files")
def my_files():
    if not login_required():
        return redirect(url_for("login_page"))

    user_files = files.find({
        "user_id": session["user_id"]
    })

    return render_template("my_files.html", files=user_files)

# ---------------- TIME LOCKS (FIXED) ----------------
@app.route("/time-locks")
def time_locks():
    if not login_required():
        return redirect(url_for("login_page"))

    locked_cursor = files.find({
        "user_id": session["user_id"],
        "unlock_time": {"$ne": None, "$gt": datetime.datetime.now()},
        "destroyed": False
    })

    locked_files = list(locked_cursor)   # 🔥 CURSOR → LIST FIX

    return render_template("time_locks.html", files=locked_files)

# ---------------- SELF DESTRUCT ----------------
@app.route("/self-destruct")
def self_destruct():
    if not login_required():
        return redirect(url_for("login_page"))

    destroyed_files = list(files.find({
        "user_id": session["user_id"],
        "destroyed": True
    }))

    return render_template("self_destruct.html", files=destroyed_files)

# ---------------- UNLOCK ----------------
@app.route("/unlock/<file_id>", methods=["POST"])
def unlock_file(file_id):
    if not login_required():
        return redirect(url_for("login_page"))

    file = files.find_one({
        "_id": ObjectId(file_id),
        "user_id": session["user_id"]
    })

    if not file or file.get("destroyed"):
        flash("File not available")
        return redirect(url_for("my_files"))

    # ⏳ TIME LOCK CHECK (SAFE)
    if file.get("unlock_time") and datetime.datetime.now() < file["unlock_time"]:
        remaining = file["unlock_time"] - datetime.datetime.now()
        flash(f"Vault locked. Try again after {int(remaining.total_seconds())} seconds")
        return redirect(url_for("my_files"))

    # 🔐 PIN CHECK
    if hash_pin(request.form["pin"]) != file["pin_hash"]:
        attempts = file.get("wrong_attempts", 0) + 1

        if attempts >= 3:
            files.update_one(
                {"_id": ObjectId(file_id)},
                {"$set": {"destroyed": True}}
            )
            flash("3 wrong PIN attempts. File permanently destroyed.")
        else:
            files.update_one(
                {"_id": ObjectId(file_id)},
                {"$set": {"wrong_attempts": attempts}}
            )
            flash(f"Wrong PIN. Attempts left: {3 - attempts}")

        return redirect(url_for("my_files"))

    # ✅ CORRECT PIN
    files.update_one(
        {"_id": ObjectId(file_id)},
        {"$set": {"wrong_attempts": 0}}
    )

    encrypted_path = os.path.join(UPLOAD_FOLDER, file["encrypted_name"])
    decrypted_data = cipher.decrypt(open(encrypted_path, "rb").read())

    temp_path = os.path.join(tempfile.gettempdir(), file["original_name"])
    with open(temp_path, "wb") as f:
        f.write(decrypted_data)

    flash("Now you can open your vault")
    return send_file(temp_path, as_attachment=True)

# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
