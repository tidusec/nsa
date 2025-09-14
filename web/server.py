#!/usr/bin/env python3

import os
from pathlib import Path
import uuid
import json
import logging
import datetime
import secrets
import base64

import bwt
import sqlalchemy
import requests
from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from flask import render_template, redirect, g
from functools import wraps
from flask import abort
from Crypto.PublicKey import RSA
from base64 import b64encode

# Import functions from crypto_utils.py
from crypto_utils import encryption_oracle, decrypt, generate_keys
from backend import Backend


def get_bwt_keys():
    KEY_FORMAT = "DER"
    key_path = os.environ.get("BWT_KEY_FILE", os.path.join("config", "private.key"))

    with open(key_path, "rb") as f:
        key = RSA.import_key(f.read())

    return {
        "private": key.export_key(format=KEY_FORMAT),
        "public": key.public_key().export_key(format=KEY_FORMAT),
    }


app = Flask(__name__)
# Use environment variable for secret key, fallback to secure random if not set
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_urlsafe(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABSE_URI", "postgresql://dbuser:superSecret@nsa-db:5432/vulndb"
)
if not app.config["SQLALCHEMY_DATABASE_URI"]:
    del app.config["SQLALCHEMY_DATABASE_URI"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

BWT_ALG = "RS256"
bwt_keys = get_bwt_keys()

backend = Backend(
    f"http://{os.environ.get('BACKEND_HOST', 'localhost:8080')}/api",
    lambda: get_request_subject(),
)


class Store1User(db.Model):
    __tablename__ = "users1"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, unique=True)
    password = Column(String(50), nullable=False)
    secret = Column(String(200), nullable=False)


class EncryptedChat(db.Model):
    __tablename__ = "encrypted_chats"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=sqlalchemy.func.now())
    chat_data = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)


with app.app_context():
    db.create_all()
    db.session.commit()


# Rate limiting implementation
failed_login_attempts = {}
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes

def is_rate_limited(ip):
    """Check if IP is rate limited"""
    current_time = datetime.datetime.now()
    if ip in failed_login_attempts:
        attempts = failed_login_attempts[ip]
        # Clean old attempts
        attempts = [attempt for attempt in attempts if (current_time - attempt).seconds < RATE_LIMIT_WINDOW]
        failed_login_attempts[ip] = attempts
        return len(attempts) >= RATE_LIMIT_ATTEMPTS
    return False

def record_failed_login(ip):
    """Record a failed login attempt"""
    current_time = datetime.datetime.now()
    if ip not in failed_login_attempts:
        failed_login_attempts[ip] = []
    failed_login_attempts[ip].append(current_time)

def clear_failed_logins(ip):
    """Clear failed login attempts for successful login"""
    if ip in failed_login_attempts:
        del failed_login_attempts[ip]


#################################
# BWT AUTHENTICATION
# pls do not move away from BWT as authentication method. some stuff depends on that. thx :)
def require_bwt(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not checkBWT():
            # For API endpoints, return 403
            if request.path.startswith("/api/"):
                return abort(403)
            # For UI pages, redirect to '/'
            else:
                return redirect("/")
        return f(*args, **kwargs)

    return decorated_function


def checkBWT():
    token = request.cookies.get("NSA_JWT")

    if token is not None:
        claims = bwt.decode(token, bwt_keys["public"], BWT_ALG)

        if claims is not None:
            g.subject = claims["sub"]
            return True

    return False


def get_request_subject():
    return g.subject if hasattr(g, "subject") else None


#################################


# currently it is possible to view the login page when alrady logged in
# a simple redirect would be unwise since we don't have a logout button
@app.route("/", methods=["GET", "POST"])
def landing():
    if checkBWT():
        return redirect("/dashboard")

    success = request.args.get("success", "")
    if request.method == "POST":
        # Input validation
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Basic input validation
        if not username or not password:
            return render_template("index.html", error="Please enter both username and password"), 400
            
        if len(username) > 50 or len(password) > 100:
            return render_template("index.html", error="Invalid credentials"), 400
            
        # Rate limiting check (simple implementation)
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if is_rate_limited(client_ip):
            return render_template("index.html", error="Too many login attempts. Please try again later."), 429
        
        user = {
            "username": username,
            "password": password,
        }
        
        try:
            login_response = backend.post("/accounts/login", json=user)
            error = getResponseErrorMessage(login_response)
            if error:
                record_failed_login(client_ip)
                return render_template("index.html", error="Invalid ID or Access Code"), 401
            subject = login_response.json()["subject"]
            token = bwt.encode({"sub": subject}, bwt_keys["private"], BWT_ALG)

            response = redirect("/dashboard")
            response.set_cookie("NSA_JWT", token, httponly=True, secure=True, samesite='Strict')
            clear_failed_logins(client_ip)
            return response
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            record_failed_login(client_ip)
            return render_template("index.html", error="Login failed. Please try again."), 500

    return render_template("index.html", success=success)


@app.route("/register", methods=["GET", "POST"])
def register():
    if checkBWT():
        return redirect("/dashboard")

    if request.method == "POST":
        user = {
            "username": request.form.get("username", default=""),
            "password": request.form.get("password", default=""),
            "firstname": request.form.get("firstname", default=""),
            "lastname": request.form.get("lastname", default=""),
            "email": request.form.get("email", default=""),
            "biometricFingerprint": request.form.get(
                "biometricFingerprint", default=""
            ),
        }
        response = backend.post("/accounts/register", json=user)
        error = getResponseErrorMessage(response)
        if error:
            return render_template("register.html", error=error), response.status_code

        username = request.form.get("username", default="")
        picture_url = request.form.get("profile-picture", default="")
        if picture_url != "":
            pictureJson = {
                "profilePictureUrl": request.form.get("profile-picture", default="")
            }
            responsePicture = backend.put(
                f"/accounts/{username}/profilePicture?register=true", json=pictureJson
            )
            error = getResponseErrorMessage(responsePicture)
            if error:
                return (
                    render_template("register.html", error=error),
                    response.status_code,
                )

        return redirect("/?success=Account successfully created")

    return render_template("register.html")


@app.route("/logout", methods=["GET"])
@require_bwt
def logout():
    response = redirect("/")
    response.delete_cookie("NSA_JWT")
    return response


@app.route("/dashboard", methods=["GET"])
@require_bwt
def dashboard():
    n_chats = EncryptedChat.query.count()

    subordinates_response = backend.get(f"/accounts/subordinates")
    subordinates = subordinates_response.json() if subordinates_response.ok else []
    n_subordinates = len(subordinates)

    return render_template(
        "dashboard.html",
        name=get_request_subject(),
        n_subordinates=n_subordinates,
        n_chats=n_chats,
    )


@app.route("/agents", methods=["GET", "POST"])
@require_bwt
def agents():
    username = get_request_subject()

    if request.method == "POST":
        data = request.get_json()
        action = data.get("action")
        target_username = data.get("username")

        if action == "promote":
            promote_response = backend.post(f"/accounts/{target_username}/promote")
            error_message = getResponseErrorMessage(promote_response)
            if error_message:
                return jsonify({"status": "error", "message": error_message}), 400
            else:
                return (
                    jsonify(
                        {
                            "status": "success",
                            "message": f"User {target_username} promoted.",
                        }
                    ),
                    200,
                )

        elif action == "demote":
            demote_response = backend.post(f"/accounts/{target_username}/demote")
            error_message = getResponseErrorMessage(demote_response)
            if error_message:
                return jsonify({"status": "error", "message": error_message}), 400
            else:
                return (
                    jsonify(
                        {
                            "status": "success",
                            "message": f"User {target_username} demoted.",
                        }
                    ),
                    200,
                )

    # Fetch the user data from the backend
    response = backend.get(f"/accounts/{username}")
    user_data = response.json() if response.ok else {}

    # If the backend returns user, role, and permission level, extract these values
    user = user_data.get("username", "N/A")
    role = user_data.get("role", "N/A")
    permission_level = user_data.get("permissionLevel", "N/A")

    subordinates_response = backend.get(f"/accounts/subordinates")
    subordinates = subordinates_response.json() if subordinates_response.ok else []

    columns = ["username", "role", "permissionLevel", "actions"]
    for sub in subordinates:
        if "biometricFingerprint" in sub:
            columns.append("biometricFingerprint")
            break

    # Pass the data to the agents.html template
    return render_template(
        "agents.html",
        user=user,
        role=role,
        permission_level=permission_level,
        subordinates=subordinates,
        columns=columns,
    )


@app.route("/chats", methods=["GET"])
@require_bwt
def chats():
    username = get_request_subject()

    # Fetch user data (role, etc.) from backend
    response = backend.get(f"/accounts/{username}")
    user_data = response.json() if response.ok else {}
    user = user_data.get("username", "N/A")
    role = user_data.get("role", "N/A")

    # Pull chats from your database (EncryptedChat model)
    chats_query = EncryptedChat.query.all()
    chats_data = []
    for c in chats_query:
        chats_data.append(
            {
                "id": c.id,
                "user_id": c.user_id,
                "timestamp": c.timestamp,
                "chat_data": c.chat_data,
                "formatted_time": c.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    return render_template("chats.html", chats=chats_data, user=user, role=role)


@app.route("/settings", methods=["GET", "POST"])
@require_bwt
def settings():
    username = get_request_subject()
    error = None
    status_code = 200
    if request.method == "POST":
        profileJson = {
            "firstname": request.form.get("firstname", default=""),
            "lastname": request.form.get("lastname", default=""),
            "email": request.form.get("email", default=""),
            "password": request.form.get("password", default=""),
        }
        responseProfile = backend.put(f"/accounts/{username}/edit", json=profileJson)
        error = getResponseErrorMessage(responseProfile)
        if error:
            status_code = responseProfile.status_code

        picture_url = request.form.get("profile-picture", default="")
        if picture_url != "" and not error:
            pictureJson = {
                "profilePictureUrl": request.form.get("profile-picture", default="")
            }
            responsePicture = backend.put(
                f"/accounts/{username}/profilePicture", json=pictureJson
            )
            error = getResponseErrorMessage(responsePicture)
            if error:
                status_code = responseProfile.status_code

    response = backend.get(f"/accounts/{username}")
    user = response.json() if response.ok else {}

    if not error and not response.ok:
        error = getResponseErrorMessage(response)
        status_code = response.status_code

    return render_template("settings.html", user=user, error=error), status_code


# API Endpoints


# pls no not remove or change. thx :)
@app.route("/api/v1/get-bwt-public-key", methods=["GET"])
def get_bwt_public_key():
    return (
        jsonify({"bwt_public_key": b64encode(bwt_keys["public"]).decode("utf-8")}),
        200,
    )


# Every logged in user can upload "stolen" chats which will be encrypted using the public key in the frontend and stored (encrypted) in a database
@app.route("/api/v1/upload-chat", methods=["POST"])
@require_bwt
def upload_chat():
    # Current user from JWT
    user_id = get_request_subject()

    # Read chat data from the form submission
    chat_data = request.form.get("chat_data", "")
    if not chat_data.strip():
        return jsonify({"status": "error", "message": "Chat data not provided"}), 400
    
    # Input validation
    if len(chat_data) > 10000:  # Limit to 10KB
        return jsonify({"status": "error", "message": "Chat data too large"}), 400
    
    # Sanitize input (basic)
    chat_data = chat_data.replace('<script', '&lt;script').replace('</script>', '&lt;/script&gt;')

    try:
        # Generate new keypair for this chat
        chat_public_key, chat_private_key = generate_keys()

        # Encrypt the chat with your existing function
        encrypted_chat = encryption_oracle(chat_data, chat_public_key)

        # Store encrypted chat in the DB
        new_chat = EncryptedChat(
            user_id=user_id,
            chat_data=json.dumps(encrypted_chat),
            public_key=json.dumps(chat_public_key),
            private_key=json.dumps(chat_private_key)
        )
        db.session.add(new_chat)
        db.session.commit()

        # Redirect user back to the chats page
        return jsonify({
            "status": "success", 
            "chat_id": new_chat.id,
            "public_key": chat_public_key
        }), 200
    except Exception as e:
        app.logger.error(f"Chat upload error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to upload chat"}), 500


@app.route("/api/v1/download-chat", methods=["GET"])
@require_bwt
def download_chat():
    chat_id = request.args.get("chat_id")
    current_user = get_request_subject()
    
    # Input validation
    if not chat_id:
        return jsonify({"status": "error", "message": "Chat ID required"}), 400
    
    try:
        chat_id = int(chat_id)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid chat ID"}), 400

    # Check role from backend
    try:
        user_response = backend.get(f"/accounts/{current_user}")
        if not user_response.ok:
            return jsonify({"status": "error", "message": "User not found"}), 404
        user_data = user_response.json()
        role = user_data.get("role", "user")
    except Exception as e:
        app.logger.error(f"Error fetching user data: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to verify user"}), 500

    chat = EncryptedChat.query.get(chat_id)
    if not chat:
        return jsonify({"status": "error", "message": "Chat not found"}), 404

    # Admins or chat owner => decrypted, else => encrypted
    if role == "ADMIN" or chat.user_id == current_user:
        # Decrypt
        try:
            chat_data_list = json.loads(chat.chat_data)
            chat_private_key = json.loads(chat.private_key)
            decrypted_chat_data = decrypt(chat_data_list, chat_private_key)
            return jsonify({
                "data": {
                    "chat_data": decrypted_chat_data
                }
            }), 200
        except Exception as e:
            app.logger.error(f"Decryption error: {str(e)}")
            return jsonify({"status": "error", "message": "Failed to decrypt chat"}), 500
    
    return jsonify({
        "data": {
            "chat_data": chat.chat_data,
            "public_key": json.loads(chat.public_key)
        }
    }), 200


# Endpoint to return the entire encrypted chat database as JSON
@app.route("/api/v1/all-encrypted-chats", methods=["GET"])
@require_bwt
def get_all_encrypted_chats():
    chats = EncryptedChat.query.all()
    chat_list = []
    for chat in chats:
        chat_list.append(
            {
                "id": chat.id,
                "user_id": chat.user_id,
                "timestamp": chat.timestamp,
                "chat_data": chat.chat_data,
                "public_key": chat.public_key,
            }
        )
    return jsonify({"status": "success", "data": chat_list}), 200


@app.route("/profilePicture/<username>", methods=["GET"])
def get_profile_picture(username):
    response = backend.get(f"/accounts/{username}/profilePicture")
    return response.content, response.status_code, {"Content-Type": "image"}


def getResponseErrorMessage(response):
    if response.ok:
        return None
    try:
        return response.text
    except:
        return "No error message"


if __name__ == "__main__":
    # Disable debug mode in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(port=1337, debug=debug_mode)
