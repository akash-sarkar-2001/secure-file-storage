import os, random, string, io, re
from flask import Flask, request, render_template, jsonify, redirect, send_file, url_for, Response
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import werkzeug, pyotp, qrcode
from itsdangerous import URLSafeTimedSerializer
from io import BytesIO
import paramiko
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from blockchain import Blockchain
from aes_crypto import encrypt_file_data, decrypt_file_data
import csv
from flask import make_response

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config["MONGO_URI"] = "mongodb://localhost:27017/users"
mongo = PyMongo(app)
blockchain = Blockchain(mongo.db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")

# Ensure unique index on encryption metadata
try:
    mongo.db.encryption.create_index(
        [("user_id", 1), ("filename", 1)],
        unique=True
    )
except Exception as e:
    print("Index creation failed:", e)


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Set to False if testing locally without HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=True
)

# Secret key for signing tokens
serializer = URLSafeTimedSerializer(app.secret_key)

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# VPS Connection Details (Use environment variables instead of hardcoded values)
VPS_HOST = os.getenv("VPS_HOST")  # Default: Local VPS
VPS_PORT = int(os.getenv("VPS_PORT"))  # Convert port to integer
VPS_USERNAME = os.getenv("VPS_USERNAME")
VPS_PASSWORD = os.getenv("VPS_PASSWORD")  # Avoid hardcoding passwords

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "mp4", "mkv", "mov", "avi"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"user_id": user_id})  # Fetch by user_id
    if user:
        return User(user_id)  # Return user_id instead of username
    return None

@app.after_request
def add_security_headers(response):
    # Disable right-click via CSP
    response.headers['Content-Security-Policy'] = "context-menu 'none'"
    
    # Also inject JavaScript for clients that don't support CSP
    if response.content_type == 'text/html; charset=utf-8':
        js = """
        <script>
        document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
        });
        </script>
        """
        response.data = response.data.replace(b'</body>', js.encode('utf-8') + b'</body>')
    
    return response

def get_file_type(filename):
    ext = filename.split('.')[-1].lower()
    if ext in ['jpg', 'jpeg', 'png', 'gif']:
        return 'image/' + ext
    elif ext in ['txt', 'log']:
        return 'text/plain'
    elif ext == 'pdf':
        return 'application/pdf'
    elif ext == 'mp4':
        return 'video/mp4'
    elif ext == 'mkv':
        return 'video/x-matroska'
    elif ext == 'mov':
        return 'video/quicktime'
    elif ext == 'avi':
        return 'video/x-msvideo'
    return 'application/octet-stream'

def is_valid_username(username):
    """Validate username against a strict regex."""
    return bool(USERNAME_REGEX.match(username))

def is_strong_password(password):
    """Ensure password is at least 8 characters, includes letters & numbers."""
    return bool(re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$", password))

def generate_user_id():
    """Generate a random 8-character alphanumeric user ID."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=8))

def ssh_connect():
    """Establish a secure SSH connection using password-based authentication."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            VPS_HOST,
            port=VPS_PORT,
            username=VPS_USERNAME,
            password=VPS_PASSWORD,  # Use password instead of key_filename
            timeout=10
        )
        print("✅ SSH Connection Established Successfully!")
        return ssh
    except paramiko.AuthenticationException:
        print("❌ SSH Authentication failed. Check your credentials.")
    except paramiko.SSHException as e:
        print(f"❌ SSH Connection Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")

    return None

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def list_vps_files(user_id):
    """List files inside a user's dedicated folder on the VPS."""
    ssh = ssh_connect()
    if not ssh:
        return []
    try:
        sftp = ssh.open_sftp()
        folder_path = f"/home/{VPS_USERNAME}/SFS/{user_id}/"
        files = sftp.listdir(folder_path)
        sftp.close()
        ssh.close()
        return files
    except Exception as e:
        print(f"❌ List Error: {e}")
        return []

def upload_to_vps(local_path, remote_path):
    """Upload file to user's folder on VPS."""
    ssh = ssh_connect()
    if not ssh:
        return False
    try:
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        ssh.close()
        print(f"✅ File '{local_path}' uploaded to '{remote_path}' on VPS.")
        return True
    except Exception as e:
        print(f"❌ Upload Error: {e}")
        return False
    
def generate_recovery_codes():
    """Generate 5 one-time-use recovery codes."""
    return ["".join(random.choices(string.ascii_uppercase + string.digits, k=10)) for _ in range(5)]

@app.route("/")
@login_required
def index():
    # Log page access
    blockchain.add_block({
        "action": "page_access",
        "page": "dashboard",
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    user_id = current_user.id
    user_folder = f"/home/{VPS_USERNAME}/SFS/{user_id}"
    
    # Get the user document from MongoDB
    user_data = mongo.db.users.find_one({"user_id": user_id})
    
    files = []
    ssh = ssh_connect()
    if ssh:
        try:
            sftp = ssh.open_sftp()
            for filename in sftp.listdir(user_folder):
                if '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
                    file_info = sftp.stat(f"{user_folder}/{filename}")
                    files.append({
                        "name": filename,
                        "size": file_info.st_size,
                        "type": get_file_type(filename)
                    })
            sftp.close()
            ssh.close()
        except Exception as e:
            print(f"Error listing files: {e}")
    
    return render_template("upload.html", 
                         user_id=user_id,
                         username=user_data.get("_id"),  # Add username
                         full_name=user_data.get("name", ""),  # Add full name
                         files=files)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.json.get("username", "").strip()
        password = request.json.get("password", "").strip()
        name = request.json.get("name", "").strip()  # Get the name from the request

        if not is_valid_username(username):
            return jsonify({"status": "error", "message": "Invalid username format"}), 400
        
        if not is_strong_password(password):
            return jsonify({"status": "error", "message": "Weak password. Use at least 8 characters, 1 letter, and 1 number."}), 400

        if mongo.db.users.find_one({"_id": username}):
            return jsonify({"status": "error", "message": "Username already exists"}), 400

        hashed_pw = bcrypt.generate_password_hash(password, rounds=14).decode('utf-8')
        user_id = generate_user_id()
        otp_secret = pyotp.random_base32()  # Always generate OTP secret
        recovery_codes = generate_recovery_codes()

        mongo.db.users.insert_one({
            "_id": username,
            "password": hashed_pw,
            "user_id": user_id,
            "name": name,  # Store the full name
            "otp_secret": otp_secret,
            "recovery_codes": recovery_codes,
            "verified": False
        })

        blockchain.add_block({
            "action": "user_registration",
            "username": username,
            "user_id": user_id,
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })

        ssh = ssh_connect()
        if ssh:
            ssh.exec_command(f"mkdir -p /home/{VPS_USERNAME}/SFS/{user_id}/")
            ssh.close()

        return jsonify({
            "status": "success",
            "message": "Registration successful!",
            "user_id": user_id,
            "recovery_codes": recovery_codes,
            "otp_secret": otp_secret
        })
    
    blockchain.add_block({
        "action": "page_access",
        "page": "register",
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Log page access for GET requests
        blockchain.add_block({
            "action": "page_access",
            "page": "login",
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })
        return render_template("login.html")

    # Determine if login was via JSON or form
    is_json = request.is_json

    # Get credentials from JSON or form data
    if is_json:
        username = request.json.get("username", "").strip()
        password = request.json.get("password", "").strip()
    else:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

    if not is_valid_username(username):
        if is_json:
            return jsonify({"status": "error", "message": "Invalid username format"}), 400
        else:
            return render_template("login.html", error="Invalid username format"), 400

    user = mongo.db.users.find_one({"_id": username})
    if user and bcrypt.check_password_hash(user["password"], password):
        blockchain.add_block({
            "action": "user_login",
            "username": username,
            "user_id": user["user_id"],
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })

        # Flask-Login login
        login_user(User(user["user_id"]))

        if is_json:
            return jsonify({
                "status": "success",
                "message": "Login successful! Please complete 2FA verification.",
                "requires_2fa": True
            })
        else:
            return redirect(url_for("verify_otp"))
    else:
        blockchain.add_block({
            "action": "login_failed",
            "username": username,
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })

        if is_json:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        else:
            return render_template("login.html", error="Invalid username or password"), 401

@app.route("/verify-otp", methods=["GET", "POST"])
@login_required
def verify_otp():
    if request.method == "GET":
        return render_template("verify_otp.html")
    
    otp_code = request.json.get("otp_code", "").strip()
    user = mongo.db.users.find_one({"user_id": current_user.id})
    
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    totp = pyotp.TOTP(user["otp_secret"])
    if totp.verify(otp_code):
        blockchain.add_block({
                "action": "otp_verified",
                "user_id": current_user.id,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
        # Mark device as trusted if remember_me was checked during login
        return jsonify({"status": "success", "message": "2FA verified!"})
    
    elif otp_code in user["recovery_codes"]:
        blockchain.add_block({
                "action": "otp_failed",
                "user_id": current_user.id,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
        
        mongo.db.users.update_one(
            {"user_id": user["user_id"]},
            {"$pull": {"recovery_codes": otp_code}}
        )
        return jsonify({"status": "success", "message": "Recovery code accepted!"})
    
    blockchain.add_block({
        "action": "page_access",
        "page": "verify_otp",
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })

    return jsonify({"status": "error", "message": "Invalid OTP or Recovery Code"}), 401

@app.route("/generate-qr")
def generate_qr():
    # Get parameters from URL
    username = request.args.get('username')
    otp_secret = request.args.get('secret')
    
    if not username or not otp_secret:
        return "Missing parameters", 400

    # Generate QR code
    totp = pyotp.TOTP(otp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Secure File Storage")
    
    qr = qrcode.make(uri)
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

@app.route("/logout")
@login_required
def logout():
    # Log logout action
    blockchain.add_block({
        "action": "user_logout",
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    logout_user()
    response = redirect(url_for("login"))
    return response

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        blockchain.add_block({
            "action": "upload_failed",
            "reason": "no_file",
            "user_id": current_user.id,
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400

    # Sanitize filename
    filename = werkzeug.utils.secure_filename(file.filename)

    blockchain.add_block({
        "action": "file_upload",
        "filename": filename,
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })

    # Validate file type
    if not allowed_file(filename):
        return jsonify({"status": "error", "message": "Invalid file type"}), 400

    # Check file size (read into memory first)
    file.seek(0, os.SEEK_END)  # Move to end of file
    file_size = file.tell()
    file.seek(0)  # Reset file pointer

    if file_size > MAX_FILE_SIZE:
        return jsonify({"status": "error", "message": "File size exceeds 100MB limit"}), 400

    user_id = current_user.id
    user_folder = f"/home/{VPS_USERNAME}/SFS/{user_id}"

    ssh = ssh_connect()
    if ssh:
        try:
            sftp = ssh.open_sftp()
            try:
                sftp.mkdir(user_folder)
            except IOError:
                pass  # Folder exists

            remote_path = f"{user_folder}/{filename}"
            file_data = file.read()
            enc_result = encrypt_file_data(file_data)
            with sftp.open(remote_path, "wb") as remote_file:
                remote_file.write(enc_result["ciphertext"])
            mongo.db.encryption.insert_one({
                "user_id": user_id,
                "filename": filename,
                "key": enc_result["key"],
                "iv": enc_result["iv"],
                "tag": enc_result["tag"]
            })

            sftp.close()
            ssh.close()
            return jsonify({"status": "success", "message": f"Uploaded {filename}!"})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Upload failed: {str(e)}"}), 500
    else:
        return jsonify({"status": "error", "message": "SSH connection failed"}), 500
    
@app.route("/download/<filename>")
@login_required
def download_file(filename):
    blockchain.add_block({
        "action": "file_download",
        "filename": filename,
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    user_id = current_user.id
    user_folder = f"/home/{VPS_USERNAME}/SFS/{user_id}"
    sanitized_filename = werkzeug.utils.secure_filename(filename)
    
    if not allowed_file(sanitized_filename):
        return jsonify({"status": "error", "message": "Invalid file type"}), 400

    ssh = ssh_connect()
    if ssh:
        try:
            sftp = ssh.open_sftp()
            remote_path = f"{user_folder}/{sanitized_filename}"
            
            try:
                file_size = sftp.stat(remote_path).st_size
            except FileNotFoundError:
                return jsonify({"status": "error", "message": "File not found"}), 404

            # Handle range requests for video streaming
            range_header = request.headers.get('Range', None)
            if range_header:
                start, end = 0, file_size - 1
                range_ = range_header.split('=')[1].split('-')
                start = int(range_[0])
                end = int(range_[1]) if range_[1] else file_size - 1
                
                length = end - start + 1
                file_obj = io.BytesIO()
                with sftp.open(remote_path, 'rb') as remote_file:
                    remote_file.seek(start)
                    file_obj.write(remote_file.read(length))
                file_obj.seek(0)
                
                response = Response(
                    file_obj,
                    206,
                    mimetype=get_file_type(filename),
                    content_type=get_file_type(filename),
                    direct_passthrough=True
                )
                response.headers.add('Content-Range', f'bytes {start}-{end}/{file_size}')
                response.headers.add('Accept-Ranges', 'bytes')
                response.headers.add('Content-Length', str(length))
                sftp.close()
                ssh.close()
                return response
            
            # Regular file download
            file_obj = io.BytesIO()
            sftp.getfo(remote_path, file_obj)
            file_obj.seek(0)
            ciphertext = file_obj.read()

            key_doc = mongo.db.encryption.find_one({"user_id": user_id, "filename": sanitized_filename})
            if not key_doc:
                return jsonify({"status": "error", "message": "Encryption metadata not found"}), 500
            
            try:
                decrypted_data = decrypt_file_data(
                    ciphertext,
                    key_doc["key"],
                    key_doc["iv"],
                    key_doc["tag"]
                )
            except Exception as e:
                return jsonify({"status": "error", "message": f"Decryption failed: {str(e)}"}), 500
            
            file_obj = io.BytesIO(decrypted_data)
            
            sftp.close()
            ssh.close()
            
            return send_file(
                file_obj,
                mimetype=get_file_type(filename),
                as_attachment=False,
                download_name=sanitized_filename
            )
            
        except Exception as e:
            return jsonify({"status": "error", "message": f"Download failed: {str(e)}"}), 500
    return jsonify({"status": "error", "message": "SSH connection failed"}), 500

@app.route("/delete/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    blockchain.add_block({
        "action": "file_deleted",
        "filename": filename,
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    user_id = current_user.id  # Ensure user can only delete their own files
    user_folder = f"/home/{VPS_USERNAME}/SFS/{user_id}"

    # Sanitize filename to prevent path traversal attacks
    sanitized_filename = werkzeug.utils.secure_filename(filename)

    # Validate file type
    if not allowed_file(sanitized_filename):
        return jsonify({"status": "error", "message": "Invalid file type"}), 400

    ssh = ssh_connect()
    if ssh:
        try:
            sftp = ssh.open_sftp()
            remote_path = f"{user_folder}/{sanitized_filename}"

            # Ensure the file exists before attempting deletion
            try:
                sftp.stat(remote_path)  # Check if file exists
            except FileNotFoundError:
                return jsonify({"status": "error", "message": "File not found"}), 404

            # Delete the file
            sftp.remove(remote_path)
            sftp.close()
            ssh.close()

            mongo.db.encryption.delete_one({
                "user_id": user_id,
                "filename": sanitized_filename
            })

            mongo.db.shares.delete_many({
                "owner_id": user_id,
                "filename": sanitized_filename
            })

            return jsonify({"status": "success", "message": f"Deleted {sanitized_filename}!"})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Delete failed: {str(e)}"}), 500
    return jsonify({"status": "error", "message": "SSH connection failed"}), 500

# Add these new routes
@app.route("/share-file", methods=["POST"])
@login_required
def share_file():
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        # Get required parameters with proper error handling
        filename = data.get("filename")
        recipient_id = data.get("recipient_id")
        permission = data.get("permission", "preview")  # Default to preview

        if not filename or not recipient_id:
            return jsonify({
                "status": "error", 
                "message": "Missing filename or recipient_id"
            }), 400

        # Verify recipient exists
        recipient = mongo.db.users.find_one({"user_id": recipient_id})
        if not recipient:
            return jsonify({
                "status": "error", 
                "message": "Recipient not found"
            }), 404

        # Check if file exists in owner's folder
        ssh = ssh_connect()
        if not ssh:
            return jsonify({
                "status": "error", 
                "message": "Connection error"
            }), 500
            
        try:
            sftp = ssh.open_sftp()
            owner_folder = f"/home/{VPS_USERNAME}/SFS/{current_user.id}"
            try:
                sftp.stat(f"{owner_folder}/{filename}")
            except FileNotFoundError:
                return jsonify({
                    "status": "error", 
                    "message": "File not found"
                }), 404
                
            # Create sharing record
            share_id = str(ObjectId())
            mongo.db.shares.insert_one({
                "_id": share_id,
                "owner_id": current_user.id,
                "recipient_id": recipient_id,
                "filename": filename,
                "permission": permission,
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(days=30)
            })
            
            # Blockchain logging
            blockchain.add_block({
                "action": "file_shared",
                "filename": filename,
                "owner_id": current_user.id,
                "recipient_id": recipient_id,
                "permission": permission,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })

            return jsonify({
                "status": "success",
                "message": f"Access granted to {recipient_id}",
                "share_id": share_id
            })
        except Exception as e:
            # Log error to blockchain
            blockchain.add_block({
                "action": "share_error",
                "error": str(e),
                "user_id": current_user.id,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
            return jsonify({
                "status": "error", 
                "message": f"Sharing failed: {str(e)}"
            }), 500
        finally:
            if ssh:
                ssh.close()
    except Exception as e:
        # Catch any unexpected errors
        blockchain.add_block({
            "action": "unexpected_error",
            "error": str(e),
            "route": "share-file",
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred"
        }), 500

@app.route("/revoke-access", methods=["POST"])
@login_required
def revoke_access():
    try:
        # Get share_id from request data
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "No data provided"
            }), 400

        share_id = data.get("share_id")
        if not share_id:
            return jsonify({
                "status": "error",
                "message": "Missing share_id parameter"
            }), 400

        # Verify the share exists and belongs to current user
        share = mongo.db.shares.find_one({
            "_id": share_id,
            "owner_id": current_user.id
        })
        
        if not share:
            # Log failed revocation attempt
            blockchain.add_block({
                "action": "revoke_failed",
                "reason": "share_not_found_or_unauthorized",
                "user_id": current_user.id,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
            return jsonify({
                "status": "error",
                "message": "Share not found or not authorized"
            }), 404

        # Delete the share record
        result = mongo.db.shares.delete_one({"_id": share_id})

        if result.deleted_count == 1:
            # Log successful revocation
            blockchain.add_block({
                "action": "access_revoked",
                "share_id": share_id,
                "filename": share.get("filename", "unknown"),
                "recipient_id": share.get("recipient_id", "unknown"),
                "user_id": current_user.id,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
            return jsonify({
                "status": "success",
                "message": "Access revoked"
            })
        else:
            # Log failed deletion
            blockchain.add_block({
                "action": "revoke_failed",
                "reason": "database_error",
                "share_id": share_id,
                "user_id": current_user.id,
                "ip": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
            return jsonify({
                "status": "error",
                "message": "Failed to revoke access"
            }), 500

    except Exception as e:
        # Log unexpected errors
        blockchain.add_block({
            "action": "revoke_error",
            "error": str(e),
            "user_id": current_user.id if current_user.is_authenticated else "unknown",
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred"
        }), 500

@app.route("/shared-files")
@login_required
def shared_files():
    blockchain.add_block({
        "action": "shared_files_viewed",
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    # Files shared with current user
    shared_with_me = list(mongo.db.shares.find({
        "recipient_id": current_user.id
    }))
    
    # Files I've shared with others
    shared_by_me = list(mongo.db.shares.find({
        "owner_id": current_user.id
    }))
    
    return jsonify({
        "shared_with_me": [
            {
                "share_id": str(share["_id"]),
                "filename": share["filename"],
                "owner_id": share["owner_id"],
                "permission": share["permission"],
                "created_at": share["created_at"].strftime("%Y-%m-%d %H:%M"),
                "expires_at": share["expires_at"].strftime("%Y-%m-%d %H:%M")
            } for share in shared_with_me
        ],
        "shared_by_me": [
            {
                "share_id": str(share["_id"]),
                "filename": share["filename"],
                "recipient_id": share["recipient_id"],
                "permission": share["permission"],
                "created_at": share["created_at"].strftime("%Y-%m-%d %H:%M"),
                "expires_at": share["expires_at"].strftime("%Y-%m-%d %H:%M")
            } for share in shared_by_me
        ]
    })

@app.route("/shared-file/<owner_id>/<filename>")
@login_required
def shared_file(owner_id, filename):
    blockchain.add_block({
        "action": "shared_file_accessed",
        "filename": filename,
        "owner_id": owner_id,
        "accessor_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    # Verify the current user has access to this file
    share = mongo.db.shares.find_one({
        "owner_id": owner_id,
        "recipient_id": current_user.id,
        "filename": filename
    })
    
    if not share:
        return jsonify({"status": "error", "message": "Access denied"}), 403
    
    # Stream the file from owner's folder
    ssh = ssh_connect()
    if not ssh:
        return jsonify({"status": "error", "message": "Connection error"}), 500
        
    try:
        sftp = ssh.open_sftp()
        remote_path = f"/home/{VPS_USERNAME}/SFS/{owner_id}/{filename}"
        
        try:
            sftp.stat(remote_path)
        except FileNotFoundError:
            return jsonify({"status": "error", "message": "File not found"}), 404
            
        # For preview requests, don't send as attachment
        is_download = request.args.get('download') == 'true'
        
        if is_download and share["permission"] == "preview":
            return jsonify({"status": "error", "message": "Download not permitted"}), 403
            
        file_obj = io.BytesIO()
        sftp.getfo(remote_path, file_obj)
        file_obj.seek(0)
        ciphertext = file_obj.read()

        key_doc = mongo.db.encryption.find_one({
            "user_id": owner_id,
            "filename": filename
        })
        if not key_doc:
            return jsonify({"status": "error", "message": "Encryption metadata not found"}), 500
        
        try:
            decrypted_data = decrypt_file_data(
                ciphertext,
                key_doc["key"],
                key_doc["iv"],
                key_doc["tag"]
            )
        except Exception as e:
            return jsonify({"status": "error", "message": f"Decryption failed: {str(e)}"}), 500
        
        file_obj = io.BytesIO(decrypted_data)
        return send_file(
            file_obj,
            mimetype=get_file_type(filename),
            as_attachment=is_download,
            download_name=filename if is_download else None
        )
    finally:
        if ssh:
            ssh.close()

@app.route("/logs")
@login_required
def view_logs():
    # Log access to logs (meta-logging!)
    blockchain.add_block({
        "action": "logs_accessed",
        "user_id": current_user.id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    
    return render_template("logs.html", logs=blockchain.get_all_blocks(), is_chain_valid=blockchain.is_chain_valid())

@app.route("/test-blockchain")
def test_blockchain():
    # Add test blocks
    blockchain.add_block({"action": "test1", "data": "Sample data 1"})
    blockchain.add_block({"action": "test2", "data": "Sample data 2"})
    
    # Return chain info
    return jsonify({
        "chain_length": len(blockchain.chain),
        "is_valid": blockchain.is_chain_valid(),
        "blocks": blockchain.get_all_blocks()
    })

@app.route("/user-logs")
@login_required
def user_logs():
    user_id = current_user.id
    user_logs = [
        block for block in blockchain.get_all_blocks()
        if isinstance(block.get("data"), dict) and block["data"].get("user_id") == user_id
    ]

    blockchain.add_block({
        "action": "view_user_logs",
        "user_id": user_id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })

    return render_template("user_logs.html", logs=user_logs)


@app.route("/user-logs/download")
@login_required
def download_user_logs():
    user_id = current_user.id
    user_logs = [block for block in blockchain.get_all_blocks() if block["data"].get("user_id") == user_id]

    # Log the download action
    blockchain.add_block({
        "action": "export_user_logs_csv",
        "user_id": user_id,
        "ip": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })

    output = []
    headers = ["timestamp", "action", "filename", "ip", "error", "permission"]
    output.append(headers)

    for log in user_logs:
        data = log.get("data", {})
        output.append([
            log.get("timestamp", ""),
            data.get("action", ""),
            data.get("filename", ""),
            data.get("ip", ""),
            data.get("error", ""),
            data.get("permission", "")
        ])

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerows(output)
    response = make_response(si.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={user_id}_logs.csv"
    response.headers["Content-type"] = "text/csv"
    return response

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
