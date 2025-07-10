import os, time
import paramiko
import mimetypes
import pyotp
import io
import csv
import json
from flask import Flask, render_template, redirect, url_for, abort, Response, request, session
from dotenv import load_dotenv
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from dotenv import load_dotenv, dotenv_values
from pymongo import MongoClient
from blockchain import Blockchain
from datetime import datetime
from pathlib import Path

# Suppress Blowfish deprecation warning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["users"]

project_root = Path(__file__).resolve().parent
load_dotenv(dotenv_path=project_root / ".env")

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', os.urandom(24))

# Configuration
VPS_HOST = os.getenv('VPS_HOST')
VPS_PORT = int(os.getenv('VPS_PORT', 22))
VPS_USERNAME = os.getenv('VPS_USERNAME')
VPS_PASSWORD = os.getenv('VPS_PASSWORD')
BASE_PATH = f"/home/{VPS_USERNAME}/SFS/"
TOTP_SECRET = os.getenv('TOTP_SECRET')

def login_required(f):
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__  # Preserve the original function name
    return decorated

def get_sftp():
    try:
        transport = paramiko.Transport((VPS_HOST, VPS_PORT))
        transport.connect(username=VPS_USERNAME, password=VPS_PASSWORD)
        sftp = paramiko.SFTPClient.from_transport(transport)
        return sftp, transport
    except Exception as e:
        print(f"Connection error: {e}")
        return None, None

def get_current_totp():
    """Reload the .env file and get current TOTP secret"""
    current_env = dotenv_values('.env')  # Reload .env file
    return pyotp.TOTP(current_env.get('TOTP_SECRET', ''))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('browse', subpath=''))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        totp = get_current_totp()
        
        # Allow for time drift (30 seconds window)
        if totp.verify(otp, valid_window=1):
            session['authenticated'] = True
            session.permanent = True
            next_url = request.args.get('next') or url_for('browse', subpath='')
            return redirect(next_url)
        
        # Also check previous OTP in case of transition
        time.sleep(1)  # Small delay to prevent brute force
        return render_template('admin_login.html', error="Invalid OTP. Ensure your authenticator is synced.")
    
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def root():
    return redirect(url_for('browse', subpath=''))

@app.route('/browse/')
@app.route('/browse/<path:subpath>')
@login_required
def browse(subpath=''):
    sftp, transport = get_sftp()
    if not sftp:
        return "Connection failed", 500

    try:
        full_path = os.path.join(BASE_PATH, subpath).replace('\\', '/')
        items = sftp.listdir_attr(full_path)
        
        dirs = []
        files = []
        for item in items:
            if item.filename.startswith('.'):
                continue
            if item.st_mode & 0o40000:
                dirs.append({
                    'name': item.filename,
                    'size': f"{item.st_size/1024:.1f} KB",
                    'modified': item.st_mtime
                })
            else:
                files.append({
                    'name': item.filename,
                    'size': f"{item.st_size/1024:.1f} KB",
                    'modified': item.st_mtime
                })
        
        dirs.sort(key=lambda x: x['name'].lower())
        files.sort(key=lambda x: x['name'].lower())
        
        parent = os.path.dirname(subpath.rstrip('/'))
        transport.close()
        return render_template('index.html', 
                            dirs=dirs, 
                            files=files, 
                            current_path=subpath,
                            parent=parent)
    except Exception as e:
        print(f"Error: {e}")
        if transport:
            transport.close()
        abort(404)

@app.route('/download/<path:filepath>')
@login_required
def download(filepath):
    sftp, transport = get_sftp()
    if not sftp:
        return "Connection failed", 500

    try:
        full_path = os.path.join(BASE_PATH, filepath).replace('\\', '/')
        filename = os.path.basename(full_path)
        
        file = sftp.file(full_path, 'rb')
        content = file.read()
        file.close()
        
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        transport.close()
        response = Response(
            content,
            mimetype=mime_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Length": str(len(content))
            }
        )
        return response
    except Exception as e:
        print(f"Error downloading: {e}")
        if transport:
            transport.close()
        abort(404)

@app.route('/delete/<path:target>', methods=['POST'])
@login_required
def delete(target):
    sftp, transport = get_sftp()
    if not sftp:
        return "Connection failed", 500

    try:
        full_path = os.path.join(BASE_PATH, target).replace('\\', '/')
        if sftp.stat(full_path).st_mode & 0o40000:
            sftp.rmdir(full_path)
        else:
            sftp.remove(full_path)
        transport.close()
        return redirect(url_for('browse', subpath=os.path.dirname(target.rstrip('/'))))
    except Exception as e:
        print(f"Error deleting: {e}")
        if transport:
            transport.close()
        return "Delete failed", 500

@app.route('/logs')
@login_required
def logs():
    try:
        blockchain = Blockchain(db)
        is_valid = blockchain.is_chain_valid()
        logs = blockchain.get_all_blocks()
        
        # Process logs for display
        processed_logs = []
        for log in logs:
            # Handle both old and new log formats
            if isinstance(log, dict):
                processed = log
            else:
                processed = {
                    "index": log.index,
                    "timestamp": log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else log.timestamp,
                    "data": log.data,
                    "hash": log.hash,
                    "previous_hash": log.previous_hash
                }
            processed_logs.append(processed)
        
        return render_template("logs.html", logs=processed_logs, is_chain_valid=is_valid)
    except Exception as e:
        print(f"[ERROR] Could not load logs: {e}")
        return "Error loading logs", 500

@app.route('/logs/download')
@login_required
def download_logs():
    try:
        blockchain = Blockchain(db)
        logs = blockchain.get_all_blocks()
        
        # Create CSV data
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Block Index', 
            'Timestamp', 
            'Action', 
            'User ID', 
            'Username',
            'Filename',
            'File Size',
            'IP Address',
            'Additional Data',
            'Block Hash',
            'Previous Hash'
        ])
        
        # Write log data
        for log in logs:
            if isinstance(log, dict):
                data = log.get('data', {})
                writer.writerow([
                    log.get('index', ''),
                    log.get('timestamp', ''),
                    data.get('action', ''),
                    data.get('user_id', ''),
                    data.get('username', ''),
                    data.get('filename', ''),
                    data.get('file_size', ''),
                    data.get('ip', ''),
                    json.dumps({k: v for k, v in data.items() 
                              if k not in ['action', 'user_id', 'username', 'filename', 'file_size', 'ip']}),
                    log.get('hash', ''),
                    log.get('previous_hash', '')
                ])
            else:  # Handle Block objects if needed
                data = log.data if isinstance(log.data, dict) else {}
                writer.writerow([
                    log.index,
                    log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else log.timestamp,
                    data.get('action', ''),
                    data.get('user_id', ''),
                    data.get('username', ''),
                    data.get('filename', ''),
                    data.get('file_size', ''),
                    data.get('ip', ''),
                    json.dumps({k: v for k, v in data.items() 
                              if k not in ['action', 'user_id', 'username', 'filename', 'file_size', 'ip']}),
                    log.hash,
                    log.previous_hash
                ])
        
        # Create response
        response = Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=system_logs.csv",
                "Content-Type": "text/csv; charset=utf-8"
            }
        )
        
        # Log the export action
        blockchain.add_block({
            "action": "admin_exported_logs",
            "admin_user": session.get('username', 'admin'),
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })
        
        return response
        
    except Exception as e:
        print(f"[ERROR] Could not export logs: {e}")
        abort(500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)