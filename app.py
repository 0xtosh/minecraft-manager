import os
import re
import subprocess
import shutil
import hashlib
import requests
import io
import base64
import json
import secrets
import pyotp
import qrcode
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, flash, make_response
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load custom server environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Configured a stable key signature to persist validation across application reloads
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-key-here")

# --- CONFIGURATION ---
MC_DIR = "/usr/minecraft.dev/data"  # Path where 'world', 'mods', etc., live on the host
CONTAINER_NAME = "mc-server"
CURSEFORGE_API_KEY = os.getenv("CURSEFORGE_API_KEY")

# OTP Specific Configuration
WHITELIST_FILE = "whitelist.txt"
SECRETS_FILE = "user_secrets.json"
SERVER_NAME = "Minecraft Manager"

# API Fingerprint Endpoint for verification
API_URL = "https://api.curseforge.com/v1/fingerprints"
# ---------------------

# Configure dedicated login attempts logger
LOG_FILE_PATH = "login_attempts.log"
logger = logging.getLogger("login_security")
logger.setLevel(logging.INFO)

# Avoid adding multiple handlers if the file is reloaded in Flask debug mode
if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

# Regular expression to clean up terminal formatting escape codes (ANSI colors)
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# --- HELPER FUNCTIONS ---

def get_client_ip():
    """Retrieves the actual client IP, bypassing reverse SSH tunnel loopbacks."""
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # X-Forwarded-For can contain a list of hops: "client, proxy1, proxy2"
        return x_forwarded_for.split(',')[0].strip()
    return request.headers.get('X-Real-IP', request.remote_addr)

def login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('email_stage'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def safe_path(relative_path):
    """Prevents directory traversal attacks"""
    absolute_path = os.path.abspath(os.path.join(MC_DIR, relative_path))
    if absolute_path.startswith(os.path.abspath(MC_DIR)):
        return absolute_path
    raise ValueError("Access Denied: Path traversal detected.")

def is_whitelisted(email):
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w') as f: pass
        return False
    with open(WHITELIST_FILE, 'r') as f:
        whitelist = [line.strip().lower() for line in f if line.strip()]
    return email.strip().lower() in whitelist

def load_user_secrets():
    if not os.path.exists(SECRETS_FILE):
        return {}
    with open(SECRETS_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_user_secret(email, secret):
    data = load_user_secrets()
    data[email] = secret
    with open(SECRETS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def generate_qr_base64(uri):
    """Generates a QR code image entirely in memory as a base64 string."""
    qr = qrcode.QRCode(version=1, box_size=6, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def calculate_curseforge_fingerprint(file_path: str) -> int:
    """
    Computes the CurseForge-specific MurmurHash2 fingerprint for a given file.
    It strips out whitespace bytes (9, 10, 13, 32) and hashes with seed = 1.
    """
    M = 0x5bd1e995  
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file '{file_path}' does not exist.")

    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    whitespace_bytes = {9, 10, 13, 32}
    filtered_data = bytearray(b for b in file_bytes if b not in whitespace_bytes)
    
    length = len(filtered_data)
    h = (1 ^ length) & 0xFFFFFFFF
    
    idx = 0
    while idx <= length - 4:
        k = (filtered_data[idx] | 
             (filtered_data[idx+1] << 8) | 
             (filtered_data[idx+2] << 16) | 
             (filtered_data[idx+3] << 24)) & 0xFFFFFFFF
        
        k = (k * M) & 0xFFFFFFFF
        k = (k ^ (k >> 24)) & 0xFFFFFFFF
        k = (k * M) & 0xFFFFFFFF
        
        h = (h * M) & 0xFFFFFFFF
        h = (h ^ k) & 0xFFFFFFFF
        idx += 4

    rem = length - idx
    if rem == 3:
        h ^= filtered_data[idx+2] << 16
        h ^= filtered_data[idx+1] << 8
        h ^= filtered_data[idx]
        h = (h * M) & 0xFFFFFFFF
    elif rem == 2:
        h ^= filtered_data[idx+1] << 8
        h ^= filtered_data[idx]
        h = (h * M) & 0xFFFFFFFF
    elif rem == 1:
        h ^= filtered_data[idx]
        h = (h * M) & 0xFFFFFFFF

    h = (h ^ (h >> 13)) & 0xFFFFFFFF
    h = (h * M) & 0xFFFFFFFF
    h = (h ^ (h >> 15)) & 0xFFFFFFFF
    
    return h

# --- AUTHENTICATION PIPELINE ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def email_stage():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email or not is_whitelisted(email):
            logger.warning(f"Failed email verification: Attempt with non-whitelisted email '{email}' from IP: {get_client_ip()}")
            flash("Access denied or invalid input.", "error")
            return redirect(url_for('email_stage'))
        
        logger.info(f"Successful email whitelist match: '{email}' from IP: {get_client_ip()}")
        session['auth_email'] = email

        # --- DEVICE TRUST VERIFICATION PIPELINE ---
        # Generate hash signature matching user's specific email context
        cookie_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
        cookie_name = f"trusted_device_{cookie_hash}"
        trusted_token = request.cookies.get(cookie_name)
        
        if trusted_token:
            try:
                serializer = URLSafeTimedSerializer(app.secret_key)
                # Parse and verify signed cookie token validity inside a 30-day bounds window (30 * 24 * 3600 seconds)
                cookie_email = serializer.loads(trusted_token, max_age=30 * 24 * 3600)
                if cookie_email == email:
                    session['logged_in'] = True
                    session['user_email'] = email
                    session.pop('auth_email', None)
                    logger.info(f"Successful login via Trusted Device bypass: '{email}' from IP: {get_client_ip()}")
                    flash("Welcome back! Trusted workstation confirmed.", "success")
                    return redirect(url_for('dashboard'))
            except Exception:
                # Cookie is either tampered, forged, or expired: proceed securely with OTP challenge
                logger.warning(f"Failed Trusted Device bypass attempt: '{email}' (cookie was invalid or expired) from IP: {get_client_ip()}")
                pass

        user_secrets = load_user_secrets()
        
        # If user has no authenticator secret yet, send them to setup screen
        if email not in user_secrets:
            return redirect(url_for('setup_stage'))
        
        # If already registered, go straight to entering the 6-digit code
        return redirect(url_for('verify_stage'))
        
    return render_template('email.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup_stage():
    email = session.get('auth_email')
    if not email:
        return redirect(url_for('email_stage'))
        
    user_secrets = load_user_secrets()
    if email in user_secrets:
        return redirect(url_for('verify_stage'))
        
    if request.method == 'POST':
        # Retrieve the original secret generated during the initial page load
        secret = session.get('pending_secret')
        if not secret:
            logger.warning(f"Failed MFA setup session: Pending secret was missing from session for '{email}' from IP: {get_client_ip()}")
            flash("Session expired. Please restart the login process.", "error")
            return redirect(url_for('email_stage'))
            
        totp = pyotp.TOTP(secret)
        submitted_code = "".join([request.form.get(f'code{i}', '') for i in range(1, 7)])
        
        if totp.verify(submitted_code):
            save_user_secret(email, secret)
            session.pop('pending_secret', None)  # Clear temporary setup key
            session['logged_in'] = True          # Log the user into the configurator panel
            session['user_email'] = email
            logger.info(f"Successful MFA setup and paired: '{email}' with verification code {submitted_code} from IP: {get_client_ip()}")
            flash("Authenticator paired successfully!", "success")

            response = make_response(redirect(url_for('dashboard')))
            
            # If the user verified the warning and checked the trust box, set cookie with path='/'
            if request.form.get('trust_device'):
                serializer = URLSafeTimedSerializer(app.secret_key)
                token = serializer.dumps(email)
                cookie_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
                cookie_name = f"trusted_device_{cookie_hash}"
                # Expire in exactly 30 Days (2,592,000 seconds) scoped to path='/' globally
                response.set_cookie(cookie_name, token, max_age=2592000, httponly=True, secure=False, path='/')
                logger.info(f"User '{email}' chose to trust device from IP: {get_client_ip()}")
                
            return response
        else:
            logger.warning(f"Failed MFA setup verification: '{email}' entered invalid setup code '{submitted_code}' from IP: {get_client_ip()}")
            flash("Invalid code. Please try again with the same QR code.", "error")
            # Re-render UI with the persistent key so they don't have to re-scan
            provisioning_uri = totp.provisioning_uri(name=email, issuer_name=SERVER_NAME)
            qr_code_image = generate_qr_base64(provisioning_uri)
            return render_template('setup.html', qr_code=qr_code_image, secret=secret)

    # --- GET REQUEST ---
    # Generate the secret ONCE and lock it into the session data
    secret = pyotp.random_base32()
    session['pending_secret'] = secret
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name=SERVER_NAME)
    qr_code_image = generate_qr_base64(provisioning_uri)
    
    return render_template('setup.html', qr_code=qr_code_image, secret=secret)

@app.route('/verify', methods=['GET', 'POST'])
def verify_stage():
    email = session.get('auth_email')
    user_secrets = load_user_secrets()
    
    if not email or email not in user_secrets:
        flash("Please log in first.", "error")
        return redirect(url_for('email_stage'))
        
    if request.method == 'POST':
        submitted_code = "".join([request.form.get(f'code{i}', '') for i in range(1, 7)])
        user_secret = user_secrets[email]
        
        totp = pyotp.TOTP(user_secret)
        
        # verify() checks the current code window against server system time
        if totp.verify(submitted_code):
            session.pop('auth_email', None)  # Clear login tracking state upon success
            session['logged_in'] = True      # Grant complete system access
            session['user_email'] = email
            logger.info(f"Successful MFA login: '{email}' verified with code {submitted_code} from IP: {get_client_ip()}")

            response = make_response(redirect(url_for('dashboard')))

            # If the user verified the warning and checked the trust box, set cookie with path='/'
            if request.form.get('trust_device'):
                serializer = URLSafeTimedSerializer(app.secret_key)
                token = serializer.dumps(email)
                cookie_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
                cookie_name = f"trusted_device_{cookie_hash}"
                # Expire in exactly 30 Days (2,592,000 seconds) scoped to path='/' globally
                response.set_cookie(cookie_name, token, max_age=2592000, httponly=True, secure=False, path='/')
                logger.info(f"User '{email}' chose to trust device from IP: {get_client_ip()}")
                
            return response
        else:
            logger.warning(f"Failed MFA login verification: '{email}' entered invalid code '{submitted_code}' from IP: {get_client_ip()}")
            flash("Invalid code. Please try again.", "error")
            
    return render_template('verify.html')

@app.route('/logout')
def logout():
    email = session.get('user_email', 'unknown')
    logger.info(f"User logged out: '{email}' from IP: {get_client_ip()}")
    session.clear()  # Wipes session payload completely to log the user out
    return redirect(url_for('email_stage'))

# --- CORE CONFIGURATOR PANEL FUNCTIONS ---

def get_server_status():
    """Queries Docker engine directly for the exact container lifecycle state"""
    try:
        cmd = f"docker inspect -f '{{{{.State.Status}}}}' {CONTAINER_NAME}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.stdout.strip()  # typical outputs: 'running', 'exited', 'restarting'
    except Exception:
        return "offline"

def get_active_players():
    """Parses standard Minecraft lifecycle patterns sequentially out of the logs"""
    if get_server_status() != "running":
        return []
    
    try:
        # Fetch up to 25,000 lines to guarantee players logging in long ago are processed.
        # Redirect 2>&1 to capture logs even if the container pipes thread logging to stderr.
        cmd = f"docker logs --tail 25000 {CONTAINER_NAME} 2>&1"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        logs = res.stdout.splitlines()
        
        active_players = set()
        
        # Adaptive regular expressions scanning standard INFO lines securely.
        join_pattern = re.compile(r"(?::|\s)\s*([a-zA-Z0-9_\.\*\-]{3,16})\s+joined the (?:game|server)", re.IGNORECASE)
        leave_pattern = re.compile(r"(?::|\s)\s*([a-zA-Z0-9_\.\*\-]{3,16})\s+(?:left the (?:game|server)|lost connection|was kicked|disconnected)", re.IGNORECASE)
        
        for line in logs:
            # Strip ANSI terminal styles/colors
            clean_line = ANSI_ESCAPE.sub('', line)
            
            # Skip lines containing chat bracket indicators to protect against chat spoofing exploits
            if "<" in clean_line or ">" in clean_line:
                continue
            
            # Reset player tracking state if server reboot boundaries are encountered
            lower_line = clean_line.lower()
            if "starting minecraft server" in lower_line or "starting dedicated server" in lower_line or "loading properties" in lower_line or "environment: " in lower_line:
                active_players.clear()
                continue
            
            # Match logins
            join_match = join_pattern.search(clean_line)
            if join_match:
                active_players.add(join_match.group(1))
                continue
                
            # Match logouts
            leave_match = leave_pattern.search(clean_line)
            if leave_match:
                player = leave_match.group(1)
                
                # Search and remove case-insensitively to prevent desyncs
                matched_player = None
                for p in active_players:
                    if p.lower() == player.lower():
                        matched_player = p
                        break
                if matched_player:
                    active_players.remove(matched_player)
                    
        return list(active_players)
    except Exception as e:
        print(f"[Error] Failed to parse active players: {e}")
        return []

# --- PANEL APPLICATION ROUTES ---

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/status')
@login_required
def server_status_api():
    status = get_server_status()
    players = get_active_players() if status == "running" else []
    return jsonify({
        "status": status,
        "players": players
    })

@app.route('/api/server/<action>', methods=['POST'])
@login_required
def server_control(action):
    if action in ['start', 'stop', 'restart']:
        cmd = f"docker {action} {CONTAINER_NAME}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return jsonify({"status": "success", "output": res.stdout or res.stderr})
    return jsonify({"status": "error", "message": "Invalid action"}), 400

@app.route('/api/server/backup', methods=['POST'])
@login_required
def server_backup():
    try:
        # 1. Stop Server
        subprocess.run(f"docker stop {CONTAINER_NAME}", shell=True, check=True)
        
        # 2. Backup World
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        world_path = os.path.join(MC_DIR, "world")
        backup_path = os.path.join(MC_DIR, f"world.{timestamp}")
        
        if os.path.exists(world_path):
            shutil.copytree(world_path, backup_path)
            msg = f"Backup created successfully: world.{timestamp}"
        else:
            msg = "World directory not found, skipping copy. Restarting container..."
            
        # 3. Restart Server
        subprocess.run(f"docker start {CONTAINER_NAME}", shell=True, check=True)
        return jsonify({"status": "success", "output": msg})
    except Exception as e:
        # Safety valve: try to bring server back up if copy fails
        subprocess.run(f"docker start {CONTAINER_NAME}", shell=True)
        return jsonify({"status": "error", "output": str(e)}), 500

@app.route('/api/files/list', methods=['GET'])
@login_required
def list_files():
    rel_subdir = request.args.get('dir', '')  # 'mods' or '' for configs
    try:
        target_dir = safe_path(rel_subdir)
        if not os.path.exists(target_dir):
            return jsonify([])
        
        files = []
        for f in os.listdir(target_dir):
            full_p = os.path.join(target_dir, f)
            if os.path.isfile(full_p):
                files.append({
                    "name": f, 
                    "path": os.path.relpath(full_p, MC_DIR),
                    "is_mod": rel_subdir == 'mods'
                })
        return jsonify(files)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/files/view', methods=['GET'])
@login_required
def view_file():
    try:
        path = safe_path(request.args.get('path'))
        with open(path, 'r', errors='ignore') as f:
            return jsonify({"content": f.read()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/files/save', methods=['POST'])
@login_required
def save_file():
    try:
        path = safe_path(request.json.get('path'))
        content = request.json.get('content')
        with open(path, 'w') as f:
            f.write(content)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    temp_path = None
    try:
        target_dir = safe_path('mods')
        if 'file' not in request.files:
            return jsonify({"error": "No file stream payload provided."}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No designated filename."}), 400
        
        if not file.filename.lower().endswith('.jar'):
            return jsonify({"error": "System policy only allows files carrying .jar extensions."}), 400
        
        filename = secure_filename(file.filename)
        # Write temporarily to execute fingerprint validation
        temp_path = os.path.join(target_dir, f"temp_{filename}")
        file.save(temp_path)
        
        # 1. Block uploads if CurseForge API credentials are not set
        if not CURSEFORGE_API_KEY:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return jsonify({"error": "Security scans are unconfigured. Set CURSEFORGE_API_KEY in server variables."}), 400

        # 2. Compute Custom MurmurHash2 Fingerprint
        fingerprint = calculate_curseforge_fingerprint(temp_path)

        # 3. Query CurseForge Database via Fingerprint Match
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-api-key": CURSEFORGE_API_KEY
        }
        payload = {
            "fingerprints": [fingerprint]
        }
        
        response = requests.post(API_URL, headers=headers, json=payload, timeout=10)
        
        if response.status_code != 200:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return jsonify({"error": f"CurseForge directory connection failed (Status Code: {response.status_code})"}), 400

        data = response.json().get("data", {})
        exact_matches = data.get("exactMatches", [])
        
        if exact_matches:
            # Verification Success! Commit target location write.
            final_path = os.path.join(target_dir, filename)
            if os.path.exists(final_path):
                os.remove(final_path)
            os.rename(temp_path, final_path)
            
            match_info = exact_matches[0].get("file", {})
            return jsonify({
                "status": "success",
                "fingerprint": fingerprint,
                "mod_info": {
                    "modId": match_info.get("modId"),
                    "fileId": match_info.get("id"),
                    "fileName": match_info.get("fileName"),
                    "displayName": match_info.get("displayName")
                }
            })
        else:
            # Verification Failure! Erase bytecode from server.
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return jsonify({
                "status": "unverified",
                "fingerprint": fingerprint,
                "error": "File signature did not match CurseForge listings. Denied for system safety."
            }), 400

    except Exception as e:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/delete', methods=['POST'])
@login_required
def delete_file():
    try:
        path = safe_path(request.json.get('path'))
        os.remove(path)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/files/rename', methods=['POST'])
@login_required
def rename_file():
    try:
        old_path = safe_path(request.json.get('old_path'))
        dir_name = os.path.dirname(old_path)
        new_name = secure_filename(request.json.get('new_name'))
        new_path = os.path.join(dir_name, new_name)
        
        os.rename(old_path, new_path)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- LIVE LOG STREAMING ---
@app.route('/api/logs')
@login_required
def logs_stream():
    def generate():
        # Redirect 2>&1 to ensure stderr is piped to the SSE feed
        proc = subprocess.Popen(
            f"docker logs -f --tail 100 {CONTAINER_NAME} 2>&1",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            yield f"data: {line}\n\n"
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    # Listens on all local network adapters
    app.run(host='0.0.0.0', port=7777, debug=True)
