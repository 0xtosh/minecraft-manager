# 💎⛏️ Minecraft Server Configuration Manager

A lightweight, web-based management panel for custom Minecraft server administration to allow mod and server administration without giving operating system access. 

---

## Features

### Multi-Stage Security Pipeline
* **Email Whitelisting:** Restricts access explicitly to emails pre-defined in `whitelist.txt`.
* **Time-Based One-Time Password (TOTP):** Seamlessly pairs with Google Authenticator, Aegis, Bitwarden, or any standard authenticator app via an in-memory generated QR code.
* **Workstation Trust Persistence:** Optional 30-day cryptographically signed cookie session mapping for trusted personal devices.
* **Anti-Automation Gateway:** Features an interactive "Slide to Unlock" interface styled after classic Minecraft options grids to mitigate generic bot targeting.

### File & Mod Integrity Management
* **CurseForge Security Check:** Computes custom MurmurHash2 fingerprints locally on jar file streams, querying the CurseForge API to cross-reference integrity blocks before allowing compilation into your production environment.
* **Sandbox Isolation:** Injected paths go through structural validations preventing directory traversal attacks.
* **In-Browser Configuration Engine:** Live view, edit, modify, rename, and delete text layouts/properties maps for system configurations inside a dedicated panel code editor.

### Live Operations Dashboard
* **Docker Integration:** Handles runtime lifecycles (`Start`, `Stop`, `Restart`) using direct sub-process interfaces.
* **Persistent Live Terminal Stream:** Utilizes Server-Sent Events (SSE) to pipe `docker logs -f` into an in-browser console.
* **Real-Time Player Profiles:** Dynamically tracks player sessions out of the thread logs, rendering raw head avatars directly from skin services without truncation or desyncs.
* **Automated Backups:** Safely locks container access threads, generates snapshot backups of your `world/` maps with precise time stamps, and safely restarts the engine automatically.

---

## Network Deployment Configurations

Because this application controls your underlying system's Docker daemon, exposing it safely is a priority. You can expose and secure the dashboard over the internet using these primary routing strategies:

### Option A: Local Port Forwarding + Access Control List (ACL)
1. Configure your network router to pass an open external port directly to the machine's local hosting adapter (Default port: `7777`).
2. **Crucial:** Restrict incoming connections at your router or local OS firewall layer using an explicit **Access Control List (ACL)**, whitelist-allowing only known static external IPs (e.g., your workplace or home IP) to communicate with that socket.

### Option B: Remote VPS Reverse Proxy (Direct Routing)
If your home environment is hidden behind Carrier-Grade NAT (CGNAT) or you want to protect your home IP address:
1. Establish a cloud-hosted Virtual Private Server (VPS) carrying a static public IP to act as your external edge router.
2. Install a web engine (like Nginx or Caddy) on the cloud instance configured as a reverse proxy, mapping encrypted traffic downward to your home network setup.

### Option C: Reverse SSH Tunneling (Recommended for Hidden Hosts)
To expose the web application safely without altering local router security profiles or punching outward-facing firewall holes:
1. Fire up a remote VPS instance.
2. Initiate a persistent reverse SSH connection *outward* from your local Minecraft server host toward your cloud VPS using a loop back bridge:
   ```bash ssh -R 7777:localhost:7777 user@your-vps-ip -N```
3. Configure your VPS reverse proxy layout to point directly to incoming requests bound to the machine's internal loopback socket (`localhost:7777`).

##  Installation & Setup

### 1. Clone the Architecture

git clone [https://github.com/your-username/minecraft-manager.git](https://github.com/your-username/minecraft-manager.git)
cd minecraft-manager


### 2. Install Required Dependencies

Ensure you have Python installed, along with the required libraries:

```pip install flask python-dotenv requests pyotp qrcode itsdangerous werkzeug pillow```


### 3. File Permissions & Group Management 

To ensure both the Flask web server application and the Minecraft daemon/Docker container can safely manage the file tree without permissions collisions, the raw files within your Minecraft directory must share common permission contexts.

The Minecraft server data files must be owned by a shared user group that contains both the system user running your Flask application as well as the system user running your Minecraft instance.
```
# Create a shared group if it does not exist
sudo groupadd mc-managers

# Add your Flask application execution user to the group
sudo usermod -aG mc-managers $USER

# Add the system Minecraft user to the group
sudo usermod -aG mc-managers minecraft

# Set group ownership on your Minecraft data directory
sudo chown -R :mc-managers /opt/minecraft/data

# Ensure the group has read, write, and execute permissions on directories
sudo chmod -R 775 /opt/minecraft/data
sudo chmod g+s /opt/minecraft/data
```

Note: Ensure your Flask application execution user account also belongs to the local machine's docker system permissions group to permit seamless API sub-process control loops.

### 4. Configure the Environment

Create and adjust your target .env settings map inside the core folder directory:
```
FLASK_SECRET_KEY=your_highly_cryptographic_random_string_here
CURSEFORGE_API_KEY=your_official_curseforge_production_api_key_here
```

### 5. Adjust Application Configuration

Open app.py and modify the system config constants to match your host layout:
```
MC_DIR = "/opt/minecraft/data"  # Absolute path to your server's data mount folder
CONTAINER_NAME = "minecraft"   # Exact name assigned to your Docker minecraft container
```

### 6. Setup Access Rights

Add authorized email strings straight into whitelist.txt (one individual email address per line):
```
admin@example.com
player1@domain.com
```

### 7. Run the Panel Application
```
python app.py
```

The panel will execute immediately on http://0.0.0.0:7777.
