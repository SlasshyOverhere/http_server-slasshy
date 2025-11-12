import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import socket
import os
import subprocess
import sys
from pathlib import Path
from flask import Flask, render_template_string, send_from_directory, request, Response
from functools import wraps
import secrets
import qrcode
from PIL import Image, ImageTk
from io import BytesIO
import json
import time
import re
import shutil
import webbrowser
import logging

class FileServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LAN File Server - Share Files Instantly")
        self.root.geometry("750x850")
        self.root.resizable(False, False)
        
        # Config file path
        self.config_file = self.get_config_path()
        self.config = self.load_config()
        
        # Variables
        self.selected_directory = tk.StringVar(value="No directory selected")
        self.server_status = tk.StringVar(value="Server Status: Stopped")
        self.server_url = tk.StringVar(value="")
        self.tunnel_url = tk.StringVar(value="")
        self.password_enabled = tk.BooleanVar(value=False)
        self.password_value = tk.StringVar()
        self.tunnel_enabled = tk.BooleanVar(value=False)
        self.port = tk.IntVar(value=8080)
        self.cloudflared_path = tk.StringVar(value=self.config.get('cloudflared_path', ''))
        
        # Server objects
        self.flask_app = None
        self.server_thread = None
        self.tunnel_process = None
        self.is_running = False
        self.qr_photo = None
        
        # Setup Flask logging to GUI
        self.setup_logging()
        
        self.create_widgets()
        
    def setup_logging(self):
        """Setup logging to redirect Flask logs to GUI"""
        self.log_handler = GUILogHandler(self)
        self.log_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
        self.log_handler.setFormatter(formatter)
        
    def get_config_path(self):
        """Get config file path - works for both script and exe"""
        try:
            if getattr(sys, 'frozen', False):
                app_dir = os.path.dirname(sys.executable)
            else:
                app_dir = os.path.dirname(os.path.abspath(__file__))
            
            return os.path.join(app_dir, 'lan_file_server_config.json')
        except Exception as e:
            return 'lan_file_server_config.json'
    
    def load_config(self):
        """Load configuration from JSON file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def save_config(self):
        """Save configuration to JSON file"""
        try:
            self.config['cloudflared_path'] = self.cloudflared_path.get()
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.log("✅ Configuration saved")
        except Exception as e:
            self.log(f"❌ Failed to save config: {e}")
    
    def create_widgets(self):
        # Title
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(title_frame, text="🚀 LAN File Server", font=("Arial", 18, "bold"))
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, text="Share files instantly over your local network or the internet", font=("Arial", 9))
        subtitle_label.pack()
        
        credits_label = ttk.Label(title_frame, text="Created by Suman Patgiri © 2025", font=("Arial", 8, "italic"), foreground="gray")
        credits_label.pack(pady=(2, 0))
        
        # Directory Selection
        dir_frame = ttk.LabelFrame(self.root, text="📁 Directory Selection", padding="10")
        dir_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(dir_frame, textvariable=self.selected_directory, wraplength=650).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(dir_frame, text="Browse", command=self.select_directory).pack(side=tk.RIGHT)
        
        # Server Configuration
        config_frame = ttk.LabelFrame(self.root, text="⚙️ Server Configuration", padding="10")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Port
        port_frame = ttk.Frame(config_frame)
        port_frame.pack(fill=tk.X, pady=2)
        ttk.Label(port_frame, text="Port:", width=15).pack(side=tk.LEFT)
        ttk.Spinbox(port_frame, from_=1024, to=65535, textvariable=self.port, width=10).pack(side=tk.LEFT)
        
        # Password Protection
        password_frame = ttk.Frame(config_frame)
        password_frame.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(password_frame, text="🔒 Enable Password Protection", variable=self.password_enabled, command=self.toggle_password).pack(side=tk.LEFT)
        
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_value, show="*", width=20, state=tk.DISABLED)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        self.generate_btn = ttk.Button(password_frame, text="Generate", command=self.generate_password, state=tk.DISABLED)
        self.generate_btn.pack(side=tk.LEFT)
        
        ttk.Label(config_frame, text="💡 Tip: Username is same as password when logging in", font=("Arial", 8, "italic"), foreground="blue").pack(anchor=tk.W, pady=(2, 0))
        
        # Tunnel Configuration
        tunnel_frame = ttk.Frame(config_frame)
        tunnel_frame.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(tunnel_frame, text="🌐 Expose to Internet (Cloudflare Tunnel)", variable=self.tunnel_enabled).pack(side=tk.LEFT)
        
        # Cloudflared Path Configuration
        cloudflared_frame = ttk.LabelFrame(self.root, text="🔧 Cloudflared Configuration", padding="10")
        cloudflared_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(cloudflared_frame, text="Cloudflared Path:", width=15).pack(side=tk.LEFT)
        ttk.Entry(cloudflared_frame, textvariable=self.cloudflared_path, state="readonly", width=40).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(cloudflared_frame, text="Browse", command=self.browse_cloudflared).pack(side=tk.LEFT, padx=2)
        ttk.Button(cloudflared_frame, text="Clear", command=self.clear_cloudflared_path).pack(side=tk.LEFT, padx=2)
        
        # Server Controls
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X, padx=10)
        
        self.start_btn = ttk.Button(control_frame, text="▶ Start Server", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Status Display
        status_frame = ttk.LabelFrame(self.root, text="📊 Server Status", padding="10")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(status_frame, textvariable=self.server_status, font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        # Local URL
        url_frame = ttk.Frame(status_frame)
        url_frame.pack(fill=tk.X, pady=3)
        ttk.Label(url_frame, text="Local URL:", font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Entry(url_frame, textvariable=self.server_url, state="readonly", width=40).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.copy_local_btn = ttk.Button(url_frame, text="Copy", command=lambda: self.copy_to_clipboard(self.server_url.get()), state=tk.DISABLED)
        self.copy_local_btn.pack(side=tk.LEFT)
        
        # Tunnel URL
        tunnel_url_frame = ttk.Frame(status_frame)
        tunnel_url_frame.pack(fill=tk.X, pady=3)
        ttk.Label(tunnel_url_frame, text="Internet URL:", font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Entry(tunnel_url_frame, textvariable=self.tunnel_url, state="readonly", width=40).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.copy_tunnel_btn = ttk.Button(tunnel_url_frame, text="Copy", command=lambda: self.copy_to_clipboard(self.tunnel_url.get()), state=tk.DISABLED)
        self.copy_tunnel_btn.pack(side=tk.LEFT)
        
        # QR Code Display (SMALLER)
        qr_frame = ttk.LabelFrame(self.root, text="📱 QR Code", padding="5")
        qr_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.qr_label = ttk.Label(qr_frame, text="QR will appear when server starts", anchor=tk.CENTER)
        self.qr_label.pack()
        
        # Log Display (ALWAYS VISIBLE)
        log_frame = ttk.LabelFrame(self.root, text="📝 Server Logs (Live)", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED, wrap=tk.WORD, font=("Consolas", 8))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Bottom Credits
        footer_frame = ttk.Frame(self.root)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ttk.Label(footer_frame, text="© 2025 Suman Patgiri | All Rights Reserved", font=("Arial", 8), foreground="gray", anchor=tk.CENTER).pack(pady=5)
    
    def select_directory(self):
        directory = filedialog.askdirectory(title="Select Directory to Share")
        if directory:
            self.selected_directory.set(directory)
            self.log(f"📁 Selected directory: {directory}")
    
    def browse_cloudflared(self):
        file_path = filedialog.askopenfilename(title="Select cloudflared.exe", filetypes=[("Executable files", "*.exe"), ("All files", "*.*")])
        if file_path:
            if self.verify_cloudflared(file_path):
                self.cloudflared_path.set(file_path)
                self.save_config()
                self.log(f"✅ Cloudflared path set: {file_path}")
            else:
                messagebox.showerror("Invalid File", "The selected file is not a valid cloudflared executable.")
    
    def clear_cloudflared_path(self):
        self.cloudflared_path.set('')
        self.save_config()
        self.log("🗑️ Cloudflared path cleared")
    
    def verify_cloudflared(self, path):
        try:
            result = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=5)
            output = (result.stdout + result.stderr).lower()
            return 'cloudflared' in output and 'version' in output
        except Exception:
            return False
    
    def toggle_password(self):
        if self.password_enabled.get():
            self.password_entry.config(state=tk.NORMAL)
            self.generate_btn.config(state=tk.NORMAL)
        else:
            self.password_entry.config(state=tk.DISABLED)
            self.generate_btn.config(state=tk.DISABLED)
    
    def generate_password(self):
        password = secrets.token_urlsafe(12)
        self.password_value.set(password)
        self.log(f"🔑 Generated password: {password}")
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def log(self, message):
        try:
            self.log_text.config(state=tk.NORMAL)
            timestamp = time.strftime('%H:%M:%S')
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        except Exception:
            pass
    
    def copy_to_clipboard(self, text):
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log("📋 URL copied to clipboard")
    
    def generate_qr_code(self, url):
        try:
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=4, border=2)
            qr.add_data(url)
            qr.make(fit=True)
            
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_img = qr_img.resize((150, 150), Image.Resampling.LANCZOS)
            
            self.qr_photo = ImageTk.PhotoImage(qr_img)
            self.qr_label.config(image=self.qr_photo, text="")
            self.log(f"📱 QR Code generated")
        except Exception as e:
            self.log(f"❌ QR Code failed: {e}")
    
    def get_cloudflared_command(self):
        custom_path = self.cloudflared_path.get()
        if custom_path and os.path.exists(custom_path):
            return custom_path
        if shutil.which('cloudflared'):
            return 'cloudflared'
        return None
    
    def show_cloudflared_instructions(self):
        try:
            instructions_window = tk.Toplevel(self.root)
            instructions_window.title("Install Cloudflared")
            instructions_window.geometry("600x400")
            
            tk.Label(instructions_window, text="📦 Cloudflared Required", font=("Arial", 14, "bold"), pady=10).pack()
            
            msg = """To use Internet Tunnel:

1. Click 'Download' button below
2. Save cloudflared.exe anywhere
3. Click 'Browse' in app and select it
4. Done!

Alternative: Add to System PATH
"""
            
            text_widget = tk.Text(instructions_window, wrap=tk.WORD, height=12, padx=20, pady=10)
            text_widget.insert("1.0", msg)
            text_widget.config(state=tk.DISABLED)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            btn_frame = ttk.Frame(instructions_window)
            btn_frame.pack(pady=10)
            
            ttk.Button(btn_frame, text="📥 Download", command=lambda: webbrowser.open("https://github.com/cloudflare/cloudflared/releases/latest")).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Close", command=instructions_window.destroy).pack(side=tk.LEFT, padx=5)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open instructions: {e}")
    
    def create_flask_app(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = secrets.token_hex(16)
        
        # Add custom logger to redirect to GUI
        app.logger.addHandler(self.log_handler)
        app.logger.setLevel(logging.INFO)
        
        # Disable werkzeug default logging to console
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        directory = self.selected_directory.get()
        password = self.password_value.get() if self.password_enabled.get() else None
        
        def check_auth(pwd):
            return pwd == password
        
        def authenticate():
            return Response('Password Required\nUsername is same as password.\n', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        
        def requires_auth(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not password:
                    return f(*args, **kwargs)
                auth = request.authorization
                if not auth or not check_auth(auth.password):
                    return authenticate()
                return f(*args, **kwargs)
            return decorated
        
        def get_client_ip():
            """Get real client IP address"""
            if request.environ.get('HTTP_X_FORWARDED_FOR'):
                return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
            elif request.environ.get('HTTP_X_REAL_IP'):
                return request.environ['HTTP_X_REAL_IP']
            else:
                return request.environ.get('REMOTE_ADDR', 'Unknown')
        
        HTML_TEMPLATE = '''<!DOCTYPE html>
<html><head>
<title>File Server</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta charset="UTF-8">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, system-ui, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 10px; }
.container { max-width: 900px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
.header h1 { font-size: 1.8em; margin-bottom: 8px; }
.header p { opacity: 0.9; font-size: 0.9em; }
.credits { font-size: 0.75em; opacity: 0.8; margin-top: 8px; font-style: italic; }
.content { padding: 15px; }
.file-list { list-style: none; }
.file-item { display: flex; align-items: center; padding: 12px; margin-bottom: 8px; background: #f8f9fa; border-radius: 10px; transition: all 0.3s; flex-wrap: wrap; gap: 10px; }
.file-item:hover { background: #e9ecef; transform: translateX(3px); }
.file-icon { font-size: 1.8em; min-width: 40px; text-align: center; }
.file-info { flex: 1; min-width: 150px; }
.file-name { font-weight: 500; word-break: break-word; font-size: 0.95em; }
.file-size { color: #6c757d; font-size: 0.85em; margin-top: 2px; }
.download-btn { background: #667eea; color: white; border: none; padding: 10px 18px; border-radius: 8px; cursor: pointer; text-decoration: none; font-size: 0.9em; white-space: nowrap; }
.download-btn:hover { background: #5568d3; }
.breadcrumb { padding: 12px 0; color: #6c757d; margin-bottom: 15px; border-bottom: 2px solid #e9ecef; font-size: 0.9em; overflow-x: auto; }
.breadcrumb a { color: #667eea; text-decoration: none; margin-right: 5px; }
.empty-state { text-align: center; padding: 40px 20px; color: #6c757d; }
.footer { background: #f8f9fa; text-align: center; padding: 15px; border-top: 2px solid #e9ecef; color: #6c757d; font-size: 0.85em; }
@media (max-width: 600px) {
  body { padding: 5px; }
  .header h1 { font-size: 1.5em; }
  .file-item { flex-direction: column; align-items: flex-start; }
  .file-info { width: 100%; }
  .download-btn { width: 100%; padding: 12px; text-align: center; }
}
</style>
</head><body>
<div class="container">
<div class="header">
<h1>🚀 File Server</h1>
<p>Browse and download files</p>
<div class="credits">Created by Suman Patgiri © 2025</div>
</div>
<div class="content">
<div class="breadcrumb">📁 <a href="/">Home</a> {{ breadcrumb }}</div>
{% if items %}
<ul class="file-list">
{% for item in items %}
<li class="file-item">
<span class="file-icon">{{ item.icon }}</span>
<div class="file-info">
<div class="file-name">{{ item.name }}</div>
<div class="file-size">{{ item.size }}</div>
</div>
<a href="{{ item.url }}" class="download-btn">{{ 'Open' if item.is_dir else 'Download' }}</a>
</li>
{% endfor %}
</ul>
{% else %}
<div class="empty-state"><h2>📭 Empty Directory</h2></div>
{% endif %}
</div>
<div class="footer">© 2025 Suman Patgiri | All Rights Reserved</div>
</div>
</body></html>'''
        
        def get_file_size(size):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
        
        @app.route('/')
        @app.route('/<path:subpath>')
        @requires_auth
        def browse(subpath=''):
            try:
                client_ip = get_client_ip()
                full_path = os.path.join(directory, subpath)
                
                if os.path.isfile(full_path):
                    file_size = os.path.getsize(full_path)
                    self.log(f"📥 Download: {os.path.basename(full_path)} ({get_file_size(file_size)}) from {client_ip}")
                    return send_from_directory(directory, subpath, as_attachment=True)
                
                # Log directory access
                if subpath:
                    self.log(f"👁️ Browse: /{subpath} from {client_ip}")
                else:
                    self.log(f"🌐 Connected: {client_ip}")
                
                items = []
                for item in sorted(os.listdir(full_path)):
                    if item.startswith('.'):
                        continue
                    
                    item_path = os.path.join(full_path, item)
                    is_dir = os.path.isdir(item_path)
                    
                    items.append({
                        'name': item,
                        'icon': '📁' if is_dir else '📄',
                        'is_dir': is_dir,
                        'size': get_file_size(os.path.getsize(item_path)) if not is_dir else '—',
                        'url': f"/{os.path.join(subpath, item).replace(os.sep, '/')}"
                    })
                
                breadcrumb = ' / '.join([
                    f'<a href="/{"/".join(subpath.split(os.sep)[:i+1])}">{part}</a>'
                    for i, part in enumerate(subpath.split(os.sep)) if part
                ])
                
                return render_template_string(HTML_TEMPLATE, items=items, breadcrumb=breadcrumb)
            
            except Exception as e:
                self.log(f"❌ Error: {str(e)}")
                return f"Error: {str(e)}", 500
        
        return app
    
    def start_server(self):
        if self.selected_directory.get() == "No directory selected":
            messagebox.showerror("Error", "Please select a directory first!")
            return
        
        if self.password_enabled.get() and not self.password_value.get():
            messagebox.showerror("Error", "Please enter or generate a password!")
            return
        
        try:
            self.is_running = True
            self.flask_app = self.create_flask_app()
            
            self.server_thread = threading.Thread(target=self.run_flask, daemon=True)
            self.server_thread.start()
            
            local_ip = self.get_local_ip()
            port = self.port.get()
            local_url = f"http://{local_ip}:{port}"
            self.server_url.set(local_url)
            
            self.server_status.set("Server Status: Running ✅")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.copy_local_btn.config(state=tk.NORMAL)
            
            self.log(f"🚀 Server started on {local_url}")
            
            if self.password_enabled.get():
                self.log(f"🔒 Password: {self.password_value.get()} (username is same as password)")
            
            self.generate_qr_code(local_url)
            
            if self.tunnel_enabled.get():
                self.start_tunnel()
        
        except Exception as e:
            self.log(f"❌ Error starting server: {e}")
            messagebox.showerror("Error", f"Failed to start server: {e}")
            self.is_running = False
    
    def run_flask(self):
        try:
            self.flask_app.run(host='0.0.0.0', port=self.port.get(), debug=False, use_reloader=False, threaded=True)
        except Exception as e:
            self.log(f"❌ Flask error: {e}")
    
    def start_tunnel(self):
        try:
            self.log("🔍 Checking for cloudflared...")
            
            cf_command = self.get_cloudflared_command()
            
            if not cf_command:
                self.log("❌ cloudflared not found")
                self.show_cloudflared_instructions()
                return
            
            self.log(f"✅ Using: {cf_command}")
            
            port = self.port.get()
            self.log(f"🌐 Starting Cloudflare tunnel...")
            
            self.tunnel_process = subprocess.Popen(
                [cf_command, 'tunnel', '--url', f'http://localhost:{port}'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            def monitor_tunnel():
                try:
                    while self.tunnel_process.poll() is None:
                        line = self.tunnel_process.stderr.readline()
                        if line and 'https://' in line and 'trycloudflare.com' in line:
                            url_match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                            if url_match:
                                url = url_match.group(0)
                                self.tunnel_url.set(url)
                                self.copy_tunnel_btn.config(state=tk.NORMAL)
                                self.log(f"✅ Tunnel URL: {url}")
                                self.generate_qr_code(url)
                                break
                except Exception as e:
                    self.log(f"❌ Tunnel error: {e}")
            
            threading.Thread(target=monitor_tunnel, daemon=True).start()
            
        except Exception as e:
            self.log(f"❌ Tunnel error: {e}")
    
    def stop_server(self):
        try:
            self.is_running = False
            
            if self.tunnel_process:
                self.tunnel_process.terminate()
                try:
                    self.tunnel_process.wait(timeout=3)
                except:
                    self.tunnel_process.kill()
                self.tunnel_process = None
            
            self.server_status.set("Server Status: Stopped")
            self.server_url.set("")
            self.tunnel_url.set("")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.copy_local_btn.config(state=tk.DISABLED)
            self.copy_tunnel_btn.config(state=tk.DISABLED)
            self.qr_label.config(image='', text="QR will appear when server starts")
            self.qr_photo = None
            
            self.log("⏹️ Server stopped")
            self.root.after(1000, lambda: os._exit(0))
            
        except Exception as e:
            self.log(f"❌ Stop error: {e}")

class GUILogHandler(logging.Handler):
    """Custom logging handler to redirect Flask logs to GUI"""
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
    
    def emit(self, record):
        msg = self.format(record)
        self.gui.log(msg)

def main():
    try:
        root = tk.Tk()
        app = FileServerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
