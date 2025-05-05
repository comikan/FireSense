#!/usr/bin/env python3
"""
FireSense Server Implementation
A comprehensive file storage monitoring system that activates a local server
when new files are uploaded to the FireSense project directory.
"""

import os
import sys
import time
import hashlib
import logging
import signal
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
import mimetypes
import json
import argparse
import ssl
from datetime import datetime
import zipfile
import tarfile
import magic
import shutil
import tempfile
from urllib.parse import urlparse, parse_qs
import webbrowser
import subprocess
import platform

# Configuration Constants
CONFIG = {
    "HOST": "localhost",
    "PORT": 8080,
    "MONITOR_DIR": "FireSense_Uploads",
    "LOG_FILE": "firesense_server.log",
    "MAX_FILE_SIZE": 1024 * 1024 * 100,  # 100MB
    "ALLOWED_EXTENSIONS": {
        'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'],
        'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
        'archives': ['.zip', '.tar', '.gz', '.7z'],
        'data': ['.csv', '.json', '.xml', '.xls', '.xlsx'],
        'code': ['.py', '.js', '.html', '.css', '.php', '.sh']
    },
    "SSL_CERT": None,
    "SSL_KEY": None,
    "AUTO_OPEN_BROWSER": True,
    "THROTTLE_UPLOADS": True,
    "THROTTLE_DELAY": 1,  # seconds
    "MAX_THREADS": 50,
    "BACKUP_DIR": "FireSense_Backups",
    "METADATA_FILE": "firesense_metadata.json"
}

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG["LOG_FILE"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("FireSense")

class FireSenseMetadata:
    """Handles metadata storage and retrieval for uploaded files"""
    
    def __init__(self, metadata_file=CONFIG["METADATA_FILE"]):
        self.metadata_file = metadata_file
        self.metadata = self._load_metadata()
        
    def _load_metadata(self):
        """Load metadata from JSON file"""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading metadata: {e}")
        return {}
    
    def save_metadata(self):
        """Save metadata to JSON file"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
            return False
    
    def add_file(self, file_path, file_hash, file_size, file_type):
        """Add file information to metadata"""
        rel_path = os.path.relpath(file_path, CONFIG["MONITOR_DIR"])
        self.metadata[rel_path] = {
            "hash": file_hash,
            "size": file_size,
            "type": file_type,
            "upload_time": datetime.now().isoformat(),
            "last_accessed": datetime.now().isoformat()
        }
        return self.save_metadata()
    
    def update_access_time(self, file_path):
        """Update last accessed time for a file"""
        rel_path = os.path.relpath(file_path, CONFIG["MONITOR_DIR"])
        if rel_path in self.metadata:
            self.metadata[rel_path]["last_accessed"] = datetime.now().isoformat()
            return self.save_metadata()
        return False
    
    def get_file_info(self, file_path):
        """Get metadata for a specific file"""
        rel_path = os.path.relpath(file_path, CONFIG["MONITOR_DIR"])
        return self.metadata.get(rel_path, None)

class FireSenseFileHandler(FileSystemEventHandler):
    """Handles file system events for the monitored directory"""
    
    def __init__(self, server_instance):
        super().__init__()
        self.server = server_instance
        self.metadata = FireSenseMetadata()
        self.last_upload_time = 0
        
    def on_created(self, event):
        """Called when a file or directory is created"""
        if event.is_directory:
            return
            
        current_time = time.time()
        if CONFIG["THROTTLE_UPLOADS"] and (current_time - self.last_upload_time) < CONFIG["THROTTLE_DELAY"]:
            logger.info(f"Throttling upload: {event.src_path}")
            return
            
        self.last_upload_time = current_time
        logger.info(f"New file detected: {event.src_path}")
        
        # Process the file in a separate thread
        threading.Thread(target=self.process_new_file, args=(event.src_path,)).start()
    
    def process_new_file(self, file_path):
        """Process a newly uploaded file"""
        try:
            # Validate the file
            if not self.validate_file(file_path):
                logger.warning(f"Invalid file removed: {file_path}")
                os.remove(file_path)
                return
                
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Determine file type
            file_type = self.determine_file_type(file_path)
            
            # Add to metadata
            self.metadata.add_file(file_path, file_hash, file_size, file_type)
            
            # Notify the server
            self.server.notify_new_file(file_path)
            
            logger.info(f"Processed new file: {file_path} (Type: {file_type}, Size: {file_size} bytes)")
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
    
    def validate_file(self, file_path):
        """Validate the uploaded file"""
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > CONFIG["MAX_FILE_SIZE"]:
                logger.warning(f"File too large: {file_path} ({file_size} bytes)")
                return False
                
            # Check file extension
            ext = os.path.splitext(file_path)[1].lower()
            allowed = False
            for category in CONFIG["ALLOWED_EXTENSIONS"].values():
                if ext in category:
                    allowed = True
                    break
                    
            if not allowed:
                logger.warning(f"File extension not allowed: {file_path}")
                return False
                
            # Additional validation based on file type
            if ext in CONFIG["ALLOWED_EXTENSIONS"]["archives"]:
                if not self.validate_archive(file_path):
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Validation error for {file_path}: {e}")
            return False
    
    def validate_archive(self, file_path):
        """Validate archive files"""
        try:
            ext = os.path.splitext(file_path)[1].lower()
            
            if ext == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    if zip_ref.testzip() is not None:
                        logger.warning(f"Corrupt ZIP archive: {file_path}")
                        return False
                        
            elif ext in ['.tar', '.gz']:
                try:
                    with tarfile.open(file_path, 'r:*') as tar_ref:
                        tar_ref.getmembers()  # Attempt to read members
                except tarfile.TarError:
                    logger.warning(f"Corrupt TAR archive: {file_path}")
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Archive validation error for {file_path}: {e}")
            return False
    
    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """Calculate file hash for verification"""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def determine_file_type(self, file_path):
        """Determine the file type using both extension and magic numbers"""
        # First try with python-magic
        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            return mime_type
        except:
            pass
            
        # Fall back to extension
        ext = os.path.splitext(file_path)[1].lower()
        for category, extensions in CONFIG["ALLOWED_EXTENSIONS"].items():
            if ext in extensions:
                return f"{category}/{ext[1:]}"
                
        return "unknown"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread"""
    daemon_threads = True

class FireSenseRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the FireSense server"""
    
    def __init__(self, *args, **kwargs):
        self.metadata = FireSenseMetadata()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            
            if path == '/':
                self.handle_root()
            elif path == '/list':
                self.handle_file_list()
            elif path.startswith('/download'):
                self.handle_download(parsed_path)
            elif path == '/status':
                self.handle_status()
            elif path == '/metadata':
                self.handle_metadata()
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal server error")
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            
            if path == '/upload':
                self.handle_upload(content_length)
            elif path == '/search':
                self.handle_search(content_length)
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal server error")
    
    def handle_root(self):
        """Handle root endpoint"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <html>
            <head>
                <title>FireSense Server</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    h1 { color: #ff6600; }
                    .container { max-width: 800px; margin: 0 auto; }
                    .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>FireSense File Storage Server</h1>
                    <p>Welcome to the FireSense server. Available endpoints:</p>
                    
                    <div class="endpoint">
                        <h3>GET /</h3>
                        <p>This information page.</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>GET /list</h3>
                        <p>List all available files.</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>GET /download?file=path</h3>
                        <p>Download a specific file.</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>POST /upload</h3>
                        <p>Upload a new file (multipart form data).</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>GET /status</h3>
                        <p>Get server status information.</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>GET /metadata</h3>
                        <p>Get all file metadata.</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>POST /search</h3>
                        <p>Search files (JSON payload with search criteria).</p>
                    </div>
                </div>
            </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))
    
    def handle_file_list(self):
        """Handle file listing endpoint"""
        try:
            files = []
            base_dir = CONFIG["MONITOR_DIR"]
            
            for root, _, filenames in os.walk(base_dir):
                for filename in filenames:
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, base_dir)
                    files.append({
                        "path": rel_path,
                        "size": os.path.getsize(full_path),
                        "modified": os.path.getmtime(full_path)
                    })
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(files, indent=2).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error generating file list: {e}")
            self.send_error(500, "Error generating file list")
    
    def handle_download(self, parsed_path):
        """Handle file download endpoint"""
        try:
            query = parse_qs(parsed_path.query)
            file_param = query.get('file', [None])[0]
            
            if not file_param:
                self.send_error(400, "File parameter missing")
                return
                
            file_path = os.path.join(CONFIG["MONITOR_DIR"], file_param)
            
            if not os.path.exists(file_path):
                self.send_error(404, "File not found")
                return
                
            if not os.path.isfile(file_path):
                self.send_error(400, "Path is not a file")
                return
                
            # Update access time in metadata
            self.metadata.update_access_time(file_path)
            
            # Determine MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'
                
            # Send file
            self.send_response(200)
            self.send_header('Content-type', mime_type)
            self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}"')
            self.send_header('Content-Length', str(os.path.getsize(file_path)))
            self.end_headers()
            
            with open(file_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
                
        except Exception as e:
            logger.error(f"Error handling download: {e}")
            self.send_error(500, "Error handling download")
    
    def handle_status(self):
        """Handle server status endpoint"""
        try:
            status = {
                "status": "running",
                "start_time": self.server.start_time.isoformat(),
                "uptime": str(datetime.now() - self.server.start_time),
                "files_processed": len(self.metadata.metadata),
                "monitor_directory": CONFIG["MONITOR_DIR"],
                "host": CONFIG["HOST"],
                "port": CONFIG["PORT"],
                "ssl_enabled": bool(CONFIG["SSL_CERT"] and CONFIG["SSL_KEY"])
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(status, indent=2).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error generating status: {e}")
            self.send_error(500, "Error generating status")
    
    def handle_metadata(self):
        """Handle metadata endpoint"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.metadata.metadata, indent=2).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error retrieving metadata: {e}")
            self.send_error(500, "Error retrieving metadata")
    
    def handle_upload(self, content_length):
        """Handle file upload endpoint"""
        try:
            if content_length == 0:
                self.send_error(400, "No file data received")
                return
                
            if content_length > CONFIG["MAX_FILE_SIZE"]:
                self.send_error(413, "File too large")
                return
                
            # Parse multipart form data
            form_data = self.parse_multipart(content_length)
            
            if 'file' not in form_data:
                self.send_error(400, "No file in upload")
                return
                
            file_item = form_data['file'][0]
            filename = file_item['filename']
            file_data = file_item['data']
            
            # Create upload directory if it doesn't exist
            os.makedirs(CONFIG["MONITOR_DIR"], exist_ok=True)
            
            # Save file
            file_path = os.path.join(CONFIG["MONITOR_DIR"], filename)
            
            # Check for existing file
            if os.path.exists(file_path):
                self.send_error(409, "File already exists")
                return
                
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Process the file
            event_handler = self.server.event_handler
            event_handler.process_new_file(file_path)
            
            self.send_response(201)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "path": filename,
                "size": len(file_data)
            }).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error handling upload: {e}")
            self.send_error(500, "Error handling upload")
    
    def handle_search(self, content_length):
        """Handle file search endpoint"""
        try:
            if content_length == 0:
                self.send_error(400, "No search criteria provided")
                return
                
            # Read JSON payload
            data = self.rfile.read(content_length)
            search_criteria = json.loads(data.decode('utf-8'))
            
            # Validate search criteria
            if not isinstance(search_criteria, dict):
                self.send_error(400, "Invalid search criteria format")
                return
                
            # Perform search
            results = []
            for rel_path, meta in self.metadata.metadata.items():
                match = True
                for key, value in search_criteria.items():
                    if key not in meta or str(meta[key]).lower().find(str(value).lower()) == -1:
                        match = False
                        break
                        
                if match:
                    results.append({
                        "path": rel_path,
                        "metadata": meta
                    })
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(results, indent=2).encode('utf-8'))
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON payload")
        except Exception as e:
            logger.error(f"Error handling search: {e}")
            self.send_error(500, "Error handling search")
    
    def parse_multipart(self, content_length):
        """Parse multipart form data"""
        # This is a simplified multipart parser - in production consider using a library
        content_type = self.headers.get('Content-Type')
        if not content_type or not content_type.startswith('multipart/form-data'):
            raise ValueError("Not a multipart request")
            
        boundary = content_type.split('boundary=')[1].encode('utf-8')
        remaining = content_length
        form_data = {}
        
        # Read the multipart data
        data = self.rfile.read(content_length)
        
        # Split by boundary
        parts = data.split(b'--' + boundary)
        
        for part in parts:
            if not part.strip():
                continue
                
            headers, body = part.split(b'\r\n\r\n', 1)
            headers = headers.decode('utf-8').split('\r\n')
            
            disposition = None
            for header in headers:
                if header.lower().startswith('content-disposition:'):
                    disposition = header[len('content-disposition:'):].strip()
                    break
                    
            if not disposition:
                continue
                
            # Parse disposition
            disposition_parts = disposition.split(';')
            name = None
            filename = None
            
            for part in disposition_parts:
                part = part.strip()
                if part.startswith('name="'):
                    name = part[len('name="'):-1]
                elif part.startswith('filename="'):
                    filename = part[len('filename="'):-1]
            
            if name and filename:
                # It's a file upload
                if name not in form_data:
                    form_data[name] = []
                    
                form_data[name].append({
                    'filename': filename,
                    'data': body[:-2]  # Remove trailing \r\n
                })
            elif name:
                # It's a form field
                if name not in form_data:
                    form_data[name] = []
                    
                form_data[name].append(body[:-2].decode('utf-8'))  # Remove trailing \r\n
        
        return form_data
    
    def log_message(self, format, *args):
        """Override default logging to use our logger"""
        logger.info("%s - - [%s] %s" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))

class FireSenseServer:
    """Main FireSense server class"""
    
    def __init__(self):
        self.httpd = None
        self.observer = None
        self.event_handler = None
        self.start_time = datetime.now()
        self.running = False
        
    def initialize(self):
        """Initialize the server components"""
        try:
            # Create monitor directory if it doesn't exist
            os.makedirs(CONFIG["MONITOR_DIR"], exist_ok=True)
            
            # Create backup directory if it doesn't exist
            os.makedirs(CONFIG["BACKUP_DIR"], exist_ok=True)
            
            # Initialize file system observer
            self.event_handler = FireSenseFileHandler(self)
            self.observer = Observer()
            self.observer.schedule(self.event_handler, CONFIG["MONITOR_DIR"], recursive=True)
            
            # Initialize HTTP server
            server_address = (CONFIG["HOST"], CONFIG["PORT"])
            self.httpd = ThreadedHTTPServer(server_address, FireSenseRequestHandler)
            self.httpd.event_handler = self.event_handler
            self.httpd.start_time = self.start_time
            
            # Configure SSL if certificates are provided
            if CONFIG["SSL_CERT"] and CONFIG["SSL_KEY"]:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=CONFIG["SSL_CERT"], keyfile=CONFIG["SSL_KEY"])
                self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
                logger.info("SSL/TLS enabled")
            
            logger.info("FireSense server initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False
    
    def start(self):
        """Start the server"""
        if not self.initialize():
            return False
            
        self.running = True
        
        # Start the file system observer
        self.observer.start()
        logger.info(f"Started monitoring directory: {CONFIG['MONITOR_DIR']}")
        
        # Start the HTTP server in a separate thread
        server_thread = threading.Thread(target=self.httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        logger.info(f"Server started on {CONFIG['HOST']}:{CONFIG['PORT']}")
        
        # Open browser if configured
        if CONFIG["AUTO_OPEN_BROWSER"]:
            protocol = "https" if CONFIG["SSL_CERT"] and CONFIG["SSL_KEY"] else "http"
            url = f"{protocol}://{CONFIG['HOST']}:{CONFIG['PORT']}"
            try:
                webbrowser.open(url)
                logger.info(f"Opened browser at {url}")
            except Exception as e:
                logger.warning(f"Could not open browser: {e}")
        
        return True
    
    def stop(self):
        """Stop the server"""
        if not self.running:
            return
            
        self.running = False
        
        # Stop the file system observer
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("Stopped directory monitoring")
        
        # Stop the HTTP server
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("Stopped HTTP server")
        
        logger.info("FireSense server stopped")
    
    def notify_new_file(self, file_path):
        """Notify about a new file (can be extended for notifications)"""
        logger.info(f"New file ready for access: {file_path}")
        
    def backup_files(self):
        """Create a backup of all files"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"firesense_backup_{timestamp}.zip"
            backup_path = os.path.join(CONFIG["BACKUP_DIR"], backup_name)
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(CONFIG["MONITOR_DIR"]):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, CONFIG["MONITOR_DIR"])
                        zipf.write(file_path, arcname)
            
            # Backup metadata too
            metadata_backup = os.path.join(CONFIG["BACKUP_DIR"], f"metadata_{timestamp}.json")
            shutil.copy2(CONFIG["METADATA_FILE"], metadata_backup)
            
            logger.info(f"Created backup: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="FireSense File Storage Server")
    parser.add_argument('--host', help=f"Host to bind to (default: {CONFIG['HOST']})")
    parser.add_argument('--port', type=int, help=f"Port to listen on (default: {CONFIG['PORT']})")
    parser.add_argument('--dir', help=f"Directory to monitor (default: {CONFIG['MONITOR_DIR']})")
    parser.add_argument('--ssl-cert', help="Path to SSL certificate file")
    parser.add_argument('--ssl-key', help="Path to SSL private key file")
    parser.add_argument('--no-browser', action='store_true', help="Don't open browser automatically")
    parser.add_argument('--max-size', type=int, help=f"Maximum file size in bytes (default: {CONFIG['MAX_FILE_SIZE']})")
    return parser.parse_args()

def update_config_from_args(args):
    """Update configuration from command line arguments"""
    if args.host:
        CONFIG["HOST"] = args.host
    if args.port:
        CONFIG["PORT"] = args.port
    if args.dir:
        CONFIG["MONITOR_DIR"] = args.dir
    if args.ssl_cert:
        CONFIG["SSL_CERT"] = args.ssl_cert
    if args.ssl_key:
        CONFIG["SSL_KEY"] = args.ssl_key
    if args.no_browser:
        CONFIG["AUTO_OPEN_BROWSER"] = False
    if args.max_size:
        CONFIG["MAX_FILE_SIZE"] = args.max_size

def signal_handler(sig, frame):
    """Handle termination signals"""
    logger.info("Received termination signal, shutting down...")
    server.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Parse command line arguments
    args = parse_args()
    update_config_from_args(args)
    
    # Initialize and start server
    server = FireSenseServer()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the server
    if server.start():
        try:
            # Main loop (just keep the program running)
            while server.running:
                time.sleep(1)

                if datetime.now().minute == 0 and datetime.now().second == 0:
                    server.backup_files()
                    
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, shutting down...")
            server.stop()
    else:
        logger.error("Failed to start server")
        sys.exit(1)
