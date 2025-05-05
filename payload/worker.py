#!/usr/bin/env python3
"""
FireSense Worker Implementation
A robust file processing worker that handles files from the FireSense storage system.
"""

import os
import sys
import time
import json
import logging
import hashlib
import shutil
import threading
import queue
from datetime import datetime
import mimetypes
import magic
import zipfile
import tarfile
import subprocess
from pathlib import Path
import argparse
import signal

# Configuration Constants
CONFIG = {
    "INPUT_DIR": "FireSense_Uploads",
    "PROCESSED_DIR": "FireSense_Processed",
    "FAILED_DIR": "FireSense_Failed",
    "LOG_FILE": "firesense_worker.log",
    "MAX_FILE_SIZE": 1024 * 1024 * 100,  # 100MB
    "WORKER_ID": os.uname().nodename if hasattr(os, 'uname') else 'worker-1',
    "QUEUE_CHECK_INTERVAL": 1,  # seconds
    "MAX_RETRIES": 3,
    "RETRY_DELAY": 5,  # seconds
    "METADATA_FILE": "firesense_worker_metadata.json",
    "THUMBNAIL_DIR": "FireSense_Thumbnails",
    "THUMBNAIL_SIZE": "128x128",
    "ALLOWED_EXTENSIONS": {
        'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'],
        'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
        'archives': ['.zip', '.tar', '.gz', '.7z'],
        'data': ['.csv', '.json', '.xml', '.xls', '.xlsx'],
        'code': ['.py', '.js', '.html', '.css', '.php', '.sh']
    }
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
logger = logging.getLogger("FireSense.Worker")

class FileProcessor:
    """Handles the processing of individual files"""
    
    def __init__(self, worker_id=CONFIG["WORKER_ID"]):
        self.worker_id = worker_id
        self.metadata = self._load_metadata()
        self._ensure_directories()
        
    def _load_metadata(self):
        """Load worker metadata from JSON file"""
        try:
            if os.path.exists(CONFIG["METADATA_FILE"]):
                with open(CONFIG["METADATA_FILE"], 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading metadata: {e}")
        return {"processed_files": {}, "failed_files": {}}
    
    def _save_metadata(self):
        """Save worker metadata to JSON file"""
        try:
            with open(CONFIG["METADATA_FILE"], 'w') as f:
                json.dump(self.metadata, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
            return False
    
    def _ensure_directories(self):
        """Ensure all required directories exist"""
        os.makedirs(CONFIG["INPUT_DIR"], exist_ok=True)
        os.makedirs(CONFIG["PROCESSED_DIR"], exist_ok=True)
        os.makedirs(CONFIG["FAILED_DIR"], exist_ok=True)
        os.makedirs(CONFIG["THUMBNAIL_DIR"], exist_ok=True)
    
    def process_file(self, file_path):
        """Process a single file"""
        file_name = os.path.basename(file_path)
        logger.info(f"[{self.worker_id}] Processing file: {file_name}")
        
        try:
            # Validate the file first
            if not self._validate_file(file_path):
                raise ValueError(f"File validation failed: {file_name}")
            
            # Get file metadata
            file_hash = self._calculate_hash(file_path)
            file_size = os.path.getsize(file_path)
            file_type = self._determine_file_type(file_path)
            
            # Process based on file type
            if file_type.startswith('image/'):
                self._process_image(file_path)
            elif file_type.startswith('document/'):
                self._process_document(file_path)
            elif file_type.startswith('archive/'):
                self._process_archive(file_path)
            else:
                self._process_generic(file_path)
            
            # Create thumbnail if possible
            self._create_thumbnail(file_path)
            
            # Move to processed directory
            processed_path = self._move_to_processed(file_path)
            
            # Update metadata
            self.metadata["processed_files"][file_name] = {
                "hash": file_hash,
                "size": file_size,
                "type": file_type,
                "processed_at": datetime.now().isoformat(),
                "worker": self.worker_id,
                "processed_path": processed_path
            }
            self._save_metadata()
            
            logger.info(f"[{self.worker_id}] Successfully processed: {file_name}")
            return True
            
        except Exception as e:
            logger.error(f"[{self.worker_id}] Error processing {file_name}: {e}")
            self._handle_failed_file(file_path, str(e))
            return False
    
    def _validate_file(self, file_path):
        """Validate the file before processing"""
        try:
            # Check file exists
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File does not exist: {file_path}")
                
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > CONFIG["MAX_FILE_SIZE"]:
                raise ValueError(f"File too large: {file_size} bytes")
                
            # Check file extension
            ext = os.path.splitext(file_path)[1].lower()
            allowed = False
            for category in CONFIG["ALLOWED_EXTENSIONS"].values():
                if ext in category:
                    allowed = True
                    break
                    
            if not allowed:
                raise ValueError(f"File extension not allowed: {ext}")
                
            return True
            
        except Exception as e:
            logger.warning(f"[{self.worker_id}] Validation failed: {e}")
            raise
    
    def _calculate_hash(self, file_path, algorithm='sha256'):
        """Calculate file hash"""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def _determine_file_type(self, file_path):
        """Determine the file type"""
        try:
            # First try with python-magic
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
                
        return "application/octet-stream"
    
    def _process_image(self, file_path):
        pass
    
    def _process_document(self, file_path):
        pass
    
    def _process_archive(self, file_path):
        """Special processing for archive files"""
        # Validate archive integrity
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.zip':
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                if zip_ref.testzip() is not None:
                    raise ValueError("Corrupt ZIP archive")
        elif ext in ['.tar', '.gz']:
            try:
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.getmembers()
            except tarfile.TarError:
                raise ValueError("Corrupt TAR archive")
    
    def _process_generic(self, file_path):
        """Generic file processing"""
        pass
    
    def _create_thumbnail(self, file_path):
        """Create thumbnail for supported file types"""
        try:
            file_type = self._determine_file_type(file_path)
            
            if not file_type.startswith('image/'):
                return False
                
            thumb_name = f"{os.path.splitext(os.path.basename(file_path))[0]}_thumb.jpg"
            thumb_path = os.path.join(CONFIG["THUMBNAIL_DIR"], thumb_name)
            
            # Use ImageMagick if available
            if shutil.which('convert'):
                cmd = [
                    'convert',
                    file_path,
                    '-thumbnail', CONFIG["THUMBNAIL_SIZE"],
                    '-background', 'white',
                    '-gravity', 'center',
                    '-extent', CONFIG["THUMBNAIL_SIZE"],
                    thumb_path
                ]
                subprocess.run(cmd, check=True)
                return True
            else:
                logger.warning("ImageMagick not available, skipping thumbnail creation")
                return False
                
        except Exception as e:
            logger.warning(f"Could not create thumbnail: {e}")
            return False
    
    def _move_to_processed(self, file_path):
        """Move file to processed directory"""
        file_name = os.path.basename(file_path)
        processed_path = os.path.join(CONFIG["PROCESSED_DIR"], file_name)
        
        # Handle name conflicts
        counter = 1
        while os.path.exists(processed_path):
            base, ext = os.path.splitext(file_name)
            processed_path = os.path.join(
                CONFIG["PROCESSED_DIR"],
                f"{base}_{counter}{ext}"
            )
            counter += 1
            
        shutil.move(file_path, processed_path)
        return processed_path
    
    def _handle_failed_file(self, file_path, error_msg):
        """Handle files that failed processing"""
        file_name = os.path.basename(file_path)
        
        # Update metadata
        self.metadata["failed_files"][file_name] = {
            "error": error_msg,
            "failed_at": datetime.now().isoformat(),
            "worker": self.worker_id
        }
        self._save_metadata()
        
        # Move to failed directory
        failed_path = os.path.join(CONFIG["FAILED_DIR"], file_name)
        
        # Handle name conflicts
        counter = 1
        while os.path.exists(failed_path):
            base, ext = os.path.splitext(file_name)
            failed_path = os.path.join(
                CONFIG["FAILED_DIR"],
                f"{base}_{counter}{ext}"
            )
            counter += 1
            
        shutil.move(file_path, failed_path)
        logger.info(f"[{self.worker_id}] Moved failed file to: {failed_path}")

class Worker:
    """Main worker class that monitors and processes files"""
    
    def __init__(self):
        self.processor = FileProcessor()
        self.file_queue = queue.Queue()
        self.running = False
        self.worker_threads = []
        
    def start(self, num_workers=4):
        """Start the worker with specified number of threads"""
        self.running = True
        
        # Start file watcher thread
        threading.Thread(target=self._watch_directory, daemon=True).start()
        
        # Start worker threads
        for i in range(num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                args=(f"Worker-{i+1}",),
                daemon=True
            )
            t.start()
            self.worker_threads.append(t)
            logger.info(f"Started worker thread {i+1}")
            
        logger.info("FireSense worker started successfully")
        
        # Main loop (just keep the program running)
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the worker"""
        self.running = False
        logger.info("Stopping FireSense worker...")
        
        # Wait for worker threads to finish
        for t in self.worker_threads:
            t.join(timeout=5)
            
        logger.info("FireSense worker stopped")
    
    def _watch_directory(self):
        """Watch the input directory for new files"""
        logger.info("Started directory watcher")
        
        processed_files = set(self.processor.metadata.get("processed_files", {}).keys())
        failed_files = set(self.processor.metadata.get("failed_files", {}).keys())
        
        while self.running:
            try:
                # Scan directory for new files
                for entry in os.scandir(CONFIG["INPUT_DIR"]):
                    if entry.is_file():
                        file_name = entry.name
                        
                        # Skip already processed or failed files
                        if file_name in processed_files or file_name in failed_files:
                            continue
                            
                        file_path = entry.path
                        
                        # Add to queue if not already there
                        if file_path not in list(self.file_queue.queue):
                            self.file_queue.put(file_path)
                            logger.debug(f"Queued file: {file_name}")
                
                time.sleep(CONFIG["QUEUE_CHECK_INTERVAL"])
                
            except Exception as e:
                logger.error(f"Error in directory watcher: {e}")
                time.sleep(5)  # Prevent tight loop on errors
    
    def _worker_loop(self, worker_name):
        """Worker thread processing loop"""
        logger.info(f"{worker_name} started processing loop")
        
        while self.running:
            try:
                # Get next file from queue (with timeout to allow checking self.running)
                try:
                    file_path = self.file_queue.get(timeout=1)
                except queue.Empty:
                    continue
                    
                # Process the file with retries
                success = False
                for attempt in range(CONFIG["MAX_RETRIES"]):
                    try:
                        success = self.processor.process_file(file_path)
                        if success:
                            break
                    except Exception as e:
                        logger.warning(
                            f"{worker_name} attempt {attempt+1} failed for {file_path}: {e}"
                        )
                        
                    if attempt < CONFIG["MAX_RETRIES"] - 1:
                        time.sleep(CONFIG["RETRY_DELAY"])
                
                self.file_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in worker {worker_name}: {e}")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="FireSense File Processing Worker")
    parser.add_argument('--workers', type=int, default=4,
                      help="Number of worker threads (default: 4)")
    parser.add_argument('--input-dir', help=f"Input directory (default: {CONFIG['INPUT_DIR']})")
    parser.add_argument('--processed-dir', help=f"Processed files directory (default: {CONFIG['PROCESSED_DIR']})")
    parser.add_argument('--failed-dir', help=f"Failed files directory (default: {CONFIG['FAILED_DIR']})")
    parser.add_argument('--max-size', type=int, help=f"Maximum file size in bytes (default: {CONFIG['MAX_FILE_SIZE']})")
    parser.add_argument('--worker-id', help=f"Worker ID (default: {CONFIG['WORKER_ID']})")
    return parser.parse_args()

def update_config_from_args(args):
    """Update configuration from command line arguments"""
    if args.input_dir:
        CONFIG["INPUT_DIR"] = args.input_dir
    if args.processed_dir:
        CONFIG["PROCESSED_DIR"] = args.processed_dir
    if args.failed_dir:
        CONFIG["FAILED_DIR"] = args.failed_dir
    if args.max_size:
        CONFIG["MAX_FILE_SIZE"] = args.max_size
    if args.worker_id:
        CONFIG["WORKER_ID"] = args.worker_id

def signal_handler(sig, frame):
    """Handle termination signals"""
    logger.info("Received termination signal, shutting down...")
    worker.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Parse command line arguments
    args = parse_args()
    update_config_from_args(args)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start worker
    worker = Worker()
    worker.start(num_workers=args.workers)
