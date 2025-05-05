from typing import Optional, Dict, Generator, Tuple
import os
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass
import threading
from contextlib import contextmanager

__version__ = "1.0.0"
__all__ = ['FileTransfer', 'FileDatabase', 'AtomicOperation']

@dataclass
class FileMeta:
    path: str
    size: int
    sha256: str
    mtime: float
    metadata: Dict[str, str] = None

class FileTransfer:
    """Unified client/server file transfer handler"""
    
    CHUNK_SIZE = 1024 * 1024  # 1MB
    
    @staticmethod
    def chunk_generator(file_path: str) -> Generator[Tuple[bytes, str], None, None]:
        """Generate file chunks with incremental checksum"""
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(FileTransfer.CHUNK_SIZE):
                sha.update(chunk)
                yield chunk, sha.hexdigest()
    
    @staticmethod
    def verify_file(file_path: str, expected_hash: str) -> bool:
        """Validate file integrity"""
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(FileTransfer.CHUNK_SIZE), b""):
                sha.update(chunk)
        return sha.hexdigest() == expected_hash

class FileDatabase:
    """Thread-safe file metadata registry"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_path: str = "firesense.db"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_db(db_path)
        return cls._instance
    
    def _init_db(self, db_path: str):
        """Initialize database schema"""
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                mtime REAL NOT NULL,
                metadata TEXT NOT NULL
            )
        """)
    
    def register_file(self, meta: FileMeta) -> None:
        """Register or update file metadata"""
        self.conn.execute("""
            INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)
        """, (
            meta.path,
            meta.size,
            meta.sha256,
            meta.mtime,
            json.dumps(meta.metadata or {})
        ))
        self.conn.commit()

class AtomicOperation:
    """Atomic file operation context manager"""
    
    @staticmethod
    @contextmanager
    def save(file_path: str):
        """Atomic file save operation"""
        temp_path = f"{file_path}.tmp"
        try:
            yield temp_path
            os.replace(temp_path, file_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    @staticmethod
    @contextmanager
    def move(src: str, dest: str):
        """Atomic move operation"""
        temp_dest = f"{dest}.tmp"
        try:
            if os.path.exists(temp_dest):
                os.remove(temp_dest)
            yield temp_dest
            os.replace(src, temp_dest)
            os.rename(temp_dest, dest)
        finally:
            if os.path.exists(temp_dest):
                os.remove(temp_dest)
