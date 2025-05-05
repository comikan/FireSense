#!/usr/bin/env python3
import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import threading
import sqlite3
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FireSense.DB")

@dataclass
class FileVersion:
    timestamp: datetime
    size: int
    hash: str
    operation: str  # 'create', 'update', 'delete'
    user: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FileRecord:
    file_path: str
    current_hash: str
    current_size: int
    created: datetime
    modified: datetime
    versions: List[FileVersion] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class FileDatabase:
    """Thread-safe database handler for file metadata"""
    
    def __init__(self, db_path: str = "firesense_metadata.db"):
        self.db_path = db_path
        self._init_db()
        self._lock = threading.Lock()
    
    def _init_db(self):
        """Initialize database schema"""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    path TEXT PRIMARY KEY,
                    current_hash TEXT NOT NULL,
                    current_size INTEGER NOT NULL,
                    created TEXT NOT NULL,
                    modified TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    hash TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    user TEXT,
                    metadata TEXT NOT NULL,
                    FOREIGN KEY(file_path) REFERENCES files(path) ON DELETE CASCADE
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_versions_path ON versions(file_path)
            """)
    
    @contextmanager
    def _connect(self):
        """Thread-safe database connection context manager"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file contents"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def record_upload(self, file_path: str, user: Optional[str] = None, metadata: Optional[Dict] = None) -> FileRecord:
        """Record a new file upload"""
        file_path = str(Path(file_path).absolute())
        file_size = os.path.getsize(file_path)
        file_hash = self._calculate_hash(file_path)
        now = datetime.utcnow().isoformat()
        
        with self._connect() as conn:
            # Insert or update file record
            conn.execute("""
                INSERT INTO files (path, current_hash, current_size, created, modified, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    current_hash = excluded.current_hash,
                    current_size = excluded.current_size,
                    modified = excluded.modified,
                    metadata = excluded.metadata
            """, (
                file_path,
                file_hash,
                file_size,
                now,
                now,
                json.dumps(metadata or {})
            ))
            
            # Record version history
            conn.execute("""
                INSERT INTO versions (file_path, timestamp, size, hash, operation, user, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                file_path,
                now,
                file_size,
                file_hash,
                'create' if not self.get_file(file_path) else 'update',
                user,
                json.dumps(metadata or {})
            ))
        
        return self.get_file(file_path)
    
    def record_deletion(self, file_path: str, user: Optional[str] = None) -> None:
        """Record file deletion"""
        file_path = str(Path(file_path).absolute())
        record = self.get_file(file_path)
        
        if record:
            now = datetime.utcnow().isoformat()
            
            with self._connect() as conn:
                # Record deletion in version history
                conn.execute("""
                    INSERT INTO versions (file_path, timestamp, size, hash, operation, user, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    file_path,
                    now,
                    0,
                    '',
                    'delete',
                    user,
                    json.dumps(record.metadata)
                ))
                
                # Remove file record
                conn.execute("DELETE FROM files WHERE path = ?", (file_path,))
    
    def get_file(self, file_path: str) -> Optional[FileRecord]:
        """Get file record with version history"""
        file_path = str(Path(file_path).absolute())
        
        with self._connect() as conn:
            file_row = conn.execute(
                "SELECT * FROM files WHERE path = ?", 
                (file_path,)
            ).fetchone()
            
            if not file_row:
                return None
                
            version_rows = conn.execute(
                "SELECT * FROM versions WHERE file_path = ? ORDER BY timestamp DESC",
                (file_path,)
            ).fetchall()
            
            versions = [
                FileVersion(
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    size=row['size'],
                    hash=row['hash'],
                    operation=row['operation'],
                    user=row['user'],
                    metadata=json.loads(row['metadata'])
                ) for row in version_rows
            ]
            
            return FileRecord(
                file_path=file_row['path'],
                current_hash=file_row['current_hash'],
                current_size=file_row['current_size'],
                created=datetime.fromisoformat(file_row['created']),
                modified=datetime.fromisoformat(file_row['modified']),
                versions=versions,
                metadata=json.loads(file_row['metadata'])
            )
    
    def verify_file(self, file_path: str) -> bool:
        """Verify file integrity against database record"""
        file_path = str(Path(file_path).absolute())
        record = self.get_file(file_path)
        
        if not record:
            return False
            
        if not os.path.exists(file_path):
            return False
            
        current_hash = self._calculate_hash(file_path)
        return current_hash == record.current_hash
    
    def get_file_history(self, file_path: str) -> List[FileVersion]:
        """Get complete version history for a file"""
        record = self.get_file(file_path)
        return record.versions if record else []
