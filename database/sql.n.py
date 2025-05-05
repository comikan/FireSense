#!/usr/bin/env python3
"""
FireSense Advanced Database Manager
A compact yet sophisticated SQL database handler with connection pooling,
transaction management, and schema migrations.
"""

import sqlite3
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Iterator
from dataclasses import dataclass
from pathlib import Path
import hashlib
import logging
from threading import Lock

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FireSenseDB")

@dataclass
class DBConfig:
    db_path: str = "firesense.db"
    pool_size: int = 5
    timeout: float = 30.0
    journal_mode: str = "WAL"
    foreign_keys: bool = True

class ConnectionPool:
    """Advanced connection pool with thread safety"""
    
    def __init__(self, config: DBConfig):
        self.config = config
        self._pool: List[sqlite3.Connection] = []
        self._lock = Lock()
        self._initialize_pool()
        self._run_migrations()

    def _initialize_pool(self):
        """Initialize the connection pool"""
        with self._lock:
            for _ in range(self.config.pool_size):
                conn = sqlite3.connect(
                    self.config.db_path,
                    timeout=self.config.timeout,
                    isolation_level=None
                )
                self._configure_connection(conn)
                self._pool.append(conn)

    def _configure_connection(self, conn: sqlite3.Connection):
        """Configure connection settings"""
        conn.execute(f"PRAGMA journal_mode={self.config.journal_mode}")
        conn.execute(f"PRAGMA foreign_keys={'ON' if self.config.foreign_keys else 'OFF'}")
        conn.row_factory = sqlite3.Row

    def _run_migrations(self):
        """Run database migrations"""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL UNIQUE,
                    hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    file_type TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    file_id INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (file_id, key),
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    @contextmanager
    def get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get a connection from the pool with context management"""
        conn = None
        try:
            with self._lock:
                if not self._pool:
                    raise RuntimeError("Connection pool exhausted")
                conn = self._pool.pop()
            yield conn
        finally:
            if conn:
                with self._lock:
                    self._pool.append(conn)

class FireSenseDB:
    """Advanced database operations for FireSense"""
    
    def __init__(self, config: Optional[DBConfig] = None):
        self.config = config or DBConfig()
        self.pool = ConnectionPool(self.config)

    @contextmanager
    def _transaction(self):
        """Context manager for database transactions"""
        with self.pool.get_connection() as conn:
            try:
                conn.execute("BEGIN")
                yield conn
                conn.execute("COMMIT")
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Transaction failed: {e}")
                raise

    def add_file(self, path: str, file_hash: str, size: int, file_type: str) -> int:
        """Add a new file record"""
        with self._transaction() as conn:
            cursor = conn.execute("""
                INSERT INTO files (path, hash, size, file_type)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    hash = excluded.hash,
                    size = excluded.size,
                    file_type = excluded.file_type,
                    modified_at = CURRENT_TIMESTAMP
                RETURNING id
            """, (path, file_hash, size, file_type))
            return cursor.fetchone()["id"]

    def get_file(self, file_id: int) -> Optional[Dict[str, Any]]:
        """Get file by ID"""
        with self.pool.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM files WHERE id = ?
            """, (file_id,))
            if row := cursor.fetchone():
                return dict(row)
            return None

    def search_files(self, query: str) -> List[Dict[str, Any]]:
        """Search files by path or metadata"""
        with self.pool.get_connection() as conn:
            cursor = conn.execute("""
                SELECT f.* FROM files f
                LEFT JOIN metadata m ON f.id = m.file_id
                WHERE f.path LIKE ? OR m.value LIKE ?
                GROUP BY f.id
            """, (f"%{query}%", f"%{query}%"))
            return [dict(row) for row in cursor.fetchall()]

    def add_metadata(self, file_id: int, key: str, value: str):
        """Add metadata to a file"""
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO metadata (file_id, key, value)
                VALUES (?, ?, ?)
                ON CONFLICT(file_id, key) DO UPDATE SET
                    value = excluded.value
            """, (file_id, key, value))

    def get_metadata(self, file_id: int) -> Dict[str, str]:
        """Get all metadata for a file"""
        with self.pool.get_connection() as conn:
            cursor = conn.execute("""
                SELECT key, value FROM metadata
                WHERE file_id = ?
            """, (file_id,))
            return {row["key"]: row["value"] for row in cursor.fetchall()}

    def calculate_checksums(self) -> Dict[str, str]:
        """Calculate and verify file checksums"""
        with self.pool.get_connection() as conn:
            cursor = conn.execute("SELECT id, path, hash FROM files")
            results = {}
            for row in cursor.fetchall():
                file_path = Path(row["path"])
                if file_path.exists():
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                        results[row["path"]] = "OK" if file_hash == row["hash"] else "MISMATCH"
                else:
                    results[row["path"]] = "MISSING"
            return results

if __name__ == "__main__":
    # Example usage
    db = FireSenseDB()
    
    # Add a file
    file_id = db.add_file(
        path="/data/test.txt",
        file_hash="a1b2c3d4",
        size=1024,
        file_type="text/plain"
    )
    
    # Add metadata
    db.add_metadata(file_id, "author", "FireSense Team")
    
    # Search files
    results = db.search_files("test")
    print(f"Search results: {results}")
    
    # Verify checksums
    print("Checksum verification:", db.calculate_checksums())
