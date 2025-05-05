#!/usr/bin/env python3
import sqlite3
import hashlib
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from contextlib import contextmanager

@dataclass
class SchemaChange:
    version: int
    sql: str
    rollback_sql: str
    checksum: str
    applied_at: Optional[datetime] = None

class ChangeManager:
    """Professional-grade database change handler in minimal code"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_changelog()
    
    @contextmanager
    def _connect(self):
        """Transactional database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_changelog(self):
        """Initialize change tracking table"""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_changes (
                    version INTEGER PRIMARY KEY,
                    sql TEXT NOT NULL,
                    rollback_sql TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    def _calculate_checksum(self, sql: str) -> str:
        """Generate SQL checksum"""
        return hashlib.sha256(sql.encode()).hexdigest()
    
    def apply_changes(self, changes: List[SchemaChange]) -> bool:
        """Apply schema changes with verification"""
        with self._connect() as conn:
            current_version = conn.execute(
                "SELECT MAX(version) FROM schema_changes"
            ).fetchone()[0] or 0
            
            for change in sorted(changes, key=lambda x: x.version):
                if change.version <= current_version:
                    continue
                
                if self._calculate_checksum(change.sql) != change.checksum:
                    raise ValueError(f"Checksum mismatch for version {change.version}")
                
                conn.executescript(change.sql)
                conn.execute("""
                    INSERT INTO schema_changes 
                    (version, sql, rollback_sql, checksum)
                    VALUES (?, ?, ?, ?)
                """, (
                    change.version,
                    change.sql,
                    change.rollback_sql,
                    change.checksum
                ))
        
        return True
    
    def rollback(self, target_version: int) -> bool:
        """Rollback to specific schema version"""
        with self._connect() as conn:
            current_version = conn.execute(
                "SELECT MAX(version) FROM schema_changes"
            ).fetchone()[0]
            
            if not current_version:
                return False
            
            rollbacks = conn.execute("""
                SELECT version, rollback_sql FROM schema_changes
                WHERE version > ?
                ORDER BY version DESC
            """, (target_version,)).fetchall()
            
            for rollback in rollbacks:
                conn.executescript(rollback['rollback_sql'])
                conn.execute(
                    "DELETE FROM schema_changes WHERE version = ?",
                    (rollback['version'],)
                )
        
        return True
    
    def verify_schema(self) -> bool:
        """Verify all applied changes match their checksums"""
        with self._connect() as conn:
            changes = conn.execute(
                "SELECT version, sql, checksum FROM schema_changes"
            ).fetchall()
            
            for change in changes:
                if self._calculate_checksum(change['sql']) != change['checksum']:
                    return False
        return True
      
if __name__ == "__main__":
    changes = [
        SchemaChange(
            version=1,
            sql="""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """,
            rollback_sql="DROP TABLE users;",
            checksum=hashlib.sha256(b"""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """).hexdigest()
        ),
        SchemaChange(
            version=2,
            sql="""
                ALTER TABLE users ADD COLUMN email TEXT;
                CREATE INDEX idx_user_email ON users(email);
            """,
            rollback_sql="""
                DROP INDEX idx_user_email;
                ALTER TABLE users DROP COLUMN email;
            """,
            checksum=hashlib.sha256(b"""
                ALTER TABLE users ADD COLUMN email TEXT;
                CREATE INDEX idx_user_email ON users(email);
            """).hexdigest()
        )
    ]
    
    # Apply changes
    manager = ChangeManager("firesense.db")
    manager.apply_changes(changes)
    
    # Verify schema
    print(f"Schema valid: {manager.verify_schema()}")
