"""
FireSense Intel Handler Module

This module provides comprehensive intelligence and analytics capabilities for the FireSense storage system.
It handles metadata management, file indexing, security analysis, performance monitoring, and advanced
search capabilities.

Key Features:
- Real-time file system monitoring and analytics
- Advanced metadata extraction and indexing
- Security threat detection
- Usage pattern analysis
- Automated tagging and categorization
- Performance optimization recommendations
- Custom reporting engine
"""

import os
import json
import hashlib
import datetime
import time
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from logging.handlers import RotatingFileHandler
import platform
import psutil
import magic
import pytz
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import queue
import sqlite3
from sqlite3 import Error as SQLiteError
import re
import zipfile
import tarfile
import csv
import xml.etree.ElementTree as ET
import PyPDF2
from PIL import Image, ExifTags
import openpyxl
from docx import Document
import email
import email.policy
import chardet
import numpy as np
from sklearn.cluster import KMeans
from collections import defaultdict, Counter
import heapq
import socket
import uuid
import ssl
import cryptography
from cryptography.fernet import Fernet
import jwt
import bcrypt
import yara
import pytesseract
from bs4 import BeautifulSoup
import requests
import gevent
from gevent import monkey; monkey.patch_all()
import humanize
import configparser

# Constants
MAX_FILE_SIZE_ANALYSIS = 100 * 1024 * 1024  # 100MB
MAX_METADATA_EXTRACTION_SIZE = 50 * 1024 * 1024  # 50MB
DEFAULT_CHUNK_SIZE = 8192
MAX_IN_MEMORY_CHUNKS = 1000
DATABASE_VERSION = "1.2.0"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
MAX_LOG_BACKUPS = 5
DEFAULT_TIMEZONE = 'UTC'
MAX_SEARCH_RESULTS = 1000
MAX_TAG_LENGTH = 64
MAX_CATEGORY_LENGTH = 128
MAX_PATTERN_LENGTH = 256
MAX_RULE_LENGTH = 1024
MAX_HISTORY_ENTRIES = 10000
MAX_REPORT_ITEMS = 500
MAX_ANALYSIS_THREADS = 8
MAX_EVENT_QUEUE_SIZE = 10000
MAX_CACHE_SIZE = 10000
CACHE_EXPIRY_SECONDS = 3600  # 1 hour

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'firesense_intel.log',
            maxBytes=MAX_LOG_SIZE,
            backupCount=MAX_LOG_BACKUPS
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('FireSenseIntel')

# Exception classes
class FireSenseIntelError(Exception):
    """Base exception class for FireSense Intel errors"""
    pass

class MetadataExtractionError(FireSenseIntelError):
    """Error during metadata extraction"""
    pass

class FileAnalysisError(FireSenseIntelError):
    """Error during file analysis"""
    pass

class DatabaseError(FireSenseIntelError):
    """Database operation error"""
    pass

class SecurityError(FireSenseIntelError):
    """Security-related error"""
    pass

class ConfigurationError(FireSenseIntelError):
    """Configuration error"""
    pass

class CacheError(FireSenseIntelError):
    """Cache-related error"""
    pass

class SearchError(FireSenseIntelError):
    """Search-related error"""
    pass

# Utility functions
def generate_file_fingerprint(file_path: str) -> str:
    """
    Generate a unique fingerprint for a file using SHA-256 hash and file metadata
    
    Args:
        file_path: Path to the file
        
    Returns:
        SHA-256 hash string representing the file fingerprint
    """
    sha256_hash = hashlib.sha256()
    file_size = os.path.getsize(file_path)
    modified_time = os.path.getmtime(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(DEFAULT_CHUNK_SIZE), b''):
                sha256_hash.update(chunk)
    except IOError as e:
        logger.error(f"Error reading file for fingerprint: {file_path} - {str(e)}")
        raise FileAnalysisError(f"Could not read file for fingerprint: {file_path}") from e
    
    # Include file metadata in the fingerprint
    metadata_hash = hashlib.sha256(f"{file_size}{modified_time}".encode()).hexdigest()
    combined_hash = hashlib.sha256(
        (sha256_hash.hexdigest() + metadata_hash).encode()
    ).hexdigest()
    
    return combined_hash

def is_binary_file(file_path: str) -> bool:
    """
    Check if a file is binary (as opposed to text)
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if binary, False if text
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                return True
            # Additional check for common binary file signatures
            return not bool(chunk.decode('utf-8', errors='ignore').isprintable())
    except Exception as e:
        logger.warning(f"Could not determine if file is binary: {file_path} - {str(e)}")
        return True

def get_file_type(file_path: str) -> str:
    """
    Get the file type using python-magic
    
    Args:
        file_path: Path to the file
        
    Returns:
        String describing the file type
    """
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        return file_type
    except Exception as e:
        logger.warning(f"Could not determine file type: {file_path} - {str(e)}")
        return "application/octet-stream"

def safe_read_file(file_path: str, max_size: int = MAX_METADATA_EXTRACTION_SIZE) -> bytes:
    """
    Safely read a file with size limitations
    
    Args:
        file_path: Path to the file
        max_size: Maximum size to read in bytes
        
    Returns:
        File content as bytes
    """
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        raise MetadataExtractionError(f"File too large for metadata extraction: {file_size} bytes")
    
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        raise MetadataExtractionError(f"Could not read file: {file_path}") from e

def validate_tag(tag: str) -> bool:
    """
    Validate a tag string
    
    Args:
        tag: Tag to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not tag or len(tag) > MAX_TAG_LENGTH:
        return False
    # Only allow alphanumeric, hyphen, underscore and space
    return bool(re.match(r'^[a-zA-Z0-9\-_\s]+$', tag))

def validate_category(category: str) -> bool:
    """
    Validate a category string
    
    Args:
        category: Category to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not category or len(category) > MAX_CATEGORY_LENGTH:
        return False
    # More permissive than tags
    return bool(re.match(r'^[a-zA-Z0-9\-_\.\s]+$', category))

def get_current_timestamp() -> str:
    """
    Get current timestamp in ISO format with timezone
    
    Returns:
        ISO formatted timestamp string
    """
    return datetime.datetime.now(pytz.timezone(DEFAULT_TIMEZONE)).isoformat()

def human_readable_size(size_bytes: int) -> str:
    """
    Convert size in bytes to human-readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human-readable size string
    """
    return humanize.naturalsize(size_bytes)

def is_safe_path(base_path: str, path: str) -> bool:
    """
    Check if a path is safe and within the base path
    
    Args:
        base_path: The base directory
        path: The path to check
        
    Returns:
        True if path is safe, False otherwise
    """
    try:
        base_path = os.path.abspath(base_path)
        path = os.path.abspath(path)
        return os.path.commonpath([base_path, path]) == base_path
    except Exception:
        return False

# Database schema and operations
class FireSenseIntelDatabase:
    """Database handler for FireSense Intel"""
    
    def __init__(self, db_path: str = 'firesense_intel.db'):
        """
        Initialize the database
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.connection = None
        self.lock = threading.Lock()
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Initialize the database schema"""
        try:
            with self.lock:
                self.connection = sqlite3.connect(self.db_path)
                self.connection.execute('PRAGMA journal_mode=WAL')
                self.connection.execute('PRAGMA synchronous=NORMAL')
                self.connection.execute('PRAGMA foreign_keys=ON')
                
                # Check if database needs to be created or upgraded
                cursor = self.connection.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
                if not cursor.fetchone():
                    self._create_database_schema()
                else:
                    self._check_database_version()
        except SQLiteError as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise DatabaseError("Failed to initialize database") from e
    
    def _create_database_schema(self) -> None:
        """Create the database schema"""
        try:
            cursor = self.connection.cursor()
            
            # Metadata table - core file information
            cursor.execute("""
                CREATE TABLE metadata (
                    file_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_type TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    created_time TEXT NOT NULL,
                    modified_time TEXT NOT NULL,
                    accessed_time TEXT NOT NULL,
                    is_binary INTEGER NOT NULL,
                    is_encrypted INTEGER DEFAULT 0,
                    is_compressed INTEGER DEFAULT 0,
                    is_archive INTEGER DEFAULT 0,
                    is_media INTEGER DEFAULT 0,
                    is_document INTEGER DEFAULT 0,
                    is_executable INTEGER DEFAULT 0,
                    is_hidden INTEGER DEFAULT 0,
                    is_system INTEGER DEFAULT 0,
                    owner TEXT,
                    group_name TEXT,
                    permissions TEXT,
                    last_analyzed TEXT,
                    analysis_version TEXT
                )
            """)
            
            # Extended metadata table - file format specific metadata
            cursor.execute("""
                CREATE TABLE extended_metadata (
                    file_id TEXT PRIMARY KEY,
                    author TEXT,
                    title TEXT,
                    subject TEXT,
                    keywords TEXT,
                    comments TEXT,
                    creator TEXT,
                    producer TEXT,
                    creation_date TEXT,
                    modification_date TEXT,
                    page_count INTEGER,
                    word_count INTEGER,
                    character_count INTEGER,
                    line_count INTEGER,
                    language TEXT,
                    width INTEGER,
                    height INTEGER,
                    duration REAL,
                    bitrate INTEGER,
                    sample_rate INTEGER,
                    channels INTEGER,
                    color_depth INTEGER,
                    resolution TEXT,
                    camera_make TEXT,
                    camera_model TEXT,
                    gps_coordinates TEXT,
                    software_used TEXT,
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE
                )
            """)
            
            # Tags table
            cursor.execute("""
                CREATE TABLE tags (
                    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tag_name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_time TEXT NOT NULL,
                    last_used TEXT
                )
            """)
            
            # File tags mapping
            cursor.execute("""
                CREATE TABLE file_tags (
                    file_id TEXT NOT NULL,
                    tag_id INTEGER NOT NULL,
                    added_time TEXT NOT NULL,
                    added_by TEXT,
                    confidence REAL DEFAULT 1.0,
                    PRIMARY KEY (file_id, tag_id),
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE,
                    FOREIGN KEY (tag_id) REFERENCES tags(tag_id) ON DELETE CASCADE
                )
            """)
            
            # Categories table
            cursor.execute("""
                CREATE TABLE categories (
                    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category_name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    parent_id INTEGER,
                    created_time TEXT NOT NULL,
                    FOREIGN KEY (parent_id) REFERENCES categories(category_id) ON DELETE SET NULL
                )
            """)
            
            # File categories mapping
            cursor.execute("""
                CREATE TABLE file_categories (
                    file_id TEXT NOT NULL,
                    category_id INTEGER NOT NULL,
                    added_time TEXT NOT NULL,
                    added_by TEXT,
                    confidence REAL DEFAULT 1.0,
                    PRIMARY KEY (file_id, category_id),
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE,
                    FOREIGN KEY (category_id) REFERENCES categories(category_id) ON DELETE CASCADE
                )
            """)
            
            # Security indicators table
            cursor.execute("""
                CREATE TABLE security_indicators (
                    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detected_time TEXT NOT NULL,
                    description TEXT,
                    is_false_positive INTEGER DEFAULT 0,
                    verified_by TEXT,
                    verified_time TEXT,
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE
                )
            """)
            
            # File relationships table
            cursor.execute("""
                CREATE TABLE file_relationships (
                    relationship_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_file_id TEXT NOT NULL,
                    target_file_id TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    strength REAL DEFAULT 1.0,
                    created_time TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY (source_file_id) REFERENCES metadata(file_id) ON DELETE CASCADE,
                    FOREIGN KEY (target_file_id) REFERENCES metadata(file_id) ON DELETE CASCADE
                )
            """)
            
            # File content patterns table
            cursor.execute("""
                CREATE TABLE content_patterns (
                    pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    pattern_value TEXT NOT NULL,
                    start_offset INTEGER,
                    end_offset INTEGER,
                    context TEXT,
                    detected_time TEXT NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE
                )
            """)
            
            # Analysis history table
            cursor.execute("""
                CREATE TABLE analysis_history (
                    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    analysis_time TEXT NOT NULL,
                    duration REAL NOT NULL,
                    result_status TEXT NOT NULL,
                    result_summary TEXT,
                    details TEXT,
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE
                )
            """)
            
            # System events table
            cursor.execute("""
                CREATE TABLE system_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    related_file_id TEXT,
                    user_context TEXT,
                    FOREIGN KEY (related_file_id) REFERENCES metadata(file_id) ON DELETE SET NULL
                )
            """)
            
            # Search history table
            cursor.execute("""
                CREATE TABLE search_history (
                    search_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_query TEXT NOT NULL,
                    search_time TEXT NOT NULL,
                    user_context TEXT,
                    result_count INTEGER,
                    duration REAL,
                    search_type TEXT
                )
            """)
            
            # User annotations table
            cursor.execute("""
                CREATE TABLE user_annotations (
                    annotation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    annotation_time TEXT NOT NULL,
                    annotation_type TEXT NOT NULL,
                    annotation_text TEXT NOT NULL,
                    is_private INTEGER DEFAULT 0,
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE
                )
            """)
            
            # YARA rules table
            cursor.execute("""
                CREATE TABLE yara_rules (
                    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    rule_text TEXT NOT NULL,
                    category TEXT,
                    author TEXT,
                    created_time TEXT NOT NULL,
                    modified_time TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    severity TEXT DEFAULT 'medium'
                )
            """)
            
            # Custom metadata fields table
            cursor.execute("""
                CREATE TABLE custom_metadata_fields (
                    field_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    field_name TEXT NOT NULL UNIQUE,
                    field_type TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    description TEXT,
                    validation_pattern TEXT,
                    is_required INTEGER DEFAULT 0,
                    default_value TEXT,
                    created_time TEXT NOT NULL
                )
            """)
            
            # Custom metadata values table
            cursor.execute("""
                CREATE TABLE custom_metadata_values (
                    value_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    field_id INTEGER NOT NULL,
                    field_value TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    updated_by TEXT,
                    FOREIGN KEY (file_id) REFERENCES metadata(file_id) ON DELETE CASCADE,
                    FOREIGN KEY (field_id) REFERENCES custom_metadata_fields(field_id) ON DELETE CASCADE,
                    UNIQUE (file_id, field_id)
                )
            """)
            
            # Database version table
            cursor.execute("""
                CREATE TABLE db_version (
                    version_id INTEGER PRIMARY KEY,
                    version_number TEXT NOT NULL,
                    upgrade_time TEXT NOT NULL,
                    upgrade_script TEXT
                )
            """)
            
            # Insert initial version
            cursor.execute("""
                INSERT INTO db_version (version_id, version_number, upgrade_time)
                VALUES (1, ?, ?)
            """, (DATABASE_VERSION, get_current_timestamp()))
            
            self.connection.commit()
            logger.info("Created new FireSense Intel database schema")
        except SQLiteError as e:
            self.connection.rollback()
            logger.error(f"Failed to create database schema: {str(e)}")
            raise DatabaseError("Failed to create database schema") from e
    
    def _check_database_version(self) -> None:
        """Check database version and apply upgrades if needed"""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT version_number FROM db_version ORDER BY version_id DESC LIMIT 1")
            result = cursor.fetchone()
            
            if not result:
                logger.warning("No version found in database, assuming new version")
                self._create_database_schema()
                return
            
            current_version = result[0]
            if current_version != DATABASE_VERSION:
                logger.info(f"Database version {current_version} detected, upgrading to {DATABASE_VERSION}")
                self._upgrade_database(current_version, DATABASE_VERSION)
        except SQLiteError as e:
            logger.error(f"Failed to check database version: {str(e)}")
            raise DatabaseError("Failed to check database version") from e
    
    def _upgrade_database(self, from_version: str, to_version: str) -> None:
        """Upgrade database schema from one version to another"""
        # This would contain version-specific upgrade scripts in a real implementation
        logger.info(f"Upgrading database from {from_version} to {to_version}")
        
        try:
            cursor = self.connection.cursor()
            
            # Example upgrade - add new columns if they don't exist
            cursor.execute("PRAGMA table_info(metadata)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'is_hidden' not in columns:
                cursor.execute("ALTER TABLE metadata ADD COLUMN is_hidden INTEGER DEFAULT 0")
            
            if 'is_system' not in columns:
                cursor.execute("ALTER TABLE metadata ADD COLUMN is_system INTEGER DEFAULT 0")
            
            # Record the upgrade
            cursor.execute("""
                INSERT INTO db_version (version_number, upgrade_time)
                VALUES (?, ?)
            """, (to_version, get_current_timestamp()))
            
            self.connection.commit()
            logger.info(f"Successfully upgraded database to version {to_version}")
        except SQLiteError as e:
            self.connection.rollback()
            logger.error(f"Failed to upgrade database: {str(e)}")
            raise DatabaseError("Failed to upgrade database") from e
    
    def close(self) -> None:
        """Close the database connection"""
        try:
            if self.connection:
                self.connection.close()
                self.connection = None
        except SQLiteError as e:
            logger.error(f"Error closing database: {str(e)}")
    
    def execute_query(self, query: str, params: tuple = (), fetch: bool = True) -> Optional[List[tuple]]:
        """
        Execute a database query
        
        Args:
            query: SQL query string
            params: Query parameters
            fetch: Whether to fetch results
            
        Returns:
            List of result rows if fetch=True, None otherwise
        """
        try:
            with self.lock:
                cursor = self.connection.cursor()
                cursor.execute(query, params)
                
                if fetch:
                    result = cursor.fetchall()
                    return result
                
                self.connection.commit()
                return None
        except SQLiteError as e:
            logger.error(f"Database query failed: {query} - {str(e)}")
            raise DatabaseError(f"Query failed: {str(e)}") from e
    
    def execute_many(self, query: str, params_list: List[tuple]) -> None:
        """
        Execute many database operations
        
        Args:
            query: SQL query string
            params_list: List of parameter tuples
        """
        try:
            with self.lock:
                cursor = self.connection.cursor()
                cursor.executemany(query, params_list)
                self.connection.commit()
        except SQLiteError as e:
            self.connection.rollback()
            logger.error(f"Database executemany failed: {query} - {str(e)}")
            raise DatabaseError(f"Executemany failed: {str(e)}") from e
    
    def get_file_metadata(self, file_id: str) -> Optional[Dict[str, Any]]:
        """
        Get file metadata by file_id
        
        Args:
            file_id: File identifier
            
        Returns:
            Dictionary of file metadata or None if not found
        """
        try:
            query = """
                SELECT * FROM metadata 
                LEFT JOIN extended_metadata USING (file_id)
                WHERE file_id = ?
            """
            result = self.execute_query(query, (file_id,))
            
            if not result:
                return None
                
            columns = [desc[0] for desc in self.connection.cursor().description]
            return dict(zip(columns, result[0]))
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get file metadata: {str(e)}")
            raise DatabaseError("Failed to get file metadata") from e
    
    def insert_file_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Insert file metadata into database
        
        Args:
            metadata: Dictionary of file metadata
        """
        try:
            # Basic metadata
            metadata_values = (
                metadata['file_id'],
                metadata['file_path'],
                metadata['file_name'],
                metadata['file_size'],
                metadata['file_type'],
                metadata['mime_type'],
                metadata['fingerprint'],
                metadata['created_time'],
                metadata['modified_time'],
                metadata['accessed_time'],
                metadata['is_binary'],
                metadata.get('is_encrypted', 0),
                metadata.get('is_compressed', 0),
                metadata.get('is_archive', 0),
                metadata.get('is_media', 0),
                metadata.get('is_document', 0),
                metadata.get('is_executable', 0),
                metadata.get('is_hidden', 0),
                metadata.get('is_system', 0),
                metadata.get('owner'),
                metadata.get('group_name'),
                metadata.get('permissions'),
                metadata.get('last_analyzed'),
                metadata.get('analysis_version')
            )
            
            self.execute_query(
                """
                INSERT INTO metadata (
                    file_id, file_path, file_name, file_size, file_type, mime_type, 
                    fingerprint, created_time, modified_time, accessed_time, is_binary,
                    is_encrypted, is_compressed, is_archive, is_media, is_document,
                    is_executable, is_hidden, is_system, owner, group_name, permissions,
                    last_analyzed, analysis_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                metadata_values,
                fetch=False
            )
            
            # Extended metadata if available
            if any(key in metadata for key in ['author', 'title', 'subject', 'keywords']):
                extended_values = (
                    metadata['file_id'],
                    metadata.get('author'),
                    metadata.get('title'),
                    metadata.get('subject'),
                    metadata.get('keywords'),
                    metadata.get('comments'),
                    metadata.get('creator'),
                    metadata.get('producer'),
                    metadata.get('creation_date'),
                    metadata.get('modification_date'),
                    metadata.get('page_count'),
                    metadata.get('word_count'),
                    metadata.get('character_count'),
                    metadata.get('line_count'),
                    metadata.get('language'),
                    metadata.get('width'),
                    metadata.get('height'),
                    metadata.get('duration'),
                    metadata.get('bitrate'),
                    metadata.get('sample_rate'),
                    metadata.get('channels'),
                    metadata.get('color_depth'),
                    metadata.get('resolution'),
                    metadata.get('camera_make'),
                    metadata.get('camera_model'),
                    metadata.get('gps_coordinates'),
                    metadata.get('software_used')
                )
                
                self.execute_query(
                    """
                    INSERT INTO extended_metadata (
                        file_id, author, title, subject, keywords, comments, creator,
                        producer, creation_date, modification_date, page_count,
                        word_count, character_count, line_count, language, width,
                        height, duration, bitrate, sample_rate, channels, color_depth,
                        resolution, camera_make, camera_model, gps_coordinates,
                        software_used
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    extended_values,
                    fetch=False
                )
            
            logger.debug(f"Inserted metadata for file: {metadata['file_id']}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to insert file metadata: {str(e)}")
            raise DatabaseError("Failed to insert file metadata") from e
    
    def update_file_metadata(self, file_id: str, updates: Dict[str, Any]) -> None:
        """
        Update file metadata
        
        Args:
            file_id: File identifier
            updates: Dictionary of fields to update
        """
        try:
            if not updates:
                return
                
            # Update basic metadata
            basic_fields = [
                'file_path', 'file_name', 'file_size', 'file_type', 'mime_type',
                'fingerprint', 'created_time', 'modified_time', 'accessed_time',
                'is_binary', 'is_encrypted', 'is_compressed', 'is_archive',
                'is_media', 'is_document', 'is_executable', 'is_hidden', 'is_system',
                'owner', 'group_name', 'permissions', 'last_analyzed', 'analysis_version'
            ]
            
            basic_updates = {k: v for k, v in updates.items() if k in basic_fields}
            if basic_updates:
                set_clause = ', '.join([f"{k} = ?" for k in basic_updates])
                values = list(basic_updates.values())
                values.append(file_id)
                
                self.execute_query(
                    f"UPDATE metadata SET {set_clause} WHERE file_id = ?",
                    tuple(values),
                    fetch=False
                )
            
            # Update extended metadata
            extended_fields = [
                'author', 'title', 'subject', 'keywords', 'comments', 'creator',
                'producer', 'creation_date', 'modification_date', 'page_count',
                'word_count', 'character_count', 'line_count', 'language', 'width',
                'height', 'duration', 'bitrate', 'sample_rate', 'channels',
                'color_depth', 'resolution', 'camera_make', 'camera_model',
                'gps_coordinates', 'software_used'
            ]
            
            extended_updates = {k: v for k, v in updates.items() if k in extended_fields}
            if extended_updates:
                # Check if extended metadata exists
                result = self.execute_query(
                    "SELECT 1 FROM extended_metadata WHERE file_id = ?",
                    (file_id,)
                )
                
                if result:
                    # Update existing extended metadata
                    set_clause = ', '.join([f"{k} = ?" for k in extended_updates])
                    values = list(extended_updates.values())
                    values.append(file_id)
                    
                    self.execute_query(
                        f"UPDATE extended_metadata SET {set_clause} WHERE file_id = ?",
                        tuple(values),
                        fetch=False
                    )
                else:
                    # Insert new extended metadata
                    extended_values = {field: None for field in extended_fields}
                    extended_values.update(extended_updates)
                    extended_values['file_id'] = file_id
                    
                    self.insert_file_metadata(extended_values)
            
            logger.debug(f"Updated metadata for file: {file_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to update file metadata: {str(e)}")
            raise DatabaseError("Failed to update file metadata") from e
    
    def delete_file_metadata(self, file_id: str) -> None:
        """
        Delete file metadata by file_id
        
        Args:
            file_id: File identifier
        """
        try:
            self.execute_query(
                "DELETE FROM metadata WHERE file_id = ?",
                (file_id,),
                fetch=False
            )
            logger.debug(f"Deleted metadata for file: {file_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to delete file metadata: {str(e)}")
            raise DatabaseError("Failed to delete file metadata") from e
    
    def add_file_tag(self, file_id: str, tag_name: str, added_by: str = None, confidence: float = 1.0) -> None:
        """
        Add a tag to a file
        
        Args:
            file_id: File identifier
            tag_name: Name of the tag
            added_by: User who added the tag
            confidence: Confidence level (0.0 to 1.0)
        """
        try:
            if not validate_tag(tag_name):
                raise ValueError(f"Invalid tag name: {tag_name}")
                
            # Get or create the tag
            tag_id = self._get_or_create_tag(tag_name)
            
            # Add file-tag relationship
            self.execute_query(
                """
                INSERT OR REPLACE INTO file_tags 
                (file_id, tag_id, added_time, added_by, confidence)
                VALUES (?, ?, ?, ?, ?)
                """,
                (file_id, tag_id, get_current_timestamp(), added_by, confidence),
                fetch=False
            )
            
            # Update tag last used time
            self.execute_query(
                "UPDATE tags SET last_used = ? WHERE tag_id = ?",
                (get_current_timestamp(), tag_id),
                fetch=False
            )
            
            logger.debug(f"Added tag '{tag_name}' to file: {file_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add file tag: {str(e)}")
            raise DatabaseError("Failed to add file tag") from e
    
    def _get_or_create_tag(self, tag_name: str) -> int:
        """
        Get or create a tag
        
        Args:
            tag_name: Name of the tag
            
        Returns:
            Tag ID
        """
        try:
            # Try to get existing tag
            result = self.execute_query(
                "SELECT tag_id FROM tags WHERE tag_name = ?",
                (tag_name,)
            )
            
            if result:
                return result[0][0]
            
            # Create new tag
            self.execute_query(
                """
                INSERT INTO tags (tag_name, created_time, last_used)
                VALUES (?, ?, ?)
                """,
                (tag_name, get_current_timestamp(), get_current_timestamp()),
                fetch=False
            )
            
            return self.connection.cursor().lastrowid
        except SQLiteError as e:
            raise DatabaseError(f"Failed to get or create tag: {str(e)}") from e
    
    def remove_file_tag(self, file_id: str, tag_name: str) -> None:
        """
        Remove a tag from a file
        
        Args:
            file_id: File identifier
            tag_name: Name of the tag
        """
        try:
            # Get the tag ID
            result = self.execute_query(
                "SELECT tag_id FROM tags WHERE tag_name = ?",
                (tag_name,)
            )
            
            if not result:
                return
                
            tag_id = result[0][0]
            
            # Remove the file-tag relationship
            self.execute_query(
                "DELETE FROM file_tags WHERE file_id = ? AND tag_id = ?",
                (file_id, tag_id),
                fetch=False
            )
            
            logger.debug(f"Removed tag '{tag_name}' from file: {file_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove file tag: {str(e)}")
            raise DatabaseError("Failed to remove file tag") from e
    
    def get_file_tags(self, file_id: str) -> List[Dict[str, Any]]:
        """
        Get all tags for a file
        
        Args:
            file_id: File identifier
            
        Returns:
            List of tag dictionaries
        """
        try:
            result = self.execute_query(
                """
                SELECT t.tag_id, t.tag_name, t.description, ft.added_time, ft.added_by, ft.confidence
                FROM tags t
                JOIN file_tags ft ON t.tag_id = ft.tag_id
                WHERE ft.file_id = ?
                ORDER BY ft.added_time DESC
                """,
                (file_id,)
            )
            
            return [
                {
                    'tag_id': row[0],
                    'tag_name': row[1],
                    'description': row[2],
                    'added_time': row[3],
                    'added_by': row[4],
                    'confidence': row[5]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get file tags: {str(e)}")
            raise DatabaseError("Failed to get file tags") from e
    
    def add_file_category(self, file_id: str, category_name: str, added_by: str = None, confidence: float = 1.0) -> None:
        """
        Add a category to a file
        
        Args:
            file_id: File identifier
            category_name: Name of the category
            added_by: User who added the category
            confidence: Confidence level (0.0 to 1.0)
        """
        try:
            if not validate_category(category_name):
                raise ValueError(f"Invalid category name: {category_name}")
                
            # Get or create the category
            category_id = self._get_or_create_category(category_name)
            
            # Add file-category relationship
            self.execute_query(
                """
                INSERT OR REPLACE INTO file_categories 
                (file_id, category_id, added_time, added_by, confidence)
                VALUES (?, ?, ?, ?, ?)
                """,
                (file_id, category_id, get_current_timestamp(), added_by, confidence),
                fetch=False
            )
            
            logger.debug(f"Added category '{category_name}' to file: {file_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add file category: {str(e)}")
            raise DatabaseError("Failed to add file category") from e
    
    def _get_or_create_category(self, category_name: str) -> int:
        """
        Get or create a category
        
        Args:
            category_name: Name of the category
            
        Returns:
            Category ID
        """
        try:
            # Try to get existing category
            result = self.execute_query(
                "SELECT category_id FROM categories WHERE category_name = ?",
                (category_name,)
            )
            
            if result:
                return result[0][0]
            
            # Create new category
            self.execute_query(
                """
                INSERT INTO categories (category_name, created_time)
                VALUES (?, ?)
                """,
                (category_name, get_current_timestamp()),
                fetch=False
            )
            
            return self.connection.cursor().lastrowid
        except SQLiteError as e:
            raise DatabaseError(f"Failed to get or create category: {str(e)}") from e
    
    def remove_file_category(self, file_id: str, category_name: str) -> None:
        """
        Remove a category from a file
        
        Args:
            file_id: File identifier
            category_name: Name of the category
        """
        try:
            # Get the category ID
            result = self.execute_query(
                "SELECT category_id FROM categories WHERE category_name = ?",
                (category_name,)
            )
            
            if not result:
                return
                
            category_id = result[0][0]
            
            # Remove the file-category relationship
            self.execute_query(
                "DELETE FROM file_categories WHERE file_id = ? AND category_id = ?",
                (file_id, category_id),
                fetch=False
            )
            
            logger.debug(f"Removed category '{category_name}' from file: {file_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove file category: {str(e)}")
            raise DatabaseError("Failed to remove file category") from e
    
    def get_file_categories(self, file_id: str) -> List[Dict[str, Any]]:
        """
        Get all categories for a file
        
        Args:
            file_id: File identifier
            
        Returns:
            List of category dictionaries
        """
        try:
            result = self.execute_query(
                """
                SELECT c.category_id, c.category_name, c.description, fc.added_time, fc.added_by, fc.confidence
                FROM categories c
                JOIN file_categories fc ON c.category_id = fc.category_id
                WHERE fc.file_id = ?
                ORDER BY fc.added_time DESC
                """,
                (file_id,)
            )
            
            return [
                {
                    'category_id': row[0],
                    'category_name': row[1],
                    'description': row[2],
                    'added_time': row[3],
                    'added_by': row[4],
                    'confidence': row[5]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get file categories: {str(e)}")
            raise DatabaseError("Failed to get file categories") from e
    
    def add_security_indicator(self, file_id: str, indicator_type: str, indicator_value: str, 
                             severity: str = 'medium', description: str = None) -> int:
        """
        Add a security indicator for a file
        
        Args:
            file_id: File identifier
            indicator_type: Type of indicator (e.g., 'hash', 'pattern', 'signature')
            indicator_value: Value of the indicator
            severity: Severity level ('low', 'medium', 'high', 'critical')
            description: Description of the indicator
            
        Returns:
            ID of the created indicator
        """
        try:
            self.execute_query(
                """
                INSERT INTO security_indicators (
                    file_id, indicator_type, indicator_value, severity, 
                    detected_time, description
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id, indicator_type, indicator_value, severity,
                    get_current_timestamp(), description
                ),
                fetch=False
            )
            
            indicator_id = self.connection.cursor().lastrowid
            logger.debug(f"Added security indicator for file: {file_id}")
            return indicator_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add security indicator: {str(e)}")
            raise DatabaseError("Failed to add security indicator") from e
    
    def get_security_indicators(self, file_id: str) -> List[Dict[str, Any]]:
        """
        Get security indicators for a file
        
        Args:
            file_id: File identifier
            
        Returns:
            List of security indicator dictionaries
        """
        try:
            result = self.execute_query(
                """
                SELECT 
                    indicator_id, indicator_type, indicator_value, severity,
                    detected_time, description, is_false_positive,
                    verified_by, verified_time
                FROM security_indicators
                WHERE file_id = ?
                ORDER BY detected_time DESC
                """,
                (file_id,)
            )
            
            return [
                {
                    'indicator_id': row[0],
                    'indicator_type': row[1],
                    'indicator_value': row[2],
                    'severity': row[3],
                    'detected_time': row[4],
                    'description': row[5],
                    'is_false_positive': bool(row[6]),
                    'verified_by': row[7],
                    'verified_time': row[8]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get security indicators: {str(e)}")
            raise DatabaseError("Failed to get security indicators") from e
    
    def add_file_relationship(self, source_file_id: str, target_file_id: str, 
                            relationship_type: str, strength: float = 1.0,
                            description: str = None) -> int:
        """
        Add a relationship between two files
        
        Args:
            source_file_id: Source file identifier
            target_file_id: Target file identifier
            relationship_type: Type of relationship
            strength: Strength of relationship (0.0 to 1.0)
            description: Description of the relationship
            
        Returns:
            ID of the created relationship
        """
        try:
            self.execute_query(
                """
                INSERT INTO file_relationships (
                    source_file_id, target_file_id, relationship_type,
                    strength, created_time, description
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_file_id, target_file_id, relationship_type,
                    strength, get_current_timestamp(), description
                ),
                fetch=False
            )
            
            relationship_id = self.connection.cursor().lastrowid
            logger.debug(f"Added file relationship between {source_file_id} and {target_file_id}")
            return relationship_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add file relationship: {str(e)}")
            raise DatabaseError("Failed to add file relationship") from e
    
    def get_file_relationships(self, file_id: str, direction: str = 'both') -> List[Dict[str, Any]]:
        """
        Get relationships for a file
        
        Args:
            file_id: File identifier
            direction: Relationship direction ('incoming', 'outgoing', or 'both')
            
        Returns:
            List of relationship dictionaries
        """
        try:
            if direction not in ['incoming', 'outgoing', 'both']:
                raise ValueError("Invalid direction, must be 'incoming', 'outgoing', or 'both'")
                
            query = """
                SELECT 
                    relationship_id, source_file_id, target_file_id, 
                    relationship_type, strength, created_time, description
                FROM file_relationships
                WHERE {}
                ORDER BY created_time DESC
            """
            
            if direction == 'incoming':
                query = query.format("target_file_id = ?")
                params = (file_id,)
            elif direction == 'outgoing':
                query = query.format("source_file_id = ?")
                params = (file_id,)
            else:
                query = query.format("source_file_id = ? OR target_file_id = ?")
                params = (file_id, file_id)
            
            result = self.execute_query(query, params)
            
            return [
                {
                    'relationship_id': row[0],
                    'source_file_id': row[1],
                    'target_file_id': row[2],
                    'relationship_type': row[3],
                    'strength': row[4],
                    'created_time': row[5],
                    'description': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get file relationships: {str(e)}")
            raise DatabaseError("Failed to get file relationships") from e
    
    def add_content_pattern(self, file_id: str, pattern_type: str, pattern_value: str,
                          start_offset: int = None, end_offset: int = None,
                          context: str = None) -> int:
        """
        Add a content pattern found in a file
        
        Args:
            file_id: File identifier
            pattern_type: Type of pattern (e.g., 'regex', 'string', 'binary')
            pattern_value: The pattern value
            start_offset: Start offset in file
            end_offset: End offset in file
            context: Context around the pattern
            
        Returns:
            ID of the created pattern
        """
        try:
            self.execute_query(
                """
                INSERT INTO content_patterns (
                    file_id, pattern_type, pattern_value,
                    start_offset, end_offset, context, detected_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id, pattern_type, pattern_value,
                    start_offset, end_offset, context, get_current_timestamp()
                ),
                fetch=False
            )
            
            pattern_id = self.connection.cursor().lastrowid
            logger.debug(f"Added content pattern for file: {file_id}")
            return pattern_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add content pattern: {str(e)}")
            raise DatabaseError("Failed to add content pattern") from e
    
    def get_content_patterns(self, file_id: str) -> List[Dict[str, Any]]:
        """
        Get content patterns for a file
        
        Args:
            file_id: File identifier
            
        Returns:
            List of content pattern dictionaries
        """
        try:
            result = self.execute_query(
                """
                SELECT 
                    pattern_id, pattern_type, pattern_value,
                    start_offset, end_offset, context, detected_time
                FROM content_patterns
                WHERE file_id = ?
                ORDER BY detected_time DESC
                """,
                (file_id,)
            )
            
            return [
                {
                    'pattern_id': row[0],
                    'pattern_type': row[1],
                    'pattern_value': row[2],
                    'start_offset': row[3],
                    'end_offset': row[4],
                    'context': row[5],
                    'detected_time': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get content patterns: {str(e)}")
            raise DatabaseError("Failed to get content patterns") from e
    
    def add_analysis_history(self, file_id: str, analysis_type: str, 
                           duration: float, result_status: str,
                           result_summary: str = None, details: str = None) -> int:
        """
        Add an analysis history record
        
        Args:
            file_id: File identifier
            analysis_type: Type of analysis performed
            duration: Duration of analysis in seconds
            result_status: Status of analysis ('success', 'failed', 'partial')
            result_summary: Summary of analysis results
            details: Detailed analysis results
            
        Returns:
            ID of the created history record
        """
        try:
            self.execute_query(
                """
                INSERT INTO analysis_history (
                    file_id, analysis_type, analysis_time,
                    duration, result_status, result_summary, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id, analysis_type, get_current_timestamp(),
                    duration, result_status, result_summary, details
                ),
                fetch=False
            )
            
            history_id = self.connection.cursor().lastrowid
            logger.debug(f"Added analysis history for file: {file_id}")
            return history_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add analysis history: {str(e)}")
            raise DatabaseError("Failed to add analysis history") from e
    
    def get_analysis_history(self, file_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get analysis history for a file
        
        Args:
            file_id: File identifier
            limit: Maximum number of history records to return
            
        Returns:
            List of analysis history dictionaries
        """
        try:
            result = self.execute_query(
                """
                SELECT 
                    history_id, analysis_type, analysis_time,
                    duration, result_status, result_summary, details
                FROM analysis_history
                WHERE file_id = ?
                ORDER BY analysis_time DESC
                LIMIT ?
                """,
                (file_id, limit)
            )
            
            return [
                {
                    'history_id': row[0],
                    'analysis_type': row[1],
                    'analysis_time': row[2],
                    'duration': row[3],
                    'result_status': row[4],
                    'result_summary': row[5],
                    'details': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get analysis history: {str(e)}")
            raise DatabaseError("Failed to get analysis history") from e
    
    def log_system_event(self, event_type: str, source: str, severity: str,
                        message: str, details: str = None, related_file_id: str = None,
                        user_context: str = None) -> int:
        """
        Log a system event
        
        Args:
            event_type: Type of event
            source: Source of the event
            severity: Severity level ('info', 'warning', 'error', 'critical')
            message: Event message
            details: Detailed event information
            related_file_id: Related file identifier if applicable
            user_context: User context if applicable
            
        Returns:
            ID of the created event
        """
        try:
            self.execute_query(
                """
                INSERT INTO system_events (
                    event_type, event_time, source, severity,
                    message, details, related_file_id, user_context
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type, get_current_timestamp(), source, severity,
                    message, details, related_file_id, user_context
                ),
                fetch=False
            )
            
            event_id = self.connection.cursor().lastrowid
            logger.debug(f"Logged system event: {event_type}")
            return event_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to log system event: {str(e)}")
            raise DatabaseError("Failed to log system event") from e
    
    def get_system_events(self, limit: int = 100, severity: str = None,
                         event_type: str = None, source: str = None) -> List[Dict[str, Any]]:
        """
        Get system events
        
        Args:
            limit: Maximum number of events to return
            severity: Filter by severity level
            event_type: Filter by event type
            source: Filter by source
            
        Returns:
            List of system event dictionaries
        """
        try:
            conditions = []
            params = []
            
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
                
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)
                
            if source:
                conditions.append("source = ?")
                params.append(source)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            params.append(limit)
            
            result = self.execute_query(
                f"""
                SELECT 
                    event_id, event_type, event_time, source, severity,
                    message, details, related_file_id, user_context
                FROM system_events
                WHERE {where_clause}
                ORDER BY event_time DESC
                LIMIT ?
                """,
                tuple(params)
            )
            
            return [
                {
                    'event_id': row[0],
                    'event_type': row[1],
                    'event_time': row[2],
                    'source': row[3],
                    'severity': row[4],
                    'message': row[5],
                    'details': row[6],
                    'related_file_id': row[7],
                    'user_context': row[8]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get system events: {str(e)}")
            raise DatabaseError("Failed to get system events") from e
    
    def log_search(self, search_query: str, user_context: str = None,
                  result_count: int = None, duration: float = None,
                  search_type: str = None) -> int:
        """
        Log a search operation
        
        Args:
            search_query: The search query
            user_context: User context if applicable
            result_count: Number of results
            duration: Search duration in seconds
            search_type: Type of search
            
        Returns:
            ID of the created search record
        """
        try:
            self.execute_query(
                """
                INSERT INTO search_history (
                    search_query, search_time, user_context,
                    result_count, duration, search_type
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    search_query, get_current_timestamp(), user_context,
                    result_count, duration, search_type
                ),
                fetch=False
            )
            
            search_id = self.connection.cursor().lastrowid
            logger.debug(f"Logged search: {search_query}")
            return search_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to log search: {str(e)}")
            raise DatabaseError("Failed to log search") from e
    
    def get_search_history(self, limit: int = 100, user_context: str = None,
                          search_type: str = None) -> List[Dict[str, Any]]:
        """
        Get search history
        
        Args:
            limit: Maximum number of searches to return
            user_context: Filter by user context
            search_type: Filter by search type
            
        Returns:
            List of search history dictionaries
        """
        try:
            conditions = []
            params = []
            
            if user_context:
                conditions.append("user_context = ?")
                params.append(user_context)
                
            if search_type:
                conditions.append("search_type = ?")
                params.append(search_type)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            params.append(limit)
            
            result = self.execute_query(
                f"""
                SELECT 
                    search_id, search_query, search_time, user_context,
                    result_count, duration, search_type
                FROM search_history
                WHERE {where_clause}
                ORDER BY search_time DESC
                LIMIT ?
                """,
                tuple(params)
            )
            
            return [
                {
                    'search_id': row[0],
                    'search_query': row[1],
                    'search_time': row[2],
                    'user_context': row[3],
                    'result_count': row[4],
                    'duration': row[5],
                    'search_type': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get search history: {str(e)}")
            raise DatabaseError("Failed to get search history") from e
    
    def add_user_annotation(self, file_id: str, user_id: str, annotation_type: str,
                          annotation_text: str, is_private: bool = False) -> int:
        """
        Add a user annotation to a file
        
        Args:
            file_id: File identifier
            user_id: User identifier
            annotation_type: Type of annotation
            annotation_text: Annotation text
            is_private: Whether the annotation is private
            
        Returns:
            ID of the created annotation
        """
        try:
            self.execute_query(
                """
                INSERT INTO user_annotations (
                    file_id, user_id, annotation_time,
                    annotation_type, annotation_text, is_private
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id, user_id, get_current_timestamp(),
                    annotation_type, annotation_text, int(is_private)
                ),
                fetch=False
            )
            
            annotation_id = self.connection.cursor().lastrowid
            logger.debug(f"Added user annotation for file: {file_id}")
            return annotation_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add user annotation: {str(e)}")
            raise DatabaseError("Failed to add user annotation") from e
    
    def get_user_annotations(self, file_id: str, user_id: str = None,
                           include_private: bool = False) -> List[Dict[str, Any]]:
        """
        Get user annotations for a file
        
        Args:
            file_id: File identifier
            user_id: Filter by user identifier
            include_private: Whether to include private annotations
            
        Returns:
            List of annotation dictionaries
        """
        try:
            conditions = ["file_id = ?"]
            params = [file_id]
            
            if user_id:
                conditions.append("user_id = ?")
                params.append(user_id)
                
            if not include_private:
                conditions.append("is_private = 0")
            
            where_clause = " AND ".join(conditions)
            
            result = self.execute_query(
                f"""
                SELECT 
                    annotation_id, user_id, annotation_time,
                    annotation_type, annotation_text, is_private
                FROM user_annotations
                WHERE {where_clause}
                ORDER BY annotation_time DESC
                """,
                tuple(params)
            )
            
            return [
                {
                    'annotation_id': row[0],
                    'user_id': row[1],
                    'annotation_time': row[2],
                    'annotation_type': row[3],
                    'annotation_text': row[4],
                    'is_private': bool(row[5])
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get user annotations: {str(e)}")
            raise DatabaseError("Failed to get user annotations") from e
    
    def add_yara_rule(self, rule_name: str, rule_text: str, category: str = None,
                     author: str = None, is_active: bool = True, severity: str = 'medium') -> int:
        """
        Add a YARA rule
        
        Args:
            rule_name: Name of the rule
            rule_text: The YARA rule text
            category: Rule category
            author: Rule author
            is_active: Whether the rule is active
            severity: Severity level
            
        Returns:
            ID of the created rule
        """
        try:
            if len(rule_text) > MAX_RULE_LENGTH:
                raise ValueError("YARA rule text exceeds maximum length")
                
            self.execute_query(
                """
                INSERT INTO yara_rules (
                    rule_name, rule_text, category, author,
                    created_time, modified_time, is_active, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule_name, rule_text, category, author,
                    get_current_timestamp(), get_current_timestamp(),
                    int(is_active), severity
                ),
                fetch=False
            )
            
            rule_id = self.connection.cursor().lastrowid
            logger.debug(f"Added YARA rule: {rule_name}")
            return rule_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add YARA rule: {str(e)}")
            raise DatabaseError("Failed to add YARA rule") from e
    
    def get_yara_rules(self, is_active: bool = None, category: str = None,
                      severity: str = None) -> List[Dict[str, Any]]:
        """
        Get YARA rules
        
        Args:
            is_active: Filter by active status
            category: Filter by category
            severity: Filter by severity
            
        Returns:
            List of YARA rule dictionaries
        """
        try:
            conditions = []
            params = []
            
            if is_active is not None:
                conditions.append("is_active = ?")
                params.append(int(is_active))
                
            if category:
                conditions.append("category = ?")
                params.append(category)
                
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            result = self.execute_query(
                f"""
                SELECT 
                    rule_id, rule_name, rule_text, category,
                    author, created_time, modified_time,
                    is_active, severity
                FROM yara_rules
                WHERE {where_clause}
                ORDER BY rule_name
                """,
                tuple(params)
            )
            
            return [
                {
                    'rule_id': row[0],
                    'rule_name': row[1],
                    'rule_text': row[2],
                    'category': row[3],
                    'author': row[4],
                    'created_time': row[5],
                    'modified_time': row[6],
                    'is_active': bool(row[7]),
                    'severity': row[8]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get YARA rules: {str(e)}")
            raise DatabaseError("Failed to get YARA rules") from e
    
    def add_custom_metadata_field(self, field_name: str, field_type: str,
                                display_name: str, description: str = None,
                                validation_pattern: str = None, is_required: bool = False,
                                default_value: str = None) -> int:
        """
        Add a custom metadata field
        
        Args:
            field_name: Name of the field (machine-readable)
            field_type: Field type ('text', 'number', 'date', 'boolean')
            display_name: Display name of the field
            description: Field description
            validation_pattern: Validation regex pattern
            is_required: Whether the field is required
            default_value: Default value
            
        Returns:
            ID of the created field
        """
        try:
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field_name):
                raise ValueError("Field name must be alphanumeric with underscores")
                
            self.execute_query(
                """
                INSERT INTO custom_metadata_fields (
                    field_name, field_type, display_name,
                    description, validation_pattern,
                    is_required, default_value, created_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    field_name, field_type, display_name,
                    description, validation_pattern,
                    int(is_required), default_value, get_current_timestamp()
                ),
                fetch=False
            )
            
            field_id = self.connection.cursor().lastrowid
            logger.debug(f"Added custom metadata field: {field_name}")
            return field_id
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to add custom metadata field: {str(e)}")
            raise DatabaseError("Failed to add custom metadata field") from e
    
    def set_custom_metadata_value(self, file_id: str, field_id: int,
                                field_value: str, updated_by: str = None) -> None:
        """
        Set a custom metadata value for a file
        
        Args:
            file_id: File identifier
            field_id: Field identifier
            field_value: Value to set
            updated_by: User who updated the value
        """
        try:
            self.execute_query(
                """
                INSERT OR REPLACE INTO custom_metadata_values (
                    file_id, field_id, field_value,
                    last_updated, updated_by
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    file_id, field_id, field_value,
                    get_current_timestamp(), updated_by
                ),
                fetch=False
            )
            
            logger.debug(f"Set custom metadata value for file {file_id}, field {field_id}")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to set custom metadata value: {str(e)}")
            raise DatabaseError("Failed to set custom metadata value") from e
    
    def get_custom_metadata_values(self, file_id: str) -> List[Dict[str, Any]]:
        """
        Get custom metadata values for a file
        
        Args:
            file_id: File identifier
            
        Returns:
            List of custom metadata value dictionaries
        """
        try:
            result = self.execute_query(
                """
                SELECT 
                    v.field_id, f.field_name, f.field_type,
                    f.display_name, v.field_value,
                    v.last_updated, v.updated_by
                FROM custom_metadata_values v
                JOIN custom_metadata_fields f ON v.field_id = f.field_id
                WHERE v.file_id = ?
                ORDER BY f.display_name
                """,
                (file_id,)
            )
            
            return [
                {
                    'field_id': row[0],
                    'field_name': row[1],
                    'field_type': row[2],
                    'display_name': row[3],
                    'field_value': row[4],
                    'last_updated': row[5],
                    'updated_by': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get custom metadata values: {str(e)}")
            raise DatabaseError("Failed to get custom metadata values") from e
    
    def search_files(self, query: str, limit: int = MAX_SEARCH_RESULTS,
                    offset: int = 0, search_type: str = 'full_text') -> Dict[str, Any]:
        """
        Search for files
        
        Args:
            query: Search query
            limit: Maximum number of results
            offset: Result offset
            search_type: Type of search ('full_text', 'metadata', 'tags', 'content')
            
        Returns:
            Dictionary containing search results and metadata
        """
        try:
            # Validate parameters
            if limit > MAX_SEARCH_RESULTS:
                limit = MAX_SEARCH_RESULTS
                
            if search_type not in ['full_text', 'metadata', 'tags', 'content']:
                raise ValueError("Invalid search type")
            
            # Log the search
            search_id = self.log_search(
                search_query=query,
                search_type=search_type
            )
            
            # Prepare base query and params
            base_query = """
                SELECT 
                    m.file_id, m.file_path, m.file_name, m.file_size,
                    m.file_type, m.mime_type, m.fingerprint,
                    m.created_time, m.modified_time
                FROM metadata m
                WHERE {}
                ORDER BY m.modified_time DESC
                LIMIT ? OFFSET ?
            """
            
            conditions = []
            params = []
            
            # Build search conditions based on search type
            if search_type == 'full_text':
                # Search across multiple fields
                conditions.append("""
                    (m.file_name LIKE ? OR 
                     m.file_path LIKE ? OR 
                     EXISTS (
                         SELECT 1 FROM file_tags ft 
                         JOIN tags t ON ft.tag_id = t.tag_id 
                         WHERE ft.file_id = m.file_id AND t.tag_name LIKE ?
                     ) OR
                     EXISTS (
                         SELECT 1 FROM content_patterns cp
                         WHERE cp.file_id = m.file_id AND cp.pattern_value LIKE ?
                     ))
                """)
                search_param = f"%{query}%"
                params.extend([search_param] * 4)
            
            elif search_type == 'metadata':
                conditions.append("""
                    (m.file_name LIKE ? OR 
                     m.file_path LIKE ? OR 
                     m.file_type LIKE ? OR
                     m.mime_type LIKE ? OR
                     EXISTS (
                         SELECT 1 FROM extended_metadata em
                         WHERE em.file_id = m.file_id AND 
                               (em.author LIKE ? OR 
                                em.title LIKE ? OR 
                                em.subject LIKE ? OR 
                                em.keywords LIKE ?)
                     ))
                """)
                search_param = f"%{query}%"
                params.extend([search_param] * 8)
            
            elif search_type == 'tags':
                conditions.append("""
                    EXISTS (
                        SELECT 1 FROM file_tags ft 
                        JOIN tags t ON ft.tag_id = t.tag_id 
                        WHERE ft.file_id = m.file_id AND t.tag_name LIKE ?
                    )
                """)
                params.append(f"%{query}%")
            
            elif search_type == 'content':
                conditions.append("""
                    EXISTS (
                        SELECT 1 FROM content_patterns cp
                        WHERE cp.file_id = m.file_id AND cp.pattern_value LIKE ?
                    )
                """)
                params.append(f"%{query}%")
            
            # Add limit and offset to params
            params.extend([limit, offset])
            
            # Execute the query
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            result = self.execute_query(
                base_query.format(where_clause),
                tuple(params)
            )
            
            # Get total count for pagination
            count_query = f"SELECT COUNT(*) FROM metadata m WHERE {where_clause}"
            total_count = self.execute_query(count_query, tuple(params[:-2]))[0][0]
            
            # Format results
            files = [
                {
                    'file_id': row[0],
                    'file_path': row[1],
                    'file_name': row[2],
                    'file_size': row[3],
                    'file_type': row[4],
                    'mime_type': row[5],
                    'fingerprint': row[6],
                    'created_time': row[7],
                    'modified_time': row[8]
                }
                for row in result
            ]
            
            # Update search log with result count
            self.execute_query(
                "UPDATE search_history SET result_count = ? WHERE search_id = ?",
                (len(files), search_id),
                fetch=False
            )
            
            return {
                'search_id': search_id,
                'query': query,
                'search_type': search_type,
                'results': files,
                'total_count': total_count,
                'limit': limit,
                'offset': offset
            }
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to search files: {str(e)}")
            raise SearchError("Failed to search files") from e
    
    def get_file_stats(self) -> Dict[str, Any]:
        """
        Get file system statistics
        
        Returns:
            Dictionary containing various file statistics
        """
        try:
            stats = {}
            
            # Basic counts
            result = self.execute_query("SELECT COUNT(*) FROM metadata")
            stats['total_files'] = result[0][0]
            
            result = self.execute_query("SELECT COUNT(DISTINCT file_type) FROM metadata")
            stats['unique_file_types'] = result[0][0]
            
            result = self.execute_query("SELECT COUNT(DISTINCT mime_type) FROM metadata")
            stats['unique_mime_types'] = result[0][0]
            
            # Size statistics
            result = self.execute_query("SELECT SUM(file_size) FROM metadata")
            stats['total_size_bytes'] = result[0][0] or 0
            stats['total_size_human'] = human_readable_size(stats['total_size_bytes'])
            
            result = self.execute_query("SELECT AVG(file_size) FROM metadata")
            stats['avg_size_bytes'] = result[0][0] or 0
            stats['avg_size_human'] = human_readable_size(stats['avg_size_bytes'])
            
            result = self.execute_query("SELECT MAX(file_size) FROM metadata")
            stats['max_size_bytes'] = result[0][0] or 0
            stats['max_size_human'] = human_readable_size(stats['max_size_bytes'])
            
            # File type distribution
            result = self.execute_query("""
                SELECT file_type, COUNT(*) as count, SUM(file_size) as total_size
                FROM metadata
                GROUP BY file_type
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['file_type_distribution'] = [
                {'file_type': row[0], 'count': row[1], 'total_size': row[2]}
                for row in result
            ]
            
            # MIME type distribution
            result = self.execute_query("""
                SELECT mime_type, COUNT(*) as count, SUM(file_size) as total_size
                FROM metadata
                GROUP BY mime_type
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['mime_type_distribution'] = [
                {'mime_type': row[0], 'count': row[1], 'total_size': row[2]}
                for row in result
            ]
            
            # Tag statistics
            result = self.execute_query("SELECT COUNT(*) FROM tags")
            stats['total_tags'] = result[0][0]
            
            result = self.execute_query("""
                SELECT t.tag_name, COUNT(*) as file_count
                FROM tags t
                JOIN file_tags ft ON t.tag_id = ft.tag_id
                GROUP BY t.tag_name
                ORDER BY file_count DESC
                LIMIT 10
            """)
            stats['popular_tags'] = [
                {'tag_name': row[0], 'file_count': row[1]}
                for row in result
            ]
            
            # Category statistics
            result = self.execute_query("SELECT COUNT(*) FROM categories")
            stats['total_categories'] = result[0][0]
            
            result = self.execute_query("""
                SELECT c.category_name, COUNT(*) as file_count
                FROM categories c
                JOIN file_categories fc ON c.category_id = fc.category_id
                GROUP BY c.category_name
                ORDER BY file_count DESC
                LIMIT 10
            """)
            stats['popular_categories'] = [
                {'category_name': row[0], 'file_count': row[1]}
                for row in result
            ]
            
            # Security indicators
            result = self.execute_query("SELECT COUNT(*) FROM security_indicators")
            stats['total_security_indicators'] = result[0][0]
            
            result = self.execute_query("""
                SELECT severity, COUNT(*) as count
                FROM security_indicators
                GROUP BY severity
                ORDER BY count DESC
            """)
            stats['security_indicator_severity'] = [
                {'severity': row[0], 'count': row[1]}
                for row in result
            ]
            
            # Analysis history
            result = self.execute_query("""
                SELECT analysis_type, COUNT(*) as count, AVG(duration) as avg_duration
                FROM analysis_history
                GROUP BY analysis_type
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['analysis_types'] = [
                {
                    'analysis_type': row[0],
                    'count': row[1],
                    'avg_duration': row[2]
                }
                for row in result
            ]
            
            return stats
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get file stats: {str(e)}")
            raise DatabaseError("Failed to get file stats") from e
    
    def get_recent_files(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recently modified files
        
        Args:
            limit: Maximum number of files to return
            
        Returns:
            List of file metadata dictionaries
        """
        try:
            result = self.execute_query("""
                SELECT 
                    file_id, file_path, file_name, file_size,
                    file_type, mime_type, modified_time
                FROM metadata
                ORDER BY modified_time DESC
                LIMIT ?
            """, (limit,))
            
            return [
                {
                    'file_id': row[0],
                    'file_path': row[1],
                    'file_name': row[2],
                    'file_size': row[3],
                    'file_type': row[4],
                    'mime_type': row[5],
                    'modified_time': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get recent files: {str(e)}")
            raise DatabaseError("Failed to get recent files") from e
    
    def get_largest_files(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get largest files
        
        Args:
            limit: Maximum number of files to return
            
        Returns:
            List of file metadata dictionaries
        """
        try:
            result = self.execute_query("""
                SELECT 
                    file_id, file_path, file_name, file_size,
                    file_type, mime_type, modified_time
                FROM metadata
                ORDER BY file_size DESC
                LIMIT ?
            """, (limit,))
            
            return [
                {
                    'file_id': row[0],
                    'file_path': row[1],
                    'file_name': row[2],
                    'file_size': row[3],
                    'file_type': row[4],
                    'mime_type': row[5],
                    'modified_time': row[6]
                }
                for row in result
            ]
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get largest files: {str(e)}")
            raise DatabaseError("Failed to get largest files") from e
    
    def get_duplicate_files(self) -> List[Dict[str, Any]]:
        """
        Get potential duplicate files (based on fingerprint)
        
        Returns:
            List of duplicate file groups
        """
        try:
            result = self.execute_query("""
                SELECT 
                    fingerprint,
                    GROUP_CONCAT(file_id, '|') as file_ids,
                    GROUP_CONCAT(file_path, '|') as file_paths,
                    COUNT(*) as count
                FROM metadata
                GROUP BY fingerprint
                HAVING count > 1
                ORDER BY count DESC
            """)
            
            duplicates = []
            for row in result:
                file_ids = row[1].split('|')
                file_paths = row[2].split('|')
                
                duplicates.append({
                    'fingerprint': row[0],
                    'files': [
                        {'file_id': fid, 'file_path': fpath}
                        for fid, fpath in zip(file_ids, file_paths)
                    ],
                    'count': row[3]
                })
            
            return duplicates
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get duplicate files: {str(e)}")
            raise DatabaseError("Failed to get duplicate files") from e
    
    def get_file_timeline(self, days: int = 30) -> Dict[str, Any]:
        """
        Get file activity timeline
        
        Args:
            days: Number of days to include in the timeline
            
        Returns:
            Dictionary containing timeline data
        """
        try:
            timeline = {}
            
            # Get creation timeline
            result = self.execute_query(f"""
                SELECT 
                    DATE(created_time) as date,
                    COUNT(*) as count
                FROM metadata
                WHERE created_time >= DATE('now', '-{days} days')
                GROUP BY DATE(created_time)
                ORDER BY date
            """)
            timeline['created'] = [{'date': row[0], 'count': row[1]} for row in result]
            
            # Get modification timeline
            result = self.execute_query(f"""
                SELECT 
                    DATE(modified_time) as date,
                    COUNT(*) as count
                FROM metadata
                WHERE modified_time >= DATE('now', '-{days} days')
                GROUP BY DATE(modified_time)
                ORDER BY date
            """)
            timeline['modified'] = [{'date': row[0], 'count': row[1]} for row in result]
            
            # Get analysis timeline
            result = self.execute_query(f"""
                SELECT 
                    DATE(analysis_time) as date,
                    COUNT(*) as count
                FROM analysis_history
                WHERE analysis_time >= DATE('now', '-{days} days')
                GROUP BY DATE(analysis_time)
                ORDER BY date
            """)
            timeline['analyzed'] = [{'date': row[0], 'count': row[1]} for row in result]
            
            return timeline
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to get file timeline: {str(e)}")
            raise DatabaseError("Failed to get file timeline") from e
    
    def backup_database(self, backup_path: str) -> None:
        """
        Create a backup of the database
        
        Args:
            backup_path: Path to save the backup
        """
        try:
            with self.lock:
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                
                backup_conn = sqlite3.connect(backup_path)
                with backup_conn:
                    self.connection.backup(backup_conn)
                backup_conn.close()
                
                logger.info(f"Database backup created at: {backup_path}")
        except Exception as e:
            logger.error(f"Failed to backup database: {str(e)}")
            raise DatabaseError("Failed to backup database") from e
    
    def vacuum_database(self) -> None:
        """Optimize database by running VACUUM"""
        try:
            with self.lock:
                self.execute_query("VACUUM", fetch=False)
                logger.info("Database optimization (VACUUM) completed")
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Failed to optimize database: {str(e)}")
            raise DatabaseError("Failed to optimize database") from e

# File metadata extractors
class MetadataExtractor:
    """Base class for metadata extractors"""
    
    @staticmethod
    def extract_basic_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extract basic file metadata
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary of basic metadata
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            stat = os.stat(file_path)
            file_name = os.path.basename(file_path)
            file_type = get_file_type(file_path)
            is_binary = is_binary_file(file_path)
            
            # Get owner and group (platform dependent)
            try:
                import pwd
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except (ImportError, AttributeError):
                owner = None
                
            try:
                import grp
                group_name = grp.getgrgid(stat.st_gid).gr_name
            except (ImportError, AttributeError):
                group_name = None
            
            # Get permissions in octal
            try:
                permissions = oct(stat.st_mode & 0o777)
            except Exception:
                permissions = None
            
            metadata = {
                'file_path': file_path,
                'file_name': file_name,
                'file_size': stat.st_size,
                'file_type': file_type,
                'mime_type': get_file_type(file_path),
                'created_time': datetime.datetime.fromtimestamp(stat.st_ctime, pytz.UTC).isoformat(),
                'modified_time': datetime.datetime.fromtimestamp(stat.st_mtime, pytz.UTC).isoformat(),
                'accessed_time': datetime.datetime.fromtimestamp(stat.st_atime, pytz.UTC).isoformat(),
                'is_binary': is_binary,
                'owner': owner,
                'group_name': group_name,
                'permissions': permissions,
                'is_hidden': file_name.startswith('.') or os.path.basename(os.path.dirname(file_path)).startswith('.'),
                'is_system': False  # This would need platform-specific detection
            }
            
            return metadata
        except Exception as e:
            logger.error(f"Failed to extract basic metadata: {file_path} - {str(e)}")
            raise MetadataExtractionError(f"Basic metadata extraction failed: {str(e)}") from e
    
    @staticmethod
    def extract_extended_metadata(file_path: str, mime_type: str = None) -> Dict[str, Any]:
        """
        Extract extended metadata based on file type
        
        Args:
            file_path: Path to the file
            mime_type: Optional MIME type of the file
            
        Returns:
            Dictionary of extended metadata
        """
        try:
            if not mime_type:
                mime_type = get_file_type(file_path)
            
            metadata = {}
            
            # Handle common document types
            if mime_type in ['application/pdf', 'application/vnd.ms-excel',
                            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                            'application/vnd.ms-powerpoint',
                            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                            'application/msword',
                            'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                metadata.update(MetadataExtractor._extract_office_metadata(file_path, mime_type))
            
            # Handle images
            elif mime_type.startswith('image/'):
                metadata.update(MetadataExtractor._extract_image_metadata(file_path))
            
            # Handle audio/video
            elif mime_type.startswith('audio/') or mime_type.startswith('video/'):
                metadata.update(MetadataExtractor._extract_media_metadata(file_path))
            
            # Handle archives
            elif mime_type in ['application/zip', 'application/x-tar',
                              'application/x-gzip', 'application/x-bzip2']:
                metadata.update(MetadataExtractor._extract_archive_metadata(file_path, mime_type))
            
            # Handle text files
            elif mime_type.startswith('text/'):
                metadata.update(MetadataExtractor._extract_text_metadata(file_path))
            
            return metadata
        except Exception as e:
            logger.error(f"Failed to extract extended metadata: {file_path} - {str(e)}")
            raise MetadataExtractionError(f"Extended metadata extraction failed: {str(e)}") from e
    
    @staticmethod
    def _extract_office_metadata(file_path: str, mime_type: str) -> Dict[str, Any]:
        """
        Extract metadata from office documents (PDF, Word, Excel, PowerPoint)
        
        Args:
            file_path: Path to the file
            mime_type: MIME type of the file
            
        Returns:
            Dictionary of office document metadata
        """
        metadata = {}
        
        try:
            if mime_type == 'application/pdf':
                with open(file_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    
                    if hasattr(pdf_reader, 'metadata'):
                        info = pdf_reader.metadata
                        if info:
                            metadata.update({
                                'author': info.get('/Author'),
                                'title': info.get('/Title'),
                                'subject': info.get('/Subject'),
                                'creator': info.get('/Creator'),
                                'producer': info.get('/Producer'),
                                'creation_date': info.get('/CreationDate'),
                                'modification_date': info.get('/ModDate')
                            })
                    
                    metadata['page_count'] = len(pdf_reader.pages)
            
            elif mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                doc = Document(file_path)
                metadata.update({
                    'author': doc.core_properties.author,
                    'title': doc.core_properties.title,
                    'subject': doc.core_properties.subject,
                    'keywords': doc.core_properties.keywords,
                    'comments': doc.core_properties.comments,
                    'creator': doc.core_properties.creator,
                    'creation_date': doc.core_properties.created.isoformat() if doc.core_properties.created else None,
                    'modification_date': doc.core_properties.modified.isoformat() if doc.core_properties.modified else None
                })
                
                # Count paragraphs as an approximation of content
                paragraph_count = 0
                for para in doc.paragraphs:
                    if para.text.strip():
                        paragraph_count += 1
                metadata['paragraph_count'] = paragraph_count
            
            elif mime_type in ['application/vnd.ms-excel',
                              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
                wb = openpyxl.load_workbook(file_path)
                metadata.update({
                    'author': wb.properties.creator,
                    'title': wb.properties.title,
                    'subject': wb.properties.subject,
                    'keywords': wb.properties.keywords,
                    'comments': wb.properties.description,
                    'creator': wb.properties.creator,
                    'creation_date': wb.properties.created.isoformat() if wb.properties.created else None,
                    'modification_date': wb.properties.modified.isoformat() if wb.properties.modified else None
                })
                metadata['sheet_count'] = len(wb.sheetnames)
            
            return metadata
        except Exception as e:
            logger.warning(f"Office metadata extraction incomplete: {file_path} - {str(e)}")
            return metadata
    
    @staticmethod
    def _extract_image_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from image files
        
        Args:
            file_path: Path to the image file
            
        Returns:
            Dictionary of image metadata
        """
        metadata = {}
        
        try:
            with Image.open(file_path) as img:
                metadata.update({
                    'width': img.width,
                    'height': img.height,
                    'format': img.format,
                    'mode': img.mode
                })
                
                # Extract EXIF data if available
                if hasattr(img, '_getexif') and img._getexif() is not None:
                    exif_data = {
                        ExifTags.TAGS[k]: v
                        for k, v in img._getexif().items()
                        if k in ExifTags.TAGS
                    }
                    
                    # Map common EXIF tags to our metadata fields
                    exif_mapping = {
                        'DateTime': 'creation_date',
                        'DateTimeOriginal': 'creation_date',
                        'DateTimeDigitized': 'modification_date',
                        'Make': 'camera_make',
                        'Model': 'camera_model',
                        'Software': 'software_used',
                        'XResolution': 'resolution',
                        'YResolution': 'resolution',
                        'GPSInfo': 'gps_coordinates'
                    }
                    
                    for exif_tag, meta_field in exif_mapping.items():
                        if exif_tag in exif_data:
                            metadata[meta_field] = exif_data[exif_tag]
            
            return metadata
        except Exception as e:
            logger.warning(f"Image metadata extraction incomplete: {file_path} - {str(e)}")
            return metadata
    
    @staticmethod
    def _extract_media_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from audio/video files
        
        Args:
            file_path: Path to the media file
            
        Returns:
            Dictionary of media metadata
        """
        metadata = {}
        
        try:
            # This would use a proper media metadata library in a real implementation
            # For now we'll just return basic info
            return metadata
        except Exception as e:
            logger.warning(f"Media metadata extraction incomplete: {file_path} - {str(e)}")
            return metadata
    
    @staticmethod
    def _extract_archive_metadata(file_path: str, mime_type: str) -> Dict[str, Any]:
        """
        Extract metadata from archive files
        
        Args:
            file_path: Path to the archive file
            mime_type: MIME type of the archive
            
        Returns:
            Dictionary of archive metadata
        """
        metadata = {}
        
        try:
            if mime_type == 'application/zip':
                with zipfile.ZipFile(file_path, 'r') as zipf:
                    metadata['file_count'] = len(zipf.infolist())
                    metadata['comment'] = zipf.comment.decode('utf-8', errors='ignore') if zipf.comment else None
            
            elif mime_type == 'application/x-tar':
                with tarfile.open(file_path, 'r:*') as tarf:
                    metadata['file_count'] = len(tarf.getmembers())
            
            return metadata
        except Exception as e:
            logger.warning(f"Archive metadata extraction incomplete: {file_path} - {str(e)}")
            return metadata
    
    @staticmethod
    def _extract_text_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from text files
        
        Args:
            file_path: Path to the text file
            
        Returns:
            Dictionary of text metadata
        """
        metadata = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Basic text statistics
                lines = content.splitlines()
                words = [word for line in lines for word in line.split()]
                
                metadata.update({
                    'line_count': len(lines),
                    'word_count': len(words),
                    'character_count': len(content)
                })
                
                # Try to detect language
                try:
                    from langdetect import detect
                    metadata['language'] = detect(content)
                except (ImportError, Exception):
                    pass
            
            return metadata
        except Exception as e:
            logger.warning(f"Text metadata extraction incomplete: {file_path} - {str(e)}")
            return metadata

# File content analyzers
class ContentAnalyzer:
    """Analyze file content for patterns, keywords, and other features"""
    
    @staticmethod
    def analyze_content(file_path: str, mime_type: str = None) -> Dict[str, Any]:
        """
        Analyze file content based on file type
        
        Args:
            file_path: Path to the file
            mime_type: Optional MIME type of the file
            
        Returns:
            Dictionary of analysis results
        """
        try:
            if not mime_type:
                mime_type = get_file_type(file_path)
            
            results = {}
            
            # Handle text-based files
            if mime_type.startswith('text/') or not is_binary_file(file_path):
                results.update(ContentAnalyzer._analyze_text_content(file_path))
            
            # Handle binary files
            else:
                results.update(ContentAnalyzer._analyze_binary_content(file_path))
            
            return results
        except Exception as e:
            logger.error(f"Content analysis failed: {file_path} - {str(e)}")
            raise FileAnalysisError(f"Content analysis failed: {str(e)}") from e
    
    @staticmethod
    def _analyze_text_content(file_path: str) -> Dict[str, Any]:
        """
        Analyze text file content
        
        Args:
            file_path: Path to the text file
            
        Returns:
            Dictionary of text analysis results
        """
        results = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Common patterns to look for
                patterns = {
                    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-]*/?',
                    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                    'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
                    'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
                    'phone': r'\b(?:\+?\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b'
                }
                
                # Find matches for each pattern
                pattern_matches = {}
                for name, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        pattern_matches[name] = {
                            'count': len(matches),
                            'examples': list(set(matches))[:3]  # Show up to 3 unique examples
                        }
                
                if pattern_matches:
                    results['pattern_matches'] = pattern_matches
                
                # Extract keywords (simple approach - would use NLP in a real implementation)
                words = re.findall(r'\w{3,}', content.lower())
                word_counts = Counter(words)
                common_words = word_counts.most_common(10)
                
                if common_words:
                    results['common_words'] = [
                        {'word': word, 'count': count}
                        for word, count in common_words
                    ]
            
            return results
        except Exception as e:
            logger.warning(f"Text content analysis incomplete: {file_path} - {str(e)}")
            return results
    
    @staticmethod
    def _analyze_binary_content(file_path: str) -> Dict[str, Any]:
        """
        Analyze binary file content
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Dictionary of binary analysis results
        """
        results = {}
        
        try:
            with open(file_path, 'rb') as f:
                # Read first 1KB for header analysis
                header = f.read(1024)
                
                # Check for common file signatures (magic numbers)
                signatures = {
                    'PE_executable': b'MZ',
                    'ELF_executable': b'\x7fELF',
                    'PDF': b'%PDF',
                    'ZIP': b'PK\x03\x04',
                    'PNG': b'\x89PNG',
                    'JPEG': b'\xff\xd8\xff',
                    'GIF': b'GIF'
                }
                
                detected_signatures = []
                for name, sig in signatures.items():
                    if header.startswith(sig):
                        detected_signatures.append(name)
                
                if detected_signatures:
                    results['file_signatures'] = detected_signatures
                
                # Check for embedded strings
                strings = re.findall(b'[\\x20-\\x7E]{4,}', header)
                if strings:
                    results['embedded_strings'] = [
                        s.decode('ascii', errors='ignore')
                        for s in strings[:10]  # Limit to first 10 strings
                    ]
            
            return results
        except Exception as e:
            logger.warning(f"Binary content analysis incomplete: {file_path} - {str(e)}")
            return results
    
    @staticmethod
    def run_yara_scan(file_path: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run YARA rules against a file
        
        Args:
            file_path: Path to the file
            rules: List of YARA rules (from database)
            
        Returns:
            List of YARA matches
        """
        matches = []
        
        try:
            # Compile YARA rules
            yara_rules = []
            for rule in rules:
                try:
                    yara_rules.append(yara.compile(source=rule['rule_text']))
                except Exception as e:
                    logger.warning(f"Failed to compile YARA rule {rule['rule_id']}: {str(e)}")
                    continue
            
            # Scan the file
            for rule, compiled in zip(rules, yara_rules):
                try:
                    with open(file_path, 'rb') as f:
                        file_matches = compiled.match(data=f.read())
                        if file_matches:
                            matches.append({
                                'rule_id': rule['rule_id'],
                                'rule_name': rule['rule_name'],
                                'category': rule['category'],
                                'severity': rule['severity'],
                                'matches': [str(m) for m in file_matches]
                            })
                except Exception as e:
                    logger.warning(f"YARA scan failed for rule {rule['rule_id']}: {str(e)}")
                    continue
            
            return matches
        except Exception as e:
            logger.error(f"YARA scanning failed: {file_path} - {str(e)}")
            raise FileAnalysisError(f"YARA scanning failed: {str(e)}") from e

# Security analyzer
class SecurityAnalyzer:
    """Analyze files for security indicators"""
    
    @staticmethod
    def analyze_file_security(file_path: str, mime_type: str = None) -> List[Dict[str, Any]]:
        """
        Analyze a file for security indicators
        
        Args:
            file_path: Path to the file
            mime_type: Optional MIME type of the file
            
        Returns:
            List of security indicators found
        """
        indicators = []
        
        try:
            if not mime_type:
                mime_type = get_file_type(file_path)
            
            # Check for executable files with suspicious properties
            if mime_type in ['application/x-dosexec', 'application/x-executable',
                            'application/x-mach-binary', 'application/x-msdownload']:
                indicators.extend(SecurityAnalyzer._analyze_executable(file_path))
            
            # Check for suspicious document macros
            elif mime_type in ['application/msword', 'application/vnd.ms-excel',
                              'application/vnd.ms-powerpoint',
                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                indicators.extend(SecurityAnalyzer._analyze_office_document(file_path, mime_type))
            
            # Check for suspicious scripts
            elif mime_type in ['text/x-python', 'application/x-shellscript',
                              'application/x-perl', 'application/x-ruby']:
                indicators.extend(SecurityAnalyzer._analyze_script(file_path, mime_type))
            
            # Check for suspicious archive files
            elif mime_type in ['application/zip', 'application/x-tar',
                              'application/x-rar-compressed']:
                indicators.extend(SecurityAnalyzer._analyze_archive(file_path, mime_type))
            
            return indicators
        except Exception as e:
            logger.error(f"Security analysis failed: {file_path} - {str(e)}")
            raise SecurityError(f"Security analysis failed: {str(e)}") from e
    
    @staticmethod
    def _analyze_executable(file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze an executable file for security indicators
        
        Args:
            file_path: Path to the executable file
            
        Returns:
            List of security indicators
        """
        indicators = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB
                
                # Check for common malware patterns
                patterns = {
                    'Suspicious_Import': [
                        b'LoadLibrary', b'GetProcAddress', b'VirtualAlloc',
                        b'CreateRemoteThread', b'WriteProcessMemory'
                    ],
                    'Packer_Signature': [
                        b'UPX', b'ASPack', b'FSG', b'PECompact'
                    ],
                    'Obfuscation_Technique': [
                        b'VMProtect', b'Themida', b'CodeVirtualizer'
                    ]
                }
                
                for indicator_type, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if pattern in content:
                            indicators.append({
                                'indicator_type': indicator_type,
                                'indicator_value': pattern.decode('ascii', errors='ignore'),
                                'severity': 'high',
                                'description': f"Found {indicator_type.replace('_', ' ')} in executable"
                            })
                            break  # Only report once per type
            
            return indicators
        except Exception as e:
            logger.warning(f"Executable analysis incomplete: {file_path} - {str(e)}")
            return indicators
    
    @staticmethod
    def _analyze_office_document(file_path: str, mime_type: str) -> List[Dict[str, Any]]:
        """
        Analyze an office document for security indicators
        
        Args:
            file_path: Path to the office document
            mime_type: MIME type of the document
            
        Returns:
            List of security indicators
        """
        indicators = []
        
        try:
            # Check for macros in older office formats
            if mime_type in ['application/msword', 'application/vnd.ms-excel',
                            'application/vnd.ms-powerpoint']:
                with open(file_path, 'rb') as f:
                    content = f.read(4096)
                    if b'Macros' in content or b'VBA' in content:
                        indicators.append({
                            'indicator_type': 'Office_Macro',
                            'indicator_value': 'Macro detected',
                            'severity': 'medium',
                            'description': "Document contains macros which could be malicious"
                        })
            
            # Check for OLE objects in newer office formats
            elif mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                with zipfile.ZipFile(file_path, 'r') as zipf:
                    if 'word/vbaProject.bin' in zipf.namelist():
                        indicators.append({
                            'indicator_type': 'Office_Macro',
                            'indicator_value': 'Macro detected',
                            'severity': 'medium',
                            'description': "Document contains macros which could be malicious"
                        })
            
            return indicators
        except Exception as e:
            logger.warning(f"Office document analysis incomplete: {file_path} - {str(e)}")
            return indicators
    
    @staticmethod
    def _analyze_script(file_path: str, mime_type: str) -> List[Dict[str, Any]]:
        """
        Analyze a script file for security indicators
        
        Args:
            file_path: Path to the script file
            mime_type: MIME type of the script
            
        Returns:
            List of security indicators
        """
        indicators = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Check for suspicious commands
                suspicious_commands = {
                    'python': ['os.system', 'subprocess.call', 'eval', 'exec', 'pickle.load'],
                    'shell': ['rm -rf', 'chmod 777', 'wget', 'curl', 'nc ', 'netcat'],
                    'powershell': ['Invoke-Expression', 'Start-Process', 'DownloadString']
                }
                
                script_type = None
                if mime_type == 'text/x-python':
                    script_type = 'python'
                elif mime_type == 'application/x-shellscript':
                    script_type = 'shell'
                
                if script_type and script_type in suspicious_commands:
                    for cmd in suspicious_commands[script_type]:
                        if cmd in content:
                            indicators.append({
                                'indicator_type': 'Suspicious_Script_Command',
                                'indicator_value': cmd,
                                'severity': 'medium',
                                'description': f"Script contains potentially dangerous command: {cmd}"
                            })
            
            return indicators
        except Exception as e:
            logger.warning(f"Script analysis incomplete: {file_path} - {str(e)}")
            return indicators
    
    @staticmethod
    def _analyze_archive(file_path: str, mime_type: str) -> List[Dict[str, Any]]:
        """
        Analyze an archive file for security indicators
        
        Args:
            file_path: Path to the archive file
            mime_type: MIME type of the archive
            
        Returns:
            List of security indicators
        """
        indicators = []
        
        try:
            # Check for suspicious file extensions in archives
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.js', '.vbs']
            
            if mime_type == 'application/zip':
                with zipfile.ZipFile(file_path, 'r') as zipf:
                    for name in zipf.namelist():
                        if any(name.lower().endswith(ext) for ext in suspicious_extensions):
                            indicators.append({
                                'indicator_type': 'Archive_Suspicious_File',
                                'indicator_value': name,
                                'severity': 'medium',
                                'description': f"Archive contains potentially dangerous file: {name}"
                            })
            
            elif mime_type == 'application/x-tar':
                with tarfile.open(file_path, 'r:*') as tarf:
                    for member in tarf.getmembers():
                        if any(member.name.lower().endswith(ext) for ext in suspicious_extensions):
                            indicators.append({
                                'indicator_type': 'Archive_Suspicious_File',
                                'indicator_value': member.name,
                                'severity': 'medium',
                                'description': f"Archive contains potentially dangerous file: {member.name}"
                            })
            
            return indicators
        except Exception as e:
            logger.warning(f"Archive analysis incomplete: {file_path} - {str(e)}")
            return indicators

# File system monitor
class FileSystemMonitor(FileSystemEventHandler):
    """Monitor file system changes and update metadata accordingly"""
    
    def __init__(self, intel_db: FireSenseIntelDatabase):
        """
        Initialize the file system monitor
        
        Args:
            intel_db: FireSenseIntelDatabase instance
        """
        self.intel_db = intel_db
        self.observer = Observer()
        self.watched_paths = set()
        self.lock = threading.Lock()
    
    def start_monitoring(self, path: str) -> None:
        """
        Start monitoring a directory path
        
        Args:
            path: Path to monitor
        """
        with self.lock:
            if path not in self.watched_paths:
                self.observer.schedule(self, path, recursive=True)
                self.watched_paths.add(path)
                logger.info(f"Started monitoring path: {path}")
    
    def stop_monitoring(self, path: str) -> None:
        """
        Stop monitoring a directory path
        
        Args:
            path: Path to stop monitoring
        """
        with self.lock:
            if path in self.watched_paths:
                for watch in self.observer._watches:
                    if watch.path == path:
                        self.observer.unschedule(watch)
                        break
                self.watched_paths.remove(path)
                logger.info(f"Stopped monitoring path: {path}")
    
    def start(self) -> None:
        """Start the observer thread"""
        if not self.observer.is_alive():
            self.observer.start()
            logger.info("File system monitor started")
    
    def stop(self) -> None:
        """Stop the observer thread"""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            logger.info("File system monitor stopped")
    
    def on_created(self, event):
        """Handle file creation event"""
        try:
            if not event.is_directory:
                file_path = event.src_path
                logger.debug(f"File created: {file_path}")
