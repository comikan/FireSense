#!/usr/bin/env python3
import os
import threading
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass
import mimetypes

@dataclass(frozen=True)
class StaticFile:
    path: str
    size: int = 0
    mime_type: Optional[str] = None
    metadata: Dict[str, str] = None

class StaticFileHandler:
    """Thread-safe static empty file handler with metadata support"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
        return cls._instance
    
    def _init(self):
        """Initialize mimetypes"""
        mimetypes.init()
        self._file_cache = {}
        self._cache_lock = threading.Lock()
    
    def register(self, file_path: str, metadata: Dict[str, str] = None) -> StaticFile:
        """Register a static file with optional metadata"""
        path = str(Path(file_path).absolute())
        
        with self._cache_lock:
            if path in self._file_cache:
                return self._file_cache[path]
                
            mime_type, _ = mimetypes.guess_type(path)
            sf = StaticFile(
                path=path,
                mime_type=mime_type,
                metadata=metadata or {}
            )
            self._file_cache[path] = sf
            return sf
    
    def get(self, file_path: str) -> Optional[StaticFile]:
        """Get registered static file"""
        path = str(Path(file_path).absolute())
        with self._cache_lock:
            return self._file_cache.get(path)
    
    def create_empty(self, file_path: str) -> StaticFile:
        """Create and register an empty file"""
        path = Path(file_path)
        path.touch(exist_ok=True)
        return self.register(str(path.absolute()))
