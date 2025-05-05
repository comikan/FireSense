#!/usr/bin/env python3
import os
import hashlib
from typing import Tuple, Generator
from dataclasses import dataclass
from contextlib import contextmanager

@dataclass
class TransferConfig:
    chunk_size: int = 1024 * 1024  # 1MB
    max_retries: int = 3
    verify_checksum: bool = True

class FireSenseHandler:
    """Bidirectional transfer handler core"""
    
    def __init__(self, config: TransferConfig = TransferConfig()):
        self.config = config
    
    def generate_chunks(self, file_path: str) -> Generator[Tuple[bytes, str], None, None]:
        """Yield file chunks with incremental checksum"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.config.chunk_size):
                hasher.update(chunk)
                yield chunk, hasher.hexdigest()
    
    def reconstruct_file(self, chunks: Generator[Tuple[bytes, str], None, None], target_path: str) -> bool:
        """Rebuild file from chunks with verification"""
        temp_path = f"{target_path}.tmp"
        hasher = hashlib.sha256()
        
        try:
            with open(temp_path, 'wb') as f:
                for chunk, chunk_checksum in chunks:
                    f.write(chunk)
                    hasher.update(chunk)
                    if self.config.verify_checksum and hasher.hexdigest() != chunk_checksum:
                        raise ValueError("Checksum mismatch")
            
            os.rename(temp_path, target_path)
            return True
        except:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    
    @contextmanager
    def atomic_upload(self, file_path: str, target_path: str):
        """Context manager for atomic file transfers"""
        temp_path = f"{target_path}.tmp"
        try:
            yield temp_path
            os.rename(temp_path, target_path)
        except:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
