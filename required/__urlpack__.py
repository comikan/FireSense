#!/usr/bin/env python3
import os
import time
import hashlib
import hmac
from urllib.parse import quote, urlencode
from typing import Optional, Dict
from dataclasses import dataclass

@dataclass
class FileURL:
    base_url: str
    file_id: str
    expires: Optional[int] = None
    disposition: Optional[str] = None
    secret: Optional[str] = None

class URLKit:
    """Secure URL generator and validator"""
    
    def __init__(self, secret_key: str = os.getenv("FIRESENSE_SECRET")):
        self.secret_key = secret_key.encode()
    
    def generate(self, file_url: FileURL) -> str:
        """Create signed URL with optional expiration"""
        params = {'id': file_url.file_id}
        if file_url.expires:
            params['exp'] = file_url.expires
        if file_url.disposition:
            params['disp'] = file_url.disposition
        
        if file_url.secret or self.secret_key:
            params['sig'] = self._sign_params(params)
        
        return f"{file_url.base_url}?{urlencode(params)}"
    
    def validate(self, url: str) -> bool:
        """Verify URL signature and expiration"""
        params = dict(pair.split('=') for pair in url.split('?')[1].split('&'))
        
        if 'sig' not in params:
            return False
            
        if 'exp' in params and int(params['exp']) < time.time():
            return False
            
        sig = params.pop('sig')
        return hmac.compare_digest(sig, self._sign_params(params))
    
    def _sign_params(self, params: Dict[str, str]) -> str:
        """HMAC-SHA256 signature of parameters"""
        msg = '&'.join(f"{k}={v}" for k, v in sorted(params.items()))
        return hmac.new(self.secret_key, msg.encode(), hashlib.sha256).hexdigest()
