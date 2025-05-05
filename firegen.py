#!/usr/bin/env python3
import os
import secrets
import sys
import argparse
from cryptography.fernet import Fernet
from typing import Optional

def generate_fernet_key() -> str:
    """Generate a Fernet-compatible encryption key"""
    return Fernet.generate_key().decode()

def generate_hmac_key(length: int = 32) -> str:
    """Generate a random HMAC signing key"""
    return secrets.token_urlsafe(length)

def generate_composite_key() -> dict:
    """Generate a set of keys for different purposes"""
    return {
        'api_auth': secrets.token_hex(32),
        'data_encryption': generate_fernet_key(),
        'url_signing': generate_hmac_key(),
        'jwt_secret': secrets.token_urlsafe(64)
    }

def save_keys(keys: dict, env_file: Optional[str] = None) -> None:
    """Save keys to environment file"""
    content = "\n".join(f"{k.upper()}={v}" for k, v in keys.items())
    
    if env_file:
        with open(env_file, 'w') as f:
            f.write(content + "\n")
        os.chmod(env_file, 0o600)  # Restrict file permissions
    else:
        print(content)

def main():
    parser = argparse.ArgumentParser(description="FireSense Key Generator")
    parser.add_argument('--env-file', help="Save to .env file", default=None)
    parser.add_argument('--rotate', help="Rotate existing keys", action='store_true')
    args = parser.parse_args()

    print("🔑 Generating FireSense secret keys...")
    keys = generate_composite_key()
    
    if args.rotate:
        keys = {k: f"OLD_{v}" for k, v in keys.items()} | generate_composite_key()
    
    save_keys(keys, args.env_file)
    print("✅ Done" + (" (saved to .env)" if args.env_file else ""))
