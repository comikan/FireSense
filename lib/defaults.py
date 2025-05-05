#!/usr/bin/env python3
"""
FireSense Default Configuration Setter
Minimal script to manage default configurations for the FireSense system.
"""

import json
import argparse
from pathlib import Path

# Default configuration
DEFAULTS = {
    "host": "localhost",
    "port": 8080,
    "upload_dir": "FireSense/uploads",
    "max_file_size": 104857600,  # 100MB
    "thumbnail_size": "128x128"
}

def save_config(config, path="firesense_config.json"):
    """Save configuration to JSON file"""
    try:
        with open(path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Configuration saved to {path}")
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

def show_config(config):
    """Display current configuration"""
    print("Current FireSense configuration:")
    for key, value in config.items():
        print(f"{key:>15}: {value}")

def main():
    parser = argparse.ArgumentParser(description="Set FireSense defaults")
    parser.add_argument('--host', help="Server host address")
    parser.add_argument('--port', type=int, help="Server port number")
    parser.add_argument('--upload-dir', help="Upload directory path")
    parser.add_argument('--max-size', type=int, 
                      help="Max file size in bytes")
    parser.add_argument('--thumb-size', help="Thumbnail dimensions")
    parser.add_argument('--show', action='store_true',
                      help="Show current defaults")
    args = parser.parse_args()

    config = DEFAULTS.copy()

    # Update from command line arguments
    if args.host: config["host"] = args.host
    if args.port: config["port"] = args.port
    if args.upload_dir: config["upload_dir"] = args.upload_dir
    if args.max_size: config["max_file_size"] = args.max_size
    if args.thumb_size: config["thumbnail_size"] = args.thumb_size

    if args.show or not any(vars(args).values()):
        show_config(config)
    
    save_config(config)

if __name__ == "__main__":
    main()
