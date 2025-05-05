#!/usr/bin/env python3
"""
FireSense Initialization Script
A professional, minimal script to initialize the FireSense file storage system.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Configuration
DEFAULT_CONFIG = {
    "base_dir": "FireSense",
    "subdirectories": [
        "uploads",
        "processed",
        "backups",
        "thumbnails",
        "failed"
    ],
    "log_file": "firesense_init.log"
}

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(DEFAULT_CONFIG["log_file"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("FireSense.Init")

def initialize_firesense(base_path, clean=False):
    """
    Initialize the FireSense directory structure
    
    Args:
        base_path (str): Path to create FireSense structure
        clean (bool): Whether to clean existing directories
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        base_path = Path(base_path).absolute()
        
        if clean:
            logger.warning(f"Cleaning existing FireSense structure at {base_path}")
            try:
                if base_path.exists():
                    for item in base_path.iterdir():
                        if item.is_dir():
                            shutil.rmtree(item)
                        else:
                            item.unlink()
            except Exception as e:
                logger.error(f"Clean failed: {e}")
                return False

        # Create base directory
        base_path.mkdir(exist_ok=True)
        logger.info(f"Created base directory: {base_path}")

        # Create subdirectories
        for subdir in DEFAULT_CONFIG["subdirectories"]:
            dir_path = base_path / subdir
            dir_path.mkdir(exist_ok=True)
            logger.info(f"Created subdirectory: {dir_path}")

        # Create README file
        readme_path = base_path / "README.md"
        if not readme_path.exists():
            with open(readme_path, 'w') as f:
                f.write("# FireSense File Storage System\n\n")
                f.write("This directory contains the FireSense file storage structure.\n")
                f.write("\n## Directory Structure\n")
                f.write("- uploads: For incoming file uploads\n")
                f.write("- processed: For successfully processed files\n")
                f.write("- backups: For system backups\n")
                f.write("- thumbnails: For generated thumbnails\n")
                f.write("- failed: For files that failed processing\n")
            logger.info(f"Created README file: {readme_path}")

        return True

    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Initialize the FireSense file storage system",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-p', '--path',
        default=DEFAULT_CONFIG["base_dir"],
        help="Base path for FireSense installation"
    )
    parser.add_argument(
        '-c', '--clean',
        action='store_true',
        help="Clean existing directory before initialization"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    return parser.parse_args()

def main():
    """Main execution function"""
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    logger.info("Starting FireSense initialization")
    logger.debug(f"Arguments: {vars(args)}")
    
    success = initialize_firesense(args.path, args.clean)
    
    if success:
        logger.info("FireSense initialization completed successfully")
        print(f"\nFireSense initialized at: {os.path.abspath(args.path)}")
        print("Directory structure created:")
        for subdir in DEFAULT_CONFIG["subdirectories"]:
            print(f"  - {os.path.join(args.path, subdir)}")
        return 0
    else:
        logger.error("FireSense initialization failed")
        return 1

if __name__ == "__main__":
    try:
        import shutil
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Initialization interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        sys.exit(1)
