# steganography_tool/logger.py

import logging
import os
from .config import LOG_FILE, LOG_DIR, VERBOSE_CONSOLE_OUTPUT

def setup_logging():
    """
    Configures logging for the Steganography Tool.
    Logs to a file and optionally to the console.
    """
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create a logger
    stego_logger = logging.getLogger('steganography_tool')
    stego_logger.setLevel(logging.DEBUG)
    stego_logger.propagate = False # Prevent messages from being passed to the root logger

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    stego_logger.addHandler(file_handler)

    # Console handler (optional)
    if VERBOSE_CONSOLE_OUTPUT:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        stego_logger.addHandler(console_handler)

    return stego_logger

# Initialize logger when module is imported
stego_logger = setup_logging()
