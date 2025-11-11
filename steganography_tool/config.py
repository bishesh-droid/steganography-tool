# steganography_tool/config.py

import os

# Number of least significant bits to use for embedding data per color channel.
# Higher values (e.g., 2 or 3) increase capacity but also increase detectability.
# 1 is generally a good balance for imperceptibility.
LSB_BITS_TO_USE = 1

# Path for the steganography tool log file
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'steganography_tool.log')

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True
