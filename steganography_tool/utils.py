from PIL import Image
import os

from .logger import stego_logger

def bytes_to_bits(data: bytes):
    """
    Converts a byte string into a generator of individual bits (0s and 1s).
    """
    for byte in data:
        for i in range(8):
            yield (byte >> (7 - i)) & 1

def bits_to_bytes(bits) -> bytes:
    """
    Converts a list/generator of bits (0s and 1s) back into a byte string.
    """
    byte_string = bytearray()
    byte = 0
    count = 0
    for bit in bits:
        byte = (byte << 1) | bit
        count += 1
        if count == 8:
            byte_string.append(byte)
            byte = 0
            count = 0
    # If there are remaining bits that don't form a full byte, they are ignored.
    return bytes(byte_string)

def get_image_format(image_path: str) -> str:
    """
    Determines the format of an image file.
    """
    try:
        with Image.open(image_path) as img:
            return img.format
    except Exception as e:
        stego_logger.error(f"[ERROR] Could not determine image format for {image_path}: {e}")
        return None

def validate_image_for_stego(image_path: str):
    """
    Validates if the image is suitable for LSB steganography (PNG or BMP).
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file not found: {image_path}")

    img_format = get_image_format(image_path)
    if img_format not in ['PNG', 'BMP']:
        raise ValueError(f"Unsupported image format: {img_format}. Only PNG and BMP are supported for LSB steganography.")
    return img_format