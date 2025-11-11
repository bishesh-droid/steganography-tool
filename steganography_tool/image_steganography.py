from PIL import Image
import math

from .logger import stego_logger
from .config import LSB_BITS_TO_USE
from .utils import bytes_to_bits, bits_to_bytes, validate_image_for_stego

# Header size in bits to store the length of the hidden message.
# We'll use 32 bits (4 bytes) to store the length, allowing messages up to 2^32 bits.
MESSAGE_LENGTH_HEADER_BITS = 32

def _get_image_capacity(image: Image.Image) -> int:
    """
    Calculates the maximum number of bits that can be hidden in an image.
    Assumes 3 color channels (RGB) and LSB_BITS_TO_USE per channel.
    """
    width, height = image.size
    # Each pixel has 3 color channels (R, G, B). Each channel can store LSB_BITS_TO_USE bits.
    capacity_bits = width * height * 3 * LSB_BITS_TO_USE
    return capacity_bits

def embed_message(image_path: str, output_path: str, message_bytes: bytes):
    """
    Embeds a byte string message into an image using LSB steganography.

    Args:
        image_path (str): Path to the cover image.
        output_path (str): Path to save the stego image.
        message_bytes (bytes): The message to embed (already encrypted).

    Raises:
        ValueError: If the message is too large for the image.
    """
    stego_logger.info(f"[*] Embedding message into {image_path}...")
    validate_image_for_stego(image_path)

    img = Image.open(image_path).convert("RGB") # Ensure RGB mode
    width, height = img.size

    # Convert message to bits
    message_bits = list(bytes_to_bits(message_bytes))
    stego_logger.debug(f"Embedding data of length: {len(message_bits)} bits")

    # Prepare message length header
    message_length = len(message_bits)
    if message_length > (2**MESSAGE_LENGTH_HEADER_BITS - 1):
        raise ValueError(f"Message is too long. Max supported bits: {2**MESSAGE_LENGTH_HEADER_BITS - 1}")
    
    length_bytes = message_length.to_bytes(MESSAGE_LENGTH_HEADER_BITS // 8, 'big')
    length_bits = list(bytes_to_bits(length_bytes))
    
    data_to_embed = length_bits + message_bits

    # Check capacity
    image_capacity_bits = _get_image_capacity(img)
    if len(data_to_embed) > image_capacity_bits:
        raise ValueError(f"Message is too large for the image. Required bits: {len(data_to_embed)}, Available bits: {image_capacity_bits}")

    data_index = 0
    new_img = img.copy()
    for y in range(height):
        for x in range(width):
            if data_index < len(data_to_embed):
                pixel = list(img.getpixel((x, y)))
                for c in range(3): # Iterate through R, G, B channels
                    if data_index < len(data_to_embed):
                        # Clear the LSB and set it to the data bit
                        pixel[c] = (pixel[c] & ~1) | data_to_embed[data_index]
                        data_index += 1
                new_img.putpixel((x, y), tuple(pixel))
            else:
                break
        else:
            continue
        break

    new_img.save(output_path, compress_level=0)
    stego_logger.info(f"[+] Message embedded successfully. Stego image saved to {output_path}")

def extract_message(image_path: str) -> bytes:
    """
    Extracts a hidden message from an image using LSB steganography.

    Args:
        image_path (str): Path to the stego image.

    Returns:
        bytes: The extracted message (encrypted).

    Raises:
        ValueError: If no message is found or image is corrupted.
    """
    stego_logger.info(f"[*] Extracting message from {image_path}...")
    validate_image_for_stego(image_path)

    img = Image.open(image_path).convert("RGB")
    width, height = img.size

    extracted_bits = []
    data_index = 0
    
    # Extract header and message in one pass
    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            for c in range(3):
                extracted_bits.append((pixel[c]) & 1)
                data_index += 1

                if data_index == MESSAGE_LENGTH_HEADER_BITS:
                    message_length_bytes = bits_to_bytes(extracted_bits)
                    message_length = int.from_bytes(message_length_bytes, 'big')
                    stego_logger.info(f"[*] Detected hidden message length: {message_length} bits.")
                    # Check if the message length is plausible
                    if message_length > width * height * 3:
                        raise ValueError("Extracted message length is impossibly large.")
                    
                if data_index > MESSAGE_LENGTH_HEADER_BITS and (data_index - MESSAGE_LENGTH_HEADER_BITS) == message_length:
                    stego_logger.debug(f"Extracted data of length: {len(extracted_bits) - MESSAGE_LENGTH_HEADER_BITS} bits")
                    extracted_bytes = bits_to_bytes(extracted_bits[MESSAGE_LENGTH_HEADER_BITS:])
                    stego_logger.info("[+] Message extracted successfully.")
                    return extracted_bytes
        else:
            continue
        break
    
    raise ValueError("Could not extract a complete message from the image.")
