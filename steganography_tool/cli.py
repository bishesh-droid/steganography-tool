import click
import sys
import os

from .image_steganography import embed_message, extract_message
from .encryption import encrypt_message, decrypt_message
from .utils import validate_image_for_stego
from .logger import stego_logger

@click.group()
def cli():
    """
    A Steganography Tool to hide and extract encrypted messages in images.
    """
    pass

@cli.command()
@click.argument('input_image_path', type=click.Path(exists=True))
@click.argument('message_to_hide', type=str)
@click.argument('output_image_path', type=click.Path(), required=False)
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=True,
              help='Password for encrypting the message.')
def embed(input_image_path, message_to_hide, output_image_path, password):
    """
    Embeds an encrypted message into an image.

    INPUT_IMAGE_PATH: Path to the cover image (PNG or BMP).
    MESSAGE_TO_HIDE: The secret text message to embed.
    OUTPUT_IMAGE_PATH: (Optional) Path where the stego image will be saved.
                       Defaults to <input_image_name>.stego.<ext>.
    """
    stego_logger.info(f"[*] Attempting to embed message into {input_image_path}...")

    if not output_image_path:
        name, ext = os.path.splitext(input_image_path)
        output_image_path = f"{name}.stego{ext}"
        stego_logger.info(f"[*] No output path specified. Defaulting to {output_image_path}")

    try:
        # 1. Validate image format
        validate_image_for_stego(input_image_path)

        # 2. Encrypt the message
        encrypted_payload = encrypt_message(message_to_hide.encode('utf-8'), password)

        # 3. Embed the encrypted payload into the image
        embed_message(input_image_path, output_image_path, encrypted_payload)
        stego_logger.info("[+] Message embedded and encrypted successfully!")
        click.echo(f"Message successfully embedded into {output_image_path}")

    except FileNotFoundError as e:
        stego_logger.error(f"[ERROR] File not found: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        stego_logger.error(f"[ERROR] Embedding failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        stego_logger.critical(f"[CRITICAL] An unexpected error occurred during embedding: {e}")
        click.echo(f"An unexpected error occurred: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('stego_image_path', type=click.Path(exists=True))
@click.option('--password', '-p', prompt=True, hide_input=True,
              help='Password for decrypting the message.')
def extract(stego_image_path, password):
    """
    Extracts and decrypts a hidden message from an image.

    STEGO_IMAGE_PATH: Path to the image containing the hidden message.
    """
    stego_logger.info(f"[*] Attempting to extract message from {stego_image_path}...")
    try:
        # 1. Validate image format
        validate_image_for_stego(stego_image_path)

        # 2. Extract the encrypted payload from the image
        encrypted_payload = extract_message(stego_image_path)

        # 3. Decrypt the payload
        decrypted_message_bytes = decrypt_message(encrypted_payload, password)
        decrypted_message = decrypted_message_bytes.decode('utf-8')

        stego_logger.info("[+] Message extracted and decrypted successfully!")
        click.echo("\n--- Extracted Message ---")
        click.echo(decrypted_message)
        click.echo("-------------------------")

    except FileNotFoundError as e:
        stego_logger.error(f"[ERROR] File not found: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        stego_logger.error(f"[ERROR] Extraction or decryption failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        stego_logger.critical(f"[CRITICAL] An unexpected error occurred during extraction: {e}")
        click.echo(f"An unexpected error occurred: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()