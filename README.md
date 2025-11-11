# Steganography Tool

This project implements a robust steganography tool that allows users to hide encrypted secret messages within image files (specifically PNG and BMP formats) and extract them. It combines the Least Significant Bit (LSB) steganography technique with strong AES-256 encryption to provide a secure method for covert communication.

## Features

-   **Image Steganography (LSB):** Utilizes the Least Significant Bit (LSB) technique to embed and extract data within the pixel data of PNG and BMP images, ensuring imperceptibility to the human eye.
-   **AES-256 Encryption:** Encrypts the secret message using AES-256 in CBC (Cipher Block Chaining) mode before embedding, providing a high level of confidentiality.
-   **Password-Based Key Derivation (PBKDF2):** Derives a strong encryption key from the user-provided password and a unique salt using PBKDF2, making brute-force attacks against the password computationally expensive.
-   **Capacity Check:** Automatically verifies if the chosen cover image has sufficient capacity to hide the encrypted message, preventing data loss.
-   **Supported Image Formats:** Works with lossless PNG and uncompressed BMP image files, which are ideal for LSB steganography.
-   **Robust Error Handling:** Includes comprehensive error handling for scenarios such as invalid file paths, unsupported image formats, insufficient image capacity, and incorrect passwords during decryption.
-   **Command-Line Interface:** Provides a user-friendly command-line interface for both embedding and extracting messages.

## Project Structure

```
.
├── steganography_tool/
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface using Click
│   ├── image_steganography.py # Core LSB embedding and extraction logic
│   ├── encryption.py      # AES-256 encryption and decryption functions
│   ├── utils.py           # Utility functions for data conversion and image validation
│   ├── logger.py          # Configures logging for the tool
│   └── config.py          # Configuration for LSB bits to use and logging
├── logs/
│   └── steganography_tool.log # Log file for tool activities
├── tests/
│   ├── __init__.py
│   ├── test_image_steganography.py # Unit tests for LSB logic
│   └── test_encryption.py # Unit tests for encryption logic
├── .env.example           # Example environment variables
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Steganography-Tool.git
    cd Steganography-Tool
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the steganography tool from the project root directory.

```bash
python -m steganography_tool.cli
```

**Commands:**

-   **`embed`**: Embeds an encrypted message into an image.
    ```bash
    python -m steganography_tool.cli embed <INPUT_IMAGE_PATH> <MESSAGE_TO_HIDE> [OUTPUT_IMAGE_PATH] --password <YOUR_PASSWORD>
    ```
    **Example:**
    ```bash
    python -m steganography_tool.cli embed cover.png "This is a secret message." --password mysecretpassword
    ```

-   **`extract`**: Extracts and decrypts a hidden message from an image.
    ```bash
    python -m steganography_tool.cli extract <STEGO_IMAGE_PATH> --password <YOUR_PASSWORD>
    ```
    **Example:**
    ```bash
    python -m steganography_tool.cli extract stego.png --password mysecretpassword
    ```

**Important Notes:**

-   **Image Capacity:** The amount of data you can hide depends on the image's dimensions. Larger images can hide more data. The tool will inform you if the message is too large.
-   **Password Security:** Use a strong, unique password for encryption. The security of your hidden message relies heavily on the strength of your password.

## Ethical Considerations

-   **Responsible Use:** Steganography can be used for both legitimate and malicious purposes. This tool is provided for educational and ethical hacking purposes only. Do not use it for illegal activities or to hide illicit content.
-   **Detection:** While LSB steganography can be imperceptible to the human eye, advanced stegananalysis tools can detect hidden data. This tool is not designed to be undetectable by sophisticated methods.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
