import os
import hashlib
import readline  # Import readline for tab completion
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# Import the Cipher module
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Function to write data to a file
def write_to_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)

# Function to read data from a file
def read_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

# Function to calculate SHA-256 checksum for a file
def calculate_sha256_checksum(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as file:
        while True:
            data = file.read(65536)  # Read in 64k chunks
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()

# Function to create an encrypted message
def create_encrypted_message():
    # Generate a random salt
    salt = os.urandom(16)

    # Prompt the user for a password (passphrase)
    passphrase = input("Enter a passphrase: ").encode('utf-8')

    # Derive a key from the passphrase and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations as needed
        salt=salt,
        length=32  # Key length
    )
    key = kdf.derive(passphrase)

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Create an AES-GCM cipher with the derived key and IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    # Encrypt the message
    message = input("Enter the message to encrypt: ").encode('utf-8')
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Get the authentication tag
    tag = encryptor.tag

    # Concatenate the salt, IV, ciphertext, and tag
    encrypted_data = salt + iv + ciphertext + tag

    # Calculate SHA-256 checksum
    sha256_checksum = hashlib.sha256(encrypted_data).hexdigest()

    # Get the current date for the filename
    current_date = datetime.now().strftime("%d_%b_%Y")

    # Create the filename with the date stamp
    filename = f'encrypted_message_{current_date}.txt'

    # Create the checksum filename
    checksum_filename = f'{filename}_sha256sum.txt'

    # Write the encrypted data to the file
    write_to_file(filename, encrypted_data)

    # Write the SHA-256 checksum to a separate file
    with open(checksum_filename, 'w') as checksum_file:
        checksum_file.write(sha256_checksum)

    print(f"Encrypted message has been saved to '{filename}'")
    print(f"SHA-256 checksum has been saved to '{checksum_filename}'")

# Function to open and decrypt an encrypted message
def open_encrypted_message():
    # Tab completion for file names when entering the filename
    def complete_filename(text, state):
        # Get a list of files in the current directory
        files = [f for f in os.listdir() if os.path.isfile(f)]
        matches = [f for f in files if f.startswith(text)]
        if state < len(matches):
            return matches[state]
        else:
            return None

    readline.parse_and_bind("tab: complete")
    readline.set_completer(complete_filename)

    # Read the encrypted data from the file
    filename = input("Enter the filename of the encrypted message: ")
    encrypted_data = read_from_file(filename)

    # Read the SHA-256 checksum from the corresponding checksum file
    checksum_filename = f'{filename}_sha256sum.txt'
    stored_checksum = read_from_file(checksum_filename).decode('utf-8')

    # Calculate the SHA-256 checksum of the encrypted data
    calculated_checksum = hashlib.sha256(encrypted_data).hexdigest()

    # Check if the calculated checksum matches the stored checksum
    if calculated_checksum != stored_checksum:
        print("WARNING: Checksum does not match. The encrypted message may be corrupted.")
        return

    # Prompt the recipient for the passphrase
    recipient_passphrase = input("Enter the recipient's passphrase: ").encode('utf-8')

    # Derive the key from the recipient's passphrase and the stored salt
    recipient_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Use the same number of iterations as in encryption
        salt=encrypted_data[:16],  # Extract the salt from the encrypted data
        length=32  # Key length
    )
    recipient_key = recipient_kdf.derive(recipient_passphrase)

    # Extract the IV, ciphertext, and tag from the encrypted data
    recipient_iv = encrypted_data[16:32]
    recipient_ciphertext = encrypted_data[32:-16]
    recipient_tag = encrypted_data[-16:]

    # Create a new AES-GCM cipher with the derived key, IV, and tag
    recipient_cipher = Cipher(algorithms.AES(recipient_key), modes.GCM(recipient_iv, recipient_tag))
    decryptor = recipient_cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_message = decryptor.update(recipient_ciphertext) + decryptor.finalize()

    # Print the decrypted message
    print("Decrypted message:", decrypted_message.decode('utf-8'))

# User menu
while True:
    print("\nMenu:")
    print("1. Create an encrypted message")
    print("2. Open an encrypted message")
    print("3. Quit")

    choice = input("Enter your choice (1/2/3): ")

    if choice == '1':
        create_encrypted_message()
    elif choice == '2':
        open_encrypted_message()
    elif choice == '3':
        break
    else:
        print("Invalid choice. Please try again.")

