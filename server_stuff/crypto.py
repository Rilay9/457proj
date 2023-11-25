# All of the cryptography-related functions are here.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def calculate_hash(message):
    """
    Calculates a SHA-256 hash of the given message.

    :param message: The message to hash.
    :return: The SHA-256 hash of the message.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()

def encrypt_with_private_key(hash, private_key_pem):
    """
    Encrypts the hash with the given private key using RSA.

    :param hash: The hash to encrypt.
    :param private_key_pem: The PEM-encoded private key.
    :return: The encrypted hash.
    """
    private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    encrypted = private_key.encrypt(
        hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def encrypt_with_symmetric_key(message, symmetric_key):
    """
    Encrypts the message with the given symmetric key using AES.

    :param message: The message to encrypt.
    :param symmetric_key: The symmetric key.
    :return: The encrypted message.
    """
    iv = os.urandom(16)  # Generates a random 16-byte IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return iv + ct  # Prepend the IV for use in decryption

def decrypt_with_symmetric_key(encrypted_message, symmetric_key):
    """
    Decrypts the encrypted message with the given symmetric key using AES.

    :param encrypted_message: The message to decrypt.
    :param symmetric_key: The symmetric key.
    :return: The decrypted message.
    """
    iv = encrypted_message[:16]  # Extract the IV from the beginning
    ct = encrypted_message[16:]  # The rest is the ciphertext
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def decrypt_with_public_key(encrypted_hash, public_key_pem):
    """
    Decrypts the encrypted hash with the given public key using RSA.

    :param encrypted_hash: The hash to decrypt.
    :param public_key_pem: The PEM-encoded public key.
    :return: The decrypted hash.
    """
    public_key = load_pem_public_key(public_key_pem, backend=default_backend())
    decrypted = public_key.decrypt(
        encrypted_hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def verify_hash(original_message, decrypted_hash):
    """
    Verifies that a given hash matches the hash of the original message.

    :param original_message: The original message.
    :param decrypted_hash: The decrypted hash to verify.
    :return: True if the hash matches, False otherwise.
    """
    new_hash = calculate_hash(original_message)
    return new_hash == decrypted_hash
