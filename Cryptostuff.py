from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Function to generate an RSA key pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Function to generate a shared AES key
def generate_aes_key():
    return get_random_bytes(16)  # AES key of 128 bits

# Function to encrypt data with an RSA public key
def encrypt_with_rsa(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message)
    return encrypted_message

# Function to decrypt data with an RSA private key
def decrypt_with_rsa(encrypted_message, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message

# Function to calculate a hash of the message using SHA-256
def hash(message):
    if isinstance(message, str):
        message = message.encode('utf-8')
    return SHA256.new(message)

# Function to sign a hash of the message with an RSA private key
def sign_hash(hash_value, private_key):
    signer = pkcs1_15.new(private_key)
    return signer.sign(hash_value)

# Function to verify a hash with its signature and an RSA public key
def verify_hash(hash_value, signature, public_key):
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hash_value, signature)
        return True
    except (ValueError, TypeError):
        return False

# Function to encrypt data with an AES key
def encrypt_with_aes(message, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(message, AES.block_size))
    return cipher_aes.iv, ct_bytes

# Function to decrypt data with an AES key
def decrypt_with_aes(iv, encrypted_message, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    original_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)
    return original_message

# Overall function for Party A to encrypt a message, including IV in the output
def encrypt_overall_with_iv(message, rsa_private_key, aes_key):
    # Hash the message
    message_hash = hash(message)
    
    # Sign the hash with RSA private key
    signature = sign_hash(message_hash, rsa_private_key)
    
    # Encrypt the message with the shared AES key
    iv, encrypted_message = encrypt_with_aes(message, aes_key)
    
    # Concatenate the encrypted message and the signature
    encrypted_data_with_signature = encrypted_message + signature
    
    # Prepend the IV to the encrypted data for transmission
    encrypted_data_with_iv = iv + encrypted_data_with_signature
    
    return encrypted_data_with_iv

# Overall function for Party B to decrypt a message
def decrypt_overall_with_iv(encrypted_data_with_iv, rsa_public_key, aes_key):
    # Extract the IV from the beginning of the encrypted data
    iv = encrypted_data_with_iv[:AES.block_size]
    encrypted_data_with_signature = encrypted_data_with_iv[AES.block_size:]
    
    # Extract the encrypted message and the signature
    signature = encrypted_data_with_signature[-256:]  # Assume RSA signature size is 256 bytes
    encrypted_message = encrypted_data_with_signature[:-256]
    
    # Decrypt the message with the shared AES key
    original_message = decrypt_with_aes(iv, encrypted_message, aes_key)
    
    # Verify the signature
    message_hash = hash(original_message)
    if verify_hash(message_hash, signature, rsa_public_key):
        return original_message
    else:
        raise ValueError("The signature is not valid. Message integrity compromised!")

# # Sample usage:
# rsa_private_key, rsa_public_key = generate_rsa_keys()  # RSA keys
# aes_key = generate_aes_key()  # AES shared key
# message = b'Hello, this is a secret message!'  # Your message

# # Encrypt the message as Party A
# encrypted_data_with_iv = encrypt_overall_with_iv(message, rsa_private_key, aes_key)

# # Decrypt the message as Party B
# try:
#     decrypted_message = decrypt_overall_with_iv(encrypted_data_with_iv, rsa_public_key, aes_key)
# except ValueError as e:
#     decrypted_message = str(e)

# # Show the decrypted message
# print(decrypted_message)