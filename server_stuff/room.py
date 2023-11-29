# Represents a Room. Has a list of users in the room, a name,
# and a password.

from user import User
from encryptionstuff import generate_aes_key, encrypt_with_rsa
import os
import hashlib

class Room:

    all_rooms = {}

    # Creates the room. The user who creates it is always added.
    def __init__(self, user:User, room_name:str, pword:str) -> None:
        self.room_users = {user.name: user}
        self.name = room_name
        self.salt = os.urandom(16)  # Generate a 16-byte salt
        self.password_hash = self.hash_password(pword, self.salt)  # Store the hashed password
        user.room = self.name
        
        self.aes_key = generate_aes_key()
        encrypted_aes_key = encrypt_with_rsa(self.aes_key, user.rsaPubKey)
        self.send_aes_key_to_user(user, encrypted_aes_key)


        Room.all_rooms[room_name] = self # Caller checks if name already exists
        

    # Join the room. Returns true if password was correct and user
    # was added, and false otherwise
    def join(self, user:User, pword:str) -> bool:
        
        if self.verify_password(pword):

            # Add user to room users
            self.room_users[user.name] = user

            # Removes user from old room
            if user.room is not None:
                old_room = Room.all_rooms[user.room]
                old_room.remove(user)
            encrypted_aes_key = encrypt_with_rsa(self.aes_key, user.rsaPubKey)
            self.send_aes_key_to_user(user, encrypted_aes_key)
            self.distribute_public_keys(user)

            # Updates user's room
            user.join_room(self.name)
            return True
        else:
            return False
    
    # Returns sorted list of user names in room
    def list_users(self):
        return sorted([username for username in self.room_users.keys()])

    # Returns sorted list of all room names
    @staticmethod
    def list_rooms():
        return sorted([room_name for room_name in Room.all_rooms.keys()])

    # Removes user from room (Caller checks if not in room). If 
    # user was the only one in the room, deletes the room
    def remove(self, user:User) -> None:
        
        del self.room_users[user.name]
        user.leave()

        if len(self.room_users) == 0:
            del self.all_rooms[self.name]


# Send the AES key to a user, encrypted with their RSA public key
def send_aes_key_to_user(self, user: User, encrypted_aes_key: bytes) -> None:
    # You would send this over the socket connection to the user
    # The message format will follow your protocol's specifications
    # For example, you might prepend the message type and the user's name
    message = b'\x84' + user.name.encode() + encrypted_aes_key
    user.sock.sendall(message)



"""
    Distributes RSA public keys among users in a chat room to facilitate encrypted communication.

    This method sends the RSA public key of the newly joined user to all existing users in the room,
    and conversely, sends the RSA public keys of all existing users to the newly joined user. This 
    exchange ensures that each user has the public keys of all other users in the room, allowing them 
    to encrypt messages in a way that only the intended recipient can decrypt.

    The method iterates over the users in the room. For each existing user, it sends a message containing
    the new user's public key. For the new user, it sends separate messages containing the public keys of 
    each existing user.

    Message Format:
    - A message type byte indicating that the message contains an RSA public key (e.g., b'\x81').
    - The length of the user's name (1 byte) to facilitate parsing on the receiving end.
    - The name of the user whose public key is being sent, encoded in bytes.
    - The RSA public key of the user, exported to byte format.

    Parameters:
    - new_user (User): The user object representing the newly joined user in the room.

    This function relies on each User object having an RSA public key (`rsaPubKey`) stored,
    and a socket object (`sock`) for sending data over the network.
"""
def distribute_public_keys(self, new_user: User) -> None:
    # Message type for distributing RSA public keys
    rsa_pub_key_msg_type = b'\x81'

    # Send the new user's public key to all existing users in the room
    for user_name, user in self.room_users.items():
        if user_name != new_user.name:
            # Prepare the message with the new user's public key
            # Format: [message type][new user's name][new user's public key]
            pub_key_msg = rsa_pub_key_msg_type + len(new_user.name).to_bytes(1, 'big') + \
                            new_user.name.encode() + new_user.rsaPubKey.export_key()
            user.sock.sendall(pub_key_msg)

            # Send each existing user's public key to the new user
            # Format: [message type][existing user's name][existing user's public key]
            pub_key_msg_to_new_user = rsa_pub_key_msg_type + len(user.name).to_bytes(1, 'big') + \
                                        user.name.encode() + user.rsaPubKey.export_key()
            new_user.sock.sendall(pub_key_msg_to_new_user)

def hash_password(self, password: str, salt: bytes) -> bytes:
    """
    Hashes a password with a given salt using SHA-256.

    Parameters:
    - password (str): The password to hash.
    - salt (bytes): The salt to use in the hashing process.

    Returns:
    - bytes: The resulting hash as a byte string.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def verify_password(self, input_password: str) -> bool:
    """
    Verifies a password against the stored hash.

    Parameters:
    - input_password (str): The password to verify.

    Returns:
    - bool: True if the password matches the stored hash, False otherwise.
    """
    input_password_hash = self.hash_password(input_password, self.salt)
    return input_password_hash == self.password_hash