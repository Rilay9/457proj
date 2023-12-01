# Represents a Room. Has a list of users in the room, a name,
# and a password.

from user import User
from Cryptostuff import *


def send_message(sock, instruction, target:User, data=b''):
    if (data != b'' and instruction != 0x81):
        data = aes_basic_encrypt(data, target.server_aes_key)    
    
    header = (len(data)).to_bytes(4, 'big') + b'\x04\x17'  # data_len, 0x04179a00

    message = header + bytes([instruction]) + data
    b = sock.sendall(message)

class Room:

    all_rooms = {}

    # Creates the room. The user who creates it is always added.
    def __init__(self, user:User, room_name:str, pword:str) -> None:
        self.room_users = {user.name: user}
        self.name = room_name
        self.password = hash(pword)
        self.aes_key = generate_aes_key()

        # Removes user from old room
        if user.room is not None:
            old_room = Room.all_rooms[user.room]
            old_room.remove(user)

        user.room = self.name
        Room.all_rooms[room_name] = self # Caller checks if name already exists
        
        # Send AES key
        send_message(user.sock, 0x84, user, self.aes_key)

    # Join the room. Returns true if password was correct and user
    # was added, and false otherwise
    def join(self, user:User, pword:str) -> bool:
        
        if compare_hashes(hash(pword), self.password):

            # Add user to room users
            self.room_users[user.name] = user

            # Removes user from old room
            if user.room is not None:
                old_room = Room.all_rooms[user.room]
                old_room.remove(user)
            
            # Updates user's room
            user.join_room(self.name)

            # Send AES key encrypted with user's public key
            send_message(user.sock, 0x84, user, self.aes_key)
            
            for roommate in self.room_users.values():
                
                if roommate is not user:
                    # Send all the room's users public keys to the new user
                    key = roommate.rsa_pub.export_key()
                    send_message(user.sock, 0x81, roommate, len(roommate.name).to_bytes(1, 'little') + roommate.name.encode() + key)

                    # Send the new user's public key to all the room's users
                    key = user.rsa_pub.export_key()
                    send_message(roommate.sock, 0x81, user, len(user.name).to_bytes(1, 'little') + user.name.encode() + key)

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


