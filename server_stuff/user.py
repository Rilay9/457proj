# Represents a user. Has the socket, the nickname, the time since last
# update and the room currently in.

import socket
import time

class User:
    
    all_users = {}
    
    # Create the user.
    def __init__(self, sock: socket) -> None:
        self.sock:socket = sock
        self.room = None
        self.time_last_updated = time.time()
        self.rsaPubKey = None # The client should be sending this right after joining
        
        # Holds the last 4 times a message was sent in order to send error if 
        # sending too much. Should only be 4 or less, as it serves as a sliding window
        self.last_message_times = [] 
        
        # Add randomly generated name. Hope this is fast enough.
        # Assumes there'll be less users than will cause the name to be larger than 256
        name_gen_count = 0
        all_usernames = set(User.all_users.keys())
        while f"rand{name_gen_count}" in all_usernames:
            name_gen_count += 1

        self.name = f"rand{name_gen_count}"

        # Add to dict of users
        User.all_users[self.name] = self

    # Change the nickname. If same name, or if doesn't exist already, update and send
    # confirmation message. Otherwise, send error message 
    def change_name(self, new_name) -> None:

        if new_name == self.name or new_name not in User.all_users.keys():
            if new_name != self.name: # To avoid unneeded work 
                del User.all_users[self.name]
                self.name = new_name
                User.all_users[new_name] = self
            
            # Send confirmation message (data_len 04 17 9a no_err, if i understand right)
            self.sock.sendall(bytes([0x00, 0x00, 0x00, 0x01, 0x04, 0x17, 0x9a, 0x00]))

        else:
            # If already exists, send error message
            # (data_len 04 17 9a err_1 special set of skills msg).
            # Again, fixed length message, so just copied from wireshark as c array
            self.sock.sendall(bytes([0x00, 0x00, 0x00, 0x4b, 0x04, 0x17, 0x9a, 0x01, \
                                     0x54, 0x68, 0x69, 0x73, 0x20, 0x6e, 0x69, 0x63, \
                                     0x6b, 0x20, 0x62, 0x65, 0x6c, 0x6f, 0x6e, 0x67, \
                                     0x73, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x6f, 0x6d, \
                                     0x65, 0x6f, 0x6e, 0x65, 0x20, 0x65, 0x6c, 0x73, \
                                     0x65, 0x2e, 0x20, 0x48, 0x65, 0x20, 0x68, 0x61, \
                                     0x73, 0x20, 0x61, 0x20, 0x76, 0x65, 0x72, 0x79, \
                                     0x20, 0x70, 0x61, 0x72, 0x74, 0x69, 0x63, 0x75, \
                                     0x6c, 0x61, 0x72, 0x20, 0x73, 0x65, 0x74, 0x20, \
                                     0x6f, 0x66, 0x20, 0x73, 0x6b, 0x69, 0x6c, 0x6c, \
                                     0x73, 0x2e]))
            
    # Update time. Sends "He's still alive but in a very deep sleep message" if 
    # it's been 20 seconds since last update
    def update_time(self) -> None:
        
        old_time = self.time_last_updated
        self.time_last_updated = time.time()

        if self.time_last_updated - old_time >= 20:
            
            # Just realized I could paste the correct bytes to send in their entirety
            # I understand the message
            send_buffer = bytes([0x00, 0x00, 0x00, 0x26, 0x04, 0x17, 0x9a, 0x03, \
                                 0x48, 0x65, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x69, \
                                 0x76, 0x65, 0x2c, 0x20, 0x62, 0x75, 0x74, 0x20, \
                                 0x69, 0x6e, 0x20, 0x61, 0x20, 0x76, 0x65, 0x72, \
                                 0x79, 0x20, 0x64, 0x65, 0x65, 0x70, 0x20, 0x73, \
                                 0x6c, 0x65, 0x65, 0x70, 0x2e])
            
            self.sock.sendall(send_buffer)

    
    # Leaves room. Called from room remove() function, which is called only
    # when it's known that user is in a room.
    def leave(self) -> None:
        self.room = None
        
    # Joins room. Only called from room's join().
    def join_room(self, room: str) -> None:
        self.room = room

    # Returns list of all usernames on server
    @staticmethod
    def list_users():
        return sorted([username for username in User.all_users.keys()])

    # Checks if too many messages are being sent too quickly.
    # From what I could tell, 5 messages in less than 5 seconds is too much.
    # Returns true if too many, false if it's fine
    def is_msg_overload(self) -> bool:
        
        curr_time = time.time()
        is_overload = False

        # Check if 4 messages have been sent yet, otherwise def
        # won't be an issue.
        if len(self.last_message_times) == 4:
            
            # Removes first element, as window is always shifted if full
            if (curr_time - self.last_message_times.pop(0)) < 5:
                is_overload = True
            
        # Either way, insert new time
        self.last_message_times.append(curr_time)

        return is_overload

    # Gets user from socket. Returns None if not found
    @staticmethod
    def get_user_by_sock(sock:socket):
        
        for user in User.all_users.values():
            if user.sock == sock:
                return user

        return None