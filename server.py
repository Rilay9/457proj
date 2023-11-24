#!/usr/bin/env python3

import socket
import time
import sys
import argparse
import selectors

from user import User
from room import Room

HEADER_LEN = 7 # The length in bytes of header. Includes data len, 04 17, and instruction

# Send confirmation message (data_len 04 17 9a no_err, if i understand right)
def server_confirm(sock):
    sock.sendall(bytes([0x00, 0x00, 0x00, 0x01, 0x04, 0x17, 0x9a, 0x00]))

# Closes user and cleans things up
def close_user(user:User):
    print("user is closing ", user)
    # Close socket if not already
    if user.sock.fileno() != -1:
        user.sock.close()

    # Remove user from its room
    if user.room is not None:
        room = Room.all_rooms[user.room]
        room.remove(user)
    
    # Remove user from all_users list
    User.all_users.pop(user.name, None)


# A receive all function for the socket (keep receiving until all bytes gotten)
# Returns none if nothing more to receive
def recv_all(sock:socket, size) -> bytearray:
    
    data = bytearray()
    
    while len(data) < size:
        seg = sock.recv(size - len(data))
        print("seg data === ", seg, size, len(seg))
        if not seg: # Return none if nothing received
            return None

        data.extend(seg)
    print("data in recv all === ", data, seg)
    return data

# Accepts new connection and receives and responds to connect message.
def accept_new(sock, sel: selectors.DefaultSelector):
    print("================= new client =================")
    # Accept connection and create new user
    try:
        conn, _ = sock.accept() # Don't need address
    except socket.error:
        import traceback
        traceback.print_exc()
        print("Error on server accept connection 1", file=sys.stderr)
        return
    
    # Receive the client connect message. Assumes always the correct 52 bytes (for now)
    print("wating for stuff")
    b = recv_all(conn, 21)
    print(len(b))
    if (len(b) != 21):
        conn.close()
        print("Error on server accept connection 2", file=sys.stderr)
        return
    # If worked, create and add the new user to the server list, and add the socket to
    # selector. Oh and send response
    else:
        # Create user. The "constructor" adds it to the static variable containing
        # all users. Went with a static one cos i was getting confused by dependencies
        new_user = User(conn) 

        # Construct response components
        header_b = b'\x04\x17\x9a'
        err_code_b = b'\x00'
        username_b = new_user.name.encode() # Need to encode, default is utf-8
        username_len = len(username_b)
        data_len = (username_len + 1).to_bytes(4, 'big') # Big endian to pad leading 0s

        # Concatenates all bytes together
        send_buffer = data_len + header_b + err_code_b + username_b

        try:
            conn.sendall(send_buffer)
        except socket.error:
            conn.close()
            print("Error on sending connect response", file=sys.stderr)
            return

        sel.register(conn, selectors.EVENT_READ, data=True)
        print("Done registering user")
    
# Processes the client messages
def process_client_msg(key: selectors.SelectorKey):
    
    sock = key.fileobj # Client socket
    user:User = User.get_user_by_sock(sock) # Added type hint for autocompletes

    # Read in data len, header stuff, and instruction code. Always 7 bytes
    header = recv_all(sock, HEADER_LEN)

    # If there's no data, it must have closed the connection, so remove from everything
    if not header:
        sel.unregister(sock)
        close_user(user)
        
    # Otherwise do the right thing based on the header
    else:
        # Extract main things and update latest time
        data_len = int.from_bytes(header[:4], byteorder='big')
        instr = header[6]
        user.update_time()
        print("header = ", header)
        # If it's simply the heartbeat, it's a fixed size message, so simply recv it
        # and update the timer for the user.
        print("Instruction = ", hex(instr), " Data length = ", data_len)
        if instr == 0x13:
            recv_all(sock, data_len)
            
        # Nickname request. Data will be nickname len (1 byte long) and then nickname.
        # I think client checks to make sure it's the right size
        elif instr == 0x0f:
            print("new_nickname request")
            # Get rest of message
            the_rest = recv_all(sock, data_len)
            print("the rest   ", the_rest)
            # Parse username, should just be from after len to end
            new_name = the_rest[1:].decode()
            old_name = user.name

            # Update name in terms of user
            user.change_name(new_name)

            # Remove the older username from room (if in one), and add new
            if user.room is not None:
                room = Room.all_rooms[user.room]
                del room.room_users[old_name]
                room.room_users[new_name] = user

        # User list request. This instruction has 0 data_len, so just update time, and send list.
        # If in room send users in room, otherwise send all in server.
        elif instr == 0x0c:

            # Set list to all users if not in room, otherwise get room list
            list = User.list_users() if (user.room is None) \
                else Room.all_rooms[user.room].list_users()
            data = b''
            
            # Iterate over list and add length and name as bytes to data
            for name in list:
                name_b = name.encode()
                name_len_b = len(name_b).to_bytes(1, 'little')
                data += name_len_b + name_b

            # Set full data_len (+1 for no_err) and header. Big-endian to pad 0s in front
            send_buffer = (len(data) + 1).to_bytes(4, 'big') + b'\x04\x17\x9a\x00' + data

            sock.sendall(send_buffer)


        # Room list request, pretty much same as user list request but more straightforward
        elif instr == 0x09:

            list = Room.list_rooms()

            data = b''
            
            # Iterate over list and add length and name as bytes to data
            for name in list:
                name_b = name.encode()
                name_len_b = len(name_b).to_bytes(1, 'little')
                data += name_len_b + name_b

            # Set full data_len (+1 for no_err) and header. Big-endian to pad 0s in front
            send_buffer = (len(data) + 1).to_bytes(4, 'big') + b'\x04\x17\x9a\x00' + data

            sock.sendall(send_buffer)


        # Room join request. Creates room if it doesn't exist, tries to join if it does.
        elif instr == 0x03:

            the_rest = recv_all(sock, data_len)

            # Assigns the data given the appropriate offsets.
            # It seems that the last byte is 00 if there's no password
            room_name_len = the_rest[0]
            room_name = the_rest[1:1+room_name_len].decode()
            password = "" if (the_rest[-1] == b'\x00') \
                else the_rest[2+room_name_len:].decode()

            # If already in room, send the appropriate error message
            # Again, it's fixed length message so copied from wireshark
            if room_name == user.room:
                sock.sendall(bytes([0x00, 0x00, 0x00, 0x3c, 0x04, 0x17, 0x9a, 0x01, \
                                    0x59, 0x6f, 0x75, 0x27, 0x72, 0x65, 0x20, 0x61, \
                                    0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x69, \
                                    0x6e, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x72, \
                                    0x6f, 0x6f, 0x6d, 0x2e, 0x20, 0x44, 0x6f, 0x20, \
                                    0x6f, 0x72, 0x20, 0x64, 0x6f, 0x20, 0x6e, 0x6f, \
                                    0x74, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65, \
                                    0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x20, 0x74, \
                                    0x72, 0x79, 0x2e]))

            # Else check if room exists
            else:
                room = Room.all_rooms.get(room_name, None)
                if room is not None:

                    # Try to join room, send the appropriate message upon result
                    if room.join(user, password):
                        server_confirm(sock)
                    
                    else:
                        # Password must have failed, send error message
                        sock.sendall(bytes([0x00, 0x00, 0x00, 0x1e, 0x04, 0x17, 0x9a, 0x01, \
                                            0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, \
                                            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, \
                                            0x2e, 0x20, 0x49, 0x74, 0x27, 0x73, 0x20, 0x61, \
                                            0x20, 0x74, 0x72, 0x61, 0x70]))
                
                # If room doesn't exist, create it. (adds to static map of rooms)
                else:
                    Room(user, room_name, password)  
                    server_confirm(sock)

        
        # Send message to room. If not in room, send 9a 01 error, otherwise send to users in room.
        # Seems can't request >= 5 messages in < 5 seconds (DM or room, and even if error) 
        elif instr == 0x15:
            
            the_rest = recv_all(sock, data_len)

            # Check if too many message requests
            if user.is_msg_overload():
                # Send "Hold your fire. There's no life forms." 9a 02 error fixed len message
                sock.sendall(bytes([0x00, 0x00, 0x00, 0x27, 0x04, 0x17, 0x9a, 0x02, \
                                    0x48, 0x6f, 0x6c, 0x64, 0x20, 0x79, 0x6f, 0x75, \
                                    0x72, 0x20, 0x66, 0x69, 0x72, 0x65, 0x2e, 0x20, \
                                    0x54, 0x68, 0x65, 0x72, 0x65, 0x27, 0x73, 0x20, \
                                    0x6e, 0x6f, 0x20, 0x6c, 0x69, 0x66, 0x65, 0x20, \
                                    0x66, 0x6f, 0x72, 0x6d, 0x73, 0x2e]))
            else:
                # Check if in room
                if user.room == None:
                    # Send "(You speak to no one. There is no one here.)" 9a 01 error
                    sock.sendall(bytes([0x00, 0x00, 0x00, 0x2b, 0x04, 0x17, 0x9a, 0x01, \
                                        0x59, 0x6f, 0x75, 0x20, 0x73, 0x70, 0x65, 0x61, \
                                        0x6b, 0x20, 0x74, 0x6f, 0x20, 0x6e, 0x6f, 0x20, \
                                        0x6f, 0x6e, 0x65, 0x2e, 0x20, 0x54, 0x68, 0x65, \
                                        0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, \
                                        0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x65, 0x72, \
                                        0x65, 0x2e]))
                else:
                    # Send message to all other users in room and send confirm message
                    
                    # Get room object
                    room = Room.all_rooms[user.room]
                    
                    # Construct message. Might as well use the bytes that were sent
                                    
                    room_name_len_b = the_rest[0]
                    room_name_b = the_rest[1:1+room_name_len_b]
                    username_b = user.name.encode()
                    username_len_b = len(username_b).to_bytes(1, 'little')
                    msg_len_b = the_rest[2+room_name_len_b]
                    msg_b = the_rest[3+room_name_len_b:]

                    # Put it all together (again, len(data) is set to big-endian to pad zeros)
                    data = room_name_len_b.to_bytes(1, 'little') + room_name_b \
                          + username_len_b + username_b + b'\x00' \
                          + msg_len_b.to_bytes(1, 'little') + msg_b
                    
                    send_buf = len(data).to_bytes(4, 'big') + b'\x04\x17\x15' + data

                    # Iterate over all users in room and send them the message (not to self though)
                    for room_user in room.room_users.values():
                        if room_user.name != user.name:
                            room_user.sock.sendall(send_buf)

                    # Send confirmation to og user
                    server_confirm(sock)  

        
        # Direct message request. Similar to room message. Has same time limit for 5 msgs.
        # If user doesn't exist, sends 9a 01 fixed len error message
        elif instr == 0x12:
            print(" ================   in direct message data len = ", data_len)
            the_rest = recv_all(sock, data_len)
            print("         the rest == ", the_rest)
            # Check if too many message requests
            if user.is_msg_overload():
                # Send "Hold your fire. There's no life forms." 9a 02 error fixed len message
                sock.sendall(bytes([0x00, 0x00, 0x00, 0x27, 0x04, 0x17, 0x9a, 0x02, \
                                    0x48, 0x6f, 0x6c, 0x64, 0x20, 0x79, 0x6f, 0x75, \
                                    0x72, 0x20, 0x66, 0x69, 0x72, 0x65, 0x2e, 0x20, \
                                    0x54, 0x68, 0x65, 0x72, 0x65, 0x27, 0x73, 0x20, \
                                    0x6e, 0x6f, 0x20, 0x6c, 0x69, 0x66, 0x65, 0x20, \
                                    0x66, 0x6f, 0x72, 0x6d, 0x73, 0x2e]))
                
            else:
                # Get the info based on offsets
                recv_uname_len = the_rest[0]
                recv_uname = the_rest[1:1+recv_uname_len].decode()
                msg_len_b = the_rest[2+recv_uname_len] # Theres a 0x00 in between
                msg_b = the_rest[3+recv_uname_len:]

                # Check if receiver user exists
                recv_user = User.all_users.get(recv_uname, None)
                print("recieved user == ", recv_user, recv_uname)
                if recv_user is None:
                    # Send fixed len error message that user doesn't exist
                    sock.sendall(bytes([0x00, 0x00, 0x00, 0x29, 0x04, 0x17, 0x9a, 0x01, \
                                        0x4e, 0x69, 0x63, 0x6b, 0x20, 0x6e, 0x6f, 0x74, \
                                        0x20, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, \
                                        0x2e, 0x20, 0x48, 0x65, 0x27, 0x73, 0x20, 0x67, \
                                        0x6f, 0x6e, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x41, \
                                        0x6c, 0x64, 0x65, 0x72, 0x61, 0x61, 0x6e, 0x2e]))
                else:
                    # Send user the message, and send sender the confirm message
                    sender_name_b = user.name.encode()
                    data = len(sender_name_b).to_bytes(1, 'little') + sender_name_b + b'\x00' \
                        + msg_len_b.to_bytes(1, 'little')+ msg_b
                    send_buf = len(data).to_bytes(4, 'big') + b'\x04\x17\x12' + data

                    recv_user.sock.sendall(send_buf)
                    server_confirm(sock)

        # Leave. Data len is 0, so no more to be received.
        # Close user if not in room, leave room if in one
        elif instr == 0x06:
            if user.room is None:
                # Close user
                print("closing user !!!!!!")
                sel.unregister(sock)
                server_confirm(sock)
                close_user(user)
            else:
                # Leave room
                room = Room.all_rooms[user.room]
                room.remove(user)
                server_confirm(sock)
        
        else:
            print("Invalid header received", file=sys.stderr)         

# Parse and get port number
args = sys.argv[1:]

parser = argparse.ArgumentParser()
parser.add_argument('-p' ,dest="port", action='store',type=int, help="server port number")
args = parser.parse_args()

# Create poll(, select, or whatever's best) object
sel = selectors.DefaultSelector()

# Set up server socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv_sock:

    # Bind
    try:
        serv_sock.bind(("", args.port))
    except socket.error:
        print("Error on server socket binding", file=sys.stderr)
        serv_sock.close()

    # Set up to listen
    try:
        serv_sock.listen()
    except socket.error:
        print("Error on server socket listen", file=sys.stderr)
        serv_sock.close()


    # Add server socket to file descriptors to look over
    # data field will be True if not a server socket
    sel.register(serv_sock, selectors.EVENT_READ, data=None)

    # Loop over sockets and process them accordingly
    while True:
        # Check the sockets, and iterate over events
        try:
            print("waiting for event")
            events = sel.select(timeout=30)
        except:
            break # To avoid exception being printed on interrupt

        for key, mask in events:
            print(key, mask)
            # If there's a timeout, all clients have timed out, so close 'em
            if not events: 
                for user in User.all_users.values():
                    sel.unregister(user.sock)
                    close_user(user)

            # If data is still None, it's the server socket which just
            # received a new connection request
            elif key.data is None:
                print(key.fileobj)
                accept_new(key.fileobj, sel)
            
            # Otherwise, a client has sent some data
            else:
                process_client_msg(key)

        # Check if any users haven't updated in 30 seconds, and if they did, close them
        curr_time = time.time()
        users_to_remove = [] # Another list, in order to avoid changing dict in iter
        for user in User.all_users.values():
            if curr_time - user.time_last_updated > 30:
                users_to_remove.append(user)
                
        # Remove the users
        for user in users_to_remove:        
            sel.unregister(user.sock)
            close_user(user)




