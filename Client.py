#!/usr/bin/env python3

import socket
import sys
import argparse
import selectors
import threading
from Cryptostuff import *

HEADER_LEN = 7

class ChatClient:

    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None
        self.currroom = None
        self.my_name = None
        self.expected_response_queue = []
        self.heartbeat_thread = None
        self.rsa_pub = None
        self.rsa_priv = None
        self.room_aes_key = None
        self.public_key_dict = {}
        self.aes_key_dict = {}

    def is_socket_closed(self, sock):
        try:
            # Attempt to read a small amount of data from the socket
            # without removing the data from the socket's buffer.
            data = sock.recv(16, socket.MSG_PEEK)
            if not data:
                return True  # The socket is closed
            return False
        except BlockingIOError:
            # No data available to read (this is normal for non-blocking sockets)
            return False
        except Exception:
            # An error occurred, which likely means the socket is closed or invalid
            return True


    def sock_close_exit(self, sock:socket, err=1):
        self.heartbeat_thread.cancel()
        try:
            sock.close()
        except:
            pass
        finally:
            sys.exit(err)


    # A receive all function for the socket (keep receiving until all bytes gotten)
    # Returns none if nothing more to receive
    def recv_all(self, sock:socket, size) -> bytearray:
        
        data = bytearray()
        
        while len(data) < size:
            seg = sock.recv(size - len(data))

            if not seg: # Return none if nothing received
                return None

            data.extend(seg)
        
        return data

    def process_response(self, sock):

        header = self.recv_all(sock, HEADER_LEN)

        # If there's no data, it must have closed the connection, so remove from everything
        if not header:
            sock.close()
            sys.exit(1)
            
        # Otherwise do the right thing based on the header
        else:
            # Extract main things and update latest time
            data_len = int.from_bytes(header[:4], byteorder='big')
            instr = header[6]
        
        the_rest = self.recv_all(sock, data_len)

            # Receive direct message
        if instr == 0x12:
            recv_uname_len = the_rest[0]
            recv_uname = the_rest[1:1+recv_uname_len].decode()
            msg_len = int.from_bytes(the_rest[2+recv_uname_len:6+recv_uname_len], 'big') 
            msg_b = the_rest[6+recv_uname_len:]
            print(f"< {recv_uname}: {msg_b.decode('utf-8')}")

        # Receive room message
        elif instr == 0x15:
            uname_len = the_rest[2 + len(self.currroom)]
            uname = the_rest[3+len(self.currroom):4+len(self.currroom)+uname_len]
            msg_len = int.from_bytes(the_rest[4+len(self.currroom)+uname_len:8+len(self.currroom)+uname_len], 'big')
            message = the_rest[8+len(self.currroom)+uname_len:]
            print(f"[{self.currroom}] < uname: {message}")
            

        # response from server list_users
        elif instr== 0x9c:
            data_len = data_len - 1
            uname_beg_index = 1
            usernames = []
            while data_len > 0:
                recv_uname_len = the_rest[uname_beg_index]
                uname = the_rest[uname_beg_index + 1 : uname_beg_index + recv_uname_len + 1]
                usernames.append(uname.decode('utf-8')) 
                uname_beg_index = recv_uname_len + 2
                data_len = data_len - recv_uname_len - 2
            print("usernames:", ", ".join(usernames))
        # response from server list_rooms
        elif instr== 0x09:

            data_len = len(the_rest)
            rname_beg_index = 0
            roomnames = []

            while data_len > 0:
                recv_rname_len = the_rest[rname_beg_index]
                rname = the_rest[rname_beg_index + 1 : rname_beg_index + 1 + recv_rname_len]
                roomnames.append(rname.decode('utf-8'))
                rname_beg_index += recv_rname_len + 1
                data_len -= recv_rname_len + 1

            print("Rooms:", ", ".join(roomnames))


        elif instr == 0x9b:
            print(f"Connected. Username is {the_rest[1:].decode('utf-8')}")
            self.my_name = the_rest[1:].decode('utf-8')

        
        # Username changed confirmation. Update username
        elif instr == 0x90:
            uname_len = the_rest[0]
            self.my_name = the_rest[1:uname_len+1].decode()
            print("Name changed to", self.my_name)

        # Room join confirmation
        elif instr == 0x91:
            rname_len = the_rest[0]
            self.currroom = the_rest[1:rname_len + 1].decode()
            print("Joined room", self.currroom)

        # Room create confirmation
        elif instr == 0x93:
            rname_len = the_rest[0]
            self.currroom = the_rest[1:rname_len + 1].decode()
            print("Created and joined room", self.currroom)

        # Left room confirm
        elif instr == 0x92:
            self.currroom = None
            print("Left room")

        # RSA Public key received
        elif instr == 0x81:
            roommate_len = the_rest[0]
            roommate = the_rest[1:roommate_len + 1]
            self.public_key_dict[roommate] = RSA.import_key(the_rest[roommate_len+3:])

        # AES room key received
        elif instr == 0x84:
            self.room_aes_key = decrypt_with_rsa(the_rest, self.rsa_priv)

        # AES DM key received
        elif instr == 0x80:
            uname_len = the_rest[0]
            uname = the_rest[1:uname_len + 1]
            self.aes_key_dict[uname] = decrypt_with_rsa(the_rest[uname_len+3:], self.rsa_priv)
           

        # Catchall for various info from server
        elif instr == 0x9a:
            print(the_rest.decode())

        else:
            print("Invalid message received.")

    def send_message(self, sock, instruction, data=b''):
        header = (len(data)).to_bytes(4, 'big') + b'\x04\x00'  # data_len, 0x04179a00
        message = header + bytes([instruction]) + data
        b = sock.sendall(message)

    def change_nickname(self, sock, new_nickname):
        self.send_message(sock, 0x0f, len(new_nickname).to_bytes(1,'little') + new_nickname.encode('utf-8'))

    def request_room_list(self, sock):
        self.send_message(sock, 0x09)

    def request_user_list(self, sock):
        print("requested_user_list")
        self.send_message(sock, 0x0c)

    def send_room_msg(self, sock, message):
        if self.currroom is None:
            print("Not currently in a room foo'")
            return
        self.send_message(sock, 0x15, len(self.currroom).to_bytes(1,'little') + self.currroom.encode()
                    + len(message).to_bytes(4, 'big') + message.encode('utf-8'))
        print(f"[{self.currroom}] > {self.my_name}: {message}")

    def send_direct_message(self, sock, username, message):
        data = len(username).to_bytes(1, 'little') + str(username).encode('utf-8') + b'\x00' + len(message).to_bytes(4, 'big') + str(message).encode('utf-8')
        self.send_message(sock, 0x12, data)
        print(f"> {self.my_name}: {message}")
        
    def join_room(self, sock, username, password):
        if len(password) > 0:
            data = len(username).to_bytes(1, 'little') + str(username).encode('utf-8') + str(password).encode('utf-8')
        else:
            data = len(username).to_bytes(1, 'little') + str(username).encode('utf-8') + b'\x00'
        self.send_message(sock, 0x03, data)
        
    def file_xfer(self, username, file_path):
        # TODO
        print("this is the file transfer function: ", username, file_path)
        return 0


    def leave_room_or_server(self, sock):
        self.send_message(sock, 0x06)

    def heartbeat(self, sock, interval=25):
        self.send_message(sock, 0x13)

    def run(self):

        self.rsa_priv, self.rsa_pub = generate_rsa_keys()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self.sock = sock
            try:
                sock.connect((self.server_host, self.server_port))
                self.send_message(sock, 0x00, self.rsa_pub.export_key())
            except Exception as e:
                print(f"Error connecting to server: {e}")
                sys.exit(1)

            self.heartbeat_thread = threading.Timer(25, self.heartbeat, [sock])
            self.heartbeat_thread.start()

            # Create poll(, select, or whatever's best) object
            sel = selectors.DefaultSelector()
            sel.register(sock, selectors.EVENT_READ, data=None)
            sel.register(sys.stdin, selectors.EVENT_READ, data=None)

            

            # Loop over sockets and process them accordingly
            while True:

                # Check the sockets, and iterate over events
                try:
                    events = sel.select(timeout=-1)
                except:
                    break # To avoid exception being printed on interrupt

                for key, mask in events:

                    # If there's a timeout, server has closed connection, so exit
                    if not events:
                        self.sock_close_exit(sock)
                        
                    # If it's the socket, process the message
                    if key.fileobj == sock:
                        
                        if self.is_socket_closed(sock):
                            self.sock_close_exit(sock)
                        
                        try:
                            self.process_response(sock)
                        except Exception as e:
                            print(f"Error processing response: {e}")
                            self.sock_close_exit(sock)

                    elif key.fileobj == sys.stdin:
                        command = input()
                        if command == 'nick':
                            new_nickname = input("Enter new nickname: ")
                            if len(new_nickname) > 255:
                                print("Nickname too large.")
                            else:
                                self.change_nickname(sock, new_nickname)
                        elif command == 'list_users':
                            self.request_user_list(sock)
                        elif command == 'list_rooms':
                            self.request_room_list(sock)
                        elif command == 'send_msg':
                            username = input("Enter username to send message to: ")
                            message = input("Enter message to send: ")
                            self.send_direct_message(sock, username, message)
                        elif command == 'join_room':
                            room_name = input("Enter room name: ")
                            password = input("Enter room password: ")
                            self.join_room(sock, room_name, password)
                        elif command == 'msg_room':
                            message = input("Enter message: ")
                            self.send_room_msg(sock, message)
                        elif command == 'file_xfer':
                            username = input("Enter username to send file to: ")
                            file_path = input("Enter file path: ")
                            self.file_xfer(username, file_path)
                        elif command == 'leave':
                            self.leave_room_or_server(sock)
                        elif command == 'quit':
                            print("Exiting client.")
                            self.sock_close_exit(sock, 0)
                        else:
                            print("usage: nick, list_users, list_rooms, send_msg,\nmsg_room join_room, file_xfer, leave, quit")

        
                    
def main(server_host, server_port):
    client = ChatClient(server_host, server_port)
    client.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Client for server communication.')
    parser.add_argument('--host', type=str, help='The host IP of the server.', required=True)
    parser.add_argument('--port', type=int, help='The port number of the server.', required=True)
    args = parser.parse_args()

    main(args.host, args.port)
