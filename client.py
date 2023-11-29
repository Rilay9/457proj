#!/usr/bin/env python3

import socket
import sys
import argparse
import selectors
import threading

HEADER_LEN = 7

def is_socket_closed(sock):
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


def sock_close_exit(sock:socket, err=1):
    try:
        sock.close()
    except:
        pass
    finally:
        sys.exit(err)


# A receive all function for the socket (keep receiving until all bytes gotten)
# Returns none if nothing more to receive
def recv_all(sock:socket, size) -> bytearray:
    
    data = bytearray()
    
    while len(data) < size:
        seg = sock.recv(size - len(data))

        if not seg: # Return none if nothing received
            return None

        data.extend(seg)
    
    return data

def process_response(sock):
    
    header = recv_all(sock, HEADER_LEN)

    # If there's no data, it must have closed the connection, so remove from everything
    if not header:
        sock.close()
        sys.exit(1)
        
    # Otherwise do the right thing based on the header
    else:
        # Extract main things and update latest time
        data_len = int.from_bytes(header[:4], byteorder='big')
        instr = header[6]
    
    the_rest = recv_all(sock, data_len)
    print("the rest ", the_rest)
        # response from server send_msg
    if instr == 0x12:
        recv_uname_len = the_rest[0]
        recv_uname = the_rest[1:1+recv_uname_len].decode()
        msg_len_b = the_rest[2+recv_uname_len] 
        msg_b = the_rest[3+recv_uname_len:]
        print(recv_uname, "> ", msg_b.decode('utf-8'))
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
    elif instr == 0x9b:
        print(f"Connected. Username is {the_rest[1:].decode('utf-8')}")


def send_message(sock, instruction, data=b''):
    if instruction != 0x13:
        print("length of data being sent", len(data))
    header = (len(data)).to_bytes(4, 'big') + b'\x04\x00'  # data_len, 0x04179a00
    message = header + bytes([instruction]) + data
    b = sock.sendall(message)
    if instruction != 0x13:
        print("bytes sent", b)

def change_nickname(sock, new_nickname):
    send_message(sock, 0x0f, len(new_nickname).to_bytes(1,'little') + new_nickname.encode('utf-8'))

def request_user_list(sock):
    print("requested_user_list")
    send_message(sock, 12)

def send_direct_message(sock, username, message):
    data = len(username).to_bytes(1, 'little') + str(username).encode('utf-8') + b'\x00' + len(message).to_bytes(1, 'little') + str(message).encode('utf-8')
    send_message(sock, 0x12, data)
    
def join_room(sock, username, password):
    if len(password) > 0:
        data = len(username).to_bytes(1, 'little') + str(username).encode('utf-8') + str(password).encode('utf-8')
    else:
        data = len(username).to_bytes(1, 'little') + str(username).encode('utf-8') + b'\x00'
    send_message(sock, 0x03, data)
    
def file_xfer(username, file_path):
    # TODO
    print("this is the file transfer function: ", username, file_path)
    return 0


def leave_server(sock):
    send_message(sock, 0x06)

def heartbeat(sock, interval=5):
    send_message(sock, 0x13)
    threading.Timer(interval, heartbeat, [sock, interval]).start()


def main(server_host, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((server_host, server_port))
            send_message(sock, 0x13, b'connected user')
        except Exception as e:
            print(f"Error connecting to server: {e}")
            sys.exit(1)

        heartbeat_thread = threading.Timer(5, heartbeat, [sock])
        heartbeat_thread.start()

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
                    sock_close_exit(sock)
                    
                # If it's the socket, process the message
                if key.fileobj == sock:
                    
                    if is_socket_closed(sock):
                        print("Socket closed unexpectedly")
                        sock_close_exit(sock)
                    
                    try:
                        process_response(sock)
                    except Exception as e:
                        print(f"Error processing response: {e}")
                        sock_close_exit(sock)

                elif key.fileobj == sys.stdin:
                    command = input()
                    if command == 'nick':
                        new_nickname = input("Enter new nickname: ")
                        change_nickname(sock, new_nickname)
                    elif command == 'list_users':
                        request_user_list(sock)
                    elif command == 'send_msg':
                        username = input("Enter username to send message to: ")
                        message = input("Enter message to send: ")
                        send_direct_message(sock, username, message)
                    elif command == 'join_room':
                        room_name = input("Enter room name: ")
                        password = input("Enter room password: ")
                        join_room(sock, room_name, password)
                    elif command == 'file_xfer':
                        username = input("Enter username to send file to: ")
                        file_path = input("Enter file path: ")
                        file_xfer(username, file_path)
                    elif command == 'leave':
                        leave_server(sock)
                    elif command == 'quit':
                        print("Exiting client.")
                        sock_close_exit(sock, 0)
                    else:
                        print("usage: nick, list_users, send_msg, join_room, file_xfer, leave, quit")
                    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Client for server communication.')
    parser.add_argument('--host', type=str, help='The host IP of the server.', required=True)
    parser.add_argument('--port', type=int, help='The port number of the server.', required=True)
    args = parser.parse_args()

    main(args.host, args.port)
