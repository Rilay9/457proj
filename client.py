#!/usr/bin/env python3

import select
import socket
import sys
import argparse
import struct
import threading
import time
from Crypto.Cipher import PKCS1_OAEP
import Crypto
HEADER_LEN = 7 # The length in bytes of header. Includes data len, 04 17, and instruction
KEY_LEN = 32 # The length in bytes of the AES key

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

def send_message(sock, instruction, data=b''):
    """
    Packs and sends a message.
    """
    header = struct.pack('>I B B', len(data) + 1, 0x04, 0x17)  # data_len, 0x0417
    message = header + bytes([instruction]) + data
    sock.sendall(message)

def receive_response(sock):
    try:
        # Read in data len, header stuff, and instruction code. Always 7 bytes
        header = recv_all(sock, HEADER_LEN)

        # If there's no data, it must have closed the connection, so remove from everything
        if not header:
            return None
        
        # Extract main things and update latest time
        data_len = int.from_bytes(header[:4], byteorder='big')
        instr = header[6]

        # If message is a simple system message (an error or just a carrier for
        # non-encrypted data)
        if instr == 0x9a:
           is_error = recv_all(sock, 1)
           data_len = data_len - 1

           # If it's just a carrier message for non-encrypted stuff, just print it
           if (is_error == 0):
                print("Server request confirmed complete.\n")
           if data_len > 0:
               msg = recv_all(sock, data_len)
               print(f"{msg.decode()}\n")

    except socket.error as e:
        print(f"Error receiving response: {e}")


# TODO:Room join request: Send the request, and read the returned AES key, decrypt it, and store it locally. 
# Can only be in one room at a time, so can just overwrite existing room key and have a single roomKey AES variable.
# Client needs to also listen for any rsa pub and AES key messages and add them to its dicts.

def listen_for_messages(sock):
    try:
        while True:
            # Poll the socket to see if it has data
            ready_to_read, _, _ = select.select([sock], [], [], 1)

            # If there's data on the socket, read it
            if ready_to_read:
                response = receive_response(sock)
                if response is None:
                    print("Server closed the connection.")
                    break
                # Handle the response
                # For example, print it, update the UI, etc.
            else:
                # No data available, can perform other tasks or just continue the loop
                # This is where you can add code for other tasks if needed
                pass

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error receiving messages: {e}")

def change_nickname(sock, new_nickname):
    nickname_len = struct.pack('>B', len(new_nickname))  # Nickname length
    send_message(sock, 0x0f, nickname_len + new_nickname.encode('utf-8'))

def request_user_list(sock):
    send_message(sock, 0x0c)

def request_room_list(sock):
    send_message(sock, 0x09)

def join_room(sock, room_name, password=''):
    room_name_encoded = room_name.encode('utf-8')
    data = struct.pack('>B', len(room_name_encoded)) + room_name_encoded
    if password:
        password_encoded = password.encode('utf-8')
        data += password_encoded
    send_message(sock, 0x03, data)

def send_room_message(sock, message):
    send_message(sock, 0x15, message.encode('utf-8'))

def send_direct_message(sock, username, message):
    username_encoded = username.encode('utf-8')
    data = struct.pack('>B', len(username_encoded)) + username_encoded + message.encode('utf-8')
    send_message(sock, 0x12, data)

def leave_server(sock):
    send_message(sock, 0x06)

def heartbeat(sock, interval=5):
    send_message(sock, 0x13)
    threading.Timer(interval, heartbeat, [sock, interval]).start()

def handle_aes_key_message(sock, rsa_private_key):
    """
    Receives and decrypts the AES key message.

    Parameters:
    - sock (socket.socket): The socket connected to the server.
    - rsa_private_key (RSA.RsaKey): The RSA private key for decryption.
    """
    # Assuming the message format and length are known
    # Extract the encrypted AES key from the message
    encrypted_aes_key = recv_all(sock, KEY_LEN)

    # Decrypt the AES key
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key
def send_rsa_public_key(sock, rsa_public_key):
    """
    Sends the RSA public key to the server.

    Parameters:
    - sock (socket.socket): The socket connected to the server.
    - rsa_public_key (RSA.RsaKey): The RSA public key to send.
    """
    public_key_data = rsa_public_key.export_key()
    send_message(sock, 0x81, public_key_data)


def main(server_host, server_port):
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((server_host, server_port))
            print(f"Connected to server at {server_host}:{server_port}")
            rsa_private_key, rsa_public_key = generate_rsa_keys()
            send_rsa_public_key(sock, rsa_public_key)
            sock.sendall(bytes([0x00, 0x00, 0x00, 0x2d, 0x04, 0x17, 0x9b, 0x41,
                0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x74, 0x69,
                0x6d, 0x65, 0x20, 0x61, 0x67, 0x6f, 0x20, 0x69,
                0x6e, 0x20, 0x61, 0x20, 0x63, 0x68, 0x61, 0x74,
                0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
                0x66, 0x61, 0x72, 0x20, 0x66, 0x61, 0x72, 0x20,
                0x61, 0x77, 0x61, 0x79]))
            receive_response(sock)
            heartbeat_thread = threading.Timer(5, heartbeat, [sock])
            heartbeat_thread.start()
        except Exception as e:
            print(f"Error connecting to server: {e}")
            sys.exit(1)

        listening_thread = threading.Thread(target=listen_for_messages, args=(sock,))
        listening_thread.start()

        # Main loop to interact with the server based on user commands
        while True:
            try:
                command = input("Enter command (nickname, list_users, list_rooms, join_room, send_room_msg, send_direct_msg, leave, quit): ")
                if command == 'nickname':
                    new_nickname = input("Enter new nickname: ")
                    change_nickname(sock, new_nickname)
                elif command == 'list_users':
                    request_user_list(sock)
                elif command == 'list_rooms':
                    request_room_list(sock)
                elif command == 'join_room':
                    room_name = input("Enter room name: ")
                    password = input("Enter password (if any): ")
                    join_room(sock, room_name, password)
                    room_key = handle_aes_key_message(sock, rsa_private_key)
                elif command == 'send_room_msg':
                    message = input("Enter message to send to room: ")
                    send_room_message(sock, message)
                elif command == 'send_direct_msg':
                    username = input("Enter username to send message to: ")
                    message = input("Enter message to send: ")
                    send_direct_message(sock, username, message)
                elif command == 'leave':
                    leave_server(sock)
                    listening_thread.cancel()
                    heartbeat_thread.cancel()
                elif command == 'quit':
                    heartbeat_thread.cancel()  # Stop the heartbeat before exiting
                    print("Exiting client.")
                    break
                else:
                    print("Unknown command.")
                
            except KeyboardInterrupt:
                heartbeat_thread.cancel()  # Stop the heartbeat before exiting
                listening_thread.cancel()
                print("\nInterrupted by user, exiting.")
                break
            except Exception as e:
                heartbeat_thread.cancel()  # Stop the heartbeat on error
                listening_thread.cancel()
                print(f"An error occurred: {e}")
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Client for server communication.')
    parser.add_argument('--host', type=str, help='The host IP of the server.', required=True)
    parser.add_argument('--port', type=int, help='The port number of the server.', required=True)
    args = parser.parse_args()

    main(args.host, args.port)
