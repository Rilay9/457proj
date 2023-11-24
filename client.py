#!/usr/bin/env python3

import select
import socket
import sys
import argparse
import struct
import threading
import time

def process_response(response):
    print("processing response", response, response[8:])
    return 0

def send_message(sock, instruction, data=b''):
    print("length of data being sent", len(data))
    header = (len(data)).to_bytes(4, 'big') + b'\x04\x00'  # data_len, 0x04179a00
    message = header + bytes([instruction]) + data
    print(hex(instruction), message)
    b = sock.sendall(message)
    print("bytes sent", b)

def receive_response(sock):
    try:
        response = sock.recv(1024)  # Buffer size might need to be adjusted
        process_response(response)
    except socket.error as e:
        print(f"Error receiving response: {e}")

def change_nickname(sock, new_nickname):
    nickname_len = struct.pack('>B', len(new_nickname))  # Nickname length
    send_message(sock, 0x0f, nickname_len + new_nickname.encode('utf-8'))

def request_user_list(sock):
    print("requested_user_list")
    send_message(sock, 12)

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

def main(server_host, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((server_host, server_port))
            send_message(sock, 0x13, b'connected user')
        except Exception as e:
            print(f"Error connecting to server: {e}")
            sys.exit(1)

        inputs = [sock, sys.stdin]
        outputs = []

        while True:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)

            for r in readable:
                if r is sock:
                    response = sock.recv(1024)
                    process_response(response)
                elif r is sys.stdin:
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
                    elif command == 'send_room_msg':
                        message = input("Enter message to send to room: ")
                        send_room_message(sock, message)
                    elif command == 'send_direct_msg':
                        username = input("Enter username to send message to: ")
                        message = input("Enter message to send: ")
                        send_direct_message(sock, username, message)
                    elif command == 'leave':
                        leave_server(sock)
                    elif command == 'quit':
                        print("Exiting client.")
                        break
                    else:
                        print("Unknown command.")                      

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Client for server communication.')
    parser.add_argument('--host', type=str, help='The host IP of the server.', required=True)
    parser.add_argument('--port', type=int, help='The port number of the server.', required=True)
    args = parser.parse_args()

    main(args.host, args.port)
