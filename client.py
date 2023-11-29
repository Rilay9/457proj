#!/usr/bin/env python3

import select
import socket
import sys
import argparse


def process_response(response):
    the_rest = response[7:]
    print("the rest ", the_rest)
        # response from server send_msg
    if response[6] == 0x12:
        recv_uname_len = the_rest[0]
        recv_uname = the_rest[1:1+recv_uname_len].decode()
        msg_len_b = the_rest[2+recv_uname_len] 
        msg_b = the_rest[3+recv_uname_len:]
        print(recv_uname, "> ", msg_b.decode('utf-8'))
        # response from server list_users
    elif response[6] == 0x9c:
        data_len = response[3] - 3
        uname_beg_index = 1
        usernames = []
        while data_len > 0:
            recv_uname_len = the_rest[uname_beg_index]
            uname = the_rest[uname_beg_index + 1 : uname_beg_index + recv_uname_len + 1]
            usernames.append(uname.decode('utf-8')) 
            uname_beg_index = recv_uname_len + 2
            data_len = data_len - recv_uname_len
        print("usernames:", ", ".join(usernames))
    elif response[6] == 0x9b:
        print("Connected:", the_rest[1:].decode('utf-8'))


def send_message(sock, instruction, data=b''):
    print("length of data being sent", len(data))
    header = (len(data)).to_bytes(4, 'big') + b'\x04\x00'  # data_len, 0x04179a00
    message = header + bytes([instruction]) + data
    b = sock.sendall(message)
    print("bytes sent", b)

def receive_response(sock):
    try:
        response = sock.recv(1024)  # Buffer size might need to be adjusted
        process_response(response)
    except socket.error as e:
        print(f"Error receiving response: {e}")

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
            readable = select.select(inputs, outputs, inputs)
            for r in readable:
                if r is sock:
                    response = sock.recv(1024)
                    if not response:
                        continue
                    else:
                        process_response(response)
                elif r is sys.stdin:
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
                        break
                    else:
                        print("usage: send_msg, file_xfer, list_users, list_rooms")
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Client for server communication.')
    parser.add_argument('--host', type=str, help='The host IP of the server.', required=True)
    parser.add_argument('--port', type=int, help='The port number of the server.', required=True)
    args = parser.parse_args()

    main(args.host, args.port)
