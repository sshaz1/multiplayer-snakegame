import socket
import numpy as np
import random
from _thread import *
import pickle
import pygame
from snake import SnakeGame
import uuid
import time 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import threading

# 3 methods for RSA encryption.

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return public_key, private_key

# Encrypts message using client's RSA public key
# Performs OAEP to add randomness to the encryption
def encrypt_message(message, key):
    ciphertext = key.encrypt(message.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return ciphertext

# Decrypts message using server's RSA private key
# Performs reversed OAEP to remove the added randomness when encrypting
def decrypt_message(ciphertext, key):
    plaintext = key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return plaintext.decode()


# server = "10.11.250.207"
server = "localhost"
port = 5555
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Keeping track of clients and their keys
clients = []
client_keys = []
addresses = []

#Generate keys
# Server
server_public_key, server_private_key = generate_key_pair()

counter = 0 
rows = 20 

try:
    s.bind((server, port))
except socket.error as e:
    str(e)

s.listen(5)
print("Waiting for a connection, Server Started")

game = SnakeGame(rows)
game_state = "" 
last_move_timestamp = time.time()
interval = 0.2
moves_queue = set()


rgb_colors = {
    "red" : (255, 0, 0),
    "green" : (0, 255, 0),
    "blue" : (0, 0, 255),
    "yellow" : (255, 255, 0),
    "orange" : (255, 165, 0),
} 
rgb_colors_list = list(rgb_colors.values())

def game_thread() : 
    global game, moves_queue, game_state 
    while True :
        last_move_timestamp = time.time()
        game.move(moves_queue)
        moves_queue = set()
        game_state = game.get_state()
        while time.time() - last_move_timestamp < interval : 
            time.sleep(0.1) 

# Sending Messages To All Connected Clients
def broadcast(msg):

    # Get index of client from clients list, find their corresponding public key and encrypt msg
    # then send
    for client in clients:
        index = clients.index(client)
        client_key = client_keys[index]
        #print(f"key: {client_key}")
        #print(msg)

        # Encrypt the msg using client's public key and send to each client
        encrypted_msg = encrypt_message(msg, client_key)
        #print(encrypted_msg)
        client.send(encrypted_msg)

def handle(conn, client_k_public_key):
    
    unique_id = str(uuid.uuid4())
    color = rgb_colors_list[np.random.randint(0, len(rgb_colors_list))]
    game.add_player(unique_id, color = color) 

    start_new_thread(game_thread, ())
    
    while True : 

        # To see if data recieved is a control or a message to be broadcasted

        # Recieve the encrypted message from the client
        encrypted_message = conn.recv(256)

        #Decrypt using server's private key
        decrypted_message = decrypt_message(encrypted_message, server_private_key)
        #print(decrypted_message)

        header, data = decrypted_message.split(":")
        #print(header)
        #print(game_state)

        # Encrypt the game state using client's public key and send to client
        encrypted_game_state = encrypt_message(game_state, client_k_public_key)
        conn.send(encrypted_game_state)

        move = None 

        if not data :
            print("no data received from client")
            break 

        if header == "control":
            if data == "get" : 
                #print("received get")
                pass 
            elif data == "quit" :
                #print("received quit")
                game.remove_player(unique_id)
                break
            elif data == "reset" : 
                #print("received RESET")
                game.reset_player(unique_id)

            elif data in ["up", "down", "left", "right"] : 
                move = data
                moves_queue.add((unique_id, move))
            else :
                print("Invalid data received from client:", data)
        
        elif header == "message":
            # Take care of broadcasting the message
            #print("Its a message to be broadcasted")
            #print(data)
            broadcast(data)

        else :
            print("Invalid data received from client:", data)
            
    conn.close()
    pass

def main() : 
    #global counter, game

    while True:
        conn, addr = s.accept()
        clients.append(conn)
        addresses.append(addr)
        print("Connected to:", addr)

        # Receive the client's public key, store in client_keys list
        client_key_bytes = conn.recv(4096)
        client_k_public_key = serialization.load_pem_public_key(client_key_bytes, backend=default_backend())
        client_keys.append(client_k_public_key)

        #Transform key into bytes using PEM format and then send to client
        conn.send(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))

        #print(f"Client's public key: {client_k_public_key}")

        thread = threading.Thread(target=handle, args=[conn, client_k_public_key])
        thread.start()

    

if __name__ == "__main__" : 
    main()