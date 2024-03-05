#Importing libraries needed
from pydoc import cli
import socket, pygame, sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

#Defining constant Color variables
BLACK = (0, 0, 0)
WHITE = (200, 200, 200)
RED = (255, 0, 0)
GREEN = (0,255,0)

#Dimensions (Constants)
WINDOW_HEIGHT = 400
WINDOW_WIDTH = 400
BLOCKSIZE = 20

# Connection variables (constants)
SERVER_ADDR = 'localhost'
SERVER_PORT = 5555

# Draw white rectangles on a black grid with 1 width, 
# becomes like a border
def drawGrid():
    for x in range(0, WINDOW_WIDTH, BLOCKSIZE):
        for y in range(0, WINDOW_HEIGHT, BLOCKSIZE):
            rect = pygame.Rect(x, y, BLOCKSIZE, BLOCKSIZE)
            pygame.draw.rect(SCREEN, WHITE, rect, 1)

# Handles when snake has "**" meaning there are multiple snakes
def handle_snakes(snake):

    if "**" in snake:
        snakes = snake.split("**")
        for snake in snakes:
            draw_snake(snake)
    else:
        draw_snake(snake)


# Draw snake (all cubes of snake)
def draw_snake(snake):

    # if multiple cubes in snake
    if "*" in snake:
        snake = snake.split("*")

        # for each coordinate of cube in snake ex. (1, 3)
        for pos in snake:

            # takes just the numbers without brackets and comma
            numbers = pos[1:-1].split(', ')
            x=int(numbers[0])
            y=int(numbers[1])

            # Create red rectangle occupying 1 entire block in grid
            rect = pygame.Rect(x*BLOCKSIZE,y*BLOCKSIZE, BLOCKSIZE, BLOCKSIZE)
            pygame.draw.rect(SCREEN, RED, rect)

    # if just one cube of snake (just the head), take out the for loop
    else:
        #print(snake)
        numbers = snake[1:-1].split(', ')
        #print(numbers)
        x=int(numbers[0])
        y=int(numbers[1])
        rect = pygame.Rect(x*BLOCKSIZE,y*BLOCKSIZE, BLOCKSIZE, BLOCKSIZE)
        pygame.draw.rect(SCREEN, RED,rect)
        
# Draw snacks, same as drawing a snake just different color
def draw_snacks(snacks):
    for pos in snacks:
        numbers = pos[1:-1].split(', ')
        x=int(numbers[0])
        y=int(numbers[1])
        rect = pygame.Rect(x*BLOCKSIZE,y*BLOCKSIZE, BLOCKSIZE, BLOCKSIZE)
        pygame.draw.rect(SCREEN, GREEN,rect)

# 3 methods for RSA encryption.

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return public_key, private_key

# Encrypts message using server's public key
# Performs OAEP to add randomness to the encryption
def encrypt_message(message, key):
    ciphertext = key.encrypt(message.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return ciphertext

# Decrypts message using client's RSA private key
# Performs reversed OAEP to remove the added randomness when encrypting
def decrypt_message(ciphertext, key):
    #print(ciphertext)
    try:
        plaintext = key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return plaintext.decode()
    except ValueError as e:
        print("Decryption error:", e)
        return None

#Encrypt message with server public key and send to server
def send_msg(msg):
    encrypted_message = encrypt_message(msg, server_public_key)
    c.send(encrypted_message)

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP connection

print("Connecting to Server...")

c.connect((SERVER_ADDR,SERVER_PORT))

print("Connected to Server!\n")

#Generate keys and exchange public keys
# Client
client_k_public_key, client_k_private_key = generate_key_pair()

#Transform key into bytes using PEM format and then send to server
c.send(client_k_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo))

# Receive the server's public key
server_key_bytes = c.recv(4096)
server_public_key = serialization.load_pem_public_key(server_key_bytes, backend=default_backend())

#print(f"Server's public key: {server_public_key}") 

print("*****")
print("RULES")
print("*****")
print("Use Arrow Keys to Move Snake")
print("Press ESC to Quit, R to Reset")
print("Z - 'Congratulations!', X - 'It works!', C - 'Ready?'\n")

# initialize pygame
pygame.init()

# Set screen to be window width and height long
SCREEN = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))

# Clock to adjust framerate
CLOCK = pygame.time.Clock()

# Sent get response to get snake's and snacks' starting positions
send_msg("control:get")

# Recieve the encrypted gamestate and decrypt it using client's private key
encrypted_gamestate = c.recv(256)
gamestate = decrypt_message(encrypted_gamestate,client_k_private_key)
#print(gamestate)

# Splitting gamestate and snacks appropriately
snake, snacks = gamestate.split("|")
snacks = snacks.split("**")

# Main Loop
while True:

    # Fill entire Screen with Black color, draw the snake, then the snacks
    # and finally the grid. 
    # Grid after snake and snacks so we can see the white borders of the grid
    SCREEN.fill(BLACK)

    # will check if multiple snakes, also calls draw_snake
    handle_snakes(snake)

    draw_snacks(snacks)
    drawGrid()
    pygame.display.update()

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            pygame.quit()
            sys.exit()
    
    # gets boolean values for all keys, if one is pressed its TRUE
    keys = pygame.key.get_pressed()

    # Sending msg to server depending on what key was pressed
    if keys[pygame.K_LEFT]:
        send_msg("control:left")
    elif keys[pygame.K_RIGHT]:
        send_msg("control:right")   
    elif keys[pygame.K_UP]:
        send_msg("control:up")
    elif keys[pygame.K_DOWN]:
        send_msg("control:down")  
    elif keys[pygame.K_ESCAPE]:
        send_msg("control:quit")
        pygame.quit()
        print("Thanks for Playing! Game Closed\n")
        sys.exit() 
    elif keys[pygame.K_r]:
        send_msg("control:reset")
    elif keys[pygame.K_z]:
        send_msg("message:"+str(c.getsockname())+"- Congratulations!") 
        print("Message sent!")
    elif keys[pygame.K_x]:
        send_msg("message:"+str(c.getsockname())+"- It works!")
        print("Message sent!")
    elif keys[pygame.K_c]:
        send_msg("message:"+str(c.getsockname())+"- Ready?")
        print("Message sent!")
    else:
        send_msg("control:get")
            
    #Recieve message from server either the gamestate or a chat message from another client
    data = c.recv(256)
    data = decrypt_message(data, client_k_private_key)

    #if its a game state
    if "*" in data:

        # game state sent back from server
        # Recieve the encrypted gamestate and decrypt it using client's private key
        gamestate = data
        #print(gamestate)
        snake, snacks = gamestate.split("|")
        snacks = snacks.split("**")

    # its a message broadcasted from server  
    else:

        # dont print if own message
        index = data.index("-")
        sockname = data[:index]

        if sockname != str(c.getsockname()):
            print(data)

    #for framerate
    CLOCK.tick(10)
