"""
Program: Client.py
Developers: Sean Mildenberger, Liam Ryan, Daulton
CMPT361-AS01 An Introduction To Networking

Purpose: The purpose of this program is to securly maintain a handshake
with a server using various encryption and decryption methods.
"""

# Imports
import json
import socket
import os,glob
import sys
import datetime
# Crytogrophy related imports
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

recv_block_size = 2048 # We can recv up to 2048 bytes in one block.
max_large_recv = 2000000 # Set maximum large recv to 2 mil
email_max_length = 1000000 # Max email content length

"""
Function: rsa_load()
Parameter(s): name, is_private
    -   name: username 
    -   is_private: whether or not the key is private or public
Return(s):
    -   a new imported rsa key or null if the key is null
"""
def rsa_load(name, is_private):
    file = None
    key = None
    # Construct the file name as either one with private permission or public permission 
    # based on if the is_private argument is true or flase
    if is_private:
        file_name = (name + "_private.pem") # private
    else:
        file_name = (name + "_public.pem") # public

    try:
        file = open(file_name, "rb")
        key = file.read()
    except:
        pass
    
    if file != None:
        file.close()
    
    if key == None:
        return None
    
    return PKCS1_OAEP.new(RSA.import_key(key))

"""
Function: aes_ecb_load
Parameter(s): sym_key
    -   symetric key for aes encryption and decryption
Return(s):
    -   a new cipher to decrpyt aes 256 bit messages in ECB mode
"""   
def aes_ecb_load(sym_key):
    return AES.new(sym_key, AES.MODE_ECB)

"""
Function: rsa_encrypt
Parameter(s): cipher, message
    -   cipher: cipher created by aes_ecb_load function
    -   message: the message to be encrypted
Return(s):
    -   rsa encrpyted message
"""
def rsa_encrypt(cipher, message):
    return cipher.encrypt(message)

"""
Function: rsa_decrypt
Parameter(s): cipher, message
    -   cipher: cipher for decryption and encryption
    -   message: the message to be decrypted
Return(s):
    -   rsa decrypted message
"""  
def rsa_decrypt(cipher, message):
    return cipher.decrypt(message)

"""
Function: aes_encrypt
Parameter(s): cipher, message
    -   cipher: cipher for decryption and encryption
    -   message: the message to be encrypted
Return(s):
    -   rsa encrypted message
"""   
def aes_encrypt(cipher, message):
    return cipher.encrypt(pad(message, 16))

"""
Function: aes_decrypt
Parameter(s): cipher, message
    -   cipher: cipher for aes decryption and encryption
    -   message: the message to be decrypted 
Return(s):
    -   aes decrypted message
"""  
def aes_decrypt(cipher, message):
    return unpad(cipher.decrypt(message), 16)

"""
Function: send_standard (for standard sized messages)
Parameter(s): connection_socket, message, cipher, encrypt_fn
    -   connection_socket: socket we are connected to the server through
    -   message: the message to be sent 
    -   cipher: cipher which can vary
    -   encrypt_fn: function used for encryption which can change
Return(s): Null
"""
def send_standard(connection_socket, message, cipher = None, encrypt_fn = None):
    if (encrypt_fn != None) and (cipher != None):
        send_msg = encrypt_fn(cipher, message)
    else:
        send_msg = message

    connection_socket.send(send_msg)

"""
Function: recv_standard (for standard sized messages)
Parameter(s): connection_socket, message, cipher, encrypt_fn
    -   connection_socket: socket we are connected to the server through
    -   cipher: a cipher which can vary
    -   encrypt_fn: function used for encryption which can change
Return(s): message
    -   message: the message we received from the server
"""   
def recv_standard(connection_socket, cipher = None, decrypt_fn = None):
    recv_message = connection_socket.recv(recv_block_size)
    
    if (decrypt_fn != None) and (cipher != None):
        message = decrypt_fn(cipher, recv_message)
    else:
        message = recv_message
        
    return message

"""
Function: send_large (for sending larger messages)
Purpose: This function aids in the sending of greater amounts of data

Parameter(s): connection_socket, message, encrypt_cipher, encrypt_fn, decrypt_cipher, decrypt_fn
    -   connection_socket: socket we are connected to the server through
    -   message: the message to be sent 
    -   encrypt_cipher: cipher encryption
    -   encrypt_fn: function used for encryption which can change
    -   decrypt_cipher: cipher decryption 
    -   decrypt_fn: function used for decryption which can change
Return(s): null
"""     
def send_large(connection_socket, message, encrypt_cipher = None, encrypt_fn = None, decrypt_cipher = None, decrypt_fn = None):
    # if both conditions evaluate to true we run the wrapped code
    # which will encrypt the message in the way its meant to be
    if (encrypt_fn != None) and (encrypt_cipher != None):
        send_msg = encrypt_fn(encrypt_cipher, message)
    else:
        # otherwise the message doesnt require further encryption 
        send_msg = message
    
    message_len = str(len(send_msg))
    send_standard(connection_socket, message_len.encode("ascii"), encrypt_cipher, encrypt_fn)
    returned_message_len = recv_standard(connection_socket, decrypt_cipher, decrypt_fn).decode("ascii")
    
    # returned_message_len may be 0 to refuse the packet!
    if message_len == returned_message_len:
        connection_socket.send(send_msg)

"""
Function: recv_large (for receiving larger messages)
Purpose: aids in the receiving of greater amounts of data

Parameter(s): connection_socket, message, encrypt_cipher, encrypt_fn, decrypt_cipher, decrypt_fn
    -   connection_socket: socket we are connected to the server through 
    -   encrypt_cipher: cipher encryption
    -   encrypt_fn: function used for encryption which can change
    -   decrypt_cipher: cipher decryption 
    -   decrypt_fn: function used for decryption which can change
Return(s): message
    -   the received (large) message from the client
"""           
def recv_large(connection_socket, encrypt_cipher = None, encrypt_fn = None, decrypt_cipher = None, decrypt_fn = None):
    # attempt to run the protected code wrapped in the try, except
    try:
        # cast int to recv_standard return value in order to get the message length
        message_len = int(recv_standard(connection_socket, decrypt_cipher, decrypt_fn).decode("ascii"))
    except:
        # on failure of the above we set the message length to zero
        message_len = 0
    # check the message length is greater than zero and within the maximum recv size
    if (message_len > 0) and (message_len <= max_large_recv):
        # send back the length of the message 
        send_standard(connection_socket, str(message_len).encode("ascii"), encrypt_cipher, encrypt_fn)
    else:
        # on failure send back the message len (which is zero)
        send_standard(connection_socket, "0".encode("ascii"), encrypt_cipher, encrypt_fn)
        return None
    # used for breaking up larger messages into smaller chunks of sizes up to 2048 bytes
    recvd = 0
    message_chunks = []
    
    """
    The below code may require more abstraction...

    We only want to recv blocks of data that are at a max 2048 bytes at a time but if we can grab less we want to
    partly because TCP is stream based and if we grab just blocks of 2048 everytime and the total data size % 2048 is not 0 then
    we will potentially recv more than we want to. To remedy this we create chunks based on the smallest value between
    2048 and the amount of data left.
    """
    # run the code wrapped inside the loop until a break is reached
    while True: 
        # choose a size for the chunk based on the minimum value in between recv_block_size (2048)
        # and the total message length - the amount of data we have already recv
        new_chunk = connection_socket.recv(min(recv_block_size, message_len - recvd))
        # update the recvd amount
        recvd += len(new_chunk)
        # add the new chunk to the message chunks list
        message_chunks.append(new_chunk)
        # when we have recvied an amount that is equal to the total message length we can break
        if (message_len - recvd) == 0:
            break
    # join all the chunks previously received into one message  
    recv_message = b''.join(message_chunks)
    # if further decryption is required...
    if (decrypt_fn != None) and (decrypt_cipher != None):
        message = decrypt_fn(decrypt_cipher, recv_message)
    else: # otherwise we can return the message.
        message = recv_message
    
    return message

"""
Function: email_request()
Purpose: Requests to send and email of some size and will only send if the contents are not null
         and if it's contents are within the maximum allowed size.
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
Return(s): Null
"""
def email_request(client_socket, aes_cipher, username):
    # recv the request answer
    req_ans = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
    # if the request answer is not equal to "Send the email" we dont send the message
    # to the server
    if req_ans != "Send the email":
        return
    # the string on the server side is split into a list based on ';'
    destinations = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")
    
    message_contents = ""# initially empty
    # if the response to the input below is either 'y' or 'Y' we execute the code wrapped inside  
    if input("Would you like to load contents from a file?(Y/N) ") in ["y", "Y"]:
        # loop while the message contents are still null and break when the contents 
        # get appended
        while message_contents == "":
            # name of file we want to read from
            file_name = input("Enter filename: ")
            
            try: # try to execute the protected code
                file = open(file_name, "r")
                message_contents = file.read() # read the file data into the message_contents variable
                file.close()
            except: # on failure
                pass
            
            # we are not allowd to exceed the maximum length we previously set for message contents
            if len(message_contents) > email_max_length:
                print("Email content needs to be less than {0} length...".format(email_max_length))
                message_contents = "" # maintain as null on failure so we loop back and try again.
    else: # wrapped in the else is code to gather the message contents from the user and 
          # check that the message is within the maximum length previously set for the email.
        while message_contents == "":
            message_contents = input("Enter message contents: ")
            
            if len(message_contents) > email_max_length:
                print("Email content needs to be less than {0} length...".format(email_max_length))
                message_contents = ""
    # when the message contents are not null we will build a header for the email
    # message with the content (actual message) at the bottom.
    email_message = "From: {0}\n".format(username)
    email_message += "To: {0}\n".format(destinations)
    email_message += "Title: {0}\n".format(title)
    email_message += "Content Length: {0}\n".format(len(message_contents))
    email_message += "Content: \n" + message_contents
    # call send large in order to send our message to the server.
    send_large(client_socket, email_message.encode("ascii"), aes_cipher, aes_encrypt, aes_cipher, aes_decrypt)
    
    print("The message is sent to the server.")
    return

"""
Function: display_inbox()
Purpose: print the inbox
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
Return(s): Null
"""
def display_inbox(client_socket, aes_cipher, username):
    # call recv_large to recv the email_message
    email_message = recv_large(client_socket, aes_cipher, aes_encrypt, aes_cipher, aes_decrypt).decode("ascii")
    
    print()#\n
    print(email_message)# display inbox

    # send "OK"
    send_standard(client_socket, "OK".encode("ascii"), aes_cipher, aes_encrypt)
    return

"""
Function: display_email()
Purpose: from user input this function will aquire an index that will be sent to the server 
         which will return the email message associated with that index
            -   Shortcoming: You have to know the index of the email you want to view
                              if you have dozens of emails or more it will be hard to remember.
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
Return(s): Null
"""
def display_email(client_socket, aes_cipher, username):
    req_ans = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
    if req_ans != "the server request email index":
        return
    # grab the email you would like to see based off its index
    email_index = input("Enter the email index you wish to view: ")
    # send the index to the server 
    send_standard(client_socket, email_index.encode("ascii"), aes_cipher, aes_encrypt)
    # recv the servers response as the email message associated with the index previously sent to the sever
    email_message = recv_large(client_socket, aes_cipher, aes_encrypt, aes_cipher, aes_decrypt).decode("ascii")

    print() #\n
    print(email_message) # display the email contents. 
    return

"""
Function: client_main()
Purpose:
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
Return(s): Null
"""
def client_main(client_socket, aes_cipher, username):
    while True:
        menu_message = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
        user_input = ""
        # if the user is not entering one of the allowed inputs we will prompt them with the 
        # menu again and send the result back to the server
        while user_input not in ["1", "2", "3", "4"]:
            user_input = input(menu_message)
        # call send_standard 
        send_standard(client_socket, user_input.encode("ascii"), aes_cipher, aes_encrypt)
        # check the user input and decide what to do next...
        if user_input == "1": # Create and send an email
            email_request(client_socket, aes_cipher, username)
        elif user_input == "2": # Display the inbox list
            display_inbox(client_socket, aes_cipher, username)
        elif user_input == "3": # Display the email contents
            display_email(client_socket, aes_cipher, username)
        else: # Terminate the connection
            terminate_message = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
            print(terminate_message)
            return
    
    return

"""
Function: client_init()
Purpose: The purpose of this function is to authorize a user by taking input on the client side
         for a username and password which are sent to the server to be authorized or denied.
Parameter(s): client_socket, server_public
client_socket: The clients socket
server_public: The public server
Return(s): Null
"""  
def client_init(client_socket, server_public):
    # get a username and password and combine them in one authorization message
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    auth_message = username + ":" + password
    # send through the client socket the encoded message to the public server using rsa_encrypt
    send_standard(client_socket, auth_message.encode("ascii"), server_public, rsa_encrypt)
    auth_response = recv_standard(client_socket)
    
    if auth_response != "Invalid username or password".encode("ascii"):
        user_private = rsa_load(username, True)
        
        if user_private != None:
            # build the sym_key for the private user
            sym_key = rsa_decrypt(user_private, auth_response)
            aes_cipher = aes_ecb_load(sym_key) # build aes_cipher
            # send "OK" using the cipher and aes encryption
            send_standard(client_socket, "OK".encode("ascii"), aes_cipher, aes_encrypt)
            client_main(client_socket, aes_cipher, username) # call client_name
        else:
            print("Failed to load client public key...")
    else:
        print("Invalid username or password.\nTerminating.")

    return
"""
Function: client()
Purpose: The client will aid in instantiating a handshake with the server by opening a 
         a public server key using the rsa_load() function and using the socket library in order
         to establish communcation with the server.
Parameter(s): None
    -   takes null parameters
Return(s): None
    -   returns null on error or end of function
"""
def client():
    # load the server_public key by specifying the "server" and by setting the private parameter to false.
    server_public = rsa_load("server", False)
    if server_public == None:
        print("Failed to open server public key! Aborting...")
        return None
    
    # Initialize socket data
    client_socket = None
    server_ip = "127.0.0.1" # "cc5-212-00.macewan.ca"
    server_port = 13000
    
    # Remove this line before handing in the project / using on the server!!!
    server_ip = input("Enter the server IP or name: ")
    
    # Try to create the socket and connect to the server
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
    except Exception as ex: # If it fails
        # Close the socket
        if client_socket != None:
            client_socket.close()
            client_socket = None    
        # Alert the user and exit
        print("Failed to connect to server: {0}".format(str(ex)))
        return
    # above we established a connection with the server then call client_init() for further handshaking
    client_init(client_socket, server_public)
    
    # If the client socket is still valid
    if client_socket != None:
        # Close it
        client_socket.close()
        client_socket = None
    
    return

if __name__ == "__main__":
    client()