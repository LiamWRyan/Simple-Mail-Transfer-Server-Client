"""
Program: Server.py
Developers: Sean Mildenberger, Liam Ryan, Daulton
CMPT361-AS01 An Introduction To Networking

Purpose: 
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

recv_block_size = 2048
max_large_recv = 2000000

# Max email content length
email_max_length = 1000000

"""
Function: json_read()
Purpose: Read from a json file it's data into a dictionary and return the json dictionary 
Parameter(s): json_file_name
    -   json_file_name: the name of the json file we want to read data from
Return(s): json_dict
    -   Return the json data in dictionary format
"""
def json_read(json_file_name):
    json_dict = {} # Assume empty dictionary
    json_file = None # Initialize file handle to None

    try: # Try to open the file
        json_file = open(json_file_name) # Open the file for read
    except Exception as ex: # If there was an error
        return json_dict # Return the empty json dictionary
    
    try: # If it fails to read the dictionary we can just use a blank dictionary
        json_dict = json.load(json_file) # Load the json dictionary
    except: # If there was an error
        json_dict = {} # Set blank dictionary on error
        
    json_file.close() # Close the file handle
    return json_dict # Return the json dictionary

"""
Function: generate_sym_key()
Purpose: Generate a 256 byte symetric key (symetric in the sense that is is used for both encryption and decryption)
Parameter(s): Null
   
Return(s): get_random_bytes(32)
    -   this will be the symetric key
"""
def generate_sym_key():
    return get_random_bytes(32) # 32*8 = 256


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
    # based on if the is_private argument is true or flase.
    if is_private:
        file_name = (name + "_private.pem") # Private
    else:
        file_name = (name + "_public.pem") # Public

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
    -   connection_socket: socket we are connected to the client through
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
    -   connection_socket: socket we are connected to the client through
    -   cipher: a cipher which can vary
    -   encrypt_fn: function used for encryption which can change
Return(s): message
    -   message: the message we received from the client
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
    -   connection_socket: socket we are connected to the client through
    -   message: the message to be sent 
    -   encrypt_cipher: cipher encryption
    -   encrypt_fn: function used for encryption which can change
    -   decrypt_cipher: cipher decryption 
    -   decrypt_fn: function used for decryption which can change
Return(s): null
"""       
def send_large(connection_socket, message, encrypt_cipher = None, encrypt_fn = None, decrypt_cipher = None, decrypt_fn = None):
    if (encrypt_fn != None) and (encrypt_cipher != None):
        send_msg = encrypt_fn(encrypt_cipher, message)
    else:
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
    -   connection_socket: socket we are connected to the client through 
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
Function: save_email()
Purpose:  Save the email to a file

Parameter(s): recipient, username, email_title, email_parts
    -   recipient: The person the email is meant for
    -   username: The person sending the email
    -   email_title: The title of the email
    -   email_parts: list of parts of the email
Return(s): True or False
    -   Return True upon successfully saving the email
    -   Return False upon failing to save the email 
""" 
def save_email(recipient, username, email_title, email_parts):
    # Define file as None so it can be checked later for closing (in case if it doesn't get to the defining stage before raising an exception)
    file = None

    try:
        # If the recipient's directory does not exist, create it
        if not os.path.exists(recipient):
            os.mkdir(recipient)
    
        # Open the file in which the email will be stored
        file = open("{0}/{1}_{2}.txt".format(recipient, username, email_title), "w")
        
        # Write each of the email segments into the file
        amount_parts = len(email_parts)
        for i in range(amount_parts):
            # Write \n after each part except for the last one!
            if i != (amount_parts - 1):
                file.write(email_parts[i] + "\n")
            else:
                file.write(email_parts[i])
        
        # Close the file handle
        file.close()
    except Exception as ex:
        # If the file was opened (and not closed), close it
        if file != None:
            file.close()
        
        # Print the error and return false
        print("Failed to save email to file... Reason: {0}.".format(str(ex)))
        return False
    
    return True

"""
Function: load_email()
Purpose:  load and return the email file data

Parameter(s): email_file_name
    -   email_file_name: email file we will read data from
Return(s): file_data
    -   file_data: the file data 
"""   
def load_email(email_file_name):
    file = None
    file_data = ""
    
    try:
        # in the case that it doesnt exist raise an exception
        if not os.path.exists(email_file_name):
            raise "Email \"{0}\" does not exist".format(email_file_name)
        
        file = open(email_file_name, "r")
        file_data = file.read()
        file.close()
    except Exception as ex:
        # print(str(ex))
        if file != None:
            file.close()
    
    return file_data

"""
Function: get_user_emails()
Purpose:  aquire an authorized users inbox which containes their emails

Parameter(s):
    -   username: the current user

Return(s): user_emails
    -   user_emails: the users emails in their inbox
"""
def get_user_emails(username):
    email_part_headers = ["From: ", "To: ", "Time and Date: ", "Title: ", "Content Length: ", "Content: ", ""]
    user_emails = []
    # attempt to execute the protected code wrapped in the try except
    try:
        for file_name in os.listdir(username):
            # load the email
            email_data = load_email("{0}/{1}".format(username, file_name))
            # check that it is not null and then append it to the user_emails list that will be returned
            if email_data != "":
                user_emails.append(email_data)
    except Exception as ex:
        # print(str(ex))
        return user_emails
    """
    Abstraction of the below line....
    sort the user_emails; set key to datetime object(s) which will be sued for sorting from least to greatest.
    datetime.datetime.strptime() will create the datetime object and takes a string and a format.
    email.split("\n")[2][len(email_part_headers[2]): once split we grab the second element which 
    is the date and time and then we substring to elimate the beggining part of the string. "so that only the time
    string is left"
    """
    user_emails.sort(key=lambda email: datetime.datetime.strptime(email.split("\n")[2][len(email_part_headers[2]):], "%Y-%m-%d %H:%M:%S.%f"))
    
    return user_emails

"""
Function: email_request()
Purpose: Requests to send and email of some size and will only send if the contents are not null
         and if it's contents are within the maximum allowed size.
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
    -   user_list: a list of authorized users
Return(s): Null
"""
def email_request(client_socket, aes_cipher, username, user_list):
   
    is_verified = True # at this point assume they are a valid user
    # inform the client whether or not to send the "large" data
    send_standard(client_socket, "Send the email".encode("ascii"), aes_cipher, aes_encrypt)
    # recv the clients message
    email_message = recv_large(client_socket, aes_cipher, aes_encrypt, aes_cipher, aes_decrypt).decode("ascii")
    # the message will be formatted such that the parts are split on new lines
    email_parts = email_message.split("\n")
    email_part_headers = ["From: ", "To: ", "Title: ", "Content Length: ", "Content: ", ""]
    
    recipient_list_checked = []
    content_len = 0
    
    rejection_reason = ""
    """
    ATTACK VECTOR: Without sanitizing user input....

    ATTACK VECTOR: With sanitizing user input....
    """
    # Email sanitization START
    # Valid email sections
    if len(email_parts) == len(email_part_headers):
        # Scan for email parts
        for i in range(len(email_part_headers)):
            # If the first part of each section does not match what it is supposed to...
            if email_parts[i][:len(email_part_headers[i])] != email_part_headers[i]:
                # Mark the email as invalid
                is_verified = False
                rejection_reason = "Invalid email headers"
        
        # If it still looks okay so far...
        if is_verified:
            # Get the real content length, and the claimed content length
            content_length_real = len(email_parts[-1])
            content_length_sent_str = email_parts[3][len(email_part_headers[3]):]
            
            if ((content_length_real == 0) # If 0 content length
                or (content_length_real > email_max_length) # Or content length is greater than the max
                or (str(content_length_real) != content_length_sent_str)): # Or content length does not match the sent content length
                is_verified = False
                rejection_reason = "Invalid content length"
            
            content_len = content_length_real # Store content length for later
        
        # If it still looks okay so far...
        if is_verified:
            # Ensure the client didn't try to spoof their username
            username_sent = email_parts[0][len(email_part_headers[0]):]
            
            if username_sent != username:
                is_verified = False
                rejection_reason = "Client spoofed username"
        
        # If it still looks okay so far...
        if is_verified:
            # We will ensure there are valid recipients
            recipient_list = email_parts[1][len(email_part_headers[1]):].split(";")
            
            # Loop through all wanted recipients
            for i in range(len(recipient_list)):
                # If the recipient exists and isn't already in recipient_list_checked
                # NOTE: USERS ARE ALLOWED TO EMAIL THEMSELVES!
                if (recipient_list[i] in user_list) and (recipient_list[i] not in recipient_list_checked):
                    # Add their name to a list
                    recipient_list_checked.append(recipient_list[i])
            
            # If there are no valid recipients after being checked
            if len(recipient_list_checked) == 0:
                is_verified = False
                rejection_reason = "No valid recipients"
    else: # Invalid email sections
        is_verified = False
        rejection_reason = "Invalid email sections"
        print(email_parts)
    # Email sanitization END
    
    if is_verified:
        # Store the email title for saving the file
        email_title = email_parts[2][len(email_part_headers[2]):]
    
        real_rcpt_str = ""
        rcpt_amount = len(recipient_list_checked)
        for i in range(rcpt_amount):
            # Add the recipient
            real_rcpt_str += recipient_list_checked[i]

            # If this is the last name in the list, don't add a ';'
            if i != (rcpt_amount - 1):
                real_rcpt_str += ";"
        
        print("An email from {0} is sent to {1} has a content length of {2}".format(username, real_rcpt_str, content_len))
        
        # Rebuild required email sections
        email_parts.insert(2, "Time and Date: {0}".format(str(datetime.datetime.now())))
        email_parts[1] = "To: {0}".format(real_rcpt_str)
        
        # Save the email in each of the recipients folders...
        for i in range(len(recipient_list_checked)):
            save_email(recipient_list_checked[i], username, email_title, email_parts)
    else:
        print("Email rejected for reason: \"{0}\".".format(rejection_reason))
 
    return
"""
Function: display_inbox()
Purpose: send the inbox to the client to be displayed
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
Return(s): Null
"""
def display_inbox(client_socket, aes_cipher, username):
    # specific parts of the email header
    email_part_headers = ["From: ", "To: ", "Time and Date: ", "Title: ", "Content Length: ", "Content: ", ""]
    # call get_user_emails() in order to get all the user emails
    user_emails = get_user_emails(username)
    # formated string representing the inbox
    inbox_str = "{:8s}{:12s}{:32s}{}\n".format("Index", "From", "DateTime", "Title")
    # iterate through all of the emails in the inbox 
    for i in range(len(user_emails)):
        email_parts = user_emails[i].split("\n")
        # grab relevent data
        e_from = email_parts[0][len(email_part_headers[0]):]
        e_time = email_parts[2][len(email_part_headers[2]):]
        e_title = email_parts[3][len(email_part_headers[3]):]
        # format relevent data
        inbox_str += "{:8s}{:12s}{:32s}{}\n".format(str(i + 1), e_from, e_time, e_title)
    # when the inbox string is complete (i.e. we have gone through all the indexes, which is equal to the length of user_emails)
    # we will call send_large
    send_large(client_socket, inbox_str.encode("ascii"), aes_cipher, aes_encrypt, aes_cipher, aes_decrypt)
    # determine if the previous operation was succesful based on if the client response is "OK"
    confirmation = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
    if confirmation != "OK":
        print("Client \"{0}\" error in handling display_inbox()".format(username))
    
    return
"""
Function: display_email()
Purpose: from user input this function will aquire an index that will be sent to the server 
         which will return the email message associated with that index
Parameter(s): client_socket, aes_cipher, username
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
Return(s): Null
"""
def display_email(client_socket, aes_cipher, username):
    # ask for the index of the email the client would like to view
    send_standard(client_socket, "the server request email index".encode("ascii"), aes_cipher, aes_encrypt)
    # receive from the client the email index as a string for the email hte client would like to veiw
    email_index_str = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
    
    email_index = -1
    # confirm that the string is a digit of sorts
    if email_index_str.isdigit():
        email_index = (int(email_index_str) - 1)
    
    return_email = ""
    # get the users emails 
    emails_list = get_user_emails(username)
    #
    if (email_index >= 0) and (email_index < len(emails_list)):
        return_email = emails_list[email_index]
    # in case of null inplace of index
    if return_email == "":
        return_email = "Email index invalid..."
    # call send large to send over the email data for display
    send_large(client_socket, return_email.encode("ascii"), aes_cipher, aes_encrypt, aes_cipher, aes_decrypt)
    return

# menu of options to display to the client in order to guide their input
menu_str = "\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nchoice: "
"""
Function: client_main()
Purpose:
Parameter(s): client_socket, aes_cipher, username, user_list
    -   client_socket: The clients socket
    -   aes_cipher: The cipher for aes encryption/decryption
    -   username: the current users username
    -   user_list: list of authorized users
Return(s): Null
"""
def client_main(client_socket, aes_cipher, username, user_list):
    while True:
        # send the menu string
        send_standard(client_socket, menu_str.encode("ascii"), aes_cipher, aes_encrypt)
        # recv the client response
        user_input = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
        
        if user_input == "1": # Create and send an email
            email_request(client_socket, aes_cipher, username, user_list)
        elif user_input == "2": # Display the inbox list
            display_inbox(client_socket, aes_cipher, username)
        elif user_input == "3": # Display the email contents
            display_email(client_socket, aes_cipher, username)
        else: # Terminate the connection
            print("Terminating connection with {0}".format(username))
            send_standard(client_socket, "The connection is terminated with the server.".encode("ascii"), aes_cipher, aes_encrypt)
            return
    
    return

"""
Function: client_init()
Purpose: The purpose of this function is to authorize a user by receiving data related to 
         a username and password for a a client who will be authorized in the below function.
Parameter(s): client_socket, rsa_private, user_list
client_socket: The clients socket
rsa_private: private rsa key
user_list: list of authorized users
Return(s): Null
"""   
def client_init(client_socket, rsa_private, user_list):
    # attempt to recv parts related to authentication 
    try:
        auth_parts = recv_standard(client_socket, rsa_private, rsa_decrypt).decode("ascii").split(':')
        username = auth_parts[0] # set the username 
        authenticated = False # assume false (guilty until proven innocent)
        # invalid length, exit function
        if len(auth_parts) != 2:
            print("The received client information: {0} is invalid (Connection Terminated).".format(username))
            send_standard(client_socket, "Invalid username or password".encode("ascii")) # inform client 
            return # exit function
        # if the username is in the list of authorized users and...
        if auth_parts[0] in user_list: # Username in list
            # the provided password matches 
            if user_list[auth_parts[0]] == auth_parts[1]: # Password matches that username
                # authenticate the client 
                authenticated = True
        # on failure to authenticate we inform the client and terminate the connection
        if not authenticated:
            print("The received client information: {0} is invalid (Connection Terminated).".format(username))
            send_standard(client_socket, "Invalid username or password".encode("ascii"))
            return
        # call rsa_load in order to load the client_rsa
        client_rsa = rsa_load(username, False)
        # failed to load the client rsa, infor client and terminate connection
        if client_rsa == None:
            print("Failed to load client public key...")
            send_standard(client_socket, "Invalid username or password".encode("ascii"))
            return
        # generate a symetric key     
        sym_key = generate_sym_key()
        # inform client
        send_standard(client_socket, sym_key, client_rsa, rsa_encrypt)
        # load a cipher for aes encrypton in ecb mode
        aes_cipher = aes_ecb_load(sym_key)
        
        print("Connection Accepted and Symmetric Key Generated for client: {0}".format(username))

        # recv a confirmation message from the client
        OK_message = recv_standard(client_socket, aes_cipher, aes_decrypt).decode("ascii")
        # if the message does not equal "OK" there was am error and we exit
        if OK_message != "OK":
            print("Unexpected message received, sym_key transfer failed...")
            return
        # now that the client connection has been initialized and authorized we call client main
        client_main(client_socket, aes_cipher, username, user_list)
    except Exception as ex:
        print("Exception caught while handling client: {0}".format(str(ex)))
    
    client_socket.close()
    return

"""
Function: server()
Purpose: The server will aid in instantiating a handshake with the client by opening a 
         a private server key using the rsa_load() function and using the socket library in order
         to establish communcation with the server.
Parameter(s): None
    -   takes null parameters
Return(s): None, False
    -   returns null on error or end of function
    -   returns False if we failed to load the file or we failed to load the rsa keys
"""
def server():
    json_file_name = "user_pass.json"
    user_list = json_read(json_file_name)
    
    if user_list == {}:
        print("Failed to load file \"{0}\"! Aborting...".format(json_file_name))
        return False

    try:
        for client in user_list:
            if not os.path.exists(client):
                os.mkdir(client)
    except:
        pass # Generated later anyways if this fails somehow

    rsa_private = rsa_load("server", True)
    # rsa_public = rsa_load("server", False)
    if (rsa_private == None): # if (rsa_private == None) or (rsa_public == None):
        print("Failed to load RSA keys! Aborting...")
        return False
    
    # Initialize socket data
    server_socket = None
    server_port = 13000
    
    # Try to create and bind the socket, also set it to listen for 5 clients
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("", server_port))
        server_socket.listen(5)
    except Exception as ex: # If it fails
        # Close the socket
        if server_socket != None:
            server_socket.close()
            server_socket = None
        
        # Alert the user and exit
        print("Error in server startup: {0}".format(str(ex)))
        return
    
    # Alert to console that the socket creation was successful, and that we are ready for connections
    print("The server is ready to accept connections")
    
    # Continue to handle clients until exiting
    while True:
        # Handle exceptions properly
        try:
            # Get the new client info
            client_socket, client_address = server_socket.accept()
            
            # Remove these ''' before handing in the project / using on the server (and remove the line below)!!!
            
            # Create a child process through fork() (this only works on Linux)
            if os.fork() != 0: # Parent process
                # On the parent process, close the new client socket and continue accepting new clients
                client_socket.close()
                # Continue execution, wait for more clients
                continue
            else: # Child process
                # On the child process, close the server connection socket and handle the specific client
                server_socket.close()
                server_socket = None
                
                # Handle the client
                client_init(client_socket, rsa_private, user_list)
                return # Exit the server() function
            
            
           # client_init(client_socket, rsa_private, user_list) # Remove this line when using the above os.fork() code...
        except KeyboardInterrupt:  # If ctrl+c is pressed
            # Alert to console and exit
            print("KeyboardInterrupt exception hit! Exiting...")
            return
        except SystemExit: # If this process is being force-exited
            # Alert to console and exit
            print("SystemExit exception hit! Exiting...")
            return
        except Exception as ex: # Every other exception
            # Alert to console and continue running
            print("Exception occured in server(): {0}".format(str(ex)))
    
    # If the server socket is still valid
    if (server_socket != None):
        # Close it
        server_socket.close()
        server_socket = None
    
    return

if __name__ == "__main__":
    server()