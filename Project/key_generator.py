import json
from Crypto.PublicKey import RSA

def key_to_file(file_name, key):
    return_value = True
    file = None

    try:
        file = open(file_name, "wb")
        file.write(key)
    except Exception as ex:
        return_value = False
    
    if file != None:
        file.close()
    
    return True

def generate_save_keys(name):
    new_rsa = RSA.generate(2048)
    
    if not key_to_file(name + "_private.pem", new_rsa.export_key()):
        return False
    
    if not key_to_file(name + "_public.pem", new_rsa.publickey().export_key()):
        return False
    
    return True

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

def KeyGen():
    json_file_name = "user_pass.json"
    json_dict = json_read(json_file_name)
    success = True
    
    if json_dict == {}:
        print("Failed to load file \"{0}\"! Aborting...".format(json_file_name))
        return False

    generate_names = ["server"]
    generate_names.extend(list(json_dict))
    
    for name in generate_names:
        if not generate_save_keys(name):
            success = False
    
    if success:
        print("All keys generated successfully!")
    else:
        print("Failed to generate keys...")
    
    return success
    
if __name__ == "__main__":
    KeyGen()