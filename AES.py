import base64
import secrets
import os
from colorama import init, Fore, Style



def clear_screen():
      os.system('clear')
      
      
init() #to call colorama


def enc_print():
    print(r'''
     ____   _    _   ___   ____  __   __  ____   _______
    / ___| | \  | | / __\ |  _ \ \ \_/ / | __ \ |__   __|
    | |_   |  \ | |/ /    |  __/  \   /  | ___/    | |
    |  _|  | |\\| || |    |  \     | |   | |       | |
    | |__  | | \  |\ \__  | | \    | |   | |       | |
    \____| |_|  \_| \___/ |_|\_\   |_|   |_|       |_|
    
    ''')

def dec_print():
    print(r'''
     ___    ____   ___   ____  __   __  ____   _______
    |   \  / ___| / __\ |  _ \ \ \_/ / | __ \ |__   __|
    | || | | |_  | /    |  __/  \   /  | ___/    | |
    | || | |  _| | |    |  \     | |   | |       | |
    | || | | |__ | \__  | | \    | |   | |       | |
    |___/  \____| \___/ |_|\_\   |_|   |_|       |_|
    
    ''')
    
def AES_print():
    print(r'''
     _____   ____    ____
    /  _  \ / ___|  / ___\
    | |_| | | |_   | |___  
    |  _  | |  _|   \___ \
    | | | | | |__   ____| |          
    |_| |_| \____| |_____/ 
        
    ''')    



def encrypt(plain_text, key):
    cipher_text = bytearray(plain_text)
    for i in range(len(plain_text)):
        cipher_text[i] ^= key[i % len(key)]
    return base64.urlsafe_b64encode(cipher_text)

def decrypt(cipher_text, key):
    plain_text = bytearray(base64.urlsafe_b64decode(cipher_text + b'=' * (4 - len(cipher_text) % 4)))
    for i in range(len(plain_text)):
        plain_text[i] ^= key[i % len(key)]
    return plain_text
    
clear_screen()
AES_print()	


while True:
    print(Fore.YELLOW,"Enter 0 for encryption, 1 for decryption, or q to quit:\n",Fore.RESET)
    choice = input("[+]")
    if choice == 'q':
        break
    elif choice == '0':
        clear_screen()
        enc_print()      
        print(Fore.BLUE,"\nEnter the plain text:\n",Fore.RESET)
        plain_text = input("[+]")
        key = secrets.token_bytes(16)
        cipher_text = encrypt(plain_text.encode('latin-1'), key)  
        print("\nCipher text: ",end="")
        print(Fore.GREEN,cipher_text.decode('latin-1'),Fore.RESET)
        print("Key: ",end="")
        print(Fore.GREEN,base64.urlsafe_b64encode(key).decode('latin-1')+"\n",Fore.RESET)
        
            
            
    elif choice == '1':
        clear_screen()
        dec_print()
        print(Fore.BLUE,"\nEnter the ciphertext:\n",Fore.RESET)
        cipher_text = input("[+]")
        print(Fore.BLUE,"\nEnter the encryption key:\n",Fore.RESET)
        key = input("[+]")
        key_bytes = base64.urlsafe_b64decode(key.encode('latin-1') + b'=' * (4 - len(key) % 4))
        decrypted_text = decrypt(cipher_text.encode('latin-1'), key_bytes)
        print("\nDecrypted text: " + decrypted_text.decode('latin-1')+"\n")
    else:
        print("Invalid choice.")
