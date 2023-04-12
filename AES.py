import base64
import secrets

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

while True:
    choice = input("Enter 0 for encryption, 1 for decryption, or q to quit: ")
    if choice == 'q':
        break
    elif choice == '0':
        plain_text = input("Enter the plain text: ")
        key = secrets.token_bytes(16)
        cipher_text = encrypt(plain_text.encode('latin-1'), key)
        print("Cipher text: " + cipher_text.decode('latin-1'))
        print("Key: " + base64.urlsafe_b64encode(key).decode('latin-1'))
    elif choice == '1':
        cipher_text = input("Enter the ciphertext text: ")
        key = input("Enter the encryption key: ")
        key_bytes = base64.urlsafe_b64decode(key.encode('latin-1') + b'=' * (4 - len(key) % 4))
        decrypted_text = decrypt(cipher_text.encode('latin-1'), key_bytes)
        print("Decrypted text: " + decrypted_text.decode('latin-1'))
    else:
        print("Invalid choice.")
