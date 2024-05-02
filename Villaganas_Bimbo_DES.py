from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_des_key():
    return get_random_bytes(8)

def encrypt_message(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message.encode(), 8)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def decrypt_message(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_message = cipher.decrypt(ciphertext)
    unpadded_message = unpad(decrypted_message, 8)
    return unpadded_message.decode()

# Example usage
if __name__ == "__main__":
    key = generate_des_key()
    message = "Hello, world!"
    ciphertext = encrypt_message(message, key)
    decrypted_message = decrypt_message(ciphertext, key)
    
    print("Original Message:", message)
    print("Encrypted Message:", ciphertext)
    print("Decrypted Message:", decrypted_message)
