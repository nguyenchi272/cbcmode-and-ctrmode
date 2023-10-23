from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_key():
    return get_random_bytes(16)

def encrypt(key, plain_text):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(pad(plain_text.encode('utf-8'), 16))
    return iv + encrypted_text

def decrypt(key, encrypted_text):
    key_bytes = bytes.fromhex(key)
    encrypted_text_bytes = bytes.fromhex(encrypted_text)
    iv = encrypted_text_bytes[:16]
    encrypted_data = encrypted_text_bytes[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data), 16)
    return decrypted_text.decode('utf-8')

def main():
    key = generate_key()
    plain_text = 'Nguyen Cao Chi'
    encrypted_text = encrypt(key, plain_text)
    print("Encrypted Text:", encrypted_text.hex())
    
    key = '140b41b22a29beb4061bda66b6747e14'
    encrypted_text = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
    decrypted_text = decrypt(key, encrypted_text)
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
