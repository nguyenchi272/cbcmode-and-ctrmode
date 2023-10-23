from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

def generate_key():
    return get_random_bytes(16)  

def ctrEncrypt(key, plainText, blockSize):
    k = bytes.fromhex(key)
    iv = Counter.new(blockSize * 8, prefix=b'0'*4, little_endian=True)
    cipher = AES.new(k, AES.MODE_CTR, counter=iv)
    encryptedText = cipher.encrypt(plainText.encode('utf-8'))
    return iv() + encryptedText

def ctrDecrypt(key, cypherText, blockSize):
    k = bytes.fromhex(key)
    ct = bytes.fromhex(cypherText)
    iv = ct[:blockSize]
    ct1 = ct[blockSize:]
    ctr = Counter.new(blockSize * 8, initial_value=int.from_bytes(iv, byteorder='big'))
    obj = AES.new(k, AES.MODE_CTR, counter=ctr)
    paddedStr = obj.decrypt(ct1)
    return paddedStr

def main():
    blockSize = 16
    # key = generate_key()
    # plain_text = ""

    # encrypted_text = ctrEncrypt(key, plain_text, blockSize)
    # print("Encrypted Text:", encrypted_text.hex())
    
    key = '36f18357be4dbd77f050515c73fcf9f2'
    encrypted_text = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
    decrypted_text = ctrDecrypt(key, encrypted_text, blockSize)
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
