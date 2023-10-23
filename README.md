brief description
=================
cbcmode: 
    - aes encryption and decryption program with cbc mode, use libraly pycryptodome
    - have 2 main function: encrypt and dycrypt, they use AES.MODE_CBC, This is the CBC mode of AES. In this mode, each block of data is encrypted independently of previous blocks using an IV
    - you can generate the key using the genarate_key function or you can enter the key from the keyboard(if you need to decrypt the ciphertext with the given key), ofcouse u have to  enter the plain text to encrypt and cipher text to decrypt

ctrmode:
    - aes encryption and decryption program with ctr mode, use libraly pycryptodome
    - have 2 main function: ctrEncrypt and ctrDycrypt, they use AES.MODE_CTR, this is the CTR mode of AES. In this mode, each block of data is encrypted using a unique Counter value
    - you can generate the key using the genarate_key function or you can enter the key from the keyboard(if you need to decrypt the ciphertext with the given key), ofcouse u have to  enter the plain text to encrypt and cipher text to decrypt

install libraly
    - in linux/macos: open terminal, run cod: pip install pycryptodome
    - im window: u can download in https://pypi.org/project/pycryptodome/

