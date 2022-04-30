from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import Salsa20
import sys
import base64


if __name__ == '__main__':

    key = get_random_bytes(Salsa20.key_size[1])
    nonce = get_random_bytes(8)

    cipher = Salsa20.new(key = key, nonce = nonce)

    f_output = open(sys.argv[2], "wb")

    ciphertext = b''

    with open(sys.argv[1] ,"rb") as f_input:
        plaintext = f_input.read(1024)
        while plaintext:
            ciphertext += cipher.encrypt(plaintext)
            f_output.write(ciphertext)
            plaintext = f_input.read(1024)

    print("Nonce = " + base64.b64encode(cipher.nonce).decode())