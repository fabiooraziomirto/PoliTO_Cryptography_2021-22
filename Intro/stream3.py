from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import Salsa20, AES
from Cryptodome.Util.Padding import pad, unpad

import sys
import base64
import json

if __name__ == '__main__':

    key = get_random_bytes(AES.key_size[0])
    iv = get_random_bytes(AES.block_size)

    f_input = open(__file__, "rb")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(f_input.read(), AES.block_size))

    f_output = open("enc.enc", "wb")

    f_output.write(ciphertext)

    print(base64.b64encode(iv))

    result = json.dumps({'ciphertext' : base64.b64encode(ciphertext).decode(), 'iv' : base64.b64encode(iv).decode()})

    print(result)

    b64_output = json.loads(result)

    iv_rec = base64.b64decode(b64_output['iv'])
    ciphertext_rec = base64.b64decode(b64_output['ciphertext'])
    cipher_dec = AES.new(key, AES.MODE_CBC, )
    plaintext_rec = cipher_dec.decrypt(ciphertext_rec)

    print(plaintext_rec)


