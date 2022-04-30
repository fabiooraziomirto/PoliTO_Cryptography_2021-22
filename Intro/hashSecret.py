from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random import get_random_bytes
import base64

import json

from pluggy import HookimplMarker

if __name__ == '__main__':
    msg = b'This is the message used in input'

    secret = b'asdafdsdsadasdasdsadasdsad'

    hmac_generator = HMAC.new(secret, digestmod = SHA3_256)


    hmac_generator.update(msg[:5])

    hmac_generator.update(msg[5:])


    print(hmac_generator.hexdigest())

    obj = json.dumps({'message' : msg.decode(), 'MAC': base64.b64encode(hmac_generator.digest()).decode()})

    print(obj)

    b64_obj = json.loads(obj)

    hmac_verifier = HMAC.new(secret, digestmod= SHA3_256)

    hmac_verifier.update(b64_obj['message'].encode())

    mac = bytearray(base64.b64decode(b64_obj['MAC'].encode()))
    mac[0] = 0

    try:
        hmac_verifier.verify(base64.b64decode(b64_obj['MAC'].encode()))
        print("The message is authentic")
    except ValueError:
        print("Wrong message or secret")