import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


def pad(s, bs = AES.block_size):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]
def encrypt(raw, key):
    key = hashlib.sha256(key).digest()
    raw = pad(raw)
    iv = Random.get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(raw.encode())).hex()


def decrypt(enc, key):
    key = hashlib.sha256(key).digest()
    enc = bytes.fromhex(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


