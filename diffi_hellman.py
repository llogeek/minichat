from cryptography.hazmat.primitives.asymmetric import dh
from data_prep import *
KEY_SIZE = 64 # X bytes = X*8 bits


# generate ephemeral DH parameters
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=KEY_SIZE * 8)
    return parameters

def get_p_g_from_params(parameters):
    p = parameters.parameter_numbers().p
    p_bytes = int(p).to_bytes(KEY_SIZE, "big")
    #print("P = ", p_bytes.hex())
    g = parameters.parameter_numbers().g
    g_bytes = int(g).to_bytes(1, "big")
    #print("g = ", g_bytes.hex())
    return p_bytes.hex(), g_bytes.hex()

# generate private key and corresponding public
def generate_privatekey_pubkey(parameters):
    private_key = parameters.generate_private_key()
    y = private_key.public_key().public_numbers().y
    x = private_key
    y_bytes = int(y).to_bytes(KEY_SIZE, "big")
    return x, y_bytes.hex()

def form_public_data(p_bytes, g_bytes, y_bytes):
    send_bytes = pack_data(p_bytes, g_bytes, y_bytes)
    return send_bytes

def to_bytes(key):
    return int(key).to_bytes(KEY_SIZE, 'big')

def from_bytes(byte_key):
    return int.from_bytes(bytes.fromhex(byte_key), "big")

def get_params(p_bytes, g_bytes, y_bytes):
    p = int.from_bytes(bytes.fromhex(p_bytes),"big")
    g = int.from_bytes(bytes.fromhex(g_bytes),"big")
    y = int.from_bytes(bytes.fromhex(y_bytes),"big")
    return p, g, y

def priv_shared(p, g, y):
    pars = dh.DHParameterNumbers(p, g)
    S_public_key = dh.DHPublicNumbers(y, pars).public_key()
    private_key = pars.parameters().generate_private_key()
    public_key = private_key.public_key()
    shared_key = private_key.exchange(S_public_key)
    return to_bytes(public_key.public_numbers().y).hex(), shared_key

def get_trent_shared(p, g, trent_private_key, other_public_key):
    pars = dh.DHParameterNumbers(from_bytes(p), from_bytes(g))
    public_key = dh.DHPublicNumbers(from_bytes(other_public_key), pars).public_key()
    shared_key = trent_private_key.exchange(public_key)
    return shared_key