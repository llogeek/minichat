import ecdsa

directory = './/keys//'
def gen_keys(priv_name, pub_name):
    ecdh = ecdsa.ECDH(curve=ecdsa.SECP256k1)
    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()

    with open(directory + pub_name, "wb") as e:
       e.write(public_key.to_pem())
    with open(directory + priv_name, "wb") as e:
       e.write(ecdh.private_key.to_pem())

def compute_shared_secret(my_priv_name, their_pub_name):
    ecdh_my = ecdsa.ECDH(curve=ecdsa.SECP256k1)
    with open(directory + my_priv_name) as f:
        ecdh_my.load_private_key_pem(f.read())
    with open(directory + their_pub_name) as f:
        ecdh_my.load_received_public_key_pem(f.read())
    return ecdh_my.generate_sharedsecret_bytes()

def get_private_key(my_priv_name):
    ecdh_my = ecdsa.ECDH(curve=ecdsa.SECP256k1)
    with open(directory + my_priv_name) as f:
        ecdh_my.load_private_key_pem(f.read())
    return ecdh_my.private_key

def get_public_key(their_pub_name):
    ecdh_my = ecdsa.ECDH(curve=ecdsa.SECP256k1)
    with open(directory + their_pub_name) as f:
        ecdh_my.load_received_public_key_pem(f.read())
    return ecdh_my.public_key