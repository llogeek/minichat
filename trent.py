from threading import Thread
from data_prep import *
import socket
import os
from diffi_hellman import *
from ecds import *
from aes import *
import time

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 9999
separator_token = "<SEP>"
client_sockets = set()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((SERVER_HOST, SERVER_PORT))
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
stateT = {'dh1': 1,
          'dh2': 1,
          'fromBob': 0,
          'ecdsa': 0,
          'chat': 0
          }

a_files = {'private':"a_private_key.pem", 'public':"a_pub_key.pem"}
b_files = {'private':"b_private_key.pem", 'public':"b_pub_key.pem"}
ecdsa_key_a = gen_keys("a_private_key.pem", "a_pub_key.pem")
ecdsa_key_b = gen_keys("b_private_key.pem", "b_pub_key.pem")
trent_data = {}
def listen_for_client(cs, dh_data):
    while True:
        try:
            msg = cs.recv(1024).decode()
        except Exception as e:
            print(f"[!] Error: {e}")
            client_sockets.remove(cs)
        else:
            if stateT['ecdsa'] == 1:
                auth_result = decrypt(msg, trent_data['Kab'])
                if auth_result == 'Success':
                    socket_sa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_sa.connect(('0.0.0.0', 7777))
                    to_send_a = pack_data(a_files['private'], b_files['public'])
                    socket_sa.send(to_send_a.encode())
                    socket_sa.close()
                    time.sleep(5)
                    socket_sb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_sb.connect(('0.0.0.0', 8888))
                    to_send_b = pack_data(b_files['private'], a_files['public'])
                    socket_sb.send(to_send_b.encode())
                    socket_sb.close()
                stateT.update({'ecdsa':0, 'chat':1})
                cs.close()
                client_sockets.remove(cs)
                break
            if stateT['fromBob'] == 1:
                msg = unpack_data(msg)
                B, Nb, ciphertext = msg
                A, Na, Tb = unpack_data(decrypt(ciphertext, trent_data['Kbs']))
                Kab = os.urandom(16)
                print('Generated session key: ', Kab)
                print('Send session key: ', Kab.hex())
                trent_data.update({'Kab':Kab})
                dataA = pack_data(B, Na, Kab.hex(), Tb)
                dataAS = encrypt(dataA, trent_data['Kas'])
                dataB = pack_data(A, Kab.hex(), Tb)
                dataBS = encrypt(dataB, trent_data['Kbs'])
                data_Alice = pack_data(dataAS, dataBS, Nb)
                socket_sa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_sa.connect(('0.0.0.0', 7777))
                socket_sa.send(data_Alice.encode())
                socket_sa.close()
                stateT.update({'fromBob': 0, 'ecdsa': 1})
                cs.close()
                client_sockets.remove(cs)
                break
            if stateT['dh1'] == 1 or stateT['dh2'] == 1:
                data = unpack_data(msg)
                if data[0] == 'A':
                    trent_data.update({'Kas': get_trent_shared(dh_data['p_as'], dh_data['g_as'], dh_data['AS_key'], data[1])})
                    print('Alice shared key: ', trent_data['Kas'])
                    stateT.update({'dh1':0})
                    if stateT['dh1'] == 0 and stateT['dh2'] == 0:
                        stateT.update({'fromBob': 1})
                    cs.close()
                    client_sockets.remove(cs)
                    break
                elif data[0] == 'B':
                    trent_data.update({'Kbs': get_trent_shared(dh_data['p_bs'], dh_data['g_bs'], dh_data['BS_key'], data[1])})
                    print('Bob shared key: ', trent_data['Kbs'])
                    stateT.update({'dh2': 0})
                    if stateT['dh1'] == 0 and stateT['dh2'] == 0:
                        stateT.update({'fromBob': 1})
                    cs.close()
                    client_sockets.remove(cs)
                    break
            else:
                msg = msg.replace(separator_token, ": ")
            for client_socket in client_sockets:
                if client_socket != cs:
                    client_socket.send(msg.encode())

def get_parameters_dh():
    params = generate_dh_parameters()
    p, g = get_p_g_from_params(params)
    private_key, public_key = generate_privatekey_pubkey(params)
    data = form_public_data(p, g, public_key)
    return data, private_key, p, g


data_as, AS_key, p_as, g_as = get_parameters_dh()
dh_data = {'p_as': p_as, 'g_as': g_as, 'AS_key': AS_key}
data_bs, BS_key , p_bs, g_bs = get_parameters_dh()
dh_data.update({'p_bs': p_bs, 'g_bs': g_bs, 'BS_key':BS_key})
sa_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sa_socket.connect(('0.0.0.0', 7777))
sa_socket.send(data_as.encode())
sa_socket.close()
sb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sb_socket.connect(('0.0.0.0', 8888))
sb_socket.send(data_bs.encode())
sb_socket.close()
while True:
    client_socket, client_address = s.accept()
    print(f"[+] {client_address} connected.")
    client_sockets.add(client_socket)
    t = Thread(target=listen_for_client, args=(client_socket, dh_data, ))
    t.daemon = True
    t.start()

for cs in client_sockets:
    cs.close()
s.close()