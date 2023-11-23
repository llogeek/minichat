import socket
import time
from threading import Thread
from diffi_hellman import *
from aes import *
import random
from client import *
from data_prep import *

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8888
separator_token = "<SEP>"
client_sockets = set()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((SERVER_HOST, SERVER_PORT))
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
eps = 360
stateB = {'dh': 1,
          'fromAlice1': 0,
          'fromAlice2': 0,
          'ecdsa': 0,
          'chat': 0
          }
st = False
bobs_data = {}
def listen_for_client(cs, event):
    while True:
        try:
            msg = cs.recv(1024).decode()
        except Exception as e:
            print(f"[!] Error: {e}")
            client_sockets.remove(cs)
        else:
            if stateB['ecdsa'] == 1:
                msg = unpack_data(msg)
                bobs_data.update({'private_ecdsa':msg[0], 'public_ecdsa':msg[1]})
                stateB.update({'ecdsa':0, 'chat':1})
                cs.close()
                break
            elif stateB['fromAlice2'] == 1:
                msg = unpack_data(msg)
                A, Kab, Tb = unpack_data(decrypt(msg[0], bobs_data['Kbs']))
                bobs_data.update({'A': A})
                if float(Tb) == bobs_data['Tb'] and float(Tb) - bobs_data['Tb'] < eps:
                    bobs_data.update({'Kab': bytes.fromhex(Kab)})
                    Nb = decrypt(msg[1], bobs_data['Kab'])
                    if int(Nb) == bobs_data['Nb']:
                        socket_bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        socket_bs.connect(('0.0.0.0', 9999))
                        auth_result = encrypt('Success', bobs_data['Kab'])
                        socket_bs.send(auth_result.encode())
                        socket_bs.close()
                stateB.update({'fromAlice2':0, 'ecdsa':1})
                cs.close()
                break
            elif stateB['fromAlice1'] == 1:
                msg = unpack_data(msg)
                print("Message from Alice to Bob, got by Bob: ", msg[0], msg[1])
                data = '\n'.join([msg[0], msg[1], str(bobs_data['Tb'])])
                cipher_text = encrypt(data, bobs_data['Kbs'])
                bs_message = '\n'.join([bobs_data['idB'], str(bobs_data['Nb']), cipher_text])
                socket_bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_bs.connect(('0.0.0.0', 9999))
                socket_bs.send(bs_message.encode())
                socket_bs.close()
                stateB.update({'fromAlice1': 0, 'fromAlice2': 1})
                cs.close()
                break
            elif stateB['dh'] == 1:
                stateB.update({'dh': 0, 'fromAlice1': 1})
                msg = unpack_data(msg)
                p, g, y = get_params(msg[0], msg[1], msg[2])
                priv, BS_shared_key = priv_shared(p, g, y)
                bobs_data.update({'Kbs': BS_shared_key})
                to_send = pack_data('B', priv)
                print('Bob shared key: ', bobs_data['Kbs'])
                bs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                bs_socket.connect(('0.0.0.0', 9999))
                bs_socket.send(to_send.encode())
                bs_socket.close()
                time.sleep(1)
                cs.close()
                break
            else:
                break


username = 'Bob'  # input('Your username: ')
bobs_data.update({'idB':username, 'Nb':random.randint(1, 100000000), 'Tb':time.time()})

while True:
    client_socket, client_address = s.accept()
    print(f"[+] {client_address} connected.")
    client_sockets.add(client_socket)
    event = Event()
    t = Thread(target=listen_for_client, args=(client_socket, event, ))
    t.daemon = True
    t.start()
    t.join()
    if stateB['chat'] == 1:
        break

print('exit')
for cs in client_sockets:
    cs.close()
s.close()

client(username, bobs_data['private_ecdsa'], bobs_data['public_ecdsa'], bobs_data['Kab'])