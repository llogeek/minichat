import socket
from threading import Thread
from diffi_hellman import *
from data_prep import *
import random
from aes import *
from client import *
import time

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 7777
separator_token = "<SEP>"
client_sockets = set()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((SERVER_HOST, SERVER_PORT))
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
stateA = {'dh': 1,
          'toBob': 0,
          'fromTrent': 0,
          'ecdsa': 0,
          'chat': 0
          }
alice_data = {}
def listen_for_client(cs):
    t = threading.current_thread()
    while getattr(t, 'do_run', True):
        try:
            msg = cs.recv(1024).decode()
        except Exception as e:
            print(f"[!] Error: {e}")
            client_sockets.remove(cs)
        else:
            if stateA['ecdsa'] == 1:
                msg = unpack_data(msg)
                alice_data.update({'private_ecdsa': msg[0], 'public_ecdsa': msg[1]})
                stateA.update({'ecdsa': 0, 'chat': 1})
                cs.close()
                break
            elif stateA['fromTrent'] == 1:
                msg = unpack_data(msg)
                B, Na, Kab, Tb = unpack_data(decrypt(msg[0], alice_data['Kas']))
                alice_data.update({'B': B})
                print(B, Na, Kab, Tb)
                alice_data.update({'Kab': bytes.fromhex(Kab)})
                if int(Na) == alice_data['Na']:
                    encNb = encrypt(msg[2], alice_data['Kab'])
                    mess_bob = pack_data(msg[1], encNb)
                    to_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    to_bob.connect(('0.0.0.0', 8888))
                    to_bob.send(mess_bob.encode())
                    to_bob.close()
                stateA.update({'fromTrent':0, 'ecdsa':1})
                cs.close()
                break
            elif stateA['toBob'] == 1:
                ab_send = pack_data(alice_data['idA'], str(alice_data['Na']))
                ab_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ab_socket.connect(('0.0.0.0', 8888))
                ab_socket.send(ab_send.encode())
                ab_socket.close()
                stateA.update({'toBob': 0, 'fromTrent': 1})
                cs.close()
                break
            elif stateA['dh'] == 1:
                stateA.update({'dh': 0, 'toBob': 1})
                msg = unpack_data(msg)
                p, g, y = get_params(msg[0], msg[1], msg[2])
                priv, AS_shared_key = priv_shared(p, g, y)
                alice_data.update({'Kas':AS_shared_key})
                to_send = pack_data('A', priv)
                print('Alice shared key: ', alice_data['Kas'])
                as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                as_socket.connect(('0.0.0.0', 9999))
                as_socket.send(to_send.encode())
                as_socket.close()
                time.sleep(2)
                continue
            else:
                break

username = 'Alice' #input('Your username: ')
alice_data.update({'idA':username, 'Na':random.randint(1, 1000000)})

while True:
    client_socket, client_address = s.accept()
    print(f"[+] {client_address} connected.")
    client_sockets.add(client_socket)
    t = Thread(target=listen_for_client, args=(client_socket,))
    t.daemon = True
    t.start()
    t.join()
    if stateA['chat'] == 1:
        #time.sleep(0.1)
        #t.do_run = False
        break

print('exit')
for cs in client_sockets:
    cs.close()
s.close()

client(username, alice_data['private_ecdsa'], alice_data['public_ecdsa'], alice_data['Kab'])