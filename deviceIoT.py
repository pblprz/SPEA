from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import paho.mqtt.client as mqtt
import os

# Solo si queremos Padding
from cryptography.hazmat.primitives import padding

# Generate DH parameters
'''
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
params_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
print(str(params_pem))
'''

print('Dame los parámetros: ')
b_pem = bytes(input().replace("\\n", "\n"), 'ascii')
# b_pem = codecs.decode(input(), "unicode-escape")
print(b_pem)
parameters = load_pem_parameters(b_pem, backend=default_backend())

#b_params_from_number = DHParameterNumbers(10, 3).parameters(backend=default_backend())
#b_params_from_pem = load_pem_parameters(b_pem, backend=default_backend())

#b_params_pem= b_params.parameter(backend=default_backend())

#parameters = b_params_from_number

#Generate private keys.
a_private_key = parameters.generate_private_key()
a_public_key = a_private_key.public_key()

print("Esta es mi clave privada: %d"%a_private_key.private_numbers().x)
print("Esta es mi clave pública: %d"%a_public_key.public_numbers().y)

'''
b_private_key = parameters.generate_private_key()
b_public_key = b_private_key.public_key()
'''

print("Dame la pública de tu compañero: ")
b_public_key_number = int(input())

#Des-serializando
peer_public_numbers = dh.DHPublicNumbers(b_public_key_number, parameters.parameter_numbers())
b_public_key = peer_public_numbers.public_key(default_backend())

'''
print("Esta es tu clave privada: %d"%b_private_key.private_numbers().x)
print("Esta es tu clave pública: %d"%b_public_key.public_numbers().y)
'''
a_shared_key = a_private_key.exchange(b_public_key)
#b_shared_key = b_private_key.exchange(a_public_key)

print("a_shared_key: " + str(a_shared_key))
#print("b_shared_key: " + str(b_shared_key))

key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(a_shared_key)
print(key)

# 1. Iot -> S : publish "register" Pu_IoT_DH
# 2. S -> FF :  publish "pu_S" Pu_S_DH 
# 3. S, IoT : Generate K_s
# 4. IoT: Generate Code = Random (6 digitos)
# 5. IoT: Show Code
# 6. IoT - S : publish "auth" E_K_S(Code)
# 7. S : Verify Code received = Code shown

import time

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("SPEA")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.username_pw_set("try", "try")

# client.connect("public.cloud.shiftr.io", 1883, 60)
client.connect("192.168.0.17", 1883, 60)

# Si quiero que esté escuchando para siempre:
# client.loop_forever()
# http://www.steves-internet-guide.com/loop-python-mqtt-client/

# Inicia una nueva hebra
client.loop_start()

while 1:
    time.sleep(1)

# También se puede conectar y enviar en una linea https://www.eclipse.org/paho/clients/python/docs/#single

# Y conectar y bloquear para leer una sola vez en una sola linea https://www.eclipse.org/paho/clients/python/docs/#simple