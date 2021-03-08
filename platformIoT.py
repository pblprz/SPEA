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
import base64

# Solo si queremos Padding
from cryptography.hazmat.primitives import padding

# Generate DH parameters
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
params_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
print(params_pem)

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

derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(a_shared_key)
key = base64.urlsafe_b64encode(derived_key)
print(key)

#Para CBC
iv = os.urandom(16)
mode_CBC = modes.CBC(iv)

def ejercicio1():
  return 0

backend = default_backend()

ejercicio1()

'''
# Para realiza el Padding de bloques de 128 bits (AES) habría que usar un padder
padder = padding.PKCS7(128).padder()

# Genera una clave aleatoria
key = os.urandom(16)
# msg = os.urandom(64)
msg = b"Hello world"

# Crea un objeto de cifrado usando el algoritmo y modo indicado y lo inicializa con la clave key
cipher_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

# Crea un cifrador, también se podría haber creado un descifrador
encryptor_ecb = cipher_ecb.encryptor()

# Si queremos padding antes habría que usar el padder
p = padder.update(msg)
p += padder.finalize() 

# msj tiene longitud multiplo de 128 bits
cifrado = encryptor_ecb.update(p)

#Como no hay padding, finaliza no devuelve nada adicional
# encryptor_ecb.finalize()

print(p)
print(cifrado.hex())

decryptor_ecb = cipher_ecb.decryptor()
descifrado = decryptor_ecb.update(cifrado)
decryptor_ecb.finalize()
print(descifrado)

unpadder = padding.PKCS7(128).unpadder()
output = unpadder.update(descifrado) + unpadder.finalize()
print(output)
'''

## FERNET
# key is generated 
# key = Fernet.generate_key()
  
# value of key is assigned to a variable 
f = Fernet(key) 

# the plaintext is converted to ciphertext 
cifrado = f.encrypt(b"Hello world") 

# display the ciphertext 
print(cifrado) 

# decrypting the ciphertext 
descifrado = f.decrypt(cifrado) 
  
# display the plaintext and the decode() method  
# converts it from byte to string 
print(descifrado.decode())

### PRUEBA
derived_key2 = HKDF(algorithm=hashes.SHA256(), length=24, salt=None, info=b'handshake data').derive(a_shared_key)
key2 = base64.urlsafe_b64encode(derived_key2)
print(key2)

## AEAD
# key = aead.AESGCM.generate_key(bit_length=128)
aesgcm = aead.AESGCM(key2)
nonce = os.urandom(12)
# aad = b"Authenticated but unencrypted data"
cifrado = aesgcm.encrypt(nonce, b"Hello world", None)
descifrado = aesgcm.decrypt(nonce, cifrado, None)
print(descifrado.decode())

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
    # client.subscribe("SPEA")

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
    # Publish a message every second
    client.publish("SPEA", "Hello World", 1)
    time.sleep(1)

# También se puede conectar y enviar en una linea https://www.eclipse.org/paho/clients/python/docs/#single

# Y conectar y bloquear para leer una sola vez en una sola linea https://www.eclipse.org/paho/clients/python/docs/#simple