from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import load_pem_parameters, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
import paho.mqtt.client as mqtt
import os
import base64
import time
import hmac
import hashlib
import threading

# Change for each device
mode = 0            # 0 = E, 1 = S, 2 = E/S, 3 = None
name = "Pablo"      # Device name

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    if (rc == 0):
        print("Connected OK (MQTT)")
        # Connection message -> Topic: connection -> Message: { Name: Type }
        client.publish("connection", name + ":" + str(mode) + ":" + str(asymmetric_mode) + ":" + str(symmetric_mode))
        # Subscription to channel -> Name/direction
        client.subscribe(name + "/to")
    else:
        print("Connected with result code " + str(rc))

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    global parameters
    global hmac_key
    global b_public_key_number
    global a_private_key
    global a_public_key
    global a_private_key_ecdh
    global a_public_key_ecdh
    global key_fernet
    global f_key
    global a_key

    if (msg.topic == (name + "/to")):

        # Receive params
        if (str(msg.payload.decode()).split(":")[0] == "param"):
            b_pem = str(msg.payload.decode()).split(":")[1]
            parameters = load_pem_parameters(bytes(b_pem, 'ascii'), backend = default_backend())

            # Calculate keys from params
            a_private_key = parameters.generate_private_key()
            a_public_key = a_private_key.public_key()
            client.publish(name + "/from", "public:" + str(a_public_key.public_numbers().y))

        # Receive public key
        elif (str(msg.payload.decode()).split(":")[0] == "public"):
            print("Public key received from platform.")
            
            # DH
            if (asymmetric_mode == 0):
                b_public_key_number = int(str(msg.payload.decode()).split(":")[1])
                peer_public_numbers = dh.DHPublicNumbers(b_public_key_number, parameters.parameter_numbers())
                b_public_key = peer_public_numbers.public_key(default_backend())
                # Calculate shared key
                a_shared_key = a_private_key.exchange(b_public_key)

            # ECDH
            else:
                # Generate private and public key ECDH
                a_private_key_ecdh = ec.generate_private_key(ec.SECP384R1())
                a_public_key_ecdh = a_private_key_ecdh.public_key()

                b_public_key_number = str(msg.payload.decode()).split(":")[1]
                b_public_key = load_pem_public_key(b_public_key_number.encode())
                client.publish(name + "/from", "public:" + a_public_key_ecdh.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo).decode())
                # Calculate shared key
                a_shared_key = a_private_key_ecdh.exchange(ec.ECDH(), b_public_key)

            print("Shared key calculated.")

            # Calculate HMAC
            def hebra():
                # If device has just 'input', write HMAC key here
                if (mode == 0):
                    hmac_key = str(input("Introduce la clave que aparece en la plataforma: "))
                # If device has 'output' or nothing, write HMAC key on web page
                else:
                    hmac_key = str(os.urandom(2).hex())
                print("HMAC KEY: " + hmac_key)

                # Calcula HMAC (DH or ECDH)
                if (asymmetric_mode == 0):
                    h = hmac.new(bytes(hmac_key, 'ascii'), bytes(str(a_public_key.public_numbers().y), 'ascii'), hashlib.sha256)
                else:
                    h = hmac.new(bytes(hmac_key, 'ascii'), a_public_key_ecdh.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo), hashlib.sha256)

                # Send to platform HMAC
                client.publish(name + "/from", "hmac:" + str(h.hexdigest()))

            # New thread because 'input' is blocking
            threading.Thread(target = hebra).start()

            # Calculate FERNET key using HASH
            derived_key_fernet = HKDF(algorithm = hashes.SHA256(), length = 32, salt = None, info = b'handshake data').derive(a_shared_key)
            key_fernet = base64.urlsafe_b64encode(derived_key_fernet)
            f_key = Fernet(key_fernet)

            # Calculate AEAD key using HASH
            derived_key_aead = HKDF(algorithm = hashes.SHA256(), length = 24, salt = None, info = b'handshake data').derive(a_shared_key)
            key_aead = base64.urlsafe_b64encode(derived_key_aead)
            a_key = aead.AESGCM(key_aead)

# Asymmetric crypto
asymmetric_mode = int(input("Introduce 0 para DH y 1 para ECDH: "))

# Symmetric crypto
symmetric_mode = int(input("Introduce 0 para Fernet y 1 para AEAD: "))

# Generate private and public key ECDH
a_private_key_ecdh = ec.generate_private_key(ec.SECP384R1())
a_public_key_ecdh = a_private_key_ecdh.public_key()

# Create MQTT client
client = mqtt.Client(name)
# Function for new connection
client.on_connect = on_connect
# Function for new message
client.on_message = on_message
# Server y port MQTT 
client.connect("192.168.0.17", 1883)
# Start new thread
client.loop_start()

# Loop
while 1:

    # Send a message periodically
    time.sleep(20)

    # Fernet or AEAD
    if (symmetric_mode == 0):
        cifrado = f_key.encrypt(b"Hello world")
        client.publish(name + "/from", "message: " + cifrado.decode())
    else:
        cifrado = a_key.encrypt(b"12345678", b"Hello world", None)
        client.publish(name + "/from", "message: " + cifrado.decode('latin-1'))
    print("Message sent")
